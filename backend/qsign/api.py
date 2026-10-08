"""HTTP API and web app.

Privacy by design: browsers hash documents locally and send only the hash.
Documents never reach the server.

Identity always comes from the verified sign-in (see identity.py), never from
what a caller types.
"""

from __future__ import annotations

import os
import time
from functools import lru_cache
from importlib import resources

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from . import __version__
from .algorithms import fingerprint
from .audit import AuditLog, audit_from_env
from .bundle import JURISDICTIONS, MEANINGS, build_manifest, sign_manifest, verify_bundle
from .envelopes import (
    EnvelopeError,
    awaiting,
    can_view,
    cancel_envelope,
    create_envelope,
    decline_envelope,
    evidence_pack,
    public_view,
    sign_envelope,
    verify_evidence,
)
from .esign import DEFAULT_DISCLOSURE, MAX_DISCLOSURE
from .identity import GUEST_ORG, Principal, current_principal, dev_mode, require_admin
from .plans import PlanStore, plan_store_from_env, status as plan_status
from .services import Directory, Notifier, directory_from_env, notifier_from_env
from .signers import Signer, signers_from_env
from .store import Conflict, EnvelopeStore, NotFound, store_from_env

SHA512 = Field(..., min_length=128, max_length=128, pattern="^[0-9a-fA-F]{128}$")


# ---------- request bodies ----------

class DocumentIn(BaseModel):
    name: str = Field("", max_length=255)
    size: int | None = Field(None, ge=0)
    sha512: str = SHA512


class SignRequest(BaseModel):
    document: DocumentIn
    consent: bool
    reason: str = Field("", max_length=500)
    location: str = Field("", max_length=200)
    jurisdiction: str = "OTHER"
    meaning: str = "agreement"


class VerifyRequest(BaseModel):
    bundle: dict | None = None
    evidence: dict | None = None
    sha512: str | None = Field(None, min_length=128, max_length=128)


class SignerIn(BaseModel):
    email: str = Field(..., max_length=320)
    name: str = Field("", max_length=200)


class EnvelopeIn(BaseModel):
    title: str = Field(..., max_length=200)
    document: DocumentIn
    signers: list[SignerIn] = Field(..., min_length=1, max_length=25)
    sequential: bool = True
    message: str = Field("", max_length=2000)
    expires_in_days: int = Field(30, ge=1, le=365)
    consumer_disclosure: str | None = Field(None, max_length=MAX_DISCLOSURE)


class EnvelopeSignIn(BaseModel):
    sha512: str = SHA512
    consent: bool
    reason: str = Field("", max_length=500)
    location: str = Field("", max_length=200)
    jurisdiction: str = "OTHER"
    meaning: str = "agreement"
    disclosure_accepted: bool = False


class DeclineIn(BaseModel):
    reason: str = Field("", max_length=500)


class InviteIn(BaseModel):
    email: str = Field(..., max_length=320)
    name: str = Field(..., min_length=1, max_length=200)
    admin: bool = False


# ---------- shared services (overridable in tests) ----------

@lru_cache
def get_signers() -> list[Signer]:
    return signers_from_env()


@lru_cache
def get_audit() -> AuditLog:
    return audit_from_env()


@lru_cache
def get_store() -> EnvelopeStore:
    return store_from_env()


@lru_cache
def get_notifier() -> Notifier:
    return notifier_from_env()


@lru_cache
def get_directory() -> Directory:
    return directory_from_env()


@lru_cache
def get_plans() -> PlanStore:
    return plan_store_from_env()


def require_active_plan(who: Principal, plans: PlanStore) -> None:
    """New signing needs an active trial or paid plan. Viewing and verifying never do."""
    if who.org_id == GUEST_ORG:
        raise HTTPException(402, "guest accounts can sign envelopes sent to them; "
                                 "signing your own documents needs a QSign plan for your organisation")
    if not plan_status(plans.get_or_start_trial(who.org_id))["active"]:
        raise HTTPException(402, "your organisation's QSign trial or plan has ended; "
                                 "ask your administrator to subscribe. Existing signatures stay valid.")


def trusted_fingerprints(signers: list[Signer]) -> list[str]:
    """Current keys plus retired ones, so signatures made before a key rotation stay trusted."""
    retired = [f.strip() for f in os.environ.get("QSIGN_RETIRED_KEY_FINGERPRINTS", "").split(",") if f.strip()]
    return [fingerprint(s.public_key_der()) for s in signers] + retired


def signing_reauth_minutes() -> int:
    return int(os.environ.get("QSIGN_SIGNING_REAUTH_MINUTES", "0") or 0)


def require_recent_login(who: Principal) -> None:
    """With QSIGN_SIGNING_REAUTH_MINUTES set, signing needs a password + MFA entered that recently
    (FDA 21 CFR 11.200: every signing outside one continuous session uses all signature components)."""
    minutes = signing_reauth_minutes()
    if minutes <= 0:
        return
    if who.auth_time is None and dev_mode():
        return
    if who.auth_time is None or time.time() - who.auth_time > minutes * 60:
        raise HTTPException(401, {"code": "reauth_required",
                                  "message": "Confirm your password and authenticator code to sign."})


def _ip(request: Request) -> str | None:
    event = request.scope.get("aws.event") or {}
    ip = ((event.get("requestContext") or {}).get("http") or {}).get("sourceIp")
    return ip or (request.client.host if request.client else None)


def _app_url(request: Request) -> str:
    return (os.environ.get("QSIGN_APP_URL") or str(request.base_url)).rstrip("/")


def _load(store: EnvelopeStore, envelope_id: str, who: Principal) -> dict:
    try:
        env = store.get(envelope_id)
    except NotFound:
        raise HTTPException(404, "envelope not found")
    if not can_view(env, who):
        raise HTTPException(404, "envelope not found")
    return env


def _save(store: EnvelopeStore, env: dict) -> None:
    try:
        store.save(env)
    except Conflict:
        raise HTTPException(409, "someone else changed this envelope at the same time; reload and try again")


def _notify_turn(notifier: Notifier, env: dict, app_url: str) -> None:
    for s in awaiting(env):
        notifier.send(
            s["email"],
            f"Please sign: {env['title']}",
            f"{env['created_by']['name']} asked you to sign \"{env['title']}\" "
            f"({env['document']['name']}).\n\n{env['message']}\n\n"
            f"Open {app_url}/#envelope={env['id']} to review and sign. "
            f"You will need the same document to sign it.",
        )


def create_app() -> FastAPI:
    if dev_mode() and os.environ.get("QSIGN_MODE") == "kms":
        raise RuntimeError("QSIGN_ALLOW_UNAUTHENTICATED must never be enabled with production KMS keys")

    app = FastAPI(title="QSign", version=__version__, description="Quantum-safe hybrid e-signatures")

    @app.exception_handler(EnvelopeError)
    async def _envelope_error(request, exc: EnvelopeError):
        from fastapi.responses import JSONResponse

        return JSONResponse(status_code=exc.status, content={"detail": str(exc)})

    # ---------- public ----------

    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    def index():
        return resources.files("qsign").joinpath("static/index.html").read_text(encoding="utf-8")

    @app.get("/health")
    def health():
        return {"status": "ok", "version": __version__}

    @app.get("/api/config")
    def config():
        return {
            "region": os.environ.get("AWS_REGION", ""),
            "cognito_client_id": os.environ.get("QSIGN_COGNITO_CLIENT_ID", ""),
            "auth_required": not dev_mode(),
            "jurisdictions": sorted(JURISDICTIONS),
            "meanings": list(MEANINGS),
            "signing_reauth_minutes": signing_reauth_minutes(),
            "esign_disclosure_template": DEFAULT_DISCLOSURE,
            "version": __version__,
        }

    @app.get("/api/keys")
    def keys(signers: list[Signer] = Depends(get_signers)):
        current = [
            {"alg": s.alg, "key_id": s.key_id, "key_fingerprint": fingerprint(s.public_key_der()), "status": "active"}
            for s in signers
        ]
        retired = [
            {"key_fingerprint": f, "status": "retired"}
            for f in trusted_fingerprints(signers)[len(signers):]
        ]
        return {"keys": current + retired}

    @app.post("/api/verify")
    def verify(body: VerifyRequest, signers: list[Signer] = Depends(get_signers)):
        trusted = trusted_fingerprints(signers)
        digests = {"sha512": body.sha512} if body.sha512 else None
        if body.evidence is not None:
            return {"kind": "evidence", **verify_evidence(body.evidence, document_digests=digests, trusted_fingerprints=trusted)}
        if body.bundle is not None:
            return {"kind": "signature", **verify_bundle(body.bundle, document_digests=digests, trusted_fingerprints=trusted)}
        raise HTTPException(400, "send a bundle or an evidence pack")

    # ---------- signed-in users ----------

    @app.get("/api/me")
    def me(who: Principal = Depends(current_principal)):
        return {"email": who.email, "name": who.name, "org_id": who.org_id, "is_org_admin": who.is_org_admin}

    @app.get("/api/plan")
    def plan(who: Principal = Depends(current_principal), plans: PlanStore = Depends(get_plans)):
        if who.org_id == GUEST_ORG:
            return {"org_id": GUEST_ORG, "plan": "guest", "active": False, "can_sign": False,
                    "expires_at": None, "days_left": 0}
        return plan_status(plans.get_or_start_trial(who.org_id))

    @app.post("/api/sign")
    def sign(
        body: SignRequest,
        request: Request,
        who: Principal = Depends(current_principal),
        signers: list[Signer] = Depends(get_signers),
        audit: AuditLog = Depends(get_audit),
        plans: PlanStore = Depends(get_plans),
    ):
        require_active_plan(who, plans)
        if not body.consent:
            raise HTTPException(400, "consent to sign electronically is required")
        require_recent_login(who)
        try:
            manifest = build_manifest(
                document=body.document.model_dump(),
                signer=who.signer_record(),
                reason=body.reason,
                location=body.location,
                jurisdiction=body.jurisdiction,
                meaning=body.meaning,
            )
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        bundle = sign_manifest(manifest, signers)
        record = audit.record(bundle, _ip(request))
        return {"bundle": bundle, "audit_id": record["id"]}

    @app.post("/api/envelopes", status_code=201)
    def new_envelope(
        body: EnvelopeIn,
        request: Request,
        who: Principal = Depends(current_principal),
        store: EnvelopeStore = Depends(get_store),
        audit: AuditLog = Depends(get_audit),
        notifier: Notifier = Depends(get_notifier),
        directory: Directory = Depends(get_directory),
        plans: PlanStore = Depends(get_plans),
    ):
        if who.org_id == GUEST_ORG:
            raise HTTPException(403, "guest accounts can sign but cannot send envelopes")
        require_active_plan(who, plans)
        env = create_envelope(
            who,
            title=body.title,
            document=body.document.model_dump(),
            signers=[s.model_dump() for s in body.signers],
            sequential=body.sequential,
            message=body.message,
            expires_in_days=body.expires_in_days,
            consumer_disclosure=body.consumer_disclosure,
        )
        if os.environ.get("QSIGN_AUTO_INVITE_SIGNERS") == "1":
            for s in env["signers"]:
                if not directory.exists(s["email"]):
                    directory.invite(s["email"], s["name"], GUEST_ORG)
        store.create(env)
        audit.event(
            "envelope.created", org_id=env["org_id"], actor=who.email, source_ip=_ip(request),
            envelope_id=env["id"], document_sha512=env["document"]["sha512"],
            signers=[s["email"] for s in env["signers"]],
        )
        _notify_turn(notifier, env, _app_url(request))
        return public_view(env)

    @app.get("/api/envelopes")
    def my_envelopes(who: Principal = Depends(current_principal), store: EnvelopeStore = Depends(get_store)):
        out = []
        for env in store.list_for(who.email):
            view = public_view(env)
            out.append(
                {
                    "id": env["id"],
                    "title": env["title"],
                    "status": view["status"],
                    "created_at": env["created_at"],
                    "created_by": env["created_by"],
                    "document_name": env["document"]["name"],
                    "my_turn": any(s["email"] == who.email for s in awaiting(env)) and view["status"] == "open",
                    "signed": sum(s["status"] == "signed" for s in env["signers"]),
                    "total": len(env["signers"]),
                }
            )
        return {"envelopes": out}

    @app.get("/api/envelopes/{envelope_id}")
    def get_envelope(envelope_id: str, who: Principal = Depends(current_principal),
                     store: EnvelopeStore = Depends(get_store)):
        env = _load(store, envelope_id, who)
        view = public_view(env)
        view["my_turn"] = any(s["email"] == who.email for s in awaiting(env)) and view["status"] == "open"
        return view

    @app.post("/api/envelopes/{envelope_id}/sign")
    def sign_in_envelope(
        envelope_id: str,
        body: EnvelopeSignIn,
        request: Request,
        who: Principal = Depends(current_principal),
        store: EnvelopeStore = Depends(get_store),
        signers: list[Signer] = Depends(get_signers),
        audit: AuditLog = Depends(get_audit),
        notifier: Notifier = Depends(get_notifier),
    ):
        env = _load(store, envelope_id, who)
        if body.meaning not in MEANINGS:
            raise HTTPException(400, f"meaning must be one of {list(MEANINGS)}")
        require_recent_login(who)
        bundle = sign_envelope(
            env, who, sha512=body.sha512, consent=body.consent, signers=signers,
            reason=body.reason, location=body.location, jurisdiction=body.jurisdiction,
            meaning=body.meaning, disclosure_accepted=body.disclosure_accepted,
        )
        _save(store, env)
        audit.write(
            {**_signature_event(bundle, who, _ip(request)), "org_id": env["org_id"]}, archive=bundle
        )
        if env["status"] == "completed":
            evidence = evidence_pack(env)
            audit.event("envelope.completed", org_id=env["org_id"], actor=who.email,
                        envelope_id=env["id"], archive=evidence)
            for email in {env["created_by"]["email"], *(s["email"] for s in env["signers"])}:
                notifier.send(email, f"Completed: {env['title']}",
                              f"Everyone has signed \"{env['title']}\". Download the evidence pack at "
                              f"{_app_url(request)}/#envelope={env['id']}")
        else:
            _notify_turn(notifier, env, _app_url(request))
        return {"bundle": bundle, "envelope": public_view(env)}

    @app.post("/api/envelopes/{envelope_id}/decline")
    def decline(envelope_id: str, body: DeclineIn, request: Request,
                who: Principal = Depends(current_principal), store: EnvelopeStore = Depends(get_store),
                audit: AuditLog = Depends(get_audit), notifier: Notifier = Depends(get_notifier)):
        env = _load(store, envelope_id, who)
        decline_envelope(env, who, body.reason)
        _save(store, env)
        audit.event("envelope.declined", org_id=env["org_id"], actor=who.email, source_ip=_ip(request),
                    envelope_id=env["id"], reason=body.reason)
        notifier.send(env["created_by"]["email"], f"Declined: {env['title']}",
                      f"{who.name} declined to sign \"{env['title']}\". Reason: {body.reason or 'none given'}")
        return public_view(env)

    @app.post("/api/envelopes/{envelope_id}/cancel")
    def cancel(envelope_id: str, request: Request, who: Principal = Depends(current_principal),
               store: EnvelopeStore = Depends(get_store), audit: AuditLog = Depends(get_audit)):
        env = _load(store, envelope_id, who)
        cancel_envelope(env, who)
        _save(store, env)
        audit.event("envelope.cancelled", org_id=env["org_id"], actor=who.email, source_ip=_ip(request),
                    envelope_id=env["id"])
        return public_view(env)

    @app.get("/api/envelopes/{envelope_id}/evidence")
    def evidence(envelope_id: str, who: Principal = Depends(current_principal),
                 store: EnvelopeStore = Depends(get_store)):
        return evidence_pack(_load(store, envelope_id, who))

    # ---------- organisation administrators ----------

    @app.post("/api/admin/users", status_code=201)
    def invite_user(body: InviteIn, request: Request, admin: Principal = Depends(require_admin),
                    directory: Directory = Depends(get_directory), audit: AuditLog = Depends(get_audit)):
        email = body.email.strip().lower()
        try:
            directory.invite(email, body.name, admin.org_id, admin=body.admin)
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc
        audit.event("user.invited", org_id=admin.org_id, actor=admin.email, source_ip=_ip(request),
                    invited_email=email, invited_as_admin=body.admin)
        return {"email": email, "org_id": admin.org_id, "admin": body.admin}

    @app.get("/api/admin/audit")
    def org_audit(limit: int = 100, admin: Principal = Depends(require_admin),
                  audit: AuditLog = Depends(get_audit)):
        return {"records": audit.list_for_org(admin.org_id, max(1, min(limit, 500)))}

    return app


def _signature_event(bundle: dict, who: Principal, ip: str | None) -> dict:
    from .audit import make_event, signature_details

    return make_event("signature.created", org_id=who.org_id, actor=who.email, source_ip=ip,
                      **signature_details(bundle))


app = create_app()
