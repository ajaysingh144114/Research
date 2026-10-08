"""Envelopes: one document, several signers, one evidence pack.

A sender creates an envelope for a document (by hash) and a list of signers.
Signers sign in order (or in any order if `sequential` is false). Each signer
gets their own hybrid signature bundle. When the last one signs, QSign adds a
*completion seal*: a hybrid signature over the list of every signer bundle, so
nobody can later add, drop or swap a signature without it showing.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from datetime import datetime, timedelta, timezone

from .bundle import build_manifest, canonical, sign_manifest, verify_bundle
from .identity import Principal

EVIDENCE_FORMAT = "qsign-evidence/1"
MAX_SIGNERS = 25
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class EnvelopeError(ValueError):
    """The request breaks an envelope rule (maps to HTTP 400/403/409)."""

    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


def _now(now: datetime | None) -> datetime:
    return (now or datetime.now(timezone.utc)).astimezone(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def bundle_digest(bundle: dict) -> str:
    return hashlib.sha256(canonical(bundle)).hexdigest()


def create_envelope(
    sender: Principal,
    *,
    title: str,
    document: dict,
    signers: list[dict],
    sequential: bool = True,
    message: str = "",
    expires_in_days: int = 30,
    now: datetime | None = None,
) -> dict:
    title = title.strip()[:200]
    if not title:
        raise EnvelopeError("title is required")
    sha512 = str(document.get("sha512", "")).lower()
    if not re.fullmatch(r"[0-9a-f]{128}", sha512):
        raise EnvelopeError("document.sha512 must be a 128-character hex digest")
    if not 1 <= len(signers) <= MAX_SIGNERS:
        raise EnvelopeError(f"an envelope needs between 1 and {MAX_SIGNERS} signers")
    if not 1 <= expires_in_days <= 365:
        raise EnvelopeError("expires_in_days must be between 1 and 365")
    seen, people = set(), []
    for i, s in enumerate(signers):
        email = str(s.get("email", "")).strip().lower()
        if not EMAIL_RE.match(email):
            raise EnvelopeError(f"signer {i + 1} has an invalid email")
        if email in seen:
            raise EnvelopeError(f"{email} is listed twice")
        seen.add(email)
        people.append(
            {"email": email, "name": str(s.get("name") or email)[:200], "order": i + 1, "status": "pending"}
        )
    t = _now(now)
    return {
        "id": str(uuid.uuid4()),
        "org_id": sender.org_id,
        "title": title,
        "message": message[:2000],
        "document": {
            "name": str(document.get("name", ""))[:255],
            "size": int(document["size"]) if document.get("size") is not None else None,
            "sha512": sha512,
        },
        "created_by": {"email": sender.email, "name": sender.name},
        "created_at": _iso(t),
        "expires_at": _iso(t + timedelta(days=expires_in_days)),
        "sequential": bool(sequential),
        "status": "open",
        "signers": people,
        "seal": None,
    }


def is_expired(env: dict, now: datetime | None = None) -> bool:
    return env["status"] == "open" and _iso(_now(now)) > env["expires_at"]


def awaiting(env: dict) -> list[dict]:
    """Signers who may sign right now."""
    if env["status"] != "open":
        return []
    pending = [s for s in env["signers"] if s["status"] == "pending"]
    return pending[:1] if env["sequential"] else pending


def can_view(env: dict, who: Principal) -> bool:
    if who.email == env["created_by"]["email"]:
        return True
    if any(s["email"] == who.email for s in env["signers"]):
        return True
    return who.is_org_admin and who.org_id == env["org_id"]


def _require_open(env: dict, now: datetime | None) -> None:
    if is_expired(env, now):
        raise EnvelopeError("this envelope has expired", 409)
    if env["status"] != "open":
        raise EnvelopeError(f"this envelope is {env['status']}", 409)


def _slot_for(env: dict, who: Principal) -> dict:
    for s in awaiting(env):
        if s["email"] == who.email:
            return s
    if any(s["email"] == who.email for s in env["signers"]):
        raise EnvelopeError("it is not your turn to sign, or you have already acted", 409)
    raise EnvelopeError("you are not a signer on this envelope", 403)


def sign_envelope(
    env: dict,
    who: Principal,
    *,
    sha512: str,
    consent: bool,
    signers,
    reason: str = "",
    location: str = "",
    jurisdiction: str = "OTHER",
    now: datetime | None = None,
) -> dict:
    """Add `who`'s signature. Returns their bundle; mutates `env`."""
    _require_open(env, now)
    slot = _slot_for(env, who)
    if not consent:
        raise EnvelopeError("consent to sign electronically is required")
    if str(sha512).lower() != env["document"]["sha512"]:
        raise EnvelopeError("this is not the document in the envelope (hash does not match)")
    t = _now(now)
    manifest = build_manifest(
        document=env["document"],
        signer=who.signer_record(),
        reason=reason,
        location=location,
        jurisdiction=jurisdiction,
        signed_at=t,
        envelope={
            "id": env["id"],
            "title": env["title"],
            "signer_order": slot["order"],
            "total_signers": len(env["signers"]),
        },
    )
    bundle = sign_manifest(manifest, signers)
    slot.update(status="signed", signed_at=_iso(t), bundle=bundle, name=who.name)
    if all(s["status"] == "signed" for s in env["signers"]):
        env["status"] = "completed"
        env["completed_at"] = _iso(t)
        env["seal"] = sign_manifest(seal_manifest(env), signers)
    return bundle


def seal_manifest(env: dict) -> dict:
    return {
        "type": "envelope-completion",
        "envelope_id": env["id"],
        "org_id": env["org_id"],
        "title": env["title"],
        "document": env["document"],
        "created_by": env["created_by"],
        "created_at": env["created_at"],
        "completed_at": env["completed_at"],
        "signers": [
            {
                "order": s["order"],
                "email": s["email"],
                "signed_at": s["signed_at"],
                "bundle_sha256": bundle_digest(s["bundle"]),
            }
            for s in env["signers"]
        ],
    }


def decline_envelope(env: dict, who: Principal, reason: str = "", now: datetime | None = None) -> None:
    _require_open(env, now)
    slot = _slot_for(env, who)
    slot.update(status="declined", declined_at=_iso(_now(now)), decline_reason=reason[:500])
    env["status"] = "declined"


def cancel_envelope(env: dict, who: Principal, now: datetime | None = None) -> None:
    owner = who.email == env["created_by"]["email"]
    admin = who.is_org_admin and who.org_id == env["org_id"]
    if not (owner or admin):
        raise EnvelopeError("only the sender or an organisation administrator can cancel", 403)
    _require_open(env, now)
    env["status"] = "cancelled"
    env["cancelled_at"] = _iso(_now(now))
    env["cancelled_by"] = who.email


def public_view(env: dict) -> dict:
    """Envelope without internal fields, for API responses."""
    out = {k: v for k, v in env.items() if k != "version"}
    if is_expired(env):
        out["status"] = "expired"
    return out


def evidence_pack(env: dict) -> dict:
    if env["status"] != "completed":
        raise EnvelopeError("evidence is available once every signer has signed", 409)
    return {"format": EVIDENCE_FORMAT, "envelope": public_view(env), "seal": env["seal"]}


def verify_evidence(
    evidence: dict, *, document_digests: dict | None = None, trusted_fingerprints=None
) -> dict:
    """Check an evidence pack: the seal, every signer's signature and that they all fit together."""
    errors: list[str] = []
    if evidence.get("format") != EVIDENCE_FORMAT:
        errors.append("not a QSign evidence pack")
        return {"valid": False, "errors": errors, "signers": [], "seal": None}
    env = evidence.get("envelope") or {}
    seal = evidence.get("seal") or {}
    seal_report = verify_bundle(seal, trusted_fingerprints=trusted_fingerprints)
    if not seal_report["valid"]:
        errors.append("completion seal is not valid")
    sealed = seal.get("manifest") or {}
    if sealed.get("type") != "envelope-completion" or sealed.get("envelope_id") != env.get("id"):
        errors.append("seal does not belong to this envelope")
    if (sealed.get("document") or {}).get("sha512") != (env.get("document") or {}).get("sha512"):
        errors.append("seal covers a different document")

    sealed_signers = {s.get("order"): s for s in sealed.get("signers") or []}
    signer_reports = []
    trusted_all = seal_report["trusted_keys"]
    for s in env.get("signers") or []:
        bundle = s.get("bundle") or {}
        rep = verify_bundle(
            bundle, document_digests=document_digests, trusted_fingerprints=trusted_fingerprints
        )
        m = rep["manifest"]
        ok = rep["valid"]
        expected = sealed_signers.get(s.get("order"))
        if not expected or expected.get("bundle_sha256") != bundle_digest(bundle):
            ok = False
            errors.append(f"signature {s.get('order')} is not the one that was sealed")
        if (m.get("envelope") or {}).get("id") != env.get("id"):
            ok = False
            errors.append(f"signature {s.get('order')} belongs to a different envelope")
        if (m.get("signer") or {}).get("email") != s.get("email"):
            ok = False
            errors.append(f"signature {s.get('order')} was made by someone else")
        if not rep["valid"]:
            errors.extend(f"signer {s.get('order')}: {e}" for e in rep["errors"])
        if trusted_all is not None:
            trusted_all = trusted_all and bool(rep["trusted_keys"])
        signer_reports.append(
            {
                "order": s.get("order"),
                "email": (m.get("signer") or {}).get("email"),
                "name": (m.get("signer") or {}).get("name"),
                "signed_at": m.get("signed_at"),
                "identity": (m.get("signer") or {}).get("verified_by"),
                "valid": ok,
            }
        )
    if len(signer_reports) != len(sealed_signers):
        errors.append("number of signatures does not match the seal")
    return {
        "valid": not errors,
        "errors": errors,
        "trusted_keys": trusted_all,
        "title": env.get("title"),
        "document": env.get("document"),
        "completed_at": sealed.get("completed_at"),
        "signers": signer_reports,
        "seal": {"valid": seal_report["valid"], "signatures": seal_report["signatures"]},
    }
