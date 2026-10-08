"""HTTP API and web page.

Privacy by design: the browser hashes the document locally and sends only the
hash. The document itself never reaches the server.

Signer identity comes from the Cognito login that API Gateway has already
checked, never from what the caller types. For local development only,
QSIGN_ALLOW_UNAUTHENTICATED=1 lets the caller state a name and email; such
signatures are labelled "verified_by": "self-declared (development)".
"""

from __future__ import annotations

import os
from functools import lru_cache
from importlib import resources

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from . import __version__
from .algorithms import fingerprint
from .audit import AuditLog, audit_from_env
from .bundle import JURISDICTIONS, build_manifest, sign_manifest, verify_bundle
from .signers import Signer, signers_from_env


class DocumentIn(BaseModel):
    name: str = Field("", max_length=255)
    size: int | None = Field(None, ge=0)
    sha512: str = Field(..., min_length=128, max_length=128)


class SignRequest(BaseModel):
    document: DocumentIn
    consent: bool = Field(..., description="Signer agrees to sign electronically")
    reason: str = Field("", max_length=500)
    location: str = Field("", max_length=200)
    jurisdiction: str = "OTHER"
    # Only honoured when QSIGN_ALLOW_UNAUTHENTICATED=1 (local development).
    signer_name: str = Field("", max_length=200)
    signer_email: str = Field("", max_length=320)


class VerifyRequest(BaseModel):
    bundle: dict
    sha512: str | None = Field(None, min_length=128, max_length=128)


@lru_cache
def get_signers() -> list[Signer]:
    return signers_from_env()


@lru_cache
def get_audit() -> AuditLog:
    return audit_from_env()


def _jwt_claims(request: Request) -> dict | None:
    event = request.scope.get("aws.event") or {}
    return ((event.get("requestContext") or {}).get("authorizer") or {}).get("jwt", {}).get("claims")


def signer_identity(request: Request, body: SignRequest) -> dict:
    claims = _jwt_claims(request)
    if claims:
        return {
            "name": claims.get("name") or claims.get("email", ""),
            "email": claims.get("email", ""),
            "subject": claims.get("sub", ""),
            "verified_by": f"cognito:{claims.get('iss', '')}",
        }
    if os.environ.get("QSIGN_ALLOW_UNAUTHENTICATED") == "1":
        if not body.signer_email:
            raise HTTPException(400, "signer_email is required")
        return {
            "name": body.signer_name or body.signer_email,
            "email": body.signer_email,
            "subject": "",
            "verified_by": "self-declared (development)",
        }
    raise HTTPException(401, "sign-in required")


def create_app() -> FastAPI:
    app = FastAPI(title="QSign", version=__version__)

    @app.get("/", response_class=HTMLResponse)
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
            "auth_required": os.environ.get("QSIGN_ALLOW_UNAUTHENTICATED") != "1",
            "jurisdictions": sorted(JURISDICTIONS),
        }

    @app.get("/api/keys")
    def keys(signers: list[Signer] = Depends(get_signers)):
        out = []
        for s in signers:
            pub = s.public_key_der()
            out.append({"alg": s.alg, "key_id": s.key_id, "key_fingerprint": fingerprint(pub)})
        return {"keys": out}

    @app.post("/api/sign")
    def sign(
        body: SignRequest,
        request: Request,
        signers: list[Signer] = Depends(get_signers),
        audit: AuditLog = Depends(get_audit),
    ):
        if not body.consent:
            raise HTTPException(400, "consent to sign electronically is required")
        identity = signer_identity(request, body)
        try:
            manifest = build_manifest(
                document=body.document.model_dump(),
                signer=identity,
                reason=body.reason,
                location=body.location,
                jurisdiction=body.jurisdiction,
            )
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        bundle = sign_manifest(manifest, signers)
        record = audit.record(bundle, request.client.host if request.client else None)
        return {"bundle": bundle, "audit_id": record["id"]}

    @app.post("/api/verify")
    def verify(body: VerifyRequest, signers: list[Signer] = Depends(get_signers)):
        trusted = [fingerprint(s.public_key_der()) for s in signers]
        digests = {"sha512": body.sha512} if body.sha512 else None
        report = verify_bundle(body.bundle, document_digests=digests, trusted_fingerprints=trusted)
        return report

    return app


app = create_app()
