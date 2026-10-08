"""Who is calling: the signed-in person, their organisation and their role.

In AWS, API Gateway has already checked the Cognito token, and we read the
verified claims it passes along. The organisation comes from the
`custom:org_id` attribute, which only administrators can set, and the admin
role from membership of the `org-admin` Cognito group.

For local development only, QSIGN_ALLOW_UNAUTHENTICATED=1 accepts the
X-QSign-Dev-* headers instead, and every signature made that way is labelled
"self-declared (development)".
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from fastapi import HTTPException, Request

ADMIN_GROUP = "org-admin"
GUEST_ORG = "guest"


@dataclass(frozen=True)
class Principal:
    email: str
    name: str
    subject: str
    org_id: str
    verified_by: str
    groups: frozenset[str] = field(default_factory=frozenset)

    @property
    def is_org_admin(self) -> bool:
        return ADMIN_GROUP in self.groups and self.org_id != GUEST_ORG

    def signer_record(self) -> dict:
        return {
            "name": self.name,
            "email": self.email,
            "subject": self.subject,
            "org_id": self.org_id,
            "verified_by": self.verified_by,
        }


def parse_groups(value) -> frozenset[str]:
    """Cognito groups arrive as a list, or as "[a b]" text from API Gateway."""
    if not value:
        return frozenset()
    if isinstance(value, (list, tuple, set)):
        return frozenset(str(v) for v in value)
    text = str(value).strip().strip("[]")
    return frozenset(p for p in text.replace(",", " ").split() if p)


def principal_from_claims(claims: dict) -> Principal:
    email = str(claims.get("email", "")).lower()
    return Principal(
        email=email,
        name=str(claims.get("name") or email),
        subject=str(claims.get("sub", "")),
        org_id=str(claims.get("custom:org_id") or GUEST_ORG),
        verified_by=f"cognito:{claims.get('iss', '')}",
        groups=parse_groups(claims.get("cognito:groups")),
    )


def jwt_claims(request: Request) -> dict | None:
    event = request.scope.get("aws.event") or {}
    return ((event.get("requestContext") or {}).get("authorizer") or {}).get("jwt", {}).get("claims")


def dev_mode() -> bool:
    return os.environ.get("QSIGN_ALLOW_UNAUTHENTICATED") == "1"


def _bearer_claims(request: Request) -> dict | None:
    """Self-verify the token when not behind API Gateway (QSIGN_JWT_ISSUER set)."""
    issuer = os.environ.get("QSIGN_JWT_ISSUER")
    auth = request.headers.get("authorization", "")
    if not issuer or not auth.lower().startswith("bearer "):
        return None
    from .jwt_verify import InvalidToken, verify_id_token

    try:
        return verify_id_token(auth[7:].strip(), issuer=issuer, audience=os.environ.get("QSIGN_COGNITO_CLIENT_ID", ""))
    except InvalidToken as exc:
        raise HTTPException(401, f"invalid sign-in token: {exc}") from exc


def optional_principal(request: Request) -> Principal | None:
    claims = jwt_claims(request) or _bearer_claims(request)
    if claims:
        return principal_from_claims(claims)
    if dev_mode():
        email = request.headers.get("x-qsign-dev-email", "").strip().lower()
        if not email:
            return None
        return Principal(
            email=email,
            name=request.headers.get("x-qsign-dev-name") or email,
            subject="",
            org_id=request.headers.get("x-qsign-dev-org") or "dev-org",
            verified_by="self-declared (development)",
            groups=parse_groups(request.headers.get("x-qsign-dev-groups", "")),
        )
    return None


def current_principal(request: Request) -> Principal:
    principal = optional_principal(request)
    if principal is None or not principal.email:
        raise HTTPException(401, "sign-in required")
    return principal


def require_admin(request: Request) -> Principal:
    principal = current_principal(request)
    if not principal.is_org_admin:
        raise HTTPException(403, "organisation administrator role required")
    return principal
