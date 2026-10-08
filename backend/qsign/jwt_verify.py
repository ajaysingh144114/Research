"""Verify Amazon Cognito ID tokens inside the app.

Used when QSign runs outside API Gateway (containers on ECS/EKS or on-premises),
where nothing in front of the app has checked the token. Behind API Gateway the
JWT authorizer does this instead.

Checks: RS256 signature against the pool's published keys, issuer, audience
(app client id), token_use=id and expiry.
"""

from __future__ import annotations

import base64
import json
import time
import urllib.request

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

_JWKS_CACHE: dict[str, tuple[float, dict]] = {}
JWKS_TTL = 3600
LEEWAY = 60


class InvalidToken(Exception):
    pass


def _b64url(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def _int(data: str) -> int:
    return int.from_bytes(_b64url(data), "big")


def fetch_jwks(issuer: str) -> dict:
    cached = _JWKS_CACHE.get(issuer)
    if cached and time.time() - cached[0] < JWKS_TTL:
        return cached[1]
    with urllib.request.urlopen(f"{issuer}/.well-known/jwks.json", timeout=5) as resp:  # noqa: S310 (https issuer)
        jwks = json.load(resp)
    _JWKS_CACHE[issuer] = (time.time(), jwks)
    return jwks


def verify_id_token(token: str, *, issuer: str, audience: str, jwks: dict | None = None, now: float | None = None) -> dict:
    try:
        header_b64, payload_b64, sig_b64 = token.split(".")
        header = json.loads(_b64url(header_b64))
        claims = json.loads(_b64url(payload_b64))
        signature = _b64url(sig_b64)
    except Exception as exc:
        raise InvalidToken("malformed token") from exc
    if header.get("alg") != "RS256":
        raise InvalidToken("unexpected algorithm")
    keys = (jwks or fetch_jwks(issuer)).get("keys", [])
    jwk = next((k for k in keys if k.get("kid") == header.get("kid") and k.get("kty") == "RSA"), None)
    if jwk is None:
        raise InvalidToken("unknown signing key")
    public_key = rsa.RSAPublicNumbers(_int(jwk["e"]), _int(jwk["n"])).public_key()
    try:
        public_key.verify(signature, f"{header_b64}.{payload_b64}".encode(), padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature as exc:
        raise InvalidToken("bad signature") from exc
    t = time.time() if now is None else now
    if claims.get("iss") != issuer:
        raise InvalidToken("wrong issuer")
    if claims.get("aud") != audience:
        raise InvalidToken("wrong audience")
    if claims.get("token_use") != "id":
        raise InvalidToken("not an ID token")
    if float(claims.get("exp", 0)) + LEEWAY < t:
        raise InvalidToken("token expired")
    return claims
