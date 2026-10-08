import base64
import json
import time

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from qsign.jwt_verify import InvalidToken, verify_id_token

ISS = "https://cognito-idp.ap-south-1.amazonaws.com/ap-south-1_TEST"
AUD = "client123"


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


@pytest.fixture(scope="module")
def key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def jwks_for(key, kid="k1"):
    n = key.public_key().public_numbers()
    to = lambda i: b64(i.to_bytes((i.bit_length() + 7) // 8, "big"))
    return {"keys": [{"kid": kid, "kty": "RSA", "alg": "RS256", "e": to(n.e), "n": to(n.n)}]}


def token(key, kid="k1", **overrides):
    claims = {"iss": ISS, "aud": AUD, "token_use": "id", "exp": time.time() + 600,
              "email": "a@acme.com", "sub": "u1", "custom:org_id": "acme"}
    claims.update(overrides)
    head = b64(json.dumps({"alg": "RS256", "kid": kid}).encode())
    body = b64(json.dumps(claims).encode())
    sig = key.sign(f"{head}.{body}".encode(), padding.PKCS1v15(), hashes.SHA256())
    return f"{head}.{body}.{b64(sig)}"


def test_valid_token(key):
    claims = verify_id_token(token(key), issuer=ISS, audience=AUD, jwks=jwks_for(key))
    assert claims["custom:org_id"] == "acme"


@pytest.mark.parametrize("override", [
    {"iss": "https://evil"}, {"aud": "other"}, {"token_use": "access"}, {"exp": time.time() - 3600},
])
def test_rejected_claims(key, override):
    with pytest.raises(InvalidToken):
        verify_id_token(token(key, **override), issuer=ISS, audience=AUD, jwks=jwks_for(key))


def test_forged_signature_rejected(key):
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(InvalidToken):
        verify_id_token(token(other), issuer=ISS, audience=AUD, jwks=jwks_for(key))


def test_tampered_payload_rejected(key):
    head, body, sig = token(key).split(".")
    claims = json.loads(base64.urlsafe_b64decode(body + "=="))
    claims["custom:org_id"] = "victim"
    forged = f"{head}.{b64(json.dumps(claims).encode())}.{sig}"
    with pytest.raises(InvalidToken):
        verify_id_token(forged, issuer=ISS, audience=AUD, jwks=jwks_for(key))


def test_alg_none_rejected(key):
    head = b64(json.dumps({"alg": "none", "kid": "k1"}).encode())
    body = token(key).split(".")[1]
    with pytest.raises(InvalidToken):
        verify_id_token(f"{head}.{body}.", issuer=ISS, audience=AUD, jwks=jwks_for(key))


def test_api_uses_self_verified_token(key, monkeypatch):
    from fastapi.testclient import TestClient

    from qsign import api, jwt_verify

    monkeypatch.delenv("QSIGN_ALLOW_UNAUTHENTICATED", raising=False)
    monkeypatch.setenv("QSIGN_JWT_ISSUER", ISS)
    monkeypatch.setenv("QSIGN_COGNITO_CLIENT_ID", AUD)
    monkeypatch.setattr(jwt_verify, "fetch_jwks", lambda issuer: jwks_for(key))
    client = TestClient(api.create_app())
    r = client.get("/api/me", headers={"Authorization": "Bearer " + token(key)})
    assert r.status_code == 200 and r.json()["org_id"] == "acme"
    bad = client.get("/api/me", headers={"Authorization": "Bearer " + token(key, aud="x")})
    assert bad.status_code == 401
