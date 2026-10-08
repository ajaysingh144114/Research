import hashlib

import pytest
from fastapi.testclient import TestClient

from qsign import api
from qsign.audit import FileAuditLog
from qsign.signers import generate_local_keys, load_local_signers

DOC = b"employment agreement v3"
SHA = hashlib.sha512(DOC).hexdigest()


@pytest.fixture()
def client(tmp_path, monkeypatch):
    generate_local_keys(tmp_path / "keys")
    signers = load_local_signers(tmp_path / "keys")
    app = api.create_app()
    app.dependency_overrides[api.get_signers] = lambda: signers
    app.dependency_overrides[api.get_audit] = lambda: FileAuditLog(tmp_path / "audit.jsonl")
    return TestClient(app)


def sign_body(**extra):
    return {"document": {"name": "a.pdf", "size": len(DOC), "sha512": SHA}, "consent": True, "jurisdiction": "EU", **extra}


def test_sign_requires_login(client, monkeypatch):
    monkeypatch.delenv("QSIGN_ALLOW_UNAUTHENTICATED", raising=False)
    assert client.post("/api/sign", json=sign_body(signer_email="x@y.z")).status_code == 401


def test_sign_requires_consent(client, monkeypatch):
    monkeypatch.setenv("QSIGN_ALLOW_UNAUTHENTICATED", "1")
    r = client.post("/api/sign", json=sign_body(consent=False, signer_email="x@y.z"))
    assert r.status_code == 400


def test_dev_mode_sign_then_verify(client, monkeypatch, tmp_path):
    monkeypatch.setenv("QSIGN_ALLOW_UNAUTHENTICATED", "1")
    r = client.post("/api/sign", json=sign_body(signer_email="dev@example.com", signer_name="Dev"))
    assert r.status_code == 200, r.text
    bundle = r.json()["bundle"]
    assert bundle["manifest"]["signer"]["verified_by"] == "self-declared (development)"
    assert (tmp_path / "audit.jsonl").read_text().count("\n") == 1

    v = client.post("/api/verify", json={"bundle": bundle, "sha512": SHA}).json()
    assert v["valid"] and v["document_match"] and v["trusted_keys"]

    wrong = hashlib.sha512(b"something else").hexdigest()
    assert client.post("/api/verify", json={"bundle": bundle, "sha512": wrong}).json()["valid"] is False


def test_identity_comes_from_cognito_claims_not_the_body(client, monkeypatch):
    claims = {"sub": "abc-123", "email": "real@example.com", "name": "Real Person", "iss": "https://cognito-idp.example/pool"}
    monkeypatch.setattr(api, "_jwt_claims", lambda request: claims)
    r = client.post("/api/sign", json=sign_body(signer_email="spoof@example.com"))
    signer = r.json()["bundle"]["manifest"]["signer"]
    assert signer["email"] == "real@example.com"
    assert signer["subject"] == "abc-123"
    assert signer["verified_by"].startswith("cognito:")


def test_index_and_keys(client):
    assert "QSign" in client.get("/").text
    keys = client.get("/api/keys").json()["keys"]
    assert {k["alg"] for k in keys} == {"ML-DSA-65", "ECDSA-P384-SHA384"}
