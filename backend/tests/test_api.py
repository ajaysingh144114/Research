import hashlib

import pytest
from fastapi.testclient import TestClient

from qsign import api
from qsign.audit import FileAuditLog
from qsign.plans import MemoryPlanStore
from qsign.services import Directory, Notifier
from qsign.signers import generate_local_keys, load_local_signers
from qsign.store import MemoryEnvelopeStore

DOC = b"employment agreement v3"
SHA = hashlib.sha512(DOC).hexdigest()


def dev(email, org="acme", groups=""):
    return {"x-qsign-dev-email": email, "x-qsign-dev-name": email.split("@")[0].title(),
            "x-qsign-dev-org": org, "x-qsign-dev-groups": groups}


@pytest.fixture()
def services(tmp_path, monkeypatch):
    monkeypatch.setenv("QSIGN_ALLOW_UNAUTHENTICATED", "1")
    monkeypatch.delenv("QSIGN_MODE", raising=False)
    generate_local_keys(tmp_path / "keys")
    s = {
        "signers": load_local_signers(tmp_path / "keys"),
        "audit": FileAuditLog(tmp_path / "audit.jsonl"),
        "store": MemoryEnvelopeStore(),
        "notifier": Notifier(),
        "directory": Directory(),
        "plans": MemoryPlanStore(),
    }
    return s


@pytest.fixture()
def client(services):
    app = api.create_app()
    app.dependency_overrides.update({
        api.get_signers: lambda: services["signers"],
        api.get_audit: lambda: services["audit"],
        api.get_store: lambda: services["store"],
        api.get_notifier: lambda: services["notifier"],
        api.get_directory: lambda: services["directory"],
        api.get_plans: lambda: services["plans"],
    })
    return TestClient(app)


def sign_body(**extra):
    return {"document": {"name": "a.pdf", "size": len(DOC), "sha512": SHA}, "consent": True, "jurisdiction": "EU", **extra}


def test_sign_requires_login(client, monkeypatch):
    monkeypatch.delenv("QSIGN_ALLOW_UNAUTHENTICATED")
    assert client.post("/api/sign", json=sign_body(), headers=dev("x@y.z")).status_code == 401


def test_dev_headers_ignored_without_dev_mode(client, monkeypatch):
    monkeypatch.delenv("QSIGN_ALLOW_UNAUTHENTICATED")
    assert client.get("/api/me", headers=dev("x@y.z")).status_code == 401


def test_dev_mode_refused_with_kms(monkeypatch):
    monkeypatch.setenv("QSIGN_ALLOW_UNAUTHENTICATED", "1")
    monkeypatch.setenv("QSIGN_MODE", "kms")
    with pytest.raises(RuntimeError):
        api.create_app()


def test_sign_requires_consent(client):
    assert client.post("/api/sign", json=sign_body(consent=False), headers=dev("x@y.z")).status_code == 400


def test_sign_then_verify(client, services):
    r = client.post("/api/sign", json=sign_body(), headers=dev("dev@example.com"))
    assert r.status_code == 200, r.text
    bundle = r.json()["bundle"]
    assert bundle["manifest"]["signer"]["verified_by"] == "self-declared (development)"
    assert bundle["manifest"]["signer"]["org_id"] == "acme"

    v = client.post("/api/verify", json={"bundle": bundle, "sha512": SHA}).json()
    assert v["kind"] == "signature" and v["valid"] and v["document_match"] and v["trusted_keys"]
    wrong = hashlib.sha512(b"something else").hexdigest()
    assert client.post("/api/verify", json={"bundle": bundle, "sha512": wrong}).json()["valid"] is False


def test_identity_comes_from_cognito_claims(client, monkeypatch):
    claims = {"sub": "abc-123", "email": "Real@Example.com", "name": "Real Person",
              "iss": "https://cognito-idp.example/pool", "custom:org_id": "acme", "cognito:groups": "[org-admin]"}
    monkeypatch.setattr("qsign.identity.jwt_claims", lambda request: claims)
    r = client.post("/api/sign", json=sign_body(), headers=dev("spoof@example.com"))
    signer = r.json()["bundle"]["manifest"]["signer"]
    assert signer["email"] == "real@example.com"
    assert signer["subject"] == "abc-123"
    assert signer["verified_by"].startswith("cognito:")
    assert client.get("/api/me").json()["is_org_admin"] is True


def test_retired_keys_stay_trusted(client, monkeypatch):
    bundle = client.post("/api/sign", json=sign_body(), headers=dev("a@b.co")).json()["bundle"]
    fps = ",".join(s["key_fingerprint"] for s in bundle["signatures"])
    monkeypatch.setenv("QSIGN_RETIRED_KEY_FINGERPRINTS", "deadbeef," + fps)
    keys = client.get("/api/keys").json()["keys"]
    assert any(k["status"] == "retired" and k["key_fingerprint"] == "deadbeef" for k in keys)


def test_admin_routes_require_admin(client, services):
    body = {"email": "new@acme.com", "name": "New Person"}
    assert client.post("/api/admin/users", json=body, headers=dev("u@acme.com")).status_code == 403
    r = client.post("/api/admin/users", json=body, headers=dev("boss@acme.com", groups="org-admin"))
    assert r.status_code == 201
    assert services["directory"].users["new@acme.com"]["org_id"] == "acme"
    assert client.post("/api/admin/users", json=body, headers=dev("boss@acme.com", groups="org-admin")).status_code == 409
    audit = client.get("/api/admin/audit", headers=dev("boss@acme.com", groups="org-admin")).json()["records"]
    assert audit[0]["event"] == "user.invited"
    other_org = client.get("/api/admin/audit", headers=dev("boss@other.com", org="other", groups="org-admin")).json()
    assert other_org["records"] == []


def test_index_and_keys(client):
    assert "QSign" in client.get("/").text
    keys = client.get("/api/keys").json()["keys"]
    assert {k["alg"] for k in keys} == {"ML-DSA-65", "ECDSA-P384-SHA384"}
