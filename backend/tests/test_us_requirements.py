"""US buyer requirements: ESIGN consumer consent, FDA Part 11 signature meaning and re-login, CNSA 2.0 key choice."""

import copy
import time

import pytest

from qsign.envelopes import verify_evidence
from qsign.esign import DEFAULT_DISCLOSURE
from tests.test_api import SHA, client, dev, services, sign_body  # noqa: F401  (fixtures)
from tests.test_verifier import qv

ACME = dev("ann@acme.com")
BOB = dev("bob@partner.io", org="guest")
DISCLOSURE = DEFAULT_DISCLOSURE.replace("[Company name]", "Acme Bank")


def consumer_envelope(client):
    return client.post("/api/envelopes", headers=ACME, json={
        "title": "Loan agreement", "document": {"name": "loan.pdf", "sha512": SHA},
        "signers": [{"email": "bob@partner.io", "name": "Bob"}], "consumer_disclosure": DISCLOSURE}).json()


def test_config_offers_disclosure_template_and_meanings(client):
    cfg = client.get("/api/config").json()
    assert "CONSENT TO ELECTRONIC RECORDS" in cfg["esign_disclosure_template"]
    assert "approval" in cfg["meanings"] and cfg["signing_reauth_minutes"] == 0


def test_consumer_must_accept_disclosure_before_signing(client):
    env = consumer_envelope(client)
    assert env["consumer_disclosure"]["text"].startswith("CONSENT")
    url = f"/api/envelopes/{env['id']}/sign"
    assert client.post(url, json={"sha512": SHA, "consent": True}, headers=BOB).status_code == 400
    r = client.post(url, json={"sha512": SHA, "consent": True, "disclosure_accepted": True}, headers=BOB)
    assert r.status_code == 200
    accepted = r.json()["bundle"]["manifest"]["consumer_disclosure"]
    assert accepted == {"sha256": env["consumer_disclosure"]["sha256"], "accepted": True}


def test_evidence_detects_edited_disclosure(client):
    env = consumer_envelope(client)
    client.post(f"/api/envelopes/{env['id']}/sign", json={"sha512": SHA, "consent": True, "disclosure_accepted": True}, headers=BOB)
    ev = client.get(f"/api/envelopes/{env['id']}/evidence", headers=ACME).json()
    assert verify_evidence(ev, document_digests={"sha512": SHA})["valid"]
    assert qv.verify_evidence(ev, document_digests={"sha512": SHA})["valid"]
    edited = copy.deepcopy(ev)
    edited["envelope"]["consumer_disclosure"]["text"] += " Paper copies cost $50."
    for check in (verify_evidence, qv.verify_evidence):
        rep = check(edited, document_digests={"sha512": SHA})
        assert not rep["valid"] and "the consumer disclosure text was changed" in rep["errors"]


def test_signature_meaning_is_signed(client):
    r = client.post("/api/sign", json=sign_body(meaning="approval"), headers=ACME)
    assert r.json()["bundle"]["manifest"]["meaning"] == "approval"
    assert client.post("/api/sign", json=sign_body(meaning="whatever"), headers=ACME).status_code == 400
    env = consumer_envelope(client)
    bad = {"sha512": SHA, "consent": True, "disclosure_accepted": True, "meaning": "nonsense"}
    assert client.post(f"/api/envelopes/{env['id']}/sign", json=bad, headers=BOB).status_code == 400


def test_reauthentication_window(client, monkeypatch):
    monkeypatch.setenv("QSIGN_SIGNING_REAUTH_MINUTES", "5")
    stale = {**ACME, "x-qsign-dev-auth-time": str(int(time.time()) - 600)}
    fresh = {**ACME, "x-qsign-dev-auth-time": str(int(time.time()) - 30)}
    r = client.post("/api/sign", json=sign_body(), headers=stale)
    assert r.status_code == 401 and r.json()["detail"]["code"] == "reauth_required"
    assert client.post("/api/sign", json=sign_body(), headers=fresh).status_code == 200


def test_reauthentication_required_when_token_lacks_auth_time(monkeypatch):
    from fastapi import HTTPException

    from qsign.api import require_recent_login
    from qsign.identity import principal_from_claims

    monkeypatch.setenv("QSIGN_SIGNING_REAUTH_MINUTES", "5")
    monkeypatch.delenv("QSIGN_ALLOW_UNAUTHENTICATED", raising=False)
    who = principal_from_claims({"email": "a@b.co", "sub": "1"})
    with pytest.raises(HTTPException):
        require_recent_login(who)
    ok = principal_from_claims({"email": "a@b.co", "sub": "1", "auth_time": str(int(time.time()))})
    require_recent_login(ok)


def test_cnsa_key_choice(monkeypatch):
    import sys
    import types

    from qsign.signers import signers_from_env

    monkeypatch.setitem(sys.modules, "boto3", types.SimpleNamespace(client=lambda name: object()))
    monkeypatch.setenv("QSIGN_MODE", "kms")
    monkeypatch.setenv("QSIGN_KMS_MLDSA_KEY_ID", "k1")
    monkeypatch.setenv("QSIGN_KMS_ECDSA_KEY_ID", "k2")
    monkeypatch.setenv("QSIGN_MLDSA_ALG", "ML-DSA-87")
    assert [s.alg for s in signers_from_env()] == ["ML-DSA-87", "ECDSA-P384-SHA384"]
    monkeypatch.setenv("QSIGN_MLDSA_ALG", "ML-DSA-44")
    with pytest.raises(ValueError):
        signers_from_env()
