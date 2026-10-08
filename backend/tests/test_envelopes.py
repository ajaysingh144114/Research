"""Multi-signer envelopes through the HTTP API, plus evidence-pack tampering."""

import copy
import hashlib

import pytest

from qsign.envelopes import verify_evidence
from tests.test_api import client, dev, services  # noqa: F401  (fixtures)

DOC = b"master services agreement"
SHA = hashlib.sha512(DOC).hexdigest()
SENDER = dev("legal@acme.com")
ALICE = dev("alice@acme.com")
BOB = dev("bob@partner.io", org="guest")


def create(client, **extra):
    body = {
        "title": "MSA 2026",
        "document": {"name": "msa.pdf", "size": len(DOC), "sha512": SHA},
        "signers": [{"email": "alice@acme.com", "name": "Alice"}, {"email": "Bob@Partner.io", "name": "Bob"}],
        **extra,
    }
    r = client.post("/api/envelopes", json=body, headers=SENDER)
    assert r.status_code == 201, r.text
    return r.json()


def sign(client, env_id, who, sha=SHA):
    return client.post(f"/api/envelopes/{env_id}/sign", json={"sha512": sha, "consent": True}, headers=who)


def test_full_sequential_flow_and_evidence(client, services):
    env = create(client)
    assert services["notifier"].sent[-1]["to"] == "alice@acme.com"

    assert sign(client, env["id"], BOB).status_code == 409  # not Bob's turn yet
    assert client.get("/api/envelopes", headers=ALICE).json()["envelopes"][0]["my_turn"] is True

    assert sign(client, env["id"], ALICE).status_code == 200
    assert services["notifier"].sent[-1]["to"] == "bob@partner.io"
    assert client.get(f"/api/envelopes/{env['id']}/evidence", headers=SENDER).status_code == 409

    r = sign(client, env["id"], BOB)
    assert r.status_code == 200
    assert r.json()["envelope"]["status"] == "completed"

    evidence = client.get(f"/api/envelopes/{env['id']}/evidence", headers=BOB).json()
    report = client.post("/api/verify", json={"evidence": evidence, "sha512": SHA}).json()
    assert report["kind"] == "evidence" and report["valid"], report["errors"]
    assert [s["email"] for s in report["signers"]] == ["alice@acme.com", "bob@partner.io"]
    assert report["trusted_keys"] is True

    events = [r["event"] for r in services["audit"].list_for_org("acme")]
    assert events.count("signature.created") == 2
    assert "envelope.completed" in events and "envelope.created" in events


def test_wrong_document_cannot_be_signed(client):
    env = create(client)
    other = hashlib.sha512(b"a different file").hexdigest()
    assert sign(client, env["id"], ALICE, sha=other).status_code == 400


def test_outsiders_cannot_see_or_sign(client):
    env = create(client)
    eve = dev("eve@evil.com", org="evil")
    assert client.get(f"/api/envelopes/{env['id']}", headers=eve).status_code == 404
    assert sign(client, env["id"], eve).status_code == 404
    admin_same_org = dev("boss@acme.com", groups="org-admin")
    assert client.get(f"/api/envelopes/{env['id']}", headers=admin_same_org).status_code == 200
    admin_other_org = dev("boss@evil.com", org="evil", groups="org-admin")
    assert client.get(f"/api/envelopes/{env['id']}", headers=admin_other_org).status_code == 404


def test_parallel_envelope_any_order(client):
    env = create(client, sequential=False)
    assert sign(client, env["id"], BOB).status_code == 200
    assert sign(client, env["id"], ALICE).json()["envelope"]["status"] == "completed"


def test_decline_and_cancel(client, services):
    env = create(client)
    r = client.post(f"/api/envelopes/{env['id']}/decline", json={"reason": "wrong price"}, headers=ALICE)
    assert r.json()["status"] == "declined"
    assert services["notifier"].sent[-1]["to"] == "legal@acme.com"
    assert sign(client, env["id"], ALICE).status_code == 409

    env2 = create(client)
    assert client.post(f"/api/envelopes/{env2['id']}/cancel", headers=ALICE).status_code == 403
    assert client.post(f"/api/envelopes/{env2['id']}/cancel", headers=SENDER).json()["status"] == "cancelled"


def test_guests_cannot_send(client):
    body = {"title": "x", "document": {"sha512": SHA}, "signers": [{"email": "a@b.co"}]}
    assert client.post("/api/envelopes", json=body, headers=BOB).status_code == 403


def test_auto_invite_creates_guest_accounts(client, services, monkeypatch):
    monkeypatch.setenv("QSIGN_AUTO_INVITE_SIGNERS", "1")
    create(client)
    assert services["directory"].users["bob@partner.io"]["org_id"] == "guest"


def test_concurrent_save_is_rejected(services):
    from qsign.store import Conflict

    store = services["store"]
    env = {"id": "e1", "created_at": "2026-01-01T00:00:00Z", "created_by": {"email": "a@b.co"}, "signers": []}
    store.create(env)
    first, second = store.get("e1"), store.get("e1")
    store.save(first)
    with pytest.raises(Conflict):
        store.save(second)


@pytest.fixture()
def evidence(client):
    env = create(client)
    sign(client, env["id"], ALICE)
    sign(client, env["id"], BOB)
    return client.get(f"/api/envelopes/{env['id']}/evidence", headers=SENDER).json()


def test_evidence_tampering_is_detected(evidence):
    assert verify_evidence(evidence, document_digests={"sha512": SHA})["valid"]

    dropped = copy.deepcopy(evidence)
    dropped["envelope"]["signers"].pop()
    assert not verify_evidence(dropped)["valid"]

    swapped = copy.deepcopy(evidence)
    swapped["envelope"]["signers"][0]["email"] = "mallory@evil.com"
    assert not verify_evidence(swapped)["valid"]

    reseal = copy.deepcopy(evidence)
    reseal["seal"]["manifest"]["title"] = "Different deal"
    assert not verify_evidence(reseal)["valid"]

    wrong_doc = hashlib.sha512(b"other").hexdigest()
    assert not verify_evidence(evidence, document_digests={"sha512": wrong_doc})["valid"]
