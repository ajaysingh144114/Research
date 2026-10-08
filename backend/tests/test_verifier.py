"""The free standalone verifier (verifier/qsign_verify.py) must agree with the platform."""

import copy
import importlib.util
import json
from pathlib import Path

from qsign.bundle import verify_bundle
from qsign.envelopes import verify_evidence
from tests.test_api import DOC, SHA, client, dev, services, sign_body  # noqa: F401  (fixtures)

_path = Path(__file__).resolve().parents[2] / "verifier" / "qsign_verify.py"
_spec = importlib.util.spec_from_file_location("qsign_verify", _path)
qv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(qv)

ACME = dev("ann@acme.com")
BOB = dev("bob@partner.io", org="guest")


def make_evidence(client):
    env = client.post("/api/envelopes", headers=ACME, json={
        "title": "NDA", "document": {"name": "a.pdf", "sha512": SHA},
        "signers": [{"email": "bob@partner.io", "name": "Bob"}, {"email": "ann@acme.com", "name": "Ann"}]}).json()
    for who in (BOB, ACME):
        assert client.post(f"/api/envelopes/{env['id']}/sign", json={"sha512": SHA, "consent": True}, headers=who).status_code == 200
    return client.get(f"/api/envelopes/{env['id']}/evidence", headers=ACME).json()


def test_bundles_agree(client):
    bundle = client.post("/api/sign", json=sign_body(), headers=ACME).json()["bundle"]
    tampered = copy.deepcopy(bundle)
    tampered["manifest"]["signer"]["name"] = "Mallory"
    no_pq = copy.deepcopy(bundle)
    no_pq["signatures"] = [s for s in no_pq["signatures"] if not s["alg"].startswith("ML-DSA")]
    for b in (bundle, tampered, no_pq):
        for digests in ({"sha512": SHA}, {"sha512": "0" * 128}, None):
            mine = qv.verify_bundle(b, document_digests=digests)
            theirs = verify_bundle(b, document_digests=digests)
            assert (mine["valid"], mine["errors"]) == (theirs["valid"], theirs["errors"])
    assert qv.verify_bundle(bundle, document_digests={"sha512": SHA})["valid"]


def test_evidence_agrees(client):
    ev = make_evidence(client)
    swapped = copy.deepcopy(ev)
    swapped["envelope"]["signers"].reverse()
    dropped = copy.deepcopy(ev)
    dropped["envelope"]["signers"].pop()
    for e in (ev, swapped, dropped):
        mine = qv.verify_evidence(e, document_digests={"sha512": SHA})
        theirs = verify_evidence(e, document_digests={"sha512": SHA})
        assert mine["valid"] == theirs["valid"]
    assert qv.verify_evidence(ev, document_digests={"sha512": SHA})["valid"]


def test_command_line(client, tmp_path, services):
    doc = tmp_path / "a.pdf"
    doc.write_bytes(DOC)
    sig = tmp_path / "a.pdf.qsig.json"
    sig.write_text(json.dumps(client.post("/api/sign", json=sign_body(), headers=ACME).json()["bundle"]))
    ev = tmp_path / "evidence.json"
    ev.write_text(json.dumps(make_evidence(client)))
    fps = [s["key_fingerprint"] for s in client.get("/api/keys").json()["keys"]]
    trust = [x for fp in fps for x in ("--trust", fp)]
    assert qv.main([str(doc), str(sig), *trust]) == 0
    assert qv.main([str(doc), str(ev), *trust]) == 0
    assert qv.main([str(doc), str(sig), "--trust", "f" * 64]) == 1
    doc.write_bytes(DOC + b"!")
    assert qv.main([str(doc), str(sig)]) == 1
