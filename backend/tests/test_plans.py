from datetime import datetime, timedelta, timezone

from qsign.cli import main as cli
from qsign.plans import MemoryPlanStore, new_trial, set_plan, status

from tests.test_api import SHA, client, dev, services, sign_body  # noqa: F401  (fixtures)

ACME = dev("ann@acme.com")
GUEST = dev("bob@partner.io", org="guest")


def envelope_body():
    return {"title": "NDA", "document": {"name": "a.pdf", "sha512": SHA},
            "signers": [{"email": "bob@partner.io", "name": "Bob"}]}


def expire(services, org="acme"):
    sub = services["plans"].get_or_start_trial(org)
    sub["expires_at"] = "2020-01-01T00:00:00Z"
    services["plans"].put(sub)


def test_new_organisation_gets_a_30_day_trial(client):
    p = client.get("/api/plan", headers=ACME).json()
    assert p["plan"] == "trial" and p["active"] and p["can_sign"]
    assert p["days_left"] in (29, 30)


def test_trial_length_is_configurable(monkeypatch):
    monkeypatch.setenv("QSIGN_TRIAL_DAYS", "14")
    now = datetime(2026, 10, 8, tzinfo=timezone.utc)
    assert new_trial("acme", now)["expires_at"] == "2026-10-22T00:00:00Z"


def test_signing_works_during_trial(client):
    assert client.post("/api/sign", json=sign_body(), headers=ACME).status_code == 200
    assert client.post("/api/envelopes", json=envelope_body(), headers=ACME).status_code == 201


def test_expired_trial_blocks_new_signing_but_not_verifying(client, services):
    bundle = client.post("/api/sign", json=sign_body(), headers=ACME).json()["bundle"]
    expire(services)
    assert client.post("/api/sign", json=sign_body(), headers=ACME).status_code == 402
    assert client.post("/api/envelopes", json=envelope_body(), headers=ACME).status_code == 402
    assert client.get("/api/plan", headers=ACME).json()["active"] is False
    v = client.post("/api/verify", json={"bundle": bundle, "sha512": SHA}).json()
    assert v["valid"]


def test_envelopes_already_sent_can_still_be_completed(client, services):
    env = client.post("/api/envelopes", json=envelope_body(), headers=ACME).json()
    expire(services)
    r = client.post(f"/api/envelopes/{env['id']}/sign", json={"sha512": SHA, "consent": True}, headers=GUEST)
    assert r.status_code == 200 and r.json()["envelope"]["status"] == "completed"


def test_guests_sign_envelopes_but_cannot_self_sign(client):
    assert client.post("/api/sign", json=sign_body(), headers=GUEST).status_code == 402
    assert client.get("/api/plan", headers=GUEST).json()["plan"] == "guest"


def test_paid_plan_reactivates_signing(client, services):
    expire(services)
    set_plan(services["plans"], "acme", "business", datetime.now(timezone.utc) + timedelta(days=365))
    assert client.post("/api/sign", json=sign_body(), headers=ACME).status_code == 200
    assert client.get("/api/plan", headers=ACME).json()["plan"] == "business"


def test_organisations_are_billed_separately(client, services):
    expire(services, "acme")
    other = dev("cy@globex.com", org="globex")
    assert client.post("/api/sign", json=sign_body(), headers=other).status_code == 200


def test_trial_is_started_only_once():
    store = MemoryPlanStore()
    first = store.get_or_start_trial("acme", datetime(2026, 1, 1, tzinfo=timezone.utc))
    again = store.get_or_start_trial("acme", datetime(2026, 6, 1, tzinfo=timezone.utc))
    assert again == first
    assert status(first, datetime(2026, 6, 1, tzinfo=timezone.utc))["active"] is False


def test_operator_cli_sets_plan(tmp_path, monkeypatch, capsys):
    store = MemoryPlanStore()
    monkeypatch.setattr("qsign.plans.plan_store_from_env", lambda: store)
    monkeypatch.setenv("QSIGN_AUDIT_FILE", str(tmp_path / "audit.jsonl"))
    assert cli(["plan", "set", "acme", "--plan", "enterprise", "--until", "2027-12-31"]) == 0
    assert store.get("acme")["expires_at"] == "2027-12-31T23:59:59Z"
    assert '"plan.changed"' in (tmp_path / "audit.jsonl").read_text()
    assert cli(["plan", "show", "acme"]) == 0
    assert cli(["plan", "show", "nobody"]) == 1
