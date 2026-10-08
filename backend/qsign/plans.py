"""Subscriptions: a free trial for every new organisation, then a paid plan.

Each organisation starts a trial the first time one of its members uses QSign.
While the trial or a paid plan is active the organisation can sign documents
and send envelopes. When it lapses, new signing stops, but nothing already
signed is affected: envelopes in progress can still be completed, and anyone
can still view, download and verify every signature and evidence pack.

The operator (whoever runs this deployment) turns a trial into a paid plan with
`qsign plan set <org> --plan business --until 2027-12-31`.
"""

from __future__ import annotations

import copy
import json
import os
import threading
from datetime import datetime, timedelta, timezone

PLANS = {"trial", "business", "enterprise"}
DEFAULT_TRIAL_DAYS = 30


def trial_days() -> int:
    return int(os.environ.get("QSIGN_TRIAL_DAYS", DEFAULT_TRIAL_DAYS))


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse(text: str) -> datetime:
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def new_trial(org_id: str, now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    return {
        "org_id": org_id,
        "plan": "trial",
        "started_at": _iso(now),
        "expires_at": _iso(now + timedelta(days=trial_days())),
        "updated_at": _iso(now),
    }


def status(sub: dict, now: datetime | None = None) -> dict:
    """What the organisation may do now, for the API and the web app."""
    now = now or datetime.now(timezone.utc)
    expires = _parse(sub["expires_at"])
    active = now < expires
    days_left = max(0, (expires - now).days) if active else 0
    return {
        "org_id": sub["org_id"],
        "plan": sub["plan"],
        "active": active,
        "expires_at": sub["expires_at"],
        "days_left": days_left,
        "can_sign": active,
    }


class PlanStore:
    def get(self, org_id: str) -> dict | None:
        raise NotImplementedError

    def create(self, sub: dict) -> dict:
        """Store `sub` unless the organisation already has one; return what is stored."""
        raise NotImplementedError

    def put(self, sub: dict) -> None:
        raise NotImplementedError

    def get_or_start_trial(self, org_id: str, now: datetime | None = None) -> dict:
        return self.get(org_id) or self.create(new_trial(org_id, now))


class MemoryPlanStore(PlanStore):
    def __init__(self):
        self._items: dict[str, dict] = {}
        self._lock = threading.Lock()

    def get(self, org_id):
        with self._lock:
            sub = self._items.get(org_id)
            return copy.deepcopy(sub) if sub else None

    def create(self, sub):
        with self._lock:
            self._items.setdefault(sub["org_id"], copy.deepcopy(sub))
            return copy.deepcopy(self._items[sub["org_id"]])

    def put(self, sub):
        with self._lock:
            self._items[sub["org_id"]] = copy.deepcopy(sub)


class DynamoPlanStore(PlanStore):
    """Kept in the envelope table: pk=ORG#<org_id>, sk=PLAN."""

    def __init__(self, table_name: str):
        import boto3

        self.client = boto3.client("dynamodb")
        self.table = table_name

    def _key(self, org_id):
        return {"pk": {"S": f"ORG#{org_id}"}, "sk": {"S": "PLAN"}}

    def get(self, org_id):
        resp = self.client.get_item(TableName=self.table, Key=self._key(org_id), ConsistentRead=True)
        return json.loads(resp["Item"]["data"]["S"]) if "Item" in resp else None

    def create(self, sub):
        try:
            self.client.put_item(
                TableName=self.table,
                Item={**self._key(sub["org_id"]), "data": {"S": json.dumps(sub)}},
                ConditionExpression="attribute_not_exists(pk)",
            )
            return sub
        except self.client.exceptions.ConditionalCheckFailedException:
            return self.get(sub["org_id"])

    def put(self, sub):
        self.client.put_item(TableName=self.table, Item={**self._key(sub["org_id"]), "data": {"S": json.dumps(sub)}})


def plan_store_from_env() -> PlanStore:
    table = os.environ.get("QSIGN_ENVELOPE_TABLE")
    return DynamoPlanStore(table) if table else MemoryPlanStore()


def set_plan(store: PlanStore, org_id: str, plan: str, until: datetime, now: datetime | None = None) -> dict:
    if plan not in PLANS:
        raise ValueError(f"plan must be one of {sorted(PLANS)}")
    now = now or datetime.now(timezone.utc)
    sub = store.get(org_id) or new_trial(org_id, now)
    sub.update({"plan": plan, "expires_at": _iso(until), "updated_at": _iso(now)})
    store.put(sub)
    return sub
