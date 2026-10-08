"""Envelope storage.

DynamoDB in AWS, memory for development and tests. Every save is guarded by a
version number (optimistic locking), so two people acting on the same
envelope at the same moment can never overwrite each other.
"""

from __future__ import annotations

import copy
import json
import os
import threading


class NotFound(Exception):
    pass


class Conflict(Exception):
    pass


def _participants(env: dict) -> set[str]:
    return {env["created_by"]["email"]} | {s["email"] for s in env["signers"]}


class EnvelopeStore:
    def create(self, env: dict) -> None:
        raise NotImplementedError

    def get(self, envelope_id: str) -> dict:
        raise NotImplementedError

    def save(self, env: dict) -> None:
        """Write `env` if nobody changed it since it was read; bumps its version."""
        raise NotImplementedError

    def list_for(self, email: str, limit: int = 50) -> list[dict]:
        raise NotImplementedError


class MemoryEnvelopeStore(EnvelopeStore):
    def __init__(self):
        self._items: dict[str, dict] = {}
        self._lock = threading.Lock()

    def create(self, env):
        with self._lock:
            if env["id"] in self._items:
                raise Conflict(env["id"])
            env["version"] = 1
            self._items[env["id"]] = copy.deepcopy(env)

    def get(self, envelope_id):
        with self._lock:
            if envelope_id not in self._items:
                raise NotFound(envelope_id)
            return copy.deepcopy(self._items[envelope_id])

    def save(self, env):
        with self._lock:
            current = self._items.get(env["id"])
            if current is None:
                raise NotFound(env["id"])
            if current["version"] != env["version"]:
                raise Conflict(env["id"])
            env["version"] += 1
            self._items[env["id"]] = copy.deepcopy(env)

    def list_for(self, email, limit=50):
        email = email.lower()
        with self._lock:
            mine = [copy.deepcopy(e) for e in self._items.values() if email in _participants(e)]
        return sorted(mine, key=lambda e: e["created_at"], reverse=True)[:limit]


class DynamoEnvelopeStore(EnvelopeStore):
    """Single-table layout.

    pk=ENV#<id>      sk=META                        the envelope (JSON in `data`)
    pk=USER#<email>  sk=ENV#<created_at>#<id>       one index row per participant
    """

    def __init__(self, table_name: str):
        import boto3

        self.client = boto3.client("dynamodb")
        self.table = table_name

    def create(self, env):
        env["version"] = 1
        items = [
            {
                "Put": {
                    "TableName": self.table,
                    "Item": {
                        "pk": {"S": f"ENV#{env['id']}"},
                        "sk": {"S": "META"},
                        "version": {"N": "1"},
                        "data": {"S": json.dumps(env)},
                    },
                    "ConditionExpression": "attribute_not_exists(pk)",
                }
            }
        ]
        for email in sorted(_participants(env)):
            items.append(
                {
                    "Put": {
                        "TableName": self.table,
                        "Item": {
                            "pk": {"S": f"USER#{email}"},
                            "sk": {"S": f"ENV#{env['created_at']}#{env['id']}"},
                            "envelope_id": {"S": env["id"]},
                        },
                    }
                }
            )
        try:
            self.client.transact_write_items(TransactItems=items)
        except self.client.exceptions.TransactionCanceledException as exc:
            raise Conflict(env["id"]) from exc

    def get(self, envelope_id):
        resp = self.client.get_item(
            TableName=self.table,
            Key={"pk": {"S": f"ENV#{envelope_id}"}, "sk": {"S": "META"}},
            ConsistentRead=True,
        )
        if "Item" not in resp:
            raise NotFound(envelope_id)
        env = json.loads(resp["Item"]["data"]["S"])
        env["version"] = int(resp["Item"]["version"]["N"])
        return env

    def save(self, env):
        expected = env["version"]
        env["version"] = expected + 1
        try:
            self.client.put_item(
                TableName=self.table,
                Item={
                    "pk": {"S": f"ENV#{env['id']}"},
                    "sk": {"S": "META"},
                    "version": {"N": str(expected + 1)},
                    "data": {"S": json.dumps(env)},
                },
                ConditionExpression="version = :v",
                ExpressionAttributeValues={":v": {"N": str(expected)}},
            )
        except self.client.exceptions.ConditionalCheckFailedException as exc:
            env["version"] = expected
            raise Conflict(env["id"]) from exc

    def list_for(self, email, limit=50):
        resp = self.client.query(
            TableName=self.table,
            KeyConditionExpression="pk = :p AND begins_with(sk, :s)",
            ExpressionAttributeValues={":p": {"S": f"USER#{email.lower()}"}, ":s": {"S": "ENV#"}},
            ScanIndexForward=False,
            Limit=limit,
        )
        ids = [item["envelope_id"]["S"] for item in resp.get("Items", [])]
        if not ids:
            return []
        got = self.client.batch_get_item(
            RequestItems={
                self.table: {"Keys": [{"pk": {"S": f"ENV#{i}"}, "sk": {"S": "META"}} for i in ids]}
            }
        )["Responses"][self.table]
        envs = []
        for item in got:
            env = json.loads(item["data"]["S"])
            env["version"] = int(item["version"]["N"])
            envs.append(env)
        return sorted(envs, key=lambda e: e["created_at"], reverse=True)


def store_from_env() -> EnvelopeStore:
    table = os.environ.get("QSIGN_ENVELOPE_TABLE")
    return DynamoEnvelopeStore(table) if table else MemoryEnvelopeStore()
