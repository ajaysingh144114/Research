"""Audit trail: one record per event (signature, envelope created, declined...).

On AWS, records go to DynamoDB and every signature bundle and evidence pack is
copied to an S3 bucket with Object Lock (write-once), so nobody, including an
administrator, can quietly alter the history. Locally, records go to a
JSON-lines file.
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .bundle import canonical

NO_ORG = "none"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def make_event(event: str, *, org_id: str, actor: str, source_ip: str | None = None, **details) -> dict:
    rec = {
        "id": str(uuid.uuid4()),
        "event": event,
        "at": _now(),
        "org_id": org_id or NO_ORG,
        "actor_email": actor or "",
        "source_ip": source_ip or "",
    }
    rec.update({k: v for k, v in details.items() if v is not None})
    return rec


def signature_details(bundle: dict) -> dict:
    m = bundle["manifest"]
    return {
        "document_name": m["document"].get("name", ""),
        "document_sha512": m["document"]["sha512"],
        "identity_verified_by": m["signer"].get("verified_by", ""),
        "jurisdiction": m["jurisdiction"],
        "envelope_id": (m.get("envelope") or {}).get("id"),
        "key_fingerprints": [s["key_fingerprint"] for s in bundle["signatures"]],
        "bundle_sha256": hashlib.sha256(canonical(bundle)).hexdigest(),
    }


class AuditLog:
    def write(self, record: dict, archive: dict | None = None) -> dict:
        raise NotImplementedError

    def list_for_org(self, org_id: str, limit: int = 100) -> list[dict]:
        raise NotImplementedError

    # Convenience wrappers -------------------------------------------------
    def record(self, bundle: dict, source_ip: str | None = None) -> dict:
        signer = bundle["manifest"]["signer"]
        rec = make_event(
            "signature.created",
            org_id=signer.get("org_id", ""),
            actor=signer.get("email", ""),
            source_ip=source_ip,
            **signature_details(bundle),
        )
        return self.write(rec, archive=bundle)

    def event(self, event: str, *, org_id: str, actor: str, source_ip: str | None = None,
              archive: dict | None = None, **details) -> dict:
        return self.write(make_event(event, org_id=org_id, actor=actor, source_ip=source_ip, **details), archive)


class FileAuditLog(AuditLog):
    def __init__(self, path: str | Path):
        self.path = Path(path)

    def write(self, record, archive=None):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")
        return record

    def list_for_org(self, org_id, limit=100):
        if not self.path.exists():
            return []
        rows = [json.loads(line) for line in self.path.read_text(encoding="utf-8").splitlines() if line]
        rows = [r for r in rows if r.get("org_id") == org_id]
        return sorted(rows, key=lambda r: r["at"], reverse=True)[:limit]


class AwsAuditLog(AuditLog):
    def __init__(self, table_name: str, bucket: str | None = None):
        import boto3

        self.table = boto3.resource("dynamodb").Table(table_name)
        self.s3 = boto3.client("s3") if bucket else None
        self.bucket = bucket

    def write(self, record, archive=None):
        if archive is not None and self.s3:
            key = f"archive/{record['at'][:10]}/{record['event']}/{record['id']}.json"
            self.s3.put_object(
                Bucket=self.bucket,
                Key=key,
                Body=json.dumps(archive, indent=2).encode(),
                ContentType="application/json",
                ChecksumAlgorithm="SHA256",
            )
            record["archive_key"] = key
        self.table.put_item(Item=record)
        return record

    def list_for_org(self, org_id, limit=100):
        from boto3.dynamodb.conditions import Key

        resp = self.table.query(
            IndexName="by_org",
            KeyConditionExpression=Key("org_id").eq(org_id),
            ScanIndexForward=False,
            Limit=limit,
        )
        return resp.get("Items", [])


def audit_from_env() -> AuditLog:
    table = os.environ.get("QSIGN_AUDIT_TABLE")
    if table:
        return AwsAuditLog(table, os.environ.get("QSIGN_ARCHIVE_BUCKET") or None)
    return FileAuditLog(os.environ.get("QSIGN_AUDIT_FILE", "audit/audit.jsonl"))
