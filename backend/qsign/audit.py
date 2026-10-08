"""Audit trail: one record per signature, plus an optional copy of each bundle.

On AWS, records go to DynamoDB and bundles to an S3 bucket with Object Lock
(write-once), so nobody, including an admin, can quietly alter the history.
Locally, records go to a JSON-lines file.
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from pathlib import Path

from .bundle import canonical


def make_record(bundle: dict, source_ip: str | None) -> dict:
    m = bundle["manifest"]
    return {
        "id": str(uuid.uuid4()),
        "signed_at": m["signed_at"],
        "document_name": m["document"].get("name", ""),
        "document_sha512": m["document"]["sha512"],
        "signer_email": m["signer"].get("email", ""),
        "signer_subject": m["signer"].get("subject", ""),
        "identity_verified_by": m["signer"].get("verified_by", ""),
        "jurisdiction": m["jurisdiction"],
        "key_fingerprints": [s["key_fingerprint"] for s in bundle["signatures"]],
        "bundle_sha256": hashlib.sha256(canonical(bundle)).hexdigest(),
        "source_ip": source_ip or "",
    }


class AuditLog:
    def record(self, bundle: dict, source_ip: str | None = None) -> dict:
        raise NotImplementedError


class FileAuditLog(AuditLog):
    def __init__(self, path: str | Path):
        self.path = Path(path)

    def record(self, bundle, source_ip=None):
        rec = make_record(bundle, source_ip)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec) + "\n")
        return rec


class AwsAuditLog(AuditLog):
    def __init__(self, table_name: str, bucket: str | None = None):
        import boto3

        self.table = boto3.resource("dynamodb").Table(table_name)
        self.s3 = boto3.client("s3") if bucket else None
        self.bucket = bucket

    def record(self, bundle, source_ip=None):
        rec = make_record(bundle, source_ip)
        if self.s3:
            key = f"bundles/{rec['signed_at'][:10]}/{rec['id']}.qsig.json"
            self.s3.put_object(
                Bucket=self.bucket,
                Key=key,
                Body=json.dumps(bundle, indent=2).encode(),
                ContentType="application/json",
                ChecksumAlgorithm="SHA256",
            )
            rec["archive_key"] = key
        self.table.put_item(Item=rec)
        return rec


def audit_from_env() -> AuditLog:
    table = os.environ.get("QSIGN_AUDIT_TABLE")
    if table:
        return AwsAuditLog(table, os.environ.get("QSIGN_ARCHIVE_BUCKET") or None)
    return FileAuditLog(os.environ.get("QSIGN_AUDIT_FILE", "audit/audit.jsonl"))
