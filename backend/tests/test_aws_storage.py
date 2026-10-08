"""DynamoDB envelope store and AWS audit log, against moto's AWS emulator."""

import json

import boto3
import pytest

moto = pytest.importorskip("moto")


@pytest.fixture()
def aws(monkeypatch):
    monkeypatch.setenv("AWS_DEFAULT_REGION", "ap-south-1")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    with moto.mock_aws():
        ddb = boto3.client("dynamodb")
        ddb.create_table(
            TableName="env",
            AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"},
                                  {"AttributeName": "sk", "AttributeType": "S"}],
            KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
            BillingMode="PAY_PER_REQUEST",
        )
        ddb.create_table(
            TableName="audit",
            AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"},
                                  {"AttributeName": "org_id", "AttributeType": "S"},
                                  {"AttributeName": "at", "AttributeType": "S"}],
            KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
            GlobalSecondaryIndexes=[{
                "IndexName": "by_org",
                "KeySchema": [{"AttributeName": "org_id", "KeyType": "HASH"}, {"AttributeName": "at", "KeyType": "RANGE"}],
                "Projection": {"ProjectionType": "ALL"},
            }],
            BillingMode="PAY_PER_REQUEST",
        )
        boto3.client("s3").create_bucket(Bucket="archive", CreateBucketConfiguration={"LocationConstraint": "ap-south-1"})
        yield


def envelope(i, creator="a@x.co", signers=("b@y.co",)):
    return {"id": f"e{i}", "created_at": f"2026-01-0{i}T00:00:00Z", "title": f"T{i}",
            "created_by": {"email": creator}, "signers": [{"email": s} for s in signers]}


def test_dynamo_store_round_trip_and_locking(aws):
    from qsign.store import Conflict, DynamoEnvelopeStore, NotFound

    store = DynamoEnvelopeStore("env")
    store.create(envelope(1))
    store.create(envelope(2, signers=("c@z.co",)))
    with pytest.raises(Conflict):
        store.create(envelope(1))

    assert [e["id"] for e in store.list_for("a@x.co")] == ["e2", "e1"]
    assert [e["id"] for e in store.list_for("B@Y.CO")] == ["e1"]

    first, second = store.get("e1"), store.get("e1")
    first["title"] = "changed"
    store.save(first)
    assert store.get("e1")["title"] == "changed" and store.get("e1")["version"] == 2
    with pytest.raises(Conflict):
        store.save(second)
    with pytest.raises(NotFound):
        store.get("nope")


def test_aws_audit_log_archives_and_queries_by_org(aws):
    from qsign.audit import AwsAuditLog

    log = AwsAuditLog("audit", "archive")
    rec = log.event("envelope.completed", org_id="acme", actor="a@x.co", archive={"hello": "world"},
                    envelope_id="e1")
    log.event("user.invited", org_id="other", actor="b@y.co")
    body = boto3.client("s3").get_object(Bucket="archive", Key=rec["archive_key"])["Body"].read()
    assert json.loads(body) == {"hello": "world"}
    rows = log.list_for_org("acme")
    assert [r["event"] for r in rows] == ["envelope.completed"]
