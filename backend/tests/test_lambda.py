"""The Lambda path reads the signer from API Gateway's verified JWT claims."""

import hashlib
import json

from qsign import api
from qsign.audit import FileAuditLog
from qsign.signers import generate_local_keys, load_local_signers


def test_lambda_event_with_jwt_claims(tmp_path, monkeypatch):
    monkeypatch.delenv("QSIGN_ALLOW_UNAUTHENTICATED", raising=False)
    generate_local_keys(tmp_path)
    signers = load_local_signers(tmp_path)
    api.app.dependency_overrides[api.get_signers] = lambda: signers
    api.app.dependency_overrides[api.get_audit] = lambda: FileAuditLog(tmp_path / "a.jsonl")
    from qsign.lambda_handler import handler

    body = {"document": {"name": "x.pdf", "sha512": hashlib.sha512(b"x").hexdigest()}, "consent": True}
    event = {
        "version": "2.0",
        "routeKey": "POST /api/sign",
        "rawPath": "/api/sign",
        "rawQueryString": "",
        "headers": {"content-type": "application/json", "host": "example.execute-api.aws"},
        "requestContext": {
            "http": {"method": "POST", "path": "/api/sign", "protocol": "HTTP/1.1", "sourceIp": "203.0.113.9"},
            "authorizer": {"jwt": {"claims": {"sub": "u-1", "email": "signer@example.com", "iss": "https://cognito-idp.x/pool"}}},
            "stage": "$default",
        },
        "body": json.dumps(body),
        "isBase64Encoded": False,
    }
    try:
        resp = handler(event, None)
    finally:
        api.app.dependency_overrides.clear()
    assert resp["statusCode"] == 200, resp["body"]
    signer = json.loads(resp["body"])["bundle"]["manifest"]["signer"]
    assert signer["email"] == "signer@example.com"
    assert signer["subject"] == "u-1"
