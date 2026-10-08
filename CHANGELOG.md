# Changelog

## 0.3.0

- QSign is now commercial software under the QSign Commercial Licence, with a 30-day free trial per organisation and paid Business and Enterprise plans. Versions up to 0.2.0 stay available under Apache 2.0.
- New free, open-source (Apache 2.0) QSign Verifier in `verifier/`: one file that checks signatures and evidence packs offline. Tests keep it in step with the platform.
- Plans are enforced on signing and sending; viewing, verifying and finishing envelopes already sent always work.
- Guest accounts sign envelopes sent to them but no longer sign their own documents.
- `GET /api/plan`, trial banner in the web app, and `qsign plan show / set` for operators.

## 0.2.0

- Multi-signer envelopes: ordered or parallel signing, expiry, decline, cancel.
- Completion seal and evidence pack, with tamper checks in verification.
- Organisations and roles: organisation admins invite users and read their audit trail; guest accounts for external signers.
- Sign-in hardening: MFA (authenticator app) required, invite-only accounts, organisation attribute not editable by users.
- In-app Cognito token verification for container deployments; Dockerfile.
- Key rotation: retired key fingerprints stay trusted.
- AWS: envelope table, audit index by organisation, API access logs, CloudWatch alarms with email, SES notifications.
- Web app rebuilt: inbox, send, sign, decline, evidence download, verify, admin.
- Docs: operations, API and security guides. Apache 2.0 license.

## 0.1.0

- Hybrid ML-DSA-65 + ECDSA P-384 signatures with AWS KMS, Cognito sign-in, audit table and S3 Object Lock archive, CLI and web page.
