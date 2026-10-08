# API reference

Every running QSign also serves an interactive reference at `/docs` (OpenAPI).
Requests and responses are JSON. Signed-in routes need
`Authorization: Bearer <Cognito ID token>`.

Documents are never sent: clients send the document's SHA-512 as 128 hex
characters (`sha512`).

## Public

| Method and path | Purpose |
|---|---|
| `GET /health` | Liveness check |
| `GET /api/config` | Region, Cognito client id, whether sign-in is required |
| `GET /api/keys` | Active and retired key fingerprints. Publish these so others can trust your signatures |
| `POST /api/verify` | `{"bundle": {...}, "sha512": "..."}` or `{"evidence": {...}, "sha512": "..."}`. Returns `valid`, `trusted_keys`, per-signature results and `errors` |

## Signed-in users

| Method and path | Purpose |
|---|---|
| `GET /api/me` | Email, name, organisation, admin flag |
| `POST /api/sign` | Sign a document yourself. Body: `document {name, size, sha512}`, `consent: true`, optional `reason`, `location`, `jurisdiction` (`US`, `IN`, `EU`, `OTHER`). Returns `bundle` |
| `POST /api/envelopes` | Create an envelope. Body: `title`, `document`, `signers [{email, name}]`, `sequential` (default true), `message`, `expires_in_days` (1-365). Guests cannot send |
| `GET /api/envelopes` | Envelopes you sent or must sign, newest first, with `my_turn` |
| `GET /api/envelopes/{id}` | One envelope |
| `POST /api/envelopes/{id}/sign` | Sign when it is your turn. Body: `sha512` (must match), `consent: true`, optional `reason`, `location`, `jurisdiction` |
| `POST /api/envelopes/{id}/decline` | Decline with an optional `reason`; the envelope stops |
| `POST /api/envelopes/{id}/cancel` | Sender or organisation admin stops an open envelope |
| `GET /api/envelopes/{id}/evidence` | Evidence pack, once completed |

## Organisation administrators

| Method and path | Purpose |
|---|---|
| `POST /api/admin/users` | Invite `{email, name, admin}` into your organisation |
| `GET /api/admin/audit?limit=100` | Your organisation's latest audit events (max 500) |

## Errors

`400` invalid input · `401` not signed in · `403` not allowed · `404` not found
(also returned when you may not see an envelope) · `409` wrong state, not your
turn, or a concurrent change (reload and retry).

## Signature file format (`qsign/1`)

```json
{
  "format": "qsign/1",
  "manifest": {
    "format": "qsign/1",
    "document": {"name": "msa.pdf", "size": 48213, "sha512": "…", "sha3_512": "…"},
    "signer": {"name": "…", "email": "…", "subject": "…", "org_id": "acme", "verified_by": "cognito:https://…"},
    "intent": "I have reviewed this document and I intend to sign it electronically.",
    "reason": "", "location": "", "jurisdiction": "IN",
    "signed_at": "2026-10-08T07:43:29Z",
    "envelope": {"id": "…", "title": "…", "signer_order": 1, "total_signers": 2}
  },
  "signatures": [
    {"alg": "ML-DSA-65", "key_id": "arn:aws:kms:…", "public_key": "<base64 DER>", "key_fingerprint": "<sha256 hex>", "signature": "<base64>"},
    {"alg": "ECDSA-P384-SHA384", "…": "…"}
  ]
}
```

The signed bytes are the manifest serialised as JSON with sorted keys, no
whitespace and UTF-8. An evidence pack (`qsign-evidence/1`) holds the envelope,
each signer's signature file and a completion `seal` in the same format.
