# QSign: quantum-safe e-signatures on AWS

QSign is an electronic signature platform for organisations. Every signature
is **two signatures at once**:

- **ML-DSA-65**, the post-quantum standard NIST published as FIPS 204 (2024)
- **ECDSA P-384**, today's widely trusted classical signature

Both keys live in **AWS KMS** hardware security modules (FIPS 140-3 Level 3)
and can never be exported. A signature counts only if both parts verify, so it
stays safe even after quantum computers can break today's cryptography.

QSign is commercial software from Justivia Legal Ventures LLP: every organisation
gets a **30-day free trial**, then a paid subscription (see [Plans](#plans) and
[LICENSE](LICENSE)). The [QSign Verifier](verifier/) is free and open source
(Apache 2.0), so anyone can always check a QSign signature. For the legal position
in the USA, India and the EU, read [docs/COMPLIANCE.md](docs/COMPLIANCE.md).

## Features

| | |
|---|---|
| **Envelopes** | Send one document to up to 25 signers, in order or in parallel, with expiry, decline and cancel |
| **Evidence pack** | When everyone has signed, QSign seals the envelope: one file that proves who signed, when, and that nothing was added, removed or swapped |
| **Organisations** | Each company is its own organisation. Admins invite users and read their organisation's audit trail. External signers get guest accounts automatically |
| **Strong sign-in** | Amazon Cognito accounts, authenticator-app MFA required for everyone, invite-only |
| **Privacy** | Documents are hashed in the browser and never uploaded |
| **Tamper-evident records** | Every event goes to DynamoDB, and every signature and evidence pack to S3 Object Lock (write-once, 10 years by default) |
| **Open verification** | Anyone can verify, on the web page or offline with the free [QSign Verifier](verifier/) or OpenSSL, without an account or subscription |
| **Operations** | Access logs, CloudWatch alarms to email, key rotation without breaking old signatures, Lambda or container deployment |

## How it works

New to QSign? Start with the illustrated guide **[QSign: how it works (PDF)](docs/QSign-How-It-Works.pdf)**. It explains hashes, keys, post-quantum and hybrid signatures, envelopes, verification, security and the law in plain language.

```
 Sender's browser            QSign on AWS                              Signers
 ────────────────            ────────────                              ───────
 hash document  ──create──►  API Gateway (Cognito + MFA) ─► Lambda
                                                              │
                                            envelope ─► DynamoDB     ◄── email "please sign"
                                                              │               │
                             ◄──sign (hash must match)────────┼────── hash same document
                                                              ▼
                                     KMS ML-DSA-65 + KMS ECDSA P-384
                                                              │
                                  per-signer signature + audit event + S3 Object Lock
                                                              │
                                last signer ─► completion seal ─► evidence pack
```

## Repository layout

| Path | What it is |
|---|---|
| `backend/qsign/bundle.py` | What gets signed (the manifest) and signature verification |
| `backend/qsign/envelopes.py` | Multi-signer envelopes, completion seal and evidence-pack verification |
| `backend/qsign/signers.py` | AWS KMS signer, plus a local signer for development |
| `backend/qsign/identity.py`, `jwt_verify.py` | Who is calling: Cognito claims, organisation and admin role |
| `backend/qsign/store.py`, `audit.py`, `services.py` | DynamoDB, audit trail and S3 archive, SES email, Cognito invites |
| `backend/qsign/plans.py` | Free trial and paid plans per organisation |
| `backend/qsign/api.py` | HTTP API (FastAPI); interactive reference at `/docs` |
| `backend/qsign/static/index.html` | Web app: inbox, send, sign, verify, admin |
| `backend/qsign/cli.py` | `qsign keygen / sign / verify` for offline use, `qsign plan` for operators |
| `verifier/` | Free, open-source (Apache 2.0) one-file verifier for anyone |
| `backend/Dockerfile` | Container image for ECS, EKS or on-premises |
| `infra/template.yaml` | AWS SAM stack |
| `scripts/create-org-admin.sh` | Creates the first administrator of a new organisation |
| `docs/` | [How it works (PDF)](docs/QSign-How-It-Works.pdf), [compliance](docs/COMPLIANCE.md), [operations](docs/OPERATIONS.md) and [API](docs/API.md) guides |

## Quick start on your computer (no AWS needed)

```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -e . -r requirements-dev.txt
qsign keygen --dir keys

QSIGN_MODE=local QSIGN_LOCAL_KEY_DIR=keys QSIGN_ALLOW_UNAUTHENTICATED=1 \
  uvicorn qsign.api:app --reload
# open http://127.0.0.1:8000 and "sign in" with any email (development mode)
```

Development mode trusts whatever identity you type and labels every signature
"self-declared (development)". QSign refuses to start in development mode with
KMS keys.

Run the tests with `pytest` in `backend/`.

## Plans

| Plan | What the organisation gets |
|---|---|
| **Trial** | Everything, free for 30 days from the first time a member signs in |
| **Business** / **Enterprise** | Everything, for the paid term; Enterprise adds the terms agreed in the contract |

When a trial or plan ends, the organisation can no longer sign documents or
send new envelopes. Everything else keeps working: envelopes already sent can be
completed, and every signature and evidence pack can still be viewed,
downloaded and verified. Guest signers never need a plan; they sign envelopes
that a paying organisation sent them.

The operator turns a trial into a paid plan with
`qsign plan set acme --plan business --until 2027-12-31` (see
[docs/OPERATIONS.md](docs/OPERATIONS.md#subscriptions)).

## Deploy to AWS

```bash
cd infra
sam build --template template.yaml
sam deploy --guided --stack-name qsign
scripts/create-org-admin.sh qsign acme admin@acme.com "Asha Admin"
```

Then open the **AppUrl** output. Full steps (email sending, custom domain,
alarms, key rotation, backups) are in [docs/OPERATIONS.md](docs/OPERATIONS.md).

## Verifying without QSign

A signature file's signatures cover the canonical JSON of its `manifest`
(keys sorted, no spaces, UTF-8):

```bash
# 1. Rebuild the exact bytes that were signed
python3 -c "import json,sys;b=json.load(open(sys.argv[1]));sys.stdout.buffer.write(json.dumps(b['manifest'],sort_keys=True,separators=(',',':'),ensure_ascii=False).encode())" contract.pdf.qsig.json > manifest.bin

# 2. ML-DSA-65 signature (needs OpenSSL 3.5 or newer)
jq -r '.signatures[0].public_key' contract.pdf.qsig.json | base64 -d > mldsa_pub.der
jq -r '.signatures[0].signature'  contract.pdf.qsig.json | base64 -d > mldsa.sig
openssl dgst -verify mldsa_pub.der -signature mldsa.sig manifest.bin

# 3. ECDSA P-384 signature (any OpenSSL)
jq -r '.signatures[1].public_key' contract.pdf.qsig.json | base64 -d > ecdsa_pub.der
jq -r '.signatures[1].signature'  contract.pdf.qsig.json | base64 -d > ecdsa.sig
openssl dgst -sha384 -verify ecdsa_pub.der -signature ecdsa.sig manifest.bin

# 4. The document must match the signed hash
sha512sum contract.pdf   # compare with manifest.document.sha512
```

Compare each `key_fingerprint` with the fingerprints the organisation publishes
at `/api/keys`, so you know whose keys they are. Or simply run the free verifier:
`python verifier/qsign_verify.py contract.pdf contract.pdf.qsig.json --trust <fingerprint>`
(it also checks evidence packs).

## Security

See [SECURITY.md](SECURITY.md) for the security model and how to report a
vulnerability.
