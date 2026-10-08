# QSign: quantum-safe e-signatures on AWS

QSign is an electronic signature platform for organisations. Every signature
is **two signatures at once**:

- **ML-DSA-65**, the post-quantum standard NIST published as FIPS 204 (2024)
- **ECDSA P-384**, today's widely trusted classical signature

Both keys live in **AWS KMS** hardware security modules (FIPS 140-3 Level 3)
and can never be exported. A signature counts only if both parts verify, so it
stays safe even after quantum computers can break today's cryptography.

Licensed under [Apache 2.0](LICENSE). For the legal position in the USA, India
and the EU, read [docs/COMPLIANCE.md](docs/COMPLIANCE.md).

## Features

| | |
|---|---|
| **Envelopes** | Send one document to up to 25 signers, in order or in parallel, with expiry, decline and cancel |
| **Evidence pack** | When everyone has signed, QSign seals the envelope: one file that proves who signed, when, and that nothing was added, removed or swapped |
| **Organisations** | Each company is its own organisation. Admins invite users and read their organisation's audit trail. External signers get guest accounts automatically |
| **Strong sign-in** | Amazon Cognito accounts, authenticator-app MFA required for everyone, invite-only |
| **Privacy** | Documents are hashed in the browser and never uploaded |
| **Tamper-evident records** | Every event goes to DynamoDB, and every signature and evidence pack to S3 Object Lock (write-once, 10 years by default) |
| **Open verification** | Anyone can verify, on the web page or offline with OpenSSL or the `qsign` CLI, without an account |
| **Operations** | Access logs, CloudWatch alarms to email, key rotation without breaking old signatures, Lambda or container deployment |

## How it works

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
| `backend/qsign/api.py` | HTTP API (FastAPI); interactive reference at `/docs` |
| `backend/qsign/static/index.html` | Web app: inbox, send, sign, verify, admin |
| `backend/qsign/cli.py` | `qsign keygen / sign / verify` for offline use |
| `backend/Dockerfile` | Container image for ECS, EKS or on-premises |
| `infra/template.yaml` | AWS SAM stack |
| `scripts/create-org-admin.sh` | Creates the first administrator of a new organisation |
| `docs/` | [Compliance](docs/COMPLIANCE.md), [operations](docs/OPERATIONS.md) and [API](docs/API.md) guides |

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
at `/api/keys`, so you know whose keys they are. Or simply run
`qsign verify contract.pdf contract.pdf.qsig.json --trust <fingerprint>`.

## Security

See [SECURITY.md](SECURITY.md) for the security model and how to report a
vulnerability.
