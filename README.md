# QSign: quantum-safe e-signatures on AWS

QSign signs documents with **two signatures at once**:

- **ML-DSA-65**, the post-quantum signature standard NIST published as FIPS 204 in 2024
- **ECDSA P-384**, today's widely trusted classical signature

Both keys live in **AWS KMS** hardware security modules and can never be
exported. A signature is accepted only if both parts check out, so it stays
safe even after large quantum computers can break today's cryptography.

For what this means legally in the USA, India and the EU, read
[docs/COMPLIANCE.md](docs/COMPLIANCE.md).

## How it works

```
Browser                          AWS
───────                          ───
1. Pick document
2. SHA-512 hash computed here ─► API Gateway ─► checks Cognito login
   (file never uploaded)              │
                                      ▼
                                 Lambda (QSign)
                                 builds a manifest:
                                 hash + signer + time + intent
                                      │
                       ┌──────────────┼──────────────┐
                       ▼              ▼              ▼
                  KMS ML-DSA-65  KMS ECDSA P-384  DynamoDB audit
                       └──────┬───────┘          + S3 Object Lock
                              ▼                    (write-once)
3. Download contract.pdf.qsig.json  ◄── signature bundle
```

The `.qsig.json` file is a *detached signature*: keep it next to the document.
Anyone can verify it with the web page, the command line, or any library
that supports ML-DSA (for example OpenSSL 3.5+).

## Repository layout

| Path | What it is |
|---|---|
| `backend/qsign/bundle.py` | What gets signed (the manifest) and how a bundle is verified |
| `backend/qsign/signers.py` | AWS KMS signer and a local signer for development |
| `backend/qsign/api.py` | HTTP API (FastAPI) and the web page |
| `backend/qsign/cli.py` | `qsign keygen / sign / verify` command line |
| `backend/qsign/static/index.html` | Sign and verify page |
| `infra/template.yaml` | AWS SAM template: KMS keys, Cognito, API Gateway, Lambda, DynamoDB, S3 |
| `docs/COMPLIANCE.md` | USA, India and EU legal guide and roadmap |

## Try it on your computer (no AWS needed)

```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -e . pytest httpx

qsign keygen --dir keys
qsign sign contract.pdf --name "Your Name" --email you@example.com --jurisdiction IN
qsign verify contract.pdf contract.pdf.qsig.json
```

Run the web app locally in development mode, where the signer types their own
name and email (labelled "self-declared" in the signature):

```bash
QSIGN_MODE=local QSIGN_LOCAL_KEY_DIR=keys QSIGN_ALLOW_UNAUTHENTICATED=1 \
  uvicorn qsign.api:app --reload
# open http://127.0.0.1:8000
```

Run the tests:

```bash
pytest
```

## Deploy to AWS

Requirements: an AWS account, the [AWS SAM CLI](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/install-sam-cli.html)
and a region where KMS supports ML-DSA keys.

```bash
cd infra
sam build --template template.yaml
sam deploy --guided --stack-name qsign
```

After deployment:

1. Open the **AppUrl** output in a browser.
2. In the Cognito console, open the **UserPoolId** output and create a user for
   each signer (self sign-up is switched off, so only people you add can sign).
3. Sign a test document, then verify it on the **Verify** tab.

What the stack creates:

| Resource | Purpose |
|---|---|
| KMS key `ML_DSA_65` | Post-quantum signing key |
| KMS key `ECC_NIST_P384` | Classical signing key |
| Cognito user pool | Signer accounts; identity in each signature comes from here |
| HTTP API + Lambda | Sign (login required), verify, public keys |
| DynamoDB table | One audit record per signature (point-in-time recovery on) |
| S3 bucket with Object Lock (compliance mode) | Write-once copy of every signature bundle |

The archive bucket and audit table are kept if you delete the stack, and
locked bundles cannot be deleted until their retention period ends (default
10 years, `ArchiveRetentionDays`). Use a short retention while testing.

## Verifying without QSign

A bundle's signatures cover the canonical JSON of its `manifest`
(keys sorted, no spaces, UTF-8). To check it with OpenSSL:

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

Also compare each `key_fingerprint` (SHA-256 of the public key) with the
fingerprints the signer publishes at `/api/keys`, so you know whose keys they are.

## Security notes

- Signing requires a Cognito login checked by API Gateway; the signer's identity
  is taken from the verified token, never from the request body.
- The Lambda role may only call `kms:Sign` and `kms:GetPublicKey` on the two
  QSign keys, write audit rows and add archive objects.
- Development mode (`QSIGN_ALLOW_UNAUTHENTICATED=1`) must never be set in AWS.
- Local key files are created with owner-only permissions and are git-ignored.

## Roadmap

MFA, trusted timestamps (RFC 3161), PDF-embedded signatures (PAdES),
India eSign / EU qualified-signature provider integration and ML-DSA X.509
certificates from AWS Private CA. Details in [docs/COMPLIANCE.md](docs/COMPLIANCE.md#roadmap-to-close-the-gaps).
