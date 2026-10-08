# Operations guide

How to run QSign in production: deploy, onboard organisations, send email,
monitor, rotate keys and recover.

## 1. Before you deploy

- **AWS account and region.** Use a dedicated AWS account for QSign. Pick the
  region by where your customers' data must stay: Mumbai `ap-south-1` for
  India, Frankfurt `eu-central-1` for the EU, a US region (or GovCloud for
  federal work) for the USA. Check that AWS KMS offers ML-DSA keys there.
- **Tools.** AWS CLI v2 and AWS SAM CLI, signed in with an administrator role.
- **Organisation trail.** Turn on AWS CloudTrail for the account. Every KMS
  `Sign` call is then logged by AWS itself, independently of QSign.

## 2. Deploy

```bash
cd infra
sam build --template template.yaml
sam deploy --guided --stack-name qsign
```

Parameters:

| Parameter | What to set |
|---|---|
| `ArchiveRetentionDays` | How long signatures are locked in S3. Default 3650 (10 years). **Use 1 while testing**: locked objects cannot be deleted before this ends, even by you |
| `SesSenderEmail` | Sender for "please sign" emails, e.g. `sign@yourcompany.com`. Leave empty to send no emails |
| `AlarmEmail` | Who receives operational alarms. Confirm the subscription email AWS sends |
| `AppUrl` | Your custom domain if you add one (section 6). Leave empty to use the API Gateway URL in emails |
| `AllowedOrigin` | Your web domain once you have one; `*` is fine with the built-in web app |
| `LogRetentionDays` | How long access and application logs are kept (default 365) |

The DynamoDB tables, S3 archive and Cognito user pool are protected from
deletion. Deleting the stack keeps them.

## 3. Onboard an organisation

Each customer company is an *organisation* identified by a short id such as
`acme`. Create its first administrator:

```bash
scripts/create-org-admin.sh qsign acme admin@acme.com "Asha Admin"
```

The administrator receives an email with a temporary password. On first sign-in
they choose a password and set up an authenticator app. From then on they invite
their own colleagues from the **Admin** tab.

People outside any organisation who are asked to sign an envelope get a
**guest** account automatically. Guests can sign what was sent to them and use
"Sign myself", but cannot send envelopes.

## 4. Email

- **Invitations** (temporary passwords) are sent by Cognito. Cognito's built-in
  email is limited to a few dozen messages a day. For production, connect
  Cognito to Amazon SES (Cognito console, Messaging, Email).
- **"Please sign" and "completed" emails** are sent through SES when
  `SesSenderEmail` is set. Verify that address or its domain in SES and request
  production access (new SES accounts can only email verified addresses).

## 5. Monitoring

| What | Where |
|---|---|
| Every API request (who, route, status, latency) | CloudWatch log group `ApiAccessLogs` |
| Application errors | CloudWatch log group `/aws/lambda/<function>` |
| Alarms: Lambda errors, throttling, API 5xx | SNS topic `AlarmTopicArn`, emailed to `AlarmEmail` |
| Every signing operation | CloudTrail, KMS `Sign` events |
| Business audit trail | Admin tab, or DynamoDB `AuditTableName` |

## 6. Custom domain

Create an ACM certificate for e.g. `sign.yourcompany.com`, add an API Gateway
custom domain mapped to the stack's HTTP API, point DNS at it, then redeploy with
`AppUrl=https://sign.yourcompany.com` and `AllowedOrigin` set to the same.
For a web application firewall, put Amazon CloudFront with AWS WAF in front of
that domain (HTTP APIs do not attach WAF directly).

## 7. Key rotation

QSign keys do not rotate automatically, because a new key means a new public
fingerprint that verifiers must learn. Rotate on a schedule (for example
yearly) or immediately if you suspect misuse:

1. Note the current fingerprints from `GET /api/keys`.
2. Create new KMS keys (`ML_DSA_65` and `ECC_NIST_P384`, usage `SIGN_VERIFY`).
3. Redeploy with the new key ARNs in `QSIGN_KMS_MLDSA_KEY_ID` /
   `QSIGN_KMS_ECDSA_KEY_ID`, and the old fingerprints, comma-separated, in
   `QSIGN_RETIRED_KEY_FINGERPRINTS`. Old signatures keep showing as trusted.
4. Disable the old KMS keys' signing permission. Never delete them while
   their signatures may be disputed.
5. Publish the new fingerprints to your customers.

## 8. Backup and recovery

| Data | Protection |
|---|---|
| Envelopes and audit records | DynamoDB point-in-time recovery (restore to any second in the last 35 days) and deletion protection |
| Signatures and evidence packs | S3 versioning plus Object Lock in compliance mode |
| Signing keys | AWS KMS (multi-AZ hardware). Keys cannot be exported, so plan rotation instead of backup |
| User accounts | Cognito deletion protection. Export users periodically if you need an offline copy |

## 9. Running as a container

`backend/Dockerfile` builds the same API for ECS/Fargate, EKS or on-premises.
Outside API Gateway, the app checks Cognito tokens itself. Set:

```
QSIGN_MODE=kms
QSIGN_KMS_MLDSA_KEY_ID=...        QSIGN_KMS_ECDSA_KEY_ID=...
QSIGN_AUDIT_TABLE=...             QSIGN_ARCHIVE_BUCKET=...
QSIGN_ENVELOPE_TABLE=...          QSIGN_USER_POOL_ID=...
QSIGN_COGNITO_CLIENT_ID=...       QSIGN_JWT_ISSUER=https://cognito-idp.<region>.amazonaws.com/<pool-id>
QSIGN_AUTO_INVITE_SIGNERS=1       QSIGN_SES_SENDER=...   QSIGN_APP_URL=https://...
```

Give the task role the same permissions as the Lambda function in
`infra/template.yaml`, and terminate TLS at a load balancer.

## 10. Environment variables

| Variable | Meaning |
|---|---|
| `QSIGN_MODE` | `kms` (production) or `local` (key files, development) |
| `QSIGN_ALLOW_UNAUTHENTICATED` | `1` = development mode with self-declared identity. Refused together with `kms` |
| `QSIGN_RETIRED_KEY_FINGERPRINTS` | Old key fingerprints that remain trusted after rotation |
| `QSIGN_AUTO_INVITE_SIGNERS` | `1` = create guest accounts for envelope signers who have none |
| Others | See section 9 |
