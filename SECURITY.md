# Security

## Reporting a vulnerability

Please do not open a public GitHub issue. Report it privately through GitHub:
the repository's **Security** tab, then **Report a vulnerability**. Include
steps to reproduce. We aim to acknowledge reports within 3 business days.

## Security model

**What a QSign signature proves.** That the holder of the organisation's QSign
keys signed a manifest containing the document's SHA-512 hash (plus SHA3-512 from the CLI),
the signer's verified identity, the time, the signer's consent statement and
(for envelopes) the envelope and signing order. It does not embed the document.

**Keys.** ML-DSA-65 and ECDSA P-384 keys are generated inside AWS KMS and cannot
be exported. Only the QSign function's IAM role may call `kms:Sign` on them, and
every call is recorded in CloudTrail.

**Hybrid rule.** A signature is valid only if every signature in it verifies and
at least one is post-quantum. Breaking ECDSA alone (for example with a future
quantum computer) or ML-DSA alone is not enough to forge one.

**Identity.** Signer identity comes only from verified Cognito tokens: checked by
API Gateway's JWT authorizer, or by the app itself (RS256, issuer, audience,
expiry, token use) when run as a container. Request bodies cannot set identity.
Organisation membership is a Cognito attribute that users cannot change
themselves. MFA (authenticator app) is required for every account.

**Authorisation.** Envelopes are visible only to their sender, their signers and
administrators of the sender's organisation; everyone else gets "not found".
Signers can act only on their own turn, and only by presenting the hash of the
exact document in the envelope. Concurrent changes are rejected (optimistic
locking).

**Evidence integrity.** Each completed envelope gets a completion seal over the
digests of all signer signatures. Removing, adding, reordering or swapping a
signature breaks the seal. Signatures and evidence packs are written to S3 with
Object Lock in compliance mode.

**Privacy.** Documents never leave the user's device; the server sees only
hashes, names, email addresses and the optional reason and location text.

**Development mode** (`QSIGN_ALLOW_UNAUTHENTICATED=1`) accepts self-declared
identity for local testing. Signatures made in it are labelled as such, and the
app refuses to start in that mode with KMS keys.

## Known limits

- Signing time comes from the server clock. Add an RFC 3161 timestamp authority
  for independent proof of time (roadmap).
- Signatures are detached JSON, not embedded in PDFs (PAdES is on the roadmap).
- HTTP APIs cannot attach AWS WAF directly; use CloudFront with WAF in front of a
  custom domain for internet-facing deployments.
