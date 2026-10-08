# Compliance guide: USA, India and the European Union

This guide explains, in plain language, where QSign stands legally in each
region, what it already does, and what you still need before you can sell it as
a legally recognised signature service. It is a technical guide, **not legal
advice**. Have a lawyer in each market review your service before launch.

## The short version

| | Can QSign signatures be used today? | What is needed for the highest legal level |
|---|---|---|
| **USA** | Yes, for most private contracts. US law is technology neutral. | Nothing extra for most business. Government work also needs FedRAMP and FIPS-validated crypto. |
| **India** | Only as a supporting record. A legally recognised e-signature must come from a CCA-licensed Certifying Authority. | Partner with a licensed eSign Service Provider (ESP) or CA, or get licensed yourself. |
| **EU** | Yes, as an *advanced* electronic signature (AdES), if signers are properly identified. | A *qualified* signature (QES) needs a Qualified Trust Service Provider on the EU Trusted List. |

Two facts sit behind every row:

1. **The cryptography is already government grade.** QSign signs with ML-DSA-65,
   which is NIST FIPS 204 (finalised August 2024). The keys live in AWS KMS
   hardware security modules validated to FIPS 140-3 Level 3.
2. **Legal recognition is about identity and licensing, not only cryptography.**
   A law recognises a signature because a trusted, accountable party checked who
   the signer is. That is the part the licensed providers below add.

## What QSign does today (all regions)

- **Quantum-safe and classical together.** Every document is signed with
  ML-DSA-65 *and* ECDSA P-384. A forger would have to break both. This
  "hybrid" approach is what NIST, the NSA (CNSA 2.0) and European agencies
  (ANSSI, BSI) recommend during the move to post-quantum cryptography.
- **Keys never leave AWS hardware.** Private keys are created inside AWS KMS and
  cannot be exported. Only the Lambda function can ask KMS to sign.
- **Signer identity from a real login.** The signer's name and email come from
  Amazon Cognito after sign-in with a password and an authenticator app (MFA),
  not from anything typed into the form. Accounts are invite-only.
- **Explicit consent.** The signer must tick "I agree to sign electronically",
  and that intent statement is part of what gets signed.
- **Tamper-evident record.** Every signature is written to DynamoDB (with
  point-in-time recovery) and to S3 with Object Lock in *compliance* mode, so
  nobody, not even the AWS account owner, can delete or edit it during the
  retention period (default 10 years).
- **Privacy.** Only a hash of the document reaches the server, never the
  document itself.
- **Independent verification.** Anyone can verify a signature offline with the
  open-source `cryptography` library or OpenSSL 3.5+, without trusting QSign.

---

## USA

**Laws:** the ESIGN Act (2000, federal) and UETA (adopted by 49 states).
Both are technology neutral. An electronic signature is valid if there is
intent to sign, consent to do business electronically, a clear link between
the signature and the record, and a record that can be kept and reproduced.
QSign covers all four.

**Exceptions** where e-signatures are not allowed or need extra steps include
wills, some family-law documents, court orders and certain notices (e.g.
utility shut-off, eviction). Check before using QSign for these.

**Federal government work:**
- **Crypto:** FIPS 204 (ML-DSA) and FIPS 140-3 validated modules. AWS KMS meets both.
- **Post-quantum deadlines:** NSA's CNSA 2.0 asks national security systems to
  prefer quantum-safe signatures now and use them exclusively by 2030–2033.
  NIST's draft transition plan (IR 8547) deprecates RSA and elliptic-curve
  signatures after 2030 and disallows them after 2035. QSign's hybrid design
  lets you drop ECDSA later without changing anything else.
- **Cloud authorisation:** selling to federal agencies needs FedRAMP. Deploying
  QSign in AWS GovCloud (US) and using FedRAMP-authorised services is the usual
  path; the authorisation itself is a separate project.
- **Identity:** agencies expect identity proofing to NIST SP 800-63 (IAL2/AAL2
  or higher). QSign already requires MFA; add an identity-proofing step for this.

## India

**Law:** the Information Technology Act, 2000.
- Section 3 covers *digital signatures* made with a Digital Signature
  Certificate (DSC) from a Certifying Authority licensed by the Controller of
  Certifying Authorities (CCA).
- Section 3A and the Second Schedule cover *electronic signatures*, mainly
  **Aadhaar eSign**, which is offered only by CCA-empanelled eSign Service
  Providers.
- Section 5 gives legal recognition to signatures made in these ways.

**What this means for QSign:** a signature made with QSign's own keys is not a
DSC and not Aadhaar eSign, so it does **not** get the automatic legal
presumption under the IT Act. It is still useful evidence (Indian Evidence Act /
Bharatiya Sakshya Adhiniyam, with a certificate for electronic records), but for
contracts that must be legally recognised you need one of these:

1. **Partner route (fastest):** integrate a CCA-empanelled ESP (for Aadhaar
   eSign) or a licensed CA (for DSC/USB-token signing). QSign then adds its
   ML-DSA signature on top as quantum-safe protection of the same document.
2. **Licence route (slow, costly):** become a licensed CA or an ESP yourself.
   This needs CCA approval, audits and hardware security modules in India.

**Post-quantum status:** India's CCA framework currently specifies RSA and
elliptic-curve certificates. ML-DSA certificates are not yet part of the
licensed-CA system, so the hybrid design matters here: the classical signature
from the licensed provider gives legal validity today, and the ML-DSA signature
protects it against future quantum attacks.

**Data:** the Digital Personal Data Protection Act, 2023 applies to signer
details. Deploy in an Indian AWS region (Mumbai `ap-south-1` or Hyderabad
`ap-south-2`) for Indian customers, collect consent and allow erasure of
personal data where the law permits.

## European Union

**Law:** eIDAS Regulation (EU) No 910/2014, as amended by eIDAS 2 (Regulation
(EU) 2024/1183). It defines three levels:

| Level | Requirements | QSign today |
|---|---|---|
| **Simple (SES)** | Any electronic signature | ✓ |
| **Advanced (AdES)** | Uniquely linked to and able to identify the signer, under the signer's sole control, detects later changes | ✓ when signers have their own Cognito account with MFA and you keep the audit trail. See note below. |
| **Qualified (QES)** | AdES + qualified certificate from a Qualified Trust Service Provider (QTSP) + qualified signature creation device (QSCD) | ✗ needs a QTSP |

A QES has the same legal effect as a handwritten signature in every EU country.
SES and AdES are also admissible as evidence and cannot be refused just because
they are electronic.

**Note on "sole control":** QSign signs with a service key held in KMS, and the
signer authorises it by logging in. Remote signing like this is accepted for
AdES when the provider's controls are strong (the CEN/ETSI remote signing
standards describe how). QSign requires MFA for every account; keep the
Cognito, API access and CloudTrail logs as part of the evidence.

**Getting to QES:** integrate a QTSP's remote signing API (many offer one)
following ETSI EN 319 142 (PAdES) or EN 319 122 (CAdES). The QTSP issues the
qualified certificate and holds the QSCD, and QSign adds its ML-DSA signature
alongside.

**Post-quantum status:** the EU's coordinated PQC roadmap (June 2025) asks
member states to start moving to post-quantum cryptography by the end of 2026
and to protect high-risk systems by 2030. ETSI and European standards for
qualified signatures do not yet broadly include ML-DSA, so for now a hybrid
(classical QES + ML-DSA) is the practical way to be both legally qualified and
quantum-safe.

**Data:** GDPR applies. Use an EU AWS region (e.g. Frankfurt `eu-central-1`)
for EU customers and sign a data processing agreement with each customer.

---

## Roadmap to close the gaps

| Priority | Item | Why |
|---|---|---|
| ✓ | MFA required for every account (done in v0.2) | Needed for EU AdES and US federal identity levels |
| ✓ | Multi-signer envelopes with a sealed evidence pack (done in v0.2) | Shows who signed what, in which order, and that nothing changed |
| 2 | Trusted timestamp (RFC 3161 TSA) on every signature | Proves *when* it was signed, independently of your servers |
| 3 | PDF output (PAdES) with the signature embedded | So Adobe Reader and similar tools show the signature |
| 4 | India: integrate a CCA-empanelled ESP | Legal recognition under the IT Act |
| 5 | EU: integrate a QTSP remote-signing API | Qualified (QES) signatures |
| 6 | X.509 certificates for the ML-DSA key via AWS Private CA | AWS Private CA has issued ML-DSA certificates since November 2025; ties keys to your organisation |
| 7 | FedRAMP / GovCloud deployment | US federal customers |

## Sources

- NIST FIPS 204, Module-Lattice-Based Digital Signature Standard (ML-DSA), August 2024
- AWS KMS developer guide: ML-DSA keys and offline verification
- AWS: "AWS Private CA now supports post-quantum digital certificates" (November 2025)
- NSA, Commercial National Security Algorithm Suite 2.0
- NIST IR 8547 (draft), Transition to Post-Quantum Cryptography Standards
- US ESIGN Act (15 U.S.C. §7001 et seq.) and the Uniform Electronic Transactions Act
- India: Information Technology Act, 2000 (Sections 3, 3A, 5 and the Second Schedule); Controller of Certifying Authorities (cca.gov.in)
- EU: Regulation (EU) No 910/2014 (eIDAS) and Regulation (EU) 2024/1183 (eIDAS 2)
- EU: Coordinated Implementation Roadmap for the transition to Post-Quantum Cryptography, June 2025
