# Selling QSign in the USA: what buyers require

Checked October 2026. This is a technical and business guide, **not legal
advice**. Have a US government-contracts lawyer confirm the federal points
before you bid.

## The short answer

| Buyer | Can they buy QSign today? | What stands in the way |
|---|---|---|
| **US private companies** (general business) | **Yes, legally.** ESIGN and UETA accept QSign signatures. | Their security teams will ask for proof: a SOC 2 Type II report, a penetration test, answers to a security questionnaire and insurance. |
| **Regulated companies** (pharma, banks, lenders, healthcare) | Partly. | Extra rules on consumer consent (ESIGN §101(c)), FDA 21 CFR Part 11, HIPAA. Some of these need product changes (listed below). |
| **US federal government** | **Not yet.** | FedRAMP authorisation. The Trade Agreements Act, because India is not a "designated country". SAM.gov registration. Section 508 accessibility. NSA's CNSA 2.0 needs ML-DSA-87 for national security systems. |
| **State and local government** | Possible case by case. | Many states ask for GovRAMP (formerly StateRAMP) or SOC 2, plus accessibility. |

The cryptography is already "government grade". ML-DSA is NIST FIPS 204, and
AWS KMS keeps every key in FIPS 140-3 Level 3 validated hardware. What US
buyers mostly need now is **independent proof** that the company and the
service are run securely.

---

## 1. Requirements in the law (all US buyers)

### ESIGN Act and UETA: signatures are valid
QSign already meets the core tests:
- intent to sign (consent box, signed into the record);
- a link between the signature and the record (document hash in the manifest);
- a record that can be kept and reproduced (evidence pack, 10-year write-once archive).

### ESIGN §101(c): consumer consent (gap, fix in the product)
When a business must give a **consumer** a document "in writing" and wants to
do it electronically, it must first show the consumer a clear disclosure, then
get electronic consent. The disclosure covers:
- the right to a paper copy, and any fee for one;
- the right to withdraw consent, and what happens if they do;
- which records the consent covers;
- how to update contact details;
- the hardware and software needed to open and keep the records.

The consent must be given in a way that shows the consumer can open the
electronic records. Banks, lenders, insurers and landlords will not use a
signing tool without this.

**Done in QSign 0.4:** the sender ticks "Signers are consumers" and edits the
provided disclosure template. Each signer must read and accept it on screen
before signing; the signature records the SHA-256 of the exact text accepted,
and evidence verification fails if the text is later changed. Withdrawing
consent before signing is the existing "Decline" button. Have a lawyer approve
your disclosure wording.

### FDA 21 CFR Part 11 (pharma, medical devices, labs)
| Rule | QSign today | Needed |
|---|---|---|
| 11.10 secure, time-stamped audit trail | ✓ audit table and write-once archive | — |
| 11.50 signature shows printed name, date and time, and **meaning** (review, approval, authorship…) | ✓ (0.4) every signature carries a chosen meaning, shown when verifying | — |
| 11.70 signature cannot be copied to another record | ✓ the hash ties it to one document | — |
| 11.100 unique to one person; identity verified first | ✓ invite-only Cognito accounts | Customer certifies to the FDA (their job) |
| 11.200 two components (ID and password); every signing outside one continuous session uses all of them | ✓ (0.4) set `SigningReauthMinutes` (for example 5) and signers re-enter password and code before signing | Test against your real Cognito pool before go-live |
| 11.300 password ageing, lost-token handling, alerts on misuse | Partly (Cognito policies, MFA) | Configure password expiry, lockout alerts; document the procedure |

### HIPAA (healthcare)
QSign never receives documents, only their hashes, which limits health data
exposure. Signer names and emails can still be protected health information in
context. Healthcare buyers will ask you to sign a **Business Associate
Agreement**. AWS signs one with you for the services QSign uses.

---

## 2. What enterprise security teams ask for (industry standard)

These are not laws, but almost every US company with a procurement process asks
for them before buying a security product.

| Item | What it is | Status |
|---|---|---|
| **SOC 2 Type II report** | An independent auditor checks your security controls over 3 to 12 months. The most-requested document in US SaaS sales. | **Not started.** Tools such as Vanta, Drata or Secureframe help prepare. |
| **Penetration test** | An outside firm tries to break in and gives you a report you can share. Usually yearly. | Not started. |
| **Security questionnaire** (SIG Lite or CAIQ) | A standard set of 100+ questions. Having one pre-filled saves weeks per deal. | Not started. SECURITY.md and the PDF guide cover much of it. |
| **Data processing agreement and US data region** | Contract terms for personal data (CCPA in California). Data kept in a US AWS region. | Region: ✓ (you choose it at deploy). DPA: needs a lawyer. |
| **Cyber and E&O insurance** | Buyers often require $1–5 million cover. | Not started. |
| **Uptime and support terms (SLA)** | Promised availability and response times. | Not written. |
| **Accessibility (WCAG 2.1 AA) and a VPAT** | Proof that disabled people can use the web app. | Not tested. |

## 3. Federal government

| Requirement | What it means for QSign |
|---|---|
| **FedRAMP** | Cloud services sold to federal agencies need FedRAMP. Under the new **FedRAMP 20x** process, new Class B and C pipelines opened on 31 August 2026. Class A is a transitional tier, and a recent SOC 2 Type II helps you qualify for it. So **SOC 2 is also the first step towards FedRAMP.** New Rev5 applications stop on 11 June 2027. |
| **Trade Agreements Act (TAA)** | For GSA Schedule sales (and most federal buys above $174,000), software must come from the USA or a "designated country". **India is not one.** Origin generally follows where the software is developed, compiled and tested, not where it is hosted. Options: do substantial development in the USA or a designated country, sell under the threshold, or sell to buyers TAA does not cover. **Confirm with a GSA or TAA lawyer.** |
| **SAM.gov registration** | Every federal vendor needs a Unique Entity ID. A US entity (for example a Delaware LLC or corporation) makes this, banking and contracts much easier. |
| **CNSA 2.0** (NSA) | For national security systems, signatures must use **ML-DSA-87**, and cloud services must use CNSA 2.0 exclusively by 2033. ✓ (0.4) deploy with `PostQuantumAlgorithm=ML-DSA-87`. |
| **FIPS 140-3 validated crypto** | ✓ Signing happens inside AWS KMS (FIPS 140-3 Level 3). Deploy in AWS GovCloud (US) for federal work. |
| **Section 508** | Accessibility is mandatory for federal purchases; a VPAT is expected. |

---

## 4. Recommended order

1. **Product changes** (done in QSign 0.4): ESIGN consumer disclosure, signature
   meaning, re-authentication at signing, ML-DSA-87 option.
2. **Start SOC 2 Type II now.** It opens US enterprise sales and counts towards FedRAMP 20x.
3. **Penetration test** and a **pre-filled security questionnaire**.
4. **Contracts:** DPA, SLA, BAA template, cyber insurance; consider a US entity.
5. **Accessibility** review and a VPAT.
6. **Federal:** get a TAA legal opinion, register in SAM.gov, then FedRAMP 20x.
   Sell to US businesses and state governments first while this runs.

## Sources

- ESIGN §101(c) consumer consent: FDIC Compliance Manual X-3.1, https://www.fdic.gov/regulations/compliance/manual/10/x-3.1.pdf
- 21 CFR Part 11 text: https://www.ecfr.gov/current/title-21/chapter-I/subchapter-A/part-11
- FedRAMP 20x timeline (vendor summary; confirm on fedramp.gov): https://secureframe.com/blog/fedramp-20x
- CNSA 2.0 FAQ summary: https://postquantum.com/security-pqc/nsa-cnsa-2-0-faq-v2-1-update/
- TAA and India, 2026 threshold (vendor summary; confirm with counsel): https://www.sledai.com/blog/taa-compliance-guide/
- TAA software origin, CBP rulings: https://www.dwt.com/blogs/government-contracts-insider/2016/12/substantial-transformation-of-it-products-under-th
- AWS KMS ML-DSA (44/65/87, FIPS 140-3 Level 3 HSMs): https://docs.aws.amazon.com/kms/latest/developerguide/mldsa.html
