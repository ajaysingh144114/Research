# QSign Verifier (free, open source)

Check any QSign signature or evidence pack yourself, offline, without a QSign
account and without trusting the service that made it. Courts, auditors and
the other party to a contract can use it freely.

```bash
pip install "cryptography>=48"
python qsign_verify.py contract.pdf contract.pdf.qsig.json
python qsign_verify.py contract.pdf evidence.json --trust <key fingerprint>
```

`VALID` (exit code 0) means:

- every signature in the file verifies, and at least one is post-quantum (ML-DSA);
- the document is exactly the one that was signed;
- for an evidence pack, the completion seal covers exactly these signatures, in this order;
- with `--trust`, the signatures were made with the keys the signing organisation
  published (its QSign `/api/keys` page lists them).

The verifier is one file with one dependency, so it is easy to audit. It is
licensed under the [Apache License 2.0](LICENSE); the rest of QSign is commercial
software.
