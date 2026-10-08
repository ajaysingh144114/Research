"""US ESIGN Act §101(c): consumer consent to electronic records.

When a business must give a consumer something "in writing" and wants to do it
electronically, it must first show a disclosure and get the consumer's
electronic consent. An envelope sender switches this on per envelope; each
signer then sees the disclosure and must accept it before signing, and the
signature records exactly which disclosure text they accepted (by SHA-256).

DEFAULT_DISCLOSURE is a starting template. The sender's legal team should
review it and fill in the bracketed parts.
"""

from __future__ import annotations

import hashlib

MAX_DISCLOSURE = 20000

DEFAULT_DISCLOSURE = """\
CONSENT TO ELECTRONIC RECORDS AND SIGNATURES

[Company name] would like to give you the documents for this transaction, and \
ask for your signature, electronically instead of on paper.

1. Paper copies. You may ask for a paper copy of any document at any time by \
writing to [contact email or address]. [Paper copies are free. / A fee of \
[amount] applies.]

2. Withdrawing consent. You may withdraw this consent at any time before you \
sign by choosing "Decline", or afterwards by writing to [contact email]. \
Withdrawing does not affect documents you already signed. [Describe any \
consequences, for example that the transaction will continue on paper.]

3. Scope. This consent covers the documents in this envelope only, unless \
stated otherwise here: [scope].

4. Keeping your contact details up to date. Tell us about a new email address \
by writing to [contact email].

5. What you need. A device with a current web browser (Chrome, Edge, Firefox \
or Safari), an internet connection, an email account, and a way to open and \
save PDF and JSON files. You can save or print this page and the signed \
documents.

By ticking the box below you confirm that you can read this notice on this \
screen, which shows you can access the electronic records we will provide, \
and that you agree to receive and sign them electronically.
"""


def disclosure_record(text: str) -> dict:
    text = text.strip()
    if not text:
        raise ValueError("the consumer disclosure is empty")
    if len(text) > MAX_DISCLOSURE:
        raise ValueError(f"the consumer disclosure is longer than {MAX_DISCLOSURE} characters")
    return {"text": text, "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest()}
