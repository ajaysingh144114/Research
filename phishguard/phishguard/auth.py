"""Parse SPF, DKIM and DMARC outcomes from email headers.

Reads ``Authentication-Results`` (RFC 8601), ``Received-SPF`` (RFC 7208),
``DKIM-Signature`` and ``ARC-Authentication-Results`` headers, then checks
DMARC-style alignment between the visible From: domain, the SPF envelope
domain and the DKIM signing domain.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from email.message import Message
from email.utils import getaddresses, parseaddr

from .urls import registered_domain

_RESULT_WORDS = "pass|fail|softfail|neutral|none|temperror|permerror|policy|bestguesspass"
_AR_METHOD_RE = re.compile(rf"\b(spf|dkim|dmarc|arc)\s*=\s*({_RESULT_WORDS})\b", re.I)
_PROP_RE = re.compile(r"\b(header\.from|header\.d|header\.i|smtp\.mailfrom|smtp\.helo|envelope-from|header\.s)\s*=\s*([^\s;()]+)", re.I)
_RECEIVED_SPF_RE = re.compile(rf"^\s*({_RESULT_WORDS})\b", re.I)
_DKIM_TAG_RE = re.compile(r"\b([a-z]+)\s*=\s*([^;]*)", re.I)


@dataclass
class AuthResult:
    spf: str = "none"             # pass/fail/softfail/neutral/none/temperror/permerror
    dkim: str = "none"
    dmarc: str = "none"
    from_domain: str | None = None
    spf_domain: str | None = None     # smtp.mailfrom or envelope-from domain
    dkim_domains: list[str] = field(default_factory=list)   # d= of passing signatures
    dkim_signed_domains: list[str] = field(default_factory=list)  # d= of all DKIM-Signature headers
    spf_aligned: bool | None = None
    dkim_aligned: bool | None = None
    reply_to_domain: str | None = None
    reply_to_mismatch: bool = False
    display_name_brand_mismatch: str | None = None
    authserv_id: str | None = None
    headers_seen: list[str] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)

    @property
    def dmarc_aligned(self) -> bool:
        """DMARC passes when SPF or DKIM passes *and* aligns with From:."""
        return bool((self.spf == "pass" and self.spf_aligned) or (self.dkim == "pass" and self.dkim_aligned))


def _domain_of(addr: str | None) -> str | None:
    if not addr:
        return None
    addr = addr.strip().strip("<>").lower()
    if "@" in addr:
        addr = addr.rsplit("@", 1)[1]
    return addr.strip(".") or None


def _aligned(a: str | None, b: str | None, strict: bool = False) -> bool | None:
    if not a or not b:
        return None
    if strict:
        return a == b
    return registered_domain(a) == registered_domain(b)


def _unfold(value: str) -> str:
    return re.sub(r"\s+", " ", value or "")


def parse_authentication_results(values: list[str]) -> dict[str, dict[str, str]]:
    """Return {method: {"result": ..., "header.from": ..., ...}} from one or more A-R headers.

    When several headers report the same method, the first (outermost, added
    by the receiving MTA) wins, which is the one that matters for the recipient.
    """
    out: dict[str, dict[str, str]] = {}
    for value in values:
        value = _unfold(value)
        # Split into the authserv-id and each "method=result props" stanza.
        parts = [p.strip() for p in value.split(";") if p.strip()]
        for part in parts:
            m = _AR_METHOD_RE.match(part)
            if not m:
                continue
            method, result = m.group(1).lower(), m.group(2).lower()
            if method in out:
                continue
            props = {k.lower(): v.strip('"').lower() for k, v in _PROP_RE.findall(part)}
            props["result"] = result
            out[method] = props
    return out


def parse_dkim_signature(value: str) -> dict[str, str]:
    return {k.lower(): v.strip() for k, v in _DKIM_TAG_RE.findall(_unfold(value))}


def authenticate(msg: Message, brand_names: dict[str, list[str]] | None = None) -> AuthResult:
    res = AuthResult()
    from_name, from_addr = parseaddr(msg.get("From", ""))
    res.from_domain = _domain_of(from_addr)
    if not res.from_domain:
        res.problems.append("missing_from_domain")

    ar_values = msg.get_all("Authentication-Results", []) + msg.get_all("ARC-Authentication-Results", [])
    ar = parse_authentication_results(ar_values)
    if ar_values:
        res.headers_seen.append("Authentication-Results")
        first = _unfold(ar_values[0]).split(";", 1)[0].strip()
        res.authserv_id = first.split()[0] if first else None

    if "spf" in ar:
        res.spf = ar["spf"]["result"]
        res.spf_domain = _domain_of(ar["spf"].get("smtp.mailfrom") or ar["spf"].get("envelope-from"))
    elif msg.get("Received-SPF"):
        res.headers_seen.append("Received-SPF")
        rs = _unfold(msg["Received-SPF"])
        m = _RECEIVED_SPF_RE.match(rs)
        res.spf = m.group(1).lower() if m else "none"
        pm = re.search(r"envelope-from=([^\s;]+)", rs, re.I)
        res.spf_domain = _domain_of(pm.group(1)) if pm else None
    if not res.spf_domain:
        res.spf_domain = _domain_of(msg.get("Return-Path"))

    sigs = [parse_dkim_signature(v) for v in msg.get_all("DKIM-Signature", [])]
    if sigs:
        res.headers_seen.append("DKIM-Signature")
    res.dkim_signed_domains = [s["d"].lower() for s in sigs if s.get("d")]
    if "dkim" in ar:
        res.dkim = ar["dkim"]["result"]
        d = ar["dkim"].get("header.d") or _domain_of(ar["dkim"].get("header.i"))
        if res.dkim == "pass":
            res.dkim_domains = [d] if d else list(res.dkim_signed_domains)
    elif sigs:
        res.problems.append("dkim_signature_unverified")

    if "dmarc" in ar:
        res.dmarc = ar["dmarc"]["result"]

    res.spf_aligned = _aligned(res.spf_domain, res.from_domain)
    res.dkim_aligned = any(_aligned(d, res.from_domain) for d in res.dkim_domains) if res.dkim_domains else None
    if res.dmarc == "none" and ar:
        # No DMARC verdict recorded: derive one from alignment so the verdict
        # still reflects whether the sender could prove the From: domain.
        res.dmarc = "pass" if res.dmarc_aligned else ("fail" if (res.spf != "none" or res.dkim != "none") else "none")

    if res.spf == "pass" and res.spf_aligned is False:
        res.problems.append("spf_pass_but_unaligned")
    if res.dkim == "pass" and res.dkim_aligned is False:
        res.problems.append("dkim_pass_but_unaligned")
    if res.spf in ("fail", "softfail", "permerror"):
        res.problems.append(f"spf_{res.spf}")
    if res.dkim in ("fail", "permerror"):
        res.problems.append(f"dkim_{res.dkim}")
    if res.dmarc == "fail":
        res.problems.append("dmarc_fail")
    if not ar_values and not msg.get("Received-SPF") and not sigs:
        res.problems.append("no_authentication_headers")

    reply_to = [a for _, a in getaddresses(msg.get_all("Reply-To", []))]
    if reply_to:
        res.reply_to_domain = _domain_of(reply_to[0])
        if res.from_domain and res.reply_to_domain and not _aligned(res.reply_to_domain, res.from_domain):
            res.reply_to_mismatch = True
            res.problems.append("reply_to_other_domain")

    # "PayPal <alerts@random-host.net>": display name claims a brand the domain is not.
    brands = brand_names or {}
    if from_name and res.from_domain:
        lowered = re.sub(r"[^a-z0-9]", "", from_name.lower())
        for brand_domain, names in brands.items():
            if any(n in lowered for n in names) and registered_domain(res.from_domain) != registered_domain(brand_domain):
                res.display_name_brand_mismatch = brand_domain
                res.problems.append("display_name_impersonates_brand")
                break
    return res
