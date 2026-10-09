"""Lookalike (typosquat, homoglyph, brand-in-subdomain) and new-domain checks."""

from __future__ import annotations

import json
import re
import urllib.error
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Iterable

from .feeds import Fetch, default_fetch
from .urls import FoundURL, registered_domain

# Brands most often impersonated in phishing and smishing. Operators can
# extend this with their own domains (their bank, their company, ...).
DEFAULT_BRANDS = {
    "paypal.com": ["paypal"],
    "apple.com": ["apple", "icloud"],
    "icloud.com": ["icloud"],
    "microsoft.com": ["microsoft", "office365", "outlook"],
    "live.com": ["outlook", "hotmail"],
    "google.com": ["google", "gmail"],
    "amazon.com": ["amazon"],
    "amazon.in": ["amazon"],
    "netflix.com": ["netflix"],
    "facebook.com": ["facebook"],
    "instagram.com": ["instagram"],
    "whatsapp.com": ["whatsapp"],
    "linkedin.com": ["linkedin"],
    "dhl.com": ["dhl"],
    "fedex.com": ["fedex"],
    "ups.com": ["ups"],
    "usps.com": ["usps"],
    "chase.com": ["chase"],
    "wellsfargo.com": ["wellsfargo"],
    "bankofamerica.com": ["bankofamerica"],
    "citi.com": ["citibank"],
    "hsbc.com": ["hsbc"],
    "sbi.co.in": ["onlinesbi", "sbi"],
    "hdfcbank.com": ["hdfcbank", "hdfc"],
    "icicibank.com": ["icicibank", "icici"],
    "axisbank.com": ["axisbank"],
    "irctc.co.in": ["irctc"],
    "incometax.gov.in": ["incometax"],
    "coinbase.com": ["coinbase"],
    "binance.com": ["binance"],
    "docusign.com": ["docusign"],
    "dropbox.com": ["dropbox"],
    "adobe.com": ["adobe"],
    "zoom.us": ["zoom"],
}

# Characters that look like ASCII letters (a very small confusables table).
HOMOGLYPHS = {
    "0": "o", "1": "l", "3": "e", "5": "s", "7": "t", "@": "a", "$": "s",
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y",
    "х": "x", "і": "i", "ј": "j", "һ": "h", "ԁ": "d", "ԛ": "q",
    "ɡ": "g", "ο": "o", "α": "a", "ε": "e", "ρ": "p",
    "‐": "-", "‑": "-", "à": "a", "á": "a", "è": "e", "é": "e",
    "ì": "i", "í": "i", "ò": "o", "ó": "o", "ù": "u", "ú": "u",
}
_MULTI_HOMOGLYPHS = {"rn": "m", "vv": "w", "cl": "d", "nn": "m"}

SUSPICIOUS_TLDS = {
    "zip", "mov", "top", "xyz", "club", "work", "click", "link", "gq", "ml", "cf", "tk", "ga",
    "buzz", "rest", "icu", "cam", "monster", "quest", "cfd", "sbs", "lol", "bond", "cyou",
}

_KEYWORD_RE = re.compile(
    r"(secure|login|signin|verify|verification|update|account|support|billing|wallet|"
    r"unlock|suspend|kyc|refund|reward|prize|otp|password|confirm|alert|helpdesk)"
)


@dataclass
class DomainFinding:
    domain: str
    kind: str        # homoglyph, typosquat, brand_subdomain, brand_keyword, suspicious_tld, new_domain, ...
    detail: str
    brand: str | None = None
    severity: int = 2  # 1 low, 2 medium, 3 high


@dataclass
class DomainAge:
    domain: str
    registered: datetime | None
    age_days: int | None
    source: str = "rdap"


def skeleton(label: str) -> str:
    """Map a label to its plain-ASCII look-alike form ("раура1" -> "paypal")."""
    if label.startswith("xn--"):
        try:
            label = label[4:].encode("ascii").decode("punycode")
        except (UnicodeError, ValueError):
            pass
    out = "".join(HOMOGLYPHS.get(c, c) for c in label.lower())
    for multi, single in _MULTI_HOMOGLYPHS.items():
        out = out.replace(multi, single)
    return out


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _sld(domain: str) -> str:
    """Second-level label: "paypal" for "paypal.com" or "paypal.co.uk"."""
    return registered_domain(domain).split(".")[0]


class LookalikeDetector:
    def __init__(self, brands: dict[str, list[str]] | None = None, allow: Iterable[str] = ()):
        self.brands = brands or DEFAULT_BRANDS
        self.allow = {registered_domain(d) for d in allow} | set(self.brands)

    def check_host(self, host: str) -> list[DomainFinding]:
        host = host.lower()
        reg = registered_domain(host)
        if reg in self.allow:
            return []
        findings: list[DomainFinding] = []
        sld = _sld(reg)
        sld_skel = skeleton(sld)
        raw_sld_is_ascii = sld.isascii()
        tld = reg.rsplit(".", 1)[-1]

        for brand_domain, names in self.brands.items():
            brand_sld = _sld(brand_domain)
            # 1. Homoglyph: "paypa1.com", "pаypal.com" (Cyrillic а), "rnicrosoft.com".
            if sld != brand_sld and sld_skel == brand_sld:
                findings.append(DomainFinding(reg, "homoglyph", f"'{sld}' looks like '{brand_sld}'", brand_domain, 3))
                break
            # 2. Typosquat: one edit away from the brand (two for long names).
            if raw_sld_is_ascii and sld != brand_sld and len(brand_sld) >= 5:
                limit = 1 if len(brand_sld) < 8 else 2
                if levenshtein(sld, brand_sld) <= limit:
                    findings.append(DomainFinding(reg, "typosquat", f"'{sld}' is a misspelling of '{brand_sld}'", brand_domain, 3))
                    break
            for name in names:
                # 2b. Brand hidden by look-alike characters inside a longer name:
                #     "paypa1-secure.com", "netfl1x-billing.com".
                if name in sld_skel and name not in sld:
                    findings.append(DomainFinding(reg, "homoglyph", f"'{sld}' spells '{name}' with look-alike characters", brand_domain, 3))
                    break
                # 3. Brand name in a subdomain: "paypal.com.verify-account.net".
                sub = host[: -len(reg)].rstrip(".") if host.endswith(reg) and host != reg else ""
                if sub and (name in skeleton(sub)):
                    findings.append(DomainFinding(reg, "brand_subdomain", f"'{name}' appears before the real domain '{reg}'", brand_domain, 3))
                    break
                # 4. Brand plus keyword in the registered name: "paypal-secure-login.com".
                if name in sld_skel and sld_skel != name and (
                    _KEYWORD_RE.search(sld_skel) or "-" in sld or len(sld_skel) - len(name) <= 3
                ):
                    findings.append(DomainFinding(reg, "brand_keyword", f"'{sld}' contains brand '{name}'", brand_domain, 2))
                    break
            if findings:
                break

        if tld in SUSPICIOUS_TLDS:
            findings.append(DomainFinding(reg, "suspicious_tld", f".{tld} is heavily abused by phishing", None, 1))
        if not reg.isascii() or reg.startswith("xn--") or ".xn--" in reg:
            findings.append(DomainFinding(reg, "idn_domain", "internationalised domain name (punycode)", None, 1))
        if _KEYWORD_RE.search(sld_skel) and sld_skel.count("-") >= 1 and not findings:
            findings.append(DomainFinding(reg, "urgent_keyword_domain", f"'{sld}' uses login/verify style words", None, 1))
        return findings

    def check_urls(self, urls: Iterable[FoundURL]) -> list[DomainFinding]:
        out: list[DomainFinding] = []
        seen: set[str] = set()
        for u in urls:
            if u.is_ip or u.host in seen:
                continue
            seen.add(u.host)
            out.extend(self.check_host(u.host))
        return out


RdapLookup = Callable[[str], DomainAge]


def rdap_domain_age(domain: str, fetch: Fetch = default_fetch, now: datetime | None = None) -> DomainAge:
    """Registration date from the public RDAP bootstrap service (rdap.org)."""
    raw = fetch(f"https://rdap.org/domain/{registered_domain(domain)}")
    data = json.loads(raw or b"{}")
    registered = None
    for ev in data.get("events", []):
        if ev.get("eventAction") == "registration" and ev.get("eventDate"):
            try:
                registered = datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
            except ValueError:
                pass
    if registered is None:
        return DomainAge(domain, None, None)
    if registered.tzinfo is None:
        registered = registered.replace(tzinfo=timezone.utc)
    now = now or datetime.now(timezone.utc)
    return DomainAge(domain, registered, max(0, (now - registered).days))


def check_domain_ages(
    urls: Iterable[FoundURL],
    lookup: RdapLookup = rdap_domain_age,
    max_age_days: int = 30,
    allow: Iterable[str] = (),
    max_lookups: int = 10,
) -> tuple[list[DomainFinding], list[str]]:
    """Flag domains registered less than ``max_age_days`` ago.

    Returns (findings, domains_that_could_not_be_checked).
    """
    findings: list[DomainFinding] = []
    unknown: list[str] = []
    allow = {registered_domain(d) for d in allow} | set(DEFAULT_BRANDS)
    seen: set[str] = set()
    for u in urls:
        reg = u.registered_domain
        if u.is_ip or reg in seen or reg in allow:
            continue
        if len(seen) >= max_lookups:
            break
        seen.add(reg)
        try:
            age = lookup(reg)
        except (urllib.error.URLError, OSError, ValueError, TimeoutError):
            unknown.append(reg)
            continue
        if age.age_days is None:
            unknown.append(reg)
        elif age.age_days < max_age_days:
            findings.append(DomainFinding(reg, "new_domain", f"registered {age.age_days} days ago", None, 3 if age.age_days < 7 else 2))
    return findings, unknown
