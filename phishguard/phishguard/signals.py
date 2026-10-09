"""Fast local checks for phishing and smishing warning signs.

These run on your own computer with no internet and no AWS account. They look
for the tricks attackers use most often (look-alike links, link shorteners,
requests for OTPs or passwords, fake prizes, pressure to act now) and give each
one a weight. The total is the "rule score".
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

# Score thresholds for the rules-only verdict.
SUSPICIOUS_AT = 3
PHISHING_AT = 6

# Brands that scammers impersonate a lot, mapped to the domains they really use.
# A link that mentions the brand but points somewhere else is a strong sign.
OFFICIAL_DOMAINS: dict[str, set[str]] = {
    "paypal": {"paypal.com", "paypal.me"},
    "amazon": {"amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "amazonaws.com", "amzn.to", "a.co"},
    "apple": {"apple.com", "icloud.com"},
    "microsoft": {"microsoft.com", "live.com", "outlook.com", "office.com", "microsoftonline.com"},
    "office365": {"microsoft.com", "office.com", "microsoftonline.com"},
    "google": {"google.com", "gmail.com", "youtube.com"},
    "netflix": {"netflix.com"},
    "facebook": {"facebook.com", "fb.com", "meta.com"},
    "instagram": {"instagram.com"},
    "whatsapp": {"whatsapp.com", "wa.me"},
    "linkedin": {"linkedin.com"},
    "docusign": {"docusign.com", "docusign.net"},
    "dropbox": {"dropbox.com"},
    "usps": {"usps.com"},
    "fedex": {"fedex.com"},
    "dhl": {"dhl.com"},
    "ups": {"ups.com"},
    "irs": {"irs.gov"},
    "chase": {"chase.com"},
    "wellsfargo": {"wellsfargo.com"},
    "bankofamerica": {"bankofamerica.com", "bofa.com"},
    "sbi": {"sbi.co.in", "onlinesbi.sbi", "onlinesbi.com"},
    "hdfc": {"hdfcbank.com", "hdfc.com"},
    "icici": {"icicibank.com"},
    "axis": {"axisbank.com"},
    "paytm": {"paytm.com"},
    "indiapost": {"indiapost.gov.in"},
    "fastag": {"npci.org.in", "ihmcl.co.in"},
    "ezpass": {"e-zpassny.com", "ezpassnj.com", "e-zpassiag.com"},
    "coinbase": {"coinbase.com"},
    "binance": {"binance.com"},
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "ow.ly",
    "shorturl.at", "tiny.cc", "buff.ly", "rebrand.ly", "t.ly", "s.id", "v.gd", "qrco.de",
}

# Cheap or abused top-level domains that show up often in phishing campaigns.
RISKY_TLDS = {
    "xyz", "top", "click", "zip", "mov", "icu", "cyou", "buzz", "rest", "cam", "sbs",
    "cfd", "bond", "quest", "monster", "support", "tk", "ml", "ga", "cf", "gq", "work", "shop",
}

# Two-part country suffixes, so "sbi.co.in" is treated as one site, not "co.in".
TWO_PART_SUFFIXES = {
    "co.in", "gov.in", "org.in", "net.in", "co.uk", "org.uk", "gov.uk", "ac.uk",
    "com.au", "net.au", "co.jp", "com.br", "co.za", "com.sg", "com.mx",
}

DANGEROUS_ATTACHMENTS = re.compile(
    r"\b[\w\-]+\.(zip|rar|7z|iso|img|exe|scr|js|vbs|html?|htm|xlsm|docm|lnk|one|svg)\b", re.I
)

URL_RE = re.compile(
    r"""(?xi)
    \b(
      (?:https?://|hxxps?://|www\.)[^\s<>"')\]]+          # full links
      |
      (?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+         # bare domains like paypa1-login.com/x
      (?:[a-z]{2,24})
      (?:/[^\s<>"')\]]*)?
    )
    """
)

HREF_RE = re.compile(r"""<a\s[^>]*href\s*=\s*["']([^"']+)["'][^>]*>(.*?)</a>""", re.I | re.S)
HEADER_RE = re.compile(r"^(from|reply-to|return-path|subject|to|sender)\s*:\s*(.+)$", re.I | re.M)
EMAIL_ADDR_RE = re.compile(r"[\w.+\-]+@([\w\-]+(?:\.[\w\-]+)+)")


@dataclass
class Finding:
    """One warning sign: a short plain-English reason and how much it counts."""

    reason: str
    weight: int


@dataclass
class SignalReport:
    findings: list[Finding] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)

    @property
    def score(self) -> int:
        return sum(f.weight for f in self.findings)

    @property
    def verdict(self) -> str:
        if self.score >= PHISHING_AT:
            return "phishing"
        if self.score >= SUSPICIOUS_AT:
            return "suspicious"
        return "safe"

    def add(self, reason: str, weight: int) -> None:
        if all(f.reason != reason for f in self.findings):
            self.findings.append(Finding(reason, weight))


def registrable_domain(host: str) -> str:
    """Return the part of a hostname that someone actually registers.

    "secure.login.paypal.com" -> "paypal.com", "www.onlinesbi.sbi" -> "onlinesbi.sbi",
    "netbanking.sbi.co.in" -> "sbi.co.in". Good enough for a prototype; a real
    product should use the Public Suffix List.
    """
    host = host.lower().strip(".")
    parts = host.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in TWO_PART_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _host_of(url: str) -> str:
    url = url.strip().rstrip(".,;:!?")
    url = re.sub(r"^hxxp", "http", url, flags=re.I)
    if not re.match(r"^[a-z]+://", url, re.I):
        url = "http://" + url
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def _deobfuscate(text: str) -> str:
    """Undo common look-alike swaps so 'paypa1' and 'amaz0n' still match."""
    table = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})
    return text.lower().translate(table).replace("rn", "m").replace("vv", "w")


def _mentions_brand(text: str, brand: str) -> bool:
    """True if a hostname or sender name names the brand, including look-alikes like 'paypa1'.

    Short brand names (5 letters or fewer, like 'ups' or 'sbi') must be a whole
    word, so 'groups.google.com' is not read as UPS. Longer names may be glued
    to other words, as in 'paypalsecure-login'.
    """
    words = [w for w in re.split(r"[^a-z0-9@$]+", text.lower()) if w]
    variants = [w for word in words for w in {word, _deobfuscate(word)}]
    if len(brand) <= 5:
        return brand in variants
    return any(v.startswith(brand) or v.endswith(brand) for v in variants) or brand in "".join(
        _deobfuscate(w) for w in words
    )


def _looks_like_file(candidate: str) -> bool:
    return bool(re.search(r"\.(pdf|docx?|xlsx?|pptx?|png|jpe?g|gif|txt|csv)$", candidate, re.I))


def extract_urls(text: str) -> list[str]:
    seen: list[str] = []
    for match in URL_RE.finditer(text):
        candidate = match.group(1).rstrip(".,;:!?")
        before = text[match.start(1) - 1] if match.start(1) > 0 else ""
        if before in "@.-" and before:
            continue  # the domain part of an email address, not a link
        if _looks_like_file(candidate) or DANGEROUS_ATTACHMENTS.fullmatch(candidate):
            continue  # a file name, handled by the attachment check
        if candidate not in seen:
            seen.append(candidate)
    return seen


def _check_host(host: str, raw_url: str, report: SignalReport, check_brand: bool = True) -> None:
    if not host:
        return
    domain = registrable_domain(host)
    tld = host.rsplit(".", 1)[-1]

    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        report.add(f"Link goes to a bare IP address ({host}) instead of a company website", 3)
        return
    if "xn--" in host:
        report.add(f"Link uses a disguised international domain ({host}) that can imitate real letters", 3)
    if domain in URL_SHORTENERS or host in URL_SHORTENERS:
        report.add(f"Link is hidden behind a URL shortener ({host}), so you cannot see where it really goes", 2)
    if tld in RISKY_TLDS:
        report.add(f"Link uses a domain ending (.{tld}) that is cheap and common in scams", 1)
    if host.count(".") >= 4:
        report.add(f"Link has an unusually long chain of sub-domains ({host})", 1)
    if "@" in raw_url.split("://", 1)[-1].split("/")[0]:
        report.add("Link contains an '@' trick that hides the real destination", 3)

    if not check_brand:
        return
    for brand, official in OFFICIAL_DOMAINS.items():
        if _mentions_brand(host, brand) and domain not in official:
            if any(host == d or host.endswith("." + d) for d in official):
                continue
            report.add(
                f"Link mentions {brand} but goes to {domain}, which is not an official {brand} website",
                4,
            )
            break


def _check_headers(text: str, report: SignalReport) -> None:
    headers = {}
    for name, value in HEADER_RE.findall(text):
        headers.setdefault(name.lower(), value.strip())

    from_value = headers.get("from") or headers.get("sender")
    if not from_value:
        return
    from_match = EMAIL_ADDR_RE.search(from_value)
    if not from_match:
        return
    from_domain = registrable_domain(from_match.group(1))
    display = from_value.split("<", 1)[0]

    flagged_display = False
    for brand, official in OFFICIAL_DOMAINS.items():
        if _mentions_brand(display, brand) and from_domain not in official:
            report.add(
                f"Sender name says {brand} but the email address is from {from_domain}", 4
            )
            flagged_display = True
            break
    _check_host(from_match.group(1), from_match.group(1), _SenderOnly(report), check_brand=not flagged_display)

    reply_to = headers.get("reply-to")
    if reply_to:
        reply_match = EMAIL_ADDR_RE.search(reply_to)
        if reply_match and registrable_domain(reply_match.group(1)) != from_domain:
            report.add(
                f"Replies would go to a different domain ({registrable_domain(reply_match.group(1))}) than the sender ({from_domain})",
                2,
            )


class _SenderOnly:
    """Re-label link findings so they read correctly for a sender address."""

    def __init__(self, report: SignalReport) -> None:
        self._report = report

    def add(self, reason: str, weight: int) -> None:
        self._report.add(reason.replace("Link mentions", "Sender address mentions").replace("Link uses", "Sender address uses"), weight)


def _check_html_links(text: str, report: SignalReport) -> None:
    """Catch <a href="evil.com">www.yourbank.com</a>: the text shows one site, the link goes to another."""
    for href, label in HREF_RE.findall(text):
        label_text = re.sub(r"<[^>]+>", "", label).strip()
        label_hosts = [_host_of(u) for u in extract_urls(label_text)]
        href_host = _host_of(href)
        for label_host in label_hosts:
            if label_host and href_host and registrable_domain(label_host) != registrable_domain(href_host):
                report.add(
                    f"A link shows {label_host} but really goes to {href_host}",
                    4,
                )


# (pattern, reason, weight). Patterns are matched case-insensitively.
LANGUAGE_RULES: list[tuple[str, str, int]] = [
    (r"\b(urgent(ly)?|immediately|within \d+ ?(hours?|hrs?|minutes?|mins?)|final (notice|warning|reminder)|last chance|act now|pay now|today only|expires? (today|soon|in))\b",
     "Pushes you to act fast, a classic pressure tactic", 1),
    (r"\b(suspend(ed)?|lock(ed)?|block(ed)?|deactivat(ed|e)|disabl(ed|e)|restrict(ed)?|terminat(ed|e)|clos(ed|e)) (your |the )?(account|card|card account|services?|number|sim|connection)\b|\b(account|card|sim|connection) (has been|will be|is) (suspended|locked|blocked|deactivated|disabled|restricted|terminated|closed|disconnected)\b",
     "Threatens to block or suspend your account or service", 2),
    (r"\b(verify|confirm|update|validate|re-?activate|unlock) (your |the )?(account|identity|details|information|payment|billing|card|kyc|pan|aadhaar|login|password)\b",
     "Asks you to verify or update account, payment or identity details", 2),
    (r"\b(kyc|pan card|aadhaar)\b.*\b(update|expire|expired|pending|block|suspend)|\b(update|expire|expired|pending|block|suspend)\w*\b.*\b(kyc|pan card|aadhaar)\b",
     "Mentions a KYC, PAN or Aadhaar update, a very common Indian SMS scam", 2),
    (r"(?<!not )(?<!never )(?<!n't )\b(share|send|tell|give|forward|reply with) (us |me )?(the |your |this )?(otp|one[- ]time (password|code)|verification code|pin|cvv|password)\b",
     "Asks you to share an OTP, PIN, CVV or password. No real company ever asks for these", 4),
    (r"\b(enter|provide|type) (your )?(card number|cvv|pin|password|otp|net ?banking|login details)\b",
     "Asks you to type card, PIN, password or banking details", 3),
    (r"\b(you('ve| have)? won|winner|lottery|lucky draw|jackpot|prize|free gift|claim (your )?(reward|prize|gift|cashback)|cash ?back of|reward points (will )?expire)\b",
     "Promises a prize, reward or free money", 2),
    (r"\b(refund|tax refund|rebate|compensation)\b.{0,60}\b(claim|click|link|process|receive)\b",
     "Offers a refund you must claim through a link", 2),
    (r"\b(unpaid|outstanding|overdue|pending) (toll|fee|bill|invoice|balance|amount|charges?)|\b(toll|fee|bill|fine|invoice|challan)s? (is |are |remains? )?(unpaid|overdue|outstanding)\b|\b(redelivery|customs|delivery|shipping|handling) (fee|charge|payment)\b|\b(package|parcel|shipment|delivery) (is |has been )?(on hold|held|undeliverable|could not be delivered|failed|returned)\b",
     "Unpaid toll, delivery fee or held parcel story, the most common smishing scams today", 2),
    (r"\b(electricity|power|gas|water) (connection|supply)? ?(will be|is going to be|shall be) (cut|disconnected)|\bdisconnect(ed|ion)? tonight\b",
     "Threatens to cut your electricity or utilities, a common SMS scam", 2),
    (r"\b(gift ?cards?|(itunes|google play|apple|amazon|steam) (gift )?cards?|wire transfer|bitcoin|btc|usdt|crypto ?wallet)\b",
     "Asks for payment in gift cards, wire or crypto, which scammers prefer because it cannot be reversed", 2),
    (r"\b(send|share|text|email) (me |us )?(the |those )?(card |gift card |voucher |redemption )?(codes|pins)\b|\bscratch (off )?the (back|card)\b",
     "Asks you to send gift card or voucher codes", 3),
    (r"\b(dear (customer|user|client|member|account holder|sir/madam|valued customer))\b",
     "Uses a generic greeting instead of your name", 1),
    (r"\b(are you available|i need a (quick )?favou?r|keep this (confidential|between us)|i'?m in a meeting|can you (help|do) me a favou?r)\b",
     "Reads like a 'boss needs a favour' scam (business email compromise)", 2),
    (r"\b(call|contact|dial|ring)\b.{0,40}(\+?\d[\d\s\-()]{8,}\d)\b.{0,60}\b(cancel|dispute|refund|not you|unauthori[sz]ed|didn'?t make)|\b(not you|didn'?t make this|unauthori[sz]ed)\b.{0,80}\b(call|contact|dial)\b",
     "Tells you to call a number to cancel or dispute a charge (callback phishing)", 2),
    (r"\b(scan|use) (the |this )?qr( code)?\b",
     "Asks you to scan a QR code, which hides the real link (quishing)", 2),
    (r"\b(remote (access|desktop)|anydesk|teamviewer|quick ?support|rustdesk)\b",
     "Asks you to install remote-access software", 3),
    (r"\b(download|install) (the |this |our )?(app|apk|update)\b|\.apk\b",
     "Asks you to install an app or APK from a link", 3),
]


def _check_language(text: str, report: SignalReport) -> None:
    for pattern, reason, weight in LANGUAGE_RULES:
        if re.search(pattern, text, re.I | re.S):
            report.add(reason, weight)


def analyze(text: str) -> SignalReport:
    """Run every local check on a message and return what was found."""
    report = SignalReport()
    report.urls = extract_urls(re.sub(r"<[^>]+>", " ", text)) + [
        href for href, _ in HREF_RE.findall(text)
    ]
    # Keep the list unique and in order.
    report.urls = list(dict.fromkeys(report.urls))

    for url in report.urls:
        _check_host(_host_of(url), url, report)

    _check_headers(text, report)
    _check_html_links(text, report)
    _check_language(text, report)

    attachments = sorted({m.group(0) for m in DANGEROUS_ATTACHMENTS.finditer(text)})
    if attachments:
        report.add(
            "Mentions a risky attachment type (" + ", ".join(attachments[:3]) + ") that can carry malware", 2
        )

    has_link = bool(report.urls)
    pressure = any(f.weight >= 2 for f in report.findings if not f.reason.startswith(("Link", "A link")))
    if has_link and pressure:
        report.add("Combines a link with a request or threat, the core pattern of phishing", 1)

    return report
