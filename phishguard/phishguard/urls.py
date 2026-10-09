"""Extract and normalise URLs from plain text and HTML."""

from __future__ import annotations

import html
import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit

# Scheme-less hosts like "paypal-login.com/verify" are common in SMS, so the
# pattern accepts a bare domain followed by a path, as well as full URLs.
_URL_RE = re.compile(
    r"""(?ix)
    \b(?:
        (?:https?|hxxps?)://[^\s<>"'`)\]]+          # full URL
      | (?:www\.)?[a-z0-9][a-z0-9\-]*(?:\.[a-z0-9\-]+)*\.[a-z]{2,24} # bare host, alphabetic TLD
        (?::\d{2,5})?(?:/[^\s<>"'`)\]]*)?            # optional port and path
    )
    """
)
_HREF_RE = re.compile(r"""<a\b[^>]*?href\s*=\s*["']?([^"'\s>]+)["']?[^>]*>(.*?)</a>""", re.I | re.S)
_TAG_RE = re.compile(r"<[^>]+>")

# Second-level suffixes under which registrations happen one label deeper
# (a small subset of the Public Suffix List, enough for common mail traffic).
_TWO_LEVEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "co.in", "net.in", "org.in", "gov.in",
    "ac.in", "co.jp", "ne.jp", "com.au", "net.au", "org.au", "co.nz", "com.br",
    "com.mx", "com.sg", "com.hk", "co.za", "com.tr", "com.ar", "co.kr", "com.cn",
    "com.tw", "com.my", "com.ph", "com.pk", "com.bd", "com.ng", "co.id", "com.vn",
}

SHORTENERS = {
    "bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rb.gy", "t.ly", "shorturl.at", "tiny.cc", "rebrand.ly", "bl.ink",
    "lnkd.in", "s.id", "v.gd", "qr.ae", "clck.ru", "u.to", "x.co",
}


@dataclass
class FoundURL:
    raw: str
    url: str                      # normalised http(s) URL
    host: str                     # lowercase host without port
    registered_domain: str        # e.g. "paypal.com" for "login.paypal.com"
    scheme: str
    port: int | None = None
    path: str = ""
    anchor_text: str | None = None   # visible text of the <a> tag, if any
    is_ip: bool = False
    is_shortener: bool = False
    flags: list[str] = field(default_factory=list)


def registered_domain(host: str) -> str:
    """Return the registrable part of a host name ("a.b.example.co.uk" -> "example.co.uk")."""
    labels = host.lower().strip(".").split(".")
    if len(labels) < 2:
        return host.lower()
    if len(labels) >= 3 and ".".join(labels[-2:]) in _TWO_LEVEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def normalise(raw: str) -> FoundURL | None:
    text = raw.strip().rstrip(".,;:!?")
    text = html.unescape(text)
    # Defanged URLs (hxxp://) as seen in threat reports.
    text = re.sub(r"(?i)^hxxp", "http", text)
    text = text.replace("[.]", ".").replace("(.)", ".")
    if "://" not in text:
        if re.match(r"^[a-z][a-z0-9+.\-]*:", text, re.I):
            return None  # mailto:, tel:, javascript: and friends
        text = "http://" + text
    try:
        parts = urlsplit(text)
    except ValueError:
        return None
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return None
    host = parts.hostname.lower()
    try:
        host = host.encode("idna").decode("ascii") if any(ord(c) > 127 for c in host) else host
    except UnicodeError:
        return None
    if "." not in host and not host.startswith("["):
        return None
    try:
        port = parts.port
    except ValueError:
        port = None
    is_ip = False
    try:
        ipaddress.ip_address(host.strip("[]"))
        is_ip = True
    except ValueError:
        pass
    flags: list[str] = []
    if parts.username is not None:
        flags.append("credentials_in_url")  # "https://paypal.com@evil.net/"
    if host.startswith("xn--") or ".xn--" in host:
        flags.append("punycode_host")
    if is_ip:
        flags.append("ip_address_host")
    if port and port not in (80, 443):
        flags.append("unusual_port")
    if not is_ip and host.count(".") >= 4:
        flags.append("many_subdomains")
    if len(text) > 200:
        flags.append("very_long_url")
    if re.search(r"%[0-9a-f]{2}", parts.path + parts.query, re.I) and len(parts.path + parts.query) > 60:
        flags.append("heavily_encoded")
    reg = host if is_ip else registered_domain(host)
    netloc = host if port in (None, 80, 443) else f"{host}:{port}"
    url = urlunsplit((parts.scheme, netloc, parts.path or "/", parts.query, ""))
    return FoundURL(
        raw=raw, url=url, host=host, registered_domain=reg, scheme=parts.scheme,
        port=port, path=parts.path or "/", is_ip=is_ip,
        is_shortener=reg in SHORTENERS, flags=flags,
    )


def extract_urls(text: str, html_body: str | None = None) -> list[FoundURL]:
    """Find every URL in plain text and, optionally, an HTML body.

    HTML anchors are matched href-to-text so a link whose visible text is a
    different domain from its real destination is flagged.
    """
    found: dict[str, FoundURL] = {}

    def add(raw: str, anchor: str | None = None) -> None:
        item = normalise(raw)
        if item is None:
            return
        key = item.url
        if key in found:
            if anchor and not found[key].anchor_text:
                found[key].anchor_text = anchor
            return
        item.anchor_text = anchor
        found[key] = item

    if html_body:
        for href, inner in _HREF_RE.findall(html_body):
            anchor = html.unescape(_TAG_RE.sub("", inner)).strip()
            add(href, anchor or None)
            # Visible text may itself look like a URL (the classic "shows
            # bank.com, goes to evil.com" trick).
            shown = normalise(anchor) if anchor else None
            real = normalise(href)
            if shown and real and shown.registered_domain != real.registered_domain:
                found[real.url].flags.append("anchor_text_mismatch")
        for raw in _URL_RE.findall(_TAG_RE.sub(" ", html_body)):
            add(raw)
    for raw in _URL_RE.findall(text or ""):
        add(raw)
    return list(found.values())
