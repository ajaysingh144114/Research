"""Combine URL, feed, domain and sender-authentication signals into one verdict."""

from __future__ import annotations

import email
import email.policy
from dataclasses import dataclass, field
from email.message import Message
from typing import Iterable

from .auth import AuthResult, authenticate
from .domains import DEFAULT_BRANDS, DomainFinding, LookalikeDetector, RdapLookup, check_domain_ages, rdap_domain_age
from .feeds import Feed, FeedResult, check_feeds, default_feeds
from .urls import FoundURL, extract_urls

LEVELS = ("safe", "suspicious", "likely_phishing", "phishing")


@dataclass
class Verdict:
    score: int                       # 0 (clean) .. 100 (certain phishing)
    level: str                       # one of LEVELS
    reasons: list[str] = field(default_factory=list)
    urls: list[FoundURL] = field(default_factory=list)
    feed_result: FeedResult = field(default_factory=FeedResult)
    domain_findings: list[DomainFinding] = field(default_factory=list)
    unchecked_domains: list[str] = field(default_factory=list)
    auth: AuthResult | None = None

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "level": self.level,
            "reasons": self.reasons,
            "urls": [
                {"url": u.url, "host": u.host, "domain": u.registered_domain, "flags": u.flags,
                 "anchor_text": u.anchor_text, "shortener": u.is_shortener}
                for u in self.urls
            ],
            "feeds": {
                "hits": [{"feed": h.feed, "url": h.url, "detail": h.detail} for h in self.feed_result.hits],
                "checked": self.feed_result.checked,
                "unavailable": self.feed_result.unavailable,
            },
            "domains": [
                {"domain": d.domain, "kind": d.kind, "detail": d.detail, "brand": d.brand, "severity": d.severity}
                for d in self.domain_findings
            ],
            "unchecked_domains": self.unchecked_domains,
            "auth": None if self.auth is None else {
                "spf": self.auth.spf, "dkim": self.auth.dkim, "dmarc": self.auth.dmarc,
                "from_domain": self.auth.from_domain, "spf_domain": self.auth.spf_domain,
                "dkim_domains": self.auth.dkim_domains, "spf_aligned": self.auth.spf_aligned,
                "dkim_aligned": self.auth.dkim_aligned, "dmarc_aligned": self.auth.dmarc_aligned,
                "reply_to_domain": self.auth.reply_to_domain, "problems": self.auth.problems,
            },
        }


def level_for(score: int) -> str:
    if score >= 80:
        return "phishing"
    if score >= 55:
        return "likely_phishing"
    if score >= 25:
        return "suspicious"
    return "safe"


class Analyzer:
    """Reusable analyser; construct once with feeds and brand lists, call many times.

    ``feeds=None`` uses the live feeds (OpenPhish, URLhaus and Google Safe
    Browsing when ``GSB_API_KEY`` is set). ``check_age=False`` skips the RDAP
    lookup; otherwise ``rdap`` can be swapped for a cached or mocked lookup.
    """

    def __init__(
        self,
        feeds: Iterable[Feed] | None = None,
        brands: dict[str, list[str]] | None = None,
        allow_domains: Iterable[str] = (),
        check_age: bool = True,
        rdap: RdapLookup = rdap_domain_age,
        new_domain_days: int = 30,
    ):
        self.feeds = list(feeds) if feeds is not None else default_feeds()
        self.brands = brands or DEFAULT_BRANDS
        self.allow = list(allow_domains)
        self.lookalike = LookalikeDetector(self.brands, allow=self.allow)
        self.check_age = check_age
        self.rdap = rdap
        self.new_domain_days = new_domain_days

    # -- link checks -------------------------------------------------------
    def analyse_urls(self, urls: list[FoundURL]) -> Verdict:
        score = 0
        reasons: list[str] = []
        feed_result = check_feeds(urls, self.feeds)
        flagged = {h.url for h in feed_result.hits}
        if feed_result.hits:
            score += 85
            for h in feed_result.hits[:3]:
                reasons.append(f"link {h.url} is listed by {h.feed} ({h.detail})")
        for name in feed_result.unavailable:
            reasons.append(f"threat feed {name} could not be reached, link reputation incomplete")

        findings = self.lookalike.check_urls(urls)
        unchecked: list[str] = []
        if self.check_age and urls:
            age_findings, unchecked = check_domain_ages(
                urls, lookup=self.rdap, max_age_days=self.new_domain_days, allow=self.allow,
            )
            findings.extend(age_findings)
        for f in findings:
            score += {3: 45, 2: 25, 1: 8}[f.severity]
            reasons.append(f"domain {f.domain}: {f.kind.replace('_', ' ')} ({f.detail})")

        for u in urls:
            if u.url in flagged:
                continue
            for flag in u.flags:
                weight = {
                    "anchor_text_mismatch": 40, "credentials_in_url": 45, "ip_address_host": 30,
                    "punycode_host": 10, "unusual_port": 15, "many_subdomains": 10,
                    "very_long_url": 5, "heavily_encoded": 10,
                }.get(flag, 5)
                score += weight
                reasons.append(f"link {u.url}: {flag.replace('_', ' ')}")
            if u.is_shortener:
                score += 10
                reasons.append(f"link {u.url} uses a URL shortener, destination hidden")
            if u.scheme == "http" and not u.is_ip:
                score += 3
        return Verdict(min(score, 100), level_for(min(score, 100)), reasons, urls, feed_result, findings, unchecked)

    # -- sender checks -----------------------------------------------------
    @staticmethod
    def score_auth(auth: AuthResult) -> tuple[int, list[str]]:
        score = 0
        reasons: list[str] = []
        if "display_name_impersonates_brand" in auth.problems:
            score += 45
            reasons.append(f"sender name claims {auth.display_name_brand_mismatch} but address is {auth.from_domain}")
        if auth.dmarc == "fail" or ("dmarc_fail" in auth.problems):
            score += 40
            reasons.append("DMARC failed: the sender could not prove it owns the From: domain")
        elif auth.spf in ("fail", "permerror"):
            score += 30
            reasons.append(f"SPF {auth.spf}: sending server not allowed for {auth.spf_domain or auth.from_domain}")
        elif auth.spf == "softfail":
            score += 15
            reasons.append("SPF softfail: sending server is doubtful for this domain")
        if auth.dkim in ("fail", "permerror"):
            score += 25
            reasons.append("DKIM signature failed: message altered or forged")
        if "spf_pass_but_unaligned" in auth.problems and "dkim_pass_but_unaligned" in auth.problems:
            score += 25
            reasons.append(f"SPF and DKIM pass for other domains, not for From: {auth.from_domain}")
        elif "spf_pass_but_unaligned" in auth.problems and auth.dkim != "pass":
            score += 20
            reasons.append(f"SPF passes for {auth.spf_domain}, which is not the From: domain {auth.from_domain}")
        if auth.reply_to_mismatch:
            score += 15
            reasons.append(f"replies go to {auth.reply_to_domain}, not to {auth.from_domain}")
        if "no_authentication_headers" in auth.problems:
            score += 10
            reasons.append("no SPF, DKIM or DMARC results in headers; sender unverified")
        if auth.spf == "none" and auth.dkim == "none" and "no_authentication_headers" not in auth.problems:
            score += 8
            reasons.append("sender domain publishes no SPF or DKIM; cannot be verified")
        if auth.dmarc_aligned and score == 0:
            reasons.append(f"sender authenticated: DMARC-aligned {'DKIM' if auth.dkim_aligned else 'SPF'} pass for {auth.from_domain}")
        return score, reasons

    # -- entry points ------------------------------------------------------
    def analyse_text(self, text: str, html_body: str | None = None) -> Verdict:
        """Score an SMS, chat message or plain body with no email headers."""
        return self.analyse_urls(extract_urls(text, html_body))

    def analyse_message(self, msg: Message) -> Verdict:
        text_parts, html_parts = [], []
        for part in msg.walk():
            if part.get_content_maintype() != "text":
                continue
            try:
                payload = part.get_content()
            except (KeyError, LookupError, UnicodeDecodeError):
                payload = part.get_payload(decode=True)
                payload = payload.decode("utf-8", "replace") if isinstance(payload, bytes) else str(payload)
            (html_parts if part.get_content_subtype() == "html" else text_parts).append(payload)
        urls = extract_urls("\n".join(text_parts), "\n".join(html_parts) or None)
        v = self.analyse_urls(urls)
        auth = authenticate(msg, self.brands)
        auth_score, auth_reasons = self.score_auth(auth)
        v.auth = auth
        # Link findings and sender findings reinforce each other, so a forged
        # sender plus a lookalike link scores higher than either alone.
        combined = v.score + auth_score + (10 if v.score >= 25 and auth_score >= 15 else 0)
        subject = (msg.get("Subject") or "").lower()
        if any(w in subject for w in ("urgent", "suspended", "verify", "action required", "unusual activity", "locked", "expire")):
            combined += 5
            auth_reasons.append("subject uses pressure words")
        v.score = min(combined, 100)
        v.level = level_for(v.score)
        v.reasons = v.reasons + auth_reasons
        return v

    def analyse_email(self, raw: bytes | str) -> Verdict:
        if isinstance(raw, str):
            msg = email.message_from_string(raw, policy=email.policy.default)
        else:
            msg = email.message_from_bytes(raw, policy=email.policy.default)
        return self.analyse_message(msg)


def analyse_text(text: str, html_body: str | None = None, **kwargs) -> Verdict:
    return Analyzer(**kwargs).analyse_text(text, html_body)


def analyse_email(raw: bytes | str, **kwargs) -> Verdict:
    return Analyzer(**kwargs).analyse_email(raw)
