"""Threat-feed lookups: Google Safe Browsing, OpenPhish, URLhaus.

Every feed takes an injectable ``fetch`` callable so tests run offline. A
feed that is not configured (no API key) or that fails to answer reports
``available=False`` rather than raising; a missing feed never makes an
email look safe or unsafe on its own.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Callable, Iterable, Protocol

from .urls import FoundURL

Fetch = Callable[..., bytes]


def default_fetch(url: str, data: bytes | None = None, headers: dict | None = None, timeout: float = 8.0) -> bytes:
    req = urllib.request.Request(url, data=data, headers=headers or {}, method="POST" if data else "GET")
    req.add_header("User-Agent", "PhishGuard/0.1 (+https://github.com/ajaysingh144114/Research)")
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed https endpoints
        return resp.read()


@dataclass
class FeedHit:
    feed: str
    url: str
    detail: str = ""


@dataclass
class FeedResult:
    hits: list[FeedHit] = field(default_factory=list)
    checked: list[str] = field(default_factory=list)   # feeds that answered
    unavailable: list[str] = field(default_factory=list)


class Feed(Protocol):
    name: str

    def lookup(self, urls: Iterable[FoundURL]) -> list[FeedHit]: ...


class GoogleSafeBrowsing:
    """Safe Browsing Lookup API v4. Needs an API key (env GSB_API_KEY)."""

    name = "google_safe_browsing"
    endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key="

    def __init__(self, api_key: str | None = None, fetch: Fetch = default_fetch):
        self.api_key = api_key or os.environ.get("GSB_API_KEY")
        self.fetch = fetch

    @property
    def configured(self) -> bool:
        return bool(self.api_key)

    def lookup(self, urls: Iterable[FoundURL]) -> list[FeedHit]:
        if not self.configured:
            raise RuntimeError("GSB_API_KEY not set")
        entries = [{"url": u.url} for u in urls]
        if not entries:
            return []
        body = {
            "client": {"clientId": "phishguard", "clientVersion": "0.1"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": entries,
            },
        }
        raw = self.fetch(
            self.endpoint + urllib.parse.quote(self.api_key),
            data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json"},
        )
        data = json.loads(raw or b"{}")
        return [
            FeedHit(self.name, m.get("threat", {}).get("url", ""), m.get("threatType", ""))
            for m in data.get("matches", [])
        ]


class OpenPhish:
    """OpenPhish community feed: a plain-text list of live phishing URLs."""

    name = "openphish"
    feed_url = "https://openphish.com/feed.txt"

    def __init__(self, fetch: Fetch = default_fetch, cache_seconds: int = 3600, entries: Iterable[str] | None = None):
        self.fetch = fetch
        self.cache_seconds = cache_seconds
        self._entries: set[str] | None = set(entries) if entries is not None else None
        self._hosts: set[str] = set()
        self._loaded_at = 0.0
        if self._entries is not None:
            self._index()

    def _index(self) -> None:
        self._hosts = set()
        for e in self._entries or ():
            host = urllib.parse.urlsplit(e if "://" in e else "http://" + e).hostname
            if host:
                self._hosts.add(host.lower())

    def refresh(self) -> None:
        text = self.fetch(self.feed_url).decode("utf-8", "replace")
        self._entries = {line.strip() for line in text.splitlines() if line.strip()}
        self._loaded_at = time.time()
        self._index()

    def lookup(self, urls: Iterable[FoundURL]) -> list[FeedHit]:
        if self._entries is None or (self._loaded_at and time.time() - self._loaded_at > self.cache_seconds):
            self.refresh()
        hits = []
        for u in urls:
            if u.url in self._entries or u.url.rstrip("/") in self._entries:
                hits.append(FeedHit(self.name, u.url, "exact URL listed"))
            elif u.host in self._hosts:
                hits.append(FeedHit(self.name, u.url, "host listed"))
        return hits


class URLhaus:
    """abuse.ch URLhaus host lookup (malware distribution URLs)."""

    name = "urlhaus"
    endpoint = "https://urlhaus-api.abuse.ch/v1/host/"

    def __init__(self, fetch: Fetch = default_fetch, auth_key: str | None = None):
        self.fetch = fetch
        self.auth_key = auth_key or os.environ.get("URLHAUS_AUTH_KEY")

    def lookup(self, urls: Iterable[FoundURL]) -> list[FeedHit]:
        hits = []
        seen: set[str] = set()
        for u in urls:
            if u.host in seen:
                continue
            seen.add(u.host)
            headers = {"Content-Type": "application/x-www-form-urlencoded"}
            if self.auth_key:
                headers["Auth-Key"] = self.auth_key
            raw = self.fetch(self.endpoint, data=urllib.parse.urlencode({"host": u.host}).encode(), headers=headers)
            data = json.loads(raw or b"{}")
            if data.get("query_status") == "ok" and data.get("urls"):
                online = [x for x in data["urls"] if x.get("url_status") == "online"]
                hits.append(FeedHit(self.name, u.url, f"{len(data['urls'])} malware URLs on host, {len(online)} online"))
        return hits


class StaticFeed:
    """A feed backed by an in-memory set, for tests and private blocklists."""

    def __init__(self, name: str, bad_hosts: Iterable[str] = (), bad_urls: Iterable[str] = ()):
        self.name = name
        self.bad_hosts = {h.lower() for h in bad_hosts}
        self.bad_urls = set(bad_urls)

    def lookup(self, urls: Iterable[FoundURL]) -> list[FeedHit]:
        return [
            FeedHit(self.name, u.url, "listed")
            for u in urls
            if u.url in self.bad_urls or u.host in self.bad_hosts or u.registered_domain in self.bad_hosts
        ]


def default_feeds(fetch: Fetch = default_fetch) -> list[Feed]:
    feeds: list[Feed] = [OpenPhish(fetch=fetch), URLhaus(fetch=fetch)]
    gsb = GoogleSafeBrowsing(fetch=fetch)
    if gsb.configured:
        feeds.insert(0, gsb)
    return feeds


def check_feeds(urls: list[FoundURL], feeds: Iterable[Feed]) -> FeedResult:
    result = FeedResult()
    if not urls:
        return result
    for feed in feeds:
        try:
            result.hits.extend(feed.lookup(urls))
            result.checked.append(feed.name)
        except (urllib.error.URLError, OSError, ValueError, RuntimeError, TimeoutError):
            result.unavailable.append(feed.name)
    return result
