import json

import pytest

from phishguard.feeds import GoogleSafeBrowsing, OpenPhish, StaticFeed, URLhaus, check_feeds
from phishguard.urls import extract_urls


def urls(*raw):
    return extract_urls(" ".join(raw))


def test_openphish_matches_exact_url_and_host():
    feed = OpenPhish(entries=["http://bad.example/login", "https://other.example/x"])
    hits = feed.lookup(urls("http://bad.example/login", "http://other.example/", "http://fine.example/"))
    assert {(h.url, h.detail) for h in hits} == {
        ("http://bad.example/login", "exact URL listed"),
        ("http://other.example/", "host listed"),
    }


def test_openphish_downloads_feed_once():
    calls = []

    def fetch(url, **kw):
        calls.append(url)
        return b"http://listed.example/a\nhttp://listed.example/b\n"

    feed = OpenPhish(fetch=fetch)
    assert feed.lookup(urls("http://listed.example/zzz"))[0].detail == "host listed"
    feed.lookup(urls("http://clean.example/"))
    assert calls == ["https://openphish.com/feed.txt"]


def test_google_safe_browsing_request_and_parse():
    seen = {}

    def fetch(url, data=None, headers=None, **kw):
        seen["url"], seen["body"] = url, json.loads(data)
        return json.dumps({"matches": [{"threatType": "SOCIAL_ENGINEERING", "threat": {"url": "http://bad.example/"}}]}).encode()

    hits = GoogleSafeBrowsing(api_key="k3y", fetch=fetch).lookup(urls("http://bad.example/"))
    assert seen["url"].endswith("key=k3y")
    assert seen["body"]["threatInfo"]["threatEntries"] == [{"url": "http://bad.example/"}]
    assert hits[0].detail == "SOCIAL_ENGINEERING"


def test_google_safe_browsing_without_key_is_reported_unavailable(monkeypatch):
    monkeypatch.delenv("GSB_API_KEY", raising=False)
    res = check_feeds(urls("http://x.example/"), [GoogleSafeBrowsing(fetch=lambda *a, **k: b"{}")])
    assert res.unavailable == ["google_safe_browsing"] and not res.hits


def test_urlhaus_host_lookup():
    def fetch(url, data=None, headers=None, **kw):
        assert b"host=malware.example" in data
        return json.dumps({"query_status": "ok", "urls": [{"url_status": "online"}, {"url_status": "offline"}]}).encode()

    hits = URLhaus(fetch=fetch).lookup(urls("http://malware.example/p.exe"))
    assert hits and "1 online" in hits[0].detail


def test_feed_failure_does_not_raise():
    def boom(*a, **k):
        raise OSError("network down")

    res = check_feeds(urls("http://x.example/"), [OpenPhish(fetch=boom), StaticFeed("s", bad_hosts=["x.example"])])
    assert res.unavailable == ["openphish"]
    assert res.checked == ["s"] and res.hits[0].feed == "s"


@pytest.mark.parametrize("bad", ["x.example", "sub.x.example"])
def test_static_feed_matches_registered_domain(bad):
    assert StaticFeed("s", bad_hosts=["x.example"]).lookup(urls(f"http://{bad}/"))
