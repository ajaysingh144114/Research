import json

import pytest

from phishguard.domains import LookalikeDetector, check_domain_ages, levenshtein, rdap_domain_age, skeleton
from phishguard.urls import extract_urls
from tests.conftest import fake_rdap


@pytest.fixture
def det():
    return LookalikeDetector(allow=["justivia.com"])


def kinds(det, host):
    return {f.kind for f in det.check_host(host)}


def test_skeleton_maps_homoglyphs():
    assert skeleton("paypa1") == "paypal"
    assert skeleton("rnicrosoft") == "microsoft"
    assert skeleton("xn--pypal-4ve") == "paypal"  # pаypal with Cyrillic а


def test_levenshtein():
    assert levenshtein("paypal", "paypal") == 0
    assert levenshtein("paypal", "paypol") == 1
    assert levenshtein("amazon", "amazn") == 1


@pytest.mark.parametrize("host,kind", [
    ("paypa1.com", "homoglyph"),
    ("rnicrosoft.com", "homoglyph"),
    ("xn--pypal-4ve.com", "homoglyph"),
    ("paypol.com", "typosquat"),
    ("microsfot.com", "typosquat"),
    ("paypal.com.verify-account.net", "brand_subdomain"),
    ("secure.netflix.billing-update.info", "brand_subdomain"),
    ("paypal-secure-login.com", "brand_keyword"),
    ("hdfcbank-kyc.com", "brand_keyword"),
])
def test_lookalikes_detected(det, host, kind):
    assert kind in kinds(det, host), det.check_host(host)


@pytest.mark.parametrize("host", [
    "paypal.com", "www.paypal.com", "login.microsoft.com", "netbanking.hdfcbank.com",
    "github.com", "justivia.com", "mail.justivia.com", "example-shop.com",
])
def test_real_domains_not_flagged(det, host):
    assert not kinds(det, host)


def test_suspicious_tld_and_idn_are_low_severity(det):
    f = det.check_host("parcel-update.top")
    assert {x.kind for x in f} >= {"suspicious_tld"} and all(x.severity == 1 for x in f)
    assert "idn_domain" in kinds(det, "xn--80ak6aa92e.com")


def test_check_domain_ages_flags_new_and_reports_unknown():
    urls = extract_urls("http://brand-new.example/ http://old.example/ http://unknown.example/ http://paypal.com/")
    findings, unknown = check_domain_ages(urls, lookup=fake_rdap({"brand-new.example": 3, "unknown.example": None}))
    assert [(f.domain, f.kind, f.severity) for f in findings] == [("brand-new.example", "new_domain", 3)]
    assert unknown == ["unknown.example"]


def test_rdap_parse():
    def fetch(url, **kw):
        assert url == "https://rdap.org/domain/fresh.example"
        return json.dumps({"events": [{"eventAction": "registration", "eventDate": "2026-10-01T00:00:00Z"}]}).encode()

    from datetime import datetime, timezone
    age = rdap_domain_age("www.fresh.example", fetch=fetch, now=datetime(2026, 10, 9, tzinfo=timezone.utc))
    assert age.age_days == 8
