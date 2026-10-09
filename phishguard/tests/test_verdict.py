from phishguard.cli import main
from phishguard.feeds import StaticFeed
from phishguard.verdict import Analyzer
from tests.conftest import SAMPLES, fake_rdap, sample


def test_legit_email_is_safe(offline):
    v = offline.analyse_email(sample("legit_github.eml"))
    assert v.level == "safe", v.reasons
    assert v.score < 10
    assert any("sender authenticated" in r for r in v.reasons)


def test_received_spf_only_email_is_safe(offline):
    v = offline.analyse_email(sample("legit_received_spf.eml"))
    assert v.level == "safe", v.reasons


def test_third_party_newsletter_stays_safe_or_low(offline):
    v = offline.analyse_email(sample("newsletter_unaligned.eml"))
    assert v.level == "safe", v.reasons


def test_paypal_phish_scores_phishing(offline):
    v = offline.analyse_email(sample("phish_paypal.eml"))
    assert v.level == "phishing", v.reasons
    kinds = {d.kind for d in v.domain_findings}
    assert {"brand_subdomain", "homoglyph"} <= kinds
    assert v.auth.dmarc == "fail"
    assert any("anchor text mismatch" in r for r in v.reasons)
    assert any("DMARC failed" in r for r in v.reasons)


def test_spoof_without_auth_headers_is_flagged(offline):
    v = offline.analyse_email(sample("spoof_no_auth.eml"))
    assert v.level in ("likely_phishing", "phishing"), v.reasons
    assert any("shortener" in r for r in v.reasons)
    assert any("homoglyph" in r for r in v.reasons)
    assert any("claims microsoft.com" in r for r in v.reasons)


def test_threat_feed_hit_dominates():
    a = Analyzer(feeds=[StaticFeed("openphish_test", bad_hosts=["known-bad.example"])], rdap=fake_rdap({}))
    v = a.analyse_text("Your parcel is waiting: http://known-bad.example/track")
    assert v.level == "phishing" and v.feed_result.hits[0].feed == "openphish_test"


def test_new_domain_flagged_in_sms():
    a = Analyzer(feeds=[], rdap=fake_rdap({"sbi-kyc-update.com": 2}))
    v = a.analyse_text("SBI: your KYC is pending, update at https://sbi-kyc-update.com/kyc or account blocked")
    kinds = {d.kind for d in v.domain_findings}
    assert "new_domain" in kinds and "brand_keyword" in kinds
    assert v.level in ("likely_phishing", "phishing")


def test_plain_sms_with_known_domain_is_safe():
    a = Analyzer(feeds=[], rdap=fake_rdap({}))
    v = a.analyse_text("Your Amazon order has shipped. Track at https://www.amazon.in/orders")
    assert v.level == "safe" and v.score == 0


def test_feed_unavailable_is_reported_not_fatal():
    class Broken:
        name = "openphish"

        def lookup(self, urls):
            raise OSError("down")

    v = Analyzer(feeds=[Broken()], check_age=False).analyse_text("see http://example.org/x")
    assert v.feed_result.unavailable == ["openphish"]
    assert v.level == "safe"
    assert any("could not be reached" in r for r in v.reasons)


def test_to_dict_is_json_friendly(offline):
    import json
    d = offline.analyse_email(sample("phish_paypal.eml")).to_dict()
    json.dumps(d)
    assert d["auth"]["dmarc"] == "fail" and d["level"] == "phishing"


def test_cli_offline(capsys):
    rc = main(["--offline", "check", str(SAMPLES / "phish_paypal.eml")])
    out = capsys.readouterr().out
    assert rc == 1 and out.startswith("PHISHING")
    rc = main(["--offline", "--json", "text", "hello", "https://github.com/"])
    assert rc == 0 and '"level": "safe"' in capsys.readouterr().out
