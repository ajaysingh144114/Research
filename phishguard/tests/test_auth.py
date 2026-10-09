import email
import email.policy

from phishguard.auth import authenticate, parse_authentication_results
from phishguard.domains import DEFAULT_BRANDS
from tests.conftest import sample


def parse(name):
    return email.message_from_bytes(sample(name), policy=email.policy.default)


def test_parse_authentication_results_props():
    ar = parse_authentication_results([
        "mx.google.com; dkim=pass header.i=@github.com header.s=pf2023; spf=pass smtp.mailfrom=noreply@github.com; dmarc=pass header.from=github.com"
    ])
    assert ar["dkim"]["result"] == "pass" and ar["dkim"]["header.i"] == "@github.com"
    assert ar["spf"]["smtp.mailfrom"] == "noreply@github.com"
    assert ar["dmarc"]["header.from"] == "github.com"


def test_legit_github_fully_aligned():
    a = authenticate(parse("legit_github.eml"), DEFAULT_BRANDS)
    assert (a.spf, a.dkim, a.dmarc) == ("pass", "pass", "pass")
    assert a.from_domain == "github.com" and a.spf_domain == "github.com"
    assert a.dkim_domains == ["github.com"]
    assert a.spf_aligned and a.dkim_aligned and a.dmarc_aligned
    assert a.problems == []


def test_spoofed_paypal_fails_dmarc_and_has_reply_to_mismatch():
    a = authenticate(parse("phish_paypal.eml"), DEFAULT_BRANDS)
    assert a.spf == "pass" and a.spf_aligned is False
    assert a.dmarc == "fail"
    assert a.reply_to_mismatch and a.reply_to_domain == "secure-mail-help.net"
    assert {"spf_pass_but_unaligned", "dmarc_fail", "reply_to_other_domain"} <= set(a.problems)


def test_no_auth_headers_and_display_name_brand():
    a = authenticate(parse("spoof_no_auth.eml"), DEFAULT_BRANDS)
    assert "no_authentication_headers" in a.problems
    assert a.display_name_brand_mismatch == "microsoft.com"


def test_received_spf_fallback():
    a = authenticate(parse("legit_received_spf.eml"), DEFAULT_BRANDS)
    assert a.spf == "pass" and a.spf_domain == "hdfcbank.com" and a.spf_aligned
    assert a.display_name_brand_mismatch is None


def test_third_party_sender_with_aligned_dkim_passes():
    a = authenticate(parse("newsletter_unaligned.eml"), DEFAULT_BRANDS)
    assert a.spf_aligned is False and a.dkim_aligned is True
    assert a.dmarc_aligned
    assert "spf_pass_but_unaligned" in a.problems and "dmarc_fail" not in a.problems


def test_dmarc_derived_when_not_reported():
    msg = email.message_from_string(
        "Authentication-Results: mx; spf=pass smtp.mailfrom=other.net; dkim=fail header.d=brand.com\n"
        "From: a@brand.com\nSubject: x\n\nbody", policy=email.policy.default)
    a = authenticate(msg)
    assert a.dmarc == "fail" and "dkim_fail" in a.problems
