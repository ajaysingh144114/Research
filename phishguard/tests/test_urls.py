from phishguard.urls import extract_urls, normalise, registered_domain


def test_registered_domain_handles_two_level_suffixes():
    assert registered_domain("login.paypal.com") == "paypal.com"
    assert registered_domain("mail.sbi.co.in") == "sbi.co.in"
    assert registered_domain("example.co.uk") == "example.co.uk"
    assert registered_domain("localhost") == "localhost"


def test_extracts_full_and_bare_urls_from_text():
    text = "Pay at https://pay.example.com/x and track bit.ly/abc or www.dhl-track.top/parcel."
    urls = {u.url for u in extract_urls(text)}
    assert "https://pay.example.com/x" in urls
    assert "http://bit.ly/abc" in urls
    assert "http://www.dhl-track.top/parcel" in urls
    assert [u for u in extract_urls(text) if u.host == "bit.ly"][0].is_shortener


def test_defanged_and_idn_urls():
    u = normalise("hxxps://evil[.]example/path")
    assert u and u.url == "https://evil.example/path"
    u = normalise("https://pаypal.com/")  # Cyrillic а
    assert u and u.host.startswith("xn--") and "punycode_host" in u.flags


def test_html_anchor_mismatch_flagged():
    body = '<p>Go to <a href="http://evil.example/login">https://www.paypal.com/</a></p>'
    urls = extract_urls("", body)
    evil = [u for u in urls if u.host == "evil.example"][0]
    assert "anchor_text_mismatch" in evil.flags
    assert evil.anchor_text == "https://www.paypal.com/"


def test_ip_credentials_and_port_flags():
    u = normalise("http://user@203.0.113.5:8080/a")
    assert u.is_ip and {"ip_address_host", "credentials_in_url", "unusual_port"} <= set(u.flags)


def test_dedupes_and_ignores_non_urls():
    urls = extract_urls("see example.com/a and http://example.com/a again; version 1.2.3 is out")
    assert len(urls) == 1
    assert normalise("1.2.3") is None or normalise("1.2.3").is_ip is False
    assert normalise("mailto:x@y.com") is None
