# PhishGuard: link and sender checks

Pure-Python checks that answer two questions about an email or text message:

1. **Are the links dangerous?** Every URL is extracted (plain text, HTML, SMS
   style bare domains, defanged `hxxp://` forms), then checked against live
   threat feeds and against lookalike and new-domain rules.
2. **Is the sender who it says it is?** SPF, DKIM and DMARC results are read
   from the headers and checked for DMARC alignment with the visible From: address.

Both feed one score from 0 to 100 with a level of `safe`, `suspicious`,
`likely_phishing` or `phishing`, plus plain-English reasons.

No third-party packages are needed. Python 3.11 or newer.

## Quick start

```bash
cd phishguard
pip install -e .
phishguard check message.eml            # a saved email
phishguard text "Your parcel is held, pay at dhl-track.top/pay"   # an SMS
phishguard --json check message.eml     # full result as JSON
phishguard --offline check message.eml  # no network: rules and headers only
```

From Python:

```python
from phishguard import analyse_email, analyse_text

verdict = analyse_email(open("message.eml", "rb").read())
print(verdict.level, verdict.score, verdict.reasons)

verdict = analyse_text("SBI: KYC pending, update at https://sbi-kyc-update.com/kyc")
```

For many messages build one `Analyzer` and reuse it, so the OpenPhish feed is
downloaded once an hour instead of once per message:

```python
from phishguard.verdict import Analyzer
analyzer = Analyzer(allow_domains=["justivia.com"])   # your own domains are never "lookalikes"
verdict = analyzer.analyse_email(raw_bytes)
```

## What is checked

### Links

| Source | What it finds | Setup |
|---|---|---|
| [Google Safe Browsing](https://developers.google.com/safe-browsing/v4/lookup-api) | Google's list of phishing and malware URLs | Free API key in `GSB_API_KEY` (skipped when unset) |
| [OpenPhish](https://openphish.com/) | Live phishing URLs, community feed | None, downloaded hourly |
| [URLhaus](https://urlhaus.abuse.ch/api/) | Hosts spreading malware | None (`URLHAUS_AUTH_KEY` optional) |
| RDAP (`rdap.org`) | Domains registered less than 30 days ago | None |
| Lookalike rules | `paypa1.com`, `rnicrosoft.com`, Cyrillic look-alikes, `paypol.com`, `paypal.com.verify-account.net`, `hdfcbank-kyc.com`, abused TLDs such as `.top` and `.xyz` | Built-in brand list in `phishguard/domains.py`; pass your own with `Analyzer(brands=...)` |
| URL shape | Link text that shows one domain but goes to another, IP-address hosts, `user@` tricks, odd ports, URL shorteners | None |

A feed that cannot be reached is reported in `verdict.feed_result.unavailable`
and never silently counts as "clean".

### Sender

Reads `Authentication-Results`, `ARC-Authentication-Results`, `Received-SPF`
and `DKIM-Signature` headers written by the receiving mail server (Gmail,
Microsoft 365, Proofpoint and most others add them). It reports:

- SPF, DKIM and DMARC results
- whether SPF and DKIM **align** with the From: domain (DMARC alignment), so a
  message that passes SPF for `mail-serv-04.xyz` while claiming to be
  `paypal.com` is caught
- a Reply-To on another domain
- a display name claiming a brand (`"PayPal Service" <x@random.net>`)
- missing authentication altogether

These checks need the headers a real mail server adds; a message pasted
without headers is scored on its links only.

## Scoring

Feed hit: +85. Homoglyph, typosquat, brand-in-subdomain or domain under 7 days
old: +45 each. Brand plus keyword, new domain under 30 days: +25. DMARC fail:
+40. Display name impersonating a brand: +45. SPF fail: +30. Unaligned SPF
with no DKIM: +20. Reply-To elsewhere: +15. Shortener: +10. Levels: 80+
phishing, 55+ likely phishing, 25+ suspicious.

## Tests

```bash
cd phishguard && pip install -e .[dev] && pytest -q
```

The suite runs offline against five sample emails in `tests/samples/` (a real
GitHub notification, a spoofed PayPal alert, a brand-impersonating message with
no authentication headers, a bank statement with only `Received-SPF`, and a
newsletter sent through a third party with aligned DKIM) and uses stub feeds.

## Limits

- Lookalike detection covers the brands in `DEFAULT_BRANDS`; add your clients'
  domains.
- The public-suffix handling is a short list (`co.uk`, `co.in`, ...), not the
  full Public Suffix List.
- RDAP answers slowly for some registries; `check_age=False` turns it off and
  `max_lookups` caps the number of domains checked per message.
- Google Safe Browsing's Lookup API sends the URLs to Google. Use the Update
  API or a local mirror if that is a privacy concern for your clients.
