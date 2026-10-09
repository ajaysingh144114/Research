"""PhishGuard link and sender checks.

Pure-Python email and SMS phishing checks: URL extraction, threat-feed
lookups (Google Safe Browsing, OpenPhish, URLhaus), lookalike and
newly registered domain detection, SPF/DKIM/DMARC parsing, and a combined
verdict. Network access is optional and injectable so everything can be
tested offline.
"""

from .verdict import Verdict, analyse_email, analyse_text

__all__ = ["Verdict", "analyse_email", "analyse_text"]
__version__ = "0.1.0"
