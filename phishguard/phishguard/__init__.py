"""PhishGuard: check an email or SMS for phishing using local rules and Claude on Amazon Bedrock."""

from .checker import Result, check_message

__all__ = ["Result", "check_message"]
__version__ = "0.1.0"
