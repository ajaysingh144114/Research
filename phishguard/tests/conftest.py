from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from phishguard.domains import DomainAge
from phishguard.feeds import StaticFeed
from phishguard.verdict import Analyzer

SAMPLES = Path(__file__).parent / "samples"


def sample(name: str) -> bytes:
    return (SAMPLES / name).read_bytes()


def fake_rdap(ages: dict[str, int | None]):
    """RDAP stub: ages maps domain -> age in days (None = unknown, missing = old)."""
    now = datetime.now(timezone.utc)

    def lookup(domain: str) -> DomainAge:
        if domain in ages:
            days = ages[domain]
            if days is None:
                return DomainAge(domain, None, None)
            return DomainAge(domain, now - timedelta(days=days), days)
        return DomainAge(domain, now - timedelta(days=3000), 3000)

    return lookup


@pytest.fixture
def offline() -> Analyzer:
    """Analyzer with no network: one static feed, RDAP stub where nothing is new."""
    return Analyzer(feeds=[StaticFeed("test_feed", bad_hosts=["known-bad.example"])], rdap=fake_rdap({}))
