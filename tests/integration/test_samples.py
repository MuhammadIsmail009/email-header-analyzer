"""End-to-end tests against the bundled sample headers.

These are the same samples shipped for demonstration and grading — if one of these
regresses, the demo walkthrough is broken. All DNS is served by ``StaticResolver`` with
records matching what each sample's domains would genuinely publish; no network.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.config import Settings
from app.core.models import Verdict
from app.core.verification import StaticResolver
from app.services.analysis_service import AnalysisService
from app.services.enrichment_service import EnrichmentService

pytestmark = pytest.mark.anyio

SAMPLES_DIR = Path(__file__).resolve().parents[2] / "samples"


@pytest.fixture
def anyio_backend():
    return "asyncio"


def _read(name: str) -> str:
    return (SAMPLES_DIR / name).read_text(encoding="utf-8")


_COMMON_RESOLVER_RECORDS = dict(
    txt={
        "northwind-bank.example": ["v=spf1 ip4:203.0.113.15 -all"],
        "_dmarc.northwind-bank.example": [
            "v=DMARC1; p=quarantine; pct=90; adkim=r; aspf=r"
        ],
        "partner-vendor.example": ["v=spf1 ip4:203.0.113.44 -all"],
        "_dmarc.partner-vendor.example": ["v=DMARC1; p=reject; adkim=r; aspf=r"],
        "northw1nd-secure.example": ["v=spf1 -all"],
        "_dmarc.northw1nd-secure.example": [],
    },
    ptr={
        "203.0.113.15": ["mail.northwind-bank.example"],
        "203.0.113.44": ["mail.partner-vendor.example"],
    },
    a={
        "mail.northwind-bank.example": ["203.0.113.15"],
        "mail.partner-vendor.example": ["203.0.113.44"],
    },
)


def _service(**settings_overrides) -> AnalysisService:
    base = dict(
        verification_enabled=True,
        enrichment_enabled=False,
        demo_mode=True,
        trusted_receiver_domains=("example.org",),
        protected_domains=("northwind-bank.example", "partner-vendor.example"),
        dnsbl_enabled=True,
    )
    base.update(settings_overrides)
    settings = Settings(**base)
    resolver = StaticResolver(**_COMMON_RESOLVER_RECORDS)
    enrichment = EnrichmentService.from_settings(settings)
    return AnalysisService(settings, enrichment, resolver=resolver)


async def test_legitimate_sample_is_likely_legitimate_with_zero_score():
    report = await _service().analyze(_read("legitimate_header.txt"))
    assert report.risk.verdict is Verdict.LIKELY_LEGITIMATE
    assert report.risk.score == 0
    assert not any(f.score_contribution > 0 for f in report.risk.findings)


async def test_phishing_sample_is_likely_phishing_with_high_score():
    report = await _service().analyze(_read("phishing_header.txt"))
    assert report.risk.verdict is Verdict.LIKELY_PHISHING
    assert report.risk.score >= 50
    fired = {f.rule_id for f in report.risk.findings}
    assert "IDN-001" in fired  # Reply-To mismatch
    assert "TI-003" in fired  # demo fixture flags the lookalike domain malicious


async def test_bec_sample_is_possible_bec_not_confirmed():
    report = await _service().analyze(_read("possible_bec_header.txt"))
    assert report.risk.verdict is Verdict.POSSIBLE_BEC
    assert "confirmed" not in report.risk.verdict_label.lower()
    fired = {f.rule_id for f in report.risk.findings}
    assert "BEC-001" in fired
    assert "AUTH-010" in fired  # authentication genuinely verified clean and aligned


async def test_malformed_sample_does_not_crash_and_reports_warnings():
    report = await _service(verification_enabled=False).analyze(
        _read("malformed_header.txt")
    )
    assert report.risk is not None
    assert report.warnings  # duplicate From, unparsable lines, etc.


async def test_none_of_the_four_samples_produce_a_country_based_finding():
    for name in (
        "legitimate_header.txt",
        "phishing_header.txt",
        "possible_bec_header.txt",
        "malformed_header.txt",
    ):
        report = await _service(verification_enabled="malformed" not in name).analyze(
            _read(name)
        )
        for f in report.risk.findings:
            assert "country" not in f.evidence.lower()
