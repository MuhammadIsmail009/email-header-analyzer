"""End-to-end analysis service tests: parsing through verdict, fully offline.

These exercise the seam that assembles every module together. All DNS is served by
:class:`StaticResolver`; all threat intel is disabled. No network, no API keys.
"""

from __future__ import annotations

import pytest

from app.config import Settings
from app.core.models import Verdict
from app.core.verification import StaticResolver
from app.services.analysis_service import AnalysisService
from app.services.enrichment_service import EnrichmentService

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"


LEGITIMATE_HEADER = """\
Return-Path: <billing@bank.example>
Received: from keys1.bank.example (mail.bank.example. [203.0.113.15])
    by mx.example.org with ESMTPS
    (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
    Tue, 21 Oct 2025 23:28:50 -0700 (PDT)
Received-SPF: pass (mx.example.org: domain of billing@bank.example
    designates 203.0.113.15 as permitted sender) client-ip=203.0.113.15;
Authentication-Results: mx.example.org;
    spf=pass smtp.mailfrom=billing@bank.example;
    dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bank.example
Received: by keys1.bank.example (PGP Universal, from userid 997)
    id 14643A91718; Wed, 22 Oct 2025 09:28:49 +0300 (+03)
From: Billing <billing@bank.example>
To: alice@example.org
Subject: Statement ready
Message-Id: <20251022062849.14643A91718@keys1.bank.example>
Date: Wed, 22 Oct 2025 09:28:49 +0300 (+03)
"""


def _settings(**overrides) -> Settings:
    base = dict(
        verification_enabled=True,
        enrichment_enabled=False,
        dnsbl_enabled=True,
        trusted_receiver_domains=("example.org",),
    )
    base.update(overrides)
    return Settings(**base)


def _service(settings: Settings, resolver: StaticResolver) -> AnalysisService:
    enrichment = EnrichmentService.from_settings(settings)
    return AnalysisService(settings, enrichment, resolver=resolver)


async def test_legitimate_header_end_to_end():
    resolver = StaticResolver(
        txt={
            "bank.example": ["v=spf1 ip4:203.0.113.15 -all"],
            "_dmarc.bank.example": ["v=DMARC1; p=quarantine; pct=90; adkim=r; aspf=r"],
        },
        ptr={"203.0.113.15": ["mail.bank.example"]},
        a={"mail.bank.example": ["203.0.113.15"]},
    )
    service = _service(_settings(), resolver)
    report = await service.analyze(LEGITIMATE_HEADER)

    assert report.risk is not None
    assert report.risk.verdict is Verdict.LIKELY_LEGITIMATE
    assert report.authentication.header_from_domain == "bank.example"
    assert report.route is not None
    assert len(report.route.hops_chronological) == 2
    # The PGP-gateway hop with no 'from' clause must survive — see received_parser.
    assert report.route.hops_chronological[0].by_host == "keys1.bank.example"
    assert report.route.hops_chronological[0].from_host is None
    # SPF must be evaluated against the IP the trusted receiver observed (203.0.113.15
    # on the second hop), not against the origin hop, which has no IP at all.
    assert not any(f.rule_id == "AUTH-008" for f in report.risk.findings)
    assert report.verification_performed is True


async def test_report_id_is_unique_and_opaque():
    resolver = StaticResolver()
    service = _service(_settings(verification_enabled=False), resolver)
    r1 = await service.analyze("From: a@bank.example\n")
    r2 = await service.analyze("From: a@bank.example\n")
    assert r1.report_id != r2.report_id
    assert len(r1.report_id) > 12


async def test_lookalike_domain_detected_against_recipient_org():
    """The recipient's own domain (from To:) is always in the impersonation watchlist."""
    resolver = StaticResolver()
    service = _service(
        _settings(verification_enabled=False, protected_domains=("bank.example",)),
        resolver,
    )
    header = (
        "From: Security <alerts@bank-secur1ty.example>\n"
        "To: alice@bank.example\n"
        "Subject: Verify your account\n"
    )
    report = await service.analyze(header)
    assert any(f.rule_id == "IMP-001" for f in report.risk.findings)


async def test_disagreement_between_asserted_and_verified_is_flagged():
    """The forged Authentication-Results case: header claims pass, DNS says fail."""
    resolver = StaticResolver(
        txt={"bank.example": ["v=spf1 -all"]},  # authorises nothing
    )
    header = (
        "Received: from evil.example ([198.51.100.9]) by mx.example.org;"
        " Wed, 22 Oct 2025 09:00:00 +0000\n"
        "Authentication-Results: mx.example.org; spf=pass smtp.mailfrom=a@bank.example\n"
        "From: a@bank.example\n"
    )
    service = _service(
        _settings(trusted_receiver_domains=("example.org",), dnsbl_enabled=False),
        resolver,
    )
    report = await service.analyze(header)
    assert any(f.rule_id == "AUTH-008" for f in report.risk.findings)


async def test_malformed_header_does_not_crash_the_pipeline():
    resolver = StaticResolver()
    service = _service(_settings(verification_enabled=False), resolver)
    report = await service.analyze("this is not a valid header at all\n\n\x00garbage")
    assert report.risk is not None
    assert report.risk.verdict is Verdict.INCONCLUSIVE


async def test_empty_input_does_not_crash_the_pipeline():
    resolver = StaticResolver()
    service = _service(_settings(verification_enabled=False), resolver)
    report = await service.analyze("")
    assert report.risk is not None


async def test_uploaded_eml_enables_full_dkim_verification():
    """Passing body should reach verify_dkim as more than headers-only.

    This does not assert a specific DKIM outcome (no real signature here) — it
    confirms the body reaches the verification layer at all, which is what
    distinguishes an .eml upload from a pasted header block.
    """
    resolver = StaticResolver()
    service = _service(_settings(trusted_receiver_domains=("example.org",)), resolver)
    header = (
        "DKIM-Signature: v=1; a=rsa-sha256; d=bank.example; s=sel; "
        "h=from:to; bh=xxxx; b=yyyy\n"
        "From: a@bank.example\nTo: b@example.org\n"
    )
    report = await service.analyze(header, body="hello world\n")
    assert report.verification_performed is True


async def test_spf_uses_trusted_receiver_ip_not_origin_hop_ip():
    """Regression: the origin hop of a locally-injected message (PGP gateway,
    submission agent) legitimately has no 'from' clause and therefore no IP. Using
    that hop's IP for SPF evaluation silently passed None as the connecting IP and
    made a genuinely legitimate, correctly SPF-authorised message fail DMARC.

    SPF must be evaluated against the IP the first *trusted* receiver actually
    observed on the connection — the same IP a real Received-SPF: client-ip= records.
    """
    resolver = StaticResolver(
        txt={
            "bank.example": ["v=spf1 ip4:203.0.113.15 -all"],
            "_dmarc.bank.example": ["v=DMARC1; p=quarantine; adkim=r; aspf=r"],
        },
    )
    header = (
        "Return-Path: <billing@bank.example>\n"
        "Received: from keys1.bank.example (mail.bank.example. [203.0.113.15])"
        " by mx.example.org with ESMTPS; Tue, 21 Oct 2025 23:28:50 -0700\n"
        "Received: by keys1.bank.example (PGP Universal, from userid 997)"
        " id ABC123; Wed, 22 Oct 2025 09:28:49 +0300\n"
        "From: billing@bank.example\n"
        "To: alice@example.org\n"
    )
    service = _service(
        _settings(trusted_receiver_domains=("example.org",), dnsbl_enabled=False),
        resolver,
    )
    report = await service.analyze(header)

    assert not any(f.rule_id == "AUTH-001" for f in report.risk.findings)
    assert not any(f.rule_id == "AUTH-008" for f in report.risk.findings)


async def test_verification_results_are_attached_to_the_report():
    """Regression: AnalysisReport never stored the raw VerificationResult list, so
    the 'independently verified' detail (asserted-vs-verified, DNS record, scope)
    computed during analysis was silently discarded and the UI/exports had nothing
    to show beyond pass/fail alignment flags."""
    resolver = StaticResolver(
        txt={
            "bank.example": ["v=spf1 ip4:203.0.113.15 -all"],
            "_dmarc.bank.example": ["v=DMARC1; p=quarantine; adkim=r; aspf=r"],
        },
    )
    header = (
        "Return-Path: <billing@bank.example>\n"
        "Received: from a ([203.0.113.15]) by mx.example.org; Wed, 22 Oct 2025 09:00:00 +0000\n"
        "From: billing@bank.example\nTo: alice@example.org\n"
    )
    service = _service(
        _settings(trusted_receiver_domains=("example.org",), dnsbl_enabled=False),
        resolver,
    )
    report = await service.analyze(header)

    assert len(report.verifications) == 3  # SPF, DKIM, DMARC
    methods = {v.method for v in report.verifications}
    from app.core.models import AuthMethod

    assert methods == {AuthMethod.SPF, AuthMethod.DKIM, AuthMethod.DMARC}
    assert any("Independently evaluated" in v.detail for v in report.verifications)
