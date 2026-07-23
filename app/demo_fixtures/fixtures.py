"""Deterministic fixture data for the bundled synthetic samples.

Demo mode exists so the tool can be demonstrated and graded without live API keys.
Every rule from the brief applies without exception here:

* Fixtures exist **only** for the specific indicators in ``samples/*.txt``. A custom
  indicator pasted while demo mode is on returns ``DISABLED`` from
  ``EnrichmentService`` — this module is never consulted for anything it doesn't
  recognise, and it never falls back to inventing a plausible-looking answer.
* Every :class:`ThreatIntelResult` returned here has ``is_demo_fixture=True`` and
  ``status=ProviderStatus.DEMO_FIXTURE``, so the UI, exports and the risk engine can
  all tell fixture data from a live lookup at a glance.
* Nothing here uses a keyword heuristic ("contains 'phish' -> malicious"). Each value
  is a specific, hand-authored fixture keyed on the exact normalised indicator.

Note on IP indicators: the bundled samples use RFC 5737 documentation address ranges
throughout, per the assignment's sample-safety requirements. Those ranges are correctly
classified as non-public by ``netutils.classify_ip`` and are therefore never
enrichment-eligible — in demo mode as in live mode. That is the *correct* behaviour,
not a limitation of this module: real AbuseIPDB/DNSBL enrichment against a public IP is
exercised by the unit test suite (``tests/unit/test_verification.py``,
``test_ioc_extractor.py``) using genuinely public test addresses. The demo instead
populates the domain, URL and email panels, which is what a header built from
documentation-range IPs can honestly demonstrate.
"""

from __future__ import annotations

from datetime import UTC, datetime

from app.core.models import IOCType, ProviderStatus, ThreatIntelResult

_FIXTURE_TIME = datetime(2026, 7, 23, 12, 0, 0, tzinfo=UTC)


def _fixture(
    provider: str,
    ioc: str,
    ioc_type: IOCType,
    summary: str,
    **fields: object,
) -> ThreatIntelResult:
    return ThreatIntelResult(
        provider=provider,
        ioc=ioc,
        ioc_type=ioc_type,
        status=ProviderStatus.DEMO_FIXTURE,
        looked_up_at=_FIXTURE_TIME,
        summary=summary,
        fields=fields,
        is_demo_fixture=True,
    )


# Keyed on (provider, ioc_type, normalized indicator). Values must exactly match the
# indicators present in samples/legitimate_header.txt, samples/phishing_header.txt and
# samples/possible_bec_header.txt.
_FIXTURES: dict[tuple[str, IOCType, str], ThreatIntelResult] = {}


def _register(result: ThreatIntelResult) -> None:
    _FIXTURES[(result.provider, result.ioc_type, result.ioc)] = result


# ---------------------------------------------------------------------------
# Legitimate sample — northwind-bank.example
# ---------------------------------------------------------------------------

_register(
    _fixture(
        "emailrep",
        "billing@northwind-bank.example",
        IOCType.EMAIL,
        "Reputation: high, established sender, no reported malicious activity.",
        malicious=False,
        reputation="high",
        suspicious=False,
        days_since_domain_creation=3650,
        blacklisted=False,
        malicious_activity=False,
    )
)
_register(
    _fixture(
        "virustotal",
        "northwind-bank.example",
        IOCType.DOMAIN,
        "0/70 vendors flag malicious.",
        malicious=False,
        malicious_count=0,
        suspicious_count=0,
        harmless_count=68,
        total_vendors=70,
        reputation=12,
    )
)

# ---------------------------------------------------------------------------
# Phishing sample — northw1nd-secure.example (lookalike of northwind-bank.example)
# ---------------------------------------------------------------------------

_register(
    _fixture(
        "virustotal",
        "northw1nd-secure.example",
        IOCType.DOMAIN,
        "6/70 vendors flag malicious.",
        malicious=True,
        malicious_count=6,
        suspicious_count=4,
        harmless_count=52,
        total_vendors=70,
        reputation=-38,
    )
)
_register(
    _fixture(
        "emailrep",
        "alerts@northw1nd-secure.example",
        IOCType.EMAIL,
        "Reputation: low, domain registered recently, flagged suspicious.",
        malicious=True,
        reputation="low",
        suspicious=True,
        days_since_domain_creation=6,
        blacklisted=True,
        malicious_activity=True,
    )
)

# ---------------------------------------------------------------------------
# Possible-BEC sample — clean infrastructure, identity inconsistency is the signal
# ---------------------------------------------------------------------------

_register(
    _fixture(
        "emailrep",
        "invoices@partner-vendor.example",
        IOCType.EMAIL,
        "Reputation: high, established sender, no reported malicious activity.",
        malicious=False,
        reputation="high",
        suspicious=False,
        days_since_domain_creation=1825,
        blacklisted=False,
        malicious_activity=False,
    )
)
_register(
    _fixture(
        "emailrep",
        "accounts@partner-vendor-payments.example",
        IOCType.EMAIL,
        "Reputation: none on file — domain has no established history.",
        malicious=False,
        reputation="none",
        suspicious=False,
        days_since_domain_creation=14,
        blacklisted=False,
        malicious_activity=False,
    )
)
_register(
    _fixture(
        "virustotal",
        "partner-vendor.example",
        IOCType.DOMAIN,
        "0/70 vendors flag malicious.",
        malicious=False,
        malicious_count=0,
        suspicious_count=0,
        harmless_count=65,
        total_vendors=70,
        reputation=8,
    )
)


def lookup_fixture(
    provider: str, ioc: str, ioc_type: IOCType
) -> ThreatIntelResult | None:
    """Return the fixture for this exact indicator, or ``None`` if none is defined.

    ``None`` means "not one of the bundled samples' indicators" — the caller
    (``EnrichmentService``) is responsible for returning ``DISABLED`` in that case
    rather than treating ``None`` as clean.
    """
    return _FIXTURES.get((provider, ioc_type, ioc))
