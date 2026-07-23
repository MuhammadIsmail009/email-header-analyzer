"""Provider protocol shared by every threat-intelligence integration.

Concept adopted from the indicator-type module split in MailHeaderDetective and the
provider-isolation posture in SentinelMail (see docs/REFERENCE_REPOSITORIES.md §3, §6)
— reimplemented, not copied; neither repository has a licence.

Every provider implements :meth:`Provider.lookup` and returns a
:class:`app.core.models.ThreatIntelResult`. The contract is deliberately narrow:

* A provider **never raises** out of ``lookup`` for a network, auth or rate-limit
  failure. It catches its own failures and returns the matching
  :class:`ProviderStatus` — ``UNAVAILABLE``, ``INVALID_KEY``, ``RATE_LIMITED``,
  ``TIMEOUT`` or ``PROVIDER_ERROR``. One provider's outage must never take down the
  whole enrichment pass, and the caller should never need a try/except around a
  provider call.
* A provider **never fabricates** a result. No API key configured means the call is
  never attempted and ``DISABLED`` is returned directly — not an invented "clean"
  verdict, which is the single most common mistake in this space (see
  `haseebtariq368/Emaul-Header-Analyzer` in the reference audit).
* ``fields`` carries provider-specific data (score, ISP, reputation, etc.) as a plain
  dict so the caller and templates don't need to know each provider's schema, but the
  presence of a ``malicious: bool`` key is the one contract the risk engine relies on
  (see ``rules_impl._malicious_by_ioc``).
"""

from __future__ import annotations

from typing import Protocol

from app.core.models import IOCType, ProviderStatus, ThreatIntelResult


class Provider(Protocol):
    name: str

    async def lookup(self, ioc: str, ioc_type: IOCType) -> ThreatIntelResult: ...

    def supports(self, ioc_type: IOCType) -> bool: ...


def disabled_result(provider: str, ioc: str, ioc_type: IOCType) -> ThreatIntelResult:
    """A provider with no configured key. Never attempted, never invented."""
    return ThreatIntelResult(
        provider=provider,
        ioc=ioc,
        ioc_type=ioc_type,
        status=ProviderStatus.DISABLED,
        summary=f"{provider} is not configured (no API key, or disabled).",
    )


def unavailable_result(
    provider: str, ioc: str, ioc_type: IOCType, error: str
) -> ThreatIntelResult:
    return ThreatIntelResult(
        provider=provider,
        ioc=ioc,
        ioc_type=ioc_type,
        status=ProviderStatus.UNAVAILABLE,
        summary=f"{provider} could not be reached.",
        error_type=error,
    )


def timeout_result(provider: str, ioc: str, ioc_type: IOCType) -> ThreatIntelResult:
    return ThreatIntelResult(
        provider=provider,
        ioc=ioc,
        ioc_type=ioc_type,
        status=ProviderStatus.TIMEOUT,
        summary=f"{provider} did not respond in time.",
        error_type="timeout",
    )


def invalid_key_result(provider: str, ioc: str, ioc_type: IOCType) -> ThreatIntelResult:
    return ThreatIntelResult(
        provider=provider,
        ioc=ioc,
        ioc_type=ioc_type,
        status=ProviderStatus.INVALID_KEY,
        summary=f"{provider} rejected the configured API key.",
        error_type="invalid_key",
    )


def rate_limited_result(provider: str, ioc: str, ioc_type: IOCType) -> ThreatIntelResult:
    return ThreatIntelResult(
        provider=provider,
        ioc=ioc,
        ioc_type=ioc_type,
        status=ProviderStatus.RATE_LIMITED,
        summary=f"{provider} rate-limited this request.",
        error_type="rate_limited",
    )


def provider_error_result(
    provider: str, ioc: str, ioc_type: IOCType, error: str
) -> ThreatIntelResult:
    return ThreatIntelResult(
        provider=provider,
        ioc=ioc,
        ioc_type=ioc_type,
        status=ProviderStatus.PROVIDER_ERROR,
        summary=f"{provider} returned an unexpected response.",
        error_type=error,
    )


def unknown_result(provider: str, ioc: str, ioc_type: IOCType) -> ThreatIntelResult:
    """The provider answered, but has no data on this indicator.

    Distinct from every failure status above: the lookup succeeded, it just found
    nothing. Never treated as a clean verdict — see ``ThreatIntelResult.is_actionable``.
    """
    return ThreatIntelResult(
        provider=provider,
        ioc=ioc,
        ioc_type=ioc_type,
        status=ProviderStatus.UNKNOWN,
        summary=f"{provider} has no data on this indicator.",
    )
