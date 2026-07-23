"""Threat-intelligence enrichment orchestration.

Responsibilities kept deliberately separate from the providers themselves:

* **Concurrency bounding** — a semaphore caps in-flight requests so a header with
  fifty IOCs cannot open fifty simultaneous connections to five different providers.
* **Caching** — a TTL cache keyed on ``(provider, ioc)`` so re-analysing the same
  header, or seeing a repeat indicator across analyses, does not re-spend quota.
  MailHeaderDetective has no caching at all and burns quota on every repeat submission
  (docs/REFERENCE_REPOSITORIES.md §3) — this is the fix.
* **Per-analysis limits** — ``MAX_IP_LOOKUPS`` etc. cap how many indicators of each
  type are submitted per analysis, regardless of how many were extracted.
* **Demo fixtures** — deterministic, clearly-labelled fixture data for the bundled
  synthetic samples only. A custom indicator in demo mode returns ``DISABLED``, never
  an invented verdict.
* **Offline mode** — when enrichment is disabled entirely, every indicator returns
  ``DISABLED`` without a single provider being constructed or called.

This module is the only place in the codebase that decides *whether* to call a
provider. The providers themselves never know about caching, limits or demo mode.
"""

from __future__ import annotations

from dataclasses import dataclass

import anyio
from cachetools import TTLCache

from app.config import Settings
from app.core.models import IOC, IOCType, ProviderStatus, ThreatIntelResult
from app.demo_fixtures.fixtures import lookup_fixture
from app.integrations.abuseipdb import AbuseIPDBProvider
from app.integrations.base import Provider, disabled_result
from app.integrations.emailrep import EmailRepProvider
from app.integrations.virustotal import VirusTotalProvider


@dataclass
class EnrichmentService:
    providers: tuple[Provider, ...]
    settings: Settings
    _cache: TTLCache = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self._cache is None:
            self._cache = TTLCache(
                maxsize=self.settings.intel_cache_max_entries,
                ttl=self.settings.intel_cache_ttl_seconds,
            )
        self._semaphore = anyio.Semaphore(self.settings.intel_max_concurrency)

    @classmethod
    def from_settings(cls, settings: Settings) -> EnrichmentService:
        providers: tuple[Provider, ...] = (
            AbuseIPDBProvider(
                settings.abuseipdb_api_key,
                settings.provider_enabled("abuseipdb"),
                settings.intel_timeout_seconds,
            ),
            EmailRepProvider(
                settings.emailrep_api_key,
                settings.provider_enabled("emailrep"),
                settings.intel_timeout_seconds,
            ),
            VirusTotalProvider(
                settings.virustotal_api_key,
                settings.provider_enabled("virustotal"),
                settings.intel_timeout_seconds,
            ),
        )
        return cls(providers=providers, settings=settings)

    def _limit_for(self, ioc_type: IOCType) -> int:
        return {
            IOCType.IPV4: self.settings.max_ip_lookups,
            IOCType.IPV6: self.settings.max_ip_lookups,
            IOCType.DOMAIN: self.settings.max_domain_lookups,
            IOCType.URL: self.settings.max_url_lookups,
            IOCType.EMAIL: self.settings.max_email_lookups,
        }.get(ioc_type, 0)

    def _select_iocs(self, iocs: tuple[IOC, ...]) -> list[IOC]:
        """Apply per-type limits, dropping ineligible indicators first.

        Indicators are selected in their original order so the cap consistently keeps
        the earliest-occurring ones rather than an arbitrary subset.
        """
        counts: dict[IOCType, int] = {}
        selected: list[IOC] = []
        for ioc in iocs:
            if not ioc.enrichment_eligible:
                continue
            limit = self._limit_for(ioc.ioc_type)
            used = counts.get(ioc.ioc_type, 0)
            if used >= limit:
                continue
            counts[ioc.ioc_type] = used + 1
            selected.append(ioc)
        return selected

    async def _lookup_one(
        self, provider: Provider, ioc: str, ioc_type: IOCType, demo_mode: bool
    ) -> ThreatIntelResult:
        if not provider.supports(ioc_type):
            return None  # type: ignore[return-value]

        cache_key = (provider.name, ioc_type.value, ioc)
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached.model_copy(update={"cached": True})

        if demo_mode:
            fixture = lookup_fixture(provider.name, ioc, ioc_type)
            if fixture is not None:
                return fixture
            # A custom indicator in demo mode: never invent a verdict.
            return disabled_result(provider.name, ioc, ioc_type)

        async with self._semaphore:
            result = await provider.lookup(ioc, ioc_type)

        if result.status is ProviderStatus.SUCCESS:
            self._cache[cache_key] = result
        return result

    async def enrich(
        self, iocs: tuple[IOC, ...]
    ) -> tuple[ThreatIntelResult, ...]:
        """Enrich eligible IOCs across all configured providers, concurrently.

        Returns every attempted lookup — including ``DISABLED`` results — so the UI
        and exports can show exactly what was and was not checked.
        """
        if not self.settings.enrichment_enabled and not self.settings.demo_mode:
            return tuple(
                disabled_result(provider.name, ioc.normalized, ioc.ioc_type)
                for ioc in iocs
                if ioc.enrichment_eligible
                for provider in self.providers
                if provider.supports(ioc.ioc_type)
            )

        selected = self._select_iocs(iocs)
        tasks = [
            (provider, ioc)
            for ioc in selected
            for provider in self.providers
            if provider.supports(ioc.ioc_type)
        ]

        results: list[ThreatIntelResult] = []

        async def _run(provider: Provider, ioc: IOC) -> None:
            outcome = await self._lookup_one(
                provider, ioc.normalized, ioc.ioc_type, self.settings.demo_mode
            )
            if outcome is not None:
                results.append(outcome)

        async with anyio.create_task_group() as tg:
            for provider, ioc in tasks:
                tg.start_soon(_run, provider, ioc)

        return tuple(results)
