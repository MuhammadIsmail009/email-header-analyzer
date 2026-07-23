"""EnrichmentService tests: caching, per-type limits, offline mode, demo mode."""

from __future__ import annotations

import httpx
import pytest
import respx

from app.config import Settings
from app.core.models import IOC, IOCSource, IOCType, ProviderStatus
from app.services.enrichment_service import EnrichmentService

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"


def _ioc(value: str, ioc_type: IOCType, eligible: bool = True) -> IOC:
    return IOC(
        value=value,
        normalized=value,
        ioc_type=ioc_type,
        sources=(IOCSource(header_name="From", position=0),),
        enrichment_eligible=eligible,
        defanged=value,
    )


def _settings(**overrides) -> Settings:
    base = dict(
        enrichment_enabled=True,
        abuseipdb_api_key="key",
        emailrep_api_key="key",
        virustotal_api_key="key",
        virustotal_enabled=True,
        max_ip_lookups=10,
        max_domain_lookups=10,
        max_url_lookups=10,
        max_email_lookups=10,
        intel_cache_ttl_seconds=3600,
        intel_max_concurrency=8,
    )
    base.update(overrides)
    return Settings(**base)


async def test_offline_mode_returns_disabled_without_calling_providers():
    service = EnrichmentService.from_settings(_settings(enrichment_enabled=False))
    iocs = (_ioc("198.51.100.9", IOCType.IPV4),)
    results = await service.enrich(iocs)
    assert all(r.status is ProviderStatus.DISABLED for r in results)


@respx.mock
async def test_ineligible_iocs_are_never_submitted():
    respx.get("https://api.abuseipdb.com/api/v2/check").mock(
        return_value=httpx.Response(200, json={"data": {"abuseConfidenceScore": 0}})
    )
    service = EnrichmentService.from_settings(_settings())
    private_ip = _ioc("10.1.2.3", IOCType.IPV4, eligible=False)
    results = await service.enrich((private_ip,))
    assert results == ()


@respx.mock
async def test_per_type_limit_is_enforced():
    """VirusTotal also supports IP lookups, so it must be disabled here — this test
    isolates AbuseIPDB's call count, not the combined provider fan-out."""
    route = respx.get("https://api.abuseipdb.com/api/v2/check").mock(
        return_value=httpx.Response(200, json={"data": {"abuseConfidenceScore": 0}})
    )
    service = EnrichmentService.from_settings(
        _settings(max_ip_lookups=2, virustotal_enabled=False)
    )
    ips = tuple(_ioc(f"198.51.100.{i}", IOCType.IPV4) for i in range(1, 6))
    await service.enrich(ips)
    assert route.call_count == 2


@respx.mock
async def test_cache_prevents_duplicate_lookups():
    route = respx.get("https://api.abuseipdb.com/api/v2/check").mock(
        return_value=httpx.Response(200, json={"data": {"abuseConfidenceScore": 10}})
    )
    service = EnrichmentService.from_settings(_settings(virustotal_enabled=False))
    ip = _ioc("198.51.100.9", IOCType.IPV4)

    first = await service.enrich((ip,))
    second = await service.enrich((ip,))

    assert route.call_count == 1  # second call served from cache
    assert not first[0].cached
    assert second[0].cached


async def test_demo_mode_returns_fixture_for_known_indicator():
    service = EnrichmentService.from_settings(
        _settings(enrichment_enabled=False, demo_mode=True)
    )
    ioc = _ioc("billing@northwind-bank.example", IOCType.EMAIL)
    results = await service.enrich((ioc,))
    emailrep_results = [r for r in results if r.provider == "emailrep"]
    assert emailrep_results
    assert emailrep_results[0].status is ProviderStatus.DEMO_FIXTURE
    assert emailrep_results[0].is_demo_fixture is True


async def test_demo_mode_never_invents_data_for_unknown_indicator():
    """The core honesty guarantee of demo mode."""
    service = EnrichmentService.from_settings(
        _settings(enrichment_enabled=False, demo_mode=True)
    )
    ioc = _ioc("totally-custom-domain-not-in-fixtures.example", IOCType.DOMAIN)
    results = await service.enrich((ioc,))
    assert all(r.status is ProviderStatus.DISABLED for r in results)
    assert all(not r.is_demo_fixture for r in results)


@respx.mock
async def test_concurrent_lookups_across_providers():
    respx.get("https://api.abuseipdb.com/api/v2/check").mock(
        return_value=httpx.Response(200, json={"data": {"abuseConfidenceScore": 0}})
    )
    respx.get(url__regex=r"https://emailrep\.io/.*").mock(
        return_value=httpx.Response(200, json={"reputation": "high", "suspicious": False})
    )
    service = EnrichmentService.from_settings(_settings(virustotal_enabled=False))
    iocs = (
        _ioc("198.51.100.9", IOCType.IPV4),
        _ioc("alice@bank.example", IOCType.EMAIL),
    )
    results = await service.enrich(iocs)
    assert {r.provider for r in results} >= {"abuseipdb", "emailrep"}
    # VirusTotal is disabled but still "supports" IPv4, so it still produces a
    # DISABLED result for the IP — that is correct, not a bug: disabled providers are
    # always reported so the analyst can see exactly what was and wasn't checked.
    relevant = [r for r in results if r.provider in ("abuseipdb", "emailrep")]
    assert all(r.status is ProviderStatus.SUCCESS for r in relevant)
