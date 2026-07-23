"""Threat-intelligence provider tests. All HTTP is mocked with respx — no network."""

from __future__ import annotations

import httpx
import pytest
import respx

from app.core.models import IOCType, ProviderStatus
from app.integrations.abuseipdb import AbuseIPDBProvider
from app.integrations.emailrep import EmailRepProvider
from app.integrations.virustotal import VirusTotalProvider

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"


# ---------------------------------------------------------------------------
# AbuseIPDB
# ---------------------------------------------------------------------------


@respx.mock
async def test_abuseipdb_success():
    respx.get("https://api.abuseipdb.com/api/v2/check").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {
                    "abuseConfidenceScore": 87,
                    "totalReports": 12,
                    "isp": "Some Hosting Co",
                    "usageType": "Data Center",
                    "countryCode": "RU",
                }
            },
        )
    )
    provider = AbuseIPDBProvider(api_key="testkey", enabled=True)
    result = await provider.lookup("198.51.100.9", IOCType.IPV4)

    assert result.status is ProviderStatus.SUCCESS
    assert result.fields["malicious"] is True
    assert result.fields["abuse_confidence_score"] == 87
    # Country is captured for display but must never be treated as risk-bearing here —
    # that constraint is enforced in the risk engine, this just confirms the field
    # exists for display purposes without special-casing it.
    assert result.fields["country_code"] == "RU"


@respx.mock
async def test_abuseipdb_low_confidence_is_not_malicious():
    respx.get("https://api.abuseipdb.com/api/v2/check").mock(
        return_value=httpx.Response(
            200, json={"data": {"abuseConfidenceScore": 5, "totalReports": 0}}
        )
    )
    provider = AbuseIPDBProvider(api_key="testkey", enabled=True)
    result = await provider.lookup("93.184.216.34", IOCType.IPV4)
    assert result.fields["malicious"] is False


async def test_abuseipdb_disabled_without_key():
    provider = AbuseIPDBProvider(api_key="", enabled=True)
    result = await provider.lookup("198.51.100.9", IOCType.IPV4)
    assert result.status is ProviderStatus.DISABLED
    assert result.is_demo_fixture is False


async def test_abuseipdb_disabled_by_flag():
    provider = AbuseIPDBProvider(api_key="testkey", enabled=False)
    result = await provider.lookup("198.51.100.9", IOCType.IPV4)
    assert result.status is ProviderStatus.DISABLED


@respx.mock
async def test_abuseipdb_invalid_key():
    respx.get("https://api.abuseipdb.com/api/v2/check").mock(
        return_value=httpx.Response(401)
    )
    provider = AbuseIPDBProvider(api_key="badkey", enabled=True)
    result = await provider.lookup("198.51.100.9", IOCType.IPV4)
    assert result.status is ProviderStatus.INVALID_KEY


@respx.mock
async def test_abuseipdb_rate_limited():
    respx.get("https://api.abuseipdb.com/api/v2/check").mock(
        return_value=httpx.Response(429)
    )
    provider = AbuseIPDBProvider(api_key="testkey", enabled=True)
    result = await provider.lookup("198.51.100.9", IOCType.IPV4)
    assert result.status is ProviderStatus.RATE_LIMITED


@respx.mock
async def test_abuseipdb_timeout():
    respx.get("https://api.abuseipdb.com/api/v2/check").mock(
        side_effect=httpx.TimeoutException("timed out")
    )
    provider = AbuseIPDBProvider(api_key="testkey", enabled=True)
    result = await provider.lookup("198.51.100.9", IOCType.IPV4)
    assert result.status is ProviderStatus.TIMEOUT


@respx.mock
async def test_abuseipdb_malformed_json():
    respx.get("https://api.abuseipdb.com/api/v2/check").mock(
        return_value=httpx.Response(200, content=b"not json")
    )
    provider = AbuseIPDBProvider(api_key="testkey", enabled=True)
    result = await provider.lookup("198.51.100.9", IOCType.IPV4)
    assert result.status is ProviderStatus.PROVIDER_ERROR


async def test_abuseipdb_unsupported_ioc_type_is_disabled():
    provider = AbuseIPDBProvider(api_key="testkey", enabled=True)
    result = await provider.lookup("bank.example", IOCType.DOMAIN)
    assert result.status is ProviderStatus.DISABLED


@respx.mock
async def test_abuseipdb_outage_is_unavailable_not_fabricated():
    respx.get("https://api.abuseipdb.com/api/v2/check").mock(
        side_effect=httpx.ConnectError("connection refused")
    )
    provider = AbuseIPDBProvider(api_key="testkey", enabled=True)
    result = await provider.lookup("198.51.100.9", IOCType.IPV4)
    assert result.status is ProviderStatus.UNAVAILABLE
    assert "malicious" not in result.fields


# ---------------------------------------------------------------------------
# EmailRep
# ---------------------------------------------------------------------------


@respx.mock
async def test_emailrep_success():
    respx.get("https://emailrep.io/alice%40bank.example").mock(
        return_value=httpx.Response(
            200,
            json={
                "reputation": "high",
                "suspicious": False,
                "references": 42,
                "details": {"blacklisted": False, "malicious_activity": False},
            },
        )
    )
    provider = EmailRepProvider(api_key="testkey", enabled=True)
    result = await provider.lookup("alice@bank.example", IOCType.EMAIL)
    assert result.status is ProviderStatus.SUCCESS
    assert result.fields["malicious"] is False


@respx.mock
async def test_emailrep_suspicious_is_malicious():
    respx.get("https://emailrep.io/mallory%40evil.example").mock(
        return_value=httpx.Response(
            200,
            json={
                "reputation": "low",
                "suspicious": True,
                "details": {"malicious_activity": True},
            },
        )
    )
    provider = EmailRepProvider(api_key="testkey", enabled=True)
    result = await provider.lookup("mallory@evil.example", IOCType.EMAIL)
    assert result.fields["malicious"] is True


async def test_emailrep_unsupported_type_disabled():
    provider = EmailRepProvider(api_key="testkey", enabled=True)
    result = await provider.lookup("198.51.100.9", IOCType.IPV4)
    assert result.status is ProviderStatus.DISABLED


@respx.mock
async def test_emailrep_not_found_is_unknown_not_clean():
    respx.get("https://emailrep.io/new%40example.com").mock(
        return_value=httpx.Response(404)
    )
    provider = EmailRepProvider(api_key="testkey", enabled=True)
    result = await provider.lookup("new@example.com", IOCType.EMAIL)
    assert result.status is ProviderStatus.UNKNOWN
    assert result.is_actionable is False


# ---------------------------------------------------------------------------
# VirusTotal
# ---------------------------------------------------------------------------


@respx.mock
async def test_virustotal_domain_success():
    respx.get("https://www.virustotal.com/api/v3/domains/evil.example").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 5,
                            "suspicious": 2,
                            "harmless": 60,
                            "undetected": 3,
                        },
                        "reputation": -20,
                    }
                }
            },
        )
    )
    provider = VirusTotalProvider(api_key="testkey", enabled=True)
    result = await provider.lookup("evil.example", IOCType.DOMAIN)
    assert result.status is ProviderStatus.SUCCESS
    assert result.fields["malicious"] is True
    assert result.fields["malicious_count"] == 5


@respx.mock
async def test_virustotal_url_uses_base64_identifier():
    import base64

    url = "https://evil.example/phish"
    identifier = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    respx.get(f"https://www.virustotal.com/api/v3/urls/{identifier}").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {"malicious": 0, "harmless": 70}
                    }
                }
            },
        )
    )
    provider = VirusTotalProvider(api_key="testkey", enabled=True)
    result = await provider.lookup(url, IOCType.URL)
    assert result.status is ProviderStatus.SUCCESS
    assert result.fields["malicious"] is False


async def test_virustotal_disabled_by_default():
    """VIRUSTOTAL_ENABLED defaults to false — confirm the provider honours that."""
    provider = VirusTotalProvider(api_key="testkey", enabled=False)
    result = await provider.lookup("evil.example", IOCType.DOMAIN)
    assert result.status is ProviderStatus.DISABLED


# ---------------------------------------------------------------------------
# Provider isolation — one outage must not affect another provider's lookup
# ---------------------------------------------------------------------------


@respx.mock
async def test_one_provider_failing_does_not_affect_another():
    respx.get("https://api.abuseipdb.com/api/v2/check").mock(
        side_effect=httpx.ConnectError("down")
    )
    respx.get("https://emailrep.io/alice%40bank.example").mock(
        return_value=httpx.Response(200, json={"reputation": "high", "suspicious": False})
    )

    abuse = AbuseIPDBProvider(api_key="k", enabled=True)
    rep = EmailRepProvider(api_key="k", enabled=True)

    abuse_result = await abuse.lookup("198.51.100.9", IOCType.IPV4)
    rep_result = await rep.lookup("alice@bank.example", IOCType.EMAIL)

    assert abuse_result.status is ProviderStatus.UNAVAILABLE
    assert rep_result.status is ProviderStatus.SUCCESS
