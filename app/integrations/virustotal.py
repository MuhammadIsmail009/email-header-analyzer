"""VirusTotal integration — cached-report lookups only.

Only ever reads *existing* reports for public IPs and domains, plus URL reports keyed
by VT's own URL identifier. Never uploads a file, never submits a URL for scanning, and
never requests detonation — the assignment brief and this project's threat model both
prohibit active submission of a customer's indicators.
"""

from __future__ import annotations

import base64
from datetime import UTC, datetime

import httpx

from app.core.models import IOCType, ProviderStatus, ThreatIntelResult
from app.integrations.base import (
    disabled_result,
    invalid_key_result,
    provider_error_result,
    rate_limited_result,
    timeout_result,
    unavailable_result,
    unknown_result,
)

_ENDPOINTS = {
    IOCType.IPV4: "https://www.virustotal.com/api/v3/ip_addresses/{ioc}",
    IOCType.IPV6: "https://www.virustotal.com/api/v3/ip_addresses/{ioc}",
    IOCType.DOMAIN: "https://www.virustotal.com/api/v3/domains/{ioc}",
    IOCType.URL: "https://www.virustotal.com/api/v3/urls/{ioc}",
}


def _url_identifier(url: str) -> str:
    """VT identifies a URL report by the unpadded base64 of the URL itself."""
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


class VirusTotalProvider:
    name = "virustotal"

    def __init__(self, api_key: str, enabled: bool, timeout: float = 8.0) -> None:
        self._api_key = api_key
        self._enabled = enabled
        self._timeout = timeout

    def supports(self, ioc_type: IOCType) -> bool:
        return ioc_type in _ENDPOINTS

    async def lookup(self, ioc: str, ioc_type: IOCType) -> ThreatIntelResult:
        if not self._enabled or not self._api_key:
            return disabled_result(self.name, ioc, ioc_type)
        if not self.supports(ioc_type):
            return disabled_result(self.name, ioc, ioc_type)

        identifier = _url_identifier(ioc) if ioc_type is IOCType.URL else ioc
        url = _ENDPOINTS[ioc_type].format(ioc=identifier)

        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.get(
                    url, headers={"x-apikey": self._api_key}
                )
        except httpx.TimeoutException:
            return timeout_result(self.name, ioc, ioc_type)
        except httpx.HTTPError as exc:
            return unavailable_result(self.name, ioc, ioc_type, f"{type(exc).__name__}: {exc}")

        if response.status_code == 401:
            return invalid_key_result(self.name, ioc, ioc_type)
        if response.status_code == 429:
            return rate_limited_result(self.name, ioc, ioc_type)
        if response.status_code == 404:
            return unknown_result(self.name, ioc, ioc_type)
        if response.status_code != 200:
            return provider_error_result(
                self.name, ioc, ioc_type, f"HTTP {response.status_code}"
            )

        try:
            attributes = response.json()["data"]["attributes"]
        except (KeyError, ValueError) as exc:
            return provider_error_result(self.name, ioc, ioc_type, f"malformed response: {exc}")

        stats = attributes.get("last_analysis_stats", {})
        malicious_count = stats.get("malicious", 0)
        suspicious_count = stats.get("suspicious", 0)
        total = sum(stats.values()) if stats else 0
        malicious = malicious_count > 0

        return ThreatIntelResult(
            provider=self.name,
            ioc=ioc,
            ioc_type=ioc_type,
            status=ProviderStatus.SUCCESS,
            looked_up_at=datetime.now(UTC),
            summary=(
                f"{malicious_count}/{total} vendors flag malicious, "
                f"{suspicious_count}/{total} suspicious."
                if total
                else "No vendor detections on file."
            ),
            fields={
                "malicious": malicious,
                "malicious_count": malicious_count,
                "suspicious_count": suspicious_count,
                "harmless_count": stats.get("harmless", 0),
                "total_vendors": total,
                "reputation": attributes.get("reputation"),
                "last_analysis_date": attributes.get("last_analysis_date"),
            },
        )
