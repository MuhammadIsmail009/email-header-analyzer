"""AbuseIPDB integration — public IP reputation.

Never sends anything but the bare IP address. Never uses country as a risk signal even
though AbuseIPDB's response includes one — country is captured in ``fields`` for
display only; the risk engine never reads it (asserted by
``test_country_never_contributes_to_score``).
"""

from __future__ import annotations

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
)

_API_URL = "https://api.abuseipdb.com/api/v2/check"


class AbuseIPDBProvider:
    name = "abuseipdb"

    def __init__(self, api_key: str, enabled: bool, timeout: float = 8.0) -> None:
        self._api_key = api_key
        self._enabled = enabled
        self._timeout = timeout

    def supports(self, ioc_type: IOCType) -> bool:
        return ioc_type in (IOCType.IPV4, IOCType.IPV6)

    async def lookup(self, ioc: str, ioc_type: IOCType) -> ThreatIntelResult:
        if not self._enabled or not self._api_key:
            return disabled_result(self.name, ioc, ioc_type)
        if not self.supports(ioc_type):
            return disabled_result(self.name, ioc, ioc_type)

        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.get(
                    _API_URL,
                    headers={"Key": self._api_key, "Accept": "application/json"},
                    params={"ipAddress": ioc, "maxAgeInDays": 90},
                )
        except httpx.TimeoutException:
            return timeout_result(self.name, ioc, ioc_type)
        except httpx.HTTPError as exc:
            return unavailable_result(self.name, ioc, ioc_type, f"{type(exc).__name__}: {exc}")

        if response.status_code == 401:
            return invalid_key_result(self.name, ioc, ioc_type)
        if response.status_code == 429:
            return rate_limited_result(self.name, ioc, ioc_type)
        if response.status_code != 200:
            return provider_error_result(
                self.name, ioc, ioc_type, f"HTTP {response.status_code}"
            )

        try:
            payload = response.json()["data"]
        except (KeyError, ValueError) as exc:
            return provider_error_result(self.name, ioc, ioc_type, f"malformed response: {exc}")

        confidence = payload.get("abuseConfidenceScore", 0)
        malicious = confidence >= 50
        total_reports = payload.get("totalReports", 0)

        return ThreatIntelResult(
            provider=self.name,
            ioc=ioc,
            ioc_type=ioc_type,
            status=ProviderStatus.SUCCESS,
            looked_up_at=datetime.now(UTC),
            summary=(
                f"Abuse confidence {confidence}%, {total_reports} report(s)."
                if total_reports
                else f"Abuse confidence {confidence}%, no reports."
            ),
            fields={
                "malicious": malicious,
                "abuse_confidence_score": confidence,
                "total_reports": total_reports,
                "last_reported_at": payload.get("lastReportedAt"),
                "isp": payload.get("isp"),
                "usage_type": payload.get("usageType"),
                "domain": payload.get("domain"),
                "is_whitelisted": payload.get("isWhitelisted"),
                # Captured for display only. The risk engine never reads this key.
                "country_code": payload.get("countryCode"),
            },
        )
