"""EmailRep integration — sender-address reputation.

Only ever sends an email address, never the full header. Enriches the visible From
address, and Reply-To / Sender when they differ from From (the analysis service
decides which addresses to submit; this module just performs one lookup per call).
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
    unknown_result,
)

_API_URL = "https://emailrep.io/{email}"


class EmailRepProvider:
    name = "emailrep"

    def __init__(self, api_key: str, enabled: bool, timeout: float = 8.0) -> None:
        self._api_key = api_key
        self._enabled = enabled
        self._timeout = timeout

    def supports(self, ioc_type: IOCType) -> bool:
        return ioc_type is IOCType.EMAIL

    async def lookup(self, ioc: str, ioc_type: IOCType) -> ThreatIntelResult:
        if not self._enabled or not self._api_key:
            return disabled_result(self.name, ioc, ioc_type)
        if not self.supports(ioc_type):
            return disabled_result(self.name, ioc, ioc_type)

        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.get(
                    _API_URL.format(email=ioc),
                    headers={"Key": self._api_key, "Accept": "application/json"},
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
            payload = response.json()
        except ValueError as exc:
            return provider_error_result(self.name, ioc, ioc_type, f"malformed response: {exc}")

        reputation = payload.get("reputation", "none")
        suspicious = bool(payload.get("suspicious", False))
        details = payload.get("details", {})
        malicious = suspicious or bool(details.get("malicious_activity"))

        return ThreatIntelResult(
            provider=self.name,
            ioc=ioc,
            ioc_type=ioc_type,
            status=ProviderStatus.SUCCESS,
            looked_up_at=datetime.now(UTC),
            summary=(
                f"Reputation: {reputation}"
                + (", flagged suspicious" if suspicious else "")
            ),
            fields={
                "malicious": malicious,
                "reputation": reputation,
                "suspicious": suspicious,
                "references": payload.get("references"),
                "blacklisted": details.get("blacklisted"),
                "malicious_activity": details.get("malicious_activity"),
                "credential_leaked": details.get("credentials_leaked"),
                "domain_reputation": details.get("domain_reputation"),
                "days_since_domain_creation": details.get("days_since_domain_creation"),
                "profiles": details.get("profiles"),
            },
        )
