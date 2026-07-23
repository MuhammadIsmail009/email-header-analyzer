"""Application settings.

Every limit, timeout and feature flag is here rather than scattered through the code,
so the security posture of the application can be reviewed in one file.

Defaults are deliberately conservative: **outbound enrichment is off** unless it is
explicitly enabled. A SOC analyst working a real phishing report is frequently not
permitted to submit customer indicators to third parties, and phishing URLs are often
unique per recipient — submitting one to a public scanner can tell the attacker their
campaign was detected. Opting in must be a decision, not a default.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # -- Application ------------------------------------------------------
    app_name: str = "Email Header Analyzer"
    environment: str = "development"
    debug: bool = False
    log_level: str = "INFO"

    # -- Input limits -----------------------------------------------------
    max_header_bytes: int = 256 * 1024
    """256 KiB. Headers larger than this are rejected before parsing."""

    max_request_bytes: int = 1024 * 1024
    """1 MiB total request body, enforced by middleware ahead of the route."""

    allowed_upload_extensions: tuple[str, ...] = (".eml", ".txt")

    # -- Trust boundary ---------------------------------------------------
    trusted_receiver_domains: tuple[str, ...] = ()
    """Domains whose ``Authentication-Results`` headers may be believed.

    RFC 8601 §7.1: these headers are forgeable, and safe use requires knowing which
    authserv-id belongs to infrastructure you actually control. With this empty, every
    asserted result is marked UNKNOWN trust — which is the correct default, not a bug.
    """

    trusted_receiver_hosts: tuple[str, ...] = ()

    protected_domains: tuple[str, ...] = ()
    """A watchlist of brand/organisation domains to check lookalike candidates
    against — e.g. your own org plus frequently-impersonated partners.

    This is a watchlist, never a suppression list: nothing here is ever used to
    silence an indicator that would otherwise fire. It only adds "resembles
    <protected domain>" context to an already-suspicious sender domain. The domain in
    the message's own To: header is always checked in addition to this list, since the
    most obvious brand to protect is whoever the tool is being run for.
    """

    # -- Independent verification ----------------------------------------
    verification_enabled: bool = True
    """Live DNS verification of SPF, DKIM and DMARC.

    This is what allows the tool to say 'independently verified' rather than merely
    'recorded'. Disabling it does not degrade results into guesses — the wording falls
    back to reporting only what the receiving MTA asserted.
    """

    dns_resolvers: tuple[str, ...] = ("8.8.8.8", "1.1.1.1")
    dns_timeout_seconds: float = 3.0
    dns_lifetime_seconds: float = 6.0
    dnsbl_zones: tuple[str, ...] = (
        "zen.spamhaus.org",
        "bl.spamcop.net",
        "b.barracudacentral.org",
    )
    dnsbl_enabled: bool = True

    # -- Threat-intelligence enrichment -----------------------------------
    enrichment_enabled: bool = False
    """Off by default. See the module docstring."""

    demo_mode: bool = False
    """Serve deterministic fixture data for the bundled samples only.

    Fixtures are labelled 'Demo Fixture' everywhere they appear, including in exports.
    They are never presented as live data, and a custom indicator with no configured key
    returns DISABLED or UNAVAILABLE — never an invented verdict.
    """

    abuseipdb_api_key: str = ""
    emailrep_api_key: str = ""
    virustotal_api_key: str = ""

    abuseipdb_enabled: bool = True
    emailrep_enabled: bool = True
    virustotal_enabled: bool = False

    max_ip_lookups: int = 10
    max_domain_lookups: int = 10
    max_url_lookups: int = 5
    max_email_lookups: int = 3

    intel_cache_ttl_seconds: int = 3600
    intel_cache_max_entries: int = 2048
    intel_timeout_seconds: float = 8.0
    intel_max_concurrency: int = 8

    # -- Reports ----------------------------------------------------------
    report_cache_ttl_seconds: int = 900
    report_cache_max_entries: int = 128

    # -- Rate limiting ----------------------------------------------------
    rate_limit_enabled: bool = True
    rate_limit_analyze: str = "20/minute"
    rate_limit_default: str = "120/minute"

    # -- Security ---------------------------------------------------------
    csrf_secret: str = Field(default="", repr=False)
    log_raw_headers: bool = False
    """Never enable outside a controlled debugging session. Headers contain recipient
    addresses, internal hostnames and routing detail."""

    @field_validator(
        "trusted_receiver_domains",
        "trusted_receiver_hosts",
        "protected_domains",
        "dns_resolvers",
        "dnsbl_zones",
        "allowed_upload_extensions",
        mode="before",
    )
    @classmethod
    def _split_csv(cls, value: object) -> object:
        """Accept comma-separated strings from the environment."""
        if isinstance(value, str):
            return tuple(part.strip() for part in value.split(",") if part.strip())
        return value

    def provider_enabled(self, provider: str) -> bool:
        """Two gates: the feature flag *and* a non-empty key.

        A provider that is enabled but unkeyed is not silently treated as working; it
        reports DISABLED, so the analyst can see it was never actually consulted.
        """
        flag = getattr(self, f"{provider}_enabled", False)
        key = getattr(self, f"{provider}_api_key", "")
        return bool(flag and key)

    def is_trusted_authserv(self, authserv_id: str | None) -> bool:
        """Whether an RFC 8601 authserv-id belongs to configured trusted infrastructure."""
        if not authserv_id:
            return False
        candidate = authserv_id.strip().lower().rstrip(".")
        if candidate in {h.lower() for h in self.trusted_receiver_hosts}:
            return True
        for domain in self.trusted_receiver_domains:
            domain = domain.lower().strip()
            if not domain:
                continue
            if candidate == domain or candidate.endswith("." + domain):
                return True
        return False


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
