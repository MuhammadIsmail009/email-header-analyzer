"""Independent verification against live DNS.

This package is what allows the tool to say "independently verified" rather than
"the receiving server claimed". Every reference project audited is parse-only.

All modules here are synchronous and perform blocking DNS. The service layer runs
them via ``anyio.to_thread.run_sync``.
"""

from app.core.verification.dkim_verifier import fetch_dkim_key, verify_dkim
from app.core.verification.dmarc_verifier import (
    fetch_dmarc_record,
    parse_dmarc_record,
    verify_dmarc,
)
from app.core.verification.dns_checks import check_dnsbl, check_forward_reverse
from app.core.verification.resolver import (
    DnsResolver,
    DnsUnavailable,
    Resolver,
    StaticResolver,
)
from app.core.verification.spf_verifier import verify_spf

__all__ = [
    "DnsResolver",
    "DnsUnavailable",
    "Resolver",
    "StaticResolver",
    "check_dnsbl",
    "check_forward_reverse",
    "fetch_dkim_key",
    "fetch_dmarc_record",
    "parse_dmarc_record",
    "verify_dkim",
    "verify_dmarc",
    "verify_spf",
]
