"""Sender-identity extraction and comparison.

Builds the :class:`Identity` objects that the UI's identity block and the risk
engine's ``IDN-*`` rules both depend on — From, Sender, Return-Path, Reply-To and
Message-ID.

The comparisons here are DMARC-style organisational-domain comparisons (via
``domain_analyzer.compare_domains``), never raw string equality, and never treated as
a verdict on their own. A mismatch is a data point; whether it means anything depends
on which fields disagree and by how much, which is what the risk engine's rules weigh.
"""

from __future__ import annotations

from app.core.addresses import address_domain, parse_addresses
from app.core.domain_analyzer import (
    compare_domains,
    organizational_domain,
    to_unicode,
)
from app.core.models import AlignmentResult, Identity, IdentityComparison, ParsedHeader

_IDENTITY_HEADERS = ("From", "Sender", "Return-Path", "Reply-To", "Message-ID")


def _address_domain_from_message_id(value: str) -> str | None:
    """A Message-ID's domain is the part after the last ``@`` inside ``<...>``."""
    stripped = value.strip().strip("<>")
    if "@" not in stripped:
        return None
    return address_domain(stripped)


def build_identity(header_name: str, raw_value: str) -> Identity | None:
    """Build an :class:`Identity` from one header's raw value.

    Returns ``None`` for an empty/absent value rather than an empty Identity, so the
    caller can distinguish "field absent" from "field present but unparsable" — the
    latter still produces an Identity with warnings.
    """
    if not raw_value or not raw_value.strip():
        return None

    warnings: list[str] = []

    if header_name.lower() == "message-id":
        domain = _address_domain_from_message_id(raw_value)
        return Identity(
            source_header=header_name,
            raw=raw_value,
            address=raw_value.strip().strip("<>") or None,
            domain=domain,
            organizational_domain=organizational_domain(domain) if domain else None,
            is_unicode=any(ord(c) > 127 for c in raw_value),
            warnings=tuple(warnings) if domain else ("Message-ID has no @domain part",),
        )

    if header_name.lower() == "return-path":
        # Return-Path is a bare envelope address, not display-name syntax, and is
        # sometimes literally "<>" for a bounce — that is valid and means "no sender".
        stripped = raw_value.strip().strip("<>")
        if not stripped:
            return Identity(
                source_header=header_name,
                raw=raw_value,
                warnings=("empty Return-Path: a null return path, valid for bounces",),
            )
        domain = address_domain(stripped)
        return Identity(
            source_header=header_name,
            raw=raw_value,
            address=stripped,
            domain=domain,
            organizational_domain=organizational_domain(domain) if domain else None,
            is_unicode=any(ord(c) > 127 for c in raw_value),
        )

    pairs = parse_addresses(raw_value)
    if not pairs:
        return Identity(
            source_header=header_name,
            raw=raw_value,
            warnings=(f"{header_name} could not be parsed as an address",),
        )

    display_name, address = pairs[0]
    domain = address_domain(address) if address else None
    if len(pairs) > 1:
        warnings.append(
            f"{header_name} contains {len(pairs)} addresses; only the first is compared"
        )

    return Identity(
        source_header=header_name,
        raw=raw_value,
        display_name=display_name or None,
        address=address or None,
        domain=domain,
        organizational_domain=organizational_domain(domain) if domain else None,
        is_unicode=any(ord(c) > 127 for c in raw_value),
        warnings=tuple(warnings),
    )


def build_identities(parsed: ParsedHeader) -> list[Identity]:
    """One Identity per present identity header, in the standard analyst order."""
    identities: list[Identity] = []
    for header_name in _IDENTITY_HEADERS:
        field = parsed.get_first(header_name)
        if field is None:
            continue
        value = field.decoded_value or field.normalized_value
        identity = build_identity(header_name, value)
        if identity is not None:
            identities.append(identity)
    return identities


def compare_identities(identities: list[Identity]) -> list[IdentityComparison]:
    """Pairwise comparisons against From, for the identity-block UI.

    From is the anchor because it is what the recipient actually sees. Every other
    identity field is compared against it, never against each other — a Reply-To vs
    Return-Path comparison is not a standard analyst check and would just add noise.
    """
    by_header = {i.source_header: i for i in identities}
    from_identity = by_header.get("From")
    if from_identity is None or not from_identity.domain:
        return []

    comparisons: list[IdentityComparison] = []
    for header_name in ("Sender", "Return-Path", "Reply-To", "Message-ID"):
        other = by_header.get(header_name)
        if other is None or not other.domain:
            continue
        result = compare_domains(from_identity.domain, other.domain)
        comparisons.append(
            IdentityComparison(
                left="From",
                right=header_name,
                left_domain=from_identity.domain,
                right_domain=other.domain,
                result=result,
                explanation=_explain(header_name, result, from_identity.domain, other.domain),
            )
        )
    return comparisons


def _explain(header_name: str, result: AlignmentResult, from_domain: str, other_domain: str) -> str:
    if result is AlignmentResult.EXACT:
        return f"{header_name} matches From exactly ({other_domain})."
    if result is AlignmentResult.SUBDOMAIN:
        return f"{header_name} ({other_domain}) is a subdomain relationship with From ({from_domain})."
    if result is AlignmentResult.ORGANIZATIONAL:
        return f"{header_name} ({other_domain}) shares an organisational domain with From ({from_domain})."
    if result is AlignmentResult.MISMATCH:
        return f"{header_name} ({other_domain}) belongs to a different organisation than From ({from_domain})."
    return f"{header_name} domain could not be compared with From."


def display_domain(identity: Identity | None) -> str | None:
    """Unicode form of an identity's domain, for display only — never for comparison."""
    if identity is None or not identity.domain:
        return None
    return to_unicode(identity.domain)
