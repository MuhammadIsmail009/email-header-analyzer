"""Independent DMARC policy retrieval and alignment evaluation.

DMARC (RFC 7489) does not authenticate anything by itself. It asks one question: did
SPF *or* DKIM pass **and** align with the domain in the visible ``From:`` header?

That is the question this module answers, computed from evidence rather than read out
of a ``dmarc=pass`` string. A receiver's recorded verdict tells you it aligned against
whatever it considered the From domain; recomputing it against the ``From:`` actually
present is what catches the case where SPF passes legitimately on a relay's own domain
while the visible sender claims to be someone else.
"""

from __future__ import annotations

from app.core.domain_analyzer import (
    compare_domains,
    is_aligned,
    normalize_domain,
    organizational_domain,
)
from app.core.models import (
    AlignmentResult,
    AuthMethod,
    VerificationOutcome,
    VerificationResult,
)
from app.core.verification.resolver import DnsUnavailable, Resolver


def parse_dmarc_record(record: str) -> dict[str, str]:
    """Parse a ``v=DMARC1; p=...; adkim=r; aspf=r`` record into tags."""
    tags: dict[str, str] = {}
    for part in record.split(";"):
        if "=" not in part:
            continue
        key, _, value = part.partition("=")
        key = key.strip().lower()
        if key:
            tags[key] = value.strip()
    return tags


def fetch_dmarc_record(
    domain: str | None, resolver: Resolver
) -> tuple[str | None, dict[str, str], str | None]:
    """Retrieve the DMARC record for ``domain``, falling back to its organisational parent.

    RFC 7489 §6.6.3: if no record exists at ``_dmarc.<domain>``, the organisational
    domain is queried instead. Skipping that fallback makes every subdomain of a
    protected domain look unprotected.

    Returns ``(record, tags, error)``.
    """
    normalized = normalize_domain(domain)
    if not normalized:
        return None, {}, "no domain to query"

    candidates = [normalized]
    org = organizational_domain(normalized)
    if org and org != normalized:
        candidates.append(org)

    for candidate in candidates:
        try:
            records = resolver.txt(f"_dmarc.{candidate}")
        except DnsUnavailable as exc:
            return None, {}, str(exc)
        for record in records:
            if record.strip().lower().startswith("v=dmarc1"):
                return record.strip(), parse_dmarc_record(record), None

    return None, {}, None


def verify_dmarc(
    header_from_domain: str | None,
    spf_domain: str | None,
    spf_passed: bool,
    dkim_domains: tuple[str, ...],
    dkim_passed: bool,
    resolver: Resolver,
) -> tuple[VerificationResult, AlignmentResult, AlignmentResult, str | None]:
    """Evaluate DMARC.

    Returns ``(result, spf_alignment, dkim_alignment, policy)``.
    """
    if not header_from_domain:
        return (
            VerificationResult(
                method=AuthMethod.DMARC,
                outcome=VerificationOutcome.NOT_POSSIBLE,
                detail=(
                    "No usable From: domain, so DMARC — which is defined entirely "
                    "against the visible From domain — cannot be evaluated."
                ),
            ),
            AlignmentResult.UNKNOWN,
            AlignmentResult.UNKNOWN,
            None,
        )

    record, tags, error = fetch_dmarc_record(header_from_domain, resolver)

    if error:
        return (
            VerificationResult(
                method=AuthMethod.DMARC,
                outcome=VerificationOutcome.ERROR,
                detail=f"DNS was unavailable, so DMARC could not be verified: {error}",
                checked_domain=header_from_domain,
                error=error,
            ),
            AlignmentResult.UNKNOWN,
            AlignmentResult.UNKNOWN,
            None,
        )

    strict_spf = tags.get("aspf", "r").lower() == "s"
    strict_dkim = tags.get("adkim", "r").lower() == "s"

    spf_alignment = (
        compare_domains(spf_domain, header_from_domain)
        if spf_domain
        else AlignmentResult.UNKNOWN
    )
    dkim_alignment = AlignmentResult.UNKNOWN
    if dkim_domains:
        comparisons = [compare_domains(d, header_from_domain) for d in dkim_domains]
        for preferred in (
            AlignmentResult.EXACT,
            AlignmentResult.SUBDOMAIN,
            AlignmentResult.ORGANIZATIONAL,
            AlignmentResult.MISMATCH,
        ):
            if preferred in comparisons:
                dkim_alignment = preferred
                break

    if record is None:
        return (
            VerificationResult(
                method=AuthMethod.DMARC,
                outcome=VerificationOutcome.NOT_POSSIBLE,
                detail=(
                    f"{header_from_domain} publishes no DMARC record (checked "
                    f"_dmarc.{header_from_domain} and its organisational domain). "
                    "The domain owner has not asked receivers to reject or quarantine "
                    "mail that fails alignment, so spoofing it is comparatively easy. "
                    "This is a weakness of the domain, not evidence about this message."
                ),
                checked_domain=header_from_domain,
            ),
            spf_alignment,
            dkim_alignment,
            None,
        )

    policy = tags.get("p", "none").lower()
    spf_ok = spf_passed and is_aligned(spf_alignment, strict_spf)
    dkim_ok = dkim_passed and is_aligned(dkim_alignment, strict_dkim)
    passes = spf_ok or dkim_ok

    if passes:
        via = "SPF" if spf_ok else "DKIM"
        detail = (
            f"Independently evaluated: DMARC pass via {via}. "
            f"Policy p={policy}"
            + (f", pct={tags['pct']}" if "pct" in tags else "")
            + f". Alignment mode aspf={'s' if strict_spf else 'r'}, "
            f"adkim={'s' if strict_dkim else 'r'}."
        )
        outcome = VerificationOutcome.VERIFIED_PASS
    else:
        reasons = []
        if not spf_passed:
            reasons.append("SPF did not pass")
        elif not is_aligned(spf_alignment, strict_spf):
            reasons.append(
                f"SPF passed but its domain does not align with {header_from_domain}"
            )
        if not dkim_passed:
            reasons.append("DKIM did not pass")
        elif not is_aligned(dkim_alignment, strict_dkim):
            reasons.append(
                f"DKIM passed but its signing domain does not align with "
                f"{header_from_domain}"
            )
        detail = (
            "Independently evaluated: DMARC fail. "
            + "; ".join(reasons)
            + f". The domain publishes p={policy}"
            + (
                ", so conforming receivers are asked to reject failing mail."
                if policy == "reject"
                else ", so conforming receivers are asked to quarantine failing mail."
                if policy == "quarantine"
                else ", so the domain owner requests no enforcement action."
            )
        )
        outcome = VerificationOutcome.VERIFIED_FAIL

    return (
        VerificationResult(
            method=AuthMethod.DMARC,
            outcome=outcome,
            detail=detail,
            checked_domain=header_from_domain,
            record=record,
            scope=f"alignment against From: domain {header_from_domain}",
        ),
        spf_alignment,
        dkim_alignment,
        policy,
    )
