"""Orchestrates a full analysis: parsing, verification, enrichment and risk assessment.

This is the seam between the framework-free ``app/core`` and everything that needs
I/O — live DNS and outbound HTTP. It is the one place that decides *when* to call the
blocking verification functions (always via a worker thread) and *whether* live
verification runs at all.

Kept intentionally thin: every actual decision (how to parse, how to score, what a
disagreement means) lives in ``app/core``, which stays independently testable. This
module's job is sequencing and evidence assembly into a single :class:`RiskContext`
before handing off to the risk engine.
"""

from __future__ import annotations

import secrets
from datetime import UTC, datetime

import anyio

from app.config import Settings
from app.core.authentication_parser import build_authentication_summary
from app.core.domain_analyzer import lookalike_of, structural_warnings
from app.core.header_parser import parse_headers
from app.core.identity_analyzer import build_identities, compare_identities
from app.core.ioc_extractor import extract_iocs
from app.core.models import (
    AnalysisReport,
    EnrichmentMode,
    VerificationOutcome,
)
from app.core.received_parser import build_route
from app.core.risk_engine import assess
from app.core.rules_impl import LookalikeHit, RiskContext
from app.core.vendor_headers import decode_vendor_headers
from app.core.verification import (
    DnsResolver,
    Resolver,
    check_dnsbl,
    check_forward_reverse,
    verify_dkim,
    verify_dmarc,
    verify_spf,
)
from app.services.enrichment_service import EnrichmentService


def _new_report_id() -> str:
    """An opaque, unguessable report id.

    Never derived from the header content or a sequence number — both would make
    ``/reports/{id}`` enumerable, and a header analysis is exactly the kind of thing
    that should not be guessable by another user of a shared deployment.
    """
    return secrets.token_urlsafe(18)


class AnalysisService:
    def __init__(
        self,
        settings: Settings,
        enrichment: EnrichmentService,
        resolver: Resolver | None = None,
    ) -> None:
        self._settings = settings
        self._enrichment = enrichment
        # A resolver may be injected for testing (a StaticResolver, fully offline).
        # Production wiring leaves this None and a live DnsResolver is constructed
        # lazily below, only when verification is actually enabled.
        self._resolver = resolver

    async def analyze(
        self, raw_header: str, body: str | None = None
    ) -> AnalysisReport:
        """Run a full analysis. ``body`` is only present for an uploaded ``.eml``.

        Passing ``body`` is what enables full DKIM verification (signature + body
        hash) rather than the headers-only signature check — see
        ``verification/dkim_verifier.py`` for exactly what each mode proves.
        """
        parsed = parse_headers(raw_header)
        warnings = list(parsed.warnings)

        route = build_route(
            parsed,
            trusted_domains=self._settings.trusted_receiver_domains,
            trusted_hosts=self._settings.trusted_receiver_hosts,
        )

        auth_summary = build_authentication_summary(
            parsed,
            trusted_domains=self._settings.trusted_receiver_domains,
            trusted_hosts=self._settings.trusted_receiver_hosts,
        )

        identities = build_identities(parsed)
        identity_comparisons = compare_identities(identities)
        vendor_reports = decode_vendor_headers(parsed)
        iocs = tuple(extract_iocs(parsed))

        verifications: list = []
        dnsbl_listings: list[tuple[str, tuple[str, ...]]] = []
        rdns_unconfirmed: list[str] = []
        verification_performed = False
        enrichment_mode = EnrichmentMode.OFFLINE

        if self._settings.verification_enabled:
            verification_performed = True
            resolver = self._resolver or DnsResolver(
                nameservers=self._settings.dns_resolvers,
                timeout=self._settings.dns_timeout_seconds,
                lifetime=self._settings.dns_lifetime_seconds,
            )

            connecting_ip = _spf_connecting_ip(route)
            envelope_from = auth_summary.envelope_from
            helo = auth_summary.helo_identity

            spf_result = await anyio.to_thread.run_sync(
                verify_spf, connecting_ip, envelope_from, helo, resolver
            )
            dkim_result = await anyio.to_thread.run_sync(
                verify_dkim, raw_header, body, resolver
            )

            spf_ok = spf_result.outcome is VerificationOutcome.VERIFIED_PASS
            dkim_ok = dkim_result.outcome is VerificationOutcome.VERIFIED_PASS
            spf_domain = _envelope_domain(envelope_from)

            dmarc_result, spf_alignment, dkim_alignment, dmarc_policy = (
                await anyio.to_thread.run_sync(
                    verify_dmarc,
                    auth_summary.header_from_domain,
                    spf_domain,
                    spf_ok,
                    auth_summary.dkim_signing_domains,
                    dkim_ok,
                    resolver,
                )
            )

            verifications = [spf_result, dkim_result, dmarc_result]
            auth_summary = auth_summary.model_copy(
                update={
                    "spf_alignment": spf_alignment,
                    "dkim_alignment": dkim_alignment,
                    "dmarc_policy": dmarc_policy or auth_summary.dmarc_policy,
                }
            )

            if connecting_ip:
                fcrdns = await anyio.to_thread.run_sync(
                    check_forward_reverse, connecting_ip, resolver
                )
                # checked=False means the address wasn't public (or wasn't valid), so
                # the check was skipped as not meaningful — not the same as running it
                # and getting no confirmation. Only the latter is worth a finding.
                if fcrdns.checked and not fcrdns.forward_confirmed:
                    rdns_unconfirmed.append(connecting_ip)

                if self._settings.dnsbl_enabled:
                    dnsbl = await anyio.to_thread.run_sync(
                        check_dnsbl, connecting_ip, resolver, self._settings.dnsbl_zones
                    )
                    if dnsbl.is_listed:
                        dnsbl_listings.append((connecting_ip, dnsbl.listed_on))

        # -- Lookalike / impersonation ---------------------------------------
        recipient_domain = _recipient_domain(parsed)
        watchlist = tuple(
            dict.fromkeys(
                (*self._settings.protected_domains, *([recipient_domain] if recipient_domain else ()))
            )
        )
        lookalikes: list[LookalikeHit] = []
        domain_warnings: list[str] = []
        if auth_summary.header_from_domain:
            domain_warnings.extend(structural_warnings(auth_summary.header_from_domain))
            if watchlist:
                hit = lookalike_of(auth_summary.header_from_domain, watchlist)
                if hit is not None:
                    matched, technique = hit
                    lookalikes.append(
                        LookalikeHit(
                            domain=auth_summary.header_from_domain,
                            matched=matched,
                            technique=technique,
                        )
                    )

        # -- Enrichment -------------------------------------------------------
        intel_results = ()
        if self._settings.demo_mode:
            enrichment_mode = EnrichmentMode.DEMO_FIXTURE
            intel_results = await self._enrichment.enrich(iocs)
        elif self._settings.enrichment_enabled:
            enrichment_mode = EnrichmentMode.LIVE
            intel_results = await self._enrichment.enrich(iocs)
        else:
            enrichment_mode = EnrichmentMode.DISABLED

        ctx = RiskContext(
            authentication=auth_summary,
            verifications=tuple(verifications),
            route=route,
            identities=tuple(identities),
            iocs=iocs,
            intel=intel_results,
            lookalikes=tuple(lookalikes),
            domain_warnings=tuple(domain_warnings),
            header_warnings=tuple(parsed.warnings),
            dnsbl_listings=tuple(dnsbl_listings),
            rdns_unconfirmed=tuple(rdns_unconfirmed),
            verification_performed=verification_performed,
        )
        risk = assess(ctx)

        recommendations = _build_recommendations(risk)

        return AnalysisReport(
            report_id=_new_report_id(),
            created_at=datetime.now(UTC),
            parsed_header=parsed,
            identities=tuple(identities),
            identity_comparisons=tuple(identity_comparisons),
            route=route,
            authentication=auth_summary,
            verifications=tuple(verifications),
            iocs=iocs,
            intel_results=intel_results,
            vendor_reports=tuple(vendor_reports),
            risk=risk,
            recommendations=tuple(recommendations),
            enrichment_mode=enrichment_mode,
            verification_performed=verification_performed,
            warnings=tuple(warnings),
        )


def _spf_connecting_ip(route) -> str | None:
    """The SMTP client IP that SPF must be evaluated against.

    This is **not** the origin hop's IP. SPF authenticates the client that connected to
    a receiving MTA — i.e. the IP recorded by the first *trusted* receiver, which is
    exactly what a real ``Received-SPF: client-ip=`` reflects. Using the origin hop
    instead is wrong whenever the origin has no IP of its own, which is precisely what
    a locally-injected message from a submission agent or encryption gateway looks
    like (see ``received_parser.py`` — a 'by'-only hop with no 'from' clause). Using
    the origin there would silently pass ``connecting_ip=None`` into SPF evaluation and
    make legitimate mail appear to fail DMARC.

    Falls back to the first hop (in chronological order) that actually recorded an IP,
    if no trusted boundary is configured or found.
    """
    if not route.hops_chronological:
        return None

    if route.first_trusted_hop_index is not None:
        trusted_hop = next(
            (h for h in route.hops_chronological if h.index_in_header == route.first_trusted_hop_index),
            None,
        )
        if trusted_hop and trusted_hop.primary_ip:
            return trusted_hop.primary_ip

    for hop in route.hops_chronological:
        if hop.primary_ip:
            return hop.primary_ip
    return None


def _envelope_domain(envelope_from: str | None) -> str | None:
    if not envelope_from or "@" not in envelope_from:
        return None
    return envelope_from.rsplit("@", 1)[-1].strip().rstrip(".").lower() or None


def _recipient_domain(parsed) -> str | None:
    from app.core.addresses import domain_of_header

    return domain_of_header(parsed.value_of("To"))


def _build_recommendations(risk) -> list[str]:
    """Analyst next steps, driven by the strongest findings rather than restated rules."""
    if not risk.findings:
        return [
            "No findings were generated. Confirm the supplied header was complete."
        ]
    actions: list[str] = []
    seen: set[str] = set()
    for finding in risk.findings:
        if finding.recommended_action not in seen:
            seen.add(finding.recommended_action)
            actions.append(finding.recommended_action)
        if len(actions) >= 6:
            break
    return actions
