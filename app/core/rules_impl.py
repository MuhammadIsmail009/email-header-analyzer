"""Rule matching logic, registered against the IDs declared in ``rules/rules.yaml``.

Each predicate receives a :class:`RiskContext` and returns either ``None`` (rule did
not fire) or a string describing the *specific evidence* that made it fire. The engine
pairs that evidence with the rule's declared prose and weight.

Returning evidence rather than a boolean is deliberate: a finding that says
"Reply-To organisational domain mismatch" is much less useful than one that says
"Reply-To is billing@payments-secure.example while From is billing@bank.example".
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from app.core.domain_analyzer import compare_domains, is_aligned
from app.core.models import (
    IOC,
    AlignmentResult,
    AuthenticationSummary,
    AuthMethod,
    AuthResult,
    Identity,
    MailRoute,
    ProviderStatus,
    ThreatIntelResult,
    TrustStatus,
    VerificationOutcome,
    VerificationResult,
)


@dataclass(frozen=True)
class LookalikeHit:
    domain: str
    matched: str
    technique: str


@dataclass
class RiskContext:
    """Everything the rules may inspect.

    Assembled by the analysis service. Rules must not perform I/O — they read this
    structure and nothing else, which is what makes them individually unit-testable.
    """

    authentication: AuthenticationSummary | None = None
    verifications: tuple[VerificationResult, ...] = ()
    route: MailRoute | None = None
    identities: tuple[Identity, ...] = ()
    iocs: tuple[IOC, ...] = ()
    intel: tuple[ThreatIntelResult, ...] = ()
    lookalikes: tuple[LookalikeHit, ...] = ()
    domain_warnings: tuple[str, ...] = ()
    header_warnings: tuple[str, ...] = ()
    dnsbl_listings: tuple[tuple[str, tuple[str, ...]], ...] = ()
    rdns_unconfirmed: tuple[str, ...] = ()
    verification_performed: bool = False
    reputation: dict[str, object] = field(default_factory=dict)

    # -- convenience accessors -------------------------------------------
    def verification(self, method: AuthMethod) -> VerificationResult | None:
        for result in self.verifications:
            if result.method is method:
                return result
        return None

    def identity(self, header: str) -> Identity | None:
        for item in self.identities:
            if item.source_header.lower() == header.lower():
                return item
        return None

    def verified(self, method: AuthMethod, outcome: VerificationOutcome) -> bool:
        result = self.verification(method)
        return result is not None and result.outcome is outcome

    def asserted(self, method: AuthMethod) -> AuthResult | None:
        if self.authentication is None:
            return None
        for item in self.authentication.evidence:
            if item.method is method:
                return item.result
        return None

    @property
    def from_domain(self) -> str | None:
        return self.authentication.header_from_domain if self.authentication else None


Predicate = Callable[[RiskContext], str | None]
REGISTRY: dict[str, Predicate] = {}


def rule(rule_id: str) -> Callable[[Predicate], Predicate]:
    def decorator(func: Predicate) -> Predicate:
        REGISTRY[rule_id] = func
        return func

    return decorator


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------


@rule("AUTH-001")
def dmarc_verified_fail(ctx: RiskContext) -> str | None:
    result = ctx.verification(AuthMethod.DMARC)
    if result and result.outcome is VerificationOutcome.VERIFIED_FAIL:
        return result.detail
    return None


@rule("AUTH-002")
def spf_verified_fail(ctx: RiskContext) -> str | None:
    result = ctx.verification(AuthMethod.SPF)
    if result and result.outcome is VerificationOutcome.VERIFIED_FAIL:
        return result.detail
    return None


@rule("AUTH-003")
def dkim_verified_fail(ctx: RiskContext) -> str | None:
    result = ctx.verification(AuthMethod.DKIM)
    if result and result.outcome is VerificationOutcome.VERIFIED_FAIL:
        return result.detail
    return None


@rule("AUTH-004")
def untrusted_assertion(ctx: RiskContext) -> str | None:
    """Fires only when a *pass* was asserted by infrastructure we do not trust.

    An untrusted *failure* is not worth points — nobody forges a failure against
    themselves. It is the unearned green tick that misleads.
    """
    if ctx.authentication is None:
        return None
    suspicious = [
        item
        for item in ctx.authentication.evidence
        if item.trust is TrustStatus.UNTRUSTED and item.result is AuthResult.PASS
    ]
    if not suspicious:
        return None
    methods = ", ".join(sorted({i.method.value.upper() for i in suspicious}))
    asserted_by = suspicious[0].asserted_by or "an unidentified host"
    return (
        f"{methods} pass asserted by {asserted_by}, which is not configured trusted "
        "infrastructure. Per RFC 8601 §7.1 this header can be written by the sender."
    )


@rule("AUTH-005")
def no_authentication_evidence(ctx: RiskContext) -> str | None:
    if ctx.authentication is None:
        return None
    if ctx.authentication.evidence:
        return None
    return (
        "No Authentication-Results, ARC-Authentication-Results or Received-SPF header "
        "is present in the supplied message."
    )


@rule("AUTH-006")
def spf_pass_without_alignment(ctx: RiskContext) -> str | None:
    auth = ctx.authentication
    if auth is None or auth.spf_alignment is AlignmentResult.UNKNOWN:
        return None
    passed = ctx.asserted(AuthMethod.SPF) is AuthResult.PASS or ctx.verified(
        AuthMethod.SPF, VerificationOutcome.VERIFIED_PASS
    )
    if passed and not is_aligned(auth.spf_alignment):
        return (
            f"SPF passed for envelope domain {auth.envelope_from or 'unknown'}, which "
            f"does not share an organisational domain with the visible From domain "
            f"{auth.header_from_domain}."
        )
    return None


@rule("AUTH-007")
def dkim_pass_without_alignment(ctx: RiskContext) -> str | None:
    auth = ctx.authentication
    if auth is None or auth.dkim_alignment is AlignmentResult.UNKNOWN:
        return None
    passed = ctx.asserted(AuthMethod.DKIM) is AuthResult.PASS or ctx.verified(
        AuthMethod.DKIM, VerificationOutcome.VERIFIED_PASS
    )
    if passed and not is_aligned(auth.dkim_alignment):
        return (
            f"DKIM signing domain(s) {', '.join(auth.dkim_signing_domains) or 'unknown'} "
            f"do not align with the visible From domain {auth.header_from_domain}."
        )
    return None


@rule("AUTH-008")
def verified_contradicts_asserted(ctx: RiskContext) -> str | None:
    """The disagreement case — the reason asserted and verified are shown separately."""
    if not ctx.verification_performed:
        return None
    conflicts: list[str] = []
    for method in (AuthMethod.SPF, AuthMethod.DKIM, AuthMethod.DMARC):
        asserted = ctx.asserted(method)
        verified = ctx.verification(method)
        if asserted is None or verified is None:
            continue
        if (
            asserted is AuthResult.PASS
            and verified.outcome is VerificationOutcome.VERIFIED_FAIL
        ):
            conflicts.append(
                f"{method.value.upper()}: header records 'pass', our own check says fail"
            )
        elif (
            asserted is AuthResult.FAIL
            and verified.outcome is VerificationOutcome.VERIFIED_PASS
        ):
            conflicts.append(
                f"{method.value.upper()}: header records 'fail', our own check says pass"
            )
    return "; ".join(conflicts) if conflicts else None


@rule("AUTH-009")
def no_dmarc_policy(ctx: RiskContext) -> str | None:
    result = ctx.verification(AuthMethod.DMARC)
    if (
        result
        and result.outcome is VerificationOutcome.NOT_POSSIBLE
        and "publishes no DMARC record" in result.detail
    ):
        return f"{result.checked_domain} publishes no DMARC record."
    return None


@rule("AUTH-010")
def full_aligned_pass(ctx: RiskContext) -> str | None:
    """Risk-reducing. Requires *verified* passes, not merely asserted ones."""
    auth = ctx.authentication
    if auth is None or not ctx.verification_performed:
        return None
    spf_ok = ctx.verified(AuthMethod.SPF, VerificationOutcome.VERIFIED_PASS)
    dmarc_ok = ctx.verified(AuthMethod.DMARC, VerificationOutcome.VERIFIED_PASS)
    if not (spf_ok and dmarc_ok):
        return None
    if not is_aligned(auth.spf_alignment) and not is_aligned(auth.dkim_alignment):
        return None
    return (
        f"SPF and DMARC independently verified as passing and aligned with "
        f"{auth.header_from_domain}."
    )


# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------


def _org_mismatch(ctx: RiskContext, header: str) -> tuple[str, str] | None:
    identity = ctx.identity(header)
    if identity is None or not identity.domain or not ctx.from_domain:
        return None
    if compare_domains(identity.domain, ctx.from_domain) is AlignmentResult.MISMATCH:
        return identity.address or identity.domain, ctx.from_domain
    return None


@rule("IDN-001")
def reply_to_mismatch(ctx: RiskContext) -> str | None:
    found = _org_mismatch(ctx, "Reply-To")
    if found:
        return f"Reply-To is {found[0]}, but From is in {found[1]}. Replies leave the sender's organisation."
    return None


@rule("IDN-002")
def return_path_mismatch(ctx: RiskContext) -> str | None:
    found = _org_mismatch(ctx, "Return-Path")
    if found:
        return f"Return-Path is {found[0]}, but From is in {found[1]}."
    return None


@rule("IDN-003")
def message_id_mismatch(ctx: RiskContext) -> str | None:
    identity = ctx.identity("Message-ID")
    if identity is None or not identity.domain or not ctx.from_domain:
        return None
    if compare_domains(identity.domain, ctx.from_domain) is not AlignmentResult.MISMATCH:
        return None
    # Not a finding if the Message-ID domain matches a host that actually handled it.
    if ctx.route:
        for hop in ctx.route.hops_chronological:
            for host in (hop.by_host, hop.from_host, hop.from_rdns):
                if host and compare_domains(identity.domain, host) is not AlignmentResult.MISMATCH:
                    return None
    return (
        f"Message-ID domain {identity.domain} matches neither the From domain "
        f"{ctx.from_domain} nor any host in the Received chain."
    )


@rule("IDN-004")
def display_name_contains_foreign_address(ctx: RiskContext) -> str | None:
    identity = ctx.identity("From")
    if identity is None or not identity.display_name or not identity.address:
        return None
    display = identity.display_name
    if "@" not in display:
        return None
    embedded = display.split()[-1].strip("<>\"' ")
    if "@" not in embedded:
        return None
    if compare_domains(
        embedded.rsplit("@", 1)[-1], identity.domain
    ) is AlignmentResult.MISMATCH:
        return (
            f"Display name reads {display!r}, but the actual sending address is "
            f"{identity.address}. Most mail clients show only the display name."
        )
    return None


@rule("IDN-005")
def duplicate_singleton(ctx: RiskContext) -> str | None:
    hits = [w for w in ctx.header_warnings if "RFC 5322 §3.6 permits at most one" in w]
    return " ".join(hits) if hits else None


# ---------------------------------------------------------------------------
# Impersonation
# ---------------------------------------------------------------------------


@rule("IMP-001")
def lookalike_domain(ctx: RiskContext) -> str | None:
    if not ctx.lookalikes:
        return None
    hit = ctx.lookalikes[0]
    return f"{hit.domain} resembles {hit.matched} — {hit.technique}."


@rule("IMP-002")
def punycode_or_mixed_script(ctx: RiskContext) -> str | None:
    hits = [
        w
        for w in ctx.domain_warnings
        if "punycode" in w.lower() or "writing systems" in w.lower()
    ]
    return " ".join(hits) if hits else None


# ---------------------------------------------------------------------------
# Route
# ---------------------------------------------------------------------------


@rule("RTE-001")
def negative_hop_delay(ctx: RiskContext) -> str | None:
    if ctx.route is None:
        return None
    skews = [d for d in ctx.route.delays if d.is_clock_skew]
    if not skews:
        return None
    worst = min(skews, key=lambda d: d.seconds)
    return (
        f"Transit time between hops {worst.from_hop_index} and {worst.to_hop_index} is "
        f"{worst.seconds:.1f}s."
    )


@rule("RTE-002")
def no_trust_boundary(ctx: RiskContext) -> str | None:
    if ctx.route is None or not ctx.route.hops_header_order:
        return None
    if ctx.route.first_trusted_hop_index is None:
        return ctx.route.trust_boundary_explanation
    return None


@rule("RTE-003")
def rdns_not_confirmed(ctx: RiskContext) -> str | None:
    if not ctx.rdns_unconfirmed:
        return None
    return (
        "No forward-confirmed reverse DNS for: " + ", ".join(ctx.rdns_unconfirmed) + "."
    )


@rule("RTE-004")
def unencrypted_hop(ctx: RiskContext) -> str | None:
    if ctx.route is None:
        return None
    plaintext = [
        hop for hop in ctx.route.hops_chronological if hop.used_tls is False
    ]
    if not plaintext:
        return None
    hosts = ", ".join(h.by_host or f"hop {h.index_in_header}" for h in plaintext)
    return f"Plain ESMTP (no TLS) recorded at: {hosts}."


# ---------------------------------------------------------------------------
# Threat intelligence
# ---------------------------------------------------------------------------


@rule("TI-001")
def dnsbl_listed(ctx: RiskContext) -> str | None:
    if not ctx.dnsbl_listings:
        return None
    parts = [f"{ip} listed on {', '.join(zones)}" for ip, zones in ctx.dnsbl_listings]
    return "; ".join(parts) + "."


def _malicious_by_ioc(ctx: RiskContext) -> dict[str, list[str]]:
    """Group actionable malicious verdicts by indicator.

    Only SUCCESS and DEMO_FIXTURE results are considered. Everything else means the
    provider did not tell us anything, and absence of information is not information.
    """
    grouped: dict[str, list[str]] = {}
    for result in ctx.intel:
        if not result.is_actionable:
            continue
        if result.fields.get("malicious") is True:
            grouped.setdefault(result.ioc, []).append(result.provider)
    return grouped


@rule("TI-002")
def multi_provider_malicious(ctx: RiskContext) -> str | None:
    grouped = _malicious_by_ioc(ctx)
    consensus = {ioc: p for ioc, p in grouped.items() if len(p) >= 2}
    if not consensus:
        return None
    return "; ".join(
        f"{ioc} reported malicious by {', '.join(sorted(providers))}"
        for ioc, providers in consensus.items()
    )


@rule("TI-003")
def single_provider_malicious(ctx: RiskContext) -> str | None:
    grouped = _malicious_by_ioc(ctx)
    single = {ioc: p for ioc, p in grouped.items() if len(p) == 1}
    if not single:
        return None
    return "; ".join(
        f"{ioc} reported malicious by {providers[0]} only"
        for ioc, providers in single.items()
    )


@rule("TI-004")
def intel_unavailable(ctx: RiskContext) -> str | None:
    """Zero weight. Present so the report states what was *not* checked."""
    unchecked = [
        r
        for r in ctx.intel
        if r.status
        in (
            ProviderStatus.DISABLED,
            ProviderStatus.UNAVAILABLE,
            ProviderStatus.RATE_LIMITED,
            ProviderStatus.INVALID_KEY,
            ProviderStatus.TIMEOUT,
            ProviderStatus.PROVIDER_ERROR,
        )
    ]
    if not unchecked:
        return None
    by_status: dict[str, set[str]] = {}
    for item in unchecked:
        by_status.setdefault(item.status.value, set()).add(item.provider)
    summary = "; ".join(
        f"{status}: {', '.join(sorted(providers))}"
        for status, providers in sorted(by_status.items())
    )
    return f"{len(unchecked)} lookup(s) returned no data — {summary}."


@rule("REP-001")
def poor_sender_reputation(ctx: RiskContext) -> str | None:
    for result in ctx.intel:
        if not result.is_actionable or result.provider.lower() != "emailrep":
            continue
        if result.fields.get("suspicious") is True or result.fields.get(
            "reputation"
        ) in ("low", "poor", "none"):
            return f"{result.ioc}: {result.summary or 'reported suspicious'}"
    return None


@rule("REP-002")
def good_sender_reputation(ctx: RiskContext) -> str | None:
    for result in ctx.intel:
        if not result.is_actionable or result.provider.lower() != "emailrep":
            continue
        if (
            result.fields.get("reputation") == "high"
            and result.fields.get("suspicious") is False
        ):
            return f"{result.ioc}: established address with no reported malicious activity."
    return None


# ---------------------------------------------------------------------------
# Possible BEC
# ---------------------------------------------------------------------------


@rule("BEC-001")
def possible_bec_pattern(ctx: RiskContext) -> str | None:
    """Authentication succeeds *and* identity is inconsistent.

    Requires both halves. Authentication failure plus a mismatch is ordinary phishing;
    what characterises BEC and lookalike-domain impersonation is that the message
    authenticates perfectly — because the attacker owns the domain or the mailbox — and
    the inconsistency is in who the message claims to be from and where a reply goes.
    """
    auth = ctx.authentication
    if auth is None:
        return None

    dmarc_ok = ctx.verified(
        AuthMethod.DMARC, VerificationOutcome.VERIFIED_PASS
    ) or ctx.asserted(AuthMethod.DMARC) is AuthResult.PASS
    spf_ok = ctx.verified(
        AuthMethod.SPF, VerificationOutcome.VERIFIED_PASS
    ) or ctx.asserted(AuthMethod.SPF) is AuthResult.PASS
    if not (dmarc_ok or spf_ok):
        return None

    signals: list[str] = []
    if reply_to_mismatch(ctx):
        signals.append("reply path diverges from the sending organisation")
    if ctx.lookalikes:
        hit = ctx.lookalikes[0]
        signals.append(f"sending domain resembles {hit.matched} ({hit.technique})")
    if display_name_contains_foreign_address(ctx):
        signals.append("display name misrepresents the sending address")

    if not signals:
        return None
    return (
        "Message authenticates correctly, yet: " + "; ".join(signals) + ". "
        "Authentication cannot distinguish a compromised or attacker-owned account "
        "from a legitimate one."
    )
