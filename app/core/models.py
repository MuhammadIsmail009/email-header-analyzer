"""Typed models for the analysis core.

This module — and everything else under ``app/core`` — must not import FastAPI,
Starlette or Jinja2. The analysis core is a pure library that accepts strings and
returns objects, so it can be tested without an HTTP layer. This is enforced by
``tests/unit/test_architecture.py::test_core_has_no_web_imports``.

Models are frozen. An analysis report is evidence: once produced, nothing should be
able to quietly mutate it before it reaches the analyst or an export.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True)


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class IPClass(str, Enum):
    """Classification of an IP address, per :mod:`ipaddress`.

    Only ``PUBLIC`` addresses are eligible for threat-intelligence enrichment.
    Submitting RFC 1918 space to a reputation provider leaks internal topology and
    tells you nothing, because the answer is about somebody else's 10.0.0.0/8.
    """

    PUBLIC = "public"
    PRIVATE = "private"
    LOOPBACK = "loopback"
    LINK_LOCAL = "link_local"
    RESERVED = "reserved"
    MULTICAST = "multicast"
    UNSPECIFIED = "unspecified"
    DOCUMENTATION = "documentation"
    INVALID = "invalid"


class AuthMethod(str, Enum):
    SPF = "spf"
    DKIM = "dkim"
    DMARC = "dmarc"
    ARC = "arc"
    IPREV = "iprev"


class AuthResult(str, Enum):
    """Result values defined by RFC 8601 §2.7, plus ``UNKNOWN`` for unparsable input."""

    PASS = "pass"
    FAIL = "fail"
    SOFTFAIL = "softfail"
    NEUTRAL = "neutral"
    NONE = "none"
    TEMPERROR = "temperror"
    PERMERROR = "permerror"
    POLICY = "policy"
    UNKNOWN = "unknown"


class TrustStatus(str, Enum):
    """Whether an ``Authentication-Results`` header may be believed.

    RFC 8601 §7.1 is explicit that these headers are forgeable: an attacker can place
    ``Authentication-Results: yourcompany.com; spf=pass; dkim=pass; dmarc=pass`` into a
    message they send. Safe use requires the receiving ADMD to strip inbound copies
    bearing its own authserv-id, and requires the reader to check *who* asserted the
    result. A result whose authserv-id is not configured trusted infrastructure is
    evidence of nothing.
    """

    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"
    UNKNOWN = "unknown"


class VerificationOutcome(str, Enum):
    """Result of *our own* check, as distinct from what the MTA asserted."""

    VERIFIED_PASS = "verified_pass"
    VERIFIED_FAIL = "verified_fail"
    NOT_PERFORMED = "not_performed"  # offline mode, or verification disabled
    NOT_POSSIBLE = "not_possible"  # evidence absent (e.g. no body for a body hash)
    ERROR = "error"  # DNS failure, timeout, malformed record


class AlignmentResult(str, Enum):
    """How an authenticated domain relates to the visible ``From:`` domain.

    DMARC (RFC 7489) requires SPF or DKIM to *align* with the header From domain, not
    merely to pass. This is the check that catches ESP-relayed spoofing: SPF can pass
    perfectly on ``sendgrid.net`` while ``From:`` claims ``yourbank.com``.
    """

    EXACT = "exact"
    ORGANIZATIONAL = "organizational"
    SUBDOMAIN = "subdomain"
    MISMATCH = "mismatch"
    UNKNOWN = "unknown"


class IOCType(str, Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"


class ProviderStatus(str, Enum):
    """Outcome of a threat-intelligence lookup.

    These are kept distinct on purpose. Collapsing them is the defect that makes a
    reference project unable to tell the analyst whether an indicator was clean or
    whether the API key was simply wrong. ``UNKNOWN`` means the provider has no data;
    it does **not** mean clean, and it must never be rendered as clean.
    """

    SUCCESS = "success"
    UNKNOWN = "unknown"
    UNAVAILABLE = "unavailable"
    DISABLED = "disabled"
    RATE_LIMITED = "rate_limited"
    INVALID_KEY = "invalid_key"
    TIMEOUT = "timeout"
    PROVIDER_ERROR = "provider_error"
    DEMO_FIXTURE = "demo_fixture"


class EvidenceStrength(str, Enum):
    INFORMATIONAL = "informational"
    WEAK = "weak"
    MODERATE = "moderate"
    STRONG = "strong"
    CRITICAL = "critical"


class FindingCategory(str, Enum):
    SENDER_IDENTITY = "sender_identity"
    AUTHENTICATION = "authentication"
    DOMAIN_ALIGNMENT = "domain_alignment"
    MAIL_ROUTE = "mail_route"
    HEADER_ANOMALIES = "header_anomalies"
    THREAT_INTELLIGENCE = "threat_intelligence"
    EMAIL_REPUTATION = "email_reputation"
    IMPERSONATION = "impersonation"
    POSSIBLE_BEC = "possible_bec"


class Verdict(str, Enum):
    """Note what is absent: there is no ``SAFE`` and no ``BEC_CONFIRMED``.

    Header evidence cannot establish that a message is harmless — a compromised but
    genuine mailbox passes every authentication check there is — and it cannot
    establish business context, which is what a BEC determination actually requires.
    """

    LIKELY_LEGITIMATE = "likely_legitimate"
    SUSPICIOUS = "suspicious"
    LIKELY_PHISHING = "likely_phishing"
    POSSIBLE_BEC = "possible_bec"
    INCONCLUSIVE = "inconclusive"


VERDICT_LABELS: dict[Verdict, str] = {
    Verdict.LIKELY_LEGITIMATE: "Likely Legitimate based on available header evidence",
    Verdict.SUSPICIOUS: "Suspicious",
    Verdict.LIKELY_PHISHING: "Likely Phishing",
    Verdict.POSSIBLE_BEC: "Possible BEC / Impersonation",
    Verdict.INCONCLUSIVE: "Inconclusive — insufficient evidence",
}


class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


# ---------------------------------------------------------------------------
# Parsed header
# ---------------------------------------------------------------------------


class HeaderField(_Frozen):
    """A single header field occurrence.

    Duplicates are preserved rather than collapsed: two ``From:`` headers is a real
    attack technique, and a parser that silently takes the first one hides it.
    ``order`` records the field's position in the original message so the raw view can
    be reconstructed faithfully.
    """

    name: str
    raw_value: str
    normalized_value: str
    order: int
    decoded_value: str | None = None
    warnings: tuple[str, ...] = ()


class ParsedHeader(_Frozen):
    fields: tuple[HeaderField, ...]
    warnings: tuple[str, ...] = ()
    had_body: bool = False
    truncated: bool = False

    def get_all(self, name: str) -> tuple[HeaderField, ...]:
        """All occurrences of ``name``, case-insensitively.

        Field names are case-insensitive per RFC 5322 §1.2.2. Real messages contain
        ``Message-Id`` as often as ``Message-ID``; a case-sensitive lookup silently
        misses them.
        """
        lowered = name.lower()
        return tuple(f for f in self.fields if f.name.lower() == lowered)

    def get_first(self, name: str) -> HeaderField | None:
        found = self.get_all(name)
        return found[0] if found else None

    def value_of(self, name: str) -> str | None:
        field = self.get_first(name)
        return field.normalized_value if field else None


# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------


class Identity(_Frozen):
    """An addressable identity extracted from one header field."""

    source_header: str
    raw: str
    display_name: str | None = None
    address: str | None = None
    domain: str | None = None
    organizational_domain: str | None = None
    is_unicode: bool = False
    warnings: tuple[str, ...] = ()


class IdentityComparison(_Frozen):
    left: str
    right: str
    left_domain: str | None
    right_domain: str | None
    result: AlignmentResult
    explanation: str


# ---------------------------------------------------------------------------
# Received chain
# ---------------------------------------------------------------------------


class ReceivedHop(_Frozen):
    """One ``Received:`` field, decomposed.

    Every field is optional because real ``Received:`` headers routinely omit parts of
    the RFC 5321 §4.4 grammar. In particular a line may have **no ``from`` clause at
    all** — the shape produced by locally-injected mail from submission agents and
    encryption gateways. Parsers built on ``from\\s+(.*?)\\s+by`` drop those lines
    entirely and lose the origin hop; see docs/REFERENCE_REPOSITORIES.md §2.
    """

    index_in_header: int
    raw: str
    from_host: str | None = None
    from_rdns: str | None = None
    by_host: str | None = None
    protocol: str | None = None
    tls_info: str | None = None
    queue_id: str | None = None
    for_recipient: str | None = None
    ip_addresses: tuple[str, ...] = ()
    primary_ip: str | None = None
    primary_ip_class: IPClass | None = None
    raw_timestamp: str | None = None
    timestamp_utc: datetime | None = None
    original_offset: str | None = None
    warnings: tuple[str, ...] = ()

    @property
    def used_tls(self) -> bool | None:
        """``True`` for ESMTPS/TLS, ``False`` for plain ESMTP, ``None`` if unstated."""
        if self.protocol is None:
            return None
        upper = self.protocol.upper()
        if "ESMTPS" in upper or "ESMTPSA" in upper or self.tls_info:
            return True
        if "ESMTP" in upper or "SMTP" in upper:
            return False
        return None


class HopDelay(_Frozen):
    """Elapsed time between two consecutive hops in chronological order.

    ``seconds`` is computed with ``timedelta.total_seconds()``. Using
    ``timedelta.seconds`` instead — as the most-starred tool in this space does, and as
    its best-known derivative copied verbatim — is wrong: that attribute is the
    within-day remainder, so one second of backwards clock skew is reported as 86,399
    seconds and a 25-hour delay is reported as one hour.

    Negative values are *kept* and flagged via ``is_clock_skew`` rather than clamped
    away, because backwards time between two MTAs is itself information.
    """

    from_hop_index: int
    to_hop_index: int
    seconds: float
    is_clock_skew: bool
    note: str | None = None


class MailRoute(_Frozen):
    """The reconstructed delivery path.

    ``hops_header_order`` is as stored (newest first — MTAs prepend). ``hops_chronological``
    is the reversed view, which is how an analyst reads it. Both are exposed because the
    reversal is an interpretation, and the UI labels it as such.
    """

    hops_header_order: tuple[ReceivedHop, ...]
    hops_chronological: tuple[ReceivedHop, ...]
    delays: tuple[HopDelay, ...] = ()
    total_transit_seconds: float | None = None
    estimated_origin_hop_index: int | None = None
    first_trusted_hop_index: int | None = None
    trust_boundary_confidence: Confidence = Confidence.LOW
    trust_boundary_explanation: str = ""
    missing_evidence: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------


class AuthenticationEvidence(_Frozen):
    """What one MTA asserted about one authentication method.

    ``asserted_by`` is the RFC 8601 authserv-id. ``trust`` records whether that
    identifier matches configured trusted infrastructure — without which the assertion
    carries no weight, because anyone can write this header.
    """

    method: AuthMethod
    result: AuthResult
    asserted_by: str | None = None
    trust: TrustStatus = TrustStatus.UNKNOWN
    source_header: str = "Authentication-Results"
    properties: dict[str, str] = Field(default_factory=dict)
    reason: str | None = None
    raw: str = ""

    @property
    def display(self) -> str:
        return f"Recorded {self.method.value.upper()} result: {self.result.value}"


class VerificationResult(_Frozen):
    """The result of *our own* independent check against live DNS.

    Kept deliberately separate from :class:`AuthenticationEvidence`. One is a claim we
    read; the other is a fact we established. Showing them side by side — and warning
    when they disagree — is the point of this tool.
    """

    method: AuthMethod
    outcome: VerificationOutcome
    detail: str
    checked_domain: str | None = None
    record: str | None = None
    scope: str | None = None
    """What the verification actually covered, e.g. 'signed headers only, body hash not
    checked (headers-only input)'. Prevents overclaiming."""
    error: str | None = None


class AuthenticationSummary(_Frozen):
    evidence: tuple[AuthenticationEvidence, ...] = ()
    verifications: tuple[VerificationResult, ...] = ()
    spf_alignment: AlignmentResult = AlignmentResult.UNKNOWN
    dkim_alignment: AlignmentResult = AlignmentResult.UNKNOWN
    dkim_signing_domains: tuple[str, ...] = ()
    envelope_from: str | None = None
    helo_identity: str | None = None
    header_from_domain: str | None = None
    dmarc_policy: str | None = None
    dmarc_record: str | None = None
    arc_present: bool = False
    arc_chain_status: str | None = None
    disagreements: tuple[str, ...] = ()
    """Cases where our verified result contradicts what the MTA asserted."""
    warnings: tuple[str, ...] = ()


# ---------------------------------------------------------------------------
# Indicators of compromise
# ---------------------------------------------------------------------------


class IOCSource(_Frozen):
    header_name: str
    position: int


class IOC(_Frozen):
    value: str
    normalized: str
    ioc_type: IOCType
    sources: tuple[IOCSource, ...] = ()
    occurrences: int = 1
    ip_class: IPClass | None = None
    enrichment_eligible: bool = False
    ineligibility_reason: str | None = None
    defanged: str = ""
    is_unicode: bool = False
    warnings: tuple[str, ...] = ()


# ---------------------------------------------------------------------------
# Threat intelligence
# ---------------------------------------------------------------------------


class ThreatIntelResult(_Frozen):
    provider: str
    ioc: str
    ioc_type: IOCType
    status: ProviderStatus
    looked_up_at: datetime | None = None
    summary: str = ""
    fields: dict[str, Any] = Field(default_factory=dict)
    error_type: str | None = None
    is_demo_fixture: bool = False
    cached: bool = False

    @property
    def is_actionable(self) -> bool:
        """Whether this result may contribute risk in either direction.

        Only ``SUCCESS`` and ``DEMO_FIXTURE`` carry signal. Everything else means we do
        not know — and not knowing is never evidence of cleanliness.
        """
        return self.status in (ProviderStatus.SUCCESS, ProviderStatus.DEMO_FIXTURE)


# ---------------------------------------------------------------------------
# Findings and verdict
# ---------------------------------------------------------------------------


class DetectionFinding(_Frozen):
    """One triggered rule, with everything an analyst needs to accept or reject it.

    ``legitimate_explanation`` is mandatory rather than optional. Most single indicators
    have an innocent reading — third-party mailing providers, CRM platforms, ticketing
    systems, forwarders and mailing lists all produce header shapes that look like
    spoofing in isolation. A tool that reports the suspicion without the alternative
    trains analysts badly.
    """

    rule_id: str
    title: str
    category: FindingCategory
    severity: EvidenceStrength
    evidence_strength: EvidenceStrength
    confidence: Confidence
    score_contribution: float
    evidence: str
    why_it_matters: str
    legitimate_explanation: str
    recommended_action: str
    references: tuple[str, ...] = ()


class RiskAssessment(_Frozen):
    score: int = Field(ge=0, le=100)
    verdict: Verdict
    verdict_label: str
    confidence: Confidence
    findings: tuple[DetectionFinding, ...] = ()
    strongest_evidence: tuple[str, ...] = ()
    risk_increasing: tuple[str, ...] = ()
    risk_reducing: tuple[str, ...] = ()
    missing_evidence: tuple[str, ...] = ()
    verdict_rationale: str = ""
    matched_pattern: str | None = None
    """Name of the correlation pattern that selected the verdict, if any. When this is
    ``None`` the verdict came from score thresholds instead."""
    headline_citations: tuple[str, ...] = ()
    """The verdict, traced to specific evidence: '{finding title}: {evidence quote}'
    for the strongest findings that actually decided it. ``DetectionFinding.evidence``
    already quotes the exact parsed value that triggered the rule — a domain, an
    address, a DNS record, an evaluated IP — not just the rule's generic description,
    so this is a citation, not a paraphrase. Distinct from ``strongest_evidence``
    (rule-ID/title only) because a verdict page should be able to say *why* in one
    place without the reader cross-referencing the findings list by hand."""


# ---------------------------------------------------------------------------
# Vendor filter headers
# ---------------------------------------------------------------------------


class VendorFilterReport(_Frozen):
    """Decoded output of a mail-filter vendor's own verdict headers.

    Currently Microsoft's ``X-Forefront-Antispam-Report`` and ``X-Microsoft-Antispam``.
    These carry the filter's spam confidence, bulk confidence and category — useful
    corroboration that almost no open-source tool bothers to decode.
    """

    vendor: str
    source_header: str
    raw: str
    decoded: tuple[tuple[str, str, str], ...] = ()
    """(field code, raw value, human-readable meaning)"""
    notes: tuple[str, ...] = ()


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------


class EnrichmentMode(str, Enum):
    LIVE = "live"
    DEMO_FIXTURE = "demo_fixture"
    OFFLINE = "offline"
    DISABLED = "disabled"


class AnalysisReport(_Frozen):
    report_id: str
    created_at: datetime
    parsed_header: ParsedHeader
    identities: tuple[Identity, ...] = ()
    identity_comparisons: tuple[IdentityComparison, ...] = ()
    route: MailRoute | None = None
    authentication: AuthenticationSummary | None = None
    verifications: tuple[VerificationResult, ...] = ()
    """Raw independent-verification results (SPF/DKIM/DMARC), kept separately from
    ``authentication`` so the UI can show 'asserted' and 'verified' side by side
    without reconstructing one from the other."""
    iocs: tuple[IOC, ...] = ()
    intel_results: tuple[ThreatIntelResult, ...] = ()
    vendor_reports: tuple[VendorFilterReport, ...] = ()
    risk: RiskAssessment | None = None
    recommendations: tuple[str, ...] = ()
    enrichment_mode: EnrichmentMode = EnrichmentMode.OFFLINE
    verification_performed: bool = False
    warnings: tuple[str, ...] = ()
