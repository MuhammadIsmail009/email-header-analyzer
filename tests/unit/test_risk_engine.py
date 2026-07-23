"""Risk engine, scoring and verdict-selection tests."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.core.models import (
    AlignmentResult,
    AuthenticationEvidence,
    AuthenticationSummary,
    AuthMethod,
    AuthResult,
    Confidence,
    EvidenceStrength,
    Identity,
    IOCType,
    ProviderStatus,
    ThreatIntelResult,
    TrustStatus,
    Verdict,
    VerificationOutcome,
    VerificationResult,
)
from app.core.risk_engine import assess, evaluate, load_rules, score
from app.core.rules_impl import LookalikeHit, RiskContext

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def auth(
    *,
    from_domain="bank.example",
    evidence=(),
    spf_alignment=AlignmentResult.EXACT,
    dkim_alignment=AlignmentResult.UNKNOWN,
    envelope_from="alice@bank.example",
    signing=(),
):
    return AuthenticationSummary(
        evidence=tuple(evidence),
        spf_alignment=spf_alignment,
        dkim_alignment=dkim_alignment,
        dkim_signing_domains=tuple(signing),
        envelope_from=envelope_from,
        header_from_domain=from_domain,
    )


def ev(method, result, trust=TrustStatus.TRUSTED, by="mx.google.com"):
    return AuthenticationEvidence(
        method=method, result=result, asserted_by=by, trust=trust
    )


def ver(method, outcome, detail="detail"):
    return VerificationResult(method=method, outcome=outcome, detail=detail)


def intel(provider, ioc, status=ProviderStatus.SUCCESS, **fields):
    return ThreatIntelResult(
        provider=provider,
        ioc=ioc,
        ioc_type=IOCType.IPV4,
        status=status,
        looked_up_at=datetime(2026, 7, 23, tzinfo=UTC),
        fields=fields,
    )


PASS_ALL = [
    ver(AuthMethod.SPF, VerificationOutcome.VERIFIED_PASS),
    ver(AuthMethod.DMARC, VerificationOutcome.VERIFIED_PASS),
]


# ---------------------------------------------------------------------------
# Rule definitions
# ---------------------------------------------------------------------------


def test_every_rule_has_a_predicate_and_vice_versa():
    """Guards against a rule declared in YAML that can never fire, and a predicate
    that produces findings with no analyst-facing text."""
    rules, _ = load_rules()
    assert len(rules) >= 25


def test_every_rule_has_a_legitimate_explanation():
    """Mandatory. Reporting suspicion without the innocent reading trains analysts to
    over-escalate."""
    rules, _ = load_rules()
    for rule_id, definition in rules.items():
        assert definition["legitimate"].strip(), f"{rule_id} has no legitimate explanation"
        assert definition["action"].strip(), f"{rule_id} has no recommended action"


def test_no_rule_mentions_country_or_nationality():
    """Hard constraint. Geography is a proxy for nationality, not for maliciousness."""
    rules, _ = load_rules()
    banned = ("country", "nationality", "russia", "china", "iran", "north korea", "geoip")
    for rule_id, definition in rules.items():
        haystack = " ".join(
            str(definition.get(k, "")) for k in ("title", "why", "category")
        ).lower()
        for term in banned:
            assert term not in haystack, f"{rule_id} references {term!r}"


# ---------------------------------------------------------------------------
# Constraint tests
# ---------------------------------------------------------------------------


def test_country_never_contributes_to_score():
    """Even when country data is present in a provider result it must not score."""
    ctx = RiskContext(
        authentication=auth(),
        verifications=tuple(PASS_ALL),
        verification_performed=True,
        intel=(
            intel("abuseipdb", "198.51.100.9", country="RU", isp="Some ISP", malicious=False),
        ),
    )
    findings = evaluate(ctx)
    assert not any("country" in f.evidence.lower() for f in findings)

    baseline = RiskContext(
        authentication=auth(), verifications=tuple(PASS_ALL), verification_performed=True
    )
    assert score(evaluate(ctx)) == score(evaluate(baseline))


@pytest.mark.parametrize(
    "status",
    [
        ProviderStatus.DISABLED,
        ProviderStatus.UNAVAILABLE,
        ProviderStatus.RATE_LIMITED,
        ProviderStatus.INVALID_KEY,
        ProviderStatus.TIMEOUT,
        ProviderStatus.PROVIDER_ERROR,
        ProviderStatus.UNKNOWN,
    ],
)
def test_unavailable_intel_is_informational_only(status):
    """Not knowing is never good news, and never bad news either."""
    ctx = RiskContext(
        authentication=auth(),
        verification_performed=True,
        verifications=tuple(PASS_ALL),
        intel=(intel("abuseipdb", "198.51.100.9", status=status, malicious=True),),
    )
    findings = evaluate(ctx)
    # A malicious flag on a non-actionable result must be ignored entirely.
    assert not any(f.rule_id in ("TI-002", "TI-003") for f in findings)
    for finding in findings:
        if finding.rule_id == "TI-004":
            assert finding.score_contribution == 0


def test_unavailable_intel_is_reported_as_missing_evidence():
    ctx = RiskContext(
        authentication=auth(),
        verification_performed=True,
        verifications=tuple(PASS_ALL),
        intel=(intel("virustotal", "198.51.100.9", status=ProviderStatus.DISABLED),),
    )
    result = assess(ctx)
    assert any("not the same as their being clean" in m for m in result.missing_evidence)


def test_untrusted_pass_scores_but_untrusted_fail_does_not():
    """Nobody forges an authentication failure against themselves."""
    forged = RiskContext(
        authentication=auth(
            evidence=[ev(AuthMethod.SPF, AuthResult.PASS, TrustStatus.UNTRUSTED, "evil.example")]
        )
    )
    honest_fail = RiskContext(
        authentication=auth(
            evidence=[ev(AuthMethod.SPF, AuthResult.FAIL, TrustStatus.UNTRUSTED, "evil.example")]
        )
    )
    assert any(f.rule_id == "AUTH-004" for f in evaluate(forged))
    assert not any(f.rule_id == "AUTH-004" for f in evaluate(honest_fail))


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------


def test_score_is_clamped_to_range():
    ctx = RiskContext(
        authentication=auth(
            from_domain="bank.example",
            evidence=[ev(AuthMethod.SPF, AuthResult.PASS, TrustStatus.UNTRUSTED, "evil.example")],
            spf_alignment=AlignmentResult.MISMATCH,
            envelope_from="a@evil.example",
        ),
        verifications=(
            ver(AuthMethod.DMARC, VerificationOutcome.VERIFIED_FAIL),
            ver(AuthMethod.SPF, VerificationOutcome.VERIFIED_FAIL),
            ver(AuthMethod.DKIM, VerificationOutcome.VERIFIED_FAIL),
        ),
        verification_performed=True,
        lookalikes=(LookalikeHit("bank-secure.example", "bank.example", "typosquat"),),
        dnsbl_listings=(("198.51.100.9", ("zen.spamhaus.org",)),),
        intel=(
            intel("abuseipdb", "198.51.100.9", malicious=True),
            intel("virustotal", "198.51.100.9", malicious=True),
        ),
    )
    assert 0 <= score(evaluate(ctx)) <= 100


def test_category_cap_prevents_one_area_dominating():
    """Six route observations must not outweigh a verified DMARC failure."""
    _, caps = load_rules()
    assert caps["mail_route"] < caps["authentication"]


def test_risk_reducing_findings_lower_the_score():
    with_good = RiskContext(
        authentication=auth(),
        verifications=tuple(PASS_ALL),
        verification_performed=True,
        intel=(
            ThreatIntelResult(
                provider="emailrep",
                ioc="alice@bank.example",
                ioc_type=IOCType.EMAIL,
                status=ProviderStatus.SUCCESS,
                fields={"reputation": "high", "suspicious": False},
            ),
        ),
    )
    findings = evaluate(with_good)
    assert any(f.rule_id == "REP-002" for f in findings)
    assert any(f.score_contribution < 0 for f in findings)


# ---------------------------------------------------------------------------
# Verdict selection
# ---------------------------------------------------------------------------


def test_verified_aligned_and_clean_is_likely_legitimate():
    result = assess(
        RiskContext(
            authentication=auth(evidence=[ev(AuthMethod.SPF, AuthResult.PASS)]),
            verifications=tuple(PASS_ALL),
            verification_performed=True,
        )
    )
    assert result.verdict is Verdict.LIKELY_LEGITIMATE
    assert "not intent" in result.verdict_rationale
    assert "safe" not in result.verdict_label.lower()


def test_auth_failure_with_corroboration_is_likely_phishing():
    result = assess(
        RiskContext(
            authentication=auth(
                from_domain="bank.example",
                spf_alignment=AlignmentResult.MISMATCH,
                envelope_from="a@evil.example",
            ),
            verifications=(ver(AuthMethod.DMARC, VerificationOutcome.VERIFIED_FAIL),),
            verification_performed=True,
            lookalikes=(LookalikeHit("bank-secure.example", "bank.example", "typosquat"),),
        )
    )
    assert result.verdict is Verdict.LIKELY_PHISHING
    assert result.matched_pattern == "auth-failure-with-corroboration"


def test_trusted_auth_plus_malicious_intel_is_dampened_to_suspicious():
    """The deliberate false-positive control — not escalated to phishing."""
    result = assess(
        RiskContext(
            authentication=auth(evidence=[ev(AuthMethod.SPF, AuthResult.PASS)]),
            verifications=tuple(PASS_ALL),
            verification_performed=True,
            dnsbl_listings=(("93.184.216.34", ("zen.spamhaus.org",)),),
        )
    )
    assert result.verdict is Verdict.SUSPICIOUS
    assert result.matched_pattern == "trusted-auth-with-adverse-intel-dampened"
    assert "shared" in result.verdict_rationale


def test_possible_bec_requires_passing_auth_plus_inconsistency():
    result = assess(
        RiskContext(
            authentication=auth(
                from_domain="bank.example",
                evidence=[ev(AuthMethod.DMARC, AuthResult.PASS)],
            ),
            verifications=tuple(PASS_ALL),
            verification_performed=True,
            identities=(
                Identity(
                    source_header="Reply-To",
                    raw="billing@payments-collect.example",
                    address="billing@payments-collect.example",
                    domain="payments-collect.example",
                ),
            ),
        )
    )
    assert result.verdict is Verdict.POSSIBLE_BEC
    assert result.verdict_label == "Possible BEC / Impersonation"


def test_bec_verdict_is_never_labelled_confirmed():
    result = assess(
        RiskContext(
            authentication=auth(evidence=[ev(AuthMethod.DMARC, AuthResult.PASS)]),
            verifications=tuple(PASS_ALL),
            verification_performed=True,
            lookalikes=(LookalikeHit("bank-secure.example", "bank.example", "typosquat"),),
        )
    )
    assert result.verdict is Verdict.POSSIBLE_BEC
    assert "confirmed" not in result.verdict_label.lower()
    # The rationale may say "not a confirmed determination" — that is the wording we
    # want. What must never appear is BEC being asserted as established fact.
    lowered = result.verdict_rationale.lower()
    assert "bec confirmed" not in lowered
    assert "confirmed bec" not in lowered
    assert "not a confirmed determination" in lowered
    assert "verify out of band" in result.verdict_rationale


def test_bec_does_not_fire_when_authentication_fails():
    """Auth failure plus a mismatch is ordinary phishing, not BEC."""
    result = assess(
        RiskContext(
            authentication=auth(from_domain="bank.example"),
            verifications=(ver(AuthMethod.DMARC, VerificationOutcome.VERIFIED_FAIL),),
            verification_performed=True,
            lookalikes=(LookalikeHit("bank-secure.example", "bank.example", "typosquat"),),
        )
    )
    assert result.verdict is not Verdict.POSSIBLE_BEC


def test_insufficient_evidence_is_inconclusive():
    result = assess(RiskContext(authentication=auth(evidence=[])))
    assert result.verdict is Verdict.INCONCLUSIVE
    assert "not enough evidence" in result.verdict_rationale


def test_multi_provider_consensus_is_likely_phishing():
    result = assess(
        RiskContext(
            authentication=auth(evidence=[ev(AuthMethod.SPF, AuthResult.PASS)]),
            verification_performed=False,
            intel=(
                intel("abuseipdb", "198.51.100.9", malicious=True),
                intel("virustotal", "198.51.100.9", malicious=True),
            ),
        )
    )
    assert result.verdict is Verdict.LIKELY_PHISHING
    assert result.matched_pattern == "multi-provider-consensus"


def test_no_verdict_is_ever_described_as_safe():
    from app.core.models import VERDICT_LABELS

    for label in VERDICT_LABELS.values():
        assert "safe" not in label.lower()
        assert "clean" not in label.lower()


# ---------------------------------------------------------------------------
# Confidence and framing
# ---------------------------------------------------------------------------


def test_confidence_is_low_without_independent_verification():
    result = assess(
        RiskContext(
            authentication=auth(evidence=[ev(AuthMethod.SPF, AuthResult.PASS)]),
            verification_performed=False,
        )
    )
    assert result.confidence is Confidence.LOW
    assert any("Independent DNS verification was not performed" in m for m in result.missing_evidence)


def test_confidence_rises_with_verification_and_multiple_categories():
    result = assess(
        RiskContext(
            authentication=auth(
                from_domain="bank.example",
                spf_alignment=AlignmentResult.MISMATCH,
                envelope_from="a@other.example",
                evidence=[ev(AuthMethod.SPF, AuthResult.PASS)],
            ),
            verifications=(ver(AuthMethod.DMARC, VerificationOutcome.VERIFIED_FAIL),),
            verification_performed=True,
            lookalikes=(LookalikeHit("bank-secure.example", "bank.example", "typosquat"),),
            dnsbl_listings=(("93.184.216.34", ("zen.spamhaus.org",)),),
        )
    )
    assert result.confidence is Confidence.HIGH


def test_every_finding_carries_full_analyst_context():
    result = assess(
        RiskContext(
            authentication=auth(from_domain="bank.example"),
            verifications=(ver(AuthMethod.DMARC, VerificationOutcome.VERIFIED_FAIL),),
            verification_performed=True,
        )
    )
    assert result.findings
    for finding in result.findings:
        assert finding.rule_id
        assert finding.evidence
        assert finding.why_it_matters
        assert finding.legitimate_explanation
        assert finding.recommended_action


def test_findings_are_ordered_strongest_first():
    result = assess(
        RiskContext(
            authentication=auth(from_domain="bank.example"),
            verifications=(
                ver(AuthMethod.DMARC, VerificationOutcome.VERIFIED_FAIL),
            ),
            verification_performed=True,
            route=None,
            rdns_unconfirmed=("198.51.100.9",),
        )
    )
    order = list(EvidenceStrength)
    indices = [order.index(f.evidence_strength) for f in result.findings]
    assert indices == sorted(indices, reverse=True)


def test_absence_of_evidence_never_reads_as_legitimate():
    """Regression: a header with a delivery path but no authentication and no
    verification once scored 12/100 and returned Likely Legitimate.

    A low score there means "we found nothing", not "we found it to be fine". Reporting
    Likely Legitimate on the strength of an absence is the most damaging error this
    tool could make, because it actively reassures an analyst about a message nobody
    ever checked.
    """
    from app.core.header_parser import parse_headers
    from app.core.received_parser import build_route

    parsed = parse_headers(
        "Received: from a.example.com ([198.51.100.9]) by b.example.org;"
        " Wed, 22 Oct 2025 09:00:00 +0000\n"
        "From: alice@bank.example\n"
    )
    result = assess(
        RiskContext(
            authentication=auth(evidence=[]),
            route=build_route(parsed),
            verification_performed=False,
        )
    )
    assert result.verdict is not Verdict.LIKELY_LEGITIMATE
    assert result.verdict is Verdict.INCONCLUSIVE
    assert "absence of evidence, not a favourable finding" in result.verdict_rationale


def test_absence_markers_alone_do_not_justify_any_verdict():
    """AUTH-005, AUTH-009, RTE-002 and TI-004 record what is missing, not what is wrong."""
    from app.core.risk_engine import ABSENCE_MARKERS

    rules, _ = load_rules()
    for rule_id in ABSENCE_MARKERS:
        assert rule_id in rules, f"{rule_id} is not a real rule"


# ---------------------------------------------------------------------------
# Headline citations — the "why" traced to specific quoted evidence
# ---------------------------------------------------------------------------


def test_headline_citations_quote_actual_evidence_not_just_titles():
    """The frontend's 'why this verdict' section needs the real quoted values
    (domains, IPs, evaluated results) — not just a rule title repeated."""
    result = assess(
        RiskContext(
            authentication=auth(
                from_domain="bank.example",
                spf_alignment=AlignmentResult.MISMATCH,
                envelope_from="a@evil.example",
            ),
            verifications=(
                ver(
                    AuthMethod.DMARC,
                    VerificationOutcome.VERIFIED_FAIL,
                    detail="Independently evaluated: DMARC fail. SPF did not pass; "
                    "the domain publishes p=quarantine.",
                ),
            ),
            verification_performed=True,
        )
    )
    assert result.headline_citations
    citation = result.headline_citations[0]
    assert ":" in citation
    title, _, evidence = citation.partition(": ")
    assert title  # a real title, not empty
    assert len(evidence) > 10  # a real quoted sentence, not a stub
    assert "quarantine" in evidence  # the actual quoted detail, not a paraphrase


def test_headline_citations_exclude_zero_weight_informational_findings():
    """TI-004 ('some lookups returned no data') explains nothing about *why* the
    verdict was reached and must not appear as if it were a decisive citation."""
    result = assess(
        RiskContext(
            authentication=auth(evidence=[ev(AuthMethod.SPF, AuthResult.PASS)]),
            verification_performed=True,
            verifications=tuple(PASS_ALL),
            intel=(intel("abuseipdb", "198.51.100.9", status=ProviderStatus.DISABLED),),
        )
    )
    assert not any("TI-004" in c or "lookups returned no data" in c for c in result.headline_citations)


def test_headline_citations_cap_at_four():
    result = assess(
        RiskContext(
            authentication=auth(
                from_domain="bank.example",
                spf_alignment=AlignmentResult.MISMATCH,
                envelope_from="a@evil.example",
            ),
            verifications=(
                ver(AuthMethod.DMARC, VerificationOutcome.VERIFIED_FAIL),
                ver(AuthMethod.SPF, VerificationOutcome.VERIFIED_FAIL),
            ),
            verification_performed=True,
            lookalikes=(LookalikeHit("bank-secure.example", "bank.example", "typosquat"),),
            dnsbl_listings=(("198.51.100.9", ("zen.spamhaus.org",)),),
            intel=(intel("abuseipdb", "198.51.100.9", malicious=True),),
            identities=(
                Identity(
                    source_header="Reply-To",
                    raw="x@other-org.example",
                    address="x@other-org.example",
                    domain="other-org.example",
                ),
            ),
        )
    )
    assert len(result.headline_citations) <= 4


def test_headline_citations_include_risk_reducing_findings_for_clean_verdicts():
    """A Likely Legitimate verdict should be able to cite *why* it's clean — the
    verified-and-aligned finding is a negative-weight (risk-reducing) finding."""
    result = assess(
        RiskContext(
            authentication=auth(evidence=[ev(AuthMethod.SPF, AuthResult.PASS)]),
            verifications=tuple(PASS_ALL),
            verification_performed=True,
        )
    )
    assert result.verdict is Verdict.LIKELY_LEGITIMATE
    assert any("verified" in c.lower() for c in result.headline_citations)
