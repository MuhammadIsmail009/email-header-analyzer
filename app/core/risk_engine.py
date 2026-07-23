"""Scoring and verdict selection.

Two properties matter more than the arithmetic:

**Every point is attributable.** The score is a sum of named findings, each carrying its
own evidence, rationale and innocent explanation. An analyst can reconstruct exactly
where 62/100 came from and disagree with any individual component. A bare number that
cannot be decomposed is not usable in a write-up.

**The verdict is not the score.** Named evidence *combinations* select the verdict
before thresholds are consulted; the numeric score is only the fallback. This matters
because the dangerous cases and the noisy cases sit at similar scores. In particular,
trusted authentication combined with a malicious indicator is deliberately *dampened*
to Suspicious rather than escalated — it is overwhelmingly the shared-infrastructure
false positive, and escalating it is how these tools generate noise that gets them
ignored.
"""

from __future__ import annotations

import functools
from pathlib import Path

import yaml

from app.core.models import (
    VERDICT_LABELS,
    Confidence,
    DetectionFinding,
    EvidenceStrength,
    FindingCategory,
    RiskAssessment,
    Verdict,
)
from app.core.rules_impl import REGISTRY, RiskContext

_RULES_PATH = Path(__file__).parent / "rules" / "rules.yaml"

_STRENGTH = {s.value: s for s in EvidenceStrength}
_CATEGORY = {c.value: c for c in FindingCategory}

# Score bands. Verdict correlation runs first; these only apply when no pattern matched.
THRESHOLD_SUSPICIOUS = 25
THRESHOLD_PHISHING = 50

# Rules that record the *absence* of evidence rather than the presence of a problem.
# They must never be counted as grounds for a judgement in either direction.
ABSENCE_MARKERS = frozenset({"AUTH-005", "AUTH-009", "RTE-002", "TI-004"})


class RuleDefinitionError(Exception):
    pass


@functools.lru_cache(maxsize=1)
def load_rules() -> tuple[dict[str, dict], dict[str, int]]:
    """Load and validate rule definitions.

    Validation is strict and happens at import rather than at analysis time: a rule
    with no registered predicate, an unknown category, or missing analyst-facing prose
    is a bug that should surface on startup, not silently produce a report with a
    finding nobody can act on.
    """
    data = yaml.safe_load(_RULES_PATH.read_text(encoding="utf-8"))
    caps = {k: int(v) for k, v in (data.get("category_caps") or {}).items()}

    rules: dict[str, dict] = {}
    for entry in data.get("rules") or []:
        rule_id = entry.get("id")
        if not rule_id:
            raise RuleDefinitionError("a rule has no id")
        for required in ("title", "category", "strength", "weight", "why", "legitimate", "action"):
            if not entry.get(required) and entry.get(required) != 0:
                raise RuleDefinitionError(f"{rule_id}: missing {required!r}")
        if entry["category"] not in _CATEGORY:
            raise RuleDefinitionError(f"{rule_id}: unknown category {entry['category']!r}")
        if entry["strength"] not in _STRENGTH:
            raise RuleDefinitionError(f"{rule_id}: unknown strength {entry['strength']!r}")
        if rule_id not in REGISTRY:
            raise RuleDefinitionError(
                f"{rule_id}: declared in rules.yaml but no predicate is registered "
                "in rules_impl.py"
            )
        rules[rule_id] = entry

    orphans = set(REGISTRY) - set(rules)
    if orphans:
        raise RuleDefinitionError(
            f"predicates registered with no rule definition: {sorted(orphans)}"
        )
    return rules, caps


def _confidence_for(strength: EvidenceStrength, verified: bool) -> Confidence:
    """Independent verification raises confidence; a parsed claim does not."""
    if strength in (EvidenceStrength.CRITICAL, EvidenceStrength.STRONG):
        return Confidence.HIGH if verified else Confidence.MEDIUM
    if strength is EvidenceStrength.MODERATE:
        return Confidence.MEDIUM if verified else Confidence.LOW
    return Confidence.LOW


def evaluate(ctx: RiskContext) -> list[DetectionFinding]:
    """Run every rule and return the findings that fired, strongest first."""
    rules, _ = load_rules()
    findings: list[DetectionFinding] = []

    for rule_id, definition in rules.items():
        evidence = REGISTRY[rule_id](ctx)
        if not evidence:
            continue
        strength = _STRENGTH[definition["strength"]]
        findings.append(
            DetectionFinding(
                rule_id=rule_id,
                title=definition["title"],
                category=_CATEGORY[definition["category"]],
                severity=strength,
                evidence_strength=strength,
                confidence=_confidence_for(strength, ctx.verification_performed),
                score_contribution=float(definition["weight"]),
                evidence=evidence,
                why_it_matters=" ".join(definition["why"].split()),
                legitimate_explanation=" ".join(definition["legitimate"].split()),
                recommended_action=" ".join(definition["action"].split()),
            )
        )

    order = list(EvidenceStrength)
    findings.sort(
        key=lambda f: (-order.index(f.evidence_strength), -f.score_contribution)
    )
    return findings


def score(findings: list[DetectionFinding]) -> int:
    """Sum contributions with per-category caps, clamped to 0–100.

    Capping per category stops one noisy area dominating: a message with six route
    observations should not outscore one with a verified DMARC failure. Risk-reducing
    findings (negative weights) are applied after capping so they are never cancelled
    out by a cap they did not cause.
    """
    _, caps = load_rules()

    positive: dict[str, float] = {}
    negative = 0.0
    for finding in findings:
        if finding.score_contribution < 0:
            negative += finding.score_contribution
        else:
            key = finding.category.value
            positive[key] = positive.get(key, 0.0) + finding.score_contribution

    total = sum(
        min(value, float(caps.get(category, 100)))
        for category, value in positive.items()
    )
    return max(0, min(100, int(round(total + negative))))


def _has(findings: list[DetectionFinding], *rule_ids: str) -> bool:
    present = {f.rule_id for f in findings}
    return any(rule_id in present for rule_id in rule_ids)


def select_verdict(
    ctx: RiskContext, findings: list[DetectionFinding], numeric_score: int
) -> tuple[Verdict, str, str | None]:
    """Choose a verdict. Returns ``(verdict, rationale, matched_pattern_name)``.

    Correlation patterns are evaluated in order and take precedence over thresholds.
    """
    auth_failed = _has(findings, "AUTH-001", "AUTH-002", "AUTH-003")
    untrusted_pass = _has(findings, "AUTH-004")
    malicious_intel = _has(findings, "TI-001", "TI-002", "TI-003")
    strong_intel = _has(findings, "TI-002")
    impersonation = _has(findings, "IMP-001", "IDN-004")
    bec_pattern = _has(findings, "BEC-001")
    clean_auth = _has(findings, "AUTH-010")

    # Inconclusive means "we could not learn enough to judge", which is narrower than
    # "no Authentication-Results header was present". If we verified anything
    # ourselves, or any finding of real weight fired, we *do* have grounds — an absent
    # Authentication-Results header is exactly the case where independent verification
    # earns its keep, and returning Inconclusive there would discard our best evidence.
    #
    # Absence markers are excluded from that count. They record what is *missing*, and
    # treating "no authentication was recorded" as substantive evidence would make the
    # evidence-free case look like a judgement rather than an absence of one.
    substantive = [
        f
        for f in findings_above(findings, EvidenceStrength.WEAK)
        if f.rule_id not in ABSENCE_MARKERS
    ]
    nothing_recorded = ctx.authentication is None or not ctx.authentication.evidence
    no_route = ctx.route is None or not ctx.route.hops_header_order
    nothing_established = nothing_recorded and not ctx.verification_performed

    if nothing_established and no_route and not substantive:
        return (
            Verdict.INCONCLUSIVE,
            "There is not enough evidence in the supplied material to reach a "
            "conclusion: no receiving system recorded an authentication result, no "
            "delivery path is present, and independent verification was not "
            "performed. Obtain the complete original header.",
            "insufficient-evidence",
        )

    if bec_pattern:
        return (
            Verdict.POSSIBLE_BEC,
            "The message authenticates correctly but its sender identity is "
            "internally inconsistent. That combination is characteristic of business "
            "email compromise and of lookalike-domain impersonation, because the "
            "attacker controls infrastructure that genuinely authenticates. Header "
            "evidence cannot establish business context, so this is a prompt to "
            "verify out of band — not a confirmed determination.",
            "authenticated-but-inconsistent-identity",
        )

    if (auth_failed or untrusted_pass) and (malicious_intel or impersonation):
        return (
            Verdict.LIKELY_PHISHING,
            "Authentication either failed independent verification or was asserted "
            "only by untrusted infrastructure, and this is corroborated by "
            + ("threat intelligence." if malicious_intel else "domain impersonation."),
            "auth-failure-with-corroboration",
        )

    if strong_intel and not clean_auth:
        return (
            Verdict.LIKELY_PHISHING,
            "Multiple independent providers report indicators from this message as "
            "malicious.",
            "multi-provider-consensus",
        )

    if clean_auth and malicious_intel:
        return (
            Verdict.SUSPICIOUS,
            "Authentication was independently verified as passing and aligned, yet an "
            "indicator is reported negatively. This is most often shared "
            "infrastructure being reported for a neighbouring tenant, so it is not "
            "escalated on that basis alone — but a compromised legitimate account "
            "produces exactly this picture too, so it warrants review.",
            "trusted-auth-with-adverse-intel-dampened",
        )

    if clean_auth and not findings_above(findings, EvidenceStrength.WEAK):
        return (
            Verdict.LIKELY_LEGITIMATE,
            "SPF and DMARC were independently verified as passing and aligned with the "
            "visible From domain, and no identity, route or reputation anomaly was "
            "found. Note this speaks to origin, not intent: a compromised but genuine "
            "mailbox passes every check performed here.",
            "verified-aligned-and-clean",
        )

    if numeric_score >= THRESHOLD_PHISHING:
        return (
            Verdict.LIKELY_PHISHING,
            f"No single decisive pattern matched, but the accumulated evidence scores "
            f"{numeric_score}/100 across {len(findings)} findings.",
            None,
        )
    if numeric_score >= THRESHOLD_SUSPICIOUS:
        return (
            Verdict.SUSPICIOUS,
            f"Accumulated evidence scores {numeric_score}/100. No individual finding is "
            "decisive; the combination warrants a closer look.",
            None,
        )
    if nothing_established:
        # A low score here means "we found nothing", not "we found it to be fine".
        # Reporting Likely Legitimate on the strength of an absence would be the worst
        # error this tool could make, so it is refused explicitly.
        return (
            Verdict.INCONCLUSIVE,
            "No receiving system recorded an authentication result and independent "
            "verification was not performed, so nothing about this message's origin "
            f"was established. The low score ({numeric_score}/100) reflects an absence "
            "of evidence, not a favourable finding.",
            "nothing-established",
        )

    return (
        Verdict.LIKELY_LEGITIMATE,
        f"Accumulated evidence scores {numeric_score}/100 and no strong indicator was "
        "found. This reflects the available header evidence only.",
        None,
    )


def findings_above(
    findings: list[DetectionFinding], threshold: EvidenceStrength
) -> list[DetectionFinding]:
    order = list(EvidenceStrength)
    limit = order.index(threshold)
    return [f for f in findings if order.index(f.evidence_strength) > limit]


def _confidence_overall(
    ctx: RiskContext, findings: list[DetectionFinding]
) -> Confidence:
    """Confidence in the verdict, not in any single finding.

    Driven by whether we verified anything ourselves and how many independent signals
    agree — not by how large the score is. A high score built from one category is less
    trustworthy than a moderate one built from three.
    """
    categories = {f.category for f in findings if f.score_contribution > 0}
    if ctx.verification_performed and len(categories) >= 3:
        return Confidence.HIGH
    if ctx.verification_performed and len(categories) >= 1:
        return Confidence.MEDIUM
    if len(categories) >= 3:
        return Confidence.MEDIUM
    return Confidence.LOW


def assess(ctx: RiskContext) -> RiskAssessment:
    """Full assessment: findings, score, verdict, confidence and analyst framing."""
    findings = evaluate(ctx)
    numeric = score(findings)
    verdict, rationale, pattern = select_verdict(ctx, findings, numeric)

    increasing = [f for f in findings if f.score_contribution > 0]
    reducing = [f for f in findings if f.score_contribution < 0]

    missing: list[str] = []
    if not ctx.verification_performed:
        missing.append(
            "Independent DNS verification was not performed, so authentication "
            "results reflect only what the receiving server recorded."
        )
    if ctx.route is not None and ctx.route.missing_evidence:
        missing.extend(ctx.route.missing_evidence)
    if any(f.rule_id == "TI-004" for f in findings):
        missing.append(
            "Some threat-intelligence lookups returned no data. Those indicators were "
            "not checked, which is not the same as their being clean."
        )
    if ctx.authentication and not ctx.authentication.evidence:
        missing.append("No authentication result was recorded by any receiving system.")

    # findings is already sorted strongest-first (see evaluate()). Citations are
    # the actual evidence quotes behind the verdict, not just rule titles — a
    # zero-weight informational finding (e.g. TI-004, "some lookups returned no
    # data") explains nothing about *why* the verdict was reached, so it's excluded
    # here even though it's a legitimate finding worth showing elsewhere.
    citations = tuple(
        f"{f.title}: {f.evidence}"
        for f in findings
        if f.score_contribution != 0
    )[:4]

    return RiskAssessment(
        score=numeric,
        verdict=verdict,
        verdict_label=VERDICT_LABELS[verdict],
        confidence=_confidence_overall(ctx, findings),
        findings=tuple(findings),
        strongest_evidence=tuple(
            f"{f.rule_id}: {f.title}"
            for f in findings_above(findings, EvidenceStrength.MODERATE)[:5]
        ),
        risk_increasing=tuple(f"{f.rule_id}: {f.title}" for f in increasing),
        risk_reducing=tuple(f"{f.rule_id}: {f.title}" for f in reducing),
        missing_evidence=tuple(missing),
        verdict_rationale=rationale,
        matched_pattern=pattern,
        headline_citations=citations,
    )
