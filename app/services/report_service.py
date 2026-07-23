"""In-memory report storage and JSON/Markdown export.

Reports live in a bounded, short-lived, in-memory cache — never a database. There is
nothing here that outlives the process, which is the entire point: this assignment
does not need persistence, and adding a database "for report storage" is exactly the
unnecessary-infrastructure failure mode this project deliberately avoids (see
`docs/REFERENCE_REPOSITORIES.md` §6, where a reference project ships PostgreSQL, Redis
and Celery and uses none of them meaningfully).

Report IDs are opaque (``secrets.token_urlsafe``, generated in ``analysis_service.py``)
and are never derived from message content, so listing or guessing them does not leak
anything about who analysed what.
"""

from __future__ import annotations

import io
from pathlib import Path

from cachetools import TTLCache
from jinja2 import Environment, FileSystemLoader
from xhtml2pdf import pisa

from app.core.ioc_extractor import defang
from app.core.models import AnalysisReport, EnrichmentMode


class ReportStore:
    def __init__(self, max_entries: int, ttl_seconds: int) -> None:
        self._cache: TTLCache = TTLCache(maxsize=max_entries, ttl=ttl_seconds)

    def put(self, report: AnalysisReport) -> None:
        self._cache[report.report_id] = report

    def get(self, report_id: str) -> AnalysisReport | None:
        return self._cache.get(report_id)


def _enrichment_label(mode: EnrichmentMode) -> str:
    return {
        EnrichmentMode.LIVE: "live",
        EnrichmentMode.DEMO_FIXTURE: "demo_fixture",
        EnrichmentMode.OFFLINE: "offline (verification only, no third-party enrichment)",
        EnrichmentMode.DISABLED: "disabled",
    }[mode]


def to_json_dict(report: AnalysisReport) -> dict:
    """A plain-dict JSON representation.

    Built by hand rather than a raw ``model_dump()`` so the export can state, at the
    top level, exactly what evidentiary status the report has — live vs. fixture vs.
    unavailable vs. disabled — which is a requirement from the brief, not merely
    convenient.
    """
    risk = report.risk
    auth = report.authentication

    return {
        "report_id": report.report_id,
        "created_at": report.created_at.isoformat(),
        "enrichment_mode": _enrichment_label(report.enrichment_mode),
        "verification_performed": report.verification_performed,
        "verdict": {
            "label": risk.verdict_label if risk else None,
            "score": risk.score if risk else None,
            "confidence": risk.confidence.value if risk else None,
            "rationale": risk.verdict_rationale if risk else None,
            "matched_pattern": risk.matched_pattern if risk else None,
            "headline_citations": list(risk.headline_citations) if risk else [],
        }
        if risk
        else None,
        "findings": [
            {
                "rule_id": f.rule_id,
                "title": f.title,
                "category": f.category.value,
                "evidence_strength": f.evidence_strength.value,
                "confidence": f.confidence.value,
                "score_contribution": f.score_contribution,
                "evidence": f.evidence,
                "why_it_matters": f.why_it_matters,
                "legitimate_explanation": f.legitimate_explanation,
                "recommended_action": f.recommended_action,
            }
            for f in (risk.findings if risk else ())
        ],
        "authentication": {
            "header_from_domain": auth.header_from_domain if auth else None,
            "envelope_from": auth.envelope_from if auth else None,
            "spf_alignment": auth.spf_alignment.value if auth else None,
            "dkim_alignment": auth.dkim_alignment.value if auth else None,
            "dmarc_policy": auth.dmarc_policy if auth else None,
            "arc_present": auth.arc_present if auth else None,
            "evidence": [
                {
                    "method": e.method.value,
                    "result": e.result.value,
                    "asserted_by": e.asserted_by,
                    "trust": e.trust.value,
                }
                for e in (auth.evidence if auth else ())
            ],
        }
        if auth
        else None,
        "verifications": [
            {
                "method": v.method.value,
                "outcome": v.outcome.value,
                "detail": v.detail,
                "checked_domain": v.checked_domain,
                "scope": v.scope,
            }
            for v in report.verifications
        ],
        "identities": [
            {
                "header": i.source_header,
                "display_name": i.display_name,
                "address": i.address,
                "domain": i.domain,
            }
            for i in report.identities
        ],
        "route": {
            "hop_count": len(report.route.hops_chronological),
            "total_transit_seconds": report.route.total_transit_seconds,
            "trust_boundary_confidence": report.route.trust_boundary_confidence.value,
            "trust_boundary_explanation": report.route.trust_boundary_explanation,
        }
        if report.route
        else None,
        "iocs": [
            {
                "type": i.ioc_type.value,
                "defanged": i.defanged,
                "enrichment_eligible": i.enrichment_eligible,
                "occurrences": i.occurrences,
            }
            for i in report.iocs
        ],
        "intelligence": [
            {
                "provider": r.provider,
                "ioc": defang(r.ioc, r.ioc_type),
                "status": r.status.value,
                "is_demo_fixture": r.is_demo_fixture,
                "summary": r.summary,
            }
            for r in report.intel_results
        ],
        "recommendations": list(report.recommendations),
        "warnings": list(report.warnings),
    }


def to_markdown(report: AnalysisReport) -> str:
    risk = report.risk
    lines: list[str] = []
    lines.append(f"# Email Header Analysis — Report {report.report_id}")
    lines.append("")
    lines.append(f"Generated: {report.created_at.isoformat()}")
    lines.append(
        f"Enrichment: **{_enrichment_label(report.enrichment_mode)}** · "
        f"Independent verification: **{'yes' if report.verification_performed else 'no'}**"
    )
    lines.append("")

    if risk:
        lines.append(f"## Verdict: {risk.verdict_label}")
        lines.append("")
        lines.append(f"Score: {risk.score}/100 · Confidence: {risk.confidence.value}")
        lines.append("")
        lines.append(risk.verdict_rationale)
        lines.append("")

        if risk.headline_citations:
            lines.append("**Declared on the basis of:**")
            lines.append("")
            for citation in risk.headline_citations:
                lines.append(f"- {citation}")
            lines.append("")

        if risk.findings:
            lines.append("## Findings")
            lines.append("")
            for f in risk.findings:
                lines.append(f"### {f.rule_id} — {f.title} ({f.evidence_strength.value})")
                lines.append(f"- **Evidence:** {f.evidence}")
                lines.append(f"- **Why it matters:** {f.why_it_matters}")
                lines.append(f"- **Possible legitimate explanation:** {f.legitimate_explanation}")
                lines.append(f"- **Recommended action:** {f.recommended_action}")
                lines.append("")

    if report.authentication:
        auth = report.authentication
        lines.append("## Authentication")
        lines.append("")
        lines.append(f"- From domain: `{auth.header_from_domain}`")
        lines.append(f"- SPF alignment: {auth.spf_alignment.value}")
        lines.append(f"- DKIM alignment: {auth.dkim_alignment.value}")
        for e in auth.evidence:
            lines.append(
                f"- {e.method.value.upper()}: {e.result.value} "
                f"(asserted by {e.asserted_by or 'unknown'}, trust: {e.trust.value})"
            )
        lines.append("")

    if report.verifications:
        lines.append("## Independent verification")
        lines.append("")
        for v in report.verifications:
            lines.append(f"- **{v.method.value.upper()}** ({v.outcome.value}): {v.detail}")
        lines.append("")

    if report.route:
        lines.append("## Mail route")
        lines.append("")
        lines.append(f"- Hops: {len(report.route.hops_chronological)}")
        lines.append(f"- Trust boundary: {report.route.trust_boundary_explanation}")
        lines.append("")

    if report.iocs:
        lines.append("## Indicators of compromise")
        lines.append("")
        lines.append("| Type | Value (defanged) | Eligible | Occurrences |")
        lines.append("|---|---|---|---|")
        for i in report.iocs:
            lines.append(
                f"| {i.ioc_type.value} | `{i.defanged}` | "
                f"{'yes' if i.enrichment_eligible else 'no'} | {i.occurrences} |"
            )
        lines.append("")

    if report.intel_results:
        lines.append("## Threat intelligence")
        lines.append("")
        for r in report.intel_results:
            fixture_note = " *(demo fixture)*" if r.is_demo_fixture else ""
            lines.append(
                f"- **{r.provider}** on `{defang(r.ioc, r.ioc_type)}`: "
                f"{r.status.value}{fixture_note} — {r.summary}"
            )
        lines.append("")

    if report.recommendations:
        lines.append("## Analyst recommendations")
        lines.append("")
        for rec in report.recommendations:
            lines.append(f"- {rec}")
        lines.append("")

    if report.warnings:
        lines.append("## Parsing warnings")
        lines.append("")
        for w in report.warnings:
            lines.append(f"- {w}")
        lines.append("")

    return "\n".join(lines)


_TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"
_pdf_jinja_env = Environment(loader=FileSystemLoader(str(_TEMPLATES_DIR)), autoescape=True)
_pdf_jinja_env.globals["defang"] = defang


def to_pdf(report: AnalysisReport) -> bytes:
    """Render the report to a standalone PDF via a print-only template.

    Deliberately not a screenshot of the live results page: the live page has JS
    animations, a canvas background and interactive toggles that make no sense in a
    static document. ``report_pdf.html`` is a separate, plain template covering the
    same evidence — verdict, citations, findings, auth, IOCs, threat intel — laid out
    for print. xhtml2pdf is pure-Python (reportlab-backed), so this has no external
    binary dependency (no wkhtmltopdf, no headless Chrome, no GTK) and installs cleanly
    on Windows, matching this project's zero-unnecessary-infrastructure stance.
    """
    template = _pdf_jinja_env.get_template("report_pdf.html")
    html = template.render(
        report=report,
        risk=report.risk,
        auth=report.authentication,
        enrichment_label=_enrichment_label(report.enrichment_mode),
    )

    buffer = io.BytesIO()
    result = pisa.CreatePDF(io.StringIO(html), dest=buffer)
    if result.err:
        raise RuntimeError(f"PDF rendering failed ({result.err} error(s)).")
    return buffer.getvalue()
