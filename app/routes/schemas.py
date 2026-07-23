"""Typed request/response models for the JSON API.

Kept separate from ``app/core/models.py`` — those are the analysis domain models;
these are the wire contract, and the two are allowed to diverge (for example,
``AnalyzeRequest`` accepts optional inline text or a base64 payload, which has no
equivalent inside the analysis core).
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from app.core.models import AnalysisReport


class AnalyzeRequest(BaseModel):
    raw_header: str = Field(
        ...,
        min_length=1,
        description="The raw email header block to analyze.",
        examples=[
            "From: alice@example.com\nTo: bob@example.org\nSubject: Hello\n"
        ],
    )
    body: str | None = Field(
        default=None,
        description=(
            "Optional message body, enabling full DKIM verification including the "
            "body hash. Omit for headers-only analysis."
        ),
    )


class ConfigStatusResponse(BaseModel):
    verification_enabled: bool
    enrichment_enabled: bool
    demo_mode: bool
    providers: dict[str, bool]
    trusted_receiver_domains_configured: bool


class HealthResponse(BaseModel):
    status: str = "ok"


class AnalyzeResponse(BaseModel):
    """Wraps the full typed report. ``model_config`` inherits from AnalysisReport's
    own field set — nothing is re-declared here to avoid the two drifting apart."""

    report: AnalysisReport
