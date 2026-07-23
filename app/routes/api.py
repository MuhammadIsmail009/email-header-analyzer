"""Typed JSON API.

Every response is a typed Pydantic model, per the brief. Raw headers are always
delivered in a request *body*, never a query parameter — see
``test_raw_header_never_in_url``.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, PlainTextResponse, Response

from app.config import Settings, get_settings
from app.dependencies import get_analysis_service, get_report_store
from app.rate_limit import limiter
from app.routes.schemas import (
    AnalyzeRequest,
    AnalyzeResponse,
    ConfigStatusResponse,
    HealthResponse,
)
from app.services.analysis_service import AnalysisService
from app.services.report_service import ReportStore, to_json_dict, to_markdown, to_pdf


def _analyze_rate() -> str:
    settings = get_settings()
    return settings.rate_limit_analyze if settings.rate_limit_enabled else "10000/second"

router = APIRouter(prefix="/api/v1", tags=["api"])
reports_router = APIRouter(tags=["reports"])
health_router = APIRouter(tags=["health"])


@health_router.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    return HealthResponse()


@router.get("/config-status", response_model=ConfigStatusResponse)
async def config_status(settings: Settings = Depends(get_settings)) -> ConfigStatusResponse:
    """Reports *whether* providers are configured — never leaks a key value."""
    return ConfigStatusResponse(
        verification_enabled=settings.verification_enabled,
        enrichment_enabled=settings.enrichment_enabled,
        demo_mode=settings.demo_mode,
        providers={
            "abuseipdb": settings.provider_enabled("abuseipdb"),
            "emailrep": settings.provider_enabled("emailrep"),
            "virustotal": settings.provider_enabled("virustotal"),
        },
        trusted_receiver_domains_configured=bool(settings.trusted_receiver_domains),
    )


@router.post("/analyze", response_model=AnalyzeResponse)
@limiter.limit(_analyze_rate)
async def analyze_api(
    request: Request,
    payload: AnalyzeRequest,
    settings: Settings = Depends(get_settings),
    service: AnalysisService = Depends(get_analysis_service),
    store: ReportStore = Depends(get_report_store),
) -> AnalyzeResponse:
    if len(payload.raw_header.encode("utf-8", errors="replace")) > settings.max_header_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"raw_header exceeds the {settings.max_header_bytes} byte limit.",
        )
    report = await service.analyze(payload.raw_header, body=payload.body)
    store.put(report)
    return AnalyzeResponse(report=report)


@reports_router.get("/reports/{report_id}.json")
async def report_json(report_id: str, store: ReportStore = Depends(get_report_store)):
    report = store.get(report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found or expired.")
    return JSONResponse(to_json_dict(report))


@reports_router.get("/reports/{report_id}.md")
async def report_markdown(report_id: str, store: ReportStore = Depends(get_report_store)):
    report = store.get(report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found or expired.")
    return PlainTextResponse(to_markdown(report), media_type="text/markdown")


@reports_router.get("/reports/{report_id}.pdf")
async def report_pdf(report_id: str, store: ReportStore = Depends(get_report_store)):
    report = store.get(report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found or expired.")
    pdf_bytes = to_pdf(report)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{report_id}.pdf"'},
    )
