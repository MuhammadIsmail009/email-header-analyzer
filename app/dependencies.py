"""Dependency wiring. Every service is constructed once and injected via FastAPI's
dependency system — routes never construct a service directly, so tests can override
any of these with a fake (see ``tests/integration/test_routes.py``).
"""

from __future__ import annotations

from functools import lru_cache

from app.config import Settings, get_settings
from app.services.analysis_service import AnalysisService
from app.services.enrichment_service import EnrichmentService
from app.services.report_service import ReportStore


@lru_cache(maxsize=1)
def get_enrichment_service() -> EnrichmentService:
    return EnrichmentService.from_settings(get_settings())


@lru_cache(maxsize=1)
def get_analysis_service() -> AnalysisService:
    settings = get_settings()
    return AnalysisService(settings, get_enrichment_service())


@lru_cache(maxsize=1)
def get_report_store() -> ReportStore:
    settings = get_settings()
    return ReportStore(
        max_entries=settings.report_cache_max_entries,
        ttl_seconds=settings.report_cache_ttl_seconds,
    )


def reset_dependency_caches() -> None:
    """Used by tests to force fresh service instances after changing settings."""
    get_settings.cache_clear()
    get_enrichment_service.cache_clear()
    get_analysis_service.cache_clear()
    get_report_store.cache_clear()


__all__ = [
    "Settings",
    "get_settings",
    "get_enrichment_service",
    "get_analysis_service",
    "get_report_store",
    "reset_dependency_caches",
]
