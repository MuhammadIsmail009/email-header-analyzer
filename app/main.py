"""FastAPI application factory.

Assembles middleware, routes, and error handling. Kept deliberately free of business
logic — everything here is wiring; the actual analysis lives in ``app/core`` and
``app/services``.
"""

from __future__ import annotations

import logging
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.config import get_settings
from app.rate_limit import limiter
from app.routes import api, web
from app.security import (
    MaxBodySizeMiddleware,
    RequestIDMiddleware,
    SecurityHeadersMiddleware,
    request_id_var,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("email_header_analyzer")

_STATIC_DIR = Path(__file__).resolve().parent / "static"
_TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"


def create_app() -> FastAPI:
    settings = get_settings()

    app = FastAPI(
        title="Email Header Analyzer",
        description=(
            "Explainable email header analysis with independent SPF/DKIM/DMARC "
            "verification. Header-only analysis; not a verdict on message content."
        ),
        version="1.0.0",
        debug=settings.debug,
    )

    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    # Order matters: outermost middleware runs first on the way in. Size limiting
    # happens before anything parses the body; security headers apply to every
    # response including error ones.
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RequestIDMiddleware)
    app.add_middleware(MaxBodySizeMiddleware, max_bytes=settings.max_request_bytes)

    # Deliberately no CORSMiddleware. This is a server-rendered, same-origin
    # application; there is no cross-origin use case that would justify the exposure,
    # and the brief explicitly prohibits wildcard CORS with credentials.

    app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

    app.include_router(web.router)
    app.include_router(api.router)
    app.include_router(api.reports_router)
    app.include_router(api.health_router)

    templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))

    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException):
        rid = request_id_var.get()
        accepts_html = "text/html" in request.headers.get("accept", "")
        if accepts_html and not request.url.path.startswith("/api/"):
            return templates.TemplateResponse(
                request,
                "error.html",
                {
                    "status_code": exc.status_code,
                    "message": exc.detail or "An error occurred.",
                    "request_id": rid,
                },
                status_code=exc.status_code,
            )
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail, "request_id": rid},
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception):
        rid = request_id_var.get()
        # Never leak a stack trace or exception message to the client — that can
        # contain fragments of the analysed header. Full detail goes to the log only,
        # keyed by request ID, and raw header content is never logged (see
        # settings.log_raw_headers, which defaults to and should stay False).
        logger.exception("Unhandled exception [request_id=%s]", rid)
        accepts_html = "text/html" in request.headers.get("accept", "")
        if accepts_html and not request.url.path.startswith("/api/"):
            return templates.TemplateResponse(
                request,
                "error.html",
                {
                    "status_code": 500,
                    "message": "An unexpected error occurred.",
                    "request_id": rid,
                },
                status_code=500,
            )
        return JSONResponse(
            status_code=500,
            content={"detail": "An unexpected error occurred.", "request_id": rid},
        )

    return app


app = create_app()
