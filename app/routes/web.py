"""Server-rendered routes: the form, the results page, and sample loading.

Every response here is Jinja2-rendered with autoescaping on — the primary XSS defence
for input that is, by definition, attacker-controllable. No route in this module ever
puts a raw header in a URL or query string.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates

from app.config import Settings, get_settings
from app.core.header_parser import split_header_body
from app.dependencies import get_analysis_service, get_report_store
from app.rate_limit import limiter
from app.security import csrf_cookie_kwargs, issue_csrf_token, verify_csrf
from app.services.analysis_service import AnalysisService
from app.services.report_service import ReportStore

router = APIRouter()

_TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"
templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))

_SAMPLES_DIR = Path(__file__).resolve().parent.parent.parent / "samples"
_ALLOWED_SAMPLES = frozenset(
    {
        "legitimate_header.txt",
        "phishing_header.txt",
        "possible_bec_header.txt",
        "malformed_header.txt",
    }
)


def _template_context(settings: Settings, request: Request) -> dict:
    return {
        "request": request,
        "demo_mode": settings.demo_mode,
        "enrichment_enabled": settings.enrichment_enabled,
        "verification_enabled": settings.verification_enabled,
    }


@router.get("/", response_class=HTMLResponse)
async def index(request: Request, settings: Settings = Depends(get_settings)):
    token = issue_csrf_token()
    context = _template_context(settings, request)
    context.update(
        {
            "csrf_token": token,
            "max_header_chars": settings.max_header_bytes,
            "max_header_kib": settings.max_header_bytes // 1024,
        }
    )
    response = templates.TemplateResponse(request, "index.html", context)
    response.set_cookie(**csrf_cookie_kwargs(token, secure=settings.environment == "production"))
    return response


@router.get("/samples/{sample_name}", response_class=PlainTextResponse)
async def get_sample(sample_name: str):
    """Serve a bundled sample by name.

    The name is checked against an explicit allowlist rather than joined onto a path
    — never trust a path segment from the request for filesystem access.
    """
    if sample_name not in _ALLOWED_SAMPLES:
        return PlainTextResponse("Unknown sample.", status_code=404)
    path = _SAMPLES_DIR / sample_name
    return PlainTextResponse(path.read_text(encoding="utf-8"))


def _analyze_rate() -> str:
    settings = get_settings()
    return settings.rate_limit_analyze if settings.rate_limit_enabled else "10000/second"


@router.post("/analyze", response_class=HTMLResponse)
@limiter.limit(_analyze_rate)
async def analyze_form(
    request: Request,
    raw_header: str = Form(default=""),
    csrf_token: str = Form(default=""),
    eml_file: UploadFile | None = None,
    settings: Settings = Depends(get_settings),
    service: AnalysisService = Depends(get_analysis_service),
    store: ReportStore = Depends(get_report_store),
):
    if not verify_csrf(request, csrf_token):
        context = _template_context(settings, request)
        context.update(
            {
                "csrf_token": issue_csrf_token(),
                "max_header_chars": settings.max_header_bytes,
                "max_header_kib": settings.max_header_bytes // 1024,
                "form_error": "Your session expired. Please try again.",
            }
        )
        return templates.TemplateResponse(request, "index.html", context, status_code=400)

    body_text: str | None = None
    header_text = raw_header

    if eml_file is not None and eml_file.filename:
        suffix = Path(eml_file.filename).suffix.lower()
        if suffix not in settings.allowed_upload_extensions:
            return _form_error(
                request, settings, f"Only {', '.join(settings.allowed_upload_extensions)} files are accepted."
            )
        raw_bytes = await eml_file.read()
        if len(raw_bytes) > settings.max_header_bytes:
            return _form_error(
                request, settings,
                f"Uploaded file exceeds the {settings.max_header_bytes // 1024} KiB limit.",
            )
        try:
            decoded = raw_bytes.decode("utf-8", errors="replace")
        except Exception:
            return _form_error(request, settings, "Could not decode the uploaded file as text.")
        header_text, body_text = split_header_body(decoded)

    if not header_text or not header_text.strip():
        return _form_error(request, settings, "Please paste a header or upload a file before analyzing.")

    if len(header_text.encode("utf-8", errors="replace")) > settings.max_header_bytes:
        return _form_error(
            request, settings,
            f"Header exceeds the {settings.max_header_bytes // 1024} KiB limit.",
        )

    report = await service.analyze(header_text, body=body_text)
    store.put(report)

    context = _template_context(settings, request)
    context.update({"report": report, "verifications": report.verifications})
    return templates.TemplateResponse(request, "results.html", context)


def _form_error(request: Request, settings: Settings, message: str):
    context = _template_context(settings, request)
    context.update(
        {
            "csrf_token": issue_csrf_token(),
            "max_header_chars": settings.max_header_bytes,
            "max_header_kib": settings.max_header_bytes // 1024,
            "form_error": message,
        }
    )
    return templates.TemplateResponse(request, "index.html", context, status_code=400)
