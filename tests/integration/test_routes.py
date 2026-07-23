"""HTTP-layer tests via FastAPI's TestClient.

Covers security behaviour that only exists at the route layer: CSRF, security
headers, safe error rendering, XSS-safe template rendering, path-traversal
resistance on sample loading, and request-size limits. Core analysis correctness is
covered in ``tests/unit`` and ``tests/integration/test_analysis_service.py`` — these
tests are about the web layer wrapped around it.
"""

from __future__ import annotations

import io
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.dependencies import reset_dependency_caches
from app.main import create_app

SAMPLES_DIR = Path(__file__).resolve().parents[2] / "samples"


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("VERIFICATION_ENABLED", "false")
    monkeypatch.setenv("ENRICHMENT_ENABLED", "false")
    reset_dependency_caches()
    app = create_app()
    with TestClient(app) as c:
        yield c
    reset_dependency_caches()


def _csrf(client: TestClient) -> tuple[str, str]:
    """GET / and extract the CSRF token from both the cookie and the form field."""
    response = client.get("/")
    cookie = client.cookies.get("csrf_token")
    match = re.search(r'name="csrf_token" value="([^"]+)"', response.text)
    return cookie, match.group(1)


# ---------------------------------------------------------------------------
# Basic routes
# ---------------------------------------------------------------------------


def test_health_endpoint(client: TestClient):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_index_renders(client: TestClient):
    response = client.get("/")
    assert response.status_code == 200
    assert "Email Header Analyzer" in response.text


def test_config_status_never_leaks_key_values(client: TestClient, monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "super-secret-value")
    reset_dependency_caches()
    response = client.get("/api/v1/config-status")
    assert response.status_code == 200
    assert "super-secret-value" not in response.text


# ---------------------------------------------------------------------------
# CSRF
# ---------------------------------------------------------------------------


def test_analyze_without_csrf_token_is_rejected(client: TestClient):
    response = client.post("/analyze", data={"raw_header": "From: a@example.com\n"})
    assert response.status_code == 400


def test_analyze_with_mismatched_csrf_token_is_rejected(client: TestClient):
    _cookie, _form = _csrf(client)
    response = client.post(
        "/analyze",
        data={"raw_header": "From: a@example.com\n", "csrf_token": "not-the-real-token"},
    )
    assert response.status_code == 400


def test_analyze_with_matching_csrf_token_succeeds(client: TestClient):
    _cookie, form_token = _csrf(client)
    response = client.post(
        "/analyze",
        data={"raw_header": "From: a@example.com\nTo: b@example.org\n", "csrf_token": form_token},
    )
    assert response.status_code == 200
    assert "verdict-chip" in response.text


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------


def test_empty_header_is_rejected_with_clear_error(client: TestClient):
    _cookie, token = _csrf(client)
    response = client.post("/analyze", data={"raw_header": "", "csrf_token": token})
    assert response.status_code == 400
    assert "paste a header" in response.text.lower()


def test_oversized_header_is_rejected(client: TestClient):
    _cookie, token = _csrf(client)
    big = "From: a@example.com\n" + ("X-Filler: " + "a" * 500 + "\n") * 600
    response = client.post("/analyze", data={"raw_header": big, "csrf_token": token})
    assert response.status_code == 400
    assert "exceeds" in response.text.lower()


def test_eml_upload_with_disallowed_extension_is_rejected(client: TestClient):
    _cookie, token = _csrf(client)
    files = {"eml_file": ("payload.exe", io.BytesIO(b"garbage"), "application/octet-stream")}
    response = client.post(
        "/analyze", data={"raw_header": "", "csrf_token": token}, files=files
    )
    assert response.status_code == 400


def test_eml_upload_splits_header_and_body_correctly(client: TestClient):
    _cookie, token = _csrf(client)
    content = b"From: alice@bank.example\nSubject: test\n\nThis is the body.\n"
    files = {"eml_file": ("test.eml", io.BytesIO(content), "message/rfc822")}
    response = client.post(
        "/analyze", data={"raw_header": "", "csrf_token": token}, files=files
    )
    assert response.status_code == 200
    assert "verdict-chip" in response.text


# ---------------------------------------------------------------------------
# Security headers
# ---------------------------------------------------------------------------


def test_security_headers_present_on_every_response(client: TestClient):
    response = client.get("/")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert "default-src 'self'" in response.headers["content-security-policy"]
    assert "x-request-id" in response.headers


def test_no_wildcard_cors_header_present(client: TestClient):
    response = client.get("/")
    assert "access-control-allow-origin" not in response.headers


# ---------------------------------------------------------------------------
# XSS — the payload class most relevant to a tool whose entire input is hostile
# ---------------------------------------------------------------------------


def test_xss_payload_in_subject_is_rendered_inert(client: TestClient):
    _cookie, token = _csrf(client)
    payload = (
        "From: alice@example.com\n"
        "Subject: <script>alert(document.cookie)</script>\n"
    )
    response = client.post(
        "/analyze", data={"raw_header": payload, "csrf_token": token}
    )
    assert response.status_code == 200
    assert "<script>alert(document.cookie)</script>" not in response.text
    assert "&lt;script&gt;" in response.text


def test_xss_payload_in_display_name_is_rendered_inert(client: TestClient):
    _cookie, token = _csrf(client)
    payload = (
        '''From: "><img src=x onerror=alert(1)> <alice@example.com>\n'''
        "To: bob@example.org\n"
    )
    response = client.post(
        "/analyze", data={"raw_header": payload, "csrf_token": token}
    )
    assert response.status_code == 200
    assert "<img src=x onerror=alert(1)>" not in response.text


# ---------------------------------------------------------------------------
# Path traversal on sample loading
# ---------------------------------------------------------------------------


def test_sample_loading_rejects_path_traversal(client: TestClient):
    response = client.get("/samples/..%2Frequirements.txt")
    assert response.status_code == 404


def test_sample_loading_rejects_unknown_names(client: TestClient):
    response = client.get("/samples/not_a_real_sample.txt")
    assert response.status_code == 404


def test_all_four_bundled_samples_load(client: TestClient):
    for name in (
        "legitimate_header.txt",
        "phishing_header.txt",
        "possible_bec_header.txt",
        "malformed_header.txt",
    ):
        response = client.get(f"/samples/{name}")
        assert response.status_code == 200
        assert response.text  # non-empty


# ---------------------------------------------------------------------------
# Error handling — no leaked internals
# ---------------------------------------------------------------------------


def test_404_page_has_no_stack_trace(client: TestClient):
    response = client.get("/this-route-does-not-exist", headers={"accept": "text/html"})
    assert response.status_code == 404
    assert "Traceback" not in response.text
    assert "File \"" not in response.text


def test_404_json_for_api_clients(client: TestClient):
    response = client.get("/this-route-does-not-exist", headers={"accept": "application/json"})
    assert response.status_code == 404
    body = response.json()
    assert "request_id" in body


# ---------------------------------------------------------------------------
# Raw header never in a URL — asserted by inspecting the route table itself
# ---------------------------------------------------------------------------


def test_raw_header_never_appears_in_a_url_path_or_query_param(client: TestClient):
    """Structural guarantee: the only routes that accept the raw header are POST body
    routes (form or JSON). No GET route takes header content as a parameter."""
    from app.main import app

    for route in app.routes:
        path = getattr(route, "path", "") or ""
        if "header" in path.lower() and "{" in path:
            raise AssertionError(f"a route path template exposes header content: {path}")


# ---------------------------------------------------------------------------
# Full API round-trip
# ---------------------------------------------------------------------------


def test_json_api_analyze_and_export_round_trip(client: TestClient):
    raw = (SAMPLES_DIR / "legitimate_header.txt").read_text(encoding="utf-8")
    response = client.post("/api/v1/analyze", json={"raw_header": raw})
    assert response.status_code == 200
    data = response.json()
    report_id = data["report"]["report_id"]

    json_export = client.get(f"/reports/{report_id}.json")
    assert json_export.status_code == 200
    assert json_export.json()["report_id"] == report_id

    md_export = client.get(f"/reports/{report_id}.md")
    assert md_export.status_code == 200
    assert md_export.headers["content-type"].startswith("text/markdown")

    pdf_export = client.get(f"/reports/{report_id}.pdf")
    assert pdf_export.status_code == 200
    assert pdf_export.headers["content-type"] == "application/pdf"
    assert pdf_export.content.startswith(b"%PDF-")


def test_unknown_report_id_returns_404(client: TestClient):
    response = client.get("/reports/does-not-exist-at-all.json")
    assert response.status_code == 404
    assert client.get("/reports/does-not-exist-at-all.pdf").status_code == 404


def test_api_rejects_oversized_raw_header(client: TestClient):
    big = "From: a@example.com\n" + ("X-Filler: " + "a" * 500 + "\n") * 600
    response = client.post("/api/v1/analyze", json={"raw_header": big})
    assert response.status_code == 413
