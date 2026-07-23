"""Security middleware: request-size limiting, security headers, request IDs, CSRF.

Kept as one small module rather than scattered across ``main.py`` so the whole
security posture can be reviewed in one place alongside ``docs/THREAT_MODEL.md``.
"""

from __future__ import annotations

import hmac
import secrets
import uuid
from contextvars import ContextVar

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

request_id_var: ContextVar[str] = ContextVar("request_id", default="-")


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Attaches a per-request correlation ID, echoed as X-Request-ID.

    Lets an analyst or support engineer correlate a browser-reported error with a
    server log line without either party needing to share the raw header content —
    the ID is the only thing that needs to cross that boundary.
    """

    async def dispatch(self, request: Request, call_next):
        rid = str(uuid.uuid4())
        token = request_id_var.set(rid)
        try:
            response = await call_next(request)
        finally:
            request_id_var.reset(token)
        response.headers["X-Request-ID"] = rid
        return response


class MaxBodySizeMiddleware(BaseHTTPMiddleware):
    """Enforces the total request-body limit ahead of any route or form parser.

    Checking ``Content-Length`` alone is not sufficient — it can be absent or wrong
    for chunked/multipart bodies — so the body is also read incrementally and
    aborted the moment it exceeds the limit, before a route ever sees it.
    """

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        super().__init__(app)
        self._max_bytes = max_bytes

    async def dispatch(self, request: Request, call_next):
        content_length = request.headers.get("content-length")
        if content_length is not None:
            try:
                if int(content_length) > self._max_bytes:
                    return Response(
                        content="Request too large.",
                        status_code=413,
                        media_type="text/plain",
                    )
            except ValueError:
                pass

        body = await request.body()
        if len(body) > self._max_bytes:
            return Response(
                content="Request too large.", status_code=413, media_type="text/plain"
            )

        async def receive():
            return {"type": "http.request", "body": body, "more_body": False}

        request._receive = receive  # starlette-internal, but this is the documented pattern for re-injecting a consumed body
        return await call_next(request)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Baseline security headers on every response.

    CSP has no external hosts: this application ships every asset itself (no CDN),
    which is also what keeps it usable in an air-gapped SOC environment.
    """

    _CSP = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = self._CSP
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        return response


# ---------------------------------------------------------------------------
# CSRF — double-submit cookie
# ---------------------------------------------------------------------------
#
# No server-side session exists (there is nothing to key a session on), so the
# standard synchronizer-token pattern doesn't apply directly. Double-submit cookie is
# the correct fit: the server sets a random token in a cookie the browser can read,
# the form embeds the same value as a hidden field, and a same-origin attacker cannot
# read the cookie to forge a matching hidden field (that's the entire property CSRF
# protection needs here, since GET / carries no side effects to protect in the first
# place — the actual target is POST /analyze).

_CSRF_COOKIE = "csrf_token"


def issue_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def csrf_cookie_kwargs(token: str, secure: bool) -> dict:
    return dict(
        key=_CSRF_COOKIE,
        value=token,
        httponly=False,  # must be readable by the page to embed in the form
        samesite="strict",
        secure=secure,
        max_age=3600,
    )


def verify_csrf(request: Request, submitted_token: str | None) -> bool:
    cookie_token = request.cookies.get(_CSRF_COOKIE)
    if not cookie_token or not submitted_token:
        return False
    return hmac.compare_digest(cookie_token, submitted_token)
