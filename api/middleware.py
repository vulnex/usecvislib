#
# VULNEX -Universal Security Visualization Library-
#
# File: middleware.py
# Description: Security headers, request size limit and request logging middleware
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
#

import json
import logging
import time
import uuid

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp, Message, Receive, Scope, Send

logger = logging.getLogger("usecvislib.api")


# =============================================================================
# Security Headers Middleware
# =============================================================================


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses.

    SECURITY: Implements comprehensive security headers including:
    - HSTS for HTTPS enforcement
    - CSP to prevent XSS and injection attacks
    - X-Frame-Options to prevent clickjacking
    - Additional headers to prevent various attack vectors
    """

    # CSP for Swagger UI / ReDoc documentation pages
    # SECURITY: Added object-src, base-uri, form-action, upgrade-insecure-requests
    DOCS_CSP = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "img-src 'self' data: https://fastapi.tiangolo.com; "
        "font-src 'self' https://cdn.jsdelivr.net; "
        "connect-src 'self' https://cdn.jsdelivr.net; "
        "frame-ancestors 'none'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "upgrade-insecure-requests"
    )

    # Strict CSP for API endpoints
    # SECURITY: Added object-src, base-uri, form-action, upgrade-insecure-requests
    API_CSP = (
        "default-src 'none'; "
        "frame-ancestors 'none'; "
        "object-src 'none'; "
        "base-uri 'none'; "
        "form-action 'none'; "
        "upgrade-insecure-requests"
    )

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        # SECURITY: HTTP Strict Transport Security - enforce HTTPS
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

        # SECURITY: Prevent MIME type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"

        # SECURITY: Prevent clickjacking
        response.headers["X-Frame-Options"] = "DENY"

        # SECURITY: XSS protection (legacy but still useful for older browsers)
        response.headers["X-XSS-Protection"] = "1; mode=block"

        # SECURITY: Control referrer information
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # SECURITY: Prevent Adobe Flash/PDF from reading response
        response.headers["X-Permitted-Cross-Domain-Policies"] = "none"

        # SECURITY: Content Security Policy - relaxed for docs, strict for API
        path = request.url.path
        if path in ("/docs", "/redoc", "/openapi.json") or path.startswith("/docs/") or path.startswith("/redoc/"):
            response.headers["Content-Security-Policy"] = self.DOCS_CSP
        else:
            response.headers["Content-Security-Policy"] = self.API_CSP

        # SECURITY: Permissions policy - disable unnecessary browser features
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"

        return response


# =============================================================================
# Request Size Limit Middleware
# =============================================================================


class _BodyTooLarge(Exception):
    pass


class RequestSizeLimitMiddleware:
    """Reject request bodies larger than ``max_body_size`` with 413.

    SECURITY: Starlette spools a multipart upload to disk in full before the
    endpoint runs, so the per-endpoint size checks came after any amount of
    disk had been used. This rejects an oversized ``Content-Length`` up front
    and stops reading a body (including chunked ones without a length) once
    it passes the limit.

    Plain ASGI rather than ``BaseHTTPMiddleware``: it must see the body as it
    arrives. Add it inside CORS so the 413 carries the CORS headers.
    """

    def __init__(self, app: ASGIApp, max_body_size: int) -> None:
        self.app = app
        self.max_body_size = max_body_size

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        content_length = dict(scope.get("headers") or []).get(b"content-length")
        if content_length is not None and content_length.isdigit() and int(content_length) > self.max_body_size:
            await self._reject(send)
            return

        received = 0
        too_large = False
        response_started = False

        async def limited_receive() -> Message:
            nonlocal received, too_large
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_body_size:
                    too_large = True
                    raise _BodyTooLarge
            return message

        async def guarded_send(message: Message) -> None:
            nonlocal response_started
            # Once the body is over the limit the app's own response (FastAPI
            # turns the read error into a 400) is replaced by the 413
            if too_large:
                return
            response_started = response_started or message["type"] == "http.response.start"
            await send(message)

        try:
            await self.app(scope, limited_receive, guarded_send)
        except Exception:
            if not too_large:
                raise
        if too_large and not response_started:
            await self._reject(send)

    async def _reject(self, send: Send) -> None:
        mb = self.max_body_size // (1024 * 1024)
        logger.warning(f"Request rejected: body exceeds {self.max_body_size} bytes")
        body = json.dumps({"detail": f"Request too large. Maximum size is {mb}MB."}).encode()
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())],
            }
        )
        await send({"type": "http.response.body", "body": body})


# =============================================================================
# Request Logging Middleware
# =============================================================================


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Log all incoming requests with timing."""

    async def dispatch(self, request: Request, call_next):
        request_id = str(uuid.uuid4())[:8]
        start_time = time.time()

        # Log incoming request
        logger.info(
            f"[{request_id}] --> {request.method} {request.url.path} "
            f"client={request.client.host if request.client else 'unknown'}"
        )

        try:
            response = await call_next(request)
            duration = (time.time() - start_time) * 1000

            # Log response
            logger.info(f"[{request_id}] <-- {response.status_code} duration={duration:.2f}ms")
            return response

        except Exception as e:
            duration = (time.time() - start_time) * 1000
            logger.error(f"[{request_id}] <-- ERROR {type(e).__name__}: {e!s} duration={duration:.2f}ms")
            raise
