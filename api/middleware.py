#
# VULNEX -Universal Security Visualization Library-
#
# File: middleware.py
# Description: Security headers and request logging middleware
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
#

import time
import uuid
import logging

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware

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
            logger.info(
                f"[{request_id}] <-- {response.status_code} "
                f"duration={duration:.2f}ms"
            )
            return response

        except Exception as e:
            duration = (time.time() - start_time) * 1000
            logger.error(
                f"[{request_id}] <-- ERROR {type(e).__name__}: {str(e)} "
                f"duration={duration:.2f}ms"
            )
            raise
