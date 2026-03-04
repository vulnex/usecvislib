#
# VULNEX -Universal Security Visualization Library-
#
# File: test_api_middleware.py
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
#

"""Tests for API middleware: security headers and request logging.

Validates that SecurityHeadersMiddleware sets the correct headers on all
responses (HSTS, CSP, X-Frame-Options, etc.) and that the CSP policy differs
between documentation paths and API paths.
"""

import os
import sys

# Add the api directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'api'))

# Disable auth for these tests
os.environ["USECVISLIB_AUTH_ENABLED"] = "false"

from fastapi.testclient import TestClient
from api.main import app

client = TestClient(app)


# =============================================================================
# Security Headers - Common Headers
# =============================================================================

class TestSecurityHeadersCommon:
    """Test that security headers are present on all responses."""

    def test_hsts_header(self):
        """HSTS header enforces HTTPS with includeSubDomains."""
        response = client.get("/health")
        assert response.headers["Strict-Transport-Security"] == "max-age=31536000; includeSubDomains"

    def test_x_content_type_options(self):
        """X-Content-Type-Options prevents MIME sniffing."""
        response = client.get("/health")
        assert response.headers["X-Content-Type-Options"] == "nosniff"

    def test_x_frame_options(self):
        """X-Frame-Options prevents clickjacking."""
        response = client.get("/health")
        assert response.headers["X-Frame-Options"] == "DENY"

    def test_x_xss_protection(self):
        """X-XSS-Protection enables legacy browser XSS filter."""
        response = client.get("/health")
        assert response.headers["X-XSS-Protection"] == "1; mode=block"

    def test_referrer_policy(self):
        """Referrer-Policy limits referrer information leakage."""
        response = client.get("/health")
        assert response.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"

    def test_x_permitted_cross_domain_policies(self):
        """X-Permitted-Cross-Domain-Policies blocks Flash/PDF reads."""
        response = client.get("/health")
        assert response.headers["X-Permitted-Cross-Domain-Policies"] == "none"

    def test_permissions_policy(self):
        """Permissions-Policy disables geolocation, mic, and camera."""
        response = client.get("/health")
        assert response.headers["Permissions-Policy"] == "geolocation=(), microphone=(), camera=()"

    def test_headers_on_post_endpoint(self):
        """Security headers are also present on POST responses."""
        # Use /jobs/start-demo as a simple POST endpoint
        response = client.post("/jobs/start-demo")
        assert response.headers["X-Frame-Options"] == "DENY"
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["Strict-Transport-Security"] == "max-age=31536000; includeSubDomains"

    def test_headers_on_404(self):
        """Security headers are present even on 404 responses."""
        response = client.get("/nonexistent-path")
        assert response.headers["X-Frame-Options"] == "DENY"
        assert response.headers["X-Content-Type-Options"] == "nosniff"


# =============================================================================
# Security Headers - CSP Policy (API vs Docs)
# =============================================================================

class TestCSPPolicy:
    """Test Content-Security-Policy differs between API and docs paths."""

    def test_api_csp_strict(self):
        """API endpoints get the strict CSP policy."""
        response = client.get("/health")
        csp = response.headers["Content-Security-Policy"]
        assert "default-src 'none'" in csp
        assert "frame-ancestors 'none'" in csp
        assert "object-src 'none'" in csp
        assert "base-uri 'none'" in csp
        assert "form-action 'none'" in csp
        assert "upgrade-insecure-requests" in csp

    def test_api_csp_no_script_src(self):
        """Strict API CSP does not allow any script sources."""
        response = client.get("/styles")
        csp = response.headers["Content-Security-Policy"]
        assert "script-src" not in csp

    def test_docs_csp_relaxed(self):
        """Swagger docs get a relaxed CSP that allows CDN assets."""
        response = client.get("/docs")
        csp = response.headers["Content-Security-Policy"]
        assert "default-src 'self'" in csp
        assert "cdn.jsdelivr.net" in csp
        assert "script-src" in csp

    def test_redoc_csp_relaxed(self):
        """ReDoc also gets the relaxed CSP."""
        response = client.get("/redoc")
        csp = response.headers["Content-Security-Policy"]
        assert "cdn.jsdelivr.net" in csp

    def test_openapi_json_csp_relaxed(self):
        """OpenAPI JSON endpoint gets the relaxed CSP (used by docs UI)."""
        response = client.get("/openapi.json")
        csp = response.headers["Content-Security-Policy"]
        assert "default-src 'self'" in csp

    def test_arbitrary_api_path_gets_strict_csp(self):
        """Non-docs paths always get the strict CSP."""
        response = client.get("/formats")
        csp = response.headers["Content-Security-Policy"]
        assert "default-src 'none'" in csp

    def test_templates_endpoint_gets_strict_csp(self):
        """Template listing gets strict CSP (not docs)."""
        response = client.get("/templates")
        csp = response.headers["Content-Security-Policy"]
        assert "default-src 'none'" in csp


# =============================================================================
# Request Logging Middleware
# =============================================================================

class TestRequestLoggingMiddleware:
    """Test that request logging middleware works without errors."""

    def test_request_completes_with_logging(self):
        """Requests complete successfully with logging middleware active."""
        response = client.get("/health")
        assert response.status_code == 200

    def test_multiple_sequential_requests(self):
        """Multiple requests each get logged independently."""
        for _ in range(3):
            response = client.get("/health")
            assert response.status_code == 200

    def test_logging_does_not_leak_into_response(self):
        """Request IDs and timing info stay in logs, not response body."""
        response = client.get("/health")
        body = response.json()
        # The response body should only contain health data, not logging metadata
        assert "request_id" not in body
        assert "duration" not in body
