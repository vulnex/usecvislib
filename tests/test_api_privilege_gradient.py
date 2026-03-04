#
# VULNEX -Universal Security Visualization Library-
#
# File: test_api_privilege_gradient.py
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
#

"""Tests for Privilege Gradient API router endpoints.

Covers: POST /visualize/privilege-gradient, /analyze/privilege-gradient,
/analyze/inversions, /validate/privilege-gradient
"""

import io
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'api'))
os.environ["USECVISLIB_AUTH_ENABLED"] = "false"

from fastapi.testclient import TestClient
from api.main import app

client = TestClient(app)

VALID_PRIVILEGE_GRADIENT = """
[gradient]
name = "Test Privilege Gradient"

[[zones]]
id = "untrusted"
label = "Internet"
trust_level = 0
color = "#ffcccc"

[[zones]]
id = "dmz"
label = "DMZ"
trust_level = 1
color = "#ffe0b2"

[[zones]]
id = "internal"
label = "Internal"
trust_level = 2
color = "#c8e6c9"

[[components]]
id = "firewall"
label = "Firewall"
zone = "dmz"
type = "network"

[[components]]
id = "webserver"
label = "Web Server"
zone = "dmz"
type = "server"

[[components]]
id = "database"
label = "Database"
zone = "internal"
type = "database"

[[influences]]
source = "firewall"
target = "webserver"
label = "Filters traffic"

[[influences]]
source = "webserver"
target = "database"
label = "Queries"
"""

INVALID_TOML = "{{not valid}}"


def _upload(content, filename="gradient.toml"):
    return ("file", (filename, io.BytesIO(content.encode()), "application/octet-stream"))


# =============================================================================
# Visualize
# =============================================================================

class TestVisualizePrivilegeGradient:

    def test_visualize_returns_image(self):
        response = client.post(
            "/visualize/privilege-gradient?format=png",
            files=[_upload(VALID_PRIVILEGE_GRADIENT)],
        )
        # 400 if graphviz not installed
        assert response.status_code in (200, 400)

    def test_visualize_svg(self):
        response = client.post(
            "/visualize/privilege-gradient?format=svg",
            files=[_upload(VALID_PRIVILEGE_GRADIENT)],
        )
        assert response.status_code in (200, 400)

    def test_visualize_malformed(self):
        response = client.post(
            "/visualize/privilege-gradient",
            files=[_upload(INVALID_TOML)],
        )
        assert response.status_code in (400, 500)


# =============================================================================
# Analyze
# =============================================================================

class TestAnalyzePrivilegeGradient:

    def test_analyze_returns_stats(self):
        response = client.post(
            "/analyze/privilege-gradient",
            files=[_upload(VALID_PRIVILEGE_GRADIENT)],
        )
        assert response.status_code == 200
        data = response.json()
        assert "total_zones" in data
        assert "total_components" in data
        assert "total_influences" in data
        assert data["total_zones"] >= 3

    def test_analyze_malformed(self):
        response = client.post(
            "/analyze/privilege-gradient",
            files=[_upload(INVALID_TOML)],
        )
        assert response.status_code in (400, 500)


# =============================================================================
# Inversions
# =============================================================================

class TestAnalyzeInversions:

    def test_inversions_returns_response(self):
        response = client.post(
            "/analyze/inversions",
            files=[_upload(VALID_PRIVILEGE_GRADIENT)],
        )
        assert response.status_code == 200
        data = response.json()
        assert "total" in data
        assert "inversions" in data
        assert isinstance(data["inversions"], list)

    def test_inversions_malformed(self):
        response = client.post(
            "/analyze/inversions",
            files=[_upload(INVALID_TOML)],
        )
        assert response.status_code in (400, 500)


# =============================================================================
# Validate
# =============================================================================

class TestValidatePrivilegeGradient:

    def test_validate_valid(self):
        response = client.post(
            "/validate/privilege-gradient",
            files=[_upload(VALID_PRIVILEGE_GRADIENT)],
        )
        assert response.status_code == 200
        data = response.json()
        assert "valid" in data

    def test_validate_malformed(self):
        response = client.post(
            "/validate/privilege-gradient",
            files=[_upload(INVALID_TOML)],
        )
        assert response.status_code in (200, 400, 500)
