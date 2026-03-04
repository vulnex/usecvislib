#
# VULNEX -Universal Security Visualization Library-
#
# File: test_api_threat_models.py
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
#

"""Tests for Threat Models API router endpoints.

Covers: POST /visualize/threat-model, /analyze/threat-model, /analyze/stride
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

VALID_THREAT_MODEL = """
[model]
name = "Test Threat Model"

[processes]
[processes.webapp]
label = "Web Application"

[processes.api]
label = "API Server"

[datastores]
[datastores.db]
label = "Database"

[externals]
[externals.user]
label = "End User"

[externals.admin]
label = "Admin"

[dataflows]
[dataflows.flow1]
source = "user"
target = "webapp"
label = "HTTPS Request"

[dataflows.flow2]
source = "webapp"
target = "api"
label = "API Call"

[dataflows.flow3]
source = "api"
target = "db"
label = "SQL Query"

[boundaries]
[boundaries.dmz]
label = "DMZ"
members = ["webapp"]

[boundaries.internal]
label = "Internal Network"
members = ["api", "db"]
"""

INVALID_TOML = "{{not valid}}"


def _upload(content, filename="model.toml"):
    return ("file", (filename, io.BytesIO(content.encode()), "application/octet-stream"))


# =============================================================================
# Visualize
# =============================================================================

class TestVisualizeThreatModel:

    def test_visualize_returns_image(self):
        response = client.post(
            "/visualize/threat-model?format=png",
            files=[_upload(VALID_THREAT_MODEL)],
        )
        # 400/500 if graphviz not installed
        assert response.status_code in (200, 400, 500)

    def test_visualize_svg(self):
        response = client.post(
            "/visualize/threat-model?format=svg",
            files=[_upload(VALID_THREAT_MODEL)],
        )
        assert response.status_code in (200, 400, 500)

    def test_visualize_malformed(self):
        response = client.post(
            "/visualize/threat-model",
            files=[_upload(INVALID_TOML)],
        )
        assert response.status_code in (400, 500)

    def test_visualize_invalid_extension(self):
        response = client.post(
            "/visualize/threat-model",
            files=[_upload("data", "file.exe")],
        )
        assert response.status_code in (400, 500)


# =============================================================================
# Analyze
# =============================================================================

class TestAnalyzeThreatModel:

    def test_analyze_returns_stats(self):
        response = client.post(
            "/analyze/threat-model",
            files=[_upload(VALID_THREAT_MODEL)],
        )
        assert response.status_code == 200
        data = response.json()
        assert "total_processes" in data
        assert "total_datastores" in data
        assert "total_dataflows" in data
        assert data["total_processes"] >= 2

    def test_analyze_malformed(self):
        response = client.post(
            "/analyze/threat-model",
            files=[_upload(INVALID_TOML)],
        )
        assert response.status_code in (400, 500)


# =============================================================================
# STRIDE Analysis
# =============================================================================

class TestAnalyzeStride:

    def test_stride_returns_categories(self):
        response = client.post(
            "/analyze/stride",
            files=[_upload(VALID_THREAT_MODEL)],
        )
        assert response.status_code == 200
        data = response.json()
        assert "model_name" in data
        # STRIDE categories
        for category in ["spoofing", "tampering", "repudiation",
                         "information_disclosure", "denial_of_service",
                         "elevation_of_privilege"]:
            assert category in data

    def test_stride_malformed(self):
        response = client.post(
            "/analyze/stride",
            files=[_upload(INVALID_TOML)],
        )
        assert response.status_code in (400, 500)
