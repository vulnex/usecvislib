#
# VULNEX -Universal Security Visualization Library-
#
# File: test_api_cloud.py
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
#

"""Tests for Cloud Diagrams API router endpoints.

Covers: POST /visualize/cloud, /analyze/cloud, /cloud/generate-code
GET /cloud/providers, /cloud/icons, /cloud/templates, /cloud/template/{cat}/{name}
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

VALID_CLOUD_DIAGRAM = """
[diagram]
title = "Test Cloud Diagram"
direction = "TB"
outformat = "png"
show = false

[[clusters]]
id = "vpc"
label = "VPC"

    [[clusters.nodes]]
    id = "web"
    label = "Web Server"

    [[clusters.nodes]]
    id = "db"
    label = "Database"

[[edges]]
source = "web"
target = "db"
label = "SQL"
"""

INVALID_TOML = "{{not valid}}"


def _upload(content, filename="cloud.toml"):
    return ("file", (filename, io.BytesIO(content.encode()), "application/octet-stream"))


# =============================================================================
# Providers / Icons / Templates (GET endpoints)
# =============================================================================

class TestCloudProviders:

    def test_list_providers(self):
        response = client.get("/cloud/providers")
        assert response.status_code == 200
        data = response.json()
        assert "providers" in data
        assert len(data["providers"]) > 0


class TestCloudIcons:

    def test_list_icons(self):
        response = client.get("/cloud/icons?provider=aws")
        # 503 if diagrams library not installed, 200 otherwise
        assert response.status_code in (200, 503)

    def test_list_icons_invalid_provider(self):
        response = client.get("/cloud/icons?provider=nonexistent")
        assert response.status_code == 422  # FastAPI validation


class TestCloudTemplates:

    def test_list_templates(self):
        response = client.get("/cloud/templates")
        assert response.status_code == 200
        data = response.json()
        assert "templates" in data
        assert "total" in data

    def test_list_templates_by_category(self):
        response = client.get("/cloud/templates?category=aws")
        assert response.status_code == 200

    def test_get_template(self):
        """Fetch template list first, then get a specific one by category/name."""
        templates = client.get("/cloud/templates").json()
        if not templates["templates"]:
            pytest.skip("No cloud templates available")
        t = templates["templates"][0]
        # Convert name to kebab-case ID for URL
        name_id = t["name"].lower().replace(" ", "-")
        response = client.get(f"/cloud/template/{t['category']}/{name_id}")
        assert response.status_code == 200
        data = response.json()
        assert "content" in data

    def test_get_template_not_found(self):
        response = client.get("/cloud/template/aws/nonexistent-template-xyz")
        assert response.status_code == 404

    def test_get_template_path_traversal(self):
        response = client.get("/cloud/template/../../etc/passwd")
        assert response.status_code in (400, 404, 422)


# =============================================================================
# Analyze
# =============================================================================

class TestAnalyzeCloud:

    def test_analyze_returns_stats(self):
        response = client.post(
            "/analyze/cloud",
            files=[_upload(VALID_CLOUD_DIAGRAM)],
        )
        assert response.status_code == 200
        data = response.json()
        assert "valid" in data or "stats" in data

    def test_analyze_malformed(self):
        response = client.post(
            "/analyze/cloud",
            files=[_upload(INVALID_TOML)],
        )
        assert response.status_code in (400, 500)


# =============================================================================
# Visualize
# =============================================================================

class TestVisualizeCloud:

    def test_visualize_cloud(self):
        response = client.post(
            "/visualize/cloud",
            files=[_upload(VALID_CLOUD_DIAGRAM)],
        )
        # 503 if diagrams library not installed
        assert response.status_code in (200, 503)

    def test_visualize_malformed(self):
        response = client.post(
            "/visualize/cloud",
            files=[_upload(INVALID_TOML)],
        )
        assert response.status_code in (400, 500, 503)


# =============================================================================
# Generate Code
# =============================================================================

class TestGenerateCloudCode:

    def test_generate_code(self):
        response = client.post(
            "/cloud/generate-code",
            files=[_upload(VALID_CLOUD_DIAGRAM)],
        )
        assert response.status_code == 200
        data = response.json()
        assert "code" in data
        assert "filename" in data
        assert len(data["code"]) > 0

    def test_generate_code_malformed(self):
        response = client.post(
            "/cloud/generate-code",
            files=[_upload(INVALID_TOML)],
        )
        assert response.status_code in (400, 500)
