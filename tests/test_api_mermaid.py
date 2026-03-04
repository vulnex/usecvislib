#
# VULNEX -Universal Security Visualization Library-
#
# File: test_api_mermaid.py
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
#

"""Tests for Mermaid Diagrams API router endpoints.

Covers: POST /visualize/mermaid, /analyze/mermaid
GET /mermaid/templates, /mermaid/template/{cat}/{name},
/mermaid/themes, /mermaid/types
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

VALID_MERMAID_TOML = """
[mermaid]
title = "Test Flowchart"
theme = "default"
background = "white"
width = 800
height = 600

source = \"\"\"
flowchart TD
    A[Start] --> B{Decision}
    B -->|Yes| C[OK]
    B -->|No| D[Fail]
\"\"\"
"""

INVALID_TOML = "{{not valid}}"


def _upload(content, filename="diagram.toml"):
    return ("file", (filename, io.BytesIO(content.encode()), "application/octet-stream"))


# =============================================================================
# Themes / Types (GET endpoints)
# =============================================================================

class TestMermaidThemes:

    def test_list_themes(self):
        response = client.get("/mermaid/themes")
        assert response.status_code == 200
        data = response.json()
        assert "themes" in data
        assert "default" in data
        assert len(data["themes"]) > 0


class TestMermaidTypes:

    def test_list_types(self):
        response = client.get("/mermaid/types")
        assert response.status_code == 200
        data = response.json()
        assert "types" in data
        assert "descriptions" in data
        assert len(data["types"]) > 0


# =============================================================================
# Templates
# =============================================================================

class TestMermaidTemplates:

    def test_list_templates(self):
        response = client.get("/mermaid/templates")
        assert response.status_code == 200
        data = response.json()
        assert "templates" in data
        assert "total" in data

    def test_list_templates_by_category(self):
        response = client.get("/mermaid/templates?category=flowcharts")
        assert response.status_code == 200

    def test_get_template(self):
        templates = client.get("/mermaid/templates").json()
        if not templates["templates"]:
            pytest.skip("No mermaid templates available")
        t = templates["templates"][0]
        # Convert name to kebab-case ID for URL
        name_id = t["name"].lower().replace(" ", "-")
        response = client.get(f"/mermaid/template/{t['category']}/{name_id}")
        assert response.status_code == 200
        data = response.json()
        assert "content" in data

    def test_get_template_not_found(self):
        response = client.get("/mermaid/template/flowcharts/nonexistent-xyz")
        assert response.status_code == 404

    def test_get_template_path_traversal(self):
        response = client.get("/mermaid/template/../../etc/passwd")
        assert response.status_code in (400, 404, 422)


# =============================================================================
# Analyze
# =============================================================================

class TestAnalyzeMermaid:

    def test_analyze_returns_stats(self):
        response = client.post(
            "/analyze/mermaid",
            files=[_upload(VALID_MERMAID_TOML)],
        )
        assert response.status_code == 200
        data = response.json()
        assert "valid" in data

    def test_analyze_malformed(self):
        response = client.post(
            "/analyze/mermaid",
            files=[_upload(INVALID_TOML)],
        )
        assert response.status_code in (400, 500)


# =============================================================================
# Visualize
# =============================================================================

class TestVisualizeMermaid:

    def test_visualize_mermaid(self):
        response = client.post(
            "/visualize/mermaid",
            files=[_upload(VALID_MERMAID_TOML)],
        )
        # 503 if mermaid-cli not installed
        assert response.status_code in (200, 503)

    def test_visualize_malformed(self):
        response = client.post(
            "/visualize/mermaid",
            files=[_upload(INVALID_TOML)],
        )
        assert response.status_code in (400, 500, 503)

    def test_visualize_invalid_extension(self):
        response = client.post(
            "/visualize/mermaid",
            files=[_upload("data", "file.exe")],
        )
        assert response.status_code in (400, 500)
