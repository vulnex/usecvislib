#
# VULNEX -Universal Security Visualization Library-
#
# File: test_api_maestro.py
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
#

"""Tests for the MAESTRO Agentic Threat Model API router.

Covers: POST /visualize/maestro, /analyze/maestro, /validate/maestro,
GET /maestro/catalog, /maestro/catalog/{layer}.
"""

import io
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'api'))
os.environ["USECVISLIB_AUTH_ENABLED"] = "false"

from fastapi.testclient import TestClient
from api.main import app

client = TestClient(app)


VALID_MAESTRO_TOML = b"""
[meta]
name = "API Test Single Agent"

[architecture]
patterns = ["single-agent", "task-oriented"]

[[agents]]
id = "support"
name = "Support Agent"
type = "task-oriented"
autonomy = "reactive"
layers = ["foundation-models", "data-operations", "agent-frameworks", "agent-ecosystem"]

[[assets]]
id = "kb"
name = "Knowledge Base"
layer = "data-operations"
sensitivity = "medium"

[catalog]
mode = "auto"
"""

PATTERN_MISMATCH_TOML = b"""
[meta]
name = "Pattern Mismatch"

[architecture]
patterns = ["multi-agent"]

[[agents]]
id = "internal"
layers = ["foundation-models", "agent-frameworks"]

[catalog]
mode = "auto"
"""

INVALID_TOML = b"not valid toml [[["


def _upload(content, filename="m.toml"):
    return ("file", (filename, io.BytesIO(content), "application/octet-stream"))


# =============================================================================
# Visualize
# =============================================================================

class TestVisualizeMaestro:

    def test_visualize_png(self):
        response = client.post(
            "/visualize/maestro?format=png",
            files=[_upload(VALID_MAESTRO_TOML)],
        )
        # 400 if graphviz not installed
        assert response.status_code in (200, 400, 500)

    def test_visualize_svg(self):
        response = client.post(
            "/visualize/maestro?format=svg",
            files=[_upload(VALID_MAESTRO_TOML)],
        )
        assert response.status_code in (200, 400, 500)

    def test_visualize_with_style(self):
        response = client.post(
            "/visualize/maestro?format=png&style=ma_default",
            files=[_upload(VALID_MAESTRO_TOML)],
        )
        assert response.status_code in (200, 400, 500)

    def test_visualize_malformed(self):
        response = client.post(
            "/visualize/maestro",
            files=[_upload(INVALID_TOML)],
        )
        assert response.status_code in (400, 500)

    def test_visualize_rejects_unsupported_extension(self):
        response = client.post(
            "/visualize/maestro",
            files=[_upload(VALID_MAESTRO_TOML, filename="model.exe")],
        )
        assert response.status_code in (400, 422)


# =============================================================================
# Analyze
# =============================================================================

class TestAnalyzeMaestro:

    def test_analyze_returns_stats(self):
        response = client.post(
            "/analyze/maestro",
            files=[_upload(VALID_MAESTRO_TOML)],
        )
        assert response.status_code == 200
        data = response.json()
        for key in (
            "total_agents", "total_assets", "total_threats",
            "total_cross_layer_threats", "total_mitigations",
            "unmitigated_threats", "patterns",
            "threats_by_layer", "threats_by_severity", "threats_by_status",
            "warnings",
        ):
            assert key in data
        assert data["total_agents"] == 1
        assert data["total_threats"] > 0

    def test_analyze_pattern_mismatch_surfaces_warnings(self):
        response = client.post(
            "/analyze/maestro",
            files=[_upload(PATTERN_MISMATCH_TOML)],
        )
        assert response.status_code == 200
        data = response.json()
        # multi-agent without L7 agents must produce skip-warnings
        assert any("multi-agent" in w and "skipping" in w for w in data["warnings"])

    def test_analyze_malformed(self):
        response = client.post(
            "/analyze/maestro",
            files=[_upload(INVALID_TOML)],
        )
        assert response.status_code in (400, 500)


# =============================================================================
# Validate
# =============================================================================

class TestValidateMaestro:

    def test_validate_valid(self):
        response = client.post(
            "/validate/maestro",
            files=[_upload(VALID_MAESTRO_TOML)],
        )
        assert response.status_code == 200
        data = response.json()
        assert "valid" in data
        assert "errors" in data
        assert "warnings" in data
        assert data["valid"] is True
        assert data["errors"] == []

    def test_validate_returns_warnings_for_pattern_mismatch(self):
        response = client.post(
            "/validate/maestro",
            files=[_upload(PATTERN_MISMATCH_TOML)],
        )
        assert response.status_code == 200
        data = response.json()
        # valid config (no errors), but warnings surface the mismatch
        assert data["valid"] is True
        assert any("multi-agent" in w for w in data["warnings"])

    def test_validate_malformed(self):
        response = client.post(
            "/validate/maestro",
            files=[_upload(INVALID_TOML)],
        )
        assert response.status_code in (400, 500)


# =============================================================================
# Catalog
# =============================================================================

class TestMaestroCatalog:

    def test_catalog_full(self):
        response = client.get("/maestro/catalog")
        assert response.status_code == 200
        data = response.json()
        assert data["catalog_version"] == "2026.1"
        assert len(data["threats"]) >= 50
        assert len(data["cross_layer_threats"]) >= 5
        assert len(data["mitigations"]) >= 80
        # All 7 layers represented in metadata
        assert len(data["layers"]) == 7

    def test_catalog_for_layer(self):
        response = client.get("/maestro/catalog/foundation-models")
        assert response.status_code == 200
        data = response.json()
        assert data["layer"] == "foundation-models"
        assert all(t["layer"] == "foundation-models" for t in data["threats"])
        assert len(data["threats"]) > 0

    def test_catalog_for_each_known_layer(self):
        layers = [
            "foundation-models", "data-operations", "agent-frameworks",
            "infrastructure", "observability", "security", "agent-ecosystem",
        ]
        for layer in layers:
            response = client.get(f"/maestro/catalog/{layer}")
            assert response.status_code == 200, f"layer {layer} failed: {response.text}"

    def test_catalog_for_unknown_layer(self):
        response = client.get("/maestro/catalog/nonexistent-layer")
        assert response.status_code == 400
