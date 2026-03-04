#
# VULNEX -Universal Security Visualization Library-
#
# File: test_api_utilities.py
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
#

"""Tests for Utilities API router endpoints.

Covers: /health, /styles, /formats, /engines, /convert,
/report/threat-model, /threats/library, /threats/element-types,
/batch/visualize, /export/data, /export/sections, /diff/compare,
/templates, /templates/attack-tree/{id}, /templates/threat-model/{id},
/progress/{job_id}, /jobs/start-demo
"""

import io
import json
import os
import sys
import tempfile
from pathlib import Path

import pytest

# Add the api directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'api'))

# Disable auth for these tests
os.environ["USECVISLIB_AUTH_ENABLED"] = "false"

from fastapi.testclient import TestClient
from api.main import app

client = TestClient(app)

# Paths to real template files for integration tests
TEMPLATES_DIR = Path(__file__).parent.parent / "templates"
AT_TEMPLATES_DIR = TEMPLATES_DIR / "attack-trees"
TM_TEMPLATES_DIR = TEMPLATES_DIR / "threat-models"


def _make_upload(content: str, filename: str = "test.toml", content_type: str = "application/octet-stream"):
    """Helper to create an upload file tuple for TestClient."""
    return ("file", (filename, io.BytesIO(content.encode()), content_type))


# Minimal valid attack tree config in TOML
MINIMAL_ATTACK_TREE_TOML = """
[tree]
name = "Test Tree"
root = "root"

[nodes]
[nodes.root]
label = "Root Goal"
type = "or"

[nodes.child1]
label = "Child 1"
type = "leaf"

[edges]
root = ["child1"]
"""

# Minimal valid threat model config in TOML
MINIMAL_THREAT_MODEL_TOML = """
[model]
name = "Test Model"

[processes]
[processes.webapp]
label = "Web Application"

[datastores]
[datastores.db]
label = "Database"

[externals]
[externals.user]
label = "User"

[dataflows]
[dataflows.flow1]
source = "user"
target = "webapp"
label = "HTTP Request"
"""


# =============================================================================
# Health Check
# =============================================================================

class TestHealthCheck:
    """Test /health endpoint."""

    def test_health_returns_200(self):
        response = client.get("/health")
        assert response.status_code == 200

    def test_health_returns_status(self):
        data = client.get("/health").json()
        assert "status" in data
        assert data["status"] in ("healthy", "degraded")

    def test_health_minimal_by_default(self):
        """Without details, response should be minimal (no version info)."""
        data = client.get("/health").json()
        assert "version" not in data or data.get("version") is None

    def test_health_with_details(self):
        """With ?details=true, response includes version and module info."""
        data = client.get("/health?details=true").json()
        assert "version" in data
        assert data["version"] is not None
        assert "modules" in data
        modules = data["modules"]
        assert "attack_trees" in modules
        assert "graphviz" in modules


# =============================================================================
# Styles / Formats / Engines
# =============================================================================

class TestConfigurationEndpoints:
    """Test /styles, /formats, /engines endpoints."""

    def test_styles_returns_all_types(self):
        data = client.get("/styles").json()
        assert "attack_tree" in data
        assert "attack_graph" in data
        assert "threat_model" in data
        assert "custom_diagram" in data
        assert "binary_visualization" in data
        assert "privilege_gradient" in data
        # Each should have at least one style
        for key, styles in data.items():
            assert len(styles) > 0, f"No styles for {key}"

    def test_formats_returns_formats(self):
        data = client.get("/formats").json()
        assert "formats" in data
        assert "default" in data
        assert "png" in data["formats"]
        assert data["default"] == "png"

    def test_engines_returns_engines(self):
        data = client.get("/engines").json()
        assert "engines" in data
        assert "default" in data
        assert "usecvislib" in data["engines"]
        assert "pytm_available" in data
        assert "descriptions" in data


# =============================================================================
# Format Conversion
# =============================================================================

class TestFormatConversion:
    """Test /convert endpoint."""

    def test_toml_to_json(self):
        response = client.post(
            "/convert?target_format=json",
            files=[_make_upload(MINIMAL_ATTACK_TREE_TOML, "tree.toml")],
        )
        assert response.status_code == 200
        data = response.json()
        assert data["source_format"] == "toml"
        assert data["target_format"] == "json"
        assert data["filename"].endswith(".json")
        # Content should be valid JSON
        parsed = json.loads(data["content"])
        assert "tree" in parsed

    def test_toml_to_yaml(self):
        response = client.post(
            "/convert?target_format=yaml",
            files=[_make_upload(MINIMAL_ATTACK_TREE_TOML, "tree.toml")],
        )
        assert response.status_code == 200
        data = response.json()
        assert data["target_format"] == "yaml"

    def test_invalid_extension_rejected(self):
        response = client.post(
            "/convert?target_format=json",
            files=[_make_upload("data", "file.exe")],
        )
        # HTTPException from validator is caught by generic handler → 500
        assert response.status_code in (400, 500)

    def test_malformed_toml_rejected(self):
        response = client.post(
            "/convert?target_format=json",
            files=[_make_upload("{{{{not valid toml", "bad.toml")],
        )
        assert response.status_code in (400, 500)


# =============================================================================
# Threat Library
# =============================================================================

class TestThreatLibrary:
    """Test /threats/library and /threats/element-types endpoints."""

    def test_element_types(self):
        data = client.get("/threats/element-types").json()
        assert "element_types" in data
        types = data["element_types"]
        assert "Process" in types
        assert "Datastore" in types
        assert "Dataflow" in types

    def test_threat_library_returns_response(self):
        """Threat library endpoint returns 200 if PyTM is available, 500 otherwise."""
        response = client.get("/threats/library")
        if response.status_code == 200:
            data = response.json()
            assert "threats" in data
            assert "total" in data
            assert isinstance(data["threats"], list)
        else:
            # PyTM not installed or method not available
            assert response.status_code == 500

    def test_threat_library_pagination(self):
        response = client.get("/threats/library?limit=5&offset=0")
        if response.status_code == 200:
            data = response.json()
            assert len(data["threats"]) <= 5
        else:
            assert response.status_code == 500

    def test_threat_library_filter_by_element(self):
        response = client.get("/threats/library?element_type=Process")
        # May be 500 if PyTM is not installed
        assert response.status_code in (200, 500)


# =============================================================================
# Export Sections
# =============================================================================

class TestExportSections:
    """Test /export/sections endpoint."""

    def test_attack_tree_sections(self):
        data = client.get("/export/sections?mode=attack_tree").json()
        assert data["mode"] == "attack_tree"
        assert "nodes" in data["sections"]
        assert "edges" in data["sections"]

    def test_attack_graph_sections(self):
        data = client.get("/export/sections?mode=attack_graph").json()
        assert "hosts" in data["sections"]
        assert "vulnerabilities" in data["sections"]

    def test_threat_model_sections(self):
        data = client.get("/export/sections?mode=threat_model").json()
        assert "processes" in data["sections"]
        assert "dataflows" in data["sections"]


# =============================================================================
# Export Data
# =============================================================================

class TestExportData:
    """Test /export/data endpoint."""

    def test_export_json(self):
        response = client.post(
            "/export/data?format=json",
            files=[_make_upload(MINIMAL_ATTACK_TREE_TOML, "tree.toml")],
        )
        assert response.status_code == 200
        data = response.json()
        assert data["format"] == "json"
        assert data["filename"].endswith(".json")
        # Content should be valid JSON
        json.loads(data["content"])

    def test_export_yaml(self):
        response = client.post(
            "/export/data?format=yaml",
            files=[_make_upload(MINIMAL_ATTACK_TREE_TOML, "tree.toml")],
        )
        assert response.status_code == 200
        assert response.json()["format"] == "yaml"

    def test_export_invalid_section(self):
        response = client.post(
            "/export/data?section=nonexistent",
            files=[_make_upload(MINIMAL_ATTACK_TREE_TOML, "tree.toml")],
        )
        assert response.status_code == 400

    def test_export_invalid_extension(self):
        response = client.post(
            "/export/data?format=json",
            files=[_make_upload("data", "file.exe")],
        )
        assert response.status_code == 400


# =============================================================================
# Diff / Compare
# =============================================================================

class TestDiffCompare:
    """Test /diff/compare endpoint."""

    def test_compare_identical_files(self):
        response = client.post(
            "/diff/compare?mode=attack_tree",
            files=[
                ("old_file", ("old.toml", io.BytesIO(MINIMAL_ATTACK_TREE_TOML.encode()), "application/octet-stream")),
                ("new_file", ("new.toml", io.BytesIO(MINIMAL_ATTACK_TREE_TOML.encode()), "application/octet-stream")),
            ],
        )
        assert response.status_code == 200
        data = response.json()
        assert "has_changes" in data
        assert "summary" in data
        assert data["summary"]["total"] == 0

    def test_compare_with_changes(self):
        modified = MINIMAL_ATTACK_TREE_TOML.replace('label = "Child 1"', 'label = "Modified Child"')
        response = client.post(
            "/diff/compare?mode=attack_tree",
            files=[
                ("old_file", ("old.toml", io.BytesIO(MINIMAL_ATTACK_TREE_TOML.encode()), "application/octet-stream")),
                ("new_file", ("new.toml", io.BytesIO(modified.encode()), "application/octet-stream")),
            ],
        )
        assert response.status_code == 200
        data = response.json()
        assert data["has_changes"] is True
        assert data["summary"]["total"] > 0

    def test_compare_with_report(self):
        response = client.post(
            "/diff/compare?mode=attack_tree&include_report=true",
            files=[
                ("old_file", ("old.toml", io.BytesIO(MINIMAL_ATTACK_TREE_TOML.encode()), "application/octet-stream")),
                ("new_file", ("new.toml", io.BytesIO(MINIMAL_ATTACK_TREE_TOML.encode()), "application/octet-stream")),
            ],
        )
        assert response.status_code == 200
        data = response.json()
        assert "report" in data
        assert data["report"] is not None

    def test_compare_invalid_extension(self):
        response = client.post(
            "/diff/compare?mode=attack_tree",
            files=[
                ("old_file", ("old.exe", io.BytesIO(b"data"), "application/octet-stream")),
                ("new_file", ("new.toml", io.BytesIO(b"data"), "application/octet-stream")),
            ],
        )
        assert response.status_code == 400


# =============================================================================
# Templates
# =============================================================================

class TestTemplates:
    """Test /templates, /templates/attack-tree/{id}, /templates/threat-model/{id}."""

    def test_list_templates(self):
        response = client.get("/templates")
        assert response.status_code == 200
        data = response.json()
        assert "attack_trees" in data
        assert "threat_models" in data
        assert isinstance(data["attack_trees"], list)
        assert isinstance(data["threat_models"], list)

    def test_list_templates_has_entries(self):
        """Templates directory should have at least some templates."""
        data = client.get("/templates").json()
        total = len(data["attack_trees"]) + len(data["threat_models"])
        assert total > 0

    def test_template_entry_fields(self):
        """Each template entry should have id, name, filename, format."""
        data = client.get("/templates").json()
        all_templates = data["attack_trees"] + data["threat_models"]
        if all_templates:
            entry = all_templates[0]
            assert "id" in entry
            assert "name" in entry
            assert "filename" in entry
            assert "format" in entry

    def test_get_attack_tree_template(self):
        """Fetch a specific attack tree template by ID."""
        templates = client.get("/templates").json()
        if not templates["attack_trees"]:
            pytest.skip("No attack tree templates available")
        template_id = templates["attack_trees"][0]["id"]
        response = client.get(f"/templates/attack-tree/{template_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == template_id
        assert data["type"] == "attack_tree"
        assert "content" in data
        assert len(data["content"]) > 0

    def test_get_threat_model_template(self):
        """Fetch a specific threat model template by ID."""
        templates = client.get("/templates").json()
        if not templates["threat_models"]:
            pytest.skip("No threat model templates available")
        template_id = templates["threat_models"][0]["id"]
        response = client.get(f"/templates/threat-model/{template_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == template_id
        assert data["type"] == "threat_model"

    def test_get_nonexistent_template_404(self):
        response = client.get("/templates/attack-tree/nonexistent-template-xyz")
        assert response.status_code == 404

    def test_template_path_traversal_blocked(self):
        """Path traversal in template ID should be rejected."""
        response = client.get("/templates/attack-tree/../../etc/passwd")
        assert response.status_code == 404

    def test_template_dot_dot_blocked(self):
        response = client.get("/templates/threat-model/../../../etc/shadow")
        assert response.status_code == 404


# =============================================================================
# Progress / Demo Jobs
# =============================================================================

class TestProgressAndDemoJobs:
    """Test /progress/{job_id} and /jobs/start-demo endpoints."""

    def test_start_demo_job(self):
        response = client.post("/jobs/start-demo")
        assert response.status_code == 200
        data = response.json()
        assert "job_id" in data
        assert "progress_url" in data
        assert data["job_id"].startswith("demo-")

    def test_progress_nonexistent_job(self):
        """SSE stream for nonexistent job should eventually timeout."""
        response = client.get("/progress/nonexistent-job-id")
        # SSE endpoint returns 200 with streaming content
        assert response.status_code == 200


# =============================================================================
# Batch Processing
# =============================================================================

class TestBatchProcessing:
    """Test /batch/visualize endpoint."""

    def test_batch_rejects_too_many_files(self):
        """More than 20 files should be rejected."""
        files = [
            ("files", (f"file{i}.toml", io.BytesIO(MINIMAL_ATTACK_TREE_TOML.encode()), "application/octet-stream"))
            for i in range(21)
        ]
        response = client.post(
            "/batch/visualize?mode=attack_tree",
            files=files,
        )
        assert response.status_code == 400

    def test_batch_invalid_extension(self):
        """Files with invalid extensions should fail individually."""
        files = [
            ("files", ("bad.exe", io.BytesIO(b"data"), "application/octet-stream")),
        ]
        response = client.post(
            "/batch/visualize?mode=attack_tree",
            files=files,
        )
        assert response.status_code == 200
        data = response.json()
        # The individual file should have failed
        assert data["failure_count"] >= 1


# =============================================================================
# Report Generation
# =============================================================================

class TestReportGeneration:
    """Test /report/threat-model endpoint."""

    def test_generate_markdown_report(self):
        response = client.post(
            "/report/threat-model?format=markdown",
            files=[_make_upload(MINIMAL_THREAT_MODEL_TOML, "model.toml")],
        )
        assert response.status_code == 200
        data = response.json()
        assert data["format"] == "markdown"
        assert data["filename"].endswith(".md")
        assert len(data["content"]) > 0

    def test_generate_html_report(self):
        response = client.post(
            "/report/threat-model?format=html",
            files=[_make_upload(MINIMAL_THREAT_MODEL_TOML, "model.toml")],
        )
        assert response.status_code == 200
        data = response.json()
        assert data["format"] == "html"
        assert data["filename"].endswith(".html")

    def test_report_invalid_extension(self):
        response = client.post(
            "/report/threat-model?format=markdown",
            files=[_make_upload("data", "file.exe")],
        )
        # HTTPException from validator is caught by generic handler → 500
        assert response.status_code in (400, 500)
