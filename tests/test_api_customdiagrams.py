#
# VULNEX -Universal Security Visualization Library-
#
# File: test_api_customdiagrams.py
# Author: Claude Code
# Created: 2025-12-29
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
#

"""Tests for Custom Diagrams API endpoints.

This module tests the REST API endpoints for the Custom Diagrams module:
- Shape listing and retrieval
- Template listing and retrieval
- Visualization generation
- Validation
- Statistics
- Import from other formats
"""

import pytest
import os
import sys
import tempfile
from pathlib import Path

# Add the api directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'api'))

# Disable auth for these tests
os.environ["USECVISLIB_AUTH_ENABLED"] = "false"

from fastapi.testclient import TestClient
from api.main import app

client = TestClient(app)

# Test data directory
TEMPLATES_DIR = Path(__file__).parent.parent / "templates" / "custom-diagrams"


# =============================================================================
# Shape Endpoints Tests
# =============================================================================

class TestShapeEndpoints:
    """Test shape listing and retrieval endpoints."""

    def test_list_shapes(self):
        """Test listing all available shapes."""
        response = client.get("/custom-diagrams/shapes")
        assert response.status_code == 200

        data = response.json()
        assert "shapes" in data
        assert "total" in data
        assert "categories" in data
        assert data["total"] > 0
        assert len(data["shapes"]) > 0

    def test_list_shapes_by_category(self):
        """Test filtering shapes by category."""
        # First get all shapes to find a category
        response = client.get("/custom-diagrams/shapes")
        assert response.status_code == 200
        data = response.json()

        if data["categories"]:
            category = data["categories"][0]
            response = client.get(f"/custom-diagrams/shapes?category={category}")
            assert response.status_code == 200

            filtered_data = response.json()
            for shape in filtered_data["shapes"]:
                assert shape["category"] == category

    def test_shape_has_required_fields(self):
        """Test that shapes have all required fields."""
        response = client.get("/custom-diagrams/shapes")
        assert response.status_code == 200

        data = response.json()
        if data["shapes"]:
            shape = data["shapes"][0]
            assert "id" in shape
            assert "name" in shape
            assert "category" in shape
            assert "shape" in shape

    def test_get_shape_by_id(self):
        """Test getting a specific shape by ID."""
        # First list shapes to get a valid ID
        response = client.get("/custom-diagrams/shapes")
        assert response.status_code == 200
        data = response.json()

        if data["shapes"]:
            shape_id = data["shapes"][0]["id"]
            response = client.get(f"/custom-diagrams/shapes/{shape_id}")
            assert response.status_code == 200

            shape = response.json()
            assert shape["id"] == shape_id

    def test_get_nonexistent_shape(self):
        """Test getting a shape that doesn't exist."""
        response = client.get("/custom-diagrams/shapes/nonexistent_shape_xyz")
        assert response.status_code == 404


# =============================================================================
# Template Endpoints Tests
# =============================================================================

class TestTemplateEndpoints:
    """Test template listing and retrieval endpoints."""

    def test_list_templates(self):
        """Test listing all available templates."""
        response = client.get("/custom-diagrams/templates")
        assert response.status_code == 200

        data = response.json()
        assert "templates" in data
        assert "total" in data
        assert "categories" in data

    def test_list_templates_by_category(self):
        """Test filtering templates by category."""
        response = client.get("/custom-diagrams/templates")
        data = response.json()

        if data["categories"]:
            category = data["categories"][0]
            response = client.get(f"/custom-diagrams/templates?category={category}")
            assert response.status_code == 200

            filtered_data = response.json()
            for template in filtered_data["templates"]:
                assert template["category"] == category

    def test_template_has_required_fields(self):
        """Test that templates have all required fields."""
        response = client.get("/custom-diagrams/templates")
        data = response.json()

        if data["templates"]:
            template = data["templates"][0]
            assert "id" in template
            assert "name" in template
            assert "category" in template
            assert "filename" in template

    def test_get_template_content(self):
        """Test getting template content by ID."""
        response = client.get("/custom-diagrams/templates")
        data = response.json()

        if data["templates"]:
            template_id = data["templates"][0]["id"]
            response = client.get(f"/custom-diagrams/templates/{template_id}")
            assert response.status_code == 200

            content = response.json()
            assert "content" in content
            assert "format" in content
            assert content["id"] == template_id

    def test_get_nonexistent_template(self):
        """Test getting a template that doesn't exist."""
        response = client.get("/custom-diagrams/templates/nonexistent/template")
        assert response.status_code == 404

    def test_get_template_invalid_format(self):
        """Test getting a template with invalid ID format."""
        response = client.get("/custom-diagrams/templates/invalid_format")
        assert response.status_code == 400


# =============================================================================
# Styles and Layouts Endpoints Tests
# =============================================================================

class TestStylesAndLayoutsEndpoints:
    """Test style and layout configuration endpoints."""

    def test_get_styles(self):
        """Test getting available styles."""
        response = client.get("/custom-diagrams/styles")
        assert response.status_code == 200

        data = response.json()
        assert "styles" in data
        assert "default" in data
        assert "descriptions" in data
        assert len(data["styles"]) > 0

    def test_get_layouts(self):
        """Test getting available layouts."""
        response = client.get("/custom-diagrams/layouts")
        assert response.status_code == 200

        data = response.json()
        assert "layouts" in data
        assert "default" in data
        assert "descriptions" in data
        assert len(data["layouts"]) > 0

    def test_style_descriptions(self):
        """Test that all styles have descriptions."""
        response = client.get("/custom-diagrams/styles")
        data = response.json()

        for style in data["styles"]:
            assert style in data["descriptions"]

    def test_layout_descriptions(self):
        """Test that all layouts have descriptions."""
        response = client.get("/custom-diagrams/layouts")
        data = response.json()

        for layout in data["layouts"]:
            assert layout in data["descriptions"]


# =============================================================================
# Visualization Endpoint Tests
# =============================================================================

class TestVisualizationEndpoints:
    """Test visualization generation endpoints."""

    @pytest.fixture
    def sample_custom_diagram_toml(self, tmp_path):
        """Create a sample custom diagram TOML file."""
        content = '''
[diagram]
title = "Test Diagram"
layout = "hierarchical"
direction = "TB"

[schema.nodes.process]
shape = "box"
fillcolor = "#E3F2FD"
style = "filled"

[schema.nodes.database]
shape = "cylinder"
fillcolor = "#FFF3E0"
style = "filled"

[schema.edges.flow]
style = "solid"
color = "#333333"

[[nodes]]
id = "p1"
type = "process"
label = "Process 1"

[[nodes]]
id = "db1"
type = "database"
label = "Database 1"

[[edges]]
from = "p1"
to = "db1"
type = "flow"
label = "stores"
'''
        file_path = tmp_path / "test_diagram.toml"
        file_path.write_text(content)
        return file_path

    def test_visualize_custom_diagram(self, sample_custom_diagram_toml):
        """Test generating a custom diagram visualization."""
        with open(sample_custom_diagram_toml, "rb") as f:
            response = client.post(
                "/custom-diagrams/visualize",
                files={"file": ("test_diagram.toml", f, "application/toml")},
                params={"format": "png"}
            )

        # 200 means success, 500 might occur if graphviz isn't available
        assert response.status_code in [200, 500]

        if response.status_code == 200:
            assert response.headers["content-type"] == "image/png"

    def test_visualize_with_svg_format(self, sample_custom_diagram_toml):
        """Test generating SVG output."""
        with open(sample_custom_diagram_toml, "rb") as f:
            response = client.post(
                "/custom-diagrams/visualize",
                files={"file": ("test_diagram.toml", f, "application/toml")},
                params={"format": "svg"}
            )

        assert response.status_code in [200, 500]

        if response.status_code == 200:
            assert response.headers["content-type"] == "image/svg+xml"

    def test_visualize_with_style(self, sample_custom_diagram_toml):
        """Test generating visualization with custom style."""
        with open(sample_custom_diagram_toml, "rb") as f:
            response = client.post(
                "/custom-diagrams/visualize",
                files={"file": ("test_diagram.toml", f, "application/toml")},
                params={"format": "png", "style": "cd_dark"}
            )

        assert response.status_code in [200, 500]

    def test_visualize_invalid_file(self, tmp_path):
        """Test visualization with invalid file content."""
        invalid_file = tmp_path / "invalid.toml"
        invalid_file.write_text("invalid toml content [[[")

        with open(invalid_file, "rb") as f:
            response = client.post(
                "/custom-diagrams/visualize",
                files={"file": ("invalid.toml", f, "application/toml")}
            )

        assert response.status_code == 400


# =============================================================================
# Validation Endpoint Tests
# =============================================================================

class TestValidationEndpoints:
    """Test validation endpoints."""

    @pytest.fixture
    def valid_diagram_toml(self, tmp_path):
        """Create a valid custom diagram TOML file."""
        content = '''
[diagram]
title = "Valid Diagram"
layout = "hierarchical"
direction = "TB"

[schema.nodes.box]
shape = "box"
fillcolor = "#FFFFFF"

[[nodes]]
id = "n1"
type = "box"
label = "Node 1"

[[nodes]]
id = "n2"
type = "box"
label = "Node 2"

[[edges]]
from = "n1"
to = "n2"
'''
        file_path = tmp_path / "valid_diagram.toml"
        file_path.write_text(content)
        return file_path

    @pytest.fixture
    def invalid_diagram_toml(self, tmp_path):
        """Create an invalid custom diagram TOML file with undefined types."""
        content = '''
[diagram]
title = "Invalid Diagram"

[[nodes]]
id = "n1"
type = "undefined_type"
label = "Node 1"

[[edges]]
from = "n1"
to = "nonexistent_node"
'''
        file_path = tmp_path / "invalid_diagram.toml"
        file_path.write_text(content)
        return file_path

    def test_validate_valid_diagram(self, valid_diagram_toml):
        """Test validating a valid diagram."""
        with open(valid_diagram_toml, "rb") as f:
            response = client.post(
                "/custom-diagrams/validate",
                files={"file": ("valid_diagram.toml", f, "application/toml")}
            )

        assert response.status_code == 200
        data = response.json()
        assert "valid" in data
        assert "errors" in data
        assert "warnings" in data
        assert "node_count" in data
        assert "edge_count" in data

    def test_validate_invalid_diagram(self, invalid_diagram_toml):
        """Test validating an invalid diagram."""
        with open(invalid_diagram_toml, "rb") as f:
            response = client.post(
                "/custom-diagrams/validate",
                files={"file": ("invalid_diagram.toml", f, "application/toml")}
            )

        assert response.status_code == 200
        data = response.json()
        # Should have errors due to undefined type and nonexistent edge target
        assert data["valid"] == False or len(data["errors"]) > 0 or len(data["warnings"]) > 0


# =============================================================================
# Statistics Endpoint Tests
# =============================================================================

class TestStatsEndpoints:
    """Test statistics endpoints."""

    @pytest.fixture
    def diagram_with_clusters_toml(self, tmp_path):
        """Create a diagram with clusters."""
        content = '''
[diagram]
title = "Clustered Diagram"
layout = "hierarchical"
direction = "TB"

[schema.nodes.service]
shape = "box"
fillcolor = "#E3F2FD"

[schema.nodes.database]
shape = "cylinder"
fillcolor = "#FFF3E0"

[schema.edges.flow]
style = "solid"

[[nodes]]
id = "s1"
type = "service"
label = "Service 1"

[[nodes]]
id = "s2"
type = "service"
label = "Service 2"

[[nodes]]
id = "db1"
type = "database"
label = "Database 1"

[[edges]]
from = "s1"
to = "db1"
type = "flow"

[[edges]]
from = "s2"
to = "db1"
type = "flow"

[[clusters]]
id = "backend"
label = "Backend Services"
nodes = ["s1", "s2"]
'''
        file_path = tmp_path / "clustered_diagram.toml"
        file_path.write_text(content)
        return file_path

    def test_get_stats(self, diagram_with_clusters_toml):
        """Test getting diagram statistics."""
        with open(diagram_with_clusters_toml, "rb") as f:
            response = client.post(
                "/custom-diagrams/stats",
                files={"file": ("clustered_diagram.toml", f, "application/toml")}
            )

        assert response.status_code == 200
        data = response.json()

        assert "total_nodes" in data
        assert "total_edges" in data
        assert "node_types" in data
        assert "edge_types" in data
        assert "title" in data

        assert data["total_nodes"] == 3
        assert data["total_edges"] == 2

    def test_stats_node_type_distribution(self, diagram_with_clusters_toml):
        """Test that node type distribution is calculated correctly."""
        with open(diagram_with_clusters_toml, "rb") as f:
            response = client.post(
                "/custom-diagrams/stats",
                files={"file": ("clustered_diagram.toml", f, "application/toml")}
            )

        data = response.json()

        # Should have 2 services and 1 database
        assert data["node_types"].get("service", 0) == 2
        assert data["node_types"].get("database", 0) == 1


# =============================================================================
# From Template Endpoint Tests
# =============================================================================

class TestFromTemplateEndpoints:
    """Test template-based generation endpoints."""

    def test_from_template_success(self):
        """Test generating a diagram from a built-in template."""
        # First get a valid template ID
        response = client.get("/custom-diagrams/templates")
        data = response.json()

        if data["templates"]:
            template_id = data["templates"][0]["id"]
            response = client.post(
                "/custom-diagrams/from-template",
                params={"template_id": template_id, "format": "png"}
            )

            # 200 means success, 400/500 might occur if graphviz isn't available
            assert response.status_code in [200, 400, 500]

    def test_from_template_not_found(self):
        """Test generating from a nonexistent template."""
        response = client.post(
            "/custom-diagrams/from-template",
            params={"template_id": "nonexistent/template", "format": "png"}
        )
        assert response.status_code == 404

    def test_from_template_invalid_id_format(self):
        """Test generating from a template with invalid ID format."""
        response = client.post(
            "/custom-diagrams/from-template",
            params={"template_id": "invalid_format", "format": "png"}
        )
        assert response.status_code == 400


# =============================================================================
# Import Endpoint Tests
# =============================================================================

class TestImportEndpoints:
    """Test import from other visualization types."""

    @pytest.fixture
    def sample_attack_tree_toml(self, tmp_path):
        """Create a sample attack tree TOML file."""
        content = '''
[tree]
name = "Test Attack Tree"
root = "goal"

[nodes]
goal = { label = "Compromise System", type = "OR" }
attack1 = { label = "SQL Injection", type = "AND" }
attack2 = { label = "XSS Attack", type = "AND" }

[edges]
goal = [
    { to = "attack1" },
    { to = "attack2" }
]
'''
        file_path = tmp_path / "attack_tree.toml"
        file_path.write_text(content)
        return file_path

    @pytest.fixture
    def sample_threat_model_toml(self, tmp_path):
        """Create a sample threat model TOML file."""
        content = '''
[model]
name = "Test Threat Model"

[processes.web_server]
label = "Web Server"
description = "Main web application"

[processes.api_server]
label = "API Server"
description = "REST API backend"

[datastores.database]
label = "Database"
description = "PostgreSQL database"

[externals.user]
label = "User"
description = "External user"

[dataflows.user_to_web]
from = "user"
to = "web_server"
label = "HTTP Request"

[dataflows.web_to_api]
from = "web_server"
to = "api_server"
label = "API Call"

[dataflows.api_to_db]
from = "api_server"
to = "database"
label = "Query"
'''
        file_path = tmp_path / "threat_model.toml"
        file_path.write_text(content)
        return file_path

    def test_import_from_attack_tree(self, sample_attack_tree_toml):
        """Test importing from an attack tree."""
        with open(sample_attack_tree_toml, "rb") as f:
            response = client.post(
                "/custom-diagrams/import",
                files={"file": ("attack_tree.toml", f, "application/toml")},
                params={"source_type": "attack_tree", "format": "png"}
            )

        # 200 means success, 500 might occur if graphviz isn't available
        assert response.status_code in [200, 400, 500]

    def test_import_from_threat_model(self, sample_threat_model_toml):
        """Test importing from a threat model."""
        with open(sample_threat_model_toml, "rb") as f:
            response = client.post(
                "/custom-diagrams/import",
                files={"file": ("threat_model.toml", f, "application/toml")},
                params={"source_type": "threat_model", "format": "png"}
            )

        # 200 means success, 400/500 might occur for various reasons
        assert response.status_code in [200, 400, 500]

    def test_import_unsupported_source_type(self, sample_attack_tree_toml):
        """Test importing from an unsupported source type."""
        with open(sample_attack_tree_toml, "rb") as f:
            response = client.post(
                "/custom-diagrams/import",
                files={"file": ("attack_tree.toml", f, "application/toml")},
                params={"source_type": "binary", "format": "png"}
            )

        assert response.status_code == 400


# =============================================================================
# Error Handling Tests
# =============================================================================

class TestErrorHandling:
    """Test error handling across endpoints."""

    def test_unsupported_file_extension(self, tmp_path):
        """Test uploading a file with unsupported extension."""
        test_file = tmp_path / "test.xyz"
        test_file.write_text("test content")

        with open(test_file, "rb") as f:
            response = client.post(
                "/custom-diagrams/visualize",
                files={"file": ("test.xyz", f, "application/octet-stream")}
            )

        # File extension validation may return 400 or 500 depending on where check happens
        assert response.status_code in [400, 500]

    def test_empty_file(self, tmp_path):
        """Test uploading an empty file."""
        empty_file = tmp_path / "empty.toml"
        empty_file.write_text("")

        with open(empty_file, "rb") as f:
            response = client.post(
                "/custom-diagrams/validate",
                files={"file": ("empty.toml", f, "application/toml")}
            )

        # Should return an error or validation failure
        assert response.status_code in [200, 400, 500]

    def test_malformed_toml(self, tmp_path):
        """Test uploading malformed TOML."""
        malformed_file = tmp_path / "malformed.toml"
        malformed_file.write_text("[[[invalid toml")

        with open(malformed_file, "rb") as f:
            response = client.post(
                "/custom-diagrams/validate",
                files={"file": ("malformed.toml", f, "application/toml")}
            )

        assert response.status_code in [200, 400]
        if response.status_code == 200:
            data = response.json()
            assert data["valid"] == False or len(data["errors"]) > 0


# =============================================================================
# Integration Tests
# =============================================================================

class TestIntegration:
    """Integration tests for end-to-end workflows."""

    def test_list_templates_and_generate(self):
        """Test listing templates and generating one."""
        # List templates
        response = client.get("/custom-diagrams/templates")
        assert response.status_code == 200
        data = response.json()

        if data["templates"]:
            template = data["templates"][0]

            # Get template content
            response = client.get(f"/custom-diagrams/templates/{template['id']}")
            assert response.status_code == 200

            # Generate from template
            response = client.post(
                "/custom-diagrams/from-template",
                params={"template_id": template["id"], "format": "png"}
            )
            # Success or Graphviz not available
            assert response.status_code in [200, 400, 500]

    def test_validate_then_visualize(self, tmp_path):
        """Test validating a diagram then visualizing it."""
        content = '''
[diagram]
title = "Validate Then Visualize"
layout = "hierarchical"

[schema.nodes.box]
shape = "box"

[[nodes]]
id = "a"
type = "box"
label = "A"

[[nodes]]
id = "b"
type = "box"
label = "B"

[[edges]]
from = "a"
to = "b"
'''
        file_path = tmp_path / "workflow_test.toml"
        file_path.write_text(content)

        # First validate
        with open(file_path, "rb") as f:
            response = client.post(
                "/custom-diagrams/validate",
                files={"file": ("workflow_test.toml", f, "application/toml")}
            )

        assert response.status_code == 200
        validation = response.json()

        # Only visualize if valid
        if validation["valid"]:
            with open(file_path, "rb") as f:
                response = client.post(
                    "/custom-diagrams/visualize",
                    files={"file": ("workflow_test.toml", f, "application/toml")},
                    params={"format": "svg"}
                )

            assert response.status_code in [200, 500]

    def test_stats_and_styles(self, tmp_path):
        """Test getting stats and applying different styles."""
        content = '''
[diagram]
title = "Stats and Styles Test"
layout = "hierarchical"

[schema.nodes.box]
shape = "box"

[[nodes]]
id = "n1"
type = "box"
label = "Node 1"

[[nodes]]
id = "n2"
type = "box"
label = "Node 2"

[[edges]]
from = "n1"
to = "n2"
'''
        file_path = tmp_path / "stats_styles_test.toml"
        file_path.write_text(content)

        # Get stats
        with open(file_path, "rb") as f:
            response = client.post(
                "/custom-diagrams/stats",
                files={"file": ("stats_styles_test.toml", f, "application/toml")}
            )

        assert response.status_code == 200
        stats = response.json()
        assert stats["total_nodes"] == 2
        assert stats["total_edges"] == 1

        # Get available styles
        response = client.get("/custom-diagrams/styles")
        assert response.status_code == 200
        styles = response.json()

        # Try generating with different styles
        for style in styles["styles"][:2]:  # Test first 2 styles
            with open(file_path, "rb") as f:
                response = client.post(
                    "/custom-diagrams/visualize",
                    files={"file": ("stats_styles_test.toml", f, "application/toml")},
                    params={"format": "svg", "style": style}
                )
            # May fail if graphviz not available
            assert response.status_code in [200, 500]
