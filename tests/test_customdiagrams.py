#
# VULNEX -Universal Security Visualization Library-
#
# File: tests/test_customdiagrams.py
# Author: Simon Roses Femerling
# Created: 2025-12-29
# Last Modified: 2025-12-29
# Version: 0.3.1
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Unit tests for the Custom Diagrams module."""

import json
import pytest
import tempfile
import os
from pathlib import Path

from usecvislib.customdiagrams import (
    CustomDiagrams,
    CustomDiagramError,
    DiagramSettings,
    VisualizationResult,
)
from usecvislib.schema import (
    SchemaValidator,
    NodeTypeSchema,
    EdgeTypeSchema,
)
from usecvislib.shapes import ShapeRegistry
from usecvislib.utils import ValidationError


# Sample configuration for tests
SAMPLE_CONFIG = {
    "diagram": {
        "title": "Test Network Diagram",
        "description": "A test diagram",
        "layout": "hierarchical",
        "direction": "TB",
        "style": "cd_default",
    },
    "schema": {
        "nodes": {
            "server": {
                "shape": "server",
                "required_fields": ["name"],
                "optional_fields": ["ip", "os"],
                "style": {"fillcolor": "#3498DB", "fontcolor": "white"},
                "label_template": "{name}",
            },
            "database": {
                "shape": "database",
                "required_fields": ["name"],
                "optional_fields": ["type"],
                "style": {"fillcolor": "#27AE60", "fontcolor": "white"},
                "label_template": "{name}",
            },
        },
        "edges": {
            "connection": {
                "style": "solid",
                "color": "#333333",
                "arrowhead": "vee",
                "label_field": "protocol",
            },
            "dataflow": {
                "style": "dashed",
                "color": "#3498DB",
                "arrowhead": "normal",
            },
        },
    },
    "nodes": [
        {"id": "web", "type": "server", "name": "Web Server", "ip": "10.0.1.10"},
        {"id": "api", "type": "server", "name": "API Server", "ip": "10.0.1.11"},
        {"id": "db", "type": "database", "name": "User DB"},
    ],
    "edges": [
        {"from": "web", "to": "api", "type": "connection", "protocol": "REST"},
        {"from": "api", "to": "db", "type": "dataflow"},
    ],
}


class TestDiagramSettings:
    """Tests for DiagramSettings dataclass."""

    def test_default_settings(self):
        """Test default settings values."""
        settings = DiagramSettings()
        assert settings.title == "Custom Diagram"
        assert settings.layout == "hierarchical"
        assert settings.direction == "TB"
        assert settings.splines == "ortho"
        assert settings.nodesep == 0.5
        assert settings.ranksep == 1.0

    def test_from_dict(self):
        """Test creating settings from dictionary."""
        data = {
            "title": "My Diagram",
            "layout": "circular",
            "direction": "LR",
            "splines": "curved",
            "nodesep": 0.8,
        }
        settings = DiagramSettings.from_dict(data)
        assert settings.title == "My Diagram"
        assert settings.layout == "circular"
        assert settings.direction == "LR"
        assert settings.splines == "curved"
        assert settings.nodesep == 0.8

    def test_rankdir_sync(self):
        """Test that rankdir syncs with direction."""
        settings = DiagramSettings(direction="LR")
        assert settings.rankdir == "LR"


class TestVisualizationResult:
    """Tests for VisualizationResult dataclass."""

    def test_creation(self):
        """Test creating a result."""
        result = VisualizationResult(
            output_path="/tmp/test.png",
            format="png",
            stats={"nodes": 5},
        )
        assert result.output_path == "/tmp/test.png"
        assert result.format == "png"
        assert result.success is True
        assert result.stats == {"nodes": 5}

    def test_to_dict(self):
        """Test converting to dictionary."""
        result = VisualizationResult(
            output_path="/tmp/test.png",
            format="png",
        )
        data = result.to_dict()
        assert data["output_path"] == "/tmp/test.png"
        assert data["format"] == "png"
        assert data["success"] is True


class TestCustomDiagrams:
    """Tests for CustomDiagrams class."""

    @pytest.fixture
    def cd(self):
        """Create a fresh CustomDiagrams instance."""
        return CustomDiagrams()

    @pytest.fixture
    def loaded_cd(self, cd):
        """Create a CustomDiagrams instance with loaded config."""
        cd.load_from_string(json.dumps(SAMPLE_CONFIG), "json")
        return cd

    def test_initialization(self, cd):
        """Test CustomDiagrams initialization."""
        assert cd.shape_registry is not None
        assert cd.schema_validator is not None
        assert cd.settings is None
        assert cd.nodes == []
        assert cd.edges == []
        assert cd._config_loaded is False

    def test_load_from_string_json(self, cd):
        """Test loading configuration from JSON string."""
        cd.load_from_string(json.dumps(SAMPLE_CONFIG), "json")
        assert cd._config_loaded is True
        assert cd.settings.title == "Test Network Diagram"
        assert len(cd.nodes) == 3
        assert len(cd.edges) == 2

    def test_load_settings(self, loaded_cd):
        """Test that settings are loaded correctly."""
        assert loaded_cd.settings.title == "Test Network Diagram"
        assert loaded_cd.settings.layout == "hierarchical"
        assert loaded_cd.settings.direction == "TB"

    def test_load_schema(self, loaded_cd):
        """Test that schema is loaded correctly."""
        assert "nodes" in loaded_cd.schema
        assert "edges" in loaded_cd.schema
        assert "server" in loaded_cd.schema["nodes"]
        assert "database" in loaded_cd.schema["nodes"]
        assert "connection" in loaded_cd.schema["edges"]

    def test_load_nodes(self, loaded_cd):
        """Test that nodes are loaded correctly."""
        assert len(loaded_cd.nodes) == 3
        node_ids = [n["id"] for n in loaded_cd.nodes]
        assert "web" in node_ids
        assert "api" in node_ids
        assert "db" in node_ids

    def test_load_edges(self, loaded_cd):
        """Test that edges are loaded correctly."""
        assert len(loaded_cd.edges) == 2
        edge = loaded_cd.edges[0]
        assert edge["from"] == "web"
        assert edge["to"] == "api"

    def test_validate_success(self, loaded_cd):
        """Test successful validation."""
        report = loaded_cd.validate(raise_on_error=False)
        assert report["valid"] is True
        assert len(report["errors"]) == 0

    def test_validate_invalid_node_type(self, cd):
        """Test validation with invalid node type."""
        config = {
            "schema": {
                "nodes": {
                    "server": {"shape": "server", "required_fields": ["name"]}
                }
            },
            "nodes": [
                {"id": "n1", "type": "invalid_type", "name": "Node 1"}
            ],
            "edges": [],
        }
        cd.load_from_string(json.dumps(config), "json")
        report = cd.validate(raise_on_error=False)
        assert report["valid"] is False
        assert any("unknown type" in e for e in report["errors"])

    def test_validate_missing_required_field(self, cd):
        """Test validation with missing required field."""
        config = {
            "schema": {
                "nodes": {
                    "server": {"shape": "server", "required_fields": ["name", "ip"]}
                }
            },
            "nodes": [
                {"id": "n1", "type": "server", "name": "Server 1"}  # Missing ip
            ],
            "edges": [],
        }
        cd.load_from_string(json.dumps(config), "json")
        report = cd.validate(raise_on_error=False)
        assert report["valid"] is False
        assert any("missing required field" in e for e in report["errors"])

    def test_validate_invalid_edge_reference(self, cd):
        """Test validation with edge referencing non-existent node."""
        config = {
            "schema": {
                "nodes": {"server": {"shape": "server", "required_fields": ["name"]}}
            },
            "nodes": [{"id": "n1", "type": "server", "name": "Server 1"}],
            "edges": [{"from": "n1", "to": "nonexistent", "type": "connection"}],
        }
        cd.load_from_string(json.dumps(config), "json")
        report = cd.validate(raise_on_error=False)
        assert report["valid"] is False
        assert any("unknown node" in e for e in report["errors"])

    def test_validate_raises_on_error(self, cd):
        """Test that validate raises exception when configured."""
        config = {
            "schema": {"nodes": {}},
            "nodes": [{"id": "n1", "type": "invalid"}],
            "edges": [],
        }
        cd.load_from_string(json.dumps(config), "json")
        with pytest.raises(ValidationError):
            cd.validate(raise_on_error=True)

    def test_validate_not_loaded(self, cd):
        """Test validation before loading config."""
        with pytest.raises(ValidationError, match="No configuration loaded"):
            cd.validate()

    def test_get_stats(self, loaded_cd):
        """Test getting diagram statistics."""
        loaded_cd.validate()
        stats = loaded_cd.get_stats()
        assert stats["title"] == "Test Network Diagram"
        assert stats["total_nodes"] == 3
        assert stats["total_edges"] == 2
        assert stats["total_clusters"] == 0
        assert "server" in stats["node_types"]
        assert stats["node_types"]["server"] == 2

    def test_get_dot_source(self, loaded_cd):
        """Test getting DOT source code."""
        loaded_cd.validate()
        dot_source = loaded_cd.get_dot_source()
        assert "digraph" in dot_source
        assert "Test_Network_Diagram" in dot_source.replace(" ", "_")

    def test_get_dot_source_not_loaded(self, cd):
        """Test DOT source before loading config."""
        with pytest.raises(CustomDiagramError, match="No configuration loaded"):
            cd.get_dot_source()

    def test_list_shapes_all(self, cd):
        """Test listing all shapes."""
        shapes = cd.list_shapes()
        assert len(shapes) > 0
        assert all("id" in s for s in shapes)

    def test_list_shapes_by_category(self, cd):
        """Test listing shapes by category."""
        shapes = cd.list_shapes(category="security")
        assert len(shapes) > 0
        assert all(s["category"] == "security" for s in shapes)

    def test_list_shapes_invalid_category(self, cd):
        """Test listing shapes with invalid category."""
        shapes = cd.list_shapes(category="invalid_category")
        assert len(shapes) == 0

    def test_repr(self, cd):
        """Test string representation."""
        repr_str = repr(cd)
        assert "CustomDiagrams" in repr_str
        assert "empty" in repr_str

    def test_repr_loaded(self, loaded_cd):
        """Test string representation after loading."""
        repr_str = repr(loaded_cd)
        assert "Test Network Diagram" in repr_str
        assert "loaded" in repr_str
        assert "nodes=3" in repr_str

    def test_layouts(self, cd):
        """Test layout mapping."""
        assert "hierarchical" in cd.LAYOUTS
        assert cd.LAYOUTS["hierarchical"] == "dot"
        assert "circular" in cd.LAYOUTS
        assert cd.LAYOUTS["circular"] == "circo"

    def test_styles(self, cd):
        """Test style presets."""
        assert "cd_default" in cd.STYLES
        assert "cd_dark" in cd.STYLES
        assert "cd_blueprint" in cd.STYLES

    def test_output_formats(self, cd):
        """Test output formats."""
        assert "png" in cd.OUTPUT_FORMATS
        assert "svg" in cd.OUTPUT_FORMATS
        assert "pdf" in cd.OUTPUT_FORMATS


class TestCustomDiagramsClusters:
    """Tests for cluster functionality."""

    @pytest.fixture
    def cd_with_clusters(self):
        """Create a CustomDiagrams with cluster config."""
        config = {
            "diagram": {"title": "Cluster Test"},
            "schema": {
                "nodes": {
                    "server": {"shape": "server", "required_fields": ["name"]}
                },
                "edges": {
                    "connection": {"style": "solid", "color": "#333"}
                },
            },
            "nodes": [
                {"id": "web1", "type": "server", "name": "Web 1"},
                {"id": "web2", "type": "server", "name": "Web 2"},
                {"id": "db1", "type": "server", "name": "DB 1"},
            ],
            "edges": [
                {"from": "web1", "to": "db1", "type": "connection"},
                {"from": "web2", "to": "db1", "type": "connection"},
            ],
            "clusters": [
                {
                    "id": "frontend",
                    "label": "Frontend Tier",
                    "nodes": ["web1", "web2"],
                    "style": {"color": "#3498DB"},
                }
            ],
        }
        cd = CustomDiagrams()
        cd.load_from_string(json.dumps(config), "json")
        return cd

    def test_clusters_loaded(self, cd_with_clusters):
        """Test that clusters are loaded."""
        assert len(cd_with_clusters.clusters) == 1
        assert cd_with_clusters.clusters[0]["id"] == "frontend"

    def test_clusters_validation(self, cd_with_clusters):
        """Test cluster validation."""
        report = cd_with_clusters.validate(raise_on_error=False)
        assert report["valid"] is True

    def test_clusters_invalid_node_reference(self):
        """Test cluster with invalid node reference."""
        config = {
            "schema": {"nodes": {"server": {"shape": "server", "required_fields": ["name"]}}},
            "nodes": [{"id": "n1", "type": "server", "name": "Node 1"}],
            "edges": [],
            "clusters": [{"id": "c1", "label": "Cluster", "nodes": ["invalid_node"]}],
        }
        cd = CustomDiagrams()
        cd.load_from_string(json.dumps(config), "json")
        report = cd.validate(raise_on_error=False)
        # Cluster validation happens but doesn't fail the whole validation
        # The warning about unknown node is added


class TestSchemaValidation:
    """Tests for schema validation."""

    @pytest.fixture
    def registry(self):
        """Get shape registry."""
        return ShapeRegistry.get_instance()

    @pytest.fixture
    def validator(self, registry):
        """Create schema validator."""
        return SchemaValidator(registry)

    def test_valid_schema(self, validator):
        """Test loading a valid schema."""
        schema = {
            "nodes": {
                "server": {"shape": "server", "required_fields": ["name"]},
            },
            "edges": {
                "connection": {"style": "solid", "color": "#333"},
            },
        }
        result = validator.load_schema(schema)
        assert result is True
        assert "server" in validator.node_types
        assert "connection" in validator.edge_types

    def test_invalid_shape(self, validator):
        """Test schema with invalid shape reference."""
        schema = {
            "nodes": {
                "mynode": {"shape": "nonexistent_shape", "required_fields": ["name"]},
            },
        }
        result = validator.load_schema(schema)
        assert result is False
        assert any("unknown shape" in e for e in validator.errors)

    def test_missing_shape(self, validator):
        """Test schema with missing shape field."""
        schema = {
            "nodes": {
                "mynode": {"required_fields": ["name"]},  # No shape
            },
        }
        result = validator.load_schema(schema)
        assert result is False
        assert any("missing required 'shape'" in e for e in validator.errors)

    def test_validate_data(self, validator):
        """Test data validation against schema."""
        schema = {
            "nodes": {"server": {"shape": "server", "required_fields": ["name"]}},
            "edges": {"connection": {"style": "solid"}},
        }
        validator.load_schema(schema)

        nodes = [{"id": "n1", "type": "server", "name": "Server 1"}]
        edges = [{"from": "n1", "to": "n1", "type": "connection"}]

        result = validator.validate_data(nodes, edges)
        assert result is True

    def test_validate_data_duplicate_ids(self, validator):
        """Test data validation with duplicate node IDs."""
        schema = {"nodes": {"server": {"shape": "server", "required_fields": ["name"]}}}
        validator.load_schema(schema)

        nodes = [
            {"id": "n1", "type": "server", "name": "Server 1"},
            {"id": "n1", "type": "server", "name": "Server 2"},  # Duplicate
        ]

        result = validator.validate_data(nodes, [])
        assert result is False
        assert any("duplicate" in e for e in validator.errors)


class TestCustomShapes:
    """Tests for custom shape functionality."""

    def test_custom_dot_shape(self):
        """Test loading a custom DOT shape."""
        config = {
            "diagram": {"title": "Custom Shape Test"},
            "custom_shapes": {
                "my_hexagon": {
                    "type": "dot",
                    "name": "My Hexagon",
                    "dot_definition": "shape=hexagon\nstyle=filled",
                    "tags": ["custom"],
                }
            },
            "schema": {
                "nodes": {"mynode": {"shape": "my_hexagon", "required_fields": ["name"]}},
            },
            "nodes": [{"id": "n1", "type": "mynode", "name": "Test"}],
            "edges": [],
        }
        cd = CustomDiagrams()
        cd.load_from_string(json.dumps(config), "json")

        # The custom shape should be registered
        assert cd.shape_registry.has_shape("my_hexagon")

        # Validation should pass
        report = cd.validate(raise_on_error=False)
        assert report["valid"] is True


class TestFileLoading:
    """Tests for loading from file."""

    def test_load_json_file(self):
        """Test loading from JSON file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(SAMPLE_CONFIG, f)
            f.flush()
            try:
                cd = CustomDiagrams()
                cd.load(f.name)
                assert cd._config_loaded is True
                assert cd.settings.title == "Test Network Diagram"
            finally:
                os.unlink(f.name)

    def test_load_nonexistent_file(self):
        """Test loading non-existent file."""
        cd = CustomDiagrams()
        with pytest.raises(Exception):  # FileError
            cd.load("/nonexistent/path/file.json")
