#
# VULNEX -Universal Security Visualization Library-
#
# File: test_clouddiagrams.py
# Author: Simon Roses Femerling
# Created: 2025-01-14
# License: Apache-2.0
#

"""Tests for CloudDiagrams module."""

import pytest
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

from usecvislib.clouddiagrams import (
    CloudDiagrams,
    CloudDiagramConfig,
    CloudNode,
    CloudEdge,
    CloudCluster,
    CloudDiagramResult,
    CloudDiagramError,
    DiagramsNotInstalledError,
    IconNotFoundError,
)
from usecvislib.utils import ValidationError


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def sample_toml_config():
    """Sample TOML configuration for cloud diagram."""
    return '''[diagram]
title = "Test Architecture"
direction = "LR"
outformat = "png"
show = false

[[clusters]]
id = "vpc"
label = "VPC"

    [[clusters.nodes]]
    id = "web"
    icon = "aws.compute.EC2"
    label = "Web Server"

    [[clusters.nodes]]
    id = "db"
    icon = "aws.database.RDS"
    label = "Database"

[[nodes]]
id = "users"
icon = "aws.general.Users"
label = "Users"

[[edges]]
from = "users"
to = "web"

[[edges]]
from = "web"
to = "db"
label = "SQL"
'''


@pytest.fixture
def sample_yaml_config():
    """Sample YAML configuration for cloud diagram."""
    return '''diagram:
  title: Test Architecture
  direction: LR
  outformat: png

clusters:
  - id: vpc
    label: VPC
    nodes:
      - id: web
        icon: aws.compute.EC2
        label: Web Server

nodes:
  - id: users
    icon: aws.general.Users
    label: Users

edges:
  - from: users
    to: web
'''


@pytest.fixture
def temp_toml_file(sample_toml_config, tmp_path):
    """Create a temporary TOML config file."""
    toml_file = tmp_path / "test.toml"
    toml_file.write_text(sample_toml_config)
    return str(toml_file)


@pytest.fixture
def temp_yaml_file(sample_yaml_config, tmp_path):
    """Create a temporary YAML config file."""
    yaml_file = tmp_path / "test.yaml"
    yaml_file.write_text(sample_yaml_config)
    return str(yaml_file)


# =============================================================================
# CloudDiagramConfig Tests
# =============================================================================

class TestCloudDiagramConfig:
    """Tests for CloudDiagramConfig dataclass."""

    def test_default_values(self):
        """Test default configuration values."""
        config = CloudDiagramConfig()
        assert config.title == "Cloud Architecture"
        assert config.direction == "LR"
        assert config.outformat == "png"
        assert config.show is False

    def test_from_dict_with_diagram_key(self):
        """Test creating config from dict with 'diagram' key."""
        data = {
            "diagram": {
                "title": "Test",
                "direction": "TB",
                "outformat": "svg"
            }
        }
        config = CloudDiagramConfig.from_dict(data)
        assert config.title == "Test"
        assert config.direction == "TB"
        assert config.outformat == "svg"

    def test_from_dict_without_diagram_key(self):
        """Test creating config from dict without 'diagram' key."""
        data = {
            "title": "Direct",
            "direction": "RL"
        }
        config = CloudDiagramConfig.from_dict(data)
        assert config.title == "Direct"
        assert config.direction == "RL"


# =============================================================================
# CloudNode Tests
# =============================================================================

class TestCloudNode:
    """Tests for CloudNode dataclass."""

    def test_from_dict_basic(self):
        """Test creating node from basic dict."""
        data = {
            "id": "node1",
            "icon": "aws.compute.EC2",
            "label": "Server"
        }
        node = CloudNode.from_dict(data)
        assert node.id == "node1"
        assert node.icon == "aws.compute.EC2"
        assert node.label == "Server"
        assert node.cluster_id is None

    def test_from_dict_with_cluster(self):
        """Test creating node with cluster ID."""
        data = {"id": "node1", "icon": "test", "label": "Test"}
        node = CloudNode.from_dict(data, cluster_id="cluster1")
        assert node.cluster_id == "cluster1"

    def test_from_dict_type_fallback(self):
        """Test icon falls back to type field."""
        data = {"id": "node1", "type": "aws.compute.EC2", "label": "Test"}
        node = CloudNode.from_dict(data)
        assert node.icon == "aws.compute.EC2"


# =============================================================================
# CloudEdge Tests
# =============================================================================

class TestCloudEdge:
    """Tests for CloudEdge dataclass."""

    def test_from_dict_basic(self):
        """Test creating edge from basic dict."""
        data = {
            "from": "node1",
            "to": "node2"
        }
        edge = CloudEdge.from_dict(data)
        assert edge.from_id == "node1"
        assert edge.to_id == "node2"
        assert edge.label == ""

    def test_from_dict_with_style(self):
        """Test creating edge with style options."""
        data = {
            "from": "node1",
            "to": "node2",
            "label": "connects",
            "color": "red",
            "style": "dashed"
        }
        edge = CloudEdge.from_dict(data)
        assert edge.label == "connects"
        assert edge.color == "red"
        assert edge.style == "dashed"

    def test_from_dict_fan_out(self):
        """Test edge with list targets."""
        data = {
            "from": "node1",
            "to": ["node2", "node3"]
        }
        edge = CloudEdge.from_dict(data)
        assert edge.to_id == ["node2", "node3"]


# =============================================================================
# CloudCluster Tests
# =============================================================================

class TestCloudCluster:
    """Tests for CloudCluster dataclass."""

    def test_from_dict_basic(self):
        """Test creating cluster from basic dict."""
        data = {
            "id": "cluster1",
            "label": "My Cluster",
            "nodes": [
                {"id": "n1", "icon": "test", "label": "Node 1"},
                {"id": "n2", "icon": "test", "label": "Node 2"}
            ]
        }
        cluster = CloudCluster.from_dict(data)
        assert cluster.id == "cluster1"
        assert cluster.label == "My Cluster"
        assert len(cluster.nodes) == 2
        assert cluster.nodes[0].cluster_id == "cluster1"


# =============================================================================
# CloudDiagramResult Tests
# =============================================================================

class TestCloudDiagramResult:
    """Tests for CloudDiagramResult dataclass."""

    def test_to_dict(self):
        """Test converting result to dictionary."""
        result = CloudDiagramResult(
            output_path="/path/to/file.png",
            format="png",
            stats={"nodes": 5},
            success=True
        )
        d = result.to_dict()
        assert d["output_path"] == "/path/to/file.png"
        assert d["format"] == "png"
        assert d["stats"]["nodes"] == 5
        assert d["success"] is True


# =============================================================================
# CloudDiagrams Tests - Initialization
# =============================================================================

class TestCloudDiagramsInit:
    """Tests for CloudDiagrams initialization."""

    def test_init_without_validation(self):
        """Test initialization without diagrams library validation."""
        cd = CloudDiagrams(validate_diagrams=False)
        assert cd.config.title == "Cloud Architecture"
        assert cd.nodes == []
        assert cd.edges == []
        assert cd.clusters == []
        assert cd._loaded is False


# =============================================================================
# CloudDiagrams Tests - Loading
# =============================================================================

class TestCloudDiagramsLoading:
    """Tests for loading cloud diagram configurations."""

    def test_load_toml_file(self, temp_toml_file):
        """Test loading from TOML file."""
        cd = CloudDiagrams(validate_diagrams=False)
        cd.load(temp_toml_file)

        assert cd._loaded is True
        assert cd.config.title == "Test Architecture"
        assert cd.config.direction == "LR"
        assert len(cd.clusters) == 1
        assert len(cd.edges) == 2

    def test_load_yaml_file(self, temp_yaml_file):
        """Test loading from YAML file."""
        cd = CloudDiagrams(validate_diagrams=False)
        cd.load(temp_yaml_file)

        assert cd._loaded is True
        assert cd.config.title == "Test Architecture"

    def test_load_from_string_toml(self, sample_toml_config):
        """Test loading from TOML string."""
        cd = CloudDiagrams(validate_diagrams=False)
        cd.load_from_string(sample_toml_config, format="toml")

        assert cd._loaded is True
        assert cd.config.title == "Test Architecture"

    def test_load_from_string_yaml(self, sample_yaml_config):
        """Test loading from YAML string."""
        cd = CloudDiagrams(validate_diagrams=False)
        cd.load_from_string(sample_yaml_config, format="yaml")

        assert cd._loaded is True

    def test_load_nonexistent_file(self):
        """Test loading non-existent file raises error."""
        cd = CloudDiagrams(validate_diagrams=False)
        with pytest.raises(FileNotFoundError):
            cd.load("/nonexistent/path/file.toml")

    def test_load_unsupported_extension(self, tmp_path):
        """Test loading file with unsupported extension."""
        bad_file = tmp_path / "test.txt"
        bad_file.write_text("content")

        cd = CloudDiagrams(validate_diagrams=False)
        with pytest.raises(ValidationError):
            cd.load(str(bad_file))

    def test_load_empty_content(self):
        """Test loading empty content raises error."""
        cd = CloudDiagrams(validate_diagrams=False)
        with pytest.raises(ValidationError):
            cd.load_from_string("", format="toml")

    def test_load_unsupported_format(self):
        """Test loading with unsupported format."""
        cd = CloudDiagrams(validate_diagrams=False)
        with pytest.raises(ValidationError):
            cd.load_from_string("content", format="xml")


# =============================================================================
# CloudDiagrams Tests - Statistics
# =============================================================================

class TestCloudDiagramsStats:
    """Tests for statistics collection."""

    def test_get_stats(self, sample_toml_config):
        """Test getting diagram statistics."""
        cd = CloudDiagrams(validate_diagrams=False)
        cd.load_from_string(sample_toml_config, format="toml")

        stats = cd.get_stats()
        assert stats["title"] == "Test Architecture"
        assert stats["total_nodes"] == 3  # web, db, users
        assert stats["total_edges"] == 2
        assert stats["total_clusters"] == 1
        assert stats["direction"] == "LR"


# =============================================================================
# CloudDiagrams Tests - Validation
# =============================================================================

class TestCloudDiagramsValidation:
    """Tests for validation."""

    def test_validate_not_loaded(self):
        """Test validation without loaded config."""
        cd = CloudDiagrams(validate_diagrams=False)
        errors = cd.validate()
        assert "No configuration loaded" in errors

    def test_validate_invalid_direction(self):
        """Test validation with invalid direction."""
        cd = CloudDiagrams(validate_diagrams=False)
        cd._loaded = True
        cd.config.direction = "INVALID"
        cd.nodes = []
        cd.edges = []

        errors = cd.validate()
        assert any("direction" in e.lower() for e in errors)


# =============================================================================
# CloudDiagrams Tests - Code Generation
# =============================================================================

class TestCloudDiagramsCodeGeneration:
    """Tests for Python code generation."""

    def test_to_python_code(self, sample_toml_config):
        """Test generating Python Diagrams code."""
        cd = CloudDiagrams(validate_diagrams=False)
        cd.load_from_string(sample_toml_config, format="toml")

        code = cd.to_python_code()

        assert "from diagrams import Diagram, Cluster, Edge" in code
        assert "Test Architecture" in code
        assert "direction=" in code
        assert "with Diagram(" in code

    def test_save_python(self, sample_toml_config, tmp_path):
        """Test saving Python code to file."""
        cd = CloudDiagrams(validate_diagrams=False)
        cd.load_from_string(sample_toml_config, format="toml")

        output = tmp_path / "output"
        saved_path = cd.save_python(str(output))

        assert saved_path.endswith(".py")
        assert Path(saved_path).exists()

        content = Path(saved_path).read_text()
        assert "from diagrams import" in content

    def test_save_python_with_extension(self, sample_toml_config, tmp_path):
        """Test saving with .py extension already present."""
        cd = CloudDiagrams(validate_diagrams=False)
        cd.load_from_string(sample_toml_config, format="toml")

        output = tmp_path / "output.py"
        saved_path = cd.save_python(str(output))

        assert saved_path.endswith(".py")
        assert not saved_path.endswith(".py.py")


# =============================================================================
# CloudDiagrams Tests - Icon Discovery
# =============================================================================

class TestCloudDiagramsIconDiscovery:
    """Tests for icon discovery functionality."""

    def test_list_providers(self):
        """Test listing available providers."""
        providers = CloudDiagrams.list_providers()

        assert isinstance(providers, list)
        assert len(providers) > 0

        # Check structure
        for p in providers:
            assert "id" in p
            assert "name" in p

        # Check some known providers
        provider_ids = [p["id"] for p in providers]
        assert "aws" in provider_ids
        assert "azure" in provider_ids
        assert "gcp" in provider_ids
        assert "k8s" in provider_ids

    def test_list_categories(self):
        """Test listing categories for a provider."""
        # This test may fail if diagrams library not installed
        try:
            categories = CloudDiagrams.list_categories("aws")
            assert isinstance(categories, list)
        except Exception:
            pytest.skip("diagrams library not available")

    def test_list_icons(self):
        """Test listing icons for a provider."""
        try:
            icons = CloudDiagrams.list_icons("aws", "compute")
            assert isinstance(icons, list)

            if icons:
                # Check structure
                assert "id" in icons[0]
                assert "path" in icons[0]
                assert "provider" in icons[0]
        except Exception:
            pytest.skip("diagrams library not available")

    def test_search_icons(self):
        """Test searching icons."""
        try:
            results = CloudDiagrams.search_icons("ec2", limit=10)
            assert isinstance(results, list)
        except Exception:
            pytest.skip("diagrams library not available")


# =============================================================================
# CloudDiagrams Tests - Conversion
# =============================================================================

class TestCloudDiagramsConversion:
    """Tests for conversion from other formats."""

    def test_from_custom_diagram(self):
        """Test converting from CustomDiagrams."""
        from usecvislib.customdiagrams import CustomDiagrams, DiagramSettings

        # Create a simple CustomDiagrams instance
        custom = CustomDiagrams()
        custom.settings = DiagramSettings(title="Test Custom", direction="LR")
        custom.nodes = [
            {"id": "n1", "name": "Node 1", "type": "server"},
            {"id": "n2", "name": "Node 2", "type": "database"}
        ]
        custom.edges = [{"from": "n1", "to": "n2", "label": "connects"}]
        custom.clusters = []
        custom._config_loaded = True

        cd = CloudDiagrams.from_custom_diagram(custom)

        assert cd._loaded is True
        assert cd.config.title == "Test Custom"
        assert len(cd.nodes) == 2
        assert len(cd.edges) == 1


# =============================================================================
# CloudDiagrams Tests - Context Manager
# =============================================================================

class TestCloudDiagramsContextManager:
    """Tests for context manager support."""

    def test_context_manager(self, sample_toml_config):
        """Test using as context manager."""
        with CloudDiagrams(validate_diagrams=False) as cd:
            cd.load_from_string(sample_toml_config, format="toml")
            assert cd._loaded is True


# =============================================================================
# CloudDiagrams Tests - Repr
# =============================================================================

class TestCloudDiagramsRepr:
    """Tests for string representation."""

    def test_repr_empty(self):
        """Test repr for empty instance."""
        cd = CloudDiagrams(validate_diagrams=False)
        repr_str = repr(cd)
        assert "empty" in repr_str
        assert "CloudDiagrams" in repr_str

    def test_repr_loaded(self, sample_toml_config):
        """Test repr for loaded instance."""
        cd = CloudDiagrams(validate_diagrams=False)
        cd.load_from_string(sample_toml_config, format="toml")

        repr_str = repr(cd)
        assert "loaded" in repr_str
        assert "Test Architecture" in repr_str


# =============================================================================
# CloudDiagrams Tests - Templates
# =============================================================================

class TestCloudDiagramsTemplates:
    """Tests for template functionality."""

    def test_list_template_categories(self):
        """Test listing template categories."""
        categories = CloudDiagrams.list_template_categories()
        assert isinstance(categories, list)

    def test_list_templates(self):
        """Test listing templates."""
        templates = CloudDiagrams.list_templates()
        assert isinstance(templates, list)


# =============================================================================
# CloudDiagrams Tests - Edge Code Generation
# =============================================================================

class TestCloudDiagramsEdgeGeneration:
    """Tests for edge code generation."""

    def test_generate_simple_edge(self, sample_toml_config):
        """Test generating simple edge code."""
        cd = CloudDiagrams(validate_diagrams=False)
        cd.load_from_string(sample_toml_config, format="toml")

        code = cd.to_python_code()
        assert ">>" in code  # Edge operator

    def test_generate_labeled_edge(self, sample_toml_config):
        """Test generating labeled edge code."""
        cd = CloudDiagrams(validate_diagrams=False)
        cd.load_from_string(sample_toml_config, format="toml")

        code = cd.to_python_code()
        assert "Edge(" in code or "SQL" in code


# =============================================================================
# Internal Method Tests
# =============================================================================

class TestCloudDiagramsInternalMethods:
    """Tests for internal methods."""

    def test_safe_var_name(self):
        """Test safe variable name generation."""
        cd = CloudDiagrams(validate_diagrams=False)

        assert cd._safe_var_name("simple") == "simple"
        assert cd._safe_var_name("with-dash") == "with_dash"
        assert cd._safe_var_name("with space") == "with_space"
        assert cd._safe_var_name("123start") == "n_123start"
        assert cd._safe_var_name("") == "node"

    def test_normalize_icon_path_full(self):
        """Test icon path normalization with full path."""
        cd = CloudDiagrams(validate_diagrams=False)

        result = cd._normalize_icon_path("aws.compute.EC2")
        assert result == "aws.compute.EC2"

    def test_normalize_icon_path_empty(self):
        """Test icon path normalization with empty input."""
        cd = CloudDiagrams(validate_diagrams=False)

        result = cd._normalize_icon_path("")
        assert result is None

    def test_get_icon_class_name(self):
        """Test extracting class name from icon path."""
        cd = CloudDiagrams(validate_diagrams=False)

        assert cd._get_icon_class_name("aws.compute.EC2") == "EC2"
        assert cd._get_icon_class_name("aws:EC2") == "EC2"
        assert cd._get_icon_class_name("EC2") == "EC2"
