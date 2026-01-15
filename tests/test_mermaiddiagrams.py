#
# VULNEX -Universal Security Visualization Library-
#
# File: test_mermaiddiagrams.py
# Author: Simon Roses Femerling
# Created: 2025-01-14
# License: Apache-2.0
#

"""Tests for MermaidDiagrams module."""

import pytest
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

from usecvislib.mermaiddiagrams import (
    MermaidDiagrams,
    MermaidConfig,
    MermaidResult,
    MermaidError,
    MermaidCLINotFoundError,
    MermaidSyntaxError,
    _sanitize_mermaid_id,
    _escape_mermaid_label,
)
from usecvislib.utils import ValidationError


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def sample_flowchart():
    """Sample flowchart Mermaid source."""
    return """flowchart TD
    A[Start] --> B{Decision}
    B -->|Yes| C[End]
    B -->|No| D[Retry]
    D --> B
"""


@pytest.fixture
def sample_sequence():
    """Sample sequence diagram Mermaid source."""
    return """sequenceDiagram
    participant A as Alice
    participant B as Bob
    A->>B: Hello
    B-->>A: Hi there
"""


@pytest.fixture
def sample_toml_config(sample_flowchart):
    """Sample TOML configuration."""
    return f'''[mermaid]
title = "Test Diagram"
theme = "dark"
background = "white"
width = 1000
height = 800

source = """
{sample_flowchart}
"""
'''


@pytest.fixture
def temp_mmd_file(sample_flowchart, tmp_path):
    """Create a temporary .mmd file."""
    mmd_file = tmp_path / "test.mmd"
    mmd_file.write_text(sample_flowchart)
    return str(mmd_file)


@pytest.fixture
def temp_toml_file(sample_toml_config, tmp_path):
    """Create a temporary TOML config file."""
    toml_file = tmp_path / "test.toml"
    toml_file.write_text(sample_toml_config)
    return str(toml_file)


# =============================================================================
# MermaidConfig Tests
# =============================================================================

class TestMermaidConfig:
    """Tests for MermaidConfig dataclass."""

    def test_default_values(self):
        """Test default configuration values."""
        config = MermaidConfig()
        assert config.title == ""
        assert config.theme == "default"
        assert config.background == "white"
        assert config.width == 800
        assert config.height == 600
        assert config.source == ""

    def test_from_dict_with_mermaid_key(self):
        """Test creating config from dict with 'mermaid' key."""
        data = {
            "mermaid": {
                "title": "Test",
                "theme": "dark",
                "source": "flowchart TD\n    A-->B"
            }
        }
        config = MermaidConfig.from_dict(data)
        assert config.title == "Test"
        assert config.theme == "dark"
        assert "flowchart" in config.source

    def test_from_dict_without_mermaid_key(self):
        """Test creating config from dict without 'mermaid' key."""
        data = {
            "title": "Direct",
            "theme": "forest",
            "width": 1200
        }
        config = MermaidConfig.from_dict(data)
        assert config.title == "Direct"
        assert config.theme == "forest"
        assert config.width == 1200


# =============================================================================
# MermaidResult Tests
# =============================================================================

class TestMermaidResult:
    """Tests for MermaidResult dataclass."""

    def test_to_dict(self):
        """Test converting result to dictionary."""
        result = MermaidResult(
            output_path="/path/to/file.png",
            format="png",
            stats={"lines": 10},
            success=True
        )
        d = result.to_dict()
        assert d["output_path"] == "/path/to/file.png"
        assert d["format"] == "png"
        assert d["stats"]["lines"] == 10
        assert d["success"] is True


# =============================================================================
# MermaidDiagrams Tests - Initialization
# =============================================================================

class TestMermaidDiagramsInit:
    """Tests for MermaidDiagrams initialization."""

    def test_init_with_validate_cli_false(self):
        """Test initialization without CLI validation."""
        md = MermaidDiagrams(validate_cli=False)
        assert md.config.theme == "default"
        assert md.source == ""
        assert md._loaded is False

    def test_init_with_custom_theme(self):
        """Test initialization with custom theme."""
        md = MermaidDiagrams(theme="dark", validate_cli=False)
        assert md.config.theme == "dark"


# =============================================================================
# MermaidDiagrams Tests - Loading
# =============================================================================

class TestMermaidDiagramsLoading:
    """Tests for loading Mermaid content."""

    def test_load_mmd_file(self, temp_mmd_file, sample_flowchart):
        """Test loading from .mmd file."""
        md = MermaidDiagrams(validate_cli=False)
        md.load(temp_mmd_file)

        assert md._loaded is True
        assert "flowchart" in md.source
        assert md.diagram_type == "flowchart"

    def test_load_toml_config(self, temp_toml_file):
        """Test loading from TOML config file."""
        md = MermaidDiagrams(validate_cli=False)
        md.load(temp_toml_file)

        assert md._loaded is True
        assert md.config.title == "Test Diagram"
        assert md.config.theme == "dark"

    def test_load_from_string_mermaid(self, sample_flowchart):
        """Test loading from raw Mermaid string."""
        md = MermaidDiagrams(validate_cli=False)
        md.load_from_string(sample_flowchart, format="mermaid")

        assert md._loaded is True
        assert md.diagram_type == "flowchart"

    def test_load_from_string_toml(self, sample_toml_config):
        """Test loading from TOML string."""
        md = MermaidDiagrams(validate_cli=False)
        md.load_from_string(sample_toml_config, format="toml")

        assert md._loaded is True
        assert md.config.title == "Test Diagram"

    def test_load_nonexistent_file(self):
        """Test loading non-existent file raises error."""
        md = MermaidDiagrams(validate_cli=False)
        with pytest.raises(FileNotFoundError):
            md.load("/nonexistent/path/file.mmd")

    def test_load_unsupported_extension(self, tmp_path):
        """Test loading file with unsupported extension."""
        bad_file = tmp_path / "test.txt"
        bad_file.write_text("content")

        md = MermaidDiagrams(validate_cli=False)
        with pytest.raises(ValidationError):
            md.load(str(bad_file))

    def test_load_empty_content(self):
        """Test loading empty content raises error."""
        md = MermaidDiagrams(validate_cli=False)
        with pytest.raises(ValidationError):
            md.load_from_string("", format="mermaid")

    def test_load_unsupported_format(self):
        """Test loading with unsupported format."""
        md = MermaidDiagrams(validate_cli=False)
        with pytest.raises(ValidationError):
            md.load_from_string("content", format="xml")


# =============================================================================
# MermaidDiagrams Tests - Type Detection
# =============================================================================

class TestMermaidDiagramsTypeDetection:
    """Tests for diagram type detection."""

    @pytest.mark.parametrize("source,expected_type", [
        ("flowchart TD\n    A-->B", "flowchart"),
        ("flowchart LR\n    A-->B", "flowchart"),
        ("graph TD\n    A-->B", "graph"),  # graph is detected as-is, not normalized to flowchart
        ("sequenceDiagram\n    A->>B: msg", "sequenceDiagram"),
        ("classDiagram\n    class A", "classDiagram"),
        ("stateDiagram-v2\n    [*] --> S1", "stateDiagram"),  # version suffix stripped
        ("erDiagram\n    A ||--o{ B : has", "erDiagram"),
        ("gantt\n    title Test", "gantt"),
        ("pie\n    title Test", "pie"),
        ("mindmap\n    root((Test))", "mindmap"),
        ("timeline\n    title Test", "timeline"),
        ("gitGraph\n    commit", "gitGraph"),
        ("unknown content", "unknown"),
    ])
    def test_detect_diagram_type(self, source, expected_type):
        """Test detection of various diagram types."""
        md = MermaidDiagrams(validate_cli=False)
        md.load_from_string(source, format="mermaid")
        assert md.diagram_type == expected_type


# =============================================================================
# MermaidDiagrams Tests - Statistics
# =============================================================================

class TestMermaidDiagramsStats:
    """Tests for statistics collection."""

    def test_get_stats(self, sample_flowchart):
        """Test getting diagram statistics."""
        md = MermaidDiagrams(validate_cli=False)
        md.load_from_string(sample_flowchart, format="mermaid")
        md.config.title = "Test Stats"

        stats = md.get_stats()
        assert stats["title"] == "Test Stats"
        assert stats["diagram_type"] == "flowchart"
        assert stats["line_count"] > 0
        assert stats["char_count"] > 0
        assert stats["non_empty_lines"] > 0


# =============================================================================
# MermaidDiagrams Tests - Export
# =============================================================================

class TestMermaidDiagramsExport:
    """Tests for export functionality."""

    def test_get_source(self, sample_flowchart):
        """Test getting raw Mermaid source."""
        md = MermaidDiagrams(validate_cli=False)
        md.load_from_string(sample_flowchart, format="mermaid")

        source = md.get_source()
        assert source == sample_flowchart

    def test_save_mmd(self, sample_flowchart, tmp_path):
        """Test saving to .mmd file."""
        md = MermaidDiagrams(validate_cli=False)
        md.load_from_string(sample_flowchart, format="mermaid")

        output = tmp_path / "output"
        saved_path = md.save_mmd(str(output))

        assert saved_path.endswith(".mmd")
        assert Path(saved_path).exists()
        assert Path(saved_path).read_text() == sample_flowchart

    def test_save_mmd_with_extension(self, sample_flowchart, tmp_path):
        """Test saving with .mmd extension already present."""
        md = MermaidDiagrams(validate_cli=False)
        md.load_from_string(sample_flowchart, format="mermaid")

        output = tmp_path / "output.mmd"
        saved_path = md.save_mmd(str(output))

        assert saved_path.endswith(".mmd")

    def test_save_mmd_empty_source(self):
        """Test saving without loaded source raises error."""
        md = MermaidDiagrams(validate_cli=False)
        with pytest.raises(ValidationError):
            md.save_mmd("/tmp/test")


# =============================================================================
# MermaidDiagrams Tests - Conversion
# =============================================================================

class TestMermaidDiagramsConversion:
    """Tests for conversion methods."""

    def test_to_custom_diagram_flowchart(self, sample_flowchart):
        """Test converting flowchart to CustomDiagrams."""
        md = MermaidDiagrams(validate_cli=False)
        md.load_from_string(sample_flowchart, format="mermaid")

        cd = md.to_custom_diagram()
        assert cd is not None
        assert len(cd.nodes) > 0

    def test_to_custom_diagram_sequence_fails(self, sample_sequence):
        """Test converting sequence diagram raises error."""
        md = MermaidDiagrams(validate_cli=False)
        md.load_from_string(sample_sequence, format="mermaid")

        with pytest.raises(MermaidError):
            md.to_custom_diagram()


# =============================================================================
# Helper Function Tests
# =============================================================================

class TestHelperFunctions:
    """Tests for helper functions."""

    @pytest.mark.parametrize("input_id,expected", [
        ("node1", "node1"),
        ("node-with-dash", "node_with_dash"),
        ("node with space", "node_with_space"),
        ("123start", "n_123start"),
        ("special@#$chars", "specialchars"),
        ("", "node"),
        (None, "node"),
    ])
    def test_sanitize_mermaid_id(self, input_id, expected):
        """Test ID sanitization."""
        result = _sanitize_mermaid_id(input_id)
        assert result == expected

    @pytest.mark.parametrize("input_label,expected_contains", [
        ("normal label", "normal label"),
        ("label with \"quotes\"", "label with 'quotes'"),
        ("label with [brackets]", "label with (brackets)"),
        ("label with {braces}", "label with (braces)"),
        ("label with <angle>", "label with ltanglegt"),
        ("line1\nline2", "line1 line2"),
    ])
    def test_escape_mermaid_label(self, input_label, expected_contains):
        """Test label escaping."""
        result = _escape_mermaid_label(input_label)
        assert expected_contains in result or result.replace(" ", "") == expected_contains.replace(" ", "")

    def test_escape_mermaid_label_truncation(self):
        """Test label truncation for long labels."""
        long_label = "a" * 200
        result = _escape_mermaid_label(long_label, max_length=100)
        assert len(result) == 100
        assert result.endswith("...")


# =============================================================================
# MermaidDiagrams Tests - Context Manager
# =============================================================================

class TestMermaidDiagramsContextManager:
    """Tests for context manager support."""

    def test_context_manager(self, sample_flowchart):
        """Test using as context manager."""
        with MermaidDiagrams(validate_cli=False) as md:
            md.load_from_string(sample_flowchart, format="mermaid")
            assert md._loaded is True


# =============================================================================
# MermaidDiagrams Tests - Repr
# =============================================================================

class TestMermaidDiagramsRepr:
    """Tests for string representation."""

    def test_repr_empty(self):
        """Test repr for empty instance."""
        md = MermaidDiagrams(validate_cli=False)
        repr_str = repr(md)
        assert "empty" in repr_str

    def test_repr_loaded(self, sample_flowchart):
        """Test repr for loaded instance."""
        md = MermaidDiagrams(validate_cli=False)
        md.load_from_string(sample_flowchart, format="mermaid")
        repr_str = repr(md)
        assert "loaded" in repr_str
        assert "flowchart" in repr_str


# =============================================================================
# MermaidDiagrams Tests - Templates
# =============================================================================

class TestMermaidDiagramsTemplates:
    """Tests for template functionality."""

    def test_list_template_categories(self):
        """Test listing template categories."""
        categories = MermaidDiagrams.list_template_categories()
        # May return empty if templates not found
        assert isinstance(categories, list)

    def test_list_templates(self):
        """Test listing templates."""
        templates = MermaidDiagrams.list_templates()
        assert isinstance(templates, list)


# =============================================================================
# MermaidDiagrams Tests - Validation (requires mmdc)
# =============================================================================

class TestMermaidDiagramsValidation:
    """Tests for validation (mocked)."""

    @patch('subprocess.run')
    def test_validate_success(self, mock_run, sample_flowchart):
        """Test successful validation."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        md = MermaidDiagrams(validate_cli=False)
        md._cli_validated = True  # Skip CLI check
        md.load_from_string(sample_flowchart, format="mermaid")

        errors = md.validate()
        assert errors == []

    @patch('subprocess.run')
    def test_validate_failure(self, mock_run, sample_flowchart):
        """Test failed validation."""
        mock_run.return_value = MagicMock(
            returncode=1,
            stdout="",
            stderr="Parse error"
        )

        md = MermaidDiagrams(validate_cli=False)
        md._cli_validated = True
        md.load_from_string(sample_flowchart, format="mermaid")

        errors = md.validate()
        assert len(errors) > 0
        assert "Parse error" in errors[0]
