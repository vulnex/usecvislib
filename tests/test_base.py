#
# VULNEX -Universal Security Visualization Library-
#
# File: test_base.py
# Author: Simon Roses Femerling
# Created: 2025-12-25
# Last Modified: 2025-12-25
# Version: 0.3.1
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Unit tests for base module and constants module (Phase 2)."""

import os
import sys
import tempfile
import pytest

# Add src to path for testing
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from usecvislib.base import VisualizationBase
from usecvislib import constants
from usecvislib.constants import (
    OutputFormat,
    ConfigFormat,
    NodeType,
    NodeTypePrefix,
    GateType,
    ElementType,
    STRIDECategory,
    BinaryVisualization,
    ThreatModelEngine,
    RiskLevel,
    cvss_to_risk_level,
    EXTENSION_FORMAT_MAP,
    CONFIG_EXTENSIONS,
    SENSITIVE_PATHS,
    DEFAULTS,
    COLORS,
    RISK_COLORS,
)


# ==============================================================================
# Constants Module Tests
# ==============================================================================

class TestOutputFormat:
    """Tests for OutputFormat enum."""

    def test_values(self):
        """Test that all expected formats are present."""
        values = OutputFormat.values()
        assert "png" in values
        assert "pdf" in values
        assert "svg" in values
        assert "dot" in values

    def test_from_string_valid(self):
        """Test converting valid strings to OutputFormat."""
        assert OutputFormat.from_string("png") == OutputFormat.PNG
        assert OutputFormat.from_string("PDF") == OutputFormat.PDF
        assert OutputFormat.from_string("SVG") == OutputFormat.SVG
        assert OutputFormat.from_string("dot") == OutputFormat.DOT

    def test_from_string_invalid(self):
        """Test that invalid format raises ValueError."""
        with pytest.raises(ValueError, match="Unsupported output format"):
            OutputFormat.from_string("invalid")

    def test_case_insensitivity(self):
        """Test case-insensitive format parsing."""
        assert OutputFormat.from_string("PNG") == OutputFormat.PNG
        assert OutputFormat.from_string("pNg") == OutputFormat.PNG


class TestConfigFormat:
    """Tests for ConfigFormat enum."""

    def test_format_values(self):
        """Test that expected config formats are present."""
        assert ConfigFormat.TOML.value == "toml"
        assert ConfigFormat.JSON.value == "json"
        assert ConfigFormat.YAML.value == "yaml"


class TestNodeType:
    """Tests for NodeType enum."""

    def test_node_types(self):
        """Test that expected node types are present."""
        assert NodeType.HOST.value == "host"
        assert NodeType.VULNERABILITY.value == "vulnerability"
        assert NodeType.PRIVILEGE.value == "privilege"
        assert NodeType.SERVICE.value == "service"
        assert NodeType.EXPLOIT.value == "exploit"


class TestNodeTypePrefix:
    """Tests for NodeTypePrefix enum."""

    def test_prefixes(self):
        """Test that expected prefixes are present."""
        assert NodeTypePrefix.HOST.value == "H"
        assert NodeTypePrefix.VULNERABILITY.value == "V"
        assert NodeTypePrefix.PRIVILEGE.value == "P"
        assert NodeTypePrefix.SERVICE.value == "S"


class TestGateType:
    """Tests for GateType enum."""

    def test_gate_types(self):
        """Test that expected gate types are present."""
        assert GateType.AND.value == "AND"
        assert GateType.OR.value == "OR"


class TestElementType:
    """Tests for ElementType enum."""

    def test_element_types(self):
        """Test that expected element types are present."""
        assert ElementType.PROCESS.value == "process"
        assert ElementType.DATASTORE.value == "datastore"
        assert ElementType.EXTERNAL.value == "external"
        assert ElementType.DATAFLOW.value == "dataflow"
        assert ElementType.BOUNDARY.value == "boundary"


class TestSTRIDECategory:
    """Tests for STRIDECategory enum."""

    def test_stride_categories(self):
        """Test that all STRIDE categories are present."""
        assert STRIDECategory.SPOOFING.value == "Spoofing"
        assert STRIDECategory.TAMPERING.value == "Tampering"
        assert STRIDECategory.REPUDIATION.value == "Repudiation"
        assert STRIDECategory.INFORMATION_DISCLOSURE.value == "Information Disclosure"
        assert STRIDECategory.DENIAL_OF_SERVICE.value == "Denial of Service"
        assert STRIDECategory.ELEVATION_OF_PRIVILEGE.value == "Elevation of Privilege"

    def test_from_element_type_process(self):
        """Test STRIDE categories for process element."""
        categories = STRIDECategory.from_element_type(ElementType.PROCESS)
        assert len(categories) == 6  # All STRIDE categories apply

    def test_from_element_type_external(self):
        """Test STRIDE categories for external entity."""
        categories = STRIDECategory.from_element_type(ElementType.EXTERNAL)
        assert STRIDECategory.SPOOFING in categories
        assert STRIDECategory.REPUDIATION in categories
        assert len(categories) == 2

    def test_from_element_type_datastore(self):
        """Test STRIDE categories for data store."""
        categories = STRIDECategory.from_element_type(ElementType.DATASTORE)
        assert STRIDECategory.TAMPERING in categories
        assert STRIDECategory.REPUDIATION in categories
        assert STRIDECategory.INFORMATION_DISCLOSURE in categories
        assert STRIDECategory.DENIAL_OF_SERVICE in categories
        assert len(categories) == 4

    def test_from_element_type_dataflow(self):
        """Test STRIDE categories for data flow."""
        categories = STRIDECategory.from_element_type(ElementType.DATAFLOW)
        assert STRIDECategory.TAMPERING in categories
        assert STRIDECategory.INFORMATION_DISCLOSURE in categories
        assert STRIDECategory.DENIAL_OF_SERVICE in categories
        assert len(categories) == 3

    def test_from_element_type_boundary(self):
        """Test STRIDE categories for trust boundary."""
        categories = STRIDECategory.from_element_type(ElementType.BOUNDARY)
        assert categories == []


class TestBinaryVisualization:
    """Tests for BinaryVisualization enum."""

    def test_visualization_types(self):
        """Test that expected visualization types are present."""
        values = BinaryVisualization.values()
        assert "entropy" in values
        assert "distribution" in values
        assert "windrose" in values
        assert "heatmap" in values
        assert "all" in values


class TestThreatModelEngine:
    """Tests for ThreatModelEngine enum."""

    def test_engine_types(self):
        """Test that expected engines are present."""
        assert ThreatModelEngine.USECVISLIB.value == "usecvislib"
        assert ThreatModelEngine.PYTM.value == "pytm"


class TestRiskLevel:
    """Tests for RiskLevel enum."""

    def test_risk_levels(self):
        """Test that expected risk levels are present."""
        assert RiskLevel.CRITICAL.value == "critical"
        assert RiskLevel.HIGH.value == "high"
        assert RiskLevel.MEDIUM.value == "medium"
        assert RiskLevel.LOW.value == "low"
        assert RiskLevel.INFO.value == "info"


class TestCVSSToRiskLevel:
    """Tests for CVSS to risk level conversion."""

    def test_critical_score(self):
        """Test critical CVSS score."""
        assert cvss_to_risk_level(9.0) == RiskLevel.CRITICAL
        assert cvss_to_risk_level(10.0) == RiskLevel.CRITICAL

    def test_high_score(self):
        """Test high CVSS score."""
        assert cvss_to_risk_level(7.0) == RiskLevel.HIGH
        assert cvss_to_risk_level(8.9) == RiskLevel.HIGH

    def test_medium_score(self):
        """Test medium CVSS score."""
        assert cvss_to_risk_level(4.0) == RiskLevel.MEDIUM
        assert cvss_to_risk_level(6.9) == RiskLevel.MEDIUM

    def test_low_score(self):
        """Test low CVSS score."""
        assert cvss_to_risk_level(0.1) == RiskLevel.LOW
        assert cvss_to_risk_level(3.9) == RiskLevel.LOW

    def test_info_score(self):
        """Test informational CVSS score."""
        assert cvss_to_risk_level(0.0) == RiskLevel.INFO


class TestConstantMappings:
    """Tests for constant mappings and default values."""

    def test_extension_format_map(self):
        """Test file extension to format mapping."""
        assert EXTENSION_FORMAT_MAP[".toml"] == ConfigFormat.TOML
        assert EXTENSION_FORMAT_MAP[".tml"] == ConfigFormat.TOML
        assert EXTENSION_FORMAT_MAP[".json"] == ConfigFormat.JSON
        assert EXTENSION_FORMAT_MAP[".yaml"] == ConfigFormat.YAML
        assert EXTENSION_FORMAT_MAP[".yml"] == ConfigFormat.YAML

    def test_config_extensions(self):
        """Test list of valid config extensions."""
        assert ".toml" in CONFIG_EXTENSIONS
        assert ".tml" in CONFIG_EXTENSIONS
        assert ".json" in CONFIG_EXTENSIONS
        assert ".yaml" in CONFIG_EXTENSIONS
        assert ".yml" in CONFIG_EXTENSIONS

    def test_sensitive_paths(self):
        """Test sensitive paths list."""
        assert "/etc" in SENSITIVE_PATHS
        assert "/usr" in SENSITIVE_PATHS
        assert "/bin" in SENSITIVE_PATHS

    def test_defaults_structure(self):
        """Test DEFAULTS structure."""
        assert "output_format" in DEFAULTS
        assert "styles" in DEFAULTS
        assert "max_file_sizes" in DEFAULTS
        assert "style_files" in DEFAULTS

    def test_defaults_styles(self):
        """Test DEFAULTS styles."""
        assert DEFAULTS["styles"]["attack_tree"] == "at_default"
        assert DEFAULTS["styles"]["attack_graph"] == "ag_default"
        assert DEFAULTS["styles"]["threat_model"] == "tm_default"
        assert DEFAULTS["styles"]["binvis"] == "bv_default"

    def test_colors_structure(self):
        """Test COLORS structure."""
        assert "attack_tree" in COLORS
        assert "attack_graph" in COLORS
        assert "threat_model" in COLORS

    def test_risk_colors(self):
        """Test RISK_COLORS mapping."""
        assert RiskLevel.CRITICAL in RISK_COLORS
        assert RiskLevel.HIGH in RISK_COLORS
        assert RiskLevel.MEDIUM in RISK_COLORS
        assert RiskLevel.LOW in RISK_COLORS
        assert RiskLevel.INFO in RISK_COLORS


# ==============================================================================
# Base Class Tests
# ==============================================================================

class ConcreteVisualization(VisualizationBase):
    """Concrete implementation for testing abstract base class."""

    STYLE_FILE = ""
    DEFAULT_STYLE_ID = "test_default"
    ALLOWED_EXTENSIONS = ['.toml', '.tml', '.json']

    def __init__(self, inputfile, outputfile, **kwargs):
        # Override validate_paths to False for testing
        kwargs.setdefault('validate_paths', False)
        super().__init__(inputfile, outputfile, **kwargs)
        self._draw_called = False
        self._test_data = {}

    def _default_style(self):
        return {"node": {"color": "blue"}, "edge": {"color": "black"}}

    def _load_impl(self):
        # Simulate loading data
        return {"name": "Test", "nodes": ["A", "B", "C"]}

    def _render_impl(self):
        # Simulate rendering
        pass

    def _draw_impl(self, outputfile):
        # Simulate drawing
        self._draw_called = True

    def _validate_impl(self):
        errors = []
        if "nodes" not in self.inputdata:
            errors.append("Missing 'nodes' section")
        return errors

    def _get_stats_impl(self):
        nodes = self.inputdata.get("nodes", [])
        return {"total_nodes": len(nodes), "name": self.inputdata.get("name", "")}


class TestVisualizationBase:
    """Tests for VisualizationBase abstract class."""

    def test_init_defaults(self):
        """Test default initialization."""
        viz = ConcreteVisualization("input.tml", "output")
        assert viz.inputfile == "input.tml"
        assert viz.outputfile == "output"
        assert viz.format == "png"
        assert viz.styleid == "test_default"

    def test_init_custom_format(self):
        """Test custom format initialization."""
        viz = ConcreteVisualization("input.tml", "output", format="svg")
        assert viz.format == "svg"

    def test_init_custom_style(self):
        """Test custom style initialization."""
        viz = ConcreteVisualization("input.tml", "output", styleid="custom")
        assert viz.styleid == "custom"

    def test_init_disabled_style(self):
        """Test style disabled with '0'."""
        viz = ConcreteVisualization("input.tml", "output", styleid="0")
        assert viz.styleid == "0"
        # Style should not be loaded (empty)
        assert viz.style == {}

    def test_is_loaded_before_load(self):
        """Test is_loaded property before loading."""
        viz = ConcreteVisualization("input.tml", "output")
        assert viz.is_loaded is False

    def test_is_loaded_after_load(self):
        """Test is_loaded property after loading."""
        viz = ConcreteVisualization("input.tml", "output")
        viz.load()
        assert viz.is_loaded is True

    def test_is_rendered_before_render(self):
        """Test is_rendered property before rendering."""
        viz = ConcreteVisualization("input.tml", "output")
        assert viz.is_rendered is False

    def test_is_rendered_after_render(self):
        """Test is_rendered property after rendering."""
        viz = ConcreteVisualization("input.tml", "output")
        viz.load()
        viz.render()
        assert viz.is_rendered is True

    def test_load_returns_self(self):
        """Test that load() returns self for chaining."""
        viz = ConcreteVisualization("input.tml", "output")
        result = viz.load()
        assert result is viz

    def test_render_returns_self(self):
        """Test that render() returns self for chaining."""
        viz = ConcreteVisualization("input.tml", "output")
        viz.load()
        result = viz.render()
        assert result is viz

    def test_draw_returns_self(self):
        """Test that draw() returns self for chaining."""
        viz = ConcreteVisualization("input.tml", "output")
        viz.load()
        viz.render()
        result = viz.draw()
        assert result is viz

    def test_fluent_interface_chaining(self):
        """Test fluent interface method chaining."""
        viz = ConcreteVisualization("input.tml", "output")
        result = viz.load().render().draw()
        assert result is viz
        assert viz.is_loaded
        assert viz.is_rendered
        assert viz._draw_called

    def test_build_complete_workflow(self):
        """Test build() executes complete workflow."""
        viz = ConcreteVisualization("input.tml", "output")
        result = viz.build()
        assert result is viz
        assert viz.is_loaded
        assert viz.is_rendered
        assert viz._draw_called

    def test_render_auto_loads(self):
        """Test that render() automatically loads if not loaded."""
        viz = ConcreteVisualization("input.tml", "output")
        viz.render()  # Should auto-load
        assert viz.is_loaded
        assert viz.is_rendered

    def test_draw_auto_renders(self):
        """Test that draw() automatically renders if not rendered."""
        viz = ConcreteVisualization("input.tml", "output")
        viz.draw()  # Should auto-load and auto-render
        assert viz.is_loaded
        assert viz.is_rendered

    def test_validate_auto_loads(self):
        """Test that validate() automatically loads if not loaded."""
        viz = ConcreteVisualization("input.tml", "output")
        errors = viz.validate()
        assert viz.is_loaded
        assert len(errors) == 0  # Valid data

    def test_get_stats_auto_loads(self):
        """Test that get_stats() automatically loads if not loaded."""
        viz = ConcreteVisualization("input.tml", "output")
        stats = viz.get_stats()
        assert viz.is_loaded
        assert stats["total_nodes"] == 3
        assert stats["name"] == "Test"

    def test_context_manager(self):
        """Test context manager support."""
        with ConcreteVisualization("input.tml", "output") as viz:
            viz.load()
            assert viz.is_loaded

    def test_default_style_loaded(self):
        """Test that default style is loaded."""
        viz = ConcreteVisualization("input.tml", "output")
        assert viz.style == {"node": {"color": "blue"}, "edge": {"color": "black"}}

    def test_backward_compat_render(self):
        """Test backward compatibility Render() method."""
        viz = ConcreteVisualization("input.tml", "output")
        viz.load()
        viz.Render()
        assert viz.is_rendered

    def test_backward_compat_loadstyle(self):
        """Test backward compatibility loadstyle() method."""
        viz = ConcreteVisualization("input.tml", "output")
        viz.loadstyle()  # Should not raise


class TestVisualizationBaseValidation:
    """Tests for validation in VisualizationBase."""

    def test_validate_returns_list(self):
        """Test that validate returns a list."""
        viz = ConcreteVisualization("input.tml", "output")
        errors = viz.validate()
        assert isinstance(errors, list)

    def test_validate_empty_for_valid_data(self):
        """Test empty errors for valid data."""
        viz = ConcreteVisualization("input.tml", "output")
        errors = viz.validate()
        assert errors == []


class TestVisualizationBaseStats:
    """Tests for statistics in VisualizationBase."""

    def test_get_stats_returns_dict(self):
        """Test that get_stats returns a dictionary."""
        viz = ConcreteVisualization("input.tml", "output")
        stats = viz.get_stats()
        assert isinstance(stats, dict)

    def test_get_stats_content(self):
        """Test stats content."""
        viz = ConcreteVisualization("input.tml", "output")
        stats = viz.get_stats()
        assert "total_nodes" in stats
        assert "name" in stats


# ==============================================================================
# Integration Tests with Real Modules
# ==============================================================================

class TestAttackTreesBaseIntegration:
    """Test AttackTrees integration with base class."""

    def test_inherits_from_base(self):
        """Test that AttackTrees inherits from VisualizationBase."""
        from usecvislib.attacktrees import AttackTrees
        assert issubclass(AttackTrees, VisualizationBase)

    def test_fluent_interface_available(self):
        """Test that fluent interface is available."""
        from usecvislib.attacktrees import AttackTrees
        at = AttackTrees("input.tml", "output", validate_paths=False)
        # Check fluent interface methods exist
        assert hasattr(at, 'load')
        assert hasattr(at, 'render')
        assert hasattr(at, 'draw')
        assert hasattr(at, 'build')
        assert hasattr(at, 'validate')
        assert hasattr(at, 'get_stats')

    def test_properties_available(self):
        """Test that properties are available."""
        from usecvislib.attacktrees import AttackTrees
        at = AttackTrees("input.tml", "output", validate_paths=False)
        assert hasattr(at, 'is_loaded')
        assert hasattr(at, 'is_rendered')


class TestAttackGraphsBaseIntegration:
    """Test AttackGraphs integration with base class."""

    def test_inherits_from_base(self):
        """Test that AttackGraphs inherits from VisualizationBase."""
        from usecvislib.attackgraphs import AttackGraphs
        assert issubclass(AttackGraphs, VisualizationBase)

    def test_fluent_interface_available(self):
        """Test that fluent interface is available."""
        from usecvislib.attackgraphs import AttackGraphs
        ag = AttackGraphs("input.tml", "output", validate_paths=False)
        assert hasattr(ag, 'load')
        assert hasattr(ag, 'render')
        assert hasattr(ag, 'draw')
        assert hasattr(ag, 'build')


class TestThreatModelingBaseIntegration:
    """Test ThreatModeling integration with base class."""

    def test_inherits_from_base(self):
        """Test that ThreatModeling inherits from VisualizationBase."""
        from usecvislib.threatmodeling import ThreatModeling
        assert issubclass(ThreatModeling, VisualizationBase)

    def test_fluent_interface_available(self):
        """Test that fluent interface is available."""
        from usecvislib.threatmodeling import ThreatModeling
        tm = ThreatModeling("input.tml", "output", validate_paths=False)
        assert hasattr(tm, 'load')
        assert hasattr(tm, 'render')
        assert hasattr(tm, 'draw')
        assert hasattr(tm, 'build')


class TestBinVisInterfaceIntegration:
    """Test BinVis common interface methods."""

    def test_has_common_interface(self):
        """Test that BinVis has common interface methods."""
        from usecvislib.binvis import BinVis
        # Check interface methods exist on the class
        assert hasattr(BinVis, 'get_stats')
        assert hasattr(BinVis, 'validate')
        assert hasattr(BinVis, 'build')
        assert hasattr(BinVis, 'is_loaded')


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
