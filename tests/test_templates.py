#
# VULNEX -Universal Security Visualization Library-
#
# File: test_templates.py
# Author: Claude Code
# Created: 2025-12-29
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
#

"""Tests for Custom Diagrams templates.

This module tests that all built-in templates:
1. Load correctly without errors
2. Validate against their schemas
3. Have proper structure
"""

import pytest
from pathlib import Path
from usecvislib import CustomDiagrams


# Get templates directory
TEMPLATES_DIR = Path(__file__).parent.parent / "templates" / "custom-diagrams"


def get_all_templates():
    """Get all template files from the templates directory."""
    if not TEMPLATES_DIR.exists():
        return []

    templates = []
    for category_dir in TEMPLATES_DIR.iterdir():
        if category_dir.is_dir() and category_dir.name != "__pycache__":
            for template_file in category_dir.glob("*.toml"):
                templates.append(
                    pytest.param(
                        category_dir.name,
                        template_file,
                        id=f"{category_dir.name}/{template_file.stem}"
                    )
                )
    return templates


class TestTemplateStructure:
    """Test template directory structure."""

    def test_templates_directory_exists(self):
        """Test that templates directory exists."""
        assert TEMPLATES_DIR.exists(), f"Templates directory not found: {TEMPLATES_DIR}"

    def test_expected_categories_exist(self):
        """Test that all expected category directories exist."""
        expected = ["general", "software", "network", "security", "business"]
        for category in expected:
            category_dir = TEMPLATES_DIR / category
            assert category_dir.exists(), f"Category directory missing: {category}"

    def test_readme_exists(self):
        """Test that README file exists in templates directory."""
        readme = TEMPLATES_DIR / "README.md"
        assert readme.exists(), "README.md not found in templates directory"

    def test_general_templates_exist(self):
        """Test that general templates exist."""
        expected = ["flowchart.toml", "mindmap.toml", "hierarchy.toml", "timeline.toml"]
        general_dir = TEMPLATES_DIR / "general"
        for template in expected:
            assert (general_dir / template).exists(), f"Missing template: general/{template}"

    def test_software_templates_exist(self):
        """Test that software templates exist."""
        expected = [
            "architecture.toml",
            "class-diagram.toml",
            "sequence-diagram.toml",
            "component-diagram.toml",
            "deployment-diagram.toml",
            "source-code.toml",
            "directory-tree.toml",
        ]
        software_dir = TEMPLATES_DIR / "software"
        for template in expected:
            assert (software_dir / template).exists(), f"Missing template: software/{template}"

    def test_network_templates_exist(self):
        """Test that network templates exist."""
        expected = ["topology.toml", "data-flow.toml", "infrastructure.toml"]
        network_dir = TEMPLATES_DIR / "network"
        for template in expected:
            assert (network_dir / template).exists(), f"Missing template: network/{template}"

    def test_security_templates_exist(self):
        """Test that security templates exist."""
        expected = ["risk-matrix.toml", "incident-flow.toml", "access-control.toml"]
        security_dir = TEMPLATES_DIR / "security"
        for template in expected:
            assert (security_dir / template).exists(), f"Missing template: security/{template}"

    def test_business_templates_exist(self):
        """Test that business templates exist."""
        expected = ["process-flow.toml", "swimlane.toml", "org-chart.toml"]
        business_dir = TEMPLATES_DIR / "business"
        for template in expected:
            assert (business_dir / template).exists(), f"Missing template: business/{template}"


class TestTemplateLoading:
    """Test that templates load correctly."""

    @pytest.mark.parametrize("category,template_path", get_all_templates())
    def test_template_loads(self, category, template_path):
        """Test that each template loads without errors."""
        cd = CustomDiagrams()
        cd.load(template_path)

        assert cd._config_loaded
        assert cd.settings is not None
        assert cd.settings.title

    @pytest.mark.parametrize("category,template_path", get_all_templates())
    def test_template_has_schema(self, category, template_path):
        """Test that each template has a schema definition."""
        cd = CustomDiagrams()
        cd.load(template_path)

        assert cd.schema, f"Template {template_path} has no schema"
        assert "nodes" in cd.schema or "edges" in cd.schema

    @pytest.mark.parametrize("category,template_path", get_all_templates())
    def test_template_has_nodes(self, category, template_path):
        """Test that each template has example nodes."""
        cd = CustomDiagrams()
        cd.load(template_path)

        assert cd.nodes, f"Template {template_path} has no example nodes"

    @pytest.mark.parametrize("category,template_path", get_all_templates())
    def test_template_has_edges(self, category, template_path):
        """Test that each template has example edges."""
        cd = CustomDiagrams()
        cd.load(template_path)

        assert cd.edges, f"Template {template_path} has no example edges"


class TestTemplateValidation:
    """Test that templates validate correctly."""

    @pytest.mark.parametrize("category,template_path", get_all_templates())
    def test_template_validates(self, category, template_path):
        """Test that each template validates without errors."""
        cd = CustomDiagrams()
        cd.load(template_path)

        # Should not raise an exception
        report = cd.validate(raise_on_error=False)

        # Check validation passed
        assert report["valid"], f"Template {template_path} validation failed: {report.get('errors', [])}"

    @pytest.mark.parametrize("category,template_path", get_all_templates())
    def test_template_node_types_valid(self, category, template_path):
        """Test that all node types in template have valid shapes."""
        cd = CustomDiagrams()
        cd.load(template_path)

        # Validate the schema loads
        cd.validate(raise_on_error=False)

        # Check that node types are registered
        for node in cd.nodes:
            node_type = node.get("type")
            if node_type:
                assert node_type in cd.schema_validator.node_types, \
                    f"Unknown node type '{node_type}' in {template_path}"

    @pytest.mark.parametrize("category,template_path", get_all_templates())
    def test_template_edge_types_valid(self, category, template_path):
        """Test that all edge types in template are defined in schema."""
        cd = CustomDiagrams()
        cd.load(template_path)

        # Validate the schema loads
        cd.validate(raise_on_error=False)

        # Check that edge types are registered
        for edge in cd.edges:
            edge_type = edge.get("type")
            if edge_type:
                assert edge_type in cd.schema_validator.edge_types, \
                    f"Unknown edge type '{edge_type}' in {template_path}"


class TestTemplateRendering:
    """Test that templates can generate DOT source."""

    @pytest.mark.parametrize("category,template_path", get_all_templates())
    def test_template_generates_dot(self, category, template_path):
        """Test that each template generates valid DOT source."""
        cd = CustomDiagrams()
        cd.load(template_path)
        cd.validate(raise_on_error=False)

        # Should generate DOT source without errors
        dot_source = cd.get_dot_source()

        assert dot_source, f"Template {template_path} generated empty DOT source"
        assert "digraph" in dot_source or "graph" in dot_source

    @pytest.mark.parametrize("category,template_path", get_all_templates())
    def test_template_stats(self, category, template_path):
        """Test that template stats are computed correctly."""
        cd = CustomDiagrams()
        cd.load(template_path)
        cd.validate(raise_on_error=False)

        stats = cd.get_stats()

        assert stats["total_nodes"] == len(cd.nodes)
        assert stats["total_edges"] == len(cd.edges)
        assert "node_types" in stats
        assert "edge_types" in stats


class TestTemplateContents:
    """Test specific template content requirements."""

    def test_flowchart_has_start_end(self):
        """Test that flowchart template has start and end nodes."""
        cd = CustomDiagrams()
        cd.load(TEMPLATES_DIR / "general" / "flowchart.toml")

        node_types = [n.get("type") for n in cd.nodes]
        assert "start" in node_types
        assert "end" in node_types

    def test_class_diagram_has_relationships(self):
        """Test that class diagram has UML relationships."""
        cd = CustomDiagrams()
        cd.load(TEMPLATES_DIR / "software" / "class-diagram.toml")

        edge_types = set(e.get("type") for e in cd.edges)
        assert "inherits" in edge_types or "implements" in edge_types

    def test_network_topology_has_devices(self):
        """Test that network topology has network devices."""
        cd = CustomDiagrams()
        cd.load(TEMPLATES_DIR / "network" / "topology.toml")

        node_types = set(n.get("type") for n in cd.nodes)
        network_types = {"router", "switch", "firewall", "server", "workstation"}
        assert node_types & network_types, "Network topology should have network device types"

    def test_risk_matrix_has_severity_levels(self):
        """Test that risk matrix has different severity levels."""
        cd = CustomDiagrams()
        cd.load(TEMPLATES_DIR / "security" / "risk-matrix.toml")

        node_types = set(n.get("type") for n in cd.nodes)
        risk_types = {"risk_critical", "risk_high", "risk_medium", "risk_low"}
        assert node_types & risk_types, "Risk matrix should have risk severity types"

    def test_org_chart_has_hierarchy(self):
        """Test that org chart has hierarchical structure."""
        cd = CustomDiagrams()
        cd.load(TEMPLATES_DIR / "business" / "org-chart.toml")

        node_types = set(n.get("type") for n in cd.nodes)
        org_types = {"executive", "director", "manager", "employee"}
        assert node_types & org_types, "Org chart should have organizational hierarchy types"


class TestTemplateSettings:
    """Test template settings and configuration."""

    @pytest.mark.parametrize("category,template_path", get_all_templates())
    def test_template_has_title(self, category, template_path):
        """Test that each template has a title."""
        cd = CustomDiagrams()
        cd.load(template_path)

        assert cd.settings.title
        assert cd.settings.title != "Custom Diagram"  # Should have custom title

    @pytest.mark.parametrize("category,template_path", get_all_templates())
    def test_template_has_valid_layout(self, category, template_path):
        """Test that each template has a valid layout."""
        cd = CustomDiagrams()
        cd.load(template_path)

        valid_layouts = {"hierarchical", "circular", "force", "grid", "radial", "compact", "sfdp"}
        assert cd.settings.layout in valid_layouts

    @pytest.mark.parametrize("category,template_path", get_all_templates())
    def test_template_has_valid_direction(self, category, template_path):
        """Test that each template has a valid direction."""
        cd = CustomDiagrams()
        cd.load(template_path)

        valid_directions = {"TB", "BT", "LR", "RL"}
        assert cd.settings.direction in valid_directions


# Count tests
def test_template_count():
    """Test that we have the expected number of templates."""
    templates = get_all_templates()
    assert len(templates) >= 17, f"Expected at least 17 templates, found {len(templates)}"

    # Count by category
    categories = {}
    for param in templates:
        category = param.values[0]  # First value in pytest.param is category
        categories[category] = categories.get(category, 0) + 1

    assert categories.get("general", 0) >= 4
    assert categories.get("software", 0) >= 7
    assert categories.get("network", 0) >= 3
    assert categories.get("security", 0) >= 3
    assert categories.get("business", 0) >= 3
