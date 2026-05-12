#
# VULNEX -Universal Security Visualization Library-
#
# File: test_privilegegradient.py
# Author: Simon Roses Femerling
# Created: 2026-02-14
# Last Modified: 2026-02-14
# Version: 0.4.0
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Unit tests for privilegegradient module."""

import os
import shutil
import sys
import tempfile
import json
import pytest

# Add src to path for testing
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from usecvislib.privilegegradient import PrivilegeGradient, PrivilegeGradientError
from usecvislib.builders import PrivilegeGradientBuilder

# Check if graphviz is installed
GRAPHVIZ_INSTALLED = shutil.which('dot') is not None


# =============================================================================
# Sample Test Data
# =============================================================================

VALID_GRADIENT = '''
[gradient]
name = "Test Privilege Gradient"
description = "Test gradient for unit tests"

[[zones]]
id = "Z0"
label = "Untrusted"
trust_level = 0
color = "#ffcccc"
border_color = "#cc0000"
font_color = "#660000"

[[zones]]
id = "Z1"
label = "Edge"
trust_level = 1
color = "#ffe0b2"
border_color = "#e65100"
font_color = "#663300"

[[zones]]
id = "Z2"
label = "Application"
trust_level = 2
color = "#fff9c4"
border_color = "#f9a825"
font_color = "#665500"

[[zones]]
id = "Z3"
label = "Control"
trust_level = 3
color = "#c8e6c9"
border_color = "#2e7d32"
font_color = "#1b5e20"

[[components]]
id = "browser"
label = "Browser"
zone = "Z0"

[[components]]
id = "gateway"
label = "API Gateway"
zone = "Z1"

[[components]]
id = "auth"
label = "Auth Service"
zone = "Z2"

[[components]]
id = "policy"
label = "Policy Engine"
zone = "Z3"

[[influence_types]]
id = "data"
label = "Data"
color = "#3498db"
style = "solid"
arrowhead = "vee"
penwidth = "1.5"

[[influence_types]]
id = "control"
label = "Control"
color = "#8e44ad"
style = "bold"
arrowhead = "dot"
penwidth = "2"

[[influences]]
id = "inf_1"
from = "gateway"
to = "browser"
type = "data"
label = "HTTP Response"

[[influences]]
id = "inf_2"
from = "auth"
to = "gateway"
type = "data"
label = "Auth Response"

[[influences]]
id = "inf_3"
from = "policy"
to = "auth"
type = "control"
label = "Policy Rules"

# Inversion: Z0 -> Z3 (trust gap 3 = critical)
[[influences]]
id = "inv_1"
from = "browser"
to = "policy"
type = "data"
label = "Policy Override"
'''

MINIMAL_GRADIENT = '''
[gradient]
name = "Minimal Gradient"

[[zones]]
id = "low"
label = "Low Trust"
trust_level = 0
color = "#ffcccc"
border_color = "#cc0000"
font_color = "#660000"

[[zones]]
id = "high"
label = "High Trust"
trust_level = 1
color = "#c8e6c9"
border_color = "#2e7d32"
font_color = "#1b5e20"

[[components]]
id = "comp_a"
label = "Component A"
zone = "low"

[[components]]
id = "comp_b"
label = "Component B"
zone = "high"

[[influences]]
from = "comp_a"
to = "comp_b"
type = "data"
'''

NO_INVERSIONS_GRADIENT = '''
[gradient]
name = "No Inversions"

[[zones]]
id = "Z0"
label = "Low"
trust_level = 0
color = "#ffcccc"
border_color = "#cc0000"
font_color = "#660000"

[[zones]]
id = "Z1"
label = "High"
trust_level = 1
color = "#c8e6c9"
border_color = "#2e7d32"
font_color = "#1b5e20"

[[components]]
id = "comp_a"
label = "A"
zone = "Z1"

[[components]]
id = "comp_b"
label = "B"
zone = "Z0"

[[influences]]
from = "comp_a"
to = "comp_b"
type = "data"
'''

MULTI_SEVERITY_GRADIENT = '''
[gradient]
name = "Multi-Severity Inversions"

[[zones]]
id = "Z0"
label = "Untrusted"
trust_level = 0
color = "#ffcccc"
border_color = "#cc0000"
font_color = "#660000"

[[zones]]
id = "Z1"
label = "Edge"
trust_level = 1
color = "#ffe0b2"
border_color = "#e65100"
font_color = "#663300"

[[zones]]
id = "Z2"
label = "App"
trust_level = 2
color = "#fff9c4"
border_color = "#f9a825"
font_color = "#665500"

[[zones]]
id = "Z3"
label = "Control"
trust_level = 3
color = "#c8e6c9"
border_color = "#2e7d32"
font_color = "#1b5e20"

[[zones]]
id = "Z4"
label = "Root"
trust_level = 4
color = "#bbdefb"
border_color = "#1565c0"
font_color = "#0d47a1"

[[components]]
id = "c0"
label = "C0"
zone = "Z0"

[[components]]
id = "c1"
label = "C1"
zone = "Z1"

[[components]]
id = "c2"
label = "C2"
zone = "Z2"

[[components]]
id = "c3"
label = "C3"
zone = "Z3"

[[components]]
id = "c4"
label = "C4"
zone = "Z4"

# Medium: Z1 -> Z2 (gap=1)
[[influences]]
from = "c1"
to = "c2"
type = "data"

# High: Z0 -> Z2 (gap=2)
[[influences]]
from = "c0"
to = "c2"
type = "data"

# Critical: Z0 -> Z3 (gap=3)
[[influences]]
from = "c0"
to = "c3"
type = "data"

# Critical: Z0 -> Z4 (gap=4)
[[influences]]
from = "c0"
to = "c4"
type = "data"
'''


# =============================================================================
# Test Classes
# =============================================================================

class TestPrivilegeGradientInit:
    """Tests for PrivilegeGradient initialization."""

    def test_init_defaults(self):
        pg = PrivilegeGradient("input.tml", "output", validate_paths=False)
        assert pg.format == "png"
        assert pg.styleid == "pg_default"
        assert pg.inputfile == "input.tml"
        assert pg.outputfile == "output"

    def test_init_custom_format(self):
        pg = PrivilegeGradient("input.tml", "output", format="svg", validate_paths=False)
        assert pg.format == "svg"

    def test_init_custom_style(self):
        pg = PrivilegeGradient("input.tml", "output", styleid="pg_dark", validate_paths=False)
        assert pg.styleid == "pg_dark"

    def test_init_graph_is_none(self):
        pg = PrivilegeGradient("input.tml", "output", validate_paths=False)
        assert pg.graph is None


class TestPrivilegeGradientLoad:
    """Tests for privilege gradient data loading."""

    def test_load_valid_file(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(VALID_GRADIENT)
            f.flush()
            try:
                pg = PrivilegeGradient(f.name, "output", validate_paths=False)
                pg.load()
                assert "gradient" in pg.inputdata
                assert pg.inputdata["gradient"]["name"] == "Test Privilege Gradient"
            finally:
                os.unlink(f.name)

    def test_load_missing_file(self):
        pg = PrivilegeGradient("/nonexistent/file.tml", "output", validate_paths=False)
        with pytest.raises(PrivilegeGradientError):
            pg.load()

    def test_load_json_file(self):
        data = {
            "gradient": {"name": "JSON Gradient"},
            "zones": [
                {"id": "low", "label": "Low", "trust_level": 0,
                 "color": "#ffcccc", "border_color": "#cc0000", "font_color": "#660000"},
                {"id": "high", "label": "High", "trust_level": 1,
                 "color": "#c8e6c9", "border_color": "#2e7d32", "font_color": "#1b5e20"},
            ],
            "components": [
                {"id": "a", "label": "A", "zone": "low"},
                {"id": "b", "label": "B", "zone": "high"},
            ],
            "influences": [
                {"from": "a", "to": "b", "type": "data"}
            ],
        }
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(data, f)
            f.flush()
            try:
                pg = PrivilegeGradient(f.name, "output", validate_paths=False)
                pg.load()
                assert pg.inputdata["gradient"]["name"] == "JSON Gradient"
            finally:
                os.unlink(f.name)

    def test_load_default_zones(self):
        """Test that default zones are used when none provided."""
        data = {
            "gradient": {"name": "No Zones"},
            "components": [
                {"id": "a", "label": "A", "zone": "Z0"},
            ],
            "influences": [],
        }
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(data, f)
            f.flush()
            try:
                pg = PrivilegeGradient(f.name, "output", validate_paths=False)
                pg.load()
                assert len(pg._zones) == 5  # default zones
                assert "Z0" in pg._zones
            finally:
                os.unlink(f.name)

    def test_load_default_influence_types(self):
        """Test that default influence types are used when none provided."""
        data = {
            "gradient": {"name": "No Types"},
            "zones": [
                {"id": "low", "label": "Low", "trust_level": 0,
                 "color": "#ffcccc", "border_color": "#cc0000", "font_color": "#660000"},
                {"id": "high", "label": "High", "trust_level": 1,
                 "color": "#c8e6c9", "border_color": "#2e7d32", "font_color": "#1b5e20"},
            ],
            "components": [],
            "influences": [],
        }
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(data, f)
            f.flush()
            try:
                pg = PrivilegeGradient(f.name, "output", validate_paths=False)
                pg.load()
                assert "data" in pg._influence_types
                assert "feedback" in pg._influence_types
                assert "resource" in pg._influence_types
                assert "control" in pg._influence_types
            finally:
                os.unlink(f.name)


class TestPrivilegeGradientValidation:
    """Tests for privilege gradient validation."""

    def test_validate_valid_config(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(VALID_GRADIENT)
            f.flush()
            try:
                pg = PrivilegeGradient(f.name, "output", validate_paths=False)
                errors = pg.validate()
                assert len(errors) == 0
            finally:
                os.unlink(f.name)

    def test_validate_missing_gradient_section(self):
        data = {
            "zones": [
                {"id": "z1", "label": "Z1", "trust_level": 0,
                 "color": "#fff", "border_color": "#000", "font_color": "#000"},
                {"id": "z2", "label": "Z2", "trust_level": 1,
                 "color": "#fff", "border_color": "#000", "font_color": "#000"},
            ],
            "components": [],
            "influences": [],
        }
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(data, f)
            f.flush()
            try:
                pg = PrivilegeGradient(f.name, "output", validate_paths=False)
                errors = pg.validate()
                assert any("gradient" in e.lower() for e in errors)
            finally:
                os.unlink(f.name)

    def test_validate_invalid_zone_ref(self):
        data = {
            "gradient": {"name": "Bad Ref"},
            "zones": [
                {"id": "z1", "label": "Z1", "trust_level": 0,
                 "color": "#fff", "border_color": "#000", "font_color": "#000"},
                {"id": "z2", "label": "Z2", "trust_level": 1,
                 "color": "#fff", "border_color": "#000", "font_color": "#000"},
            ],
            "components": [
                {"id": "comp1", "label": "Comp 1", "zone": "nonexistent_zone"},
            ],
            "influences": [],
        }
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(data, f)
            f.flush()
            try:
                pg = PrivilegeGradient(f.name, "output", validate_paths=False)
                errors = pg.validate()
                assert any("nonexistent_zone" in e for e in errors)
            finally:
                os.unlink(f.name)

    def test_validate_invalid_influence_from(self):
        data = {
            "gradient": {"name": "Bad From"},
            "zones": [
                {"id": "z1", "label": "Z1", "trust_level": 0,
                 "color": "#fff", "border_color": "#000", "font_color": "#000"},
                {"id": "z2", "label": "Z2", "trust_level": 1,
                 "color": "#fff", "border_color": "#000", "font_color": "#000"},
            ],
            "components": [
                {"id": "comp1", "label": "Comp 1", "zone": "z1"},
            ],
            "influences": [
                {"from": "nonexistent", "to": "comp1", "type": "data"},
            ],
        }
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(data, f)
            f.flush()
            try:
                pg = PrivilegeGradient(f.name, "output", validate_paths=False)
                errors = pg.validate()
                assert any("nonexistent" in e for e in errors)
            finally:
                os.unlink(f.name)

    def test_validate_too_few_zones(self):
        data = {
            "gradient": {"name": "One Zone"},
            "zones": [
                {"id": "z1", "label": "Z1", "trust_level": 0,
                 "color": "#fff", "border_color": "#000", "font_color": "#000"},
            ],
            "components": [],
            "influences": [],
        }
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(data, f)
            f.flush()
            try:
                pg = PrivilegeGradient(f.name, "output", validate_paths=False)
                errors = pg.validate()
                assert any("2 trust zones" in e for e in errors)
            finally:
                os.unlink(f.name)


class TestPrivilegeGradientInversions:
    """Tests for inversion detection."""

    def test_detect_inversions(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(VALID_GRADIENT)
            f.flush()
            try:
                pg = PrivilegeGradient(f.name, "output", validate_paths=False)
                pg.load()
                inversions = pg.detect_inversions()
                assert len(inversions) == 1
                assert inversions[0]["from"] == "browser"
                assert inversions[0]["to"] == "policy"
            finally:
                os.unlink(f.name)

    def test_no_inversions(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(NO_INVERSIONS_GRADIENT)
            f.flush()
            try:
                pg = PrivilegeGradient(f.name, "output", validate_paths=False)
                pg.load()
                inversions = pg.detect_inversions()
                assert len(inversions) == 0
            finally:
                os.unlink(f.name)

    def test_inversion_severity_critical(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(VALID_GRADIENT)
            f.flush()
            try:
                pg = PrivilegeGradient(f.name, "output", validate_paths=False)
                pg.load()
                inversions = pg.detect_inversions()
                # browser(Z0) -> policy(Z3), gap=3 -> critical
                assert inversions[0]["severity"] == "critical"
                assert inversions[0]["trust_gap"] == 3
            finally:
                os.unlink(f.name)

    def test_multi_severity_inversions(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(MULTI_SEVERITY_GRADIENT)
            f.flush()
            try:
                pg = PrivilegeGradient(f.name, "output", validate_paths=False)
                pg.load()
                inversions = pg.detect_inversions()
                severities = {inv["severity"] for inv in inversions}
                assert "medium" in severities
                assert "high" in severities
                assert "critical" in severities
            finally:
                os.unlink(f.name)

    def test_inversion_summary(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(MULTI_SEVERITY_GRADIENT)
            f.flush()
            try:
                pg = PrivilegeGradient(f.name, "output", validate_paths=False)
                pg.load()
                summary = pg.get_inversion_summary()
                assert summary["total"] == 4
                assert summary["by_severity"]["medium"] == 1
                assert summary["by_severity"]["high"] == 1
                assert summary["by_severity"]["critical"] == 2
            finally:
                os.unlink(f.name)


class TestPrivilegeGradientStats:
    """Tests for statistics."""

    def test_get_stats(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(VALID_GRADIENT)
            f.flush()
            try:
                pg = PrivilegeGradient(f.name, "output", validate_paths=False)
                stats = pg.get_stats()
                assert stats["name"] == "Test Privilege Gradient"
                assert stats["total_zones"] == 4
                assert stats["total_components"] == 4
                assert stats["total_influences"] == 4
                assert stats["total_inversions"] == 1
            finally:
                os.unlink(f.name)

    def test_stats_components_per_zone(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(VALID_GRADIENT)
            f.flush()
            try:
                pg = PrivilegeGradient(f.name, "output", validate_paths=False)
                stats = pg.get_stats()
                cpz = stats["components_per_zone"]
                assert cpz["Z0"] == 1
                assert cpz["Z1"] == 1
                assert cpz["Z2"] == 1
                assert cpz["Z3"] == 1
            finally:
                os.unlink(f.name)

    def test_stats_max_trust_gap(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(VALID_GRADIENT)
            f.flush()
            try:
                pg = PrivilegeGradient(f.name, "output", validate_paths=False)
                stats = pg.get_stats()
                assert stats["max_trust_gap"] == 3
            finally:
                os.unlink(f.name)

    def test_zone_influence_matrix(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(VALID_GRADIENT)
            f.flush()
            try:
                pg = PrivilegeGradient(f.name, "output", validate_paths=False)
                pg.load()
                matrix = pg.get_zone_influence_matrix()
                assert isinstance(matrix, dict)
                assert "Z0" in matrix
                # browser->policy is Z0->Z3 (the inversion)
                assert matrix["Z0"]["Z3"] == 1
                # gateway->browser is Z1->Z0
                assert matrix["Z1"]["Z0"] == 1
            finally:
                os.unlink(f.name)


class TestPrivilegeGradientRender:
    """Tests for rendering."""

    def test_render_creates_graph(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(VALID_GRADIENT)
            f.flush()
            try:
                pg = PrivilegeGradient(f.name, "output", validate_paths=False)
                pg.load()
                pg.render()
                assert pg.graph is not None
            finally:
                os.unlink(f.name)

    def test_render_without_load_raises(self):
        pg = PrivilegeGradient("/nonexistent/input.tml", "output", validate_paths=False)
        with pytest.raises(PrivilegeGradientError):
            pg.render()

    @pytest.mark.skipif(not GRAPHVIZ_INSTALLED, reason="Graphviz not installed")
    def test_full_build_dot(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(VALID_GRADIENT)
            f.flush()
            try:
                with tempfile.TemporaryDirectory() as tmpdir:
                    output = os.path.join(tmpdir, "output")
                    pg = PrivilegeGradient(f.name, output, format="dot")
                    pg.BuildPrivilegeGradient()
                    assert os.path.exists(f"{output}.dot")
            finally:
                os.unlink(f.name)

    @pytest.mark.skipif(not GRAPHVIZ_INSTALLED, reason="Graphviz not installed")
    def test_full_build_png(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(VALID_GRADIENT)
            f.flush()
            try:
                with tempfile.TemporaryDirectory() as tmpdir:
                    output = os.path.join(tmpdir, "output")
                    pg = PrivilegeGradient(f.name, output, format="png")
                    pg.BuildPrivilegeGradient()
                    assert os.path.exists(f"{output}.png")
            finally:
                os.unlink(f.name)

    @pytest.mark.skipif(not GRAPHVIZ_INSTALLED, reason="Graphviz not installed")
    def test_full_build_svg(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(VALID_GRADIENT)
            f.flush()
            try:
                with tempfile.TemporaryDirectory() as tmpdir:
                    output = os.path.join(tmpdir, "output")
                    pg = PrivilegeGradient(f.name, output, format="svg")
                    pg.BuildPrivilegeGradient()
                    assert os.path.exists(f"{output}.svg")
            finally:
                os.unlink(f.name)


class TestPrivilegeGradientBuilder:
    """Tests for the PrivilegeGradientBuilder."""

    def test_builder_init(self):
        builder = PrivilegeGradientBuilder("Test Graph")
        data = builder.build()
        assert data["gradient"]["name"] == "Test Graph"
        assert len(data["zones"]) == 5  # defaults
        assert len(data["influence_types"]) == 4  # defaults

    def test_builder_no_defaults(self):
        builder = PrivilegeGradientBuilder(
            "Custom", use_default_zones=False, use_default_influence_types=False
        )
        data = builder.build()
        assert len(data["zones"]) == 0
        assert len(data["influence_types"]) == 0

    def test_builder_add_zone(self):
        builder = PrivilegeGradientBuilder("Test", use_default_zones=False)
        builder.add_zone("z1", "Zone 1", 0, "#fff", "#000", "#333")
        data = builder.build()
        assert len(data["zones"]) == 1
        assert data["zones"][0]["id"] == "z1"

    def test_builder_add_component(self):
        builder = PrivilegeGradientBuilder("Test")
        builder.add_component("comp1", "Component 1", "Z0")
        data = builder.build()
        assert len(data["components"]) == 1
        assert data["components"][0]["id"] == "comp1"
        assert data["components"][0]["zone"] == "Z0"

    def test_builder_add_influence(self):
        builder = PrivilegeGradientBuilder("Test")
        builder.add_component("a", "A", "Z0")
        builder.add_component("b", "B", "Z1")
        builder.add_influence("a", "b", "data", "HTTP")
        data = builder.build()
        assert len(data["influences"]) == 1
        assert data["influences"][0]["from"] == "a"
        assert data["influences"][0]["to"] == "b"

    def test_builder_convenience_methods(self):
        builder = PrivilegeGradientBuilder("Test")
        builder.add_component("a", "A", "Z0")
        builder.add_component("b", "B", "Z1")
        builder.add_data_influence("a", "b", "Data")
        builder.add_feedback_influence("b", "a", "Feedback")
        builder.add_resource_influence("a", "b", "Resource")
        builder.add_control_influence("b", "a", "Control")
        data = builder.build()
        assert len(data["influences"]) == 4
        types = [inf["type"] for inf in data["influences"]]
        assert "data" in types
        assert "feedback" in types
        assert "resource" in types
        assert "control" in types

    def test_builder_fluent_chaining(self):
        builder = (
            PrivilegeGradientBuilder("Test")
            .add_component("a", "A", "Z0")
            .add_component("b", "B", "Z1")
            .add_data_influence("a", "b")
            .set_gradient_attribute("version", "1.0")
        )
        data = builder.build()
        assert data["gradient"]["version"] == "1.0"
        assert len(data["components"]) == 2
        assert len(data["influences"]) == 1

    def test_builder_to_json(self):
        builder = PrivilegeGradientBuilder("Test")
        builder.add_component("a", "A", "Z0")
        json_str = builder.to_json()
        parsed = json.loads(json_str)
        assert parsed["gradient"]["name"] == "Test"
        assert len(parsed["components"]) == 1

    @pytest.mark.skipif(not GRAPHVIZ_INSTALLED, reason="Graphviz not installed")
    def test_builder_to_privilege_gradient(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output = os.path.join(tmpdir, "output")
            pg = (
                PrivilegeGradientBuilder("Builder Test")
                .add_component("a", "A", "Z0")
                .add_component("b", "B", "Z1")
                .add_data_influence("a", "b", "Flow")
                .to_privilege_gradient(output, format="dot")
            )
            pg.BuildPrivilegeGradient()
            assert os.path.exists(f"{output}.dot")


class TestPrivilegeGradientStyles:
    """Tests for style loading."""

    def test_load_default_style(self):
        pg = PrivilegeGradient("input.tml", "output", styleid="pg_default", validate_paths=False)
        assert pg.styleid == "pg_default"
        assert "graph" in pg.style
        assert "zone" in pg.style
        assert "component" in pg.style
        assert "inversion" in pg.style

    def test_load_dark_style(self):
        pg = PrivilegeGradient("input.tml", "output", styleid="pg_dark", validate_paths=False)
        assert pg.styleid == "pg_dark"
        assert "graph" in pg.style

    def test_load_security_style(self):
        pg = PrivilegeGradient("input.tml", "output", styleid="pg_security", validate_paths=False)
        assert pg.styleid == "pg_security"
        assert "graph" in pg.style

    def test_load_neon_style(self):
        pg = PrivilegeGradient("input.tml", "output", styleid="pg_neon", validate_paths=False)
        assert pg.styleid == "pg_neon"
        assert "graph" in pg.style

    def test_load_corporate_style(self):
        pg = PrivilegeGradient("input.tml", "output", styleid="pg_corporate", validate_paths=False)
        assert pg.styleid == "pg_corporate"
        assert "graph" in pg.style

    def test_fallback_to_default_for_unknown_style(self):
        pg = PrivilegeGradient("input.tml", "output", styleid="pg_nonexistent", validate_paths=False)
        # Should fall back to default style
        assert "graph" in pg.style


class TestPrivilegeGradientAnalysis:
    """Tests for analysis methods."""

    def test_find_influence_paths(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(VALID_GRADIENT)
            f.flush()
            try:
                pg = PrivilegeGradient(f.name, "output", validate_paths=False)
                pg.load()
                paths = pg.find_influence_paths("browser", "auth")
                assert len(paths) >= 1
                assert paths[0][0] == "browser"
                assert paths[0][-1] == "auth"
            finally:
                os.unlink(f.name)

    def test_find_influence_paths_not_exists(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(VALID_GRADIENT)
            f.flush()
            try:
                pg = PrivilegeGradient(f.name, "output", validate_paths=False)
                pg.load()
                paths = pg.find_influence_paths("browser", "nonexistent")
                # No path to a non-existent component
                assert len(paths) == 0
            finally:
                os.unlink(f.name)

    def test_analyze_critical_components(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(VALID_GRADIENT)
            f.flush()
            try:
                pg = PrivilegeGradient(f.name, "output", validate_paths=False)
                pg.load()
                critical = pg.analyze_critical_components(top_n=5)
                assert isinstance(critical, list)
                assert len(critical) > 0
                for comp in critical:
                    assert "id" in comp
                    assert "degree_centrality" in comp
                    assert "zone" in comp
            finally:
                os.unlink(f.name)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
