#
# VULNEX -Universal Security Visualization Library-
#
# File: tests/test_custom_shapes.py
# Author: Simon Roses Femerling
# Created: 2025-12-29
# Last Modified: 2025-12-29
# Version: 0.3.1
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Comprehensive tests for custom shape functionality.

Tests cover:
- SVG-based custom shapes (file and inline)
- DOT-based custom shapes
- Error handling and validation
- Integration with CustomDiagrams
- End-to-end rendering
"""

import base64
import pytest
import tempfile
from pathlib import Path

from usecvislib.shapes import (
    CustomShapeLoader,
    CustomShapeError,
    ShapeRegistry,
    ShapeCategory,
    register_custom_shapes,
)
from usecvislib import CustomDiagrams


# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture
def registry():
    """Create a fresh registry for testing."""
    return ShapeRegistry()


@pytest.fixture
def loader(registry):
    """Create a CustomShapeLoader instance."""
    return CustomShapeLoader(registry)


@pytest.fixture
def valid_svg():
    """A valid minimal SVG string."""
    return '''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">
        <circle cx="50" cy="50" r="40" fill="blue"/>
    </svg>'''


@pytest.fixture
def svg_file(valid_svg, tmp_path):
    """Create a temporary SVG file."""
    svg_path = tmp_path / "test_shape.svg"
    svg_path.write_text(valid_svg)
    return svg_path


@pytest.fixture
def custom_shapes_dir(tmp_path):
    """Create a directory with custom shapes."""
    shapes_dir = tmp_path / "custom_shapes"
    shapes_dir.mkdir()

    # Create a simple SVG file
    (shapes_dir / "router.svg").write_text('''
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
            <rect x="4" y="20" width="56" height="24" fill="#3498DB" rx="4"/>
            <circle cx="12" cy="32" r="3" fill="#2ECC71"/>
            <circle cx="22" cy="32" r="3" fill="#F1C40F"/>
        </svg>
    ''')

    (shapes_dir / "firewall.svg").write_text('''
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
            <rect x="8" y="8" width="48" height="48" fill="#E74C3C"/>
            <path d="M20 20 L44 20 L44 44 L20 44 Z" fill="#C0392B"/>
        </svg>
    ''')

    return shapes_dir


# =============================================================================
# SVG Shape Tests
# =============================================================================


class TestSVGShapes:
    """Tests for SVG-based custom shapes."""

    def test_load_svg_from_inline_data(self, registry, valid_svg):
        """Test loading SVG shape from inline data."""
        config = {
            "custom_shapes": {
                "my_circle": {
                    "type": "svg",
                    "svg_data": valid_svg,
                    "width": 50,
                    "height": 50,
                    "name": "My Circle",
                    "description": "A blue circle",
                }
            }
        }

        loader = CustomShapeLoader(registry)
        count = loader.load_custom_shapes(config)

        assert count == 1
        shape = registry.get_shape("my_circle")
        assert shape is not None
        assert shape.name == "My Circle"
        assert shape.category == ShapeCategory.CUSTOM
        assert shape.custom is True
        assert "svg" in shape.tags
        assert shape.svg_data is not None

    def test_load_svg_from_file(self, registry, svg_file):
        """Test loading SVG shape from file path."""
        config = {
            "custom_shapes": {
                "file_shape": {
                    "type": "svg",
                    "svg_path": str(svg_file),
                    "width": 64,
                    "height": 64,
                }
            }
        }

        loader = CustomShapeLoader(registry)
        count = loader.load_custom_shapes(config, base_path=svg_file.parent)

        assert count == 1
        shape = registry.get_shape("file_shape")
        assert shape is not None
        assert shape.custom is True

    def test_load_svg_relative_path(self, registry, custom_shapes_dir):
        """Test loading SVG with relative path."""
        config = {
            "custom_shapes": {
                "router": {
                    "type": "svg",
                    "svg_path": "router.svg",
                    "width": 64,
                    "height": 64,
                }
            }
        }

        loader = CustomShapeLoader(registry)
        count = loader.load_custom_shapes(config, base_path=custom_shapes_dir)

        assert count == 1
        shape = registry.get_shape("router")
        assert shape is not None

    def test_svg_generates_data_uri(self, loader, valid_svg):
        """Test that SVG is converted to data URI correctly."""
        data_uri = loader._svg_to_data_uri(valid_svg)

        assert data_uri.startswith("data:image/svg+xml;base64,")

        # Verify it can be decoded back
        encoded_part = data_uri.split(",", 1)[1]
        decoded = base64.b64decode(encoded_part).decode("utf-8")
        assert "<svg" in decoded

    def test_svg_shape_graphviz_attrs(self, registry, valid_svg):
        """Test that SVG shapes have correct Graphviz attributes."""
        config = {
            "custom_shapes": {
                "test_svg": {
                    "type": "svg",
                    "svg_data": valid_svg,
                    "width": 50,
                    "height": 50,
                }
            }
        }

        loader = CustomShapeLoader(registry)
        loader.load_custom_shapes(config)

        shape = registry.get_shape("test_svg")
        assert shape.graphviz["shape"] == "none"
        assert "image" in shape.graphviz
        assert shape.graphviz["imagepos"] == "mc"
        assert shape.graphviz["fixedsize"] == "true"

    def test_svg_custom_ports(self, registry, valid_svg):
        """Test SVG shape with custom ports."""
        config = {
            "custom_shapes": {
                "ported_shape": {
                    "type": "svg",
                    "svg_data": valid_svg,
                    "width": 50,
                    "height": 50,
                    "ports": ["n", "s"],
                }
            }
        }

        loader = CustomShapeLoader(registry)
        loader.load_custom_shapes(config)

        shape = registry.get_shape("ported_shape")
        assert shape.ports == ["n", "s"]


class TestSVGValidation:
    """Tests for SVG validation."""

    def test_empty_svg_rejected(self, loader):
        """Test that empty SVG content is rejected."""
        with pytest.raises(CustomShapeError, match="empty"):
            loader._validate_svg("")

    def test_whitespace_only_svg_rejected(self, loader):
        """Test that whitespace-only SVG is rejected."""
        with pytest.raises(CustomShapeError, match="empty"):
            loader._validate_svg("   \n\t  ")

    def test_non_svg_content_rejected(self, loader):
        """Test that non-SVG content is rejected."""
        with pytest.raises(CustomShapeError, match="not.*valid SVG"):
            loader._validate_svg("<html><body>Not SVG</body></html>")

    def test_script_tag_rejected(self, loader):
        """Test that SVG with script tag is rejected."""
        malicious = '<svg><script>alert("xss")</script></svg>'
        with pytest.raises(CustomShapeError, match="dangerous"):
            loader._validate_svg(malicious)

    def test_javascript_handler_rejected(self, loader):
        """Test that SVG with JavaScript handlers is rejected."""
        malicious = '<svg onclick="alert(1)"><circle/></svg>'
        with pytest.raises(CustomShapeError, match="dangerous"):
            loader._validate_svg(malicious)

    def test_onload_handler_rejected(self, loader):
        """Test that SVG with onload handler is rejected."""
        malicious = '<svg onload="malicious()"><circle/></svg>'
        with pytest.raises(CustomShapeError, match="dangerous"):
            loader._validate_svg(malicious)

    def test_javascript_url_rejected(self, loader):
        """Test that SVG with javascript: URL is rejected."""
        malicious = '<svg><a href="javascript:evil()"><circle/></a></svg>'
        with pytest.raises(CustomShapeError, match="dangerous"):
            loader._validate_svg(malicious)

    def test_foreignobject_rejected(self, loader):
        """Test that SVG with foreignObject is rejected."""
        malicious = '<svg><foreignObject><html></html></foreignObject></svg>'
        with pytest.raises(CustomShapeError, match="dangerous"):
            loader._validate_svg(malicious)

    def test_iframe_rejected(self, loader):
        """Test that SVG with iframe is rejected."""
        malicious = '<svg><iframe src="evil.html"/></svg>'
        with pytest.raises(CustomShapeError, match="dangerous"):
            loader._validate_svg(malicious)

    def test_valid_svg_passes(self, loader, valid_svg):
        """Test that valid SVG passes validation."""
        result = loader._validate_svg(valid_svg)
        assert result == valid_svg


class TestSVGFileLoading:
    """Tests for SVG file loading."""

    def test_load_existing_file(self, loader, svg_file):
        """Test loading an existing SVG file."""
        content = loader._load_svg_file(str(svg_file))
        assert "<svg" in content

    def test_load_nonexistent_file(self, loader, tmp_path):
        """Test loading a nonexistent file raises error."""
        with pytest.raises(CustomShapeError, match="not found"):
            loader._load_svg_file(str(tmp_path / "nonexistent.svg"))

    def test_load_directory_rejected(self, loader, tmp_path):
        """Test that loading a directory raises error."""
        with pytest.raises(CustomShapeError, match="not a file"):
            loader._load_svg_file(str(tmp_path))

    def test_load_oversized_file(self, loader, tmp_path):
        """Test that oversized SVG file is rejected."""
        large_file = tmp_path / "large.svg"
        # Create a file larger than MAX_SVG_SIZE (512KB)
        large_file.write_text("<svg>" + "x" * (600 * 1024) + "</svg>")

        with pytest.raises(CustomShapeError, match="too large"):
            loader._load_svg_file(str(large_file))


class TestDimensionValidation:
    """Tests for dimension validation."""

    def test_valid_dimensions(self, loader):
        """Test that valid dimensions pass."""
        loader._validate_dimensions(50, 50)  # Should not raise
        loader._validate_dimensions(10, 10)  # Minimum
        loader._validate_dimensions(500, 500)  # Maximum

    def test_width_too_small(self, loader):
        """Test that width too small is rejected."""
        with pytest.raises(CustomShapeError, match="Width"):
            loader._validate_dimensions(5, 50)

    def test_width_too_large(self, loader):
        """Test that width too large is rejected."""
        with pytest.raises(CustomShapeError, match="Width"):
            loader._validate_dimensions(600, 50)

    def test_height_too_small(self, loader):
        """Test that height too small is rejected."""
        with pytest.raises(CustomShapeError, match="Height"):
            loader._validate_dimensions(50, 5)

    def test_height_too_large(self, loader):
        """Test that height too large is rejected."""
        with pytest.raises(CustomShapeError, match="Height"):
            loader._validate_dimensions(50, 600)

    def test_non_numeric_dimensions(self, loader):
        """Test that non-numeric dimensions are rejected."""
        with pytest.raises(CustomShapeError, match="numbers"):
            loader._validate_dimensions("50", 50)


# =============================================================================
# DOT Shape Tests
# =============================================================================


class TestDOTShapes:
    """Tests for DOT-based custom shapes."""

    def test_load_dot_shape_basic(self, registry):
        """Test loading a basic DOT shape."""
        config = {
            "custom_shapes": {
                "my_box": {
                    "type": "dot",
                    "dot_definition": "shape=box",
                }
            }
        }

        loader = CustomShapeLoader(registry)
        loader.load_custom_shapes(config)

        shape = registry.get_shape("my_box")
        assert shape is not None
        assert shape.graphviz["shape"] == "box"
        assert shape.custom is True
        assert "dot" in shape.tags

    def test_load_dot_shape_with_multiple_attrs(self, registry):
        """Test loading DOT shape with multiple attributes."""
        config = {
            "custom_shapes": {
                "fancy_polygon": {
                    "type": "dot",
                    "name": "Fancy Polygon",
                    "dot_definition": """
                        shape=polygon
                        sides=6
                        skew=0.4
                        distortion=0.2
                    """,
                }
            }
        }

        loader = CustomShapeLoader(registry)
        loader.load_custom_shapes(config)

        shape = registry.get_shape("fancy_polygon")
        assert shape.graphviz["shape"] == "polygon"
        assert shape.graphviz["sides"] == "6"
        assert shape.graphviz["skew"] == "0.4"

    def test_load_dot_shape_with_graphviz_dict(self, registry):
        """Test loading DOT shape with graphviz dictionary."""
        config = {
            "custom_shapes": {
                "styled_node": {
                    "type": "dot",
                    "graphviz": {
                        "shape": "ellipse",
                        "style": "filled,bold",
                        "penwidth": "2",
                    },
                    "style": {"fillcolor": "#3498DB", "fontcolor": "white"},
                }
            }
        }

        loader = CustomShapeLoader(registry)
        loader.load_custom_shapes(config)

        shape = registry.get_shape("styled_node")
        assert shape.graphviz["shape"] == "ellipse"
        assert shape.graphviz["style"] == "filled,bold"
        assert shape.default_style["fillcolor"] == "#3498DB"

    def test_dot_default_shape(self, registry):
        """Test DOT shape defaults to box when no definition."""
        config = {
            "custom_shapes": {
                "empty_def": {
                    "type": "dot",
                    "name": "Empty Definition",
                }
            }
        }

        loader = CustomShapeLoader(registry)
        loader.load_custom_shapes(config)

        shape = registry.get_shape("empty_def")
        assert shape.graphviz["shape"] == "box"


class TestDOTDefinitionParsing:
    """Tests for DOT definition string parsing."""

    def test_parse_newline_separated(self, loader):
        """Test parsing newline-separated attributes."""
        result = loader._parse_dot_definition("shape=box\nstyle=filled")
        assert result == {"shape": "box", "style": "filled"}

    def test_parse_comma_separated(self, loader):
        """Test parsing comma-separated attributes."""
        result = loader._parse_dot_definition("shape=diamond, fillcolor=red")
        assert result == {"shape": "diamond", "fillcolor": "red"}

    def test_parse_semicolon_separated(self, loader):
        """Test parsing semicolon-separated attributes."""
        result = loader._parse_dot_definition("shape=circle; label=test")
        assert result == {"shape": "circle", "label": "test"}

    def test_parse_mixed_separators(self, loader):
        """Test parsing with mixed separators."""
        result = loader._parse_dot_definition("shape=box, style=filled; color=blue\npenwidth=2")
        assert result == {"shape": "box", "style": "filled", "color": "blue", "penwidth": "2"}

    def test_parse_quoted_values(self, loader):
        """Test parsing values with quotes."""
        result = loader._parse_dot_definition('shape=box, label="Hello World"')
        assert result["label"] == "Hello World"

    def test_parse_bare_shape_name(self, loader):
        """Test parsing bare shape name."""
        result = loader._parse_dot_definition("circle")
        assert result == {"shape": "circle"}

    def test_parse_empty_definition(self, loader):
        """Test parsing empty definition."""
        result = loader._parse_dot_definition("")
        assert result == {}

    def test_parse_whitespace_handling(self, loader):
        """Test whitespace is handled correctly."""
        result = loader._parse_dot_definition("  shape = box  ,  style = filled  ")
        assert result == {"shape": "box", "style": "filled"}


# =============================================================================
# Error Handling Tests
# =============================================================================


class TestErrorHandling:
    """Tests for error handling."""

    def test_unknown_shape_type(self, registry):
        """Test that unknown shape type raises error."""
        config = {
            "custom_shapes": {
                "bad_shape": {
                    "type": "unknown",
                }
            }
        }

        loader = CustomShapeLoader(registry)
        with pytest.raises(CustomShapeError, match="Unknown.*type"):
            loader.load_custom_shapes(config)

    def test_svg_missing_path_and_data(self, registry):
        """Test SVG shape without path or data raises error."""
        config = {
            "custom_shapes": {
                "incomplete_svg": {
                    "type": "svg",
                    "width": 50,
                    "height": 50,
                }
            }
        }

        loader = CustomShapeLoader(registry)
        with pytest.raises(CustomShapeError, match="svg_path.*svg_data"):
            loader.load_custom_shapes(config)

    def test_svg_file_not_found(self, registry, tmp_path):
        """Test SVG with nonexistent file raises error."""
        config = {
            "custom_shapes": {
                "missing_svg": {
                    "type": "svg",
                    "svg_path": "nonexistent.svg",
                }
            }
        }

        loader = CustomShapeLoader(registry)
        with pytest.raises(CustomShapeError, match="not found"):
            loader.load_custom_shapes(config, base_path=tmp_path)


# =============================================================================
# Integration Tests
# =============================================================================


class TestCustomDiagramsIntegration:
    """Tests for integration with CustomDiagrams."""

    def test_custom_shapes_loaded_on_diagram_load(self, valid_svg, tmp_path):
        """Test custom shapes are loaded when loading diagram config."""
        config_path = tmp_path / "diagram.toml"
        config_path.write_text(f'''
[diagram]
title = "Custom Shapes Test"

[schema.nodes.custom_node]
shape = "my_custom"
required_fields = ["name"]

[custom_shapes.my_custom]
type = "svg"
svg_data = """{valid_svg}"""
width = 50
height = 50

[[nodes]]
id = "n1"
type = "custom_node"
name = "Test Node"
''')

        cd = CustomDiagrams()
        cd.load(config_path)

        # Custom shape should be in registry
        assert cd.shape_registry.has_shape("my_custom")
        shape = cd.shape_registry.get_shape("my_custom")
        assert shape.custom is True

    def test_dot_custom_shape_in_diagram(self, tmp_path):
        """Test DOT custom shape renders in diagram."""
        config_path = tmp_path / "diagram.toml"
        config_path.write_text('''
[diagram]
title = "DOT Custom Shape Test"

[schema.nodes.hexnode]
shape = "hex_shape"
required_fields = ["name"]

[custom_shapes.hex_shape]
type = "dot"
dot_definition = "shape=hexagon"

[[nodes]]
id = "h1"
type = "hexnode"
name = "Hex Node"
''')

        cd = CustomDiagrams()
        cd.load(config_path)
        cd.validate()  # Validate loads the schema

        dot_source = cd.get_dot_source()
        assert "shape=hexagon" in dot_source

    def test_multiple_custom_shapes(self, valid_svg, tmp_path):
        """Test loading multiple custom shapes."""
        config_path = tmp_path / "diagram.toml"
        config_path.write_text(f'''
[diagram]
title = "Multiple Custom Shapes"

[schema.nodes.svg_type]
shape = "svg_shape"
required_fields = ["name"]

[schema.nodes.dot_type]
shape = "dot_shape"
required_fields = ["name"]

[custom_shapes.svg_shape]
type = "svg"
svg_data = """{valid_svg}"""
width = 50
height = 50

[custom_shapes.dot_shape]
type = "dot"
graphviz = {{ shape = "diamond" }}

[[nodes]]
id = "s1"
type = "svg_type"
name = "SVG Node"

[[nodes]]
id = "d1"
type = "dot_type"
name = "DOT Node"
''')

        cd = CustomDiagrams()
        cd.load(config_path)

        assert cd.shape_registry.has_shape("svg_shape")
        assert cd.shape_registry.has_shape("dot_shape")

        stats = cd.get_stats()
        assert stats["custom_shapes"] == 2

    def test_custom_shape_with_edges(self, valid_svg, tmp_path):
        """Test custom shapes work with edges."""
        config_path = tmp_path / "diagram.toml"
        config_path.write_text(f'''
[diagram]
title = "Custom Shapes with Edges"

[schema.nodes.custom]
shape = "my_shape"
required_fields = ["name"]

[schema.edges.link]
style = "solid"
color = "#333333"

[custom_shapes.my_shape]
type = "dot"
graphviz = {{ shape = "oval" }}

[[nodes]]
id = "a"
type = "custom"
name = "Node A"

[[nodes]]
id = "b"
type = "custom"
name = "Node B"

[[edges]]
from = "a"
to = "b"
type = "link"
''')

        cd = CustomDiagrams()
        cd.load(config_path)
        cd.validate()  # Validate loads the schema

        dot_source = cd.get_dot_source()
        assert 'a -> b' in dot_source


# =============================================================================
# Convenience Function Tests
# =============================================================================


class TestConvenienceFunctions:
    """Tests for module-level convenience functions."""

    def test_register_custom_shapes_function(self, registry, valid_svg):
        """Test register_custom_shapes convenience function."""
        config = {
            "custom_shapes": {
                "test_shape": {
                    "type": "svg",
                    "svg_data": valid_svg,
                    "width": 50,
                    "height": 50,
                }
            }
        }

        count = register_custom_shapes(registry, config)
        assert count == 1
        assert registry.has_shape("test_shape")

    def test_register_custom_shapes_with_base_path(self, registry, custom_shapes_dir):
        """Test register_custom_shapes with base path."""
        config = {
            "custom_shapes": {
                "router": {
                    "type": "svg",
                    "svg_path": "router.svg",
                    "width": 64,
                    "height": 64,
                }
            }
        }

        count = register_custom_shapes(registry, config, base_path=custom_shapes_dir)
        assert count == 1


# =============================================================================
# Edge Case Tests
# =============================================================================


class TestEdgeCases:
    """Tests for edge cases."""

    def test_empty_custom_shapes_section(self, registry):
        """Test config with empty custom_shapes section."""
        config = {"custom_shapes": {}}
        loader = CustomShapeLoader(registry)
        count = loader.load_custom_shapes(config)
        assert count == 0

    def test_no_custom_shapes_key(self, registry):
        """Test config without custom_shapes key."""
        config = {"diagram": {"title": "Test"}}
        loader = CustomShapeLoader(registry)
        count = loader.load_custom_shapes(config)
        assert count == 0

    def test_shape_name_auto_generated(self, registry):
        """Test that shape name is auto-generated from ID."""
        config = {
            "custom_shapes": {
                "my_special_shape": {
                    "type": "dot",
                    "graphviz": {"shape": "box"},
                }
            }
        }

        loader = CustomShapeLoader(registry)
        loader.load_custom_shapes(config)

        shape = registry.get_shape("my_special_shape")
        assert shape.name == "My Special Shape"

    def test_custom_tags_preserved(self, registry, valid_svg):
        """Test that custom tags are preserved."""
        config = {
            "custom_shapes": {
                "tagged_shape": {
                    "type": "svg",
                    "svg_data": valid_svg,
                    "width": 50,
                    "height": 50,
                    "tags": ["network", "router", "infrastructure"],
                }
            }
        }

        loader = CustomShapeLoader(registry)
        loader.load_custom_shapes(config)

        shape = registry.get_shape("tagged_shape")
        assert "network" in shape.tags
        assert "router" in shape.tags

    def test_svg_with_complex_content(self, loader):
        """Test SVG with complex but safe content."""
        complex_svg = '''
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">
            <defs>
                <linearGradient id="grad1" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" style="stop-color:rgb(255,255,0);stop-opacity:1" />
                    <stop offset="100%" style="stop-color:rgb(255,0,0);stop-opacity:1" />
                </linearGradient>
            </defs>
            <rect x="10" y="10" width="80" height="80" fill="url(#grad1)"/>
            <text x="50" y="55" text-anchor="middle" fill="white">Test</text>
        </svg>
        '''
        result = loader._validate_svg(complex_svg)
        assert "<linearGradient" in result

    def test_default_type_is_dot(self, registry):
        """Test that default shape type is DOT."""
        config = {
            "custom_shapes": {
                "implicit_dot": {
                    "graphviz": {"shape": "circle"},
                }
            }
        }

        loader = CustomShapeLoader(registry)
        loader.load_custom_shapes(config)

        shape = registry.get_shape("implicit_dot")
        assert shape.graphviz["shape"] == "circle"
        assert "dot" in shape.tags
