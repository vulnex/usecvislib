#
# VULNEX -Universal Security Visualization Library-
#
# File: tests/test_shapes.py
# Author: Simon Roses Femerling
# Created: 2025-12-29
# Last Modified: 2025-12-29
# Version: 0.3.1
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Unit tests for the Shape Gallery System."""

import pytest
from pathlib import Path

from usecvislib.shapes import (
    Shape,
    ShapeCategory,
    ShapeRegistry,
    CustomShapeLoader,
    CustomShapeError,
    get_registry,
    list_all_shapes,
    search_shapes,
    STANDARD_PORTS,
)


class TestShapeCategory:
    """Tests for ShapeCategory enum."""

    def test_all_categories_exist(self):
        """Verify all expected categories are defined."""
        expected = {"basic", "security", "network", "flow", "uml", "containers", "custom"}
        actual = {cat.value for cat in ShapeCategory}
        assert actual == expected

    def test_category_values(self):
        """Test that category values match their names."""
        assert ShapeCategory.BASIC.value == "basic"
        assert ShapeCategory.SECURITY.value == "security"
        assert ShapeCategory.NETWORK.value == "network"


class TestShape:
    """Tests for Shape dataclass."""

    def test_shape_creation(self):
        """Test creating a Shape instance."""
        shape = Shape(
            id="test",
            name="Test Shape",
            category=ShapeCategory.BASIC,
            description="A test shape",
            graphviz={"shape": "box"},
        )
        assert shape.id == "test"
        assert shape.name == "Test Shape"
        assert shape.category == ShapeCategory.BASIC
        assert shape.graphviz == {"shape": "box"}

    def test_shape_defaults(self):
        """Test Shape default values."""
        shape = Shape(
            id="test",
            name="Test",
            category=ShapeCategory.BASIC,
            description="",
            graphviz={},
        )
        assert shape.default_style == {}
        assert shape.icon == ""
        assert shape.ports == ["n", "s", "e", "w"]
        assert shape.tags == []
        assert shape.custom is False
        assert shape.svg_data is None

    def test_get_all_graphviz_attrs(self):
        """Test merging graphviz attributes with overrides."""
        shape = Shape(
            id="test",
            name="Test",
            category=ShapeCategory.BASIC,
            description="",
            graphviz={"shape": "box", "style": "filled"},
            default_style={"fillcolor": "white"},
        )

        # Without overrides
        attrs = shape.get_all_graphviz_attrs()
        assert attrs == {"shape": "box", "style": "filled", "fillcolor": "white"}

        # With overrides
        attrs = shape.get_all_graphviz_attrs({"fillcolor": "red", "fontcolor": "blue"})
        assert attrs["fillcolor"] == "red"
        assert attrs["fontcolor"] == "blue"
        assert attrs["shape"] == "box"

    def test_has_port(self):
        """Test port checking."""
        shape = Shape(
            id="test",
            name="Test",
            category=ShapeCategory.BASIC,
            description="",
            graphviz={},
            ports=["n", "s"],
        )
        assert shape.has_port("n") is True
        assert shape.has_port("e") is False

    def test_to_dict(self):
        """Test Shape serialization to dictionary."""
        shape = Shape(
            id="test",
            name="Test",
            category=ShapeCategory.BASIC,
            description="A test",
            graphviz={"shape": "box"},
            tags=["test", "example"],
        )
        data = shape.to_dict()
        assert data["id"] == "test"
        assert data["category"] == "basic"
        assert data["tags"] == ["test", "example"]
        assert "svg_data" not in data  # Should not include None values

    def test_from_dict(self):
        """Test Shape creation from dictionary."""
        data = {
            "id": "test",
            "name": "Test",
            "category": "security",
            "description": "A test shape",
            "graphviz": {"shape": "ellipse"},
            "tags": ["security"],
        }
        shape = Shape.from_dict(data)
        assert shape.id == "test"
        assert shape.category == ShapeCategory.SECURITY
        assert shape.graphviz == {"shape": "ellipse"}


class TestShapeRegistry:
    """Tests for ShapeRegistry."""

    @pytest.fixture
    def fresh_registry(self):
        """Create a fresh registry for testing."""
        ShapeRegistry.reset_instance()
        registry = ShapeRegistry()
        return registry

    def test_singleton_pattern(self):
        """Test that get_instance returns same instance."""
        ShapeRegistry.reset_instance()
        r1 = ShapeRegistry.get_instance()
        r2 = ShapeRegistry.get_instance()
        assert r1 is r2

    def test_load_builtin_shapes(self, fresh_registry):
        """Test loading built-in shapes from gallery files."""
        count = fresh_registry.load_builtin_shapes()
        assert count > 0
        assert fresh_registry._loaded is True

    def test_double_load_protection(self, fresh_registry):
        """Test that loading twice doesn't duplicate shapes."""
        count1 = fresh_registry.load_builtin_shapes()
        count2 = fresh_registry.load_builtin_shapes()
        assert count1 == count2
        assert len(fresh_registry) == count1

    def test_register_shape(self, fresh_registry):
        """Test registering a custom shape."""
        shape = Shape(
            id="my_shape",
            name="My Shape",
            category=ShapeCategory.CUSTOM,
            description="Custom shape",
            graphviz={"shape": "star"},
        )
        fresh_registry.register_shape(shape)
        assert "my_shape" in fresh_registry
        assert fresh_registry.get_shape("my_shape") is shape

    def test_unregister_shape(self, fresh_registry):
        """Test unregistering a shape."""
        shape = Shape(
            id="temp",
            name="Temp",
            category=ShapeCategory.BASIC,
            description="",
            graphviz={},
        )
        fresh_registry.register_shape(shape)
        assert "temp" in fresh_registry

        result = fresh_registry.unregister_shape("temp")
        assert result is True
        assert "temp" not in fresh_registry

        # Unregistering non-existent returns False
        result = fresh_registry.unregister_shape("temp")
        assert result is False

    def test_get_shape_not_found(self, fresh_registry):
        """Test getting a non-existent shape returns None."""
        assert fresh_registry.get_shape("nonexistent") is None

    def test_has_shape(self, fresh_registry):
        """Test checking if shape exists."""
        fresh_registry.load_builtin_shapes()
        assert fresh_registry.has_shape("server") is True
        assert fresh_registry.has_shape("nonexistent") is False

    def test_list_shapes_all(self, fresh_registry):
        """Test listing all shapes."""
        fresh_registry.load_builtin_shapes()
        shapes = fresh_registry.list_shapes()
        assert len(shapes) > 0
        assert all(isinstance(s, Shape) for s in shapes)

    def test_list_shapes_by_category(self, fresh_registry):
        """Test listing shapes by category."""
        fresh_registry.load_builtin_shapes()
        security_shapes = fresh_registry.list_shapes(ShapeCategory.SECURITY)
        assert len(security_shapes) > 0
        assert all(s.category == ShapeCategory.SECURITY for s in security_shapes)

    def test_list_categories(self, fresh_registry):
        """Test listing available categories."""
        fresh_registry.load_builtin_shapes()
        categories = fresh_registry.list_categories()
        assert ShapeCategory.BASIC in categories
        assert ShapeCategory.SECURITY in categories

    def test_count_shapes(self, fresh_registry):
        """Test counting shapes."""
        fresh_registry.load_builtin_shapes()
        total = fresh_registry.count_shapes()
        security_count = fresh_registry.count_shapes(ShapeCategory.SECURITY)
        assert total > security_count > 0

    def test_search_shapes(self, fresh_registry):
        """Test searching shapes."""
        fresh_registry.load_builtin_shapes()

        # Search by name
        results = fresh_registry.search_shapes("server")
        assert len(results) > 0
        assert any(s.id == "server" for s in results)

        # Search by tag
        results = fresh_registry.search_shapes("database")
        assert len(results) > 0

        # No results
        results = fresh_registry.search_shapes("xyznonexistent")
        assert len(results) == 0

    def test_get_shapes_by_tag(self, fresh_registry):
        """Test getting shapes by tag."""
        fresh_registry.load_builtin_shapes()
        shapes = fresh_registry.get_shapes_by_tag("infrastructure")
        assert len(shapes) > 0

    def test_get_graphviz_attrs(self, fresh_registry):
        """Test getting Graphviz attributes."""
        fresh_registry.load_builtin_shapes()
        attrs = fresh_registry.get_graphviz_attrs("server")
        assert "shape" in attrs
        assert attrs["shape"] == "box3d"

    def test_get_graphviz_attrs_with_overrides(self, fresh_registry):
        """Test getting Graphviz attributes with style overrides."""
        fresh_registry.load_builtin_shapes()
        attrs = fresh_registry.get_graphviz_attrs(
            "server", {"fillcolor": "red", "custom": "value"}
        )
        assert attrs["fillcolor"] == "red"
        assert attrs["custom"] == "value"
        assert attrs["shape"] == "box3d"

    def test_get_graphviz_attrs_unknown_shape(self, fresh_registry):
        """Test that unknown shape raises ValueError."""
        with pytest.raises(ValueError, match="Unknown shape"):
            fresh_registry.get_graphviz_attrs("nonexistent")

    def test_get_shape_info(self, fresh_registry):
        """Test getting shape info as dictionary."""
        fresh_registry.load_builtin_shapes()
        info = fresh_registry.get_shape_info("database")
        assert info["id"] == "database"
        assert "graphviz" in info
        assert "category" in info

    def test_get_gallery_info(self, fresh_registry):
        """Test getting gallery summary information."""
        fresh_registry.load_builtin_shapes()
        info = fresh_registry.get_gallery_info()
        assert "total_shapes" in info
        assert "categories" in info
        assert "category_counts" in info
        assert info["loaded"] is True

    def test_export_gallery(self, fresh_registry):
        """Test exporting entire gallery."""
        fresh_registry.load_builtin_shapes()
        export = fresh_registry.export_gallery()
        assert "basic" in export
        assert "security" in export
        assert isinstance(export["basic"], list)

    def test_iterator(self, fresh_registry):
        """Test iterating over registry."""
        fresh_registry.load_builtin_shapes()
        shapes = list(fresh_registry)
        assert len(shapes) == len(fresh_registry)


class TestCustomShapeLoader:
    """Tests for CustomShapeLoader."""

    @pytest.fixture
    def registry(self):
        """Create a fresh registry for testing."""
        return ShapeRegistry()

    def test_load_dot_shape(self, registry):
        """Test loading a DOT-based custom shape."""
        config = {
            "custom_shapes": {
                "my_polygon": {
                    "type": "dot",
                    "name": "My Polygon",
                    "description": "A custom polygon",
                    "dot_definition": "shape=polygon\nsides=6\nskew=0.4",
                    "tags": ["custom", "test"],
                }
            }
        }

        loader = CustomShapeLoader(registry)
        count = loader.load_custom_shapes(config)
        assert count == 1

        shape = registry.get_shape("my_polygon")
        assert shape is not None
        assert shape.name == "My Polygon"
        assert shape.custom is True
        assert shape.graphviz["shape"] == "polygon"
        assert shape.graphviz["sides"] == "6"

    def test_load_dot_shape_with_graphviz_dict(self, registry):
        """Test loading DOT shape with graphviz dictionary."""
        config = {
            "custom_shapes": {
                "my_box": {
                    "type": "dot",
                    "graphviz": {"shape": "box", "style": "filled,rounded"},
                    "style": {"fillcolor": "red"},
                }
            }
        }

        loader = CustomShapeLoader(registry)
        loader.load_custom_shapes(config)

        shape = registry.get_shape("my_box")
        assert shape.graphviz["shape"] == "box"
        assert shape.default_style["fillcolor"] == "red"

    def test_load_no_custom_shapes(self, registry):
        """Test loading config with no custom shapes."""
        config = {"diagram": {"title": "Test"}}

        loader = CustomShapeLoader(registry)
        count = loader.load_custom_shapes(config)
        assert count == 0

    def test_parse_dot_definition(self, registry):
        """Test parsing DOT definition string."""
        loader = CustomShapeLoader(registry)

        # Newline separated
        attrs = loader._parse_dot_definition("shape=box\nstyle=filled")
        assert attrs == {"shape": "box", "style": "filled"}

        # Comma separated
        attrs = loader._parse_dot_definition("shape=box, style=filled")
        assert attrs == {"shape": "box", "style": "filled"}

        # Semicolon separated
        attrs = loader._parse_dot_definition("shape=box; style=filled")
        assert attrs == {"shape": "box", "style": "filled"}

    def test_svg_validation_empty(self, registry):
        """Test that empty SVG is rejected."""
        loader = CustomShapeLoader(registry)
        with pytest.raises(CustomShapeError, match="empty"):
            loader._validate_svg("")

    def test_svg_validation_no_svg_tag(self, registry):
        """Test that non-SVG content is rejected."""
        loader = CustomShapeLoader(registry)
        with pytest.raises(CustomShapeError, match="not.*valid SVG"):
            loader._validate_svg("<html><body>Hello</body></html>")

    def test_svg_validation_dangerous_content(self, registry):
        """Test that dangerous SVG content is rejected."""
        loader = CustomShapeLoader(registry)
        dangerous = "<svg><script>alert('xss')</script></svg>"
        with pytest.raises(CustomShapeError, match="dangerous"):
            loader._validate_svg(dangerous)

    def test_dimension_validation(self, registry):
        """Test dimension validation."""
        loader = CustomShapeLoader(registry)

        # Valid dimensions
        loader._validate_dimensions(50, 50)  # Should not raise

        # Too small
        with pytest.raises(CustomShapeError, match="Width"):
            loader._validate_dimensions(5, 50)

        # Too large
        with pytest.raises(CustomShapeError, match="Height"):
            loader._validate_dimensions(50, 600)


class TestModuleFunctions:
    """Tests for module-level convenience functions."""

    def test_get_registry(self):
        """Test get_registry returns singleton."""
        r1 = get_registry()
        r2 = get_registry()
        assert r1 is r2

    def test_list_all_shapes(self):
        """Test list_all_shapes returns dictionaries."""
        shapes = list_all_shapes()
        assert len(shapes) > 0
        assert all(isinstance(s, dict) for s in shapes)
        assert all("id" in s for s in shapes)

    def test_search_shapes(self):
        """Test search_shapes module function."""
        results = search_shapes("server")
        assert len(results) > 0
        assert all(isinstance(s, dict) for s in results)


class TestStandardPorts:
    """Tests for standard port configurations."""

    def test_default_ports(self):
        """Test default port configuration."""
        assert STANDARD_PORTS["default"] == ["n", "s", "e", "w"]

    def test_all_ports(self):
        """Test all ports configuration."""
        assert len(STANDARD_PORTS["all"]) == 8
        assert "ne" in STANDARD_PORTS["all"]
