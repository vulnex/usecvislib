#
# VULNEX -Universal Security Visualization Library-
#
# File: shapes/base.py
# Author: Simon Roses Femerling
# Created: 2025-12-29
# Last Modified: 2025-12-29
# Version: 0.3.1
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Base classes and types for the Shape Gallery System.

This module defines the foundational data structures for shapes:
- ShapeCategory: Enum of shape categories (basic, security, network, etc.)
- Shape: Dataclass representing a shape definition
- Port: Named connection points on shapes
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any


class ShapeCategory(Enum):
    """Categories for organizing shapes in the gallery."""
    BASIC = "basic"
    SECURITY = "security"
    NETWORK = "network"
    FLOW = "flow"
    UML = "uml"
    CONTAINERS = "containers"
    CUSTOM = "custom"


class Port(Enum):
    """Standard connection points on shapes."""
    NORTH = "n"
    SOUTH = "s"
    EAST = "e"
    WEST = "w"
    NORTHEAST = "ne"
    NORTHWEST = "nw"
    SOUTHEAST = "se"
    SOUTHWEST = "sw"
    CENTER = "c"


@dataclass
class Shape:
    """Represents a shape in the gallery.

    A shape defines how a node can be rendered in a diagram, including
    its Graphviz attributes, default styling, and connection points.

    Attributes:
        id: Unique identifier for the shape (e.g., "server", "database")
        name: Human-readable display name (e.g., "Server", "Database")
        category: Shape category for organization
        description: Brief description of the shape's purpose
        graphviz: Graphviz attributes (shape, style, etc.)
        default_style: Default visual styling (colors, fonts, etc.)
        icon: Icon identifier for UI display
        ports: Available connection points on the shape
        tags: Searchable tags for discovery
        custom: Whether this is a user-defined custom shape
        svg_data: Raw SVG data for custom SVG shapes
        dot_definition: Raw DOT definition for custom DOT shapes

    Example:
        >>> shape = Shape(
        ...     id="server",
        ...     name="Server",
        ...     category=ShapeCategory.SECURITY,
        ...     description="A server or computing node",
        ...     graphviz={"shape": "box3d", "style": "filled"},
        ...     default_style={"fillcolor": "#4A90D9", "fontcolor": "white"}
        ... )
    """
    id: str
    name: str
    category: ShapeCategory
    description: str
    graphviz: Dict[str, str]
    default_style: Dict[str, str] = field(default_factory=dict)
    icon: str = ""
    ports: List[str] = field(default_factory=lambda: ["n", "s", "e", "w"])
    tags: List[str] = field(default_factory=list)
    custom: bool = False
    svg_data: Optional[str] = None
    dot_definition: Optional[str] = None

    def get_all_graphviz_attrs(self, style_overrides: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """Get merged Graphviz attributes with optional overrides.

        Merges the base graphviz attributes with default_style, then applies
        any provided overrides.

        Args:
            style_overrides: Optional dictionary of attributes to override

        Returns:
            Merged dictionary of Graphviz attributes
        """
        attrs = {**self.graphviz, **self.default_style}
        if style_overrides:
            attrs.update(style_overrides)
        return attrs

    def has_port(self, port: str) -> bool:
        """Check if shape has a specific port.

        Args:
            port: Port identifier (n, s, e, w, etc.)

        Returns:
            True if port is available, False otherwise
        """
        return port in self.ports

    def to_dict(self) -> Dict[str, Any]:
        """Convert shape to dictionary representation.

        Useful for JSON serialization in API responses.

        Returns:
            Dictionary representation of the shape
        """
        return {
            "id": self.id,
            "name": self.name,
            "category": self.category.value,
            "description": self.description,
            "graphviz": self.graphviz,
            "default_style": self.default_style,
            "icon": self.icon,
            "ports": self.ports,
            "tags": self.tags,
            "custom": self.custom
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Shape":
        """Create a Shape from a dictionary.

        Args:
            data: Dictionary with shape definition

        Returns:
            New Shape instance
        """
        category = data.get("category", "basic")
        if isinstance(category, str):
            category = ShapeCategory(category)

        return cls(
            id=data["id"],
            name=data["name"],
            category=category,
            description=data.get("description", ""),
            graphviz=data.get("graphviz", {}),
            default_style=data.get("default_style", {}),
            icon=data.get("icon", ""),
            ports=data.get("ports", ["n", "s", "e", "w"]),
            tags=data.get("tags", []),
            custom=data.get("custom", False),
            svg_data=data.get("svg_data"),
            dot_definition=data.get("dot_definition")
        )


# Standard port configurations for common shape types
STANDARD_PORTS = {
    "default": ["n", "s", "e", "w"],
    "all": ["n", "s", "e", "w", "ne", "nw", "se", "sw"],
    "horizontal": ["e", "w"],
    "vertical": ["n", "s"],
    "centered": ["c"],
}


# Graphviz shape name mapping for reference
GRAPHVIZ_SHAPES = {
    # Basic shapes
    "box", "rect", "rectangle", "square",
    "circle", "ellipse", "oval",
    "diamond", "rhombus",
    "triangle", "invtriangle",
    "parallelogram",
    "hexagon", "octagon", "pentagon",
    "trapezium", "invtrapezium",
    "house", "invhouse",
    "star", "egg",

    # 3D shapes
    "box3d", "cylinder",

    # Flow shapes
    "tab", "folder", "note",
    "component", "cds",

    # Record shapes
    "record", "Mrecord",

    # Point shapes
    "point", "none", "plaintext", "plain",

    # Arrow shapes (for edge decorations)
    "normal", "vee", "dot", "diamond",
    "tee", "crow", "inv",
}
