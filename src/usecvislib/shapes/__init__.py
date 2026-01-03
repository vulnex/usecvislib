#
# VULNEX -Universal Security Visualization Library-
#
# File: shapes/__init__.py
# Author: Simon Roses Femerling
# Created: 2025-12-29
# Last Modified: 2025-12-29
# Version: 0.3.1
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Shape Gallery System for Custom Diagrams.

This package provides the shape gallery system used by the Custom Diagrams module.
It includes:

- **Shape**: Dataclass representing a shape definition
- **ShapeCategory**: Enum of available shape categories
- **ShapeRegistry**: Central registry for managing shapes
- **CustomShapeLoader**: Loader for user-defined custom shapes

Usage:
    >>> from usecvislib.shapes import ShapeRegistry, ShapeCategory
    >>>
    >>> # Get the global registry (loads built-in shapes automatically)
    >>> registry = ShapeRegistry.get_instance()
    >>>
    >>> # List available categories
    >>> categories = registry.list_categories()
    >>>
    >>> # Get shapes in a category
    >>> security_shapes = registry.list_shapes(ShapeCategory.SECURITY)
    >>>
    >>> # Get a specific shape
    >>> server = registry.get_shape("server")
    >>>
    >>> # Get Graphviz attributes for rendering
    >>> attrs = registry.get_graphviz_attrs("server", {"fillcolor": "red"})
    >>>
    >>> # Search shapes
    >>> results = registry.search_shapes("database")

Categories:
    - BASIC: General purpose geometric shapes
    - SECURITY: Security-focused shapes (server, firewall, threat, etc.)
    - NETWORK: Network topology shapes (router, switch, endpoint, etc.)
    - FLOW: Flowchart shapes (process, decision, terminator, etc.)
    - UML: UML diagram shapes (class, interface, state, etc.)
    - CONTAINERS: Grouping/container shapes (cluster, boundary, zone, etc.)
    - CUSTOM: User-defined custom shapes

Shape Gallery Files:
    shapes/gallery/basic.toml
    shapes/gallery/security.toml
    shapes/gallery/network.toml
    shapes/gallery/flow.toml
    shapes/gallery/uml.toml
    shapes/gallery/containers.toml
"""

from .base import (
    Shape,
    ShapeCategory,
    Port,
    STANDARD_PORTS,
    GRAPHVIZ_SHAPES,
)

from .registry import ShapeRegistry

from .custom import (
    CustomShapeLoader,
    CustomShapeError,
    register_custom_shapes,
)


__all__ = [
    # Base types
    "Shape",
    "ShapeCategory",
    "Port",
    "STANDARD_PORTS",
    "GRAPHVIZ_SHAPES",

    # Registry
    "ShapeRegistry",

    # Custom shapes
    "CustomShapeLoader",
    "CustomShapeError",
    "register_custom_shapes",
]


def get_registry() -> ShapeRegistry:
    """Get the global shape registry instance.

    Convenience function for accessing the singleton registry.

    Returns:
        Global ShapeRegistry with built-in shapes loaded
    """
    return ShapeRegistry.get_instance()


def list_all_shapes() -> list:
    """List all available shapes.

    Returns:
        List of shape dictionaries
    """
    registry = get_registry()
    return [s.to_dict() for s in registry.list_shapes()]


def get_shape_info(shape_id: str) -> dict:
    """Get information about a specific shape.

    Args:
        shape_id: Shape identifier

    Returns:
        Shape information dictionary

    Raises:
        ValueError: If shape not found
    """
    registry = get_registry()
    return registry.get_shape_info(shape_id)


def search_shapes(query: str) -> list:
    """Search for shapes by name, description, or tags.

    Args:
        query: Search string

    Returns:
        List of matching shape dictionaries
    """
    registry = get_registry()
    results = registry.search_shapes(query)
    return [s.to_dict() for s in results]
