#
# VULNEX -Universal Security Visualization Library-
#
# File: shapes/registry.py
# Author: Simon Roses Femerling
# Created: 2025-12-29
# Last Modified: 2025-12-29
# Version: 0.3.1
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Shape Registry for the Custom Diagrams module.

This module provides the ShapeRegistry class which manages shape definitions
for the shape gallery system. It supports:
- Loading built-in shapes from gallery TOML files
- Registering custom user-defined shapes (SVG/DOT)
- Shape lookup by ID, category, or tags
- Graphviz attribute generation for rendering
"""

import logging
from pathlib import Path
from typing import Dict, List, Optional, Set, Any

import toml

from .base import Shape, ShapeCategory


logger = logging.getLogger(__name__)


class ShapeRegistry:
    """Registry for managing shape definitions.

    The ShapeRegistry is the central component of the shape gallery system.
    It maintains a collection of shapes that can be used in custom diagrams.

    Supports:
    - Built-in shapes from gallery files (TOML format)
    - Custom user-defined shapes (SVG/DOT)
    - Shape lookup by ID or category
    - Search by name, description, or tags
    - Graphviz attribute generation

    Usage:
        >>> registry = ShapeRegistry()
        >>> registry.load_builtin_shapes()
        >>> shape = registry.get_shape("server")
        >>> attrs = registry.get_graphviz_attrs("server", {"fillcolor": "red"})

    Attributes:
        _shapes: Dictionary mapping shape IDs to Shape instances
        _categories: Dictionary mapping categories to sets of shape IDs
        _loaded: Flag indicating if built-in shapes have been loaded
    """

    # Singleton instance for global access
    _instance: Optional["ShapeRegistry"] = None

    def __init__(self):
        """Initialize empty shape registry."""
        self._shapes: Dict[str, Shape] = {}
        self._categories: Dict[ShapeCategory, Set[str]] = {}
        self._loaded = False
        self._gallery_path = Path(__file__).parent / "gallery"

    @classmethod
    def get_instance(cls) -> "ShapeRegistry":
        """Get the singleton instance of ShapeRegistry.

        Returns:
            Global ShapeRegistry instance with built-in shapes loaded
        """
        if cls._instance is None:
            cls._instance = cls()
            cls._instance.load_builtin_shapes()
        return cls._instance

    @classmethod
    def reset_instance(cls) -> None:
        """Reset the singleton instance (useful for testing)."""
        cls._instance = None

    def load_builtin_shapes(self) -> int:
        """Load all built-in shapes from gallery files.

        Scans the gallery directory for TOML files and loads shape
        definitions from each file.

        Returns:
            Number of shapes loaded

        Raises:
            FileNotFoundError: If gallery directory doesn't exist
        """
        if self._loaded:
            logger.debug("Built-in shapes already loaded")
            return len(self._shapes)

        if not self._gallery_path.exists():
            logger.warning(f"Gallery path not found: {self._gallery_path}")
            self._loaded = True
            return 0

        count = 0
        for toml_file in self._gallery_path.glob("*.toml"):
            try:
                loaded = self._load_gallery_file(toml_file)
                count += loaded
                logger.debug(f"Loaded {loaded} shapes from {toml_file.name}")
            except Exception as e:
                logger.error(f"Error loading gallery file {toml_file}: {e}")

        self._loaded = True
        logger.info(f"Loaded {count} built-in shapes from {self._gallery_path}")
        return count

    def _load_gallery_file(self, path: Path) -> int:
        """Load shapes from a single gallery TOML file.

        Args:
            path: Path to the TOML file

        Returns:
            Number of shapes loaded from file
        """
        data = toml.load(path)
        count = 0

        for shape_id, shape_def in data.get("shapes", {}).items():
            try:
                # Determine category from file name or definition
                category_str = shape_def.get("category", path.stem)
                try:
                    category = ShapeCategory(category_str)
                except ValueError:
                    logger.warning(
                        f"Unknown category '{category_str}' for shape '{shape_id}', "
                        f"defaulting to BASIC"
                    )
                    category = ShapeCategory.BASIC

                shape = Shape(
                    id=shape_id,
                    name=shape_def.get("name", shape_id.replace("_", " ").title()),
                    category=category,
                    description=shape_def.get("description", ""),
                    graphviz=shape_def.get("graphviz", {}),
                    default_style=shape_def.get("default_style", {}),
                    icon=shape_def.get("icon", ""),
                    ports=shape_def.get("ports", ["n", "s", "e", "w"]),
                    tags=shape_def.get("tags", [])
                )
                self.register_shape(shape)
                count += 1
            except Exception as e:
                logger.error(f"Error loading shape '{shape_id}': {e}")

        return count

    def register_shape(self, shape: Shape) -> None:
        """Register a shape in the registry.

        Args:
            shape: Shape instance to register

        Note:
            If a shape with the same ID already exists, it will be replaced
            and a warning will be logged.
        """
        if shape.id in self._shapes:
            logger.warning(f"Replacing existing shape: {shape.id}")

        self._shapes[shape.id] = shape

        # Update category index
        if shape.category not in self._categories:
            self._categories[shape.category] = set()
        self._categories[shape.category].add(shape.id)

    def unregister_shape(self, shape_id: str) -> bool:
        """Remove a shape from the registry.

        Args:
            shape_id: ID of shape to remove

        Returns:
            True if shape was removed, False if not found
        """
        if shape_id not in self._shapes:
            return False

        shape = self._shapes.pop(shape_id)

        # Update category index
        if shape.category in self._categories:
            self._categories[shape.category].discard(shape_id)

        return True

    def get_shape(self, shape_id: str) -> Optional[Shape]:
        """Get a shape by ID.

        Args:
            shape_id: Unique shape identifier

        Returns:
            Shape instance if found, None otherwise
        """
        return self._shapes.get(shape_id)

    def has_shape(self, shape_id: str) -> bool:
        """Check if a shape exists in the registry.

        Args:
            shape_id: Unique shape identifier

        Returns:
            True if shape exists, False otherwise
        """
        return shape_id in self._shapes

    def list_shapes(self, category: Optional[ShapeCategory] = None) -> List[Shape]:
        """List all shapes, optionally filtered by category.

        Args:
            category: Optional category to filter by

        Returns:
            List of Shape instances
        """
        if category:
            shape_ids = self._categories.get(category, set())
            return [self._shapes[sid] for sid in sorted(shape_ids)]
        return sorted(self._shapes.values(), key=lambda s: (s.category.value, s.name))

    def list_categories(self) -> List[ShapeCategory]:
        """List all available categories that have shapes.

        Returns:
            List of ShapeCategory values
        """
        return sorted(
            [cat for cat in self._categories.keys() if self._categories[cat]],
            key=lambda c: c.value
        )

    def count_shapes(self, category: Optional[ShapeCategory] = None) -> int:
        """Count shapes, optionally by category.

        Args:
            category: Optional category to count

        Returns:
            Number of shapes
        """
        if category:
            return len(self._categories.get(category, set()))
        return len(self._shapes)

    def search_shapes(self, query: str) -> List[Shape]:
        """Search shapes by name, description, or tags.

        Args:
            query: Search string (case-insensitive)

        Returns:
            List of matching Shape instances
        """
        query = query.lower()
        results = []

        for shape in self._shapes.values():
            # Search in name
            if query in shape.name.lower():
                results.append(shape)
                continue

            # Search in description
            if query in shape.description.lower():
                results.append(shape)
                continue

            # Search in tags
            if any(query in tag.lower() for tag in shape.tags):
                results.append(shape)
                continue

            # Search in ID
            if query in shape.id.lower():
                results.append(shape)

        return sorted(results, key=lambda s: s.name)

    def get_shapes_by_tag(self, tag: str) -> List[Shape]:
        """Get all shapes with a specific tag.

        Args:
            tag: Tag to search for (case-insensitive)

        Returns:
            List of shapes with the tag
        """
        tag = tag.lower()
        return [
            shape for shape in self._shapes.values()
            if any(tag == t.lower() for t in shape.tags)
        ]

    def get_graphviz_attrs(
        self,
        shape_id: str,
        style_overrides: Optional[Dict[str, str]] = None
    ) -> Dict[str, str]:
        """Get Graphviz attributes for rendering a shape.

        Merges the shape's graphviz attributes with default_style,
        then applies any provided style overrides.

        Args:
            shape_id: Shape identifier
            style_overrides: Optional dictionary of attributes to override

        Returns:
            Dictionary of Graphviz node attributes

        Raises:
            ValueError: If shape ID is not found
        """
        shape = self.get_shape(shape_id)
        if not shape:
            raise ValueError(f"Unknown shape: {shape_id}")

        return shape.get_all_graphviz_attrs(style_overrides)

    def get_shape_info(self, shape_id: str) -> Dict[str, Any]:
        """Get shape information as a dictionary.

        Useful for API responses and serialization.

        Args:
            shape_id: Shape identifier

        Returns:
            Dictionary with shape information

        Raises:
            ValueError: If shape ID is not found
        """
        shape = self.get_shape(shape_id)
        if not shape:
            raise ValueError(f"Unknown shape: {shape_id}")

        return shape.to_dict()

    def get_gallery_info(self) -> Dict[str, Any]:
        """Get summary information about the shape gallery.

        Returns:
            Dictionary with gallery statistics and category breakdown
        """
        category_counts = {
            cat.value: len(shapes)
            for cat, shapes in self._categories.items()
            if shapes
        }

        return {
            "total_shapes": len(self._shapes),
            "categories": len(category_counts),
            "category_counts": category_counts,
            "custom_shapes": sum(1 for s in self._shapes.values() if s.custom),
            "loaded": self._loaded
        }

    def export_gallery(self) -> Dict[str, List[Dict[str, Any]]]:
        """Export entire gallery as a dictionary.

        Useful for API responses that need full gallery data.

        Returns:
            Dictionary with category names as keys and shape lists as values
        """
        result = {}
        for category in self.list_categories():
            shapes = self.list_shapes(category)
            result[category.value] = [s.to_dict() for s in shapes]
        return result

    def __len__(self) -> int:
        """Return number of shapes in registry."""
        return len(self._shapes)

    def __contains__(self, shape_id: str) -> bool:
        """Check if shape ID is in registry."""
        return shape_id in self._shapes

    def __iter__(self):
        """Iterate over all shapes."""
        return iter(self._shapes.values())
