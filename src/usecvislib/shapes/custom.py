#
# VULNEX -Universal Security Visualization Library-
#
# File: shapes/custom.py
# Author: Simon Roses Femerling
# Created: 2025-12-29
# Last Modified: 2025-12-29
# Version: 0.3.1
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Custom shape loader for user-defined shapes.

This module handles loading and registering custom shapes defined by users
in their diagram configuration files. Supports:
- SVG-based shapes (image nodes in Graphviz)
- DOT-based shapes (custom Graphviz attribute combinations)
"""

import base64
import logging
import re
from pathlib import Path
from typing import Dict, Any, Optional, List

from .base import Shape, ShapeCategory
from .registry import ShapeRegistry


logger = logging.getLogger(__name__)


class CustomShapeError(Exception):
    """Exception raised for custom shape loading errors."""
    pass


class CustomShapeLoader:
    """Loader for user-defined custom shapes.

    Handles parsing and validation of custom shape definitions from
    user configuration files. Supports two types of custom shapes:

    1. SVG Shapes: Use an SVG file or inline SVG as the node image
    2. DOT Shapes: Define custom Graphviz attributes (shape, style, etc.)

    Usage:
        >>> loader = CustomShapeLoader(registry)
        >>> loader.load_custom_shapes(config_data, base_path="/path/to/config")

    Example TOML configuration:
        [custom_shapes.my_router]
        type = "svg"
        svg_path = "./assets/router.svg"
        width = 50
        height = 50
        ports = ["n", "s", "e", "w"]

        [custom_shapes.special_node]
        type = "dot"
        dot_definition = '''
            shape=polygon
            sides=6
            skew=0.4
        '''
    """

    # Maximum SVG file size (500KB)
    MAX_SVG_SIZE = 512 * 1024

    # Allowed SVG dimensions
    MIN_DIMENSION = 10
    MAX_DIMENSION = 500

    def __init__(self, registry: ShapeRegistry):
        """Initialize custom shape loader.

        Args:
            registry: ShapeRegistry to register shapes into
        """
        self.registry = registry

    def load_custom_shapes(
        self,
        config: Dict[str, Any],
        base_path: Optional[Path] = None
    ) -> int:
        """Load custom shapes from configuration.

        Args:
            config: Configuration dictionary (typically from TOML/JSON/YAML)
            base_path: Base path for resolving relative file paths

        Returns:
            Number of custom shapes successfully loaded

        Raises:
            CustomShapeError: If a shape definition is invalid
        """
        custom_shapes = config.get("custom_shapes", {})
        if not custom_shapes:
            return 0

        count = 0
        for shape_id, shape_def in custom_shapes.items():
            try:
                shape = self._create_custom_shape(shape_id, shape_def, base_path)
                self.registry.register_shape(shape)
                count += 1
                logger.debug(f"Registered custom shape: {shape_id}")
            except CustomShapeError as e:
                logger.error(f"Failed to load custom shape '{shape_id}': {e}")
                raise
            except Exception as e:
                logger.error(f"Unexpected error loading shape '{shape_id}': {e}")
                raise CustomShapeError(f"Error loading shape '{shape_id}': {e}")

        logger.info(f"Loaded {count} custom shapes")
        return count

    def _create_custom_shape(
        self,
        shape_id: str,
        definition: Dict[str, Any],
        base_path: Optional[Path] = None
    ) -> Shape:
        """Create a custom shape from definition.

        Args:
            shape_id: Unique identifier for the shape
            definition: Shape definition dictionary
            base_path: Base path for resolving relative paths

        Returns:
            New Shape instance

        Raises:
            CustomShapeError: If definition is invalid
        """
        shape_type = definition.get("type", "dot").lower()

        if shape_type == "svg":
            return self._create_svg_shape(shape_id, definition, base_path)
        elif shape_type == "dot":
            return self._create_dot_shape(shape_id, definition)
        else:
            raise CustomShapeError(
                f"Unknown custom shape type: {shape_type}. "
                f"Supported types: svg, dot"
            )

    def _create_svg_shape(
        self,
        shape_id: str,
        definition: Dict[str, Any],
        base_path: Optional[Path] = None
    ) -> Shape:
        """Create an SVG-based custom shape.

        SVG shapes are rendered in Graphviz using the 'image' attribute.
        The SVG can be provided as a file path or inline data.

        Args:
            shape_id: Shape identifier
            definition: Shape definition with SVG info
            base_path: Base path for resolving relative SVG paths

        Returns:
            Shape configured for SVG rendering
        """
        # Get SVG data
        svg_data = None
        if "svg_data" in definition:
            svg_data = definition["svg_data"]
        elif "svg_path" in definition:
            svg_path = definition["svg_path"]
            svg_data = self._load_svg_file(svg_path, base_path)
        else:
            raise CustomShapeError(
                f"SVG shape '{shape_id}' must specify 'svg_path' or 'svg_data'"
            )

        # Validate and process SVG
        svg_data = self._validate_svg(svg_data)

        # Get dimensions
        width = definition.get("width", 50)
        height = definition.get("height", 50)
        self._validate_dimensions(width, height)

        # Build Graphviz attributes for image node
        graphviz_attrs = {
            "shape": "none",
            "image": self._svg_to_data_uri(svg_data),
            "imagepos": "mc",
            "labelloc": "b",
        }

        # Add width/height as fixedsize
        graphviz_attrs["fixedsize"] = "true"
        graphviz_attrs["width"] = str(width / 72.0)  # Points to inches
        graphviz_attrs["height"] = str(height / 72.0)

        return Shape(
            id=shape_id,
            name=definition.get("name", shape_id.replace("_", " ").title()),
            category=ShapeCategory.CUSTOM,
            description=definition.get("description", f"Custom SVG shape: {shape_id}"),
            graphviz=graphviz_attrs,
            default_style=definition.get("style", {}),
            ports=definition.get("ports", ["n", "s", "e", "w"]),
            tags=definition.get("tags", ["custom", "svg"]),
            custom=True,
            svg_data=svg_data
        )

    def _create_dot_shape(
        self,
        shape_id: str,
        definition: Dict[str, Any]
    ) -> Shape:
        """Create a DOT-based custom shape.

        DOT shapes use Graphviz's built-in shape system with custom
        attribute combinations.

        Args:
            shape_id: Shape identifier
            definition: Shape definition with DOT attributes

        Returns:
            Shape configured with custom DOT attributes
        """
        # Parse DOT definition
        graphviz_attrs = {}

        if "dot_definition" in definition:
            graphviz_attrs = self._parse_dot_definition(definition["dot_definition"])
        elif "graphviz" in definition:
            graphviz_attrs = dict(definition["graphviz"])
        else:
            # Default to a simple box if no definition provided
            graphviz_attrs = {"shape": "box"}
            logger.warning(
                f"Custom shape '{shape_id}' has no dot_definition or graphviz, "
                f"defaulting to box shape"
            )

        return Shape(
            id=shape_id,
            name=definition.get("name", shape_id.replace("_", " ").title()),
            category=ShapeCategory.CUSTOM,
            description=definition.get("description", f"Custom DOT shape: {shape_id}"),
            graphviz=graphviz_attrs,
            default_style=definition.get("style", definition.get("default_style", {})),
            ports=definition.get("ports", ["n", "s", "e", "w"]),
            tags=definition.get("tags", ["custom", "dot"]),
            custom=True,
            dot_definition=definition.get("dot_definition")
        )

    def _load_svg_file(
        self,
        svg_path: str,
        base_path: Optional[Path] = None
    ) -> str:
        """Load SVG content from file.

        Args:
            svg_path: Path to SVG file (absolute or relative)
            base_path: Base path for resolving relative paths

        Returns:
            SVG file content as string

        Raises:
            CustomShapeError: If file cannot be loaded
        """
        # Resolve path
        path = Path(svg_path)
        if not path.is_absolute() and base_path:
            path = base_path / path

        # Security check: ensure path is safe
        try:
            path = path.resolve()
        except Exception as e:
            raise CustomShapeError(f"Invalid SVG path: {svg_path}: {e}")

        # Check file exists and size
        if not path.exists():
            raise CustomShapeError(f"SVG file not found: {path}")

        if not path.is_file():
            raise CustomShapeError(f"SVG path is not a file: {path}")

        file_size = path.stat().st_size
        if file_size > self.MAX_SVG_SIZE:
            raise CustomShapeError(
                f"SVG file too large: {file_size} bytes "
                f"(max: {self.MAX_SVG_SIZE} bytes)"
            )

        # Read file
        try:
            return path.read_text(encoding="utf-8")
        except Exception as e:
            raise CustomShapeError(f"Error reading SVG file: {e}")

    def _validate_svg(self, svg_data: str) -> str:
        """Validate SVG content.

        Performs basic validation to ensure the content is valid SVG
        and doesn't contain potentially dangerous elements.

        Args:
            svg_data: SVG content string

        Returns:
            Validated (potentially sanitized) SVG content

        Raises:
            CustomShapeError: If SVG is invalid or contains dangerous content
        """
        # Basic structure check
        if not svg_data.strip():
            raise CustomShapeError("SVG content is empty")

        # Must contain <svg element
        if "<svg" not in svg_data.lower():
            raise CustomShapeError("Content does not appear to be valid SVG")

        # Check for potentially dangerous elements
        dangerous_patterns = [
            r"<script",
            r"javascript:",
            r"on\w+\s*=",  # Event handlers like onclick, onload
            r"<foreignObject",
            r"<iframe",
        ]

        for pattern in dangerous_patterns:
            if re.search(pattern, svg_data, re.IGNORECASE):
                raise CustomShapeError(
                    f"SVG contains potentially dangerous content: {pattern}"
                )

        return svg_data

    def _validate_dimensions(self, width: int, height: int) -> None:
        """Validate shape dimensions.

        Args:
            width: Shape width in pixels
            height: Shape height in pixels

        Raises:
            CustomShapeError: If dimensions are invalid
        """
        if not isinstance(width, (int, float)) or not isinstance(height, (int, float)):
            raise CustomShapeError("Width and height must be numbers")

        if width < self.MIN_DIMENSION or width > self.MAX_DIMENSION:
            raise CustomShapeError(
                f"Width must be between {self.MIN_DIMENSION} and "
                f"{self.MAX_DIMENSION} pixels"
            )

        if height < self.MIN_DIMENSION or height > self.MAX_DIMENSION:
            raise CustomShapeError(
                f"Height must be between {self.MIN_DIMENSION} and "
                f"{self.MAX_DIMENSION} pixels"
            )

    def _svg_to_data_uri(self, svg_data: str) -> str:
        """Convert SVG content to a data URI for Graphviz.

        Args:
            svg_data: SVG content string

        Returns:
            Data URI string
        """
        # Encode SVG as base64
        encoded = base64.b64encode(svg_data.encode("utf-8")).decode("ascii")
        return f"data:image/svg+xml;base64,{encoded}"

    def _parse_dot_definition(self, dot_def: str) -> Dict[str, str]:
        """Parse a DOT definition string into attributes.

        Supports formats like:
        - shape=polygon
        - shape=polygon, sides=6
        - shape=polygon\\nsides=6

        Args:
            dot_def: DOT definition string

        Returns:
            Dictionary of Graphviz attributes
        """
        attrs = {}

        # Normalize the definition
        dot_def = dot_def.strip()

        # Split by newlines, commas, or semicolons
        parts = re.split(r"[\n,;]+", dot_def)

        for part in parts:
            part = part.strip()
            if not part:
                continue

            # Parse key=value pairs
            if "=" in part:
                key, value = part.split("=", 1)
                key = key.strip()
                value = value.strip().strip('"\'')
                if key:
                    attrs[key] = value
            else:
                # Could be just a shape name
                if part.lower() in {"box", "circle", "diamond", "ellipse", "polygon"}:
                    attrs["shape"] = part

        return attrs


def register_custom_shapes(
    registry: ShapeRegistry,
    config: Dict[str, Any],
    base_path: Optional[Path] = None
) -> int:
    """Convenience function to register custom shapes.

    Args:
        registry: ShapeRegistry to register shapes into
        config: Configuration dictionary containing custom_shapes
        base_path: Base path for resolving relative file paths

    Returns:
        Number of custom shapes registered
    """
    loader = CustomShapeLoader(registry)
    return loader.load_custom_shapes(config, base_path)
