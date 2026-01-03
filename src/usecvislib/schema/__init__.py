#
# VULNEX -Universal Security Visualization Library-
#
# File: schema/__init__.py
# Author: Simon Roses Femerling
# Created: 2025-12-29
# Last Modified: 2025-12-29
# Version: 0.3.1
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Schema validation system for Custom Diagrams.

This package provides schema definition and validation for user-defined
diagram configurations.

Classes:
    SchemaValidator: Validates diagram data against user-defined schemas
    NodeTypeSchema: Schema definition for a node type
    EdgeTypeSchema: Schema definition for an edge type
    DiagramSchema: Complete schema for a diagram
    FieldType: Enum of supported field types

Usage:
    >>> from usecvislib.schema import SchemaValidator, NodeTypeSchema
    >>> from usecvislib.shapes import ShapeRegistry
    >>>
    >>> registry = ShapeRegistry.get_instance()
    >>> validator = SchemaValidator(registry)
    >>>
    >>> schema = {
    ...     "nodes": {
    ...         "server": {
    ...             "shape": "server",
    ...             "required_fields": ["name"],
    ...             "label_template": "{name}"
    ...         }
    ...     },
    ...     "edges": {
    ...         "connection": {
    ...             "style": "solid",
    ...             "color": "#333333"
    ...         }
    ...     }
    ... }
    >>>
    >>> validator.load_schema(schema)
    >>> validator.validate_data(nodes, edges)
"""

from .types import (
    FieldType,
    EdgeStyle,
    ArrowStyle,
    FieldSchema,
    NodeTypeSchema,
    EdgeTypeSchema,
    ClusterSchema,
    DiagramSchema,
)

from .validator import SchemaValidator


__all__ = [
    # Types
    "FieldType",
    "EdgeStyle",
    "ArrowStyle",
    "FieldSchema",
    "NodeTypeSchema",
    "EdgeTypeSchema",
    "ClusterSchema",
    "DiagramSchema",

    # Validator
    "SchemaValidator",
]
