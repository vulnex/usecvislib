#
# VULNEX -Universal Security Visualization Library-
#
# File: schema/validator.py
# Author: Simon Roses Femerling
# Created: 2025-12-29
# Last Modified: 2025-12-29
# Version: 0.3.1
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Schema validation for Custom Diagrams.

This module provides the SchemaValidator class which validates diagram
configurations against user-defined schemas. It performs two-phase validation:
1. Schema validation: Ensure schema definition is valid
2. Data validation: Ensure data conforms to schema
"""

import logging
from typing import Dict, List, Any, Optional, Set

from .types import (
    NodeTypeSchema,
    EdgeTypeSchema,
    DiagramSchema,
    FieldType,
)

logger = logging.getLogger(__name__)


class SchemaValidator:
    """Validates diagram configurations against user-defined schemas.

    Two-phase validation:
    1. Schema validation: Ensure schema definition is valid
    2. Data validation: Ensure data conforms to schema

    Usage:
        >>> from usecvislib.shapes import ShapeRegistry
        >>> registry = ShapeRegistry()
        >>> registry.load_builtin_shapes()
        >>> validator = SchemaValidator(registry)
        >>> validator.load_schema(schema_definition)
        >>> validator.validate_data(nodes, edges)
        >>> report = validator.get_validation_report()
    """

    # Valid Graphviz edge styles
    VALID_EDGE_STYLES = {"solid", "dashed", "dotted", "bold", "invis"}

    # Valid Graphviz arrowhead styles
    VALID_ARROWHEADS = {
        "normal", "vee", "dot", "diamond", "odiamond", "empty",
        "none", "tee", "crow", "box", "obox", "open", "inv",
        "invdot", "invodot", "invempty",
    }

    def __init__(self, shape_registry):
        """Initialize the schema validator.

        Args:
            shape_registry: ShapeRegistry instance for shape validation
        """
        self.shape_registry = shape_registry
        self.node_types: Dict[str, NodeTypeSchema] = {}
        self.edge_types: Dict[str, EdgeTypeSchema] = {}
        self.errors: List[str] = []
        self.warnings: List[str] = []
        self._schema_loaded = False

    def reset(self) -> None:
        """Reset validator state."""
        self.node_types = {}
        self.edge_types = {}
        self.errors = []
        self.warnings = []
        self._schema_loaded = False

    def load_schema(self, schema_def: Dict[str, Any]) -> bool:
        """Load and validate a schema definition.

        Args:
            schema_def: Dictionary containing node and edge type definitions

        Returns:
            True if schema is valid, False otherwise
        """
        self.reset()

        # Validate node type definitions
        nodes_def = schema_def.get("nodes", {})
        for type_name, type_def in nodes_def.items():
            if self._validate_node_type(type_name, type_def):
                self.node_types[type_name] = NodeTypeSchema.from_dict(type_name, type_def)

        # Validate edge type definitions
        edges_def = schema_def.get("edges", {})
        for type_name, type_def in edges_def.items():
            if self._validate_edge_type(type_name, type_def):
                self.edge_types[type_name] = EdgeTypeSchema.from_dict(type_name, type_def)

        self._schema_loaded = len(self.errors) == 0

        if self._schema_loaded:
            logger.debug(
                f"Schema loaded: {len(self.node_types)} node types, "
                f"{len(self.edge_types)} edge types"
            )

        return self._schema_loaded

    def _validate_node_type(self, type_name: str, type_def: Dict) -> bool:
        """Validate a single node type definition.

        Args:
            type_name: Node type identifier
            type_def: Node type definition dictionary

        Returns:
            True if valid, False otherwise
        """
        valid = True

        # Validate type name
        if not type_name:
            self.errors.append("Node type name cannot be empty")
            return False

        if not type_name.replace("_", "").replace("-", "").isalnum():
            self.errors.append(
                f"Node type '{type_name}': name must be alphanumeric "
                f"(underscores and hyphens allowed)"
            )
            valid = False

        # Shape must exist in registry
        shape_id = type_def.get("shape")
        if not shape_id:
            self.errors.append(f"Node type '{type_name}': missing required 'shape' field")
            valid = False
        elif not self.shape_registry.has_shape(shape_id):
            self.errors.append(f"Node type '{type_name}': unknown shape '{shape_id}'")
            valid = False

        # Validate required_fields is a list
        required_fields = type_def.get("required_fields", [])
        if not isinstance(required_fields, list):
            self.errors.append(
                f"Node type '{type_name}': 'required_fields' must be a list"
            )
            valid = False

        # Validate optional_fields is a list
        optional_fields = type_def.get("optional_fields", [])
        if not isinstance(optional_fields, list):
            self.errors.append(
                f"Node type '{type_name}': 'optional_fields' must be a list"
            )
            valid = False

        # Warn about empty required_fields
        if not required_fields:
            self.warnings.append(
                f"Node type '{type_name}': no required_fields defined, "
                "consider adding at least 'name'"
            )

        # Validate style is a dict
        style = type_def.get("style", {})
        if not isinstance(style, dict):
            self.errors.append(f"Node type '{type_name}': 'style' must be a dictionary")
            valid = False

        # Validate label_template format
        label_template = type_def.get("label_template", "{name}")
        if not isinstance(label_template, str):
            self.errors.append(
                f"Node type '{type_name}': 'label_template' must be a string"
            )
            valid = False

        return valid

    def _validate_edge_type(self, type_name: str, type_def: Dict) -> bool:
        """Validate a single edge type definition.

        Args:
            type_name: Edge type identifier
            type_def: Edge type definition dictionary

        Returns:
            True if valid, False otherwise
        """
        valid = True

        # Validate type name
        if not type_name:
            self.errors.append("Edge type name cannot be empty")
            return False

        # Validate style
        style = type_def.get("style", "solid")
        if style not in self.VALID_EDGE_STYLES:
            self.warnings.append(
                f"Edge type '{type_name}': style '{style}' may not be supported. "
                f"Valid styles: {self.VALID_EDGE_STYLES}"
            )

        # Validate arrowhead
        arrowhead = type_def.get("arrowhead", "normal")
        if arrowhead not in self.VALID_ARROWHEADS:
            self.warnings.append(
                f"Edge type '{type_name}': arrowhead '{arrowhead}' may not be supported"
            )

        # Validate color format (basic check)
        color = type_def.get("color", "#333333")
        if isinstance(color, str):
            if color.startswith("#"):
                if len(color) not in (4, 7, 9):  # #RGB, #RRGGBB, #RRGGBBAA
                    self.warnings.append(
                        f"Edge type '{type_name}': color '{color}' may be invalid"
                    )

        return valid

    def validate_data(self, nodes: List[Dict], edges: List[Dict]) -> bool:
        """Validate diagram data against loaded schema.

        Args:
            nodes: List of node dictionaries
            edges: List of edge dictionaries

        Returns:
            True if data is valid, False otherwise
        """
        if not self._schema_loaded:
            self.errors.append("Schema not loaded. Call load_schema() first.")
            return False

        self.errors = []
        self.warnings = []

        node_ids: Set[str] = set()

        # Validate nodes
        for i, node in enumerate(nodes):
            self._validate_node(i, node, node_ids)

        # Validate edges
        for i, edge in enumerate(edges):
            self._validate_edge(i, edge, node_ids)

        return len(self.errors) == 0

    def _validate_node(self, index: int, node: Dict, node_ids: Set[str]) -> None:
        """Validate a single node.

        Args:
            index: Node index in list
            node: Node dictionary
            node_ids: Set of seen node IDs (updated in-place)
        """
        # Check for required 'id' field
        node_id = node.get("id")
        if not node_id:
            self.errors.append(f"Node {index}: missing required 'id' field")
            return

        # Check for duplicate IDs
        if node_id in node_ids:
            self.errors.append(f"Node '{node_id}': duplicate node ID")
        node_ids.add(node_id)

        # Check for required 'type' field
        node_type = node.get("type")
        if not node_type:
            self.errors.append(f"Node '{node_id}': missing required 'type' field")
            return

        # Check if type is defined in schema
        if node_type not in self.node_types:
            self.errors.append(
                f"Node '{node_id}': unknown type '{node_type}'. "
                f"Valid types: {list(self.node_types.keys())}"
            )
            return

        # Validate required fields
        schema = self.node_types[node_type]
        for field_name in schema.required_fields:
            if field_name not in node:
                self.errors.append(
                    f"Node '{node_id}' (type: {node_type}): "
                    f"missing required field '{field_name}'"
                )

        # Warn about unknown fields
        known_fields = {"id", "type"} | set(schema.required_fields) | set(schema.optional_fields)
        for field_name in node.keys():
            if field_name not in known_fields:
                self.warnings.append(
                    f"Node '{node_id}': unknown field '{field_name}' "
                    f"(not in schema for type '{node_type}')"
                )

    def _validate_edge(self, index: int, edge: Dict, node_ids: Set[str]) -> None:
        """Validate a single edge.

        Args:
            index: Edge index in list
            edge: Edge dictionary
            node_ids: Set of valid node IDs
        """
        from_id = edge.get("from")
        to_id = edge.get("to")

        # Check for required 'from' field
        if not from_id:
            self.errors.append(f"Edge {index}: missing required 'from' field")
        elif from_id not in node_ids:
            self.errors.append(f"Edge {index}: 'from' references unknown node '{from_id}'")

        # Check for required 'to' field
        if not to_id:
            self.errors.append(f"Edge {index}: missing required 'to' field")
        elif to_id not in node_ids:
            self.errors.append(f"Edge {index}: 'to' references unknown node '{to_id}'")

        # Check edge type if specified
        edge_type = edge.get("type")
        if edge_type and edge_type not in self.edge_types:
            self.errors.append(
                f"Edge {index} ({from_id} -> {to_id}): unknown type '{edge_type}'. "
                f"Valid types: {list(self.edge_types.keys())}"
            )

    def validate_clusters(self, clusters: List[Dict], node_ids: Set[str]) -> bool:
        """Validate cluster definitions.

        Args:
            clusters: List of cluster dictionaries
            node_ids: Set of valid node IDs

        Returns:
            True if clusters are valid, False otherwise
        """
        cluster_errors = []

        for i, cluster in enumerate(clusters):
            cluster_id = cluster.get("id")
            if not cluster_id:
                cluster_errors.append(f"Cluster {i}: missing required 'id' field")
                continue

            # Check that cluster nodes exist
            cluster_nodes = cluster.get("nodes", [])
            for node_id in cluster_nodes:
                if node_id not in node_ids:
                    cluster_errors.append(
                        f"Cluster '{cluster_id}': references unknown node '{node_id}'"
                    )

        self.errors.extend(cluster_errors)
        return len(cluster_errors) == 0

    def get_validation_report(self) -> Dict[str, Any]:
        """Get a detailed validation report.

        Returns:
            Dictionary with validation status, errors, warnings, and schema info
        """
        return {
            "valid": len(self.errors) == 0,
            "errors": list(self.errors),
            "warnings": list(self.warnings),
            "error_count": len(self.errors),
            "warning_count": len(self.warnings),
            "schema": {
                "node_types": list(self.node_types.keys()),
                "edge_types": list(self.edge_types.keys()),
                "node_type_count": len(self.node_types),
                "edge_type_count": len(self.edge_types),
            },
            "schema_loaded": self._schema_loaded,
        }

    def get_schema(self) -> DiagramSchema:
        """Get the loaded schema as a DiagramSchema object.

        Returns:
            DiagramSchema containing all loaded types
        """
        return DiagramSchema(
            node_types=dict(self.node_types),
            edge_types=dict(self.edge_types),
        )

    @property
    def is_valid(self) -> bool:
        """Check if the last validation was successful."""
        return len(self.errors) == 0

    @property
    def has_warnings(self) -> bool:
        """Check if there are any warnings."""
        return len(self.warnings) > 0
