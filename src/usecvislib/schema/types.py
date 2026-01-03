#
# VULNEX -Universal Security Visualization Library-
#
# File: schema/types.py
# Author: Simon Roses Femerling
# Created: 2025-12-29
# Last Modified: 2025-12-29
# Version: 0.3.1
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Type definitions for the Custom Diagrams schema system.

This module provides dataclasses and enums for representing schema
definitions used in custom diagram configurations.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any


class FieldType(Enum):
    """Supported field types for schema validation."""
    STRING = "string"
    NUMBER = "number"
    INTEGER = "integer"
    BOOLEAN = "boolean"
    LIST = "list"
    DICT = "dict"
    ANY = "any"


class EdgeStyle(Enum):
    """Graphviz edge styles."""
    SOLID = "solid"
    DASHED = "dashed"
    DOTTED = "dotted"
    BOLD = "bold"
    INVIS = "invis"


class ArrowStyle(Enum):
    """Graphviz arrowhead styles."""
    NORMAL = "normal"
    VEE = "vee"
    DOT = "dot"
    DIAMOND = "diamond"
    ODIAMOND = "odiamond"
    EMPTY = "empty"
    NONE = "none"
    TEE = "tee"
    CROW = "crow"
    BOX = "box"
    OBOX = "obox"
    OPEN = "open"
    INV = "inv"


@dataclass
class FieldSchema:
    """Schema definition for a single field.

    Attributes:
        name: Field name
        field_type: Expected data type
        required: Whether the field is required
        default: Default value if not provided
        description: Human-readable description
        validators: List of validation functions or patterns
    """
    name: str
    field_type: FieldType = FieldType.STRING
    required: bool = False
    default: Any = None
    description: str = ""
    validators: List[str] = field(default_factory=list)


@dataclass
class NodeTypeSchema:
    """Schema definition for a node type.

    Defines what shape to use, required/optional fields,
    styling, and how to construct the label.

    Attributes:
        name: Node type identifier
        shape: Shape ID from the shape gallery
        required_fields: List of fields that must be present
        optional_fields: List of fields that may be present
        style: Graphviz style overrides
        label_template: Template for constructing node label
        field_types: Optional type annotations for fields
        description: Human-readable description
    """
    name: str
    shape: str
    required_fields: List[str] = field(default_factory=list)
    optional_fields: List[str] = field(default_factory=list)
    style: Dict[str, str] = field(default_factory=dict)
    label_template: str = "{name}"
    field_types: Dict[str, FieldType] = field(default_factory=dict)
    description: str = ""

    @property
    def all_fields(self) -> List[str]:
        """Get all known fields (required + optional)."""
        return self.required_fields + self.optional_fields

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "name": self.name,
            "shape": self.shape,
            "required_fields": self.required_fields,
            "optional_fields": self.optional_fields,
            "style": self.style,
            "label_template": self.label_template,
            "description": self.description,
        }

    @classmethod
    def from_dict(cls, name: str, data: Dict[str, Any]) -> "NodeTypeSchema":
        """Create NodeTypeSchema from dictionary."""
        return cls(
            name=name,
            shape=data.get("shape", "rectangle"),
            required_fields=data.get("required_fields", []),
            optional_fields=data.get("optional_fields", []),
            style=data.get("style", {}),
            label_template=data.get("label_template", "{name}"),
            description=data.get("description", ""),
        )


@dataclass
class EdgeTypeSchema:
    """Schema definition for an edge type.

    Defines styling and labeling for edges between nodes.

    Attributes:
        name: Edge type identifier
        style: Line style (solid, dashed, dotted, bold)
        color: Edge color
        arrowhead: Arrow style at target end
        arrowtail: Arrow style at source end
        label_field: Which node field to use as edge label
        penwidth: Line thickness
        description: Human-readable description
    """
    name: str
    style: str = "solid"
    color: str = "#333333"
    arrowhead: str = "normal"
    arrowtail: str = "none"
    label_field: Optional[str] = None
    penwidth: str = "1"
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "name": self.name,
            "style": self.style,
            "color": self.color,
            "arrowhead": self.arrowhead,
            "arrowtail": self.arrowtail,
            "label_field": self.label_field,
            "penwidth": self.penwidth,
            "description": self.description,
        }

    def get_graphviz_attrs(self) -> Dict[str, str]:
        """Get Graphviz edge attributes."""
        attrs = {
            "style": self.style,
            "color": self.color,
            "arrowhead": self.arrowhead,
            "penwidth": self.penwidth,
        }
        if self.arrowtail != "none":
            attrs["arrowtail"] = self.arrowtail
            attrs["dir"] = "both"
        return attrs

    @classmethod
    def from_dict(cls, name: str, data: Dict[str, Any]) -> "EdgeTypeSchema":
        """Create EdgeTypeSchema from dictionary."""
        return cls(
            name=name,
            style=data.get("style", "solid"),
            color=data.get("color", "#333333"),
            arrowhead=data.get("arrowhead", "normal"),
            arrowtail=data.get("arrowtail", "none"),
            label_field=data.get("label_field"),
            penwidth=str(data.get("penwidth", "1")),
            description=data.get("description", ""),
        )


@dataclass
class ClusterSchema:
    """Schema definition for a cluster/subgraph.

    Attributes:
        id: Cluster identifier
        label: Display label
        nodes: List of node IDs contained in this cluster
        style: Graphviz cluster style attributes
    """
    id: str
    label: str = ""
    nodes: List[str] = field(default_factory=list)
    style: Dict[str, str] = field(default_factory=dict)

    def __post_init__(self):
        if not self.label:
            self.label = self.id

    def get_graphviz_attrs(self) -> Dict[str, str]:
        """Get Graphviz cluster attributes."""
        attrs = dict(self.style)
        attrs["label"] = self.label
        return attrs

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ClusterSchema":
        """Create ClusterSchema from dictionary."""
        return cls(
            id=data.get("id", ""),
            label=data.get("label", data.get("id", "")),
            nodes=data.get("nodes", []),
            style=data.get("style", {}),
        )


@dataclass
class DiagramSchema:
    """Complete schema for a custom diagram.

    Contains all node types, edge types, and validation rules.

    Attributes:
        node_types: Dictionary of node type schemas
        edge_types: Dictionary of edge type schemas
        allow_unknown_types: Whether to allow undefined types
    """
    node_types: Dict[str, NodeTypeSchema] = field(default_factory=dict)
    edge_types: Dict[str, EdgeTypeSchema] = field(default_factory=dict)
    allow_unknown_types: bool = False

    def has_node_type(self, type_name: str) -> bool:
        """Check if a node type is defined."""
        return type_name in self.node_types

    def has_edge_type(self, type_name: str) -> bool:
        """Check if an edge type is defined."""
        return type_name in self.edge_types

    def get_node_type(self, type_name: str) -> Optional[NodeTypeSchema]:
        """Get a node type schema by name."""
        return self.node_types.get(type_name)

    def get_edge_type(self, type_name: str) -> Optional[EdgeTypeSchema]:
        """Get an edge type schema by name."""
        return self.edge_types.get(type_name)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "nodes": {
                name: schema.to_dict()
                for name, schema in self.node_types.items()
            },
            "edges": {
                name: schema.to_dict()
                for name, schema in self.edge_types.items()
            },
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DiagramSchema":
        """Create DiagramSchema from dictionary."""
        node_types = {}
        for name, node_def in data.get("nodes", {}).items():
            node_types[name] = NodeTypeSchema.from_dict(name, node_def)

        edge_types = {}
        for name, edge_def in data.get("edges", {}).items():
            edge_types[name] = EdgeTypeSchema.from_dict(name, edge_def)

        return cls(
            node_types=node_types,
            edge_types=edge_types,
            allow_unknown_types=data.get("allow_unknown_types", False),
        )
