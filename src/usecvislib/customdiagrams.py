#
# VULNEX -Universal Security Visualization Library-
#
# File: customdiagrams.py
# Author: Simon Roses Femerling
# Created: 2025-12-29
# Last Modified: 2025-12-29
# Version: 0.3.1
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Custom Diagrams Module - Flexible, schema-driven diagram visualization.

This module provides a flexible system for creating arbitrary diagrams
without being constrained to domain-specific formats. Users define their
own node types, edge types, and validation rules.

Features:
- Shape gallery with 100+ pre-built shapes
- Custom shape support (SVG/DOT)
- User-defined schemas with validation
- Multiple layout algorithms
- Template library
- Export from existing modules (Attack Trees, Graphs, Threat Models)

Example:
    >>> from usecvislib import CustomDiagrams
    >>> cd = CustomDiagrams()
    >>> cd.load("my_diagram.toml")
    >>> result = cd.BuildCustomDiagram(output="diagram.png")
"""

import re
import logging
from typing import Dict, List, Any, Optional, Union, Set
from pathlib import Path
from dataclasses import dataclass, field

import graphviz as gv

from .shapes import ShapeRegistry
from .shapes.custom import CustomShapeLoader
from .schema import SchemaValidator
from .utils import (
    ReadConfigFile,
    parse_content,
    ValidationError,
    RenderError,
    sanitize_node_id,
    escape_dot_label,
    process_node_image,
)


logger = logging.getLogger(__name__)


class CustomDiagramError(RenderError):
    """Custom diagram specific error."""
    pass


@dataclass
class VisualizationResult:
    """Result of a diagram visualization operation.

    Attributes:
        output_path: Path to the generated output file
        format: Output format (png, svg, pdf, etc.)
        stats: Dictionary of diagram statistics
        success: Whether the operation was successful
    """
    output_path: str
    format: str
    stats: Dict[str, Any] = field(default_factory=dict)
    success: bool = True

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "output_path": self.output_path,
            "format": self.format,
            "stats": self.stats,
            "success": self.success,
        }


@dataclass
class DiagramSettings:
    """Global diagram settings.

    Attributes:
        title: Diagram title (displayed at top)
        description: Diagram description
        layout: Layout algorithm (hierarchical, circular, force, etc.)
        direction: Graph direction (TB, LR, BT, RL)
        rankdir: Graphviz rankdir (same as direction)
        splines: Edge routing (ortho, polyline, curved, line, spline)
        nodesep: Horizontal spacing between nodes
        ranksep: Vertical spacing between ranks
        style: Style preset name
        fontname: Default font name
        fontsize: Default font size
        bgcolor: Background color
    """
    title: str = "Custom Diagram"
    description: str = ""
    layout: str = "hierarchical"
    direction: str = "TB"
    rankdir: str = "TB"
    splines: str = "ortho"
    nodesep: float = 0.5
    ranksep: float = 1.0
    style: str = "cd_default"
    fontname: str = "Arial"
    fontsize: str = "12"
    bgcolor: str = ""

    def __post_init__(self):
        # Sync rankdir with direction if not explicitly set
        if self.rankdir == "TB" and self.direction != "TB":
            self.rankdir = self.direction

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DiagramSettings":
        """Create DiagramSettings from dictionary."""
        return cls(
            title=data.get("title", "Custom Diagram"),
            description=data.get("description", ""),
            layout=data.get("layout", "hierarchical"),
            direction=data.get("direction", "TB"),
            rankdir=data.get("rankdir", data.get("direction", "TB")),
            splines=data.get("splines", "ortho"),
            nodesep=float(data.get("nodesep", 0.5)),
            ranksep=float(data.get("ranksep", 1.0)),
            style=data.get("style", "cd_default"),
            fontname=data.get("fontname", "Arial"),
            fontsize=str(data.get("fontsize", "12")),
            bgcolor=data.get("bgcolor", ""),
        )


class CustomDiagrams:
    """Flexible, schema-driven diagram visualization.

    Unlike domain-specific modules (AttackTrees, AttackGraphs, ThreatModeling),
    this module allows users to define their own schemas with custom node types,
    edge types, and validation rules.

    Example:
        >>> from usecvislib import CustomDiagrams
        >>> cd = CustomDiagrams()
        >>> cd.load("my_diagram.toml")
        >>> cd.validate()
        >>> result = cd.BuildCustomDiagram(output="diagram.png")

    Attributes:
        shape_registry: Registry of available shapes
        schema_validator: Validator for schema and data
        settings: Diagram settings
        schema: Schema definition dictionary
        nodes: List of node data dictionaries
        edges: List of edge data dictionaries
        clusters: List of cluster definitions
    """

    # Style presets
    STYLES = {
        "cd_default": "Default clean style",
        "cd_dark": "Dark theme with light text",
        "cd_light": "Light minimalist theme",
        "cd_colorful": "Vibrant colors",
        "cd_blueprint": "Technical blueprint style",
        "cd_sketch": "Hand-drawn sketch style",
        "cd_corporate": "Professional corporate style",
        "cd_neon": "Neon cyberpunk style",
        "cd_pastel": "Soft pastel colors",
        "cd_monochrome": "Black and white",
    }

    # Layout algorithms mapped to Graphviz engines
    LAYOUTS = {
        "hierarchical": "dot",      # Top-down/left-right hierarchy
        "circular": "circo",        # Circular layout
        "force": "fdp",             # Force-directed placement
        "grid": "neato",            # Spring model layout
        "radial": "twopi",          # Radial layout
        "compact": "patchwork",     # Space-filling layout
        "sfdp": "sfdp",             # Scalable force-directed
    }

    # Supported output formats
    OUTPUT_FORMATS = {"png", "svg", "pdf", "dot", "jpg", "jpeg", "gif", "ps"}

    def __init__(self):
        """Initialize CustomDiagrams."""
        self.shape_registry = ShapeRegistry()
        self.shape_registry.load_builtin_shapes()
        self.schema_validator = SchemaValidator(self.shape_registry)

        self.settings: Optional[DiagramSettings] = None
        self.schema: Dict[str, Any] = {}
        self.nodes: List[Dict] = []
        self.edges: List[Dict] = []
        self.clusters: List[Dict] = []
        self.custom_shapes: Dict[str, Dict] = {}

        self._config_loaded = False
        self._config_path: Optional[Path] = None

        logger.debug("CustomDiagrams initialized")

    def load(self, config_path: Union[str, Path]) -> "CustomDiagrams":
        """Load diagram configuration from file.

        Args:
            config_path: Path to TOML, JSON, or YAML configuration file

        Returns:
            Self for method chaining

        Raises:
            FileError: If file cannot be read
            ConfigError: If configuration is invalid
        """
        path = Path(config_path)
        self._config_path = path

        config = ReadConfigFile(str(path))
        self._load_from_dict(config, path.parent)
        self._config_loaded = True

        logger.info(f"Loaded diagram from {path}")
        return self

    def load_from_string(self, content: str, format: str = "toml",
                         base_path: Optional[Path] = None) -> "CustomDiagrams":
        """Load diagram configuration from string content.

        Args:
            content: Configuration content
            format: Format of content ("toml", "json", "yaml")
            base_path: Base path for resolving relative file paths

        Returns:
            Self for method chaining
        """
        config = parse_content(content, format)
        self._load_from_dict(config, base_path)
        self._config_loaded = True

        logger.info(f"Loaded diagram from string ({format} format)")
        return self

    def _load_from_dict(self, config: Dict[str, Any],
                        base_path: Optional[Path] = None) -> None:
        """Load configuration from dictionary.

        Args:
            config: Configuration dictionary
            base_path: Base path for resolving relative file paths
        """
        # Load diagram settings
        diagram_def = config.get("diagram", {})
        self.settings = DiagramSettings.from_dict(diagram_def)

        # Load custom shapes first (before schema validation)
        self.custom_shapes = config.get("custom_shapes", {})
        if self.custom_shapes:
            loader = CustomShapeLoader(self.shape_registry)
            loader.load_custom_shapes(config, base_path)

        # Load schema
        self.schema = config.get("schema", {})

        # Load data
        self.nodes = config.get("nodes", [])
        self.edges = config.get("edges", [])
        self.clusters = config.get("clusters", [])

    def validate(self, raise_on_error: bool = True) -> Dict[str, Any]:
        """Validate the loaded configuration.

        Performs two-phase validation:
        1. Schema validation - ensure schema definition is valid
        2. Data validation - ensure data conforms to schema

        Args:
            raise_on_error: Whether to raise exception on validation failure

        Returns:
            Validation report with errors and warnings

        Raises:
            ValidationError: If validation fails and raise_on_error is True
        """
        if not self._config_loaded:
            if raise_on_error:
                raise ValidationError("No configuration loaded. Call load() first.")
            return {"valid": False, "errors": ["No configuration loaded"]}

        # Phase 1: Validate schema definition
        if not self.schema_validator.load_schema(self.schema):
            report = self.schema_validator.get_validation_report()
            if raise_on_error:
                raise ValidationError(
                    f"Schema validation failed: {report['errors']}"
                )
            return report

        # Phase 2: Validate data against schema
        if not self.schema_validator.validate_data(self.nodes, self.edges):
            report = self.schema_validator.get_validation_report()
            if raise_on_error:
                raise ValidationError(
                    f"Data validation failed: {report['errors']}"
                )
            return report

        # Phase 3: Validate clusters
        if self.clusters:
            node_ids = {n["id"] for n in self.nodes if "id" in n}
            self.schema_validator.validate_clusters(self.clusters, node_ids)

        return self.schema_validator.get_validation_report()

    def _render_impl(self) -> gv.Digraph:
        """Build Graphviz graph from configuration.

        Returns:
            Graphviz Digraph object
        """
        # Determine layout engine
        engine = self.LAYOUTS.get(self.settings.layout, "dot")

        # Create graph
        graph = gv.Digraph(
            name=sanitize_node_id(self.settings.title),
            engine=engine,
        )

        # Set graph attributes
        graph.attr(
            rankdir=self.settings.rankdir,
            splines=self.settings.splines,
            nodesep=str(self.settings.nodesep),
            ranksep=str(self.settings.ranksep),
            label=escape_dot_label(self.settings.title),
            labelloc="t",
            fontname=self.settings.fontname,
            fontsize=self.settings.fontsize,
        )

        if self.settings.bgcolor:
            graph.attr(bgcolor=self.settings.bgcolor)

        # Set default node attributes
        graph.attr("node", fontname=self.settings.fontname)

        # Apply style preset
        self._apply_style(graph)

        # Add clusters (subgraphs) and track which nodes are in clusters
        clustered_nodes = self._add_clusters(graph)

        # Add nodes not in clusters
        for node in self.nodes:
            if node.get("id") not in clustered_nodes:
                self._add_node(graph, node)

        # Add edges
        for edge in self.edges:
            self._add_edge(graph, edge)

        return graph

    def _add_node(self, graph: Union[gv.Digraph, gv.Graph], node: Dict) -> None:
        """Add a node to the graph.

        Args:
            graph: Graphviz graph or subgraph
            node: Node data dictionary
        """
        node_id = sanitize_node_id(node["id"])
        node_type = node.get("type")

        # Process node data copy to avoid modifying original
        node_data = node.copy()

        # Process and validate image attribute if present
        process_node_image(node_data, node_id, logger)

        # Get schema for this node type
        type_schema = self.schema_validator.node_types.get(node_type)
        if not type_schema:
            # If no schema, use basic box shape
            node_attrs = {"label": escape_dot_label(str(node_data.get("name", node_id)))}
            # Add image if present
            if "image" in node_data:
                node_attrs["image"] = node_data["image"]
                node_attrs["labelloc"] = "b"  # Label below image
            graph.node(node_id, **node_attrs)
            return

        # Get shape attributes from registry
        try:
            shape_attrs = self.shape_registry.get_graphviz_attrs(
                type_schema.shape,
                type_schema.style
            )
        except ValueError:
            # Shape not found, use defaults
            shape_attrs = {"shape": "box", "style": "filled"}

        # Build label from template
        label = self._build_label(type_schema.label_template, node_data)

        # Add image if present
        if "image" in node_data:
            shape_attrs["image"] = node_data["image"]
            shape_attrs["labelloc"] = "b"  # Label below image

        # Add node to graph
        graph.node(
            node_id,
            label=escape_dot_label(label),
            **shape_attrs
        )

    def _add_edge(self, graph: gv.Digraph, edge: Dict) -> None:
        """Add an edge to the graph.

        Args:
            graph: Graphviz graph
            edge: Edge data dictionary
        """
        from_id = sanitize_node_id(edge["from"])
        to_id = sanitize_node_id(edge["to"])
        edge_type = edge.get("type")

        # Get schema for this edge type
        type_schema = self.schema_validator.edge_types.get(edge_type)

        attrs = {}
        if type_schema:
            attrs = type_schema.get_graphviz_attrs()

            # Add label if label_field is specified
            if type_schema.label_field and type_schema.label_field in edge:
                attrs["label"] = escape_dot_label(str(edge[type_schema.label_field]))
        else:
            # Default edge style
            attrs = {"color": "#333333"}

        # Allow edge-level overrides
        if "label" in edge:
            attrs["label"] = escape_dot_label(str(edge["label"]))
        if "color" in edge:
            attrs["color"] = edge["color"]
        if "style" in edge:
            attrs["style"] = edge["style"]

        graph.edge(from_id, to_id, **attrs)

    def _add_clusters(self, graph: gv.Digraph) -> Set[str]:
        """Add clusters (subgraphs) and return set of clustered node IDs.

        Args:
            graph: Graphviz graph

        Returns:
            Set of node IDs that are in clusters
        """
        clustered_nodes: Set[str] = set()

        for cluster in self.clusters:
            cluster_id = f"cluster_{sanitize_node_id(cluster['id'])}"
            cluster_label = cluster.get("label", cluster["id"])
            cluster_style = cluster.get("style", {})

            with graph.subgraph(name=cluster_id) as subgraph:
                # Set cluster attributes
                subgraph.attr(label=escape_dot_label(cluster_label))

                # Apply cluster style
                for key, value in cluster_style.items():
                    subgraph.attr(**{key: str(value)})

                # Add nodes to cluster
                for node_id in cluster.get("nodes", []):
                    # Find node data
                    node_data = next(
                        (n for n in self.nodes if n.get("id") == node_id),
                        None
                    )
                    if node_data:
                        self._add_node(subgraph, node_data)
                        clustered_nodes.add(node_id)

        return clustered_nodes

    def _build_label(self, template: str, data: Dict) -> str:
        """Build node label from template and data.

        Args:
            template: Label template with {field} placeholders
            data: Node data dictionary

        Returns:
            Constructed label string
        """
        label = template

        # Replace placeholders with values
        for key, value in data.items():
            placeholder = "{" + key + "}"
            if placeholder in label:
                label = label.replace(placeholder, str(value) if value else "")

        # Remove any unreplaced placeholders
        label = re.sub(r'\{[^}]+\}', '', label)

        # Clean up empty lines and extra whitespace
        lines = [line.strip() for line in label.split("\n") if line.strip()]
        label = "\n".join(lines)

        return label

    def _apply_style(self, graph: gv.Digraph) -> None:
        """Apply style preset to graph.

        Args:
            graph: Graphviz graph
        """
        style = self.settings.style if self.settings else "cd_default"

        if style == "cd_dark":
            graph.attr(bgcolor="#1a1a2e", fontcolor="white")
            graph.attr("node", fontcolor="white", color="#444444")
            graph.attr("edge", color="#666666", fontcolor="#cccccc")

        elif style == "cd_blueprint":
            graph.attr(bgcolor="#1e3a5f", fontcolor="white")
            graph.attr("node", fontcolor="white", color="white", style="filled")
            graph.attr("edge", color="#4a90d9", fontcolor="white")

        elif style == "cd_light":
            graph.attr(bgcolor="white", fontcolor="#333333")
            graph.attr("node", fontcolor="#333333", color="#cccccc")
            graph.attr("edge", color="#999999")

        elif style == "cd_neon":
            graph.attr(bgcolor="#0a0a0a", fontcolor="#00ff00")
            graph.attr("node", fontcolor="#00ff00", color="#00ff00")
            graph.attr("edge", color="#ff00ff", fontcolor="#00ffff")

        elif style == "cd_pastel":
            graph.attr(bgcolor="#fef9f3", fontcolor="#4a4a4a")
            graph.attr("node", fontcolor="#4a4a4a")
            graph.attr("edge", color="#b8b8b8")

        elif style == "cd_monochrome":
            graph.attr(bgcolor="white", fontcolor="black")
            graph.attr("node", fontcolor="black", color="black", fillcolor="white")
            graph.attr("edge", color="black")

        # cd_default and others: use Graphviz defaults

    def BuildCustomDiagram(
        self,
        output: str = "custom_diagram",
        output_format: str = "png",
        validate: bool = True,
        view: bool = False,
    ) -> VisualizationResult:
        """Build and render the custom diagram.

        Args:
            output: Output file path (without extension)
            output_format: Output format (png, svg, pdf, dot)
            validate: Whether to validate before rendering
            view: Whether to open the result in default viewer

        Returns:
            VisualizationResult with output path and statistics

        Raises:
            CustomDiagramError: If rendering fails
            ValidationError: If validation fails
        """
        if validate:
            self.validate()

        if output_format not in self.OUTPUT_FORMATS:
            raise CustomDiagramError(
                f"Unsupported output format: {output_format}. "
                f"Supported: {self.OUTPUT_FORMATS}"
            )

        try:
            graph = self._render_impl()
            graph.format = output_format

            # Render to file
            output_path = Path(output)
            rendered_path = graph.render(
                filename=str(output_path.with_suffix("")),
                cleanup=True,
                view=view,
            )

            logger.info(f"Diagram rendered to {rendered_path}")

            return VisualizationResult(
                output_path=rendered_path,
                format=output_format,
                stats=self.get_stats(),
            )

        except Exception as e:
            raise CustomDiagramError(f"Failed to render diagram: {e}") from e

    def get_stats(self) -> Dict[str, Any]:
        """Get diagram statistics.

        Returns:
            Dictionary with diagram statistics
        """
        node_type_counts: Dict[str, int] = {}
        for node in self.nodes:
            node_type = node.get("type", "unknown")
            node_type_counts[node_type] = node_type_counts.get(node_type, 0) + 1

        edge_type_counts: Dict[str, int] = {}
        for edge in self.edges:
            edge_type = edge.get("type", "default")
            edge_type_counts[edge_type] = edge_type_counts.get(edge_type, 0) + 1

        return {
            "title": self.settings.title if self.settings else "",
            "total_nodes": len(self.nodes),
            "total_edges": len(self.edges),
            "total_clusters": len(self.clusters),
            "node_types": node_type_counts,
            "edge_types": edge_type_counts,
            "schema_node_types": list(self.schema_validator.node_types.keys()),
            "schema_edge_types": list(self.schema_validator.edge_types.keys()),
            "custom_shapes": len(self.custom_shapes),
            "layout": self.settings.layout if self.settings else "hierarchical",
        }

    def list_shapes(self, category: Optional[str] = None) -> List[Dict]:
        """List available shapes from the gallery.

        Args:
            category: Optional category filter

        Returns:
            List of shape information dictionaries
        """
        from .shapes import ShapeCategory

        if category:
            try:
                cat = ShapeCategory(category)
                shapes = self.shape_registry.list_shapes(cat)
            except ValueError:
                shapes = []
        else:
            shapes = self.shape_registry.list_shapes()

        return [s.to_dict() for s in shapes]

    def get_dot_source(self) -> str:
        """Get the Graphviz DOT source code.

        Useful for debugging or manual editing.

        Returns:
            DOT source code as string
        """
        if not self._config_loaded:
            raise CustomDiagramError("No configuration loaded")

        graph = self._render_impl()
        return graph.source

    def export_schema_template(self) -> str:
        """Export current schema as a starter template.

        Useful for creating new diagrams based on the current schema.

        Returns:
            TOML configuration template
        """
        import toml

        # Build template structure
        template: Dict[str, Any] = {
            "diagram": {
                "title": "New Diagram",
                "description": "Description here",
                "layout": self.settings.layout if self.settings else "hierarchical",
                "direction": self.settings.direction if self.settings else "TB",
            },
            "schema": self.schema,
            "nodes": [],
            "edges": [],
        }

        # Add example node for each type
        for type_name in self.schema.get("nodes", {}).keys():
            template["nodes"].append({
                "id": f"example_{type_name}",
                "type": type_name,
                "name": f"Example {type_name}",
            })

        return toml.dumps(template)

    # Class methods for importing from other modules

    @classmethod
    def from_attack_tree(cls, config_path: str) -> "CustomDiagrams":
        """Import an attack tree configuration as a custom diagram.

        Note: Analysis features are not preserved, only visual structure.

        Args:
            config_path: Path to attack tree configuration file

        Returns:
            CustomDiagrams instance with imported data
        """
        from .attacktrees import AttackTrees

        at = AttackTrees(config_path, "temp", validate_paths=False)
        at.load()

        cd = cls()

        # Set up settings
        tree_data = at.inputdata.get("tree", {})
        cd.settings = DiagramSettings(
            title=tree_data.get("name", "Imported Attack Tree"),
            layout="hierarchical",
            direction="TB",
        )

        # Define schema based on attack tree elements
        cd.schema = {
            "nodes": {
                "root": {
                    "shape": "octagon",
                    "required_fields": ["name"],
                    "style": {"fillcolor": "#E74C3C", "fontcolor": "white"},
                    "label_template": "{name}",
                },
                "and_gate": {
                    "shape": "diamond",
                    "required_fields": ["name"],
                    "style": {"fillcolor": "#3498DB", "fontcolor": "white"},
                    "label_template": "AND\n{name}",
                },
                "or_gate": {
                    "shape": "diamond",
                    "required_fields": ["name"],
                    "style": {"fillcolor": "#9B59B6", "fontcolor": "white"},
                    "label_template": "OR\n{name}",
                },
                "leaf": {
                    "shape": "rectangle",
                    "required_fields": ["name"],
                    "style": {"fillcolor": "#95E1D3"},
                    "label_template": "{name}",
                },
            },
            "edges": {
                "parent_child": {
                    "style": "solid",
                    "color": "#333333",
                    "arrowhead": "normal",
                },
            },
        }

        # Convert nodes
        nodes = at.inputdata.get("nodes", {})
        for node_id, node_data in nodes.items():
            gate = node_data.get("gate", "").upper()
            if gate == "AND":
                node_type = "and_gate"
            elif gate == "OR":
                node_type = "or_gate"
            elif node_data.get("is_root"):
                node_type = "root"
            else:
                node_type = "leaf"

            cd.nodes.append({
                "id": node_id,
                "type": node_type,
                "name": node_data.get("label", node_id),
            })

        # Convert edges from parent relationships
        for node_id, node_data in nodes.items():
            parent = node_data.get("parent")
            if parent:
                cd.edges.append({
                    "from": parent,
                    "to": node_id,
                    "type": "parent_child",
                })

        cd._config_loaded = True
        return cd

    @classmethod
    def from_attack_graph(cls, config_path: str) -> "CustomDiagrams":
        """Import an attack graph configuration as a custom diagram.

        Converts hosts, vulnerabilities, services, privileges, and exploits
        into a visual custom diagram.

        Note: Analysis features are not preserved, only visual structure.

        Args:
            config_path: Path to attack graph configuration file

        Returns:
            CustomDiagrams instance with imported data
        """
        from .attackgraphs import AttackGraphs

        ag = AttackGraphs(config_path, "temp", validate_paths=False)
        ag.load()

        cd = cls()

        # Set up settings
        graph_data = ag.inputdata.get("graph", {})
        cd.settings = DiagramSettings(
            title=graph_data.get("name", "Imported Attack Graph"),
            description=graph_data.get("description", ""),
            layout="hierarchical",
            direction="LR",
        )

        # Define schema based on attack graph elements
        cd.schema = {
            "nodes": {
                "host": {
                    "shape": "server",
                    "required_fields": ["name"],
                    "optional_fields": ["ip", "zone"],
                    "style": {"fillcolor": "#3498DB", "fontcolor": "white"},
                    "label_template": "{name}",
                },
                "vulnerability": {
                    "shape": "warning",
                    "required_fields": ["name"],
                    "optional_fields": ["cvss"],
                    "style": {"fillcolor": "#E74C3C", "fontcolor": "white"},
                    "label_template": "{name}",
                },
                "privilege": {
                    "shape": "key",
                    "required_fields": ["name"],
                    "optional_fields": ["level"],
                    "style": {"fillcolor": "#F39C12", "fontcolor": "white"},
                    "label_template": "{name}",
                },
                "service": {
                    "shape": "process",
                    "required_fields": ["name"],
                    "optional_fields": ["port"],
                    "style": {"fillcolor": "#27AE60", "fontcolor": "white"},
                    "label_template": "{name}",
                },
                "exploit": {
                    "shape": "threat",
                    "required_fields": ["name"],
                    "style": {"fillcolor": "#9B59B6", "fontcolor": "white"},
                    "label_template": "{name}",
                },
            },
            "edges": {
                "network": {
                    "style": "solid",
                    "color": "#333333",
                    "arrowhead": "vee",
                    "label_field": "label",
                },
                "affects": {
                    "style": "dashed",
                    "color": "#E74C3C",
                    "arrowhead": "normal",
                },
                "exploits": {
                    "style": "bold",
                    "color": "#9B59B6",
                    "arrowhead": "vee",
                },
                "grants": {
                    "style": "dashed",
                    "color": "#F39C12",
                    "arrowhead": "normal",
                },
                "runs_on": {
                    "style": "dotted",
                    "color": "#27AE60",
                    "arrowhead": "none",
                },
            },
        }

        # Convert hosts
        hosts = ag.inputdata.get("hosts", {})
        for host_id, host_data in hosts.items():
            cd.nodes.append({
                "id": host_id,
                "type": "host",
                "name": host_data.get("label", host_id),
                "ip": host_data.get("ip", ""),
                "zone": host_data.get("zone", ""),
            })

        # Convert vulnerabilities
        vulns = ag.inputdata.get("vulnerabilities", {})
        for vuln_id, vuln_data in vulns.items():
            cd.nodes.append({
                "id": vuln_id,
                "type": "vulnerability",
                "name": vuln_data.get("label", vuln_id),
                "cvss": str(vuln_data.get("cvss", "")),
            })
            # Create edge to affected host
            affected_host = vuln_data.get("affected_host")
            if affected_host:
                cd.edges.append({
                    "from": vuln_id,
                    "to": affected_host,
                    "type": "affects",
                })

        # Convert privileges
        privs = ag.inputdata.get("privileges", {})
        for priv_id, priv_data in privs.items():
            cd.nodes.append({
                "id": priv_id,
                "type": "privilege",
                "name": priv_data.get("label", priv_id),
                "level": priv_data.get("level", ""),
            })
            # Create edge to host
            host = priv_data.get("host")
            if host:
                cd.edges.append({
                    "from": priv_id,
                    "to": host,
                    "type": "grants",
                })

        # Convert services
        services = ag.inputdata.get("services", {})
        for svc_id, svc_data in services.items():
            cd.nodes.append({
                "id": svc_id,
                "type": "service",
                "name": svc_data.get("label", svc_id),
                "port": str(svc_data.get("port", "")),
            })
            # Create edge to host
            host = svc_data.get("host")
            if host:
                cd.edges.append({
                    "from": svc_id,
                    "to": host,
                    "type": "runs_on",
                })

        # Convert exploits
        exploits = ag.inputdata.get("exploits", {})
        for exp_id, exp_data in exploits.items():
            cd.nodes.append({
                "id": exp_id,
                "type": "exploit",
                "name": exp_data.get("label", exp_id),
            })
            # Create edges for precondition and postcondition
            vuln = exp_data.get("vulnerability")
            if vuln:
                cd.edges.append({
                    "from": exp_id,
                    "to": vuln,
                    "type": "exploits",
                })

        # Convert network edges
        network_edges = ag.inputdata.get("network_edges", {})
        for edge_id, edge_data in network_edges.items():
            if isinstance(edge_data, dict):
                cd.edges.append({
                    "from": edge_data.get("from", ""),
                    "to": edge_data.get("to", ""),
                    "type": "network",
                    "label": edge_data.get("label", ""),
                })

        cd._config_loaded = True
        return cd

    @classmethod
    def from_threat_model(cls, config_path: str) -> "CustomDiagrams":
        """Import a threat model configuration as a custom diagram.

        Converts processes, data stores, external entities, and data flows
        into a Data Flow Diagram (DFD) style custom diagram.

        Note: STRIDE analysis is not preserved, only visual structure.

        Args:
            config_path: Path to threat model configuration file

        Returns:
            CustomDiagrams instance with imported data
        """
        from .threatmodeling import ThreatModeling

        tm = ThreatModeling(config_path, "temp", validate_paths=False)
        tm.load()

        cd = cls()

        # Set up settings
        model_data = tm.inputdata.get("model", {})
        cd.settings = DiagramSettings(
            title=model_data.get("name", "Imported Threat Model"),
            description=model_data.get("description", ""),
            layout="hierarchical",
            direction="LR",
        )

        # Define schema based on DFD elements
        cd.schema = {
            "nodes": {
                "process": {
                    "shape": "ellipse",
                    "required_fields": ["name"],
                    "optional_fields": ["description"],
                    "style": {"fillcolor": "#3498DB", "fontcolor": "white"},
                    "label_template": "{name}",
                },
                "datastore": {
                    "shape": "database",
                    "required_fields": ["name"],
                    "optional_fields": ["type"],
                    "style": {"fillcolor": "#27AE60", "fontcolor": "white"},
                    "label_template": "{name}",
                },
                "external": {
                    "shape": "rectangle",
                    "required_fields": ["name"],
                    "optional_fields": ["type"],
                    "style": {"fillcolor": "#95A5A6", "fontcolor": "white"},
                    "label_template": "{name}",
                },
            },
            "edges": {
                "dataflow": {
                    "style": "solid",
                    "color": "#333333",
                    "arrowhead": "vee",
                    "label_field": "data",
                },
                "bidirectional": {
                    "style": "solid",
                    "color": "#333333",
                    "arrowhead": "none",
                    "label_field": "data",
                },
            },
        }

        # Convert processes
        processes = tm.inputdata.get("processes", {})
        for proc_id, proc_data in processes.items():
            cd.nodes.append({
                "id": proc_id,
                "type": "process",
                "name": proc_data.get("label", proc_id),
                "description": proc_data.get("description", ""),
            })

        # Convert data stores
        datastores = tm.inputdata.get("datastores", {})
        for ds_id, ds_data in datastores.items():
            cd.nodes.append({
                "id": ds_id,
                "type": "datastore",
                "name": ds_data.get("label", ds_id),
                "type_info": ds_data.get("type", ""),
            })

        # Convert external entities
        externals = tm.inputdata.get("externals", {})
        for ext_id, ext_data in externals.items():
            cd.nodes.append({
                "id": ext_id,
                "type": "external",
                "name": ext_data.get("label", ext_id),
                "type_info": ext_data.get("type", ""),
            })

        # Convert data flows
        dataflows = tm.inputdata.get("dataflows", {})
        for flow_id, flow_data in dataflows.items():
            bidirectional = flow_data.get("bidirectional", False)
            cd.edges.append({
                "from": flow_data.get("source", ""),
                "to": flow_data.get("destination", ""),
                "type": "bidirectional" if bidirectional else "dataflow",
                "data": flow_data.get("label", flow_data.get("data", "")),
            })

        # Add trust boundaries as clusters
        boundaries = tm.inputdata.get("boundaries", {})
        for boundary_id, boundary_data in boundaries.items():
            elements = boundary_data.get("elements", [])
            if elements:
                cd.clusters.append({
                    "id": boundary_id,
                    "label": boundary_data.get("label", boundary_id),
                    "nodes": elements,
                    "style": {"color": "#E74C3C", "style": "dashed"},
                })

        cd._config_loaded = True
        return cd

    # Template methods

    @classmethod
    def get_templates_dir(cls) -> Path:
        """Get the path to the templates directory.

        Returns:
            Path to templates/custom-diagrams directory
        """
        # Try relative to this file first (development)
        module_dir = Path(__file__).parent.parent.parent.parent
        templates_dir = module_dir / "templates" / "custom-diagrams"
        if templates_dir.exists():
            return templates_dir

        # Try relative to working directory
        cwd_templates = Path.cwd() / "templates" / "custom-diagrams"
        if cwd_templates.exists():
            return cwd_templates

        raise CustomDiagramError(
            "Templates directory not found. "
            "Expected at templates/custom-diagrams/"
        )

    @classmethod
    def list_templates(cls, category: Optional[str] = None) -> List[Dict[str, str]]:
        """List available diagram templates.

        Args:
            category: Optional category filter (general, software, network, security, business)

        Returns:
            List of template information dictionaries with id, name, category, path

        Example:
            >>> templates = CustomDiagrams.list_templates()
            >>> templates = CustomDiagrams.list_templates("software")
        """
        try:
            templates_dir = cls.get_templates_dir()
        except CustomDiagramError:
            return []

        templates = []

        if category:
            categories = [templates_dir / category]
        else:
            categories = [d for d in templates_dir.iterdir() if d.is_dir()]

        for category_dir in categories:
            if not category_dir.exists():
                continue

            for template_file in category_dir.glob("*.toml"):
                templates.append({
                    "id": f"{category_dir.name}/{template_file.stem}",
                    "name": template_file.stem.replace("-", " ").title(),
                    "category": category_dir.name,
                    "path": str(template_file),
                })

        return sorted(templates, key=lambda t: (t["category"], t["name"]))

    @classmethod
    def list_template_categories(cls) -> List[str]:
        """List available template categories.

        Returns:
            List of category names
        """
        try:
            templates_dir = cls.get_templates_dir()
        except CustomDiagramError:
            return []

        categories = []
        for item in templates_dir.iterdir():
            if item.is_dir() and not item.name.startswith("."):
                categories.append(item.name)

        return sorted(categories)

    @classmethod
    def from_template(cls, template_id: str) -> "CustomDiagrams":
        """Load a diagram from a built-in template.

        Args:
            template_id: Template identifier in format "category/name"
                        e.g., "software/class-diagram", "network/topology"

        Returns:
            CustomDiagrams instance loaded with the template

        Raises:
            CustomDiagramError: If template not found

        Example:
            >>> cd = CustomDiagrams.from_template("software/class-diagram")
            >>> cd.nodes.append({"id": "new", "type": "class", "name": "NewClass"})
            >>> cd.BuildCustomDiagram(output="my-diagram.png")
        """
        try:
            templates_dir = cls.get_templates_dir()
        except CustomDiagramError as e:
            raise e

        # Parse template_id
        if "/" not in template_id:
            raise CustomDiagramError(
                f"Invalid template ID format: {template_id}. "
                "Expected format: category/name (e.g., 'software/class-diagram')"
            )

        category, name = template_id.split("/", 1)
        template_path = templates_dir / category / f"{name}.toml"

        if not template_path.exists():
            available = cls.list_templates(category)
            available_ids = [t["id"] for t in available]
            raise CustomDiagramError(
                f"Template not found: {template_id}. "
                f"Available templates in '{category}': {available_ids}"
            )

        cd = cls()
        cd.load(template_path)
        return cd

    def load_template(self, template_id: str) -> "CustomDiagrams":
        """Load a built-in template into this instance.

        Args:
            template_id: Template identifier in format "category/name"

        Returns:
            Self for method chaining

        Example:
            >>> cd = CustomDiagrams()
            >>> cd.load_template("general/flowchart")
            >>> cd.BuildCustomDiagram(output="flowchart.png")
        """
        templates_dir = self.get_templates_dir()

        if "/" not in template_id:
            raise CustomDiagramError(
                f"Invalid template ID format: {template_id}. "
                "Expected format: category/name"
            )

        category, name = template_id.split("/", 1)
        template_path = templates_dir / category / f"{name}.toml"

        if not template_path.exists():
            raise CustomDiagramError(f"Template not found: {template_id}")

        return self.load(template_path)

    def __repr__(self) -> str:
        """Return string representation."""
        status = "loaded" if self._config_loaded else "empty"
        title = self.settings.title if self.settings else "Untitled"
        return f"<CustomDiagrams({title!r}, {status}, nodes={len(self.nodes)}, edges={len(self.edges)})>"
