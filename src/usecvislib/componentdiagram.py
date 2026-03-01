#
# VULNEX -Universal Security Visualization Library-
#
# File: componentdiagram.py
# Author: Simon Roses Femerling
# Created: 2026-02-14
# Last Modified: 2026-02-14
# Version: 0.3.4
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Component Diagram Visualization Module.

This module provides visualization for layered software architecture diagrams.
Components are organized into layers (Client, Application, Data, etc.) and
connected by typed connections (sync, async, bidirectional, event).

Supports TOML, JSON, and YAML input formats.
"""

from typing import Dict, Any, Optional, List

from graphviz import Digraph

from . import utils
from .base import VisualizationBase


class ComponentDiagramError(utils.RenderError):
    """Exception raised for component diagram generation errors."""
    pass


class ComponentDiagram(VisualizationBase):
    """Component diagram visualization and analysis class.

    Creates layered architecture diagrams using Graphviz.

    Supports TOML, JSON, and YAML input formats.
    """

    STYLE_FILE = "config_componentdiagram.tml"
    DEFAULT_STYLE_ID = "cd_default"
    ALLOWED_EXTENSIONS = ['.toml', '.tml', '.json', '.yaml', '.yml']
    MAX_INPUT_SIZE = 10 * 1024 * 1024  # 10 MB

    # Component type -> Graphviz shape mapping
    COMPONENT_SHAPES = {
        "frontend": {"shape": "box", "style": "filled,rounded"},
        "service": {"shape": "box", "style": "filled,rounded"},
        "database": {"shape": "cylinder", "style": "filled"},
        "cache": {"shape": "box", "style": "filled,rounded"},
        "storage": {"shape": "folder", "style": "filled"},
        "queue": {"shape": "box", "style": "filled,rounded"},
        "external_service": {"shape": "ellipse", "style": "filled,dashed"},
        "cli": {"shape": "box", "style": "filled,rounded"},
    }

    # Connection style mapping
    CONNECTION_STYLES = {
        "sync": {"style": "solid", "arrowhead": "normal"},
        "async": {"style": "dashed", "arrowhead": "open"},
        "bidirectional": {"style": "solid", "dir": "both", "arrowhead": "normal", "arrowtail": "normal"},
        "event": {"style": "dotted", "arrowhead": "normal"},
    }

    def __init__(self, inputfile: str, outputfile: str, format: str = "",
                 styleid: str = "", validate_paths: bool = True) -> None:
        if format == "":
            format = "png"
        if styleid == "":
            styleid = None

        super().__init__(
            inputfile=inputfile,
            outputfile=outputfile,
            format=format,
            styleid=styleid,
            validate_paths=validate_paths
        )

        self.graph: Optional[Digraph] = None
        self._layers: List[Dict[str, Any]] = []
        self._components: Dict[str, Dict[str, Any]] = {}
        self._connections: List[Dict[str, Any]] = []
        self._temp_input: Optional[str] = None

    def __del__(self):
        if hasattr(self, '_temp_input') and self._temp_input:
            try:
                import os
                if os.path.exists(self._temp_input):
                    os.remove(self._temp_input)
            except Exception:
                pass

    def _default_style(self) -> Dict[str, Any]:
        return {
            "graph": {
                "rankdir": "TB",
                "bgcolor": "white",
                "fontname": "Arial",
                "splines": "ortho",
                "nodesep": "0.8",
                "ranksep": "1.0",
                "pad": "0.5",
            },
            "layer": {
                "style": "filled,rounded",
                "fillcolor": "#f5f5f5",
                "color": "#cccccc",
                "fontname": "Arial Bold",
                "fontsize": "14",
                "fontcolor": "#333333",
                "penwidth": "1",
            },
            "component": {
                "fontname": "Arial",
                "fontsize": "11",
                "fontcolor": "white",
                "fillcolor": "#4a90d9",
                "color": "#357abd",
                "penwidth": "1.5",
                "margin": "0.2,0.1",
            },
            "connection": {
                "color": "#666666",
                "fontname": "Arial",
                "fontsize": "9",
                "fontcolor": "#666666",
                "penwidth": "1.2",
            },
        }

    def _get_metadata_root_key(self) -> str:
        return ""

    def _load_impl(self) -> Dict[str, Any]:
        try:
            data = utils.ReadConfigFile(self.inputfile)
        except (utils.FileError, utils.ConfigError) as e:
            self.logger.error(f"Failed to load component diagram from {self.inputfile}: {e}")
            raise ComponentDiagramError(f"Failed to load component diagram: {e}")
        except FileNotFoundError as e:
            self.logger.error(f"Input file not found: {self.inputfile}")
            raise ComponentDiagramError(f"Input file not found: {e}")

        self.inputdata = data
        self._normalize_data()
        self.logger.debug(f"Loaded component diagram with {len(self._layers)} layers, "
                          f"{len(self._components)} components, {len(self._connections)} connections")
        return data

    def _normalize_data(self) -> None:
        """Normalize the input data structures."""
        # Layers - each layer contains components
        layers_raw = self.inputdata.get("layers", [])
        self._layers = []
        self._components = {}

        if isinstance(layers_raw, list):
            for layer in layers_raw:
                if isinstance(layer, dict):
                    self._layers.append(layer)
                    # Extract components from layer
                    for comp in layer.get("components", []):
                        if isinstance(comp, dict):
                            comp_id = comp.get("id", f"comp_{len(self._components)}")
                            comp["_layer"] = layer.get("name", "Unknown")
                            self._components[comp_id] = comp

        # Connections
        conns_raw = self.inputdata.get("connections", [])
        if isinstance(conns_raw, list):
            self._connections = [c for c in conns_raw if isinstance(c, dict)]
        else:
            self._connections = []

    def _render_impl(self) -> None:
        """Build the component diagram from loaded data."""
        title = self.inputdata.get("title", "Component Diagram")

        graph_style = self.style.get("graph", self._default_style()["graph"])
        layer_style = self.style.get("layer", self._default_style()["layer"])
        component_style = self.style.get("component", self._default_style()["component"])
        connection_style = self.style.get("connection", self._default_style()["connection"])

        self.graph = Digraph(name=title, format=self.format)
        graph_attrs = utils.stringify_dict(graph_style)
        self.graph.attr(**graph_attrs)

        if title:
            self.graph.attr(label=title, labelloc="t", fontsize="16")

        # Layer background colors for visual separation
        layer_colors = [
            "#e3f2fd", "#f3e5f5", "#e8f5e9", "#fff3e0",
            "#fce4ec", "#e0f7fa", "#f1f8e9", "#ede7f6",
        ]

        # Build layer subgraphs
        for i, layer_data in enumerate(self._layers):
            layer_name = layer_data.get("name", f"Layer {i}")
            layer_color = layer_colors[i % len(layer_colors)]

            with self.graph.subgraph(name=f"cluster_{layer_name.replace(' ', '_')}") as sub:
                sub_attrs = utils.stringify_dict(layer_style.copy())
                fill = sub_attrs.pop("fillcolor", layer_color)
                border = sub_attrs.pop("color", "#cccccc")
                sub.attr(
                    label=layer_name,
                    fillcolor=fill,
                    color=border,
                    **{k: v for k, v in sub_attrs.items()
                       if k not in ("label",)}
                )

                for comp in layer_data.get("components", []):
                    comp_id = comp.get("id")
                    if not comp_id:
                        continue

                    comp_name = comp.get("name", comp_id)
                    comp_tech = comp.get("tech", "")
                    comp_type = comp.get("type", "service")

                    # Get shape from component type
                    type_attrs = self.COMPONENT_SHAPES.get(comp_type, {"shape": "box", "style": "filled,rounded"})

                    # Build HTML-like label with name + tech
                    if comp_tech:
                        label = f"<<B>{utils.escape_dot_label(comp_name)}</B><BR/><FONT POINT-SIZE='9'><I>{utils.escape_dot_label(comp_tech)}</I></FONT>>"
                    else:
                        label = comp_name

                    node_attrs = {**component_style}
                    node_attrs["shape"] = type_attrs["shape"]
                    node_attrs["style"] = type_attrs["style"]
                    node_attrs = utils.stringify_dict(node_attrs)

                    sub.node(utils.sanitize_node_id(comp_id), label, **node_attrs)

        # Draw connections
        for conn in self._connections:
            src = conn.get("from")
            tgt = conn.get("to")
            if not src or not tgt:
                continue

            conn_label = conn.get("label", "")
            conn_type = conn.get("style", "sync")

            type_attrs = self.CONNECTION_STYLES.get(conn_type, self.CONNECTION_STYLES["sync"])

            edge_attrs = {**connection_style}
            edge_attrs.update(type_attrs)

            if conn_label:
                edge_attrs["label"] = f" {conn_label}"

            edge_attrs = utils.stringify_dict(edge_attrs)
            self.graph.edge(utils.sanitize_node_id(src), utils.sanitize_node_id(tgt), **edge_attrs)

        self.logger.debug(f"Rendered component diagram with {len(self._layers)} layers, "
                          f"{len(self._components)} components")

    def _draw_impl(self, outputfile: str) -> None:
        if self.graph is None:
            raise ComponentDiagramError("Graph not rendered. Call render() first.")

        try:
            self.graph.render(outputfile, cleanup=True)
            self.logger.debug("Successfully wrote component diagram visualization")
        except Exception as e:
            self.logger.error(f"Failed to render graph to {outputfile}: {e}")
            raise ComponentDiagramError(f"Failed to render graph: {e}")

    def _validate_impl(self) -> List[str]:
        errors: List[str] = []

        if not self.inputdata.get("layers"):
            errors.append("Missing or empty 'layers' section")

        if not self._components:
            errors.append("No components defined in any layer")

        # Check connection references
        all_comp_ids = set(self._components.keys())
        for i, conn in enumerate(self._connections):
            src = conn.get("from")
            tgt = conn.get("to")

            if not src:
                errors.append(f"Connection {i} has no 'from' field")
            elif src not in all_comp_ids:
                errors.append(f"Connection from '{src}' references undefined component")

            if not tgt:
                errors.append(f"Connection {i} has no 'to' field")
            elif tgt not in all_comp_ids:
                errors.append(f"Connection to '{tgt}' references undefined component")

            conn_style = conn.get("style", "sync")
            if conn_style not in self.CONNECTION_STYLES:
                errors.append(f"Connection {i} uses undefined style '{conn_style}'")

        # Check component types
        for comp_id, comp_data in self._components.items():
            comp_type = comp_data.get("type", "service")
            if comp_type not in self.COMPONENT_SHAPES:
                errors.append(f"Component '{comp_id}' has unknown type '{comp_type}'")

        return errors

    def _get_stats_impl(self) -> Dict[str, Any]:
        title = self.inputdata.get("title", "Unknown")

        components_per_layer = {}
        for layer in self._layers:
            layer_name = layer.get("name", "Unknown")
            components_per_layer[layer_name] = len(layer.get("components", []))

        return {
            "title": title,
            "total_layers": len(self._layers),
            "total_components": len(self._components),
            "total_connections": len(self._connections),
            "components_per_layer": components_per_layer,
        }

    # Backward compatibility
    def BuildComponentDiagram(self) -> None:
        """Deprecated: Use build() instead."""
        self.build()
