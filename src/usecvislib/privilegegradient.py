#
# VULNEX -Universal Security Visualization Library-
#
# File: privilegegradient.py
# Author: Simon Roses Femerling
# Created: 2026-02-14
# Last Modified: 2026-02-14
# Version: 0.3.4
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Privilege Gradient Graph Visualization Module.

This module provides visualization and analysis tools for privilege gradient
graphs. Components are placed within trust zones (vertical colored columns
from low to high trust), connected by typed influence edges (Data, Feedback,
Resource, Control). It automatically detects and highlights privilege gradient
inversions where a lower-trust component has influence over a higher-trust
component.

Synthesized from CISA TIC 3.0, IEC 62443, and NIST Zero Trust frameworks.

Supports TOML, JSON, and YAML input formats.
"""

from collections import deque
from typing import Dict, Any, Optional, List, Set, Tuple

from graphviz import Digraph
import networkx as nx

from . import utils
from .base import VisualizationBase


class PrivilegeGradientError(utils.RenderError):
    """Exception raised for privilege gradient graph generation errors."""
    pass


class PrivilegeGradient(VisualizationBase):
    """Privilege gradient graph visualization and analysis class.

    Creates visual representations of trust zone architectures using
    Graphviz directed graphs with clustered trust zones. Supports
    inversion detection and influence path analysis.

    Supports TOML, JSON, and YAML input formats.

    Attributes:
        inputfile: Path to the configuration file (TOML, JSON, or YAML).
        outputfile: Path for the output visualization.
        format: Output format (png, pdf, svg, dot).
        styleid: Style identifier for visualization theming.
        inputdata: Parsed privilege gradient data.
        style: Style configuration dictionary.
        graph: Graphviz Digraph object.
    """

    STYLE_FILE = "config_privilegegradient.tml"
    DEFAULT_STYLE_ID = "pg_default"
    ALLOWED_EXTENSIONS = ['.toml', '.tml', '.json', '.yaml', '.yml']
    MAX_INPUT_SIZE = 10 * 1024 * 1024  # 10 MB

    DEFAULT_ZONES = [
        {"id": "Z0", "label": "Untrusted / External", "trust_level": 0,
         "color": "#ffcccc", "border_color": "#cc0000", "font_color": "#660000"},
        {"id": "Z1", "label": "Edge / DMZ", "trust_level": 1,
         "color": "#ffe0b2", "border_color": "#e65100", "font_color": "#663300"},
        {"id": "Z2", "label": "Application Tier", "trust_level": 2,
         "color": "#fff9c4", "border_color": "#f9a825", "font_color": "#665500"},
        {"id": "Z3", "label": "Control Plane", "trust_level": 3,
         "color": "#c8e6c9", "border_color": "#2e7d32", "font_color": "#1b5e20"},
        {"id": "Z4", "label": "Root of Trust", "trust_level": 4,
         "color": "#bbdefb", "border_color": "#1565c0", "font_color": "#0d47a1"},
    ]

    DEFAULT_INFLUENCE_TYPES = [
        {"id": "data", "label": "Data Flow", "color": "#3498db",
         "style": "solid", "arrowhead": "vee", "penwidth": "1.5"},
        {"id": "feedback", "label": "Feedback", "color": "#e67e22",
         "style": "dashed", "arrowhead": "vee", "penwidth": "1.5"},
        {"id": "resource", "label": "Resource", "color": "#27ae60",
         "style": "dotted", "arrowhead": "diamond", "penwidth": "2"},
        {"id": "control", "label": "Control", "color": "#8e44ad",
         "style": "bold", "arrowhead": "dot", "penwidth": "2"},
    ]

    def __init__(
        self,
        inputfile: str,
        outputfile: str,
        format: str = "",
        styleid: str = "",
        validate_paths: bool = True
    ) -> None:
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
        self._zones: Dict[str, Dict] = {}
        self._components: Dict[str, Dict] = {}
        self._influence_types: Dict[str, Dict] = {}
        self._influences: List[Dict] = []
        self._inversions: List[Dict] = []
        self._adjacency: Dict[str, List[str]] = {}
        self._reverse_adjacency: Dict[str, List[str]] = {}
        self._nx_graph: Optional[nx.DiGraph] = None
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
                "rankdir": "LR",
                "bgcolor": "white",
                "fontname": "Arial",
                "splines": "spline",
                "compound": "true",
                "nodesep": "0.6",
                "ranksep": "1.2",
            },
            "zone": {
                "style": "filled,rounded",
                "fontname": "Arial Bold",
                "fontsize": "13",
                "fontcolor": "#333333",
                "penwidth": "2",
            },
            "component": {
                "shape": "box",
                "style": "filled,rounded",
                "fontname": "Arial",
                "fontsize": "10",
                "fontcolor": "white",
                "margin": "0.15,0.08",
                "penwidth": "1.5",
            },
            "inversion": {
                "color": "#cc0000",
                "style": "bold",
                "fontname": "Arial Bold",
                "fontsize": "9",
                "fontcolor": "#cc0000",
                "penwidth": "3",
                "arrowhead": "normal",
                "arrowsize": "1.2",
            },
            "data_influence": {
                "color": "#3498db",
                "style": "solid",
                "fontname": "Arial",
                "fontsize": "9",
                "fontcolor": "#3498db",
                "penwidth": "1.5",
                "arrowhead": "vee",
            },
            "feedback_influence": {
                "color": "#e67e22",
                "style": "dashed",
                "fontname": "Arial",
                "fontsize": "9",
                "fontcolor": "#e67e22",
                "penwidth": "1.5",
                "arrowhead": "vee",
            },
            "resource_influence": {
                "color": "#27ae60",
                "style": "dotted",
                "fontname": "Arial",
                "fontsize": "9",
                "fontcolor": "#27ae60",
                "penwidth": "2",
                "arrowhead": "diamond",
            },
            "control_influence": {
                "color": "#8e44ad",
                "style": "bold",
                "fontname": "Arial",
                "fontsize": "9",
                "fontcolor": "#8e44ad",
                "penwidth": "2",
                "arrowhead": "dot",
            },
        }

    def _get_metadata_root_key(self) -> str:
        return "gradient"

    def _load_impl(self) -> Dict[str, Any]:
        try:
            data = utils.ReadConfigFile(self.inputfile)
        except (utils.FileError, utils.ConfigError) as e:
            self.logger.error(f"Failed to load privilege gradient from {self.inputfile}: {e}")
            raise PrivilegeGradientError(f"Failed to load privilege gradient: {e}")
        except FileNotFoundError as e:
            self.logger.error(f"Input file not found: {self.inputfile}")
            raise PrivilegeGradientError(f"Input file not found: {e}")

        self.inputdata = data
        self._normalize_data()
        self._build_adjacency()
        self._detect_inversions()
        self.logger.debug(f"Loaded privilege gradient with {len(self._components)} components, "
                          f"{len(self._influences)} influences, {len(self._inversions)} inversions")
        return data

    def _normalize_data(self) -> None:
        """Normalize array-of-tables to dicts keyed by 'id'."""
        # Zones
        zones_raw = self.inputdata.get("zones", [])
        if isinstance(zones_raw, list):
            self._zones = {}
            for item in zones_raw:
                if isinstance(item, dict):
                    zone_id = item.get("id", f"zone_{len(self._zones)}")
                    self._zones[zone_id] = item
        elif isinstance(zones_raw, dict):
            self._zones = zones_raw
        else:
            self._zones = {}

        if not self._zones:
            for z in self.DEFAULT_ZONES:
                self._zones[z["id"]] = z.copy()

        # Components
        comps_raw = self.inputdata.get("components", [])
        if isinstance(comps_raw, list):
            self._components = {}
            for item in comps_raw:
                if isinstance(item, dict):
                    comp_id = item.get("id", f"comp_{len(self._components)}")
                    self._components[comp_id] = item
        elif isinstance(comps_raw, dict):
            self._components = comps_raw
        else:
            self._components = {}

        # Influence types
        types_raw = self.inputdata.get("influence_types", [])
        if isinstance(types_raw, list):
            self._influence_types = {}
            for item in types_raw:
                if isinstance(item, dict):
                    type_id = item.get("id", f"type_{len(self._influence_types)}")
                    self._influence_types[type_id] = item
        elif isinstance(types_raw, dict):
            self._influence_types = types_raw
        else:
            self._influence_types = {}

        if not self._influence_types:
            for it in self.DEFAULT_INFLUENCE_TYPES:
                self._influence_types[it["id"]] = it.copy()

        # Influences (edges) - keep as list
        influences_raw = self.inputdata.get("influences", [])
        if isinstance(influences_raw, list):
            self._influences = influences_raw
        else:
            self._influences = []

    def _build_adjacency(self) -> None:
        """Build adjacency lists from loaded data."""
        self._adjacency = {}
        self._reverse_adjacency = {}

        for comp_id in self._components:
            self._adjacency[comp_id] = []
            self._reverse_adjacency[comp_id] = []

        for influence in self._influences:
            source = influence.get("from")
            target = influence.get("to")
            if source and target:
                if source not in self._adjacency:
                    self._adjacency[source] = []
                if target not in self._adjacency:
                    self._adjacency[target] = []
                if source not in self._reverse_adjacency:
                    self._reverse_adjacency[source] = []
                if target not in self._reverse_adjacency:
                    self._reverse_adjacency[target] = []
                self._adjacency[source].append(target)
                self._reverse_adjacency[target].append(source)

        self._build_nx_graph()

    def _build_nx_graph(self) -> None:
        """Build NetworkX DiGraph from adjacency data."""
        self._nx_graph = nx.DiGraph()

        for comp_id, comp_data in self._components.items():
            self._nx_graph.add_node(comp_id, **{
                k: v for k, v in comp_data.items() if k != "id"
            })

        for source, targets in self._adjacency.items():
            for target in targets:
                self._nx_graph.add_edge(source, target)

    def _detect_inversions(self) -> None:
        """Detect privilege gradient inversions."""
        self._inversions = []

        for influence in self._influences:
            source_id = influence.get("from")
            target_id = influence.get("to")

            if not source_id or not target_id:
                continue

            source_comp = self._components.get(source_id)
            target_comp = self._components.get(target_id)

            if not source_comp or not target_comp:
                continue

            source_zone_id = source_comp.get("zone")
            target_zone_id = target_comp.get("zone")

            if not source_zone_id or not target_zone_id:
                continue

            source_zone = self._zones.get(source_zone_id)
            target_zone = self._zones.get(target_zone_id)

            if not source_zone or not target_zone:
                continue

            source_trust = source_zone.get("trust_level", 0)
            target_trust = target_zone.get("trust_level", 0)

            if source_trust < target_trust:
                trust_gap = target_trust - source_trust
                if trust_gap >= 3:
                    severity = "critical"
                elif trust_gap >= 2:
                    severity = "high"
                else:
                    severity = "medium"

                self._inversions.append({
                    "from": source_id,
                    "to": target_id,
                    "from_zone": source_zone_id,
                    "to_zone": target_zone_id,
                    "from_trust": source_trust,
                    "to_trust": target_trust,
                    "trust_gap": trust_gap,
                    "severity": severity,
                    "influence_type": influence.get("type", "unknown"),
                    "label": influence.get("label", ""),
                })

    def _render_impl(self) -> None:
        """Build the privilege gradient graph from loaded data."""
        if "gradient" not in self.inputdata:
            raise PrivilegeGradientError("Missing 'gradient' section in privilege gradient configuration")

        graph_meta = self.inputdata.get("gradient", {})

        # Get styles
        graph_style = self.style.get("graph", self._default_style()["graph"])
        zone_style = self.style.get("zone", self._default_style()["zone"])
        component_style = self.style.get("component", self._default_style()["component"])
        inversion_style = self.style.get("inversion", self._default_style()["inversion"])

        # Create main graph
        self.graph = Digraph(
            name=graph_meta.get("name", "Privilege Gradient Graph"),
            format=self.format
        )

        graph_attrs = utils.stringify_dict(graph_style)
        self.graph.attr(**graph_attrs)

        if graph_meta.get("name"):
            self.graph.attr(label=graph_meta["name"], labelloc="t")

        # Sort zones by trust_level ascending (low trust left, high trust right)
        sorted_zones = sorted(
            self._zones.values(),
            key=lambda z: z.get("trust_level", 0)
        )

        # Build zone subgraphs
        zone_anchors = []
        for zone_data in sorted_zones:
            zone_id = zone_data.get("id", "unknown")
            zone_label = zone_data.get("label", zone_id)
            zone_color = zone_data.get("color", "#f0f0f0")
            zone_border = zone_data.get("border_color", "#999999")
            zone_font_color = zone_data.get("font_color", "#333333")
            trust_level = zone_data.get("trust_level", 0)

            with self.graph.subgraph(name=f"cluster_{zone_id}") as sub:
                sub_attrs = utils.stringify_dict(zone_style.copy())
                sub.attr(
                    label=f"{zone_label}\\n(Trust Level {trust_level})",
                    fillcolor=zone_color,
                    color=zone_border,
                    fontcolor=zone_font_color,
                    **{k: v for k, v in sub_attrs.items()
                       if k not in ("fillcolor", "color", "fontcolor", "label")}
                )

                # Add invisible anchor node for ordering
                anchor_id = f"_anchor_{zone_id}"
                sub.node(anchor_id, "", shape="point", style="invis", width="0", height="0")
                zone_anchors.append(anchor_id)

                # Add components in this zone
                for comp_id, comp_data in self._components.items():
                    if comp_data.get("zone") == zone_id:
                        node_attrs = comp_data.copy()
                        # Check for images
                        has_image = 'image' in node_attrs and node_attrs['image']
                        user_shape = comp_data.get('shape', '')
                        user_style_attr = comp_data.get('style', '')
                        user_fillcolor = comp_data.get('fillcolor', '')
                        wants_no_bg = user_shape in ('none', 'plaintext', 'point')
                        wants_bg = ('filled' in str(user_style_attr).lower()) or bool(user_fillcolor)
                        has_visible_shape = bool(user_shape) and not wants_no_bg
                        user_set_shape = (has_visible_shape or wants_bg) and not wants_no_bg

                        node_attrs = utils.merge_dicts(node_attrs, component_style)

                        # Set fillcolor from zone border if not specified by user
                        if "fillcolor" not in comp_data:
                            node_attrs["fillcolor"] = zone_border

                        utils.process_node_image(node_attrs, comp_id, self.logger, preserve_shape=user_set_shape)

                        if has_image and "fontcolor" not in comp_data:
                            node_attrs["fontcolor"] = "black"

                        node_attrs = utils.stringify_dict(node_attrs)
                        label = node_attrs.pop("label", comp_id)
                        # Remove non-graphviz keys
                        for key in ("id", "zone", "description", "type"):
                            node_attrs.pop(key, None)
                        sub.node(comp_id, label, **node_attrs)

        # Add invisible edges between zone anchors for ordering
        for i in range(len(zone_anchors) - 1):
            self.graph.edge(
                zone_anchors[i], zone_anchors[i + 1],
                style="invis", weight="100"
            )

        # Build inversion lookup for quick checking
        inversion_set = set()
        for inv in self._inversions:
            inversion_set.add((inv["from"], inv["to"]))

        # Draw influence edges
        for influence in self._influences:
            source = influence.get("from")
            target = influence.get("to")
            if not source or not target:
                continue

            inf_type = influence.get("type", "data")
            inf_label = influence.get("label", "")

            is_inversion = (source, target) in inversion_set

            if is_inversion:
                # Use inversion style
                edge_attrs = utils.stringify_dict(inversion_style.copy())
                # Find severity for this inversion
                inv_severity = "medium"
                for inv in self._inversions:
                    if inv["from"] == source and inv["to"] == target:
                        inv_severity = inv["severity"]
                        break
                severity_marker = {"critical": "!!!", "high": "!!", "medium": "!"}.get(inv_severity, "!")
                edge_attrs["label"] = f" {severity_marker} INVERSION {severity_marker}\\n{inf_label}" if inf_label else f" {severity_marker} INVERSION {severity_marker}"
            else:
                # Use influence type style
                style_key = f"{inf_type}_influence"
                type_style = self.style.get(style_key, self._default_style().get(style_key, {}))

                # Also check influence_types config for custom colors
                inf_type_config = self._influence_types.get(inf_type, {})
                edge_attrs = {}
                if type_style:
                    edge_attrs = utils.stringify_dict(type_style.copy())
                # Override with influence type config
                if inf_type_config.get("color"):
                    edge_attrs["color"] = inf_type_config["color"]
                    edge_attrs["fontcolor"] = inf_type_config["color"]
                if inf_type_config.get("style"):
                    edge_attrs["style"] = inf_type_config["style"]
                if inf_type_config.get("arrowhead"):
                    edge_attrs["arrowhead"] = inf_type_config["arrowhead"]
                if inf_type_config.get("penwidth"):
                    edge_attrs["penwidth"] = str(inf_type_config["penwidth"])

                if inf_label:
                    edge_attrs["label"] = f" {inf_label}"

            self.graph.edge(source, target, **edge_attrs)

        # Add legend
        self._add_legend()

        self.logger.debug(f"Rendered privilege gradient with {len(self._zones)} zones, "
                          f"{len(self._components)} components, {len(self._inversions)} inversions")

    def _add_legend(self) -> None:
        """Add a compact HTML-table legend at the bottom of the graph."""
        graph_style = self.style.get("graph", self._default_style()["graph"])
        bg = graph_style.get("bgcolor", "white")
        is_dark = bg.lower() in ("#1a1a2e", "#0d0d0d", "black", "#000000")
        font_color = "#e0e0e0" if is_dark else "#333333"
        legend_bg = "#2a2a3e" if is_dark else "#f8f8f8"
        legend_border = "#555555" if is_dark else "#cccccc"

        inv_style = self.style.get("inversion", self._default_style()["inversion"])
        inv_color = inv_style.get("color", "#cc0000")

        # Build legend as a single HTML table node
        rows = []
        for inf_type in self._influence_types.values():
            type_label = inf_type.get("label", inf_type.get("id", ""))
            type_color = inf_type.get("color", "#333333")
            line_style = inf_type.get("style", "solid")
            # Use a colored line character to represent the edge style
            if line_style == "dashed":
                line_repr = "- - - -"
            elif line_style == "dotted":
                line_repr = "&#8226; &#8226; &#8226; &#8226;"
            else:
                line_repr = "&#8212;&#8212;&#8212;&#8212;"
            rows.append(
                f'<TD><FONT COLOR="{type_color}">{line_repr} &#9654;</FONT></TD>'
                f'<TD><FONT COLOR="{font_color}" POINT-SIZE="8">{type_label}</FONT></TD>'
            )

        # Inversion entry
        rows.append(
            f'<TD><FONT COLOR="{inv_color}"><B>&#8212;&#8212;&#8212;&#8212; &#9654;</B></FONT></TD>'
            f'<TD><FONT COLOR="{inv_color}" POINT-SIZE="8"><B>INVERSION</B></FONT></TD>'
        )

        # Build horizontal table: all entries in one row
        cells = "".join(f"<TD> </TD>{r}" for r in rows)
        html_label = (
            f'<<TABLE BORDER="1" CELLBORDER="0" CELLSPACING="4" CELLPADDING="2" '
            f'BGCOLOR="{legend_bg}" COLOR="{legend_border}" STYLE="ROUNDED">'
            f'<TR><TD COLSPAN="{len(rows) * 3}"><B><FONT COLOR="{font_color}" POINT-SIZE="9">'
            f'Legend</FONT></B></TD></TR>'
            f'<TR>{cells}</TR></TABLE>>'
        )

        self.graph.node(
            "_legend", label=html_label, shape="none", margin="0",
        )

    def _draw_impl(self, outputfile: str) -> None:
        if self.graph is None:
            raise PrivilegeGradientError("Graph not rendered. Call render() first.")

        try:
            self.graph.render(outputfile, cleanup=True)
            self.logger.debug("Successfully wrote privilege gradient visualization")
        except Exception as e:
            self.logger.error(f"Failed to render graph to {outputfile}: {e}")
            raise PrivilegeGradientError(f"Failed to render graph: {e}")

    def _validate_impl(self) -> List[str]:
        errors = []

        if "gradient" not in self.inputdata:
            errors.append("Missing 'gradient' section in privilege gradient configuration")

        # Check zones
        if len(self._zones) < 2:
            errors.append("At least 2 trust zones are required")

        # Check for duplicate zone IDs (already handled by dict keying, but check trust levels)
        trust_levels = {}
        for zone_id, zone_data in self._zones.items():
            tl = zone_data.get("trust_level")
            if tl is not None and tl in trust_levels:
                errors.append(f"Duplicate trust_level {tl} in zones '{trust_levels[tl]}' and '{zone_id}'")
            if tl is not None:
                trust_levels[tl] = zone_id

        # Check component zone references
        for comp_id, comp_data in self._components.items():
            zone_ref = comp_data.get("zone")
            if not zone_ref:
                errors.append(f"Component '{comp_id}' has no zone reference")
            elif zone_ref not in self._zones:
                errors.append(f"Component '{comp_id}' references undefined zone '{zone_ref}'")

        # Check influence references
        all_comp_ids = set(self._components.keys())
        for i, influence in enumerate(self._influences):
            source = influence.get("from")
            target = influence.get("to")
            inf_type = influence.get("type", "data")

            if not source:
                errors.append(f"Influence {i} has no 'from' field")
            elif source not in all_comp_ids:
                errors.append(f"Influence from '{source}' references undefined component")

            if not target:
                errors.append(f"Influence {i} has no 'to' field")
            elif target not in all_comp_ids:
                errors.append(f"Influence to '{target}' references undefined component")

            if inf_type not in self._influence_types:
                errors.append(f"Influence {i} uses undefined type '{inf_type}'")

        return errors

    def _get_stats_impl(self) -> Dict[str, Any]:
        graph_meta = self.inputdata.get("gradient", {})

        components_per_zone: Dict[str, int] = {}
        for comp_data in self._components.values():
            zone = comp_data.get("zone", "unknown")
            components_per_zone[zone] = components_per_zone.get(zone, 0) + 1

        max_trust_gap = 0
        for inv in self._inversions:
            gap = inv.get("trust_gap", 0)
            if gap > max_trust_gap:
                max_trust_gap = gap

        return {
            "name": graph_meta.get("name", "Unknown"),
            "total_zones": len(self._zones),
            "total_components": len(self._components),
            "total_influences": len(self._influences),
            "total_inversions": len(self._inversions),
            "inversions": self._inversions,
            "components_per_zone": components_per_zone,
            "max_trust_gap": max_trust_gap,
        }

    # Public analysis methods

    def detect_inversions(self) -> List[Dict]:
        """Return the list of detected privilege gradient inversions."""
        if not self._loaded:
            self.load()
        return self._inversions

    def get_inversion_summary(self) -> Dict[str, Any]:
        """Get inversion counts by severity."""
        if not self._loaded:
            self.load()

        counts = {"critical": 0, "high": 0, "medium": 0}
        for inv in self._inversions:
            severity = inv.get("severity", "medium")
            if severity in counts:
                counts[severity] += 1

        return {
            "total": len(self._inversions),
            "by_severity": counts,
        }

    def get_zone_influence_matrix(self) -> Dict[str, Dict[str, int]]:
        """Get matrix of influence counts between zones."""
        if not self._loaded:
            self.load()

        zone_ids = list(self._zones.keys())
        matrix: Dict[str, Dict[str, int]] = {}
        for z in zone_ids:
            matrix[z] = {z2: 0 for z2 in zone_ids}

        for influence in self._influences:
            source_id = influence.get("from")
            target_id = influence.get("to")
            if not source_id or not target_id:
                continue
            source_comp = self._components.get(source_id)
            target_comp = self._components.get(target_id)
            if not source_comp or not target_comp:
                continue
            src_zone = source_comp.get("zone")
            tgt_zone = target_comp.get("zone")
            if src_zone in matrix and tgt_zone in matrix[src_zone]:
                matrix[src_zone][tgt_zone] += 1

        return matrix

    def find_influence_paths(
        self, source: str, target: str, max_paths: int = 10
    ) -> List[List[str]]:
        """Find influence paths between two components using BFS."""
        if not self._loaded:
            self.load()

        if source not in self._adjacency or target not in self._adjacency:
            return []

        paths: List[List[str]] = []
        queue: deque = deque([(source, [source])])
        visited_paths: Set[Tuple[str, ...]] = set()

        while queue and len(paths) < max_paths:
            current, path = queue.popleft()

            if current == target and len(path) > 1:
                path_tuple = tuple(path)
                if path_tuple not in visited_paths:
                    visited_paths.add(path_tuple)
                    paths.append(path)
                continue

            if len(path) > 20:  # depth limit
                continue

            for neighbor in self._adjacency.get(current, []):
                if neighbor not in path:  # avoid cycles
                    queue.append((neighbor, path + [neighbor]))

        return paths

    def analyze_critical_components(self, top_n: int = 10) -> List[Dict[str, Any]]:
        """Analyze components by degree centrality."""
        if not self._loaded:
            self.load()

        if self._nx_graph is None:
            self._build_nx_graph()

        centrality = nx.degree_centrality(self._nx_graph)
        results = []

        for comp_id, score in centrality.items():
            comp_data = self._components.get(comp_id, {})
            in_deg = len(self._reverse_adjacency.get(comp_id, []))
            out_deg = len(self._adjacency.get(comp_id, []))

            results.append({
                "id": comp_id,
                "label": comp_data.get("label", comp_id),
                "zone": comp_data.get("zone", "unknown"),
                "in_degree": in_deg,
                "out_degree": out_deg,
                "degree_centrality": round(score, 6),
            })

        results.sort(key=lambda x: x["degree_centrality"], reverse=True)
        return results[:top_n]

    # Backward compatibility

    def BuildPrivilegeGradient(self) -> None:
        """Deprecated: Use build() instead."""
        self.build()
