#
# VULNEX -Universal Security Visualization Library-
#
# File: dependencygraph.py
# Author: Simon Roses Femerling
# Created: 2026-02-14
# Last Modified: 2026-02-14
# Version: 0.4.0
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Dependency Graph Visualization Module.

This module provides visualization for module dependency graphs with
SLOC-based sizing and circular dependency detection.

Supports TOML, JSON, and YAML input formats.
"""

from typing import Any, Optional

from graphviz import Digraph

from . import utils
from .base import VisualizationBase


class DependencyGraphError(utils.RenderError):
    """Exception raised for dependency graph generation errors."""
    pass


class DependencyGraph(VisualizationBase):
    """Dependency graph visualization and analysis class.

    Creates module dependency visualizations with force-directed layout,
    SLOC-based node sizing, and circular dependency highlighting.

    Supports TOML, JSON, and YAML input formats.
    """

    STYLE_FILE = "config_dependencygraph.tml"
    DEFAULT_STYLE_ID = "dg_default"
    ALLOWED_EXTENSIONS = ['.toml', '.tml', '.json', '.yaml', '.yml']
    MAX_INPUT_SIZE = 10 * 1024 * 1024

    # Group colors for internal modules
    GROUP_COLORS = {
        "core": {"fillcolor": "#4a90d9", "fontcolor": "white"},
        "features": {"fillcolor": "#50c878", "fontcolor": "white"},
        "api": {"fillcolor": "#e67e22", "fontcolor": "white"},
        "infrastructure": {"fillcolor": "#9b59b6", "fontcolor": "white"},
        "tests": {"fillcolor": "#1abc9c", "fontcolor": "white"},
        "utils": {"fillcolor": "#f39c12", "fontcolor": "white"},
    }

    DEFAULT_INTERNAL_COLOR = {"fillcolor": "#5dade2", "fontcolor": "white"}
    EXTERNAL_COLOR = {"fillcolor": "#f8f8f8", "fontcolor": "#666666", "color": "#999999"}

    # Dependency type -> edge style
    DEPENDENCY_STYLES = {
        "import": {"style": "solid"},
        "framework": {"style": "dotted"},
        "runtime": {"style": "dashed"},
    }

    # Weight -> penwidth
    WEIGHT_MAP = {
        "light": "1",
        "medium": "2",
        "heavy": "3",
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
        self._modules: dict[str, dict[str, Any]] = {}
        self._dependencies: list[dict[str, Any]] = []
        self._circular: list[list[str]] = []
        self._circular_edges: set = set()
        self._temp_input: Optional[str] = None

    def __del__(self):
        if hasattr(self, '_temp_input') and self._temp_input:
            try:
                import os
                if os.path.exists(self._temp_input):
                    os.remove(self._temp_input)
            except Exception:
                pass

    def _default_style(self) -> dict[str, Any]:
        return {
            "graph": {
                "bgcolor": "white",
                "fontname": "Arial",
                "splines": "true",
                "overlap": "false",
                "sep": "+15",
                "pad": "0.5",
            },
            "module": {
                "shape": "box",
                "style": "filled,rounded",
                "fontname": "Arial",
                "fontsize": "11",
                "penwidth": "1.5",
                "margin": "0.15,0.08",
            },
            "external_module": {
                "shape": "box",
                "style": "dashed",
                "fontname": "Arial",
                "fontsize": "10",
                "penwidth": "1",
                "margin": "0.15,0.08",
                "fillcolor": "#f8f8f8",
                "fontcolor": "#666666",
                "color": "#999999",
            },
            "dependency": {
                "color": "#888888",
                "fontname": "Arial",
                "fontsize": "9",
                "fontcolor": "#888888",
            },
            "circular": {
                "color": "#cc0000",
                "style": "bold",
                "penwidth": "2.5",
                "fontcolor": "#cc0000",
            },
            "group": {
                "style": "filled,rounded",
                "fillcolor": "#f9f9f9",
                "color": "#dddddd",
                "fontname": "Arial Bold",
                "fontsize": "12",
                "fontcolor": "#555555",
                "penwidth": "1",
            },
        }

    def _get_metadata_root_key(self) -> str:
        return ""

    def _load_impl(self) -> dict[str, Any]:
        try:
            data = utils.ReadConfigFile(self.inputfile)
        except (utils.FileError, utils.ConfigError) as e:
            self.logger.error(f"Failed to load dependency graph from {self.inputfile}: {e}")
            raise DependencyGraphError(f"Failed to load dependency graph: {e}") from e
        except FileNotFoundError as e:
            self.logger.error(f"Input file not found: {self.inputfile}")
            raise DependencyGraphError(f"Input file not found: {e}") from e

        self.inputdata = data
        self._normalize_data()
        self._build_circular_edges()
        self.logger.debug(f"Loaded dependency graph with {len(self._modules)} modules, "
                          f"{len(self._dependencies)} dependencies, {len(self._circular)} circular")
        return data

    def _normalize_data(self) -> None:
        """Normalize the input data structures."""
        modules_raw = self.inputdata.get("modules", [])
        self._modules = {}

        if isinstance(modules_raw, list):
            for mod in modules_raw:
                if isinstance(mod, dict):
                    mod_id = mod.get("id", f"mod_{len(self._modules)}")
                    self._modules[mod_id] = mod
        elif isinstance(modules_raw, dict):
            self._modules = modules_raw

        deps_raw = self.inputdata.get("dependencies", [])
        if isinstance(deps_raw, list):
            self._dependencies = [d for d in deps_raw if isinstance(d, dict)]
        else:
            self._dependencies = []

        circ_raw = self.inputdata.get("circular", [])
        if isinstance(circ_raw, list):
            self._circular = [c for c in circ_raw if isinstance(c, list)]
        else:
            self._circular = []

    def _build_circular_edges(self) -> None:
        """Build set of circular dependency edge pairs."""
        self._circular_edges = set()
        for cycle in self._circular:
            if len(cycle) >= 2:
                for i in range(len(cycle)):
                    src = cycle[i]
                    tgt = cycle[(i + 1) % len(cycle)]
                    self._circular_edges.add((src, tgt))

    def _calc_node_size(self, sloc: int) -> tuple[str, str]:
        """Calculate node size proportional to SLOC. Linear scale from 0.5 to 2.0."""
        if not sloc or sloc <= 0:
            return "0.5", "0.4"

        # Get max sloc for scaling
        all_slocs = [m.get("sloc", 0) for m in self._modules.values() if m.get("sloc")]
        max_sloc = max(all_slocs) if all_slocs else 1

        ratio = min(sloc / max(max_sloc, 1), 1.0)
        width = 0.5 + ratio * 1.5  # Range: 0.5 to 2.0
        height = 0.4 + ratio * 1.0  # Range: 0.4 to 1.4
        return f"{width:.2f}", f"{height:.2f}"

    def _render_impl(self) -> None:
        """Build the dependency graph from loaded data."""
        title = self.inputdata.get("title", "Dependency Graph")

        graph_style = self.style.get("graph", self._default_style()["graph"])
        module_style = self.style.get("module", self._default_style()["module"])
        external_style = self.style.get("external_module", self._default_style()["external_module"])
        dep_style = self.style.get("dependency", self._default_style()["dependency"])
        circular_style = self.style.get("circular", self._default_style()["circular"])
        group_style = self.style.get("group", self._default_style()["group"])

        self.graph = Digraph(name=title, format=self.format, engine="fdp")
        graph_attrs = utils.stringify_dict(graph_style)
        self.graph.attr(**graph_attrs)

        if title:
            self.graph.attr(label=title, labelloc="t", fontsize="16")

        # Group modules by group
        groups = {}
        ungrouped = []
        for mod_id, mod_data in self._modules.items():
            group = mod_data.get("group", "")
            if group:
                if group not in groups:
                    groups[group] = []
                groups[group].append((mod_id, mod_data))
            else:
                ungrouped.append((mod_id, mod_data))

        # Render grouped modules in subgraphs
        for group_name, members in groups.items():
            with self.graph.subgraph(name=f"cluster_{group_name}") as sub:
                sub_attrs = utils.stringify_dict(group_style.copy())
                sub.attr(label=group_name, **sub_attrs)

                for mod_id, mod_data in members:
                    self._add_module_node(sub, mod_id, mod_data, module_style, external_style)

        # Render ungrouped modules
        for mod_id, mod_data in ungrouped:
            self._add_module_node(self.graph, mod_id, mod_data, module_style, external_style)

        # Draw dependency edges
        for dep in self._dependencies:
            src = dep.get("from")
            tgt = dep.get("to")
            if not src or not tgt:
                continue

            dep_type = dep.get("type", "import")
            weight = dep.get("weight", "medium")
            is_circular = (src, tgt) in self._circular_edges

            if is_circular:
                edge_attrs = {**dep_style}
                edge_attrs.update(circular_style)
                edge_attrs["label"] = " \u26a0 circular"
            else:
                edge_attrs = {**dep_style}
                type_style = self.DEPENDENCY_STYLES.get(dep_type, {})
                edge_attrs.update(type_style)

            edge_attrs["penwidth"] = self.WEIGHT_MAP.get(weight, "2")

            edge_attrs = utils.stringify_dict(edge_attrs)
            self.graph.edge(utils.sanitize_node_id(src), utils.sanitize_node_id(tgt), **edge_attrs)

        self.logger.debug(f"Rendered dependency graph with {len(self._modules)} modules")

    def _add_module_node(self, graph: Digraph, mod_id: str, mod_data: dict[str, Any],
                         module_style: dict[str, Any], external_style: dict[str, Any]) -> None:
        """Add a module node to the graph."""
        mod_name = mod_data.get("name", mod_id)
        mod_type = mod_data.get("type", "internal")
        sloc = mod_data.get("sloc", 0)
        group = mod_data.get("group", "")

        if mod_type == "external":
            node_attrs = {**external_style}
            version = mod_data.get("version", "")
            if version:
                label = f"<<B>{utils.escape_dot_label(mod_name)}</B><BR/><FONT POINT-SIZE='8'><I>v{utils.escape_dot_label(str(version))}</I></FONT>>"
            else:
                label = mod_name
        else:
            node_attrs = {**module_style}
            # Apply group color
            group_color = self.GROUP_COLORS.get(group, self.DEFAULT_INTERNAL_COLOR)
            node_attrs.update(group_color)

            # SLOC label
            if sloc and sloc > 0:
                label = f"<<B>{utils.escape_dot_label(mod_name)}</B><BR/><FONT POINT-SIZE='8'>{sloc:,} SLOC</FONT>>"
            else:
                label = mod_name

        # Size based on SLOC
        width, height = self._calc_node_size(sloc)
        node_attrs["width"] = width
        node_attrs["height"] = height
        node_attrs["fixedsize"] = "false"

        node_attrs = utils.stringify_dict(node_attrs)
        graph.node(utils.sanitize_node_id(mod_id), label, **node_attrs)

    def _draw_impl(self, outputfile: str) -> None:
        if self.graph is None:
            raise DependencyGraphError("Graph not rendered. Call render() first.")

        try:
            self.graph.render(outputfile, cleanup=True)
            self.logger.debug("Successfully wrote dependency graph visualization")
        except Exception as e:
            self.logger.error(f"Failed to render graph to {outputfile}: {e}")
            raise DependencyGraphError(f"Failed to render graph: {e}") from e

    def _validate_impl(self) -> list[str]:
        errors: list[str] = []

        if not self._modules:
            errors.append("No modules defined")

        # Check dependency references
        all_mod_ids = set(self._modules.keys())
        for i, dep in enumerate(self._dependencies):
            src = dep.get("from")
            tgt = dep.get("to")

            if not src:
                errors.append(f"Dependency {i} has no 'from' field")
            elif src not in all_mod_ids:
                errors.append(f"Dependency from '{src}' references undefined module")

            if not tgt:
                errors.append(f"Dependency {i} has no 'to' field")
            elif tgt not in all_mod_ids:
                errors.append(f"Dependency to '{tgt}' references undefined module")

        # Validate circular references exist in dependencies
        dep_edges = set()
        for dep in self._dependencies:
            src = dep.get("from")
            tgt = dep.get("to")
            if src and tgt:
                dep_edges.add((src, tgt))

        for cycle in self._circular:
            if len(cycle) >= 2:
                for i in range(len(cycle)):
                    src = cycle[i]
                    tgt = cycle[(i + 1) % len(cycle)]
                    if (src, tgt) not in dep_edges:
                        errors.append(f"Circular reference ({src} -> {tgt}) not found in dependencies")

        return errors

    def _get_stats_impl(self) -> dict[str, Any]:
        title = self.inputdata.get("title", "Unknown")

        internal_count = sum(1 for m in self._modules.values() if m.get("type", "internal") == "internal")
        external_count = sum(1 for m in self._modules.values() if m.get("type", "internal") == "external")

        groups = set()
        for m in self._modules.values():
            g = m.get("group", "")
            if g:
                groups.add(g)

        return {
            "title": title,
            "total_modules": len(self._modules),
            "total_dependencies": len(self._dependencies),
            "total_circular": len(self._circular),
            "internal_count": internal_count,
            "external_count": external_count,
            "groups": list(groups),
        }

    # Backward compatibility
    def BuildDependencyGraph(self) -> None:
        """Deprecated: Use build() instead."""
        self.build()
