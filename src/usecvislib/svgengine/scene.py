#
# VULNEX -Universal Security Visualization Library-
#
# File: scene.py
# Author: Simon Roses Femerling
# Created: 2026-08-08
# Last Modified: 2026-08-08
# Version: 0.4.1
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Scene model for the SVG engine.

A Scene is the engine's internal representation of a visualization: plain
dataclasses decoupled from any module's input schema. Painters translate
module data into a Scene; layouts assign coordinates; the canvas paints it.
Canvas and layout code never import module code.
"""

from dataclasses import dataclass, field
from typing import Any, Optional

from .. import utils


class EngineNotSupportedError(utils.RenderError):
    """Raised when the SVG engine cannot handle the requested module or format."""


class StyleEngineMismatchError(utils.ConfigError):
    """Raised when a style preset targets a different rendering engine.

    Graphviz (``at_*``-style) and SVG (``sv_*``) presets share key names
    (``node``, ``root``, ``edge``) with incompatible sub-keys, so silent
    cross-loading would produce broken output rather than a clean failure.
    """


@dataclass
class SceneNode:
    """A single visual node (card) in the scene."""

    id: str
    label: str
    kind: str = "node"  # "root" | "node"
    lines: list[str] = field(default_factory=list)  # wrapped label lines
    width: float = 0.0
    height: float = 0.0
    x: float = 0.0  # center, set by layout
    y: float = 0.0  # center, set by layout
    shape: str = "card"  # card | pill | diamond | plain
    fill: Optional[str] = None  # overrides theme fill ("#hex" or "gradient:a>b")
    border: Optional[str] = None
    text_color: Optional[str] = None
    severity: Optional[str] = None  # lowercase cvss_to_severity_label value
    cvss: Optional[float] = None
    data: dict[str, str] = field(default_factory=dict)  # extra data-* attributes


@dataclass
class SceneEdge:
    """A directed connection between two scene nodes."""

    src: str
    dst: str
    kind: str = "edge"
    color: Optional[str] = None
    dashed: bool = False
    points: list[tuple[float, float]] = field(default_factory=list)


@dataclass
class SceneGroup:
    """A named cluster of scene nodes."""

    id: str
    label: str = ""
    members: list[str] = field(default_factory=list)


@dataclass
class Scene:
    """Complete scene: nodes, edges, groups, and module metadata."""

    module: str
    nodes: list[SceneNode] = field(default_factory=list)
    edges: list[SceneEdge] = field(default_factory=list)
    groups: list[SceneGroup] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)

    def node_by_id(self, node_id: str) -> Optional[SceneNode]:
        """Look up a node by its ID."""
        for node in self.nodes:
            if node.id == node_id:
                return node
        return None

    def children_map(self) -> dict[str, list[str]]:
        """Build an ordered parent -> children adjacency from edges.

        A node with multiple parents is attached to its first parent only
        (layout treats the scene as a tree; extra edges are still drawn).
        """
        children: dict[str, list[str]] = {}
        seen: set[str] = set()
        for edge in self.edges:
            if edge.dst in seen:
                continue
            seen.add(edge.dst)
            children.setdefault(edge.src, []).append(edge.dst)
        return children

    def bounds(self) -> tuple[float, float, float, float]:
        """Compute (min_x, min_y, max_x, max_y) over all placed nodes."""
        if not self.nodes:
            return (0.0, 0.0, 0.0, 0.0)
        min_x = min(n.x - n.width / 2 for n in self.nodes)
        min_y = min(n.y - n.height / 2 for n in self.nodes)
        max_x = max(n.x + n.width / 2 for n in self.nodes)
        max_y = max(n.y + n.height / 2 for n in self.nodes)
        return (min_x, min_y, max_x, max_y)
