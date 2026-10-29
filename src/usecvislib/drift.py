#
# VULNEX -Universal Security Visualization Library-
#
# File: drift.py
# Author: Simon Roses Femerling
# Created: 2026-10-15
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Shared pieces of the drift (change) view, used by every module that supports it.

- Render marks: :class:`ElementMark` per node / edge, :class:`GroupInfo` per
  cluster, and the :class:`RenderView` both render engines draw from.
- :class:`DiffMarks`: the change status of each element, produced by a
  module's merge of two versions (see ``diffrender``).
- :class:`DriftStylingMixin`: how the Graphviz engine shows a change
  (border color, fading, a ``+`` / ``-`` / ``~`` label prefix, a legend in
  the title). The SVG engine's equivalent lives in the shared graph painter.
"""

import re
from dataclasses import dataclass, field
from typing import Any, Optional

from . import utils

# (source id, target id, kind); the kinds are module-specific
EdgeKey = tuple[str, str, str]

# Drift colors (VULNEX decision 2026-10-15); diff_colors and a preset's
# ``diff`` block override them
DIFF_COLORS = {"added": "#d6336c", "removed": "#94a3b8", "modified": "#7c3aed"}

# 35% opacity, appended to #rrggbb colors of removed elements (Graphviz engine)
REMOVED_ALPHA = "59"

DIFF_SIGNS = {"added": "+", "removed": "\u2212", "modified": "~"}

_HEX6 = re.compile(r"#[0-9a-fA-F]{6}")


@dataclass
class ElementMark:
    """Render-only facts about one node or edge."""

    diff: Optional[str] = None  # "added" | "removed" | "modified" | "unchanged"
    changed: list[str] = field(default_factory=list)  # changed fields of a modified element
    inferred: bool = False
    group: Optional[str] = None  # cluster the element sits in
    collapsed: Optional[dict[str, Any]] = None  # summary-node facts: member counts, worst CVSS
    count: int = 1  # edges merged into this one by a collapse


@dataclass
class GroupInfo:
    """A cluster of nodes, drawn expanded or collapsed into one summary node."""

    id: str
    label: str = ""
    color: Optional[str] = None
    members: list[str] = field(default_factory=list)
    collapsed: bool = False


@dataclass
class RenderView:
    """The sections to draw, and the marks and groups that style them."""

    data: dict[str, Any]
    groups: dict[str, GroupInfo] = field(default_factory=dict)
    nodes: dict[str, ElementMark] = field(default_factory=dict)
    edges: dict[EdgeKey, ElementMark] = field(default_factory=dict)

    def node_mark(self, node_id: str) -> Optional[ElementMark]:
        return self.nodes.get(node_id)

    def edge_mark(self, key: EdgeKey) -> Optional[ElementMark]:
        return self.edges.get(key)


@dataclass
class DiffMarks:
    """Change status per element for the drift view.

    ``nodes`` maps an element id to (status, changed field names); ``edges``
    maps an edge key to its status. Status is "added", "removed",
    "modified" or "unchanged". ``extra`` holds module-specific marks.
    """

    nodes: dict[str, tuple[str, list[str]]] = field(default_factory=dict)
    edges: dict[EdgeKey, str] = field(default_factory=dict)
    extra: dict[str, Any] = field(default_factory=dict)  # module-specific (e.g. inversion status)


def faded(color: str) -> str:
    """A #rrggbb color at the removed-element opacity; other color forms are kept as they are."""
    return color + REMOVED_ALPHA if _HEX6.fullmatch(str(color)) else color


class DriftStylingMixin:
    """Graphviz drift styling for a visualization with ``style`` and ``diff_colors``."""

    diff_colors: Optional[dict[str, str]] = None

    def diff_palette(self) -> dict[str, str]:
        """Drift colors: diff_colors, then the preset's ``diff`` block, then the defaults."""
        style = getattr(self, "style", None)
        preset = style.get("diff", {}) if isinstance(style, dict) else {}
        palette = {**DIFF_COLORS, **{k: v for k, v in preset.items() if k in DIFF_COLORS}}
        palette.update(self.diff_colors or {})
        return palette

    def _diff_title(self, name: str) -> str:
        """Graph title with the drift legend, as a Graphviz HTML label."""
        palette = self.diff_palette()
        legend = " &nbsp; ".join(
            f'<FONT COLOR="{palette[status]}">{sign} {status}</FONT>' for status, sign in DIFF_SIGNS.items()
        )
        title = str(name).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        return f'<{title}<BR/><FONT POINT-SIZE="10">{legend}</FONT>>'

    def _style_diff_node(self, attrs: dict[str, Any], label: str, mark: Any) -> str:
        """Apply a node's drift status to its Graphviz attributes; returns the label."""
        status = mark.diff if mark is not None else None
        if status not in DIFF_SIGNS:
            return label
        palette = self.diff_palette()
        if status == "removed":
            attrs["style"] = f"{attrs.get('style', 'filled')},dashed"
            attrs["color"] = palette["removed"]
            fill = str(attrs.get("fillcolor", ""))
            if fill:
                attrs["fillcolor"] = faded(fill)
            # The label is not faded with the fill: faded text on a faded
            # fill was close to invisible. Pick a color that reads on it.
            style = getattr(self, "style", None)
            page = style.get("graph", {}).get("bgcolor", "#ffffff") if isinstance(style, dict) else "#ffffff"
            shown = utils.blend_color(fill, page, int(REMOVED_ALPHA, 16) / 255)
            text = utils.readable_text_color(shown)
            if text:
                attrs["fontcolor"] = text
            elif "fontcolor" in attrs:
                attrs["fontcolor"] = faded(str(attrs["fontcolor"]))
        else:
            attrs["color"] = palette[status]
            attrs["penwidth"] = "3"
        if mark.changed:
            attrs["tooltip"] = "changed: " + ", ".join(mark.changed)
        if str(label).startswith("<"):  # HTML (icon) label: the border carries the status
            return label
        return f"{DIFF_SIGNS[status]} {label}"

    def _style_diff_edge(self, attrs: dict[str, Any], mark: Any) -> None:
        """Apply an edge's drift status to its Graphviz attributes in place."""
        status = mark.diff if mark is not None else None
        palette = self.diff_palette()
        if status == "added":
            attrs["color"] = palette["added"]
            try:
                attrs["penwidth"] = str(float(attrs.get("penwidth", 1.0)) + 1.0)
            except ValueError:
                attrs["penwidth"] = "2"
        elif status == "removed":
            attrs["style"] = "dashed"
            attrs["color"] = faded(palette["removed"])
        elif status == "modified":
            attrs["color"] = palette["modified"]
