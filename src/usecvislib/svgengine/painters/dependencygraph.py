#
# VULNEX -Universal Security Visualization Library-
#
# File: dependencygraph.py
# Author: Simon Roses Femerling
# Created: 2026-09-01
# Last Modified: 2026-09-01
# Version: 0.5.0
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Dependency Graph painter for the SVG engine (Phase 3, mode 8).

The second general-graph painter: it consumes the same input data as the
Graphviz path in ``dependencygraph.py`` and mirrors its semantics — module
nodes colored by group (internal) or muted (external), sized proportionally
to SLOC, connected by dependency edges whose width reflects the declared
weight and whose style reflects the type, with circular-dependency edges
drawn bold and red plus a ``⚠ circular`` label.

Groups become node color families plus labelled cluster boxes, matching the
Graphviz path's per-group subgraphs.

Layout is delegated to the engine's ``GraphvizJsonLayout`` oracle and the
painting to the shared :func:`.graph.render_graph_svg`. This painter's whole
job is to translate module data into a fully-styled ``Scene``; it holds all
dependency-graph-specific semantics so the shared renderer stays
module-agnostic.
"""

import logging
from typing import Any

from ... import utils
from .. import metrics, themes
from ..scene import Scene, SceneEdge, SceneGroup, SceneNode
from .graph import render_graph_svg

logger = logging.getLogger(__name__)

MODULE_SLUG = "dependencygraph"

# Declared dependency weight -> edge stroke width (engine units).
_WEIGHT_WIDTH = {"light": 1.3, "medium": 1.7, "heavy": 2.4}

# Declared dependency type -> dashed stroke. The scene edge model carries a
# single ``dashed`` flag (no dotted), so framework/runtime both render dashed
# while import stays solid, mirroring the Graphviz path's solid vs. non-solid
# distinction.
_DASHED_TYPES = {"framework", "runtime"}


def _wrap(label: str, font: dict, size: float, max_w: float) -> list[str]:
    return metrics.wrap_text(str(label), font["family"], size, max_w) or [str(label)]


def _size_factor(sloc: int, max_sloc: int) -> float:
    """SLOC -> card scale factor in [1.0, 1.7].

    Mirrors the Graphviz path's SLOC-proportional node sizing, but as a
    multiplier over the text-fit card so labels stay legible.
    """
    if not sloc or sloc <= 0 or max_sloc <= 0:
        return 1.0
    ratio = min(sloc / max_sloc, 1.0)
    return 1.0 + ratio * 0.7


def _build_scene(viz, theme: dict[str, Any]) -> Scene:
    """Translate the dependency-graph input data into a fully-styled Scene."""
    # Idempotent normalization in case the painter is reached on freshly-set
    # inputdata rather than through load().
    viz._normalize_data()
    viz._build_circular_edges()

    data = viz.inputdata
    dg = theme["dependencygraph"]
    groups = dg.get("groups", {})
    font = theme["font"]
    card = theme["card"]
    size = float(font["size"])
    max_w = float(card["max_label_width"])
    pad_x = float(card["padding_x"])
    pad_y = float(card["padding_y"])
    min_w = float(card["min_width"])

    name = data.get("title", "Dependency Graph")
    scene = Scene(module=MODULE_SLUG, meta={"name": name})

    slocs = [int(m.get("sloc", 0) or 0) for m in viz._modules.values()]
    max_sloc = max(slocs) if slocs else 0

    for mod_id, mod in viz._modules.items():
        if not isinstance(mod, dict):
            continue
        mod_name = mod.get("name", mod_id)
        # Same rule as the Graphviz path: `type = "external"` or `external = true`.
        is_external = viz._is_external(mod)
        group = mod.get("group", "") or ""
        sloc = int(mod.get("sloc", 0) or 0)
        lines = _wrap(mod_name, font, size, max_w)

        if is_external:
            kind = "external"
            fill = dg["external_fill"]
            border = dg["external_border"]
            text_color = dg["external_text"]
            version = mod.get("version", "")
            if version:
                lines.append(f"v{version}")
        else:
            kind = "module"
            fill = groups.get(group, dg["internal"])
            border = dg["border"]
            # light group palettes (sv_minimal) need dark text
            text_color = utils.readable_text_color(fill) or "#ffffff"
            if sloc > 0:
                lines.append(f"{sloc:,} SLOC")

        text_w, text_h = metrics.measure_block(lines, font["family"], size)
        factor = _size_factor(sloc, max_sloc)
        width = max(min_w, text_w + 2 * pad_x) * factor
        height = (text_h + 2 * pad_y) * factor

        node_data = {"node-id": utils.sanitize_node_id(mod_id), "label": mod_name, "kind": kind}
        if group:
            node_data["group"] = group
        if sloc > 0:
            node_data["sloc"] = str(sloc)
        scene.nodes.append(
            SceneNode(
                id=mod_id,
                label=mod_name,
                kind="node",
                lines=lines,
                width=width,
                height=height,
                shape="card",
                fill=fill,
                border=border,
                text_color=text_color,
                data=node_data,
            )
        )

    if not scene.nodes:
        raise utils.RenderError("Dependency graph has no nodes to render")

    # One labelled cluster per group, as the Graphviz path draws (colors come
    # from the theme's cluster block).
    members_by_group: dict[str, list[str]] = {}
    for node in scene.nodes:
        group = node.data.get("group")
        if group:
            members_by_group.setdefault(group, []).append(node.id)
    for group, members in members_by_group.items():
        scene.groups.append(SceneGroup(id=utils.sanitize_node_id(group), label=group, members=members))

    _build_edges(scene, viz, dg)
    return scene


def _build_edges(scene: Scene, viz, dg: dict) -> None:
    """Add dependency edges; circular edges are drawn bold, red, and labelled."""
    node_ids = {n.id for n in scene.nodes}
    circular = viz._circular_edges
    circular_color = dg["circular_edge"]
    circular_width = float(dg.get("circular_width", 2.6))

    for dep in viz._dependencies:
        if not isinstance(dep, dict):
            continue
        src = dep.get("from")
        tgt = dep.get("to")
        if src not in node_ids or tgt not in node_ids:
            continue

        if (src, tgt) in circular:
            scene.edges.append(
                SceneEdge(
                    src=src,
                    dst=tgt,
                    kind="circular",
                    color=circular_color,
                    width=circular_width,
                    dashed=False,
                    label="⚠ circular",
                )
            )
            continue

        dep_type = dep.get("type", "import")
        weight = dep.get("weight", "medium")
        scene.edges.append(
            SceneEdge(
                src=src,
                dst=tgt,
                kind="dependency",
                width=_WEIGHT_WIDTH.get(weight, _WEIGHT_WIDTH["medium"]),
                dashed=dep_type in _DASHED_TYPES,
            )
        )


def render_svg(viz) -> str:
    """Render a dependency graph visualization instance to SVG text."""
    theme = themes.resolve(viz.style)
    scene = _build_scene(viz, theme)
    rankdir = str(theme["dependencygraph"].get("rankdir", "LR"))
    return render_graph_svg(viz, scene, theme, MODULE_SLUG, rankdir=rankdir)
