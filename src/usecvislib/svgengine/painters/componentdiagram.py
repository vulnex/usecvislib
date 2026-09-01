#
# VULNEX -Universal Security Visualization Library-
#
# File: componentdiagram.py
# Author: Simon Roses Femerling
# Created: 2026-09-01
# Last Modified: 2026-09-01
# Version: 0.5.0
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Component Diagram painter for the SVG engine (Phase 3, mode 7).

The third general-graph painter and the first to use clusters: software
architecture layers become Graphviz ``cluster_*`` subgraphs (laid out and
bounded by the ``GraphvizJsonLayout`` oracle, painted as labelled background
rectangles by the shared :func:`.graph.render_graph_svg`). Components are
uniformly colored cards whose shape varies by type (mirroring the Graphviz
path, where layer background color — not node color — conveys grouping), and
typed connections (sync / async / event / bidirectional) map to solid, dashed,
or dotted-as-dashed edges.

This painter translates module data into a fully-styled ``Scene`` (nodes,
edges, and one group per layer); all component-diagram semantics live here so
the shared renderer stays module-agnostic.
"""

import logging
from typing import Any

from ... import utils
from .. import metrics, themes
from ..scene import Scene, SceneEdge, SceneGroup, SceneNode
from .graph import render_graph_svg

logger = logging.getLogger(__name__)

MODULE_SLUG = "componentdiagram"

# Component type -> engine card shape. Colors are uniform (theme component
# fill); the shape carries the type distinction, and layer clusters carry the
# grouping — matching the Graphviz path's semantics.
_TYPE_SHAPE = {
    "frontend": "card",
    "service": "card",
    "cache": "card",
    "queue": "card",
    "cli": "card",
    "database": "chamfer",
    "storage": "chamfer",
    "external_service": "pill",
}

# Connection style -> (edge kind, dashed). The scene edge model has a single
# dashed flag, so event (dotted in Graphviz) renders dashed like async.
_CONN_STYLE = {
    "sync": ("sync", False),
    "async": ("async", True),
    "event": ("event", True),
    "bidirectional": ("bidirectional", False),
}


def _wrap(label: str, font: dict, size: float, max_w: float) -> list[str]:
    return metrics.wrap_text(str(label), font["family"], size, max_w) or [str(label)]


def _build_scene(viz, theme: dict[str, Any]) -> Scene:
    """Translate the component-diagram input data into a fully-styled Scene."""
    # Idempotent normalization in case the painter is reached on freshly-set
    # inputdata rather than through load().
    viz._normalize_data()

    cd = theme["componentdiagram"]
    font = theme["font"]
    card = theme["card"]
    size = float(font["size"])
    max_w = float(card["max_label_width"])
    pad_x = float(card["padding_x"])
    pad_y = float(card["padding_y"])
    min_w = float(card["min_width"])
    palette = cd.get("layer_palette", ["#eef2f7"])

    name = viz.inputdata.get("title", "Component Diagram")
    scene = Scene(module=MODULE_SLUG, meta={"name": name})

    for i, layer in enumerate(viz._layers):
        if not isinstance(layer, dict):
            continue
        layer_name = layer.get("name", f"Layer {i}")
        members: list[str] = []
        for comp in layer.get("components", []):
            if not isinstance(comp, dict):
                continue
            comp_id = comp.get("id")
            if not comp_id:
                continue
            comp_name = comp.get("name", comp_id)
            comp_type = comp.get("type", "service")
            tech = comp.get("tech", "")
            lines = _wrap(comp_name, font, size, max_w)
            if tech:
                lines.append(tech)

            text_w, text_h = metrics.measure_block(lines, font["family"], size)
            node_data = {
                "node-id": utils.sanitize_node_id(comp_id),
                "label": comp_name,
                "kind": comp_type,
                "layer": layer_name,
            }
            if tech:
                node_data["tech"] = tech
            scene.nodes.append(
                SceneNode(
                    id=comp_id,
                    label=comp_name,
                    kind="node",
                    lines=lines,
                    width=max(min_w, text_w + 2 * pad_x),
                    height=text_h + 2 * pad_y,
                    shape=_TYPE_SHAPE.get(comp_type, "card"),
                    fill=cd["component"],
                    border=cd["component_border"],
                    text_color=cd["text"],
                    data=node_data,
                )
            )
            members.append(comp_id)

        if members:
            scene.groups.append(
                SceneGroup(
                    id=utils.sanitize_node_id(layer_name),
                    label=layer_name,
                    members=members,
                    fill=palette[i % len(palette)],
                    border=cd["layer_border"],
                    text_color=cd["layer_text"],
                )
            )

    if not scene.nodes:
        raise utils.RenderError("Component diagram has no nodes to render")

    _build_edges(scene, viz, cd)
    return scene


def _build_edges(scene: Scene, viz, cd: dict) -> None:
    """Add typed connection edges; skip dangling endpoints."""
    node_ids = {n.id for n in scene.nodes}
    color = cd["connection"]

    for conn in viz._connections:
        if not isinstance(conn, dict):
            continue
        src = conn.get("from")
        dst = conn.get("to")
        if src not in node_ids or dst not in node_ids:
            continue
        style = conn.get("style", "sync")
        kind, dashed = _CONN_STYLE.get(style, _CONN_STYLE["sync"])
        scene.edges.append(
            SceneEdge(src=src, dst=dst, kind=kind, color=color, dashed=dashed, label=conn.get("label") or None)
        )


def render_svg(viz) -> str:
    """Render a component diagram visualization instance to SVG text."""
    theme = themes.resolve(viz.style)
    scene = _build_scene(viz, theme)
    rankdir = str(theme["componentdiagram"].get("rankdir", "TB"))
    return render_graph_svg(viz, scene, theme, MODULE_SLUG, rankdir=rankdir)
