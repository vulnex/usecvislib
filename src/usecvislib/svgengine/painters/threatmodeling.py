#
# VULNEX -Universal Security Visualization Library-
#
# File: threatmodeling.py
# Author: Simon Roses Femerling
# Created: 2026-09-01
# Last Modified: 2026-09-01
# Version: 0.5.0
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Data Flow Diagram painter for the SVG engine (Phase 3, mode 1).

The fourth general-graph painter. It renders the DFD view of a threat model:
external entities, processes, and data stores (each a distinct card shape),
directed data flows (labelled edges), and trust boundaries (drawn as dashed
cluster rectangles via the general-graph cluster support). It consumes the
same input sections as the Graphviz path in ``threatmodeling.py`` and mirrors
its structure; the STRIDE threat analysis and report are unaffected — this
painter only draws the diagram.

Layout is delegated to the ``GraphvizJsonLayout`` oracle and painting to the
shared :func:`.graph.render_graph_svg`; all DFD-specific semantics live here.
"""

import logging
from typing import Any

from ... import utils
from .. import metrics, themes
from ..scene import Scene, SceneEdge, SceneGroup, SceneNode
from .graph import attach_icon, render_graph_svg

logger = logging.getLogger(__name__)

MODULE_SLUG = "dfd"

# DFD element type -> (engine card shape, theme fill key).
_ELEMENT_KINDS = (
    ("externals", "external", "card"),
    ("processes", "process", "pill"),
    ("datastores", "datastore", "chamfer"),
)


def _items(section: Any):
    """Yield (id, data) pairs for a section that may be a dict or a list."""
    if isinstance(section, dict):
        return list(section.items())
    if isinstance(section, list):
        return [(item.get("id", f"item_{i}"), item) for i, item in enumerate(section) if isinstance(item, dict)]
    return []


def _wrap(label: str, font: dict, size: float, max_w: float) -> list[str]:
    return metrics.wrap_text(str(label), font["family"], size, max_w) or [str(label)]


def _build_scene(viz, theme: dict[str, Any]) -> Scene:
    """Translate the threat-model DFD sections into a fully-styled Scene."""
    data = viz.inputdata
    dfd = theme["dfd"]
    font = theme["font"]
    card = theme["card"]
    size = float(font["size"])
    max_w = float(card["max_label_width"])
    pad_x = float(card["padding_x"])
    pad_y = float(card["padding_y"])
    min_w = float(card["min_width"])

    name = data.get("model", {}).get("name", "Threat Model")
    scene = Scene(module=MODULE_SLUG, meta={"name": name})

    for section, kind, shape in _ELEMENT_KINDS:
        fill = dfd[kind]
        for elem_id, elem in _items(data.get(section, {})):
            label = elem.get("label", elem_id) if isinstance(elem, dict) else str(elem_id)
            lines = _wrap(label, font, size, max_w)
            text_w, text_h = metrics.measure_block(lines, font["family"], size)
            scene.nodes.append(
                SceneNode(
                    id=elem_id,
                    label=label,
                    kind="node",
                    lines=lines,
                    width=max(min_w, text_w + 2 * pad_x),
                    height=text_h + 2 * pad_y,
                    shape=shape,
                    fill=fill,
                    border=dfd["border"],
                    text_color=dfd["text"],
                    data={"node-id": utils.sanitize_node_id(elem_id), "label": label, "kind": kind},
                )
            )

    if not scene.nodes:
        raise utils.RenderError("Threat model has no DFD elements to render")

    _build_boundaries(scene, data, dfd)
    _build_flows(scene, data, dfd)
    for section, _kind, _shape in _ELEMENT_KINDS:
        for elem_id, elem in _items(data.get(section, {})):
            node = scene.node_by_id(elem_id)
            if node is not None and isinstance(elem, dict) and elem.get("image"):
                attach_icon(node, elem["image"], theme)
    return scene


def _build_boundaries(scene: Scene, data: dict, dfd: dict) -> None:
    """Map trust boundaries to dashed cluster groups (skip empty members)."""
    node_ids = {n.id for n in scene.nodes}
    claimed: set[str] = set()
    for boundary_id, boundary in _items(data.get("boundaries", {})):
        if not isinstance(boundary, dict):
            continue
        # A node lands in its first boundary only (clusters cannot overlap).
        members = [e for e in boundary.get("elements", []) if e in node_ids and e not in claimed]
        if not members:
            continue
        claimed.update(members)
        scene.groups.append(
            SceneGroup(
                id=utils.sanitize_node_id(boundary_id),
                label=boundary.get("label", boundary_id),
                members=members,
                fill=dfd["boundary_fill"],
                border=dfd["boundary_border"],
                text_color=dfd["boundary_text"],
                dashed=True,
            )
        )


def _build_flows(scene: Scene, data: dict, dfd: dict) -> None:
    """Add directed data-flow edges (with labels); skip dangling endpoints."""
    node_ids = {n.id for n in scene.nodes}
    color = dfd["dataflow"]
    for _, flow in _items(data.get("dataflows", {})):
        if not isinstance(flow, dict):
            continue
        src = flow.get("from")
        dst = flow.get("to")
        if src not in node_ids or dst not in node_ids:
            continue
        scene.edges.append(SceneEdge(src=src, dst=dst, kind="dataflow", color=color, label=flow.get("label") or None))


def render_svg(viz) -> str:
    """Render a threat-model DFD visualization instance to SVG text."""
    theme = themes.resolve(viz.style)
    scene = _build_scene(viz, theme)
    rankdir = str(theme["dfd"].get("rankdir", "LR"))
    return render_graph_svg(viz, scene, theme, MODULE_SLUG, rankdir=rankdir)
