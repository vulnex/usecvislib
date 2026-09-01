#
# VULNEX -Universal Security Visualization Library-
#
# File: maestro.py
# Author: Simon Roses Femerling
# Created: 2026-09-01
# Last Modified: 2026-09-01
# Version: 0.5.0
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""MAESTRO agent-centric graph painter for the SVG engine (Phase 3, mode 12).

The fifth and final general-graph painter. It renders MAESTRO's agent-centric
``graph`` view: agents become nodes clustered into their primary MAESTRO layer
(Security / L6 agents float outside clusters, mirroring the Graphviz path's
cross-cutting treatment), and cross-layer threats with an attack chain become
directed edges between the agents they traverse, colored per chain.

Only the ``graph`` view is SVG-native: the ``layered`` view is a fixed 7-band
architecture stack and ``heatmap`` is a Matplotlib chart, so both raise a clear
``EngineNotSupportedError`` pointing at ``view='graph'``. Layout is delegated to
the ``GraphvizJsonLayout`` oracle and painting to the shared
:func:`.graph.render_graph_svg`; all MAESTRO semantics live here.
"""

import logging
from typing import Any, Optional

from ... import utils
from .. import metrics, themes
from ..scene import EngineNotSupportedError, Scene, SceneEdge, SceneGroup, SceneNode
from .graph import render_graph_svg

logger = logging.getLogger(__name__)

MODULE_SLUG = "maestro"


def _wrap(label: str, font: dict, size: float, max_w: float) -> list[str]:
    return metrics.wrap_text(str(label), font["family"], size, max_w) or [str(label)]


def _severity_line(viz, agent_id: str) -> str:
    """Compact unmitigated-threat severity summary, e.g. 'C1 H2 L1' (or '')."""
    from ...maestro import ThreatStatus

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for t in viz.threats.values():
        if t.target_id != agent_id:
            continue
        if t.status in (ThreatStatus.MITIGATED.value, ThreatStatus.NOT_APPLICABLE.value):
            continue
        if t.severity in counts:
            counts[t.severity] += 1
    parts = [f"{sev[0].upper()}{n}" for sev, n in counts.items() if n > 0]
    return " ".join(parts)


def _build_scene(viz, theme: dict[str, Any]) -> Scene:
    """Translate MAESTRO agents + cross-layer chains into a styled Scene."""
    from ...maestro import LAYER_DISPLAY_ORDER, MaestroLayer

    ma = theme["maestro"]
    layers_cfg = ma.get("layers", {})
    font = theme["font"]
    card = theme["card"]
    size = float(font["size"])
    max_w = float(card["max_label_width"])
    pad_x = float(card["padding_x"])
    pad_y = float(card["padding_y"])
    min_w = float(card["min_width"])
    security_key = MaestroLayer.SECURITY.value

    name = viz.inputdata.get("meta", {}).get("name", "MAESTRO Threat Model")
    scene = Scene(module=MODULE_SLUG, meta={"name": name})

    def layer_colors(layer_key: str) -> tuple[str, str]:
        entry = layers_cfg.get(layer_key, {})
        return entry.get("cluster", "#eef2f7"), entry.get("agent", "#90caf9")

    # Agents grouped by primary layer (Security agents float, no cluster).
    by_layer: dict[str, list] = {}
    for agent in viz.agents.values():
        key = viz._primary_layer(agent)
        by_layer.setdefault(key, []).append(agent)

    def add_agent(agent, layer_key: str) -> None:
        _, agent_fill = layer_colors(layer_key)
        worst = viz._max_severity_for_agent(agent.id)
        severity = worst if worst in ("low", "medium", "high", "critical") else None
        border = ma.get("critical_border", "#e53935") if worst == "critical" else ma.get("agent_border", "#616161")
        lines = _wrap(agent.name, font, size, max_w)
        subtitle = " · ".join(p for p in (agent.type, agent.autonomy) if p)
        if subtitle:
            lines.append(subtitle)
        sev = _severity_line(viz, agent.id)
        if sev:
            lines.append(sev)
        text_w, text_h = metrics.measure_block(lines, font["family"], size)
        node_data = {
            "node-id": utils.sanitize_node_id(agent.id),
            "label": agent.name,
            "kind": "agent",
            "layer": layer_key,
        }
        if severity:
            node_data["severity"] = severity
        scene.nodes.append(
            SceneNode(
                id=agent.id,
                label=agent.name,
                kind="node",
                lines=lines,
                width=max(min_w, text_w + 2 * pad_x),
                height=text_h + 2 * pad_y,
                shape="card",
                fill=agent_fill,
                border=border,
                text_color=ma.get("text", "#1f2937"),
                severity=severity,
                data=node_data,
            )
        )

    # Emit clusters in canonical layer order; Security agents render ungrouped.
    for layer in LAYER_DISPLAY_ORDER:
        layer_key = layer.value
        members = by_layer.get(layer_key, [])
        if not members or layer_key == security_key:
            continue
        cluster_fill, _ = layer_colors(layer_key)
        for agent in members:
            add_agent(agent, layer_key)
        scene.groups.append(
            SceneGroup(
                id=utils.sanitize_node_id(layer_key),
                label=viz._layer_display_name(layer_key),
                members=[a.id for a in members],
                fill=cluster_fill,
                border=ma.get("layer_border", "#bdbdbd"),
                text_color=ma.get("layer_text", "#374151"),
            )
        )
    # Security-layer agents (floating, outside any cluster).
    for agent in by_layer.get(security_key, []):
        add_agent(agent, security_key)

    if not scene.nodes:
        raise utils.RenderError("MAESTRO model has no agents to render in the graph view")

    _build_chain_edges(scene, viz)
    return scene


def _build_chain_edges(scene: Scene, viz) -> None:
    """Cross-layer threats -> directed chain edges between traversed agents."""
    from itertools import pairwise

    node_ids = {n.id for n in scene.nodes}

    def pick_agent_for_layer(layer_value: str) -> Optional[str]:
        primary = next((a for a in viz.agents.values() if a.layers and a.layers[0] == layer_value), None)
        if primary is not None:
            return primary.id
        other = next((a for a in viz.agents.values() if layer_value in a.layers), None)
        return other.id if other is not None else None

    for clt in viz.cross_layer_threats.values():
        resolved = [aid for lv in clt.layers if (aid := pick_agent_for_layer(lv)) and aid in node_ids]
        cleaned: list[str] = []
        for aid in resolved:
            if not cleaned or cleaned[-1] != aid:
                cleaned.append(aid)
        if not cleaned:
            continue
        color = viz._chain_color(clt.id)
        if len(cleaned) == 1:
            # Whole chain runs through one agent: a labelled dashed self-loop.
            scene.edges.append(
                SceneEdge(
                    src=cleaned[0],
                    dst=cleaned[0],
                    kind="chain",
                    color=color,
                    dashed=True,
                    label=f"{clt.id} ({len(clt.layers)} layers)",
                )
            )
            continue
        for i, (src, dst) in enumerate(pairwise(cleaned)):
            scene.edges.append(
                SceneEdge(
                    src=src,
                    dst=dst,
                    kind="chain",
                    color=color,
                    label=f"{clt.id}: {clt.name}" if i == 0 else None,
                )
            )


def render_svg(viz) -> str:
    """Render a MAESTRO agent-centric graph to SVG text (``graph`` view only)."""
    if getattr(viz, "view", "layered") != "graph":
        raise EngineNotSupportedError(
            "The SVG engine renders the MAESTRO agent-centric 'graph' view. "
            "Re-run with view='graph' (CLI: -v graph). The layered and heatmap "
            "views are Graphviz/Matplotlib only."
        )
    theme = themes.resolve(viz.style)
    scene = _build_scene(viz, theme)
    rankdir = str(theme["maestro"].get("rankdir", "LR"))
    return render_graph_svg(viz, scene, theme, MODULE_SLUG, rankdir=rankdir)
