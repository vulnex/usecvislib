#
# VULNEX -Universal Security Visualization Library-
#
# File: attackgraphs.py
# Author: Simon Roses Femerling
# Created: 2026-08-31
# Last Modified: 2026-08-31
# Version: 0.5.0
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Attack Graph painter for the SVG engine (Phase 3 pilot, mode 3).

The first general-graph painter: it consumes the same input data as the
Graphviz path in ``attackgraphs.py`` and mirrors its structure — typed nodes
(host / vulnerability / privilege / service / exploit) and typed edges
(network / exploit / structural host-to-vuln and host-to-service). Vulnerability nodes are filled
by CVSS severity (reusing the module's own CVSS helpers), so the SVG output
stays consistent with the Graphviz engine.

Layout is delegated to the engine's ``GraphvizJsonLayout`` oracle (Graphviz
computes positions and edge splines; we paint the SVG), and the actual
painting to the shared :func:`.graph.render_graph_svg`. This painter's whole
job is to translate module data into a fully-styled ``Scene``; it holds all
attack-graph-specific semantics so the shared renderer stays module-agnostic.
"""

import logging
from typing import Any

from ... import utils
from ...constants import cvss_to_color, cvss_to_severity_label
from ...cvss_unified import get_cvss_score_unified as get_cvss_score
from ...settings import is_cvss_enabled
from .. import metrics, themes
from ..scene import Scene, SceneEdge, SceneNode
from .graph import render_graph_svg

logger = logging.getLogger(__name__)

MODULE_SLUG = "attackgraph"

# Node kind -> engine card shape. Colors come from the theme's attackgraph block.
_KIND_SHAPE = {
    "host": "card",
    "vulnerability": "card",
    "privilege": "pill",
    "service": "card",
    "exploit": "chamfer",
}


def _wrap(label: str, font: dict, size: float, max_w: float) -> list[str]:
    return metrics.wrap_text(str(label), font["family"], size, max_w) or [str(label)]


def _build_scene(viz, theme: dict[str, Any]) -> Scene:
    """Translate the attack-graph input data into a fully-styled Scene."""
    # Input sections arrive as dicts after load(); normalize defensively in
    # case the painter is reached on freshly-set inputdata (idempotent).
    viz._normalize_data()
    data = viz.inputdata
    ag = theme["attackgraph"]
    font = theme["font"]
    card = theme["card"]
    size = float(font["size"])
    max_w = float(card["max_label_width"])
    pad_x = float(card["padding_x"])
    pad_y = float(card["padding_y"])
    min_w = float(card["min_width"])
    use_cvss_colors = bool(theme.get("severity", {}).get("use_cvss_colors", True)) and is_cvss_enabled("attack_graph")

    name = data.get("graph", {}).get("name", "Attack Graph")
    scene = Scene(module=MODULE_SLUG, meta={"name": name})

    def add_node(node_id, lines, kind, fill, severity=None, cvss=None, text_color="#ffffff"):
        text_w, text_h = metrics.measure_block(lines, font["family"], size)
        node_data = {
            "node-id": utils.sanitize_node_id(node_id),
            "label": lines[0] if lines else str(node_id),
            "kind": kind,
        }
        if severity:
            node_data["severity"] = severity
        if cvss is not None:
            node_data["cvss"] = f"{cvss:g}"
        scene.nodes.append(
            SceneNode(
                id=node_id,
                label=lines[0] if lines else str(node_id),
                kind="node",
                lines=lines,
                width=max(min_w, text_w + 2 * pad_x),
                height=text_h + 2 * pad_y,
                shape=_KIND_SHAPE.get(kind, "card"),
                fill=fill,
                border=ag["border"],
                text_color=text_color,
                severity=severity,
                cvss=cvss,
                data=node_data,
            )
        )

    # Hosts
    for host_id, host in _items(data.get("hosts", {})):
        label = host.get("label", host_id) if isinstance(host, dict) else host_id
        add_node(host_id, _wrap(label, font, size, max_w), "host", ag["host"])

    # Vulnerabilities (CVSS-driven fill + severity/cvss badge)
    for vuln_id, vuln in _items(data.get("vulnerabilities", {})):
        label = vuln.get("label", vuln_id) if isinstance(vuln, dict) else vuln_id
        lines = _wrap(label, font, size, max_w)
        score, _ = get_cvss_score(vuln.get("cvss"), vuln.get("cvss_vector")) if isinstance(vuln, dict) else (None, None)
        severity = None
        cvss = None
        fill = ag["vulnerability"]
        text_color = "#ffffff"
        if score is not None:
            severity = cvss_to_severity_label(score).lower()
            cvss = score
            lines.append(f"CVSS {score:g} · {cvss_to_severity_label(score)}")
            if use_cvss_colors:
                fill = cvss_to_color(score)
            if severity in ("low", "none"):
                text_color = "#000000"
        add_node(vuln_id, lines, "vulnerability", fill, severity=severity, cvss=cvss, text_color=text_color)

    # Privileges (optional [level] suffix)
    for priv_id, priv in _items(data.get("privileges", {})):
        label = priv.get("label", priv_id) if isinstance(priv, dict) else priv_id
        lines = _wrap(label, font, size, max_w)
        level = priv.get("level") if isinstance(priv, dict) else None
        if level:
            lines.append(f"[{level}]")
        add_node(priv_id, lines, "privilege", ag["privilege"])

    # Services (optional :port suffix)
    for svc_id, svc in _items(data.get("services", {})):
        label = svc.get("label", svc_id) if isinstance(svc, dict) else svc_id
        lines = _wrap(label, font, size, max_w)
        port = svc.get("port") if isinstance(svc, dict) else None
        if port:
            lines.append(f":{port}")
        add_node(svc_id, lines, "service", ag["service"])

    # Exploits
    for exploit_id, exploit in _items(data.get("exploits", {})):
        label = exploit.get("label", exploit_id) if isinstance(exploit, dict) else exploit_id
        add_node(exploit_id, _wrap(label, font, size, max_w), "exploit", ag["exploit"])

    if not scene.nodes:
        raise utils.RenderError("Attack graph has no nodes to render")

    _build_edges(scene, data, ag)
    return scene


def _build_edges(scene: Scene, data: dict, ag: dict) -> None:
    """Add typed edges mirroring the Graphviz path; skip dangling endpoints."""
    node_ids = {n.id for n in scene.nodes}
    exploit_width = float(ag.get("exploit_edge_width", 2.4))

    def add_edge(src, dst, kind, color, width=None, dashed=False, label=None):
        if src in node_ids and dst in node_ids:
            scene.edges.append(
                SceneEdge(src=src, dst=dst, kind=kind, color=color, width=width, dashed=dashed, label=label or None)
            )

    # Network edges (explicit from/to, with optional label)
    for _, edge in _items(data.get("network_edges", {})):
        if isinstance(edge, dict):
            add_edge(edge.get("from"), edge.get("to"), "network", ag["network_edge"], label=edge.get("label"))

    # Legacy dict-style network format: source -> [targets]
    network = data.get("network", {})
    if isinstance(network, dict):
        for source, targets in network.items():
            if isinstance(targets, list):
                for target in targets:
                    add_edge(source, target, "network", ag["network_edge"])

    # Exploit edges (precondition -> exploit -> postcondition)
    for exploit_id, exploit in _items(data.get("exploits", {})):
        if not isinstance(exploit, dict):
            continue
        pres = exploit.get("preconditions", []) or ([exploit["precondition"]] if exploit.get("precondition") else [])
        posts = exploit.get("postconditions", []) or (
            [exploit["postcondition"]] if exploit.get("postcondition") else []
        )
        for pre in pres:
            add_edge(pre, exploit_id, "exploit", ag["exploit_edge"], width=exploit_width)
        for post in posts:
            add_edge(exploit_id, post, "exploit", ag["exploit_edge"], width=exploit_width)

    # Structural host -> vulnerability links (drawn dotted in the Graphviz path)
    for vuln_id, vuln in _items(data.get("vulnerabilities", {})):
        if isinstance(vuln, dict):
            host = vuln.get("host") or vuln.get("affected_host")
            if host:
                add_edge(host, vuln_id, "structural", ag["structural_edge"], dashed=True)

    # Structural host -> service links (also dotted in the Graphviz path)
    for svc_id, svc in _items(data.get("services", {})):
        if isinstance(svc, dict) and svc.get("host"):
            add_edge(svc["host"], svc_id, "structural", ag["structural_edge"], dashed=True)


def _items(section: Any):
    """Yield (id, data) pairs for a section that may be a dict or a list."""
    if isinstance(section, dict):
        return list(section.items())
    if isinstance(section, list):
        return [(item.get("id", f"item_{i}"), item) for i, item in enumerate(section) if isinstance(item, dict)]
    return []


def render_svg(viz) -> str:
    """Render an attack graph visualization instance to SVG text."""
    theme = themes.resolve(viz.style)
    scene = _build_scene(viz, theme)
    rankdir = str(theme["attackgraph"].get("rankdir", "LR"))
    return render_graph_svg(viz, scene, theme, MODULE_SLUG, rankdir=rankdir)
