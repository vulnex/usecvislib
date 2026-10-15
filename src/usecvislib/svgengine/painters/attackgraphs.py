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
from ...attackgraph_view import merged_label, summary_label_lines
from ...constants import cvss_to_color, cvss_to_severity_label, cvss_to_text_color
from ...cvss_unified import get_cvss_score_unified as get_cvss_score
from ...settings import is_cvss_enabled
from .. import metrics, themes
from ..scene import Scene, SceneEdge, SceneGroup, SceneNode
from .graph import attach_icon, render_graph_svg

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
    """Translate the attack graph's render view into a fully-styled Scene."""
    # The view normalizes sections to dicts (idempotent), in case the painter
    # is reached on freshly-set inputdata
    view = viz.render_view()
    data = view.data
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

    def add_node(
        node_id, lines, kind, fill, severity=None, cvss=None, text_color=None, element=None, extra=None, inferred=False
    ):
        if text_color is None:
            # white on the amber privilege fill read at ~2:1
            text_color = utils.readable_text_color(fill) or "#ffffff"
        text_w, text_h = metrics.measure_block(lines, font["family"], size)
        node_data = {
            "node-id": utils.sanitize_node_id(node_id),
            "label": lines[0] if lines else str(node_id),
            "kind": kind,
        }
        if severity:
            node_data["severity"] = severity
        if cvss is not None:
            node_data["cvss"] = f"{cvss:.1f}"
        # Findings merged from several tools: "confirmed by N" chip
        source_count, source_names = utils.element_sources(element)
        if source_count:
            node_data["source-count"] = str(source_count)
        if source_names:
            node_data["sources"] = ",".join(source_names)
        node_data.update(extra or {})
        diff_mark = view.node_mark(node_id)
        diff = diff_mark.diff if diff_mark is not None else None
        if diff_mark is not None and diff_mark.changed:
            node_data["changed"] = ",".join(diff_mark.changed)
        if inferred:
            node_data["inferred"] = "true"
            confidence = utils.inferred_state(element)[1]
            if confidence:
                node_data["confidence"] = confidence
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
                sources=source_count,
                inferred=inferred,
                diff=diff,
                data=node_data,
            )
        )

    # Hosts
    for host_id, host in _items(data.get("hosts", {})):
        mark = view.node_mark(host_id)
        if mark is not None and mark.collapsed is not None:
            _add_summary_node(add_node, host_id, mark, view, ag, use_cvss_colors, theme)
            continue
        label = host.get("label", host_id) if isinstance(host, dict) else host_id
        add_node(host_id, _wrap(label, font, size, max_w), "host", ag["host"], element=host)

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
            # One decimal like the Graphviz label (":g" printed 9.0 as "9"); "*"
            # marks a score computed from the vector, as in Graphviz
            derived = "*" if vuln.get("cvss_vector") and vuln.get("cvss") is None else ""
            lines.append(f"CVSS {score:.1f}{derived} · {cvss_to_severity_label(score)}")
            if use_cvss_colors:
                fill = cvss_to_color(score)
                text_color = cvss_to_text_color(score)
            if severity in ("low", "none"):
                text_color = "#000000"
        add_node(
            vuln_id, lines, "vulnerability", fill, severity=severity, cvss=cvss, text_color=text_color, element=vuln
        )

    # Privileges (optional [level] suffix)
    for priv_id, priv in _items(data.get("privileges", {})):
        label = priv.get("label", priv_id) if isinstance(priv, dict) else priv_id
        lines = _wrap(label, font, size, max_w)
        level = priv.get("level") if isinstance(priv, dict) else None
        if level:
            lines.append(f"[{level}]")
        add_node(priv_id, lines, "privilege", ag["privilege"], element=priv)

    # Services (optional :port suffix)
    for svc_id, svc in _items(data.get("services", {})):
        label = svc.get("label", svc_id) if isinstance(svc, dict) else svc_id
        lines = _wrap(label, font, size, max_w)
        port = svc.get("port") if isinstance(svc, dict) else None
        if port:
            lines.append(f":{port}")
        add_node(svc_id, lines, "service", ag["service"], element=svc)

    # Exploits
    for exploit_id, exploit in _items(data.get("exploits", {})):
        label = exploit.get("label", exploit_id) if isinstance(exploit, dict) else exploit_id
        mark = view.node_mark(exploit_id)
        if mark is not None and mark.inferred:
            # A hypothesis: muted fill, dashed outline, "(inferred)" line
            inf = theme["inferred"]
            lines = [*_wrap(label, font, size, max_w), str(inf["marker"])]
            add_node(exploit_id, lines, "exploit", inf["fill"], text_color=inf["text"], element=exploit, inferred=True)
        else:
            add_node(exploit_id, _wrap(label, font, size, max_w), "exploit", ag["exploit"], element=exploit)

    if not scene.nodes:
        raise utils.RenderError("Attack graph has no nodes to render")

    _build_edges(scene, data, ag, view, theme.get("inferred"))
    _attach_icons(scene, data, theme)
    _add_clusters(scene, view, theme)
    return scene


def _add_summary_node(add_node, node_id, mark, view, ag, use_cvss_colors, theme) -> None:
    """A collapsed group's summary node: counts, worst-severity fill and CVSS badge."""
    facts = mark.collapsed
    max_cvss = facts.get("max_cvss")
    group = view.groups.get(mark.group)
    fill = (group.color if group else None) or theme["cluster"]["fill"]
    severity = None
    text_color = None
    if max_cvss is not None and is_cvss_enabled("attack_graph"):
        severity = cvss_to_severity_label(max_cvss).lower()
        if use_cvss_colors:
            fill = cvss_to_color(max_cvss)
            text_color = cvss_to_text_color(max_cvss)
            if severity in ("low", "none"):
                text_color = "#000000"
    counts = {
        "collapsed": "true",
        "cluster-id": utils.sanitize_node_id(mark.group),
        "member-count": str(facts.get("members", 0)),
        "hosts": str(facts.get("hosts", 0)),
        "vulnerabilities": str(facts.get("vulnerabilities", 0)),
    }
    if max_cvss is not None:
        counts["max-cvss"] = f"{max_cvss:.1f}"
    add_node(
        node_id,
        summary_label_lines(mark),
        "group",
        fill,
        severity=severity,
        cvss=max_cvss if severity else None,
        text_color=text_color,
        extra=counts,
    )


def _add_clusters(scene: Scene, view, theme: dict[str, Any]) -> None:
    """Expanded groups as labelled clusters around their drawn members."""
    drawn = {n.id for n in scene.nodes}
    cluster = theme["cluster"]
    for info in view.groups.values():
        members = [m for m in info.members if m in drawn]
        if info.collapsed or not members:
            continue
        scene.groups.append(
            SceneGroup(
                id=utils.sanitize_node_id(info.id),
                label=info.label,
                members=members,
                fill=info.color or cluster["fill"],
                border=cluster["border"],
                text_color=cluster["text"],
                data={"collapsed": "false"},
            )
        )


def _attach_icons(scene: Scene, data: dict, theme: dict) -> None:
    """Embed ``image`` icons for the node kinds the Graphviz path supports."""
    for section in ("hosts", "vulnerabilities", "privileges", "services"):
        for node_id, item in _items(data.get(section, {})):
            node = scene.node_by_id(node_id)
            if node is not None and isinstance(item, dict) and item.get("image"):
                attach_icon(node, item["image"], theme)


def _build_edges(scene: Scene, data: dict, ag: dict, view=None, inferred_theme=None) -> None:
    """Add typed edges mirroring the Graphviz path; skip dangling endpoints."""
    node_ids = {n.id for n in scene.nodes}
    exploit_width = float(ag.get("exploit_edge_width", 2.4))

    def add_edge(src, dst, kind, color, width=None, dashed=False, label=None):
        # N edges merged by a collapse: "\u00d7N" (and data-edge-count)
        mark = view.edge_mark((src, dst, kind)) if view is not None else None
        label = merged_label(mark, label)
        inferred = mark is not None and mark.inferred
        if inferred:
            # A hypothesis: muted, dashed, thinner
            color = (inferred_theme or {}).get("edge", "#a78bfa")
            width, dashed = 1.4, True
        if src in node_ids and dst in node_ids:
            scene.edges.append(
                SceneEdge(
                    src=src,
                    dst=dst,
                    kind=kind,
                    color=color,
                    width=width,
                    dashed=dashed,
                    label=label or None,
                    data={"edge-count": str(mark.count)} if mark is not None and mark.count > 1 else {},
                    inferred=inferred,
                    diff=mark.diff if mark is not None else None,
                )
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
    if getattr(viz, "diff_colors", None):
        theme["diff"] = {**theme["diff"], **viz.diff_colors}
    scene = _build_scene(viz, theme)
    if getattr(viz, "diff_marks", None) is not None:
        diff = theme["diff"]
        scene.meta["legend"] = [
            ("+ added", diff["added"]),
            ("\u2212 removed", diff["removed"]),
            ("~ modified", diff["modified"]),
        ]
    rankdir = str(theme["attackgraph"].get("rankdir", "LR"))
    return render_graph_svg(viz, scene, theme, MODULE_SLUG, rankdir=rankdir)
