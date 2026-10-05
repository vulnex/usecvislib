#
# VULNEX -Universal Security Visualization Library-
#
# File: vulntree.py
# Author: Simon Roses Femerling
# Created: 2026-08-28
# Last Modified: 2026-08-28
# Version: 0.5.0
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Vulnerability Dependency Tree painter for the SVG engine (Phase 2, mode 11).

Consumes the same input data as the Graphviz path in ``vulntree.py`` and
mirrors its semantics: nodes are packages coloured by the highest CVE
severity present, direct dependencies get a bolder border, and an edge into
a package with a known-exploited CVE is drawn bold and dark. The active
render mode (``tree`` / ``vulnerable_only`` / ``critical_path``) is honoured
through the module's own ``_visible_nodes()``, so pruning stays identical
across engines — only the painting differs.

Layout is the engine's native ``TidyTreeLayout`` (Reingold-Tilford), so the
module renders without the system Graphviz binary. Multi-root supply chains
are laid out under a hidden synthetic root that is never painted.
"""

import logging
from typing import Any

from ... import utils
from ...vulntree import SEVERITY_COLORS, VulnSeverity
from .. import metrics, shapes, themes
from ..canvas import SvgCanvas
from ..layout import TidyTreeLayout
from ..scene import Scene, SceneEdge, SceneNode

logger = logging.getLogger(__name__)

MODULE_SLUG = "vulntree"

# Hidden parent that gathers multiple roots into one tree; never painted.
_SYNTH_ROOT = "\x00__vulntree_root__"


def _node_lines(dep, font, size, max_w) -> list[str]:
    """Wrap a package's title (name@version) plus a CVE summary line."""
    title = f"{dep.name}@{dep.version}" if dep.version else dep.name
    lines = metrics.wrap_text(title, font["family"], size, max_w) or [dep.name]
    if dep.vulnerabilities:
        worst = dep.highest_severity.value
        lines.append(f"{len(dep.vulnerabilities)} CVE · {worst} {dep.max_cvss:g}")
    return lines


def _build_scene(viz, theme: dict[str, Any]) -> tuple[Scene, str]:
    """Translate the visible dependency graph into a Scene.

    Returns:
        (scene, root_id) where root_id is a real package when a single root
        is visible, otherwise the hidden synthetic root.
    """
    deps = viz.dependencies
    visible = viz._visible_nodes()
    if not visible:
        raise utils.RenderError("Vulnerability tree has no visible dependencies to render")

    font = theme["font"]
    card_cfg = theme["card"]
    size = float(font["size"])
    max_w = float(card_cfg["max_label_width"])
    pad_x = float(card_cfg["padding_x"])
    pad_y = float(card_cfg["padding_y"])

    name = viz.inputdata.get("vulntree", {}).get("name", "Vulnerability Dependency Tree")
    scene = Scene(module=MODULE_SLUG, meta={"name": name})

    for dep_id in visible:
        dep = deps[dep_id]
        sev = dep.highest_severity
        lines = _node_lines(dep, font, size, max_w)
        text_w, text_h = metrics.measure_block(lines, font["family"], size)
        node_data = {
            "node-id": utils.sanitize_node_id(dep_id),
            "label": dep.name,
            "direct": "true" if dep.direct else "false",
        }
        if dep.vulnerabilities:
            node_data["cvss"] = f"{dep.max_cvss:g}"
            node_data["severity"] = sev.value
            node_data["exploited"] = "true" if any(v.exploited for v in dep.vulnerabilities) else "false"
        scene.nodes.append(
            SceneNode(
                id=dep_id,
                label=dep.name,
                kind="node",
                lines=lines,
                width=max(float(card_cfg["min_width"]), text_w + 2 * pad_x),
                height=text_h + 2 * pad_y,
                shape="card",
                severity=sev.value,
                cvss=dep.max_cvss if dep.vulnerabilities else None,
                data=node_data,
            )
        )

    for dep_id in visible:
        for child in deps[dep_id].dependencies:
            if child in visible:
                scene.edges.append(SceneEdge(src=dep_id, dst=child, kind="dep"))

    # Choose (or synthesize) a single layout root.
    visible_roots = [r for r in viz.root_packages if r in visible]
    if not visible_roots:
        child_ids = {e.dst for e in scene.edges}
        visible_roots = [n for n in visible if n not in child_ids] or [next(iter(visible))]

    if len(visible_roots) == 1:
        return scene, visible_roots[0]

    scene.nodes.append(SceneNode(id=_SYNTH_ROOT, label="", width=0.0, height=0.0))
    for root in visible_roots:
        scene.edges.append(SceneEdge(src=_SYNTH_ROOT, dst=root, kind="synthetic"))
    return scene, _SYNTH_ROOT


def _paint_edges(scene: Scene, canvas: SvgCanvas, theme: dict[str, Any], deps: dict[str, Any]) -> None:
    """Draw dependency edges as per-parent orthogonal drops on a shared bus."""
    edge_cfg = theme["edge"]
    vt = theme["vulntree"]
    base_color = edge_cfg["color"]
    base_width = float(edge_cfg["width"])
    exploited_color = vt["exploited_color"]
    exploited_width = float(vt["exploited_width"])

    by_id = {n.id: n for n in scene.nodes}
    groups: dict[str, list[SceneEdge]] = {}
    for edge in scene.edges:
        if edge.kind == "synthetic":
            continue
        groups.setdefault(edge.src, []).append(edge)

    for src_id, edges in groups.items():
        parent = by_id.get(src_id)
        if parent is None:
            continue
        p_bottom = parent.y + parent.height / 2
        child_tops = [by_id[e.dst].y - by_id[e.dst].height / 2 for e in edges if e.dst in by_id]
        if not child_tops:
            continue
        bus = p_bottom + (min(child_tops) - p_bottom) / 2

        for edge in edges:
            child = by_id.get(edge.dst)
            if child is None:
                continue
            dep = deps.get(edge.dst)
            exploited = bool(dep and any(v.exploited for v in dep.vulnerabilities))
            color = exploited_color if exploited else base_color
            width = exploited_width if exploited else base_width
            d = _edge_path_d(scene, parent, child, p_bottom, bus)
            classes = ["usv-edge", "usv-edge--dep"]
            if exploited:
                classes.append("usv-edge--exploited")
            group = shapes.group(classes, {"from": edge.src, "to": edge.dst})
            group.append(shapes.edge_path(d, color, width, marker_url=canvas.arrow_marker(color)))
            canvas.add("edges", group)


def _edge_path_d(scene: Scene, parent, child, p_bottom: float, bus: float) -> str:
    """Bus-style connector; edges that skip rows detour around blocking nodes.

    A dependency reached at two depths (express -> qs and express ->
    body-parser -> qs) sits on the deeper row, often straight below an
    intermediate node; the plain vertical drop would run hidden behind it.
    """
    c_top = child.y - child.height / 2
    blocking = [
        n
        for n in scene.nodes
        if n is not parent
        and n is not child
        and abs(n.x - child.x) < n.width / 2 + 2
        and n.y + n.height / 2 > bus
        and n.y - n.height / 2 < c_top
    ]
    if not blocking:
        return shapes.ortho_path_d(parent.x, p_bottom, child.x, c_top, corner=10.0, horizontal=False, mid=bus)
    lane_x = max(n.x + n.width / 2 for n in blocking) + 18.0
    approach_y = (max(n.y + n.height / 2 for n in blocking) + c_top) / 2
    offset = min(child.width / 4, 14.0)  # land beside the straight-in edge's arrow
    return shapes.rounded_polyline_d(
        [
            (parent.x, p_bottom),
            (parent.x, bus),
            (lane_x, bus),
            (lane_x, approach_y),
            (child.x + offset, approach_y),
            (child.x + offset, c_top),
        ]
    )


def render_svg(viz) -> str:
    """Render a vulnerability dependency tree instance to SVG text."""
    theme = themes.resolve(viz.style)
    scene, root_id = _build_scene(viz, theme)

    layout_cfg = theme["layout"]
    TidyTreeLayout(
        h_gap=float(layout_cfg["h_gap"]),
        v_gap=float(layout_cfg["v_gap"]),
        orientation="TB",
    ).solve(scene, root_id)

    font = theme["font"]
    card_cfg = theme["card"]
    effects = theme["effects"]
    page = theme["page"]
    vt = theme["vulntree"]
    size = float(font["size"])
    radius = float(card_cfg["radius"])
    default_border = theme["node"]["border"]

    canvas = SvgCanvas(MODULE_SLUG, viz.styleid)
    shadow_url = canvas.shadow(blur=float(effects["shadow_blur"])) if effects["shadow"] else ""

    css = [f".usv-{MODULE_SLUG} text {{ font-family: {font['family']}; }}"]
    if effects["hover_glow"]:
        css.append(
            f".usv-{MODULE_SLUG} .usv-node:hover rect "
            f"{{ stroke-width: {shapes.fmt(float(card_cfg['border_width']) + 1.2)}; }}"
        )
    canvas.set_css("\n".join(css))

    # Canvas bounds from the real (painted) nodes only — the synthetic root
    # and its empty band above the real roots are excluded.
    real = [n for n in scene.nodes if n.id != _SYNTH_ROOT]
    pad = float(page["padding"])
    min_x = min(n.x - n.width / 2 for n in real) - pad
    min_y = min(n.y - n.height / 2 for n in real) - pad
    max_x = max(n.x + n.width / 2 for n in real) + pad
    max_y = max(n.y + n.height / 2 for n in real) + pad
    canvas.finalize(min_x, min_y, max_x - min_x, max_y - min_y)
    canvas.add(
        "groups",
        shapes.card(
            min_x, min_y, max_x - min_x, max_y - min_y, 0, fill=page["background"], stroke="none", stroke_width=0
        ),
    )

    title_cfg = theme["title"]
    title = str(scene.meta.get("name", "")).strip()
    if title_cfg["show"] and title:
        canvas.add(
            "labels",
            shapes.title_text(min_x + pad * 0.5, min_y + pad * 0.55, title, float(title_cfg["size"]), page["text"]),
        )

    _paint_edges(scene, canvas, theme, viz.dependencies)

    for node in real:
        dep = viz.dependencies[node.id]
        sev = dep.highest_severity
        if sev == VulnSeverity.NONE:
            # Clean packages take the preset's node colors (sv_dark/sv_corporate
            # tune them); CVE severity colors stay fixed across presets.
            fill = theme["node"].get("fill", SEVERITY_COLORS[sev])
            text_color = theme["node"].get("text", "#ffffff")
        else:
            fill = SEVERITY_COLORS[sev]
            text_color = "#000000" if sev == VulnSeverity.LOW else "#ffffff"
        border = vt["direct_border"] if dep.direct else default_border
        border_width = float(vt["direct_border_width"]) if dep.direct else float(card_cfg["border_width"])

        classes = ["usv-node", "usv-node--package", f"usv-sev--{sev.value}"]
        if dep.direct:
            classes.append("usv-node--direct")
        group = shapes.group(classes, node.data)

        x, y = node.x - node.width / 2, node.y - node.height / 2
        group.append(shapes.card(x, y, node.width, node.height, radius, fill, border, border_width, shadow_url))
        text_h = len(node.lines) * size * metrics.LINE_HEIGHT
        group.extend(shapes.text_lines(node.x, node.y - text_h / 2, node.lines, size, text_color))
        canvas.add("nodes", group)

        # Highest-CVSS badge docked on the top-right corner
        if dep.vulnerabilities and dep.max_cvss > 0 and theme["badges"].get("cvss", True):
            badge_size = size * 0.78
            badge_label = f"{dep.max_cvss:g}"
            badge_w = metrics.measure_text(badge_label, font["family"], badge_size, bold=True)
            canvas.add(
                "badges",
                shapes.badge(
                    node.x + node.width / 2 - radius * 0.4,
                    y,
                    badge_label,
                    badge_w,
                    fill=theme["badges"]["fill"],
                    text_color=theme["badges"]["text"],
                    size=badge_size,
                    ring=page["background"],
                ),
            )

    return canvas.to_string()
