#
# VULNEX -Universal Security Visualization Library-
#
# File: killchain.py
# Author: Simon Roses Femerling
# Created: 2026-08-09
# Last Modified: 2026-08-09
# Version: 0.4.1
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Kill Chain painter for the SVG engine (Phase 2, mode 9).

Renders the framework as a left-to-right swimlane: one column per phase,
a colored phase header at the top of each column, and the phase's
technique cards stacked beneath it. A single flow arrow runs across the
header row (the kill-chain progression), and incident technique paths are
drawn as curved cross-column connectors over the cards.

Phase-column x-centers come from the engine's LinearLayout (one lane node
per phase, sized to the widest card), so the flow axis matches the other
sequence modules; technique cards then stack manually inside each column.
Techniques are heat-colored by detection/mitigation coverage and carry a
small D/M coverage chip, so the diagram doubles as a detection-gap map.
"""

import logging
from itertools import pairwise
from typing import Any

from ... import utils
from .. import metrics, shapes, themes
from ..canvas import SvgCanvas
from ..layout import LinearLayout
from ..scene import Scene, SceneNode

logger = logging.getLogger(__name__)

MODULE_SLUG = "killchain"

# Coverage -> heat color (both / one of the two / neither).
_COVERAGE_FILLS = {
    "covered": "#27ae60",
    "partial": "#e0a53f",
    "gap": "#e74c3c",
}

_PHASE_GAP = 26.0  # horizontal gap between phase columns
_CARD_GAP = 12.0  # vertical gap between stacked technique cards
_HEADER_GAP = 20.0  # gap between a phase header and its first card
_MIN_COL_WIDTH = 96.0


def _coverage_kind(tech) -> str:
    if tech.detected and tech.mitigated:
        return "covered"
    if tech.detected or tech.mitigated:
        return "partial"
    return "gap"


def _tech_lines(tech, font, size, max_w) -> list[str]:
    """Wrap a technique's id + name into card label lines."""
    lines = []
    if tech.id and tech.id != tech.name:
        lines.append(tech.id)
    lines.extend(metrics.wrap_text(tech.name, font["family"], size, max_w))
    return lines or [tech.name]


def _header_height(theme) -> float:
    return float(theme["font"]["root_size"]) * 0.8 * 1.6 + 12.0


def _build_scene(viz, theme):
    """Build technique card nodes; return (scene, phases, grouped, tech_by_id)."""
    phases = viz.active_phases() or viz.phase_order
    grouped = viz.techniques_by_phase()

    font = theme["font"]
    card_cfg = theme["card"]
    size = float(font["size"])
    max_w = float(card_cfg["max_label_width"])
    pad_x = float(card_cfg["padding_x"])
    pad_y = float(card_cfg["padding_y"])

    scene = Scene(module=MODULE_SLUG, meta={"name": viz.inputdata.get("killchain", {}).get("name", "Kill Chain")})
    tech_by_id: dict[str, Any] = {}

    for phase in phases:
        for tech in grouped.get(phase, []):
            lines = _tech_lines(tech, font, size, max_w)
            text_w, text_h = metrics.measure_block(lines, font["family"], size)
            scene.nodes.append(
                SceneNode(
                    id=tech.id,
                    label=tech.name,
                    kind="node",
                    lines=lines,
                    width=max(float(card_cfg["min_width"]), text_w + 2 * pad_x),
                    height=text_h + 2 * pad_y,
                    shape="card",
                    severity=tech.severity if tech.severity in ("critical", "high", "medium", "low", "none") else None,
                    data={
                        "node-id": utils.sanitize_node_id(tech.id),
                        "label": tech.name,
                        "phase": tech.phase,
                        "coverage": _coverage_kind(tech),
                        "detected": "true" if tech.detected else "false",
                        "mitigated": "true" if tech.mitigated else "false",
                    },
                )
            )
            tech_by_id[tech.id] = tech

    return scene, phases, grouped, tech_by_id


def _layout(viz, scene, phases, theme):
    """Place cards on a shared row grid; return phase -> (cx, col_width, bottom).

    LinearLayout supplies the ordered, variable-width column centers (one
    lane node per phase, sized to its widest card / header). Rows come from
    the module's grid planner (shared with the Graphviz engine): incident
    flows keep one row across the phases they span, so every flow edge is
    a straight line and passes only through empty slots - never behind a
    card it does not connect to. Cards are centered vertically in their
    row, which is as tall as its tallest card.
    """
    font = theme["font"]
    header_size = float(font["root_size"]) * 0.8
    by_id = {n.id: n for n in scene.nodes}
    grid, _, _ = viz.plan_grid(phases)

    lane_scene = Scene(module=MODULE_SLUG)
    for phase in phases:
        widest = max((by_id[t].width for t in grid.get(phase, {}).values() if t), default=0.0)
        header_w = metrics.measure_text(phase, font["family"], header_size, bold=True) + 28.0
        col_w = max(_MIN_COL_WIDTH, widest, header_w)
        lane_scene.nodes.append(SceneNode(id=phase, label=phase, width=col_w, height=_header_height(theme)))
    LinearLayout(gap=_PHASE_GAP, orientation="LR").solve(lane_scene)

    row_count = max((row + 1 for rows in grid.values() for row in rows), default=0)
    row_heights = [
        max((by_id[t].height for rows in grid.values() if (t := rows.get(row))), default=0.0)
        for row in range(row_count)
    ]
    row_centers = []
    top = _header_height(theme) + _HEADER_GAP
    for height in row_heights:
        row_centers.append(top + height / 2)
        top += height + _CARD_GAP

    boxes: dict[str, tuple[float, float, float]] = {}
    for lane in lane_scene.nodes:
        for row, tech_id in grid.get(lane.id, {}).items():
            if tech_id:
                by_id[tech_id].x = lane.x
                by_id[tech_id].y = row_centers[row]
        boxes[lane.id] = (lane.x, lane.width, top)
    return boxes


def render_svg(viz) -> str:
    """Render a kill chain visualization instance to SVG text."""
    theme = themes.resolve(viz.style)
    scene, phases, _grouped, tech_by_id = _build_scene(viz, theme)
    if not scene.nodes:
        raise utils.RenderError("Kill chain has no techniques to render")

    boxes = _layout(viz, scene, phases, theme)

    font = theme["font"]
    card_cfg = theme["card"]
    edge_cfg = theme["edge"]
    effects = theme["effects"]
    page = theme["page"]
    kc = theme.get("killchain", {})
    phase_fill = kc.get("phase_fill", "#2c3e50")
    phase_text = kc.get("phase_text", "#ffffff")
    flow_color = kc.get("flow_color", edge_cfg["color"])
    size = float(font["size"])
    header_size = float(font["root_size"]) * 0.8
    header_h = _header_height(theme)

    canvas = SvgCanvas(MODULE_SLUG, viz.styleid)
    shadow_url = canvas.shadow(blur=float(effects["shadow_blur"])) if effects["shadow"] else ""

    css = [f".usv-{MODULE_SLUG} text {{ font-family: {font['family']}; }}"]
    if effects["hover_glow"]:
        css.append(
            f".usv-{MODULE_SLUG} .usv-node:hover rect "
            f"{{ stroke-width: {shapes.fmt(float(card_cfg['border_width']) + 1.2)}; }}"
        )
    canvas.set_css("\n".join(css))

    # Canvas bounds from header boxes (widest x) and the tallest column.
    pad = float(page["padding"])
    min_x = min(cx - w / 2 for cx, w, _ in boxes.values()) - pad
    max_x = max(cx + w / 2 for cx, w, _ in boxes.values()) + pad
    max_y = max((b for _, _, b in boxes.values()), default=header_h) + pad
    min_y = -pad
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

    # Flow arrow across the header row (phase progression)
    mid_y = header_h / 2
    for left_phase, right_phase in pairwise(phases):
        cx_l, w_l, _ = boxes[left_phase]
        cx_r, w_r, _ = boxes[right_phase]
        d = f"M {shapes.fmt(cx_l + w_l / 2)} {shapes.fmt(mid_y)} L {shapes.fmt(cx_r - w_r / 2)} {shapes.fmt(mid_y)}"
        g = shapes.group(["usv-flow"], {"from": left_phase, "to": right_phase})
        g.append(
            shapes.edge_path(d, flow_color, float(edge_cfg["width"]) + 0.4, marker_url=canvas.arrow_marker(flow_color))
        )
        canvas.add("edges", g)

    # Phase headers
    for phase in phases:
        cx, col_w, _ = boxes[phase]
        g = shapes.group(["usv-phase"], {"phase": phase})
        g.append(
            shapes.card(cx - col_w / 2, 0.0, col_w, header_h, header_h / 2, phase_fill, phase_fill, 0.0, shadow_url)
        )
        g.extend(
            shapes.text_lines(
                cx, (header_h - header_size * metrics.LINE_HEIGHT) / 2, [phase], header_size, phase_text, bold=True
            )
        )
        canvas.add("nodes", g)

    # Incident technique paths as curved cross-column connectors
    by_id = {n.id: n for n in scene.nodes}
    for incident in viz.incidents:
        chain = [tid for tid in incident.techniques if tid in by_id]
        for src_id, dst_id in pairwise(chain):
            a, b = by_id[src_id], by_id[dst_id]
            if abs(a.x - b.x) < 0.01:
                # Same-phase step: a vertical arrow between the stacked cards.
                down = b.y > a.y
                y1 = a.y + a.height / 2 if down else a.y - a.height / 2
                y2 = b.y - b.height / 2 if down else b.y + b.height / 2
                d = f"M {shapes.fmt(a.x)} {shapes.fmt(y1)} L {shapes.fmt(b.x)} {shapes.fmt(y2)}"
            else:
                forward = b.x > a.x
                x1 = a.x + a.width / 2 if forward else a.x - a.width / 2
                x2 = b.x - b.width / 2 if forward else b.x + b.width / 2
                d = shapes.curve_path_d(x1, a.y, x2, b.y, horizontal=True)
            g = shapes.group(
                ["usv-edge", "usv-edge--incident"],
                {"from": src_id, "to": dst_id, "incident": incident.incident_id},
            )
            g.append(
                shapes.edge_path(
                    d, edge_cfg["color"], float(edge_cfg["width"]), marker_url=canvas.arrow_marker(edge_cfg["color"])
                )
            )
            canvas.add("edges", g)

    # Technique cards + coverage chips
    border = theme["node"]["border"]
    for node in scene.nodes:
        tech = tech_by_id.get(node.id)
        cover = _coverage_kind(tech) if tech else "gap"
        fill = _COVERAGE_FILLS[cover]
        x, y = node.x - node.width / 2, node.y - node.height / 2

        classes = ["usv-node", "usv-node--technique", f"usv-cover--{cover}"]
        if node.severity:
            classes.append(f"usv-sev--{node.severity}")
        g = shapes.group(classes, node.data)
        g.append(
            shapes.card(
                x,
                y,
                node.width,
                node.height,
                float(card_cfg["radius"]),
                fill,
                border,
                float(card_cfg["border_width"]),
                shadow_url,
            )
        )
        text_h = len(node.lines) * size * metrics.LINE_HEIGHT
        g.extend(shapes.text_lines(node.x, node.y - text_h / 2, node.lines, size, "#ffffff"))
        canvas.add("nodes", g)

        if tech is not None and theme["badges"].get("coverage", True):
            chip = ("D" if tech.detected else "·") + ("M" if tech.mitigated else "·")
            chip_size = size * 0.72
            chip_w = metrics.measure_text(chip, font["family"], chip_size, bold=True)
            canvas.add(
                "badges",
                shapes.badge(
                    node.x + node.width / 2 - float(card_cfg["radius"]) * 0.4,
                    y + node.height,
                    chip,
                    chip_w,
                    fill=theme["badges"]["fill"],
                    text_color=theme["badges"]["text"],
                    size=chip_size,
                    ring=page["background"],
                    variant="coverage",
                ),
            )

    return canvas.to_string()
