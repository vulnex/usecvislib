#
# VULNEX -Universal Security Visualization Library-
#
# File: graph.py
# Author: Simon Roses Femerling
# Created: 2026-08-31
# Last Modified: 2026-08-31
# Version: 0.5.0
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Shared general-graph renderer for the SVG engine (Phase 3).

General-graph modules (Attack Graphs, and later Dependency Graph, Component
Diagram, DFD, MAESTRO agent graph) share one paint path: their painter maps
module data into a fully-styled ``Scene`` — each ``SceneNode`` carrying its
``fill`` / ``border`` / ``text_color`` / ``shape`` and each ``SceneEdge`` its
``color`` / ``width`` / ``dashed`` — and then calls :func:`render_graph_svg`.

This function is deliberately module-agnostic: it runs the
``GraphvizJsonLayout`` oracle to place nodes and route edge splines, then
paints edges (as Bézier paths through the oracle's control points, falling
back to a straight connector when a spline is missing), node cards, CVSS
badges, and the title — emitting the standard interactivity contract. All
node-kind semantics live in the caller; none leak here.
"""

from typing import Any

from ... import utils
from .. import images, metrics, shapes
from ..canvas import SvgCanvas
from ..layout import GraphvizJsonLayout
from ..scene import Scene

# Gap between an embedded icon and the label block below it (px).
_IMAGE_TEXT_GAP = 4.0


def attach_icon(node, image_ref: Any, theme: dict[str, Any]) -> None:
    """Embed an ``image`` reference (bundled:/file path) at the top of a node card.

    Resolves to a base64 data URI (unresolvable references are skipped with a
    warning by the resolver, leaving the plain card) and grows the card so
    the icon sits above the label.
    """
    href = images.resolve_data_uri(str(image_ref), node.id) if image_ref else None
    if not href:
        return
    img = float(theme["images"]["size"])
    node.image_href = href
    node.height += img + _IMAGE_TEXT_GAP
    node.width = max(node.width, img + 2 * float(theme["card"]["padding_x"]))


def _border_point(node, toward_x: float, toward_y: float) -> tuple[float, float]:
    """Point on ``node``'s rectangle boundary in the direction of a target.

    Used only for the straight-line fallback when the layout oracle returned
    no spline for an edge; spline edges already start/end on node borders.
    """
    dx = toward_x - node.x
    dy = toward_y - node.y
    if dx == 0 and dy == 0:
        return node.x, node.y
    half_w = node.width / 2
    half_h = node.height / 2
    scale_x = half_w / abs(dx) if dx else float("inf")
    scale_y = half_h / abs(dy) if dy else float("inf")
    scale = min(scale_x, scale_y)
    return node.x + dx * scale, node.y + dy * scale


def _edge_anchor(points: list[tuple[float, float]]) -> tuple[float, float]:
    """A label anchor on the middle of an edge path.

    Fallback for edges the oracle returned no label position for. The points
    are a cubic B-spline (start + 3 per segment, head tip last), so the middle
    segment is evaluated at t=0.5 — a bare control point lies off the curve.
    """
    if not points:
        return 0.0, 0.0
    ctrl = points[:-1] if len(points) % 3 == 2 else points
    segments = (len(ctrl) - 1) // 3
    if segments < 1:
        return points[len(points) // 2]
    i = (segments // 2) * 3
    (x0, y0), (x1, y1), (x2, y2), (x3, y3) = ctrl[i : i + 4]
    return (x0 + 3 * x1 + 3 * x2 + x3) / 8, (y0 + 3 * y1 + 3 * y2 + y3) / 8


def _reserve_label_sizes(scene: Scene, theme: dict[str, Any]) -> None:
    """Size each edge label (as painted by ``shapes.edge_label``) for the oracle."""
    family = theme["font"]["family"]
    size = float(theme["edge"].get("label_size", 10))
    for edge in scene.edges:
        if edge.label:
            text_w = metrics.measure_text(edge.label, family, size, bold=True) + 0.3 * len(edge.label)
            edge.label_width = text_w + size * 0.8
            edge.label_height = size * 1.5


def render_graph_svg(viz, scene: Scene, theme: dict[str, Any], module_slug: str, *, rankdir: str = "LR") -> str:
    """Render a general-graph ``Scene`` to SVG text via the Graphviz oracle.

    Args:
        viz: The visualization instance (used only for ``styleid``).
        scene: A fully-styled scene (nodes/edges carry their own colors).
        theme: The resolved ``sv_*`` theme dict.
        module_slug: Module slug for CSS classes / data attributes.
        rankdir: Layout direction passed to the oracle ("LR" | "TB" | ...).
    """
    from ... import utils

    if not scene.nodes:
        raise utils.RenderError("Graph has no nodes to render")

    # Bound layout/paint cost before invoking the Graphviz oracle, matching the
    # Graphviz render path and the attack-tree SVG painter (the SVG engine skips
    # _render_impl, so this guard would otherwise be bypassed).
    utils.check_graph_complexity(len(scene.nodes), len(scene.edges))

    _reserve_label_sizes(scene, theme)
    ag = theme.get("attackgraph", {})
    GraphvizJsonLayout(
        rankdir=rankdir,
        nodesep=float(ag.get("nodesep", 0.4)),
        ranksep=float(ag.get("ranksep", 0.7)),
    ).solve(scene)

    font = theme["font"]
    card_cfg = theme["card"]
    edge_cfg = theme["edge"]
    effects = theme["effects"]
    page = theme["page"]
    node_cfg = theme["node"]
    size = float(font["size"])
    radius = float(card_cfg["radius"])
    border_width = float(card_cfg["border_width"])

    canvas = SvgCanvas(module_slug, viz.styleid)
    shadow_url = canvas.shadow(blur=float(effects["shadow_blur"])) if effects["shadow"] else ""

    css = [f".usv-{module_slug} text {{ font-family: {font['family']}; }}"]
    if effects["hover_glow"]:
        css.append(
            f".usv-{module_slug} .usv-node:hover rect, .usv-{module_slug} .usv-node:hover polygon "
            f"{{ stroke-width: {shapes.fmt(border_width + 1.2)}; }}"
        )
    canvas.set_css("\n".join(css))

    pad = float(page["padding"])
    # Bounds span nodes and any placed cluster rectangles (clusters extend
    # beyond their members by the reserved padding + label band).
    xs_lo = [n.x - n.width / 2 for n in scene.nodes]
    ys_lo = [n.y - n.height / 2 for n in scene.nodes]
    xs_hi = [n.x + n.width / 2 for n in scene.nodes]
    ys_hi = [n.y + n.height / 2 for n in scene.nodes]
    for grp in scene.groups:
        if grp.width > 0 and grp.height > 0:
            xs_lo.append(grp.x)
            ys_lo.append(grp.y)
            xs_hi.append(grp.x + grp.width)
            ys_hi.append(grp.y + grp.height)
    for edge in scene.edges:
        if edge.label and edge.label_pos:
            lx, ly = edge.label_pos
            xs_lo.append(lx - edge.label_width / 2)
            xs_hi.append(lx + edge.label_width / 2)
            ys_lo.append(ly - edge.label_height / 2)
            ys_hi.append(ly + edge.label_height / 2)
    min_x = min(xs_lo) - pad
    min_y = min(ys_lo) - pad
    max_x = max(xs_hi) + pad
    max_y = max(ys_hi) + pad
    canvas.finalize(min_x, min_y, max_x - min_x, max_y - min_y)
    canvas.add(
        "groups",
        shapes.card(
            min_x, min_y, max_x - min_x, max_y - min_y, 0, fill=page["background"], stroke="none", stroke_width=0
        ),
    )

    _paint_clusters(scene, canvas, theme)

    title_cfg = theme["title"]
    title = str(scene.meta.get("name", "")).strip()
    if title_cfg["show"] and title:
        canvas.add(
            "labels",
            shapes.title_text(min_x + pad * 0.5, min_y + pad * 0.55, title, float(title_cfg["size"]), page["text"]),
        )

    _paint_edges(scene, canvas, theme, edge_cfg)
    _paint_nodes(scene, canvas, theme, node_cfg, size, radius, border_width, shadow_url)

    return canvas.to_string()


def _paint_clusters(scene: Scene, canvas: SvgCanvas, theme: dict[str, Any]) -> None:
    """Draw each placed group as a labelled background rectangle behind nodes.

    Rectangles land in the bottom ``groups`` layer (above the page background,
    below edges and nodes), so members always paint on top of their cluster.
    """
    if not scene.groups:
        return
    cfg = theme.get("cluster", {})
    default_fill = cfg.get("fill", "#eef2f7")
    default_border = cfg.get("border", "#cbd5e1")
    default_text = cfg.get("text", "#475569")
    label_size = float(cfg.get("label_size", 12))
    radius = float(cfg.get("radius", 10))

    # Outer clusters first so nested ones paint on top of their parent
    depth = {}
    by_id = {g.id: g for g in scene.groups}
    for grp in scene.groups:
        d, cur = 0, grp
        while cur.parent in by_id and d < len(by_id):
            cur, d = by_id[cur.parent], d + 1
        depth[grp.id] = d
    for grp in sorted(scene.groups, key=lambda g: depth[g.id]):
        if grp.width <= 0 or grp.height <= 0:
            continue
        fill = grp.fill or default_fill
        border = grp.border or default_border
        text_color = grp.text_color or default_text

        group = shapes.group(["usv-cluster"], {"cluster-id": grp.id, "label": grp.label or grp.id, **grp.data})
        rect = shapes.card(grp.x, grp.y, grp.width, grp.height, radius, fill, border, 1.6 if grp.dashed else 1.2)
        if grp.dashed:
            rect.set("stroke-dasharray", "7 4")
        group.append(rect)
        if grp.label:
            # Label sits in the band Graphviz reserved at the cluster's top.
            group.append(
                shapes.anchored_text(
                    grp.x + radius, grp.y + label_size + 2, grp.label, label_size, text_color, bold=True
                )
            )
        canvas.add("groups", group)


def _paint_edges(scene: Scene, canvas: SvgCanvas, theme: dict[str, Any], edge_cfg: dict) -> None:
    """Draw each edge as a spline path (fallback: straight border-to-border)."""
    by_id = {n.id: n for n in scene.nodes}
    base_color = edge_cfg["color"]
    base_width = float(edge_cfg["width"])
    label_size = float(edge_cfg.get("label_size", 10))
    label_color = edge_cfg.get("label_color", theme["page"]["text"])
    page_bg = theme["page"]["background"]

    for edge in scene.edges:
        src = by_id.get(edge.src)
        dst = by_id.get(edge.dst)
        if src is None or dst is None:
            continue
        color = edge.color or base_color
        width = edge.width if edge.width is not None else base_width

        d = shapes.spline_path_d(edge.points)
        if not d:
            x1, y1 = _border_point(src, dst.x, dst.y)
            x2, y2 = _border_point(dst, src.x, src.y)
            d = f"M {shapes.fmt(x1)} {shapes.fmt(y1)} L {shapes.fmt(x2)} {shapes.fmt(y2)}"
            anchor = ((x1 + x2) / 2, (y1 + y2) / 2)
        else:
            anchor = edge.label_pos or _edge_anchor(edge.points)

        classes = ["usv-edge", f"usv-edge--{edge.kind}"]
        if edge.inferred:
            classes.append("usv-edge--inferred")
        group = shapes.group(classes, {"from": edge.src, "to": edge.dst, **edge.data})
        group.append(shapes.edge_path(d, color, width, dashed=edge.dashed, marker_url=canvas.arrow_marker(color)))
        canvas.add("edges", group)

        if edge.label:
            # Labels sit in the top layer: the oracle reserved room for them,
            # so painting above nodes/cluster titles never hides them.
            canvas.add("labels", shapes.edge_label(anchor[0], anchor[1], edge.label, label_size, label_color, page_bg))


def _paint_nodes(
    scene: Scene,
    canvas: SvgCanvas,
    theme: dict[str, Any],
    node_cfg: dict,
    size: float,
    radius: float,
    border_width: float,
    shadow_url: str,
) -> None:
    """Draw node bodies (shape per ``node.shape``), labels, CVSS and source-count badges."""
    font = theme["font"]
    page = theme["page"]
    default_fill = node_cfg["fill"]
    default_border = node_cfg["border"]
    default_text = node_cfg.get("text", "#ffffff")

    for node in scene.nodes:
        fill = node.fill or default_fill
        border = node.border or default_border
        text_color = node.text_color or default_text
        x, y = node.x - node.width / 2, node.y - node.height / 2

        classes = ["usv-node"]
        kind = node.data.get("kind")
        if kind:
            classes.append(f"usv-node--{kind}")
        if node.severity:
            classes.append(f"usv-sev--{node.severity}")
        body = _node_body(node, x, y, radius, fill, border, border_width, shadow_url)
        if node.inferred:
            classes.append("usv-node--inferred")
            shapes.dash_outline(body, str(theme.get("inferred", {}).get("dash", "5 3")))
        group = shapes.group(classes, node.data)
        group.append(body)

        lines = node.lines or [node.label]
        text_h = len(lines) * size * metrics.LINE_HEIGHT
        if node.shape == "cylinder":
            # Keep the label below the lid's front rim
            text_top = node.y - text_h / 2 + min(8.0, node.height * 0.16) / 2
        elif node.image_href:
            # Icon centered at the top, label block below it
            img = float(theme["images"]["size"])
            img_top = node.y - (img + _IMAGE_TEXT_GAP + text_h) / 2
            group.append(shapes.image(node.x - img / 2, img_top, img, img, node.image_href))
            text_top = img_top + img + _IMAGE_TEXT_GAP
        else:
            text_top = node.y - text_h / 2
        group.extend(shapes.text_lines(node.x, text_top, lines, size, text_color))
        canvas.add("nodes", group)

        if node.sources >= utils.MIN_SOURCES_FOR_BADGE and theme["badges"].get("sources", True):
            badge_size = size * 0.78
            badge_label = f"✓{node.sources}"
            badge_w = metrics.measure_text(badge_label, font["family"], badge_size, bold=True)
            canvas.add(
                "badges",
                shapes.badge(
                    node.x - node.width / 2 + radius * 0.4,
                    y,
                    badge_label,
                    badge_w,
                    fill=theme["badges"].get("sources_fill", theme["badges"]["fill"]),
                    text_color=theme["badges"]["text"],
                    size=badge_size,
                    ring=page["background"],
                    variant="sources",
                ),
            )

        if node.cvss is not None and node.cvss > 0 and theme["badges"].get("cvss", True):
            badge_size = size * 0.78
            badge_label = f"{node.cvss:.1f}"
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


def _node_body(node, x: float, y: float, radius: float, fill: str, border: str, border_width: float, shadow_url: str):
    """Build the node's background element for its ``shape``."""
    shape = node.shape or "card"
    if shape == "pill":
        return shapes.card(x, y, node.width, node.height, node.height / 2, fill, border, border_width, shadow_url)
    if shape == "chamfer":
        cut = min(12.0, node.height * 0.32)
        return shapes.chamfer_card(x, y, node.width, node.height, cut, fill, border, border_width, shadow_url)
    if shape == "cylinder":
        return shapes.cylinder(x, y, node.width, node.height, fill, border, border_width, shadow_url)
    if shape == "diamond":
        return shapes.diamond(node.x, node.y, node.width, node.height, fill, border, border_width, shadow_url)
    return shapes.card(x, y, node.width, node.height, radius, fill, border, border_width, shadow_url)
