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

from typing import Any, Optional

from ... import utils
from .. import images, metrics, shapes, themes
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


def render_graph_svg(
    viz,
    scene: Scene,
    theme: dict[str, Any],
    module_slug: str,
    *,
    rankdir: str = "LR",
    nodesep: Optional[float] = None,
    ranksep: Optional[float] = None,
) -> str:
    """Render a general-graph ``Scene`` to SVG text via the Graphviz oracle.

    Args:
        viz: The visualization instance (used only for ``styleid``).
        scene: A fully-styled scene (nodes/edges carry their own colors).
        theme: The resolved ``sv_*`` theme dict.
        module_slug: Module slug for CSS classes / data attributes.
        rankdir: Layout direction passed to the oracle ("LR" | "TB" | ...).
        nodesep, ranksep: Oracle spacing in inches (default: the theme's
            ``attackgraph`` spacing, which the first painters shared).
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
        nodesep=float(nodesep if nodesep is not None else ag.get("nodesep", 0.4)),
        ranksep=float(ranksep if ranksep is not None else ag.get("ranksep", 0.7)),
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
    drawn = [n for n in scene.nodes if not n.layout_only]
    xs_lo = [n.x - n.width / 2 for n in drawn]
    ys_lo = [n.y - n.height / 2 for n in drawn]
    xs_hi = [n.x + n.width / 2 for n in drawn]
    ys_hi = [n.y + n.height / 2 for n in drawn]
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
    legend = (scene.meta.get("legend") or []) if theme.get("legend", {}).get("show", True) else []
    legend_y = max_y + size * 0.6
    legend_rows = wrap_legend(theme, legend, max(max_x - min_x - 2 * pad, 480.0)) if legend else []
    if legend_rows:
        max_y = legend_y + size * 1.4 * len(legend_rows) + pad * 0.5
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
    for row, items in enumerate(legend_rows):
        paint_legend(canvas, theme, items, min_x + pad, legend_y + size + row * size * 1.4)

    return canvas.to_string()


_DIFF_CHIPS = {"added": "+", "removed": "\u2212", "modified": "~"}


def _legend_item_width(theme: dict[str, Any], item: tuple) -> float:
    """Width of one legend item: swatch, gap, label and the gap to the next item."""
    size = float(theme["font"]["size"]) * 0.85
    spec = item[2] if len(item) > 2 else None
    label_w = metrics.measure_text(item[0], theme["font"]["family"], size)
    if spec is not None and spec.get("swatch") == "text":
        return label_w + 24.0
    swatch_w = size * 2.6 if spec is not None and spec.get("swatch") != "box" else size * 1.6
    return swatch_w + size * 0.5 + label_w + 24.0


def wrap_legend(theme: dict[str, Any], items: list, max_width: float) -> list[list]:
    """Legend items split into rows no wider than ``max_width`` (at least one item per row)."""
    rows: list[list] = [[]]
    used = 0.0
    for item in items:
        w = _legend_item_width(theme, item)
        if rows[-1] and used + w > max_width:
            rows.append([])
            used = 0.0
        rows[-1].append(item)
        used += w
    return [row for row in rows if row]


def paint_legend(canvas: SvgCanvas, theme: dict[str, Any], items: list, x: float, y: float) -> None:
    """One legend row: a swatch and a label per item.

    An item is (label, color) for an outlined box, (label, color, line) for a
    short line in an edge style, where ``line`` is {"width", "dashed", "dash"},
    (label, color, {"swatch": "box", "fill", "dashed"}) for a filled (or
    dashed) box, or (label, color, {"swatch": "text"}) for a note without a
    swatch.
    """
    font = theme["font"]
    size = float(font["size"]) * 0.85
    text_color = theme["page"]["text"]
    g = shapes.group(["usv-legend"])
    for item in items:
        label, color = item[0], item[1]
        spec = item[2] if len(item) > 2 else None
        kind = spec.get("swatch") if spec is not None else None
        if kind == "text":
            swatch_w = -size * 0.5
        elif kind == "box":
            box = shapes.card(x, y - size * 0.85, size * 1.6, size, 3.0, spec.get("fill", "none"), color, 1.2)
            if spec.get("dashed"):
                box.set("stroke-dasharray", "4 2")
            g.append(box)
            swatch_w = size * 1.6
        elif spec is not None:
            mid = y - size * 0.35
            d = f"M {shapes.fmt(x)} {shapes.fmt(mid)} L {shapes.fmt(x + size * 2.6)} {shapes.fmt(mid)}"
            width = float(spec.get("width", 2.0))
            g.append(shapes.edge_path(d, color, width, dashed=bool(spec.get("dashed")), dash=spec.get("dash")))
            swatch_w = size * 2.6
        else:
            g.append(shapes.card(x, y - size * 0.85, size * 1.6, size, 3.0, "none", color, 2.0))
            swatch_w = size * 1.6
        g.append(shapes.anchored_text(x + swatch_w + size * 0.5, y, label, size, text_color, anchor="start"))
        x += _legend_item_width(theme, item)
    canvas.add("labels", g)


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
    diff_cfg = theme.get("diff", {})
    font_family = theme["font"]["family"]
    page_bg = theme["page"]["background"]
    obstacles = _edge_obstacles(scene)

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
        stroke_width = 1.6 if grp.dashed else 1.2
        label = grp.label
        classes = ["usv-cluster"]
        data = {"cluster-id": grp.id, "label": grp.label or grp.id, **grp.data}
        if grp.diff:
            # Drift: the border takes the change color, the label its sign
            classes.append(f"usv-diff--{grp.diff}")
            data["diff"] = grp.diff
            chip = _DIFF_CHIPS.get(grp.diff)
            if chip:
                border = diff_cfg.get(grp.diff, border)
                stroke_width = float(diff_cfg.get("border_width", 3.0))
                label = f"{chip} {label}" if label else chip

        group = shapes.group(classes, data)
        if grp.diff == "removed":
            group.set("opacity", shapes.fmt(float(diff_cfg.get("removed_opacity", 0.35))))
        rect = shapes.card(grp.x, grp.y, grp.width, grp.height, radius, fill, border, stroke_width)
        if grp.dashed or grp.diff == "removed":
            rect.set("stroke-dasharray", "7 4")
        group.append(rect)
        canvas.add("groups", group)
        if label:
            # The title sits in the band Graphviz reserved at the cluster's
            # top, on the side edges cross least. Edges route through that
            # band, so it paints above them with a halo in the cluster fill.
            label_w = metrics.measure_text(label, font_family, label_size, bold=True)
            x = _cluster_label_x(grp, label_w, label_size, radius, obstacles)
            baseline = grp.y + label_size + 2
            title = shapes.group(["usv-label", "usv-label--cluster"], {"cluster-id": grp.id})
            if grp.diff == "removed":
                title.set("opacity", shapes.fmt(float(diff_cfg.get("removed_opacity", 0.35))))
            halo_color = fill if themes.parse_fill(fill)[0] != "gradient" and fill != "none" else page_bg
            if halo_color:
                halo = shapes.anchored_text(x, baseline, label, label_size, halo_color, bold=True)
                halo.set("stroke", halo_color)
                halo.set("stroke-width", shapes.fmt(label_size * 0.4))
                halo.set("stroke-linejoin", "round")
                title.append(halo)
            title.append(shapes.anchored_text(x, baseline, label, label_size, text_color, bold=True))
            canvas.add("labels", title)


def _edge_obstacles(scene: Scene) -> tuple[list[tuple[float, float]], list[tuple[float, float, float, float]]]:
    """Points along every drawn edge, and every edge label's box."""
    points: list[tuple[float, float]] = []
    boxes: list[tuple[float, float, float, float]] = []
    for edge in scene.edges:
        if edge.layout_only:
            continue
        pts = edge.points or []
        i = 1
        path = pts[:1]
        while i + 2 < len(pts):  # cubic triples, as spline_path_d draws them
            p0, c1, c2, p1 = path[-1], pts[i], pts[i + 1], pts[i + 2]
            for k in range(1, 11):
                t = k / 10
                u = 1 - t
                path.append(
                    (
                        u**3 * p0[0] + 3 * u * u * t * c1[0] + 3 * u * t * t * c2[0] + t**3 * p1[0],
                        u**3 * p0[1] + 3 * u * u * t * c1[1] + 3 * u * t * t * c2[1] + t**3 * p1[1],
                    )
                )
            i += 3
        path.extend(pts[i:])
        for a, b in zip(path, path[1:]):
            steps = max(1, int(max(abs(b[0] - a[0]), abs(b[1] - a[1])) / 3))
            points.extend((a[0] + (b[0] - a[0]) * k / steps, a[1] + (b[1] - a[1]) * k / steps) for k in range(steps))
        points.extend(path[-1:])
        if edge.label and edge.label_pos:
            lx, ly = edge.label_pos
            w, h = edge.label_width / 2, edge.label_height / 2
            boxes.append((lx - w, ly - h, lx + w, ly + h))
    return points, boxes


def _cluster_label_x(grp, label_w: float, label_size: float, radius: float, obstacles) -> float:
    """Left x of a cluster title: left, center or right of the top band, whichever edges cross least."""
    left = grp.x + radius
    if grp.width < label_w + 2 * radius + 12:
        return left
    points, boxes = obstacles
    top, bottom = grp.y + 1, grp.y + label_size + 6

    def crossings(x0: float) -> int:
        x1 = x0 + label_w
        hit = sum(1 for px, py in points if x0 - 3 <= px <= x1 + 3 and top <= py <= bottom)
        return hit + 50 * sum(1 for b in boxes if b[0] < x1 and x0 < b[2] and b[1] < bottom and top < b[3])

    candidates = [left, grp.x + (grp.width - label_w) / 2, grp.x + grp.width - radius - label_w]
    scores = [crossings(x) for x in candidates]
    return candidates[scores.index(min(scores))]  # the first (left) on a tie


def _paint_edges(scene: Scene, canvas: SvgCanvas, theme: dict[str, Any], edge_cfg: dict) -> None:
    """Draw each edge as a spline path (fallback: straight border-to-border)."""
    by_id = {n.id: n for n in scene.nodes}
    base_color = edge_cfg["color"]
    base_width = float(edge_cfg["width"])
    label_size = float(edge_cfg.get("label_size", 10))
    label_color = edge_cfg.get("label_color", theme["page"]["text"])
    page_bg = theme["page"]["background"]
    diff_cfg = theme.get("diff", {})

    for edge in scene.edges:
        src = by_id.get(edge.src)
        dst = by_id.get(edge.dst)
        if src is None or dst is None or edge.layout_only:
            continue
        color = edge.color or base_color
        width = edge.width if edge.width is not None else base_width
        dashed = edge.dashed
        if edge.diff == "added":
            color = diff_cfg.get("added", color)
            width += 1.0
        elif edge.diff == "removed":
            color = diff_cfg.get("removed", color)
            dashed = True
        elif edge.diff == "modified":
            color = diff_cfg.get("modified", color)

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
        data = {"from": edge.src, "to": edge.dst, **edge.data}
        if edge.diff:
            classes.append(f"usv-diff--{edge.diff}")
            data["diff"] = edge.diff
        group = shapes.group(classes, data)
        if edge.diff == "removed":
            group.set("opacity", shapes.fmt(float(diff_cfg.get("removed_opacity", 0.35))))
        group.append(
            shapes.edge_path(d, color, width, dashed=dashed, marker_url=canvas.arrow_marker(color), dash=edge.dash)
        )
        canvas.add("edges", group)

        if edge.label:
            # Labels sit in the top layer: the oracle reserved room for them,
            # so painting above nodes/cluster titles never hides them.
            canvas.add(
                "labels",
                shapes.edge_label(
                    anchor[0], anchor[1], edge.label, label_size, edge.label_color or label_color, page_bg
                ),
            )


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
        if node.layout_only:
            continue
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
        diff_cfg = theme.get("diff", {})
        if node.diff in ("added", "modified"):
            border = diff_cfg.get(node.diff, border)
        body = _node_body(
            node,
            x,
            y,
            radius,
            fill,
            border,
            float(diff_cfg.get("border_width", 3.0)) if node.diff in ("added", "modified") else border_width,
            shadow_url,
        )
        if node.inferred:
            classes.append("usv-node--inferred")
            shapes.dash_outline(body, str(theme.get("inferred", {}).get("dash", "5 3")))
        data = node.data
        if node.diff:
            classes.append(f"usv-diff--{node.diff}")
            data = {**node.data, "diff": node.diff}
            if node.diff == "removed":
                shapes.dash_outline(body, "6 3")
        group = shapes.group(classes, data)
        if node.diff == "removed":
            # Fade the body only; the label stays opaque in a color that
            # reads on the faded fill (faded text was close to invisible).
            opacity = float(diff_cfg.get("removed_opacity", 0.35))
            body.set("opacity", shapes.fmt(opacity))
            shown = utils.blend_color(fill, page["background"], opacity)
            text_color = utils.readable_text_color(shown) or text_color
        group.append(body)

        lines = node.lines or [node.label]
        text_h = len(lines) * size * metrics.LINE_HEIGHT
        if node.image_href:
            # Icon centered at the top, label block below it
            img = float(theme["images"]["size"])
            img_top = node.y - (img + _IMAGE_TEXT_GAP + text_h) / 2
            icon = shapes.image(node.x - img / 2, img_top, img, img, node.image_href)
            if node.diff == "removed":
                icon.set("opacity", shapes.fmt(float(diff_cfg.get("removed_opacity", 0.35))))
            group.append(icon)
            text_top = img_top + img + _IMAGE_TEXT_GAP
        elif node.shape == "cylinder":
            # Keep the label below the lid's front rim
            text_top = node.y - text_h / 2 + min(8.0, node.height * 0.16) / 2
        else:
            text_top = node.y - text_h / 2
        group.extend(shapes.text_lines(node.x, text_top, lines, size, text_color))
        canvas.add("nodes", group)

        chip = _DIFF_CHIPS.get(node.diff or "")
        if chip:
            # Change chip, bottom-left (CVSS is top-right, sources top-left)
            chip_size = size * 0.85
            canvas.add(
                "badges",
                shapes.badge(
                    node.x - node.width / 2 + radius * 0.4,
                    y + node.height,
                    chip,
                    metrics.measure_text(chip, font["family"], chip_size, bold=True),
                    fill=theme.get("diff", {}).get(node.diff, "#475569"),
                    text_color="#ffffff",
                    size=chip_size,
                    ring=page["background"],
                    variant="diff",
                ),
            )

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
