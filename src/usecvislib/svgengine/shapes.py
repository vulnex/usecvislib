#
# VULNEX -Universal Security Visualization Library-
#
# File: shapes.py
# Author: Simon Roses Femerling
# Created: 2026-08-08
# Last Modified: 2026-08-08
# Version: 0.4.1
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Shape builders for the SVG engine.

Pure functions producing ElementTree elements from geometry and style
values. All text content goes through ElementTree serialization (never
string-interpolated markup), so escaping is structural. Shapes never
carry behavior — no event attributes, no links.
"""

import re
import xml.etree.ElementTree as ET
from typing import Optional

from .canvas import fmt
from .metrics import LINE_HEIGHT

# Arrows, math operators, technical symbols, geometric shapes, misc symbols,
# dingbats: glyphs many text fonts lack (Carlito has no U+26A0). cairosvg does
# no per-glyph font fallback and misplaces a <tspan> in centered text, so a
# line holding one is set in a symbol-capable font as a whole.
_SYMBOL = re.compile(r"[\u2190-\u23ff\u25a0-\u27bf\u2b00-\u2bff]")
SYMBOL_FONT = "DejaVu Sans, Segoe UI Symbol, Apple Symbols, sans-serif"


def set_text(element: ET.Element, text: str) -> ET.Element:
    """Set ``element``'s text; a line with a symbol gets :data:`SYMBOL_FONT`."""
    element.text = text
    if _SYMBOL.search(text):
        # Inline style: it outranks the painters' ``.usv-* text`` font rule
        element.set("style", f"font-family: {SYMBOL_FONT}")
    return element


def group(classes: list[str], data: Optional[dict[str, str]] = None) -> ET.Element:
    """Build a <g> carrying the interactivity contract (classes + data-*)."""
    g = ET.Element("g", {"class": " ".join(classes)})
    for key in sorted(data or {}):
        g.set(f"data-{key}", str((data or {})[key]))
    return g


def card(
    x: float,
    y: float,
    width: float,
    height: float,
    radius: float,
    fill: str,
    stroke: str,
    stroke_width: float,
    filter_url: str = "",
) -> ET.Element:
    """Rounded-rectangle node body ("card" shape; radius=height/2 gives "pill")."""
    attrs = {
        "x": fmt(x),
        "y": fmt(y),
        "width": fmt(width),
        "height": fmt(height),
        "rx": fmt(radius),
        "fill": fill,
        "stroke": stroke,
        "stroke-width": fmt(stroke_width),
    }
    if filter_url:
        attrs["filter"] = filter_url
    return ET.Element("rect", attrs)


def dash_outline(element: ET.Element, pattern: str = "5 3") -> ET.Element:
    """Give a shape (or each shape in a group) a dashed outline; returns the element."""
    targets = list(element) if element.tag == "g" else [element]
    for target in targets:
        if target.get("stroke") not in (None, "none"):
            target.set("stroke-dasharray", pattern)
    return element


def diamond(
    cx: float,
    cy: float,
    width: float,
    height: float,
    fill: str,
    stroke: str,
    stroke_width: float,
    filter_url: str = "",
) -> ET.Element:
    """Diamond node body."""
    half_w, half_h = width / 2, height / 2
    points = (
        f"{fmt(cx)},{fmt(cy - half_h)} {fmt(cx + half_w)},{fmt(cy)} "
        f"{fmt(cx)},{fmt(cy + half_h)} {fmt(cx - half_w)},{fmt(cy)}"
    )
    attrs = {
        "points": points,
        "fill": fill,
        "stroke": stroke,
        "stroke-width": fmt(stroke_width),
        "stroke-linejoin": "round",
    }
    if filter_url:
        attrs["filter"] = filter_url
    return ET.Element("polygon", attrs)


def chamfer_card(
    x: float,
    y: float,
    width: float,
    height: float,
    cut: float,
    fill: str,
    stroke: str,
    stroke_width: float,
    filter_url: str = "",
) -> ET.Element:
    """Cut-corner (chamfered) node body - the octagon family's card variant.

    Keeps goal/outcome nodes (Graphviz octagon/doubleoctagon/hexagon)
    visually distinct from regular rounded cards without leaving the
    card aesthetic.
    """
    points = (
        f"{fmt(x + cut)},{fmt(y)} {fmt(x + width - cut)},{fmt(y)} "
        f"{fmt(x + width)},{fmt(y + cut)} {fmt(x + width)},{fmt(y + height - cut)} "
        f"{fmt(x + width - cut)},{fmt(y + height)} {fmt(x + cut)},{fmt(y + height)} "
        f"{fmt(x)},{fmt(y + height - cut)} {fmt(x)},{fmt(y + cut)}"
    )
    attrs = {
        "points": points,
        "fill": fill,
        "stroke": stroke,
        "stroke-width": fmt(stroke_width),
        "stroke-linejoin": "round",
    }
    if filter_url:
        attrs["filter"] = filter_url
    return ET.Element("polygon", attrs)


def cylinder(
    x: float,
    y: float,
    width: float,
    height: float,
    fill: str,
    stroke: str,
    stroke_width: float,
    filter_url: str = "",
) -> ET.Element:
    """Database cylinder: elliptical top/bottom caps plus the front rim of the lid."""
    rx = width / 2
    ry = min(8.0, height * 0.16)
    body = (
        f"M {fmt(x)} {fmt(y + ry)} A {fmt(rx)} {fmt(ry)} 0 0 1 {fmt(x + width)} {fmt(y + ry)} "
        f"L {fmt(x + width)} {fmt(y + height - ry)} A {fmt(rx)} {fmt(ry)} 0 0 1 {fmt(x)} {fmt(y + height - ry)} Z"
    )
    g = ET.Element("g", {"class": "usv-cylinder"})
    attrs = {"d": body, "fill": fill, "stroke": stroke, "stroke-width": fmt(stroke_width)}
    if filter_url:
        attrs["filter"] = filter_url
    g.append(ET.Element("path", attrs))
    rim = f"M {fmt(x)} {fmt(y + ry)} A {fmt(rx)} {fmt(ry)} 0 0 0 {fmt(x + width)} {fmt(y + ry)}"
    g.append(ET.Element("path", {"d": rim, "fill": "none", "stroke": stroke, "stroke-width": fmt(stroke_width)}))
    return g


def dot(
    cx: float,
    cy: float,
    radius: float,
    fill: str,
    stroke: str = "none",
    stroke_width: float = 0.0,
    filter_url: str = "",
) -> ET.Element:
    """Filled circle marker (e.g. a timeline event point)."""
    attrs = {"cx": fmt(cx), "cy": fmt(cy), "r": fmt(radius), "fill": fill}
    if stroke and stroke != "none":
        attrs["stroke"] = stroke
        attrs["stroke-width"] = fmt(stroke_width)
    if filter_url:
        attrs["filter"] = filter_url
    return ET.Element("circle", attrs)


def band(
    x: float,
    y: float,
    width: float,
    height: float,
    fill: str,
    opacity: float = 1.0,
    radius: float = 0.0,
) -> ET.Element:
    """Flat rectangle for lane / phase / gantt background bands and bars."""
    attrs = {"x": fmt(x), "y": fmt(y), "width": fmt(width), "height": fmt(height), "fill": fill}
    if radius:
        attrs["rx"] = fmt(radius)
    if opacity != 1.0:
        attrs["fill-opacity"] = fmt(opacity)
    return ET.Element("rect", attrs)


def anchored_text(
    x: float,
    baseline_y: float,
    text: str,
    size: float,
    fill: str,
    anchor: str = "start",
    bold: bool = False,
) -> ET.Element:
    """Single line of text with an explicit anchor (start / middle / end)."""
    attrs = {"x": fmt(x), "y": fmt(baseline_y), "text-anchor": anchor, "font-size": fmt(size), "fill": fill}
    if bold:
        attrs["font-weight"] = "bold"
    element = ET.Element("text", attrs)
    set_text(element, text)
    return element


def text_lines(
    cx: float,
    top_y: float,
    lines: list[str],
    size: float,
    fill: str,
    bold: bool = False,
) -> list[ET.Element]:
    """Centered text block: one <text> per wrapped line.

    ``top_y`` is the top of the text block; the first baseline sits one
    font size below it.
    """
    elements = []
    for i, line in enumerate(lines):
        attrs = {
            "x": fmt(cx),
            "y": fmt(top_y + size + i * size * LINE_HEIGHT),
            "text-anchor": "middle",
            "font-size": fmt(size),
            "fill": fill,
        }
        if bold:
            attrs["font-weight"] = "bold"
        text = ET.Element("text", attrs)
        set_text(text, line)
        elements.append(text)
    return elements


def badge(
    center_x: float,
    center_y: float,
    label: str,
    label_width: float,
    fill: str,
    text_color: str,
    size: float,
    ring: str = "",
    variant: str = "cvss",
) -> ET.Element:
    """Small pill badge (e.g. a CVSS score) centered at (center_x, center_y).

    ``ring`` draws a cutout stroke in the page background color, so a badge
    docked on a card corner reads as a floating chip. ``variant`` names the
    badge kind in its CSS class (cvss score chip, AND/OR gate chip, ...).
    """
    pad = size * 0.55
    height = size * 1.6
    width = label_width + 2 * pad
    g = ET.Element("g", {"class": f"usv-badge usv-badge--{variant}", "data-value": label})
    rect_attrs = {
        "x": fmt(center_x - width / 2),
        "y": fmt(center_y - height / 2),
        "width": fmt(width),
        "height": fmt(height),
        "rx": fmt(height / 2),
        "fill": fill,
    }
    if ring:
        rect_attrs["stroke"] = ring
        rect_attrs["stroke-width"] = fmt(size * 0.16)
    g.append(ET.Element("rect", rect_attrs))
    text = ET.Element(
        "text",
        {
            "x": fmt(center_x),
            "y": fmt(center_y + size * 0.36),
            "text-anchor": "middle",
            "font-size": fmt(size),
            "font-weight": "bold",
            "fill": text_color,
        },
    )
    set_text(text, label)
    g.append(text)
    return g


def edge_label(x: float, y: float, text: str, size: float, fill: str, halo: str) -> ET.Element:
    """Small edge annotation centered on the line it labels.

    ``halo`` (the page background color) is painted as a stroked copy of
    the text UNDER the filled copy, so the label stays readable where it
    sits on an edge stroke. Two elements, not paint-order="stroke": the
    cairosvg rasterizer ignores paint-order and would stroke over the
    fill, leaving an invisible page-colored blob that breaks the line.
    """
    g = ET.Element("g", {"class": "usv-edge-label"})
    base = {
        "x": fmt(x),
        "y": fmt(y + size * 0.36),
        "text-anchor": "middle",
        "font-size": fmt(size),
        "font-weight": "600",
        "letter-spacing": "0.3",
    }
    if halo:
        halo_attrs = dict(base)
        halo_attrs.update(
            {
                "fill": halo,
                "stroke": halo,
                "stroke-width": fmt(size * 0.32),
                "stroke-linejoin": "round",
            }
        )
        halo_text = ET.Element("text", halo_attrs)
        set_text(halo_text, text)
        g.append(halo_text)
    element = ET.Element("text", dict(base, fill=fill))
    set_text(element, text)
    g.append(element)
    return g


def title_text(x: float, baseline_y: float, text: str, size: float, fill: str) -> ET.Element:
    """Muted diagram title, left-anchored."""
    element = ET.Element(
        "text",
        {
            "x": fmt(x),
            "y": fmt(baseline_y),
            "text-anchor": "start",
            "font-size": fmt(size),
            "font-weight": "600",
            "fill": fill,
            "opacity": "0.65",
            "letter-spacing": "0.4",
        },
    )
    set_text(element, text)
    return element


def ortho_path_d(
    x1: float,
    y1: float,
    x2: float,
    y2: float,
    corner: float = 10.0,
    horizontal: bool = False,
    mid: Optional[float] = None,
) -> str:
    """Orthogonal parent->child connector with rounded corners.

    Top-down by default: runs vertically from (x1, y1), turns at ``mid``
    (defaults to the midpoint) toward x2, and drops into (x2, y2). Passing
    the same ``mid`` for all edges of one parent aligns sibling connectors
    on a single bus line even when children have different heights. With
    ``horizontal=True`` (left-right orientation) the roles of the axes are
    mirrored. Collinear endpoints produce a straight line.
    """
    if horizontal:
        if abs(y1 - y2) < 0.5:
            return f"M {fmt(x1)} {fmt(y1)} L {fmt(x2)} {fmt(y2)}"
        mid_x = mid if mid is not None else (x1 + x2) / 2
        r = max(0.0, min(corner, abs(y2 - y1) / 2, abs(mid_x - x1), abs(x2 - mid_x)))
        direction = 1 if y2 > y1 else -1
        return (
            f"M {fmt(x1)} {fmt(y1)} "
            f"L {fmt(mid_x - r)} {fmt(y1)} "
            f"Q {fmt(mid_x)} {fmt(y1)} {fmt(mid_x)} {fmt(y1 + direction * r)} "
            f"L {fmt(mid_x)} {fmt(y2 - direction * r)} "
            f"Q {fmt(mid_x)} {fmt(y2)} {fmt(mid_x + r)} {fmt(y2)} "
            f"L {fmt(x2)} {fmt(y2)}"
        )
    if abs(x1 - x2) < 3.0:
        # Near-collinear: a 1-2px offset would otherwise draw a tiny S-jog.
        return f"M {fmt(x2)} {fmt(y1)} L {fmt(x2)} {fmt(y2)}"
    mid_y = mid if mid is not None else (y1 + y2) / 2
    r = max(0.0, min(corner, abs(x2 - x1) / 2, abs(mid_y - y1), abs(y2 - mid_y)))
    direction = 1 if x2 > x1 else -1
    return (
        f"M {fmt(x1)} {fmt(y1)} "
        f"L {fmt(x1)} {fmt(mid_y - r)} "
        f"Q {fmt(x1)} {fmt(mid_y)} {fmt(x1 + direction * r)} {fmt(mid_y)} "
        f"L {fmt(x2 - direction * r)} {fmt(mid_y)} "
        f"Q {fmt(x2)} {fmt(mid_y)} {fmt(x2)} {fmt(mid_y + r)} "
        f"L {fmt(x2)} {fmt(y2)}"
    )


def rounded_polyline_d(points: list[tuple[float, float]], corner: float = 10.0) -> str:
    """Axis-aligned polyline through ``points`` with rounded corners.

    Each interior vertex is replaced by a quadratic curve whose radius is
    capped at half of either adjacent segment.
    """
    if len(points) < 2:
        return ""
    parts = [f"M {fmt(points[0][0])} {fmt(points[0][1])}"]
    for (px, py), (cx, cy), (nx, ny) in zip(points, points[1:], points[2:], strict=False):
        len_in = abs(cx - px) + abs(cy - py)
        len_out = abs(nx - cx) + abs(ny - cy)
        r = max(0.0, min(corner, len_in / 2, len_out / 2))
        if r == 0:
            parts.append(f"L {fmt(cx)} {fmt(cy)}")
            continue

        def toward(ax, ay, bx, by, dist):
            length = abs(bx - ax) + abs(by - ay)
            return ax + (bx - ax) * dist / length, ay + (by - ay) * dist / length

        ix, iy = toward(cx, cy, px, py, r)
        ox, oy = toward(cx, cy, nx, ny, r)
        parts.append(f"L {fmt(ix)} {fmt(iy)} Q {fmt(cx)} {fmt(cy)} {fmt(ox)} {fmt(oy)}")
    parts.append(f"L {fmt(points[-1][0])} {fmt(points[-1][1])}")
    return " ".join(parts)


def curve_path_d(x1: float, y1: float, x2: float, y2: float, horizontal: bool = False) -> str:
    """Cubic-bezier parent->child connector (top-down; mirrored when horizontal)."""
    if horizontal:
        dx = (x2 - x1) / 2
        return f"M {fmt(x1)} {fmt(y1)} C {fmt(x1 + dx)} {fmt(y1)} {fmt(x2 - dx)} {fmt(y2)} {fmt(x2)} {fmt(y2)}"
    dy = (y2 - y1) / 2
    return f"M {fmt(x1)} {fmt(y1)} C {fmt(x1)} {fmt(y1 + dy)} {fmt(x2)} {fmt(y2 - dy)} {fmt(x2)} {fmt(y2)}"


def spline_path_d(points: list[tuple[float, float]]) -> str:
    """Path through a Graphviz B-spline: the point list from a layout oracle.

    ``points`` is the ordered control-point list a general-graph layout
    (``GraphvizJsonLayout``) reads back from Graphviz: the first point is the
    curve start, then cubic segments in groups of three, and — for a directed
    edge — a final arrow-tip point that does not complete a triple. Cubic
    triples become ``C`` segments; any trailing point(s) become ``L`` segments
    so the stroke reaches the arrowhead. Fewer than two points yields an empty
    path (the caller falls back to a straight connector).
    """
    if len(points) < 2:
        return ""
    pts = [(fmt(x), fmt(y)) for x, y in points]
    segments = [f"M {pts[0][0]} {pts[0][1]}"]
    i, n = 1, len(pts)
    while i + 2 < n:  # a full cubic needs three further points
        c1, c2, end = pts[i], pts[i + 1], pts[i + 2]
        segments.append(f"C {c1[0]} {c1[1]} {c2[0]} {c2[1]} {end[0]} {end[1]}")
        i += 3
    while i < n:  # trailing point(s) (e.g. the arrow tip) as line segments
        segments.append(f"L {pts[i][0]} {pts[i][1]}")
        i += 1
    return " ".join(segments)


def image(x: float, y: float, width: float, height: float, href: str) -> ET.Element:
    """Embedded image (data URI href), aspect-fit inside its box."""
    return ET.Element(
        "image",
        {
            "x": fmt(x),
            "y": fmt(y),
            "width": fmt(width),
            "height": fmt(height),
            "href": href,
            "preserveAspectRatio": "xMidYMid meet",
        },
    )


def edge_path(
    d: str,
    color: str,
    width: float,
    dashed: bool = False,
    marker_url: str = "",
    dash: Optional[str] = None,
) -> ET.Element:
    """Edge stroke along a path, with optional dash pattern and arrowhead.

    ``dash`` is an explicit stroke-dasharray (e.g. "1.5 4" for dotted) and
    overrides ``dashed``.
    """
    attrs = {
        "d": d,
        "fill": "none",
        "stroke": color,
        "stroke-width": fmt(width),
        "stroke-linecap": "round",
    }
    if dash:
        attrs["stroke-dasharray"] = dash
    elif dashed:
        attrs["stroke-dasharray"] = f"{fmt(width * 3)} {fmt(width * 2.5)}"
    if marker_url:
        attrs["marker-end"] = marker_url
    return ET.Element("path", attrs)
