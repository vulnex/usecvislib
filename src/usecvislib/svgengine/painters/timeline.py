#
# VULNEX -Universal Security Visualization Library-
#
# File: timeline.py
# Author: Simon Roses Femerling
# Created: 2026-08-28
# Last Modified: 2026-08-28
# Version: 0.5.0
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Incident Timeline painter for the SVG engine (Phase 2, mode 10).

Renders the same event/phase/lane data as the Matplotlib path in
``timeline.py`` and mirrors its four render modes natively as SVG:

- **swimlane** (default): one horizontal lane per asset/actor, events as
  severity-colored markers (with duration bars) on a shared time axis.
- **gantt**: one row per event, a duration bar per event.
- **vertical**: top-down time axis, markers on a center line with
  alternating left/right annotations.
- **compact**: a single-row strip of markers.

Events are placed by scaling their timestamp onto a pixel time axis (pure
``timedelta`` math — no Graphviz, no Matplotlib), response ``[[phases]]``
shade the background, and labels are greedily staggered to avoid overlap.
Severity marker colors come from the module (fixed), so SVG output stays
color-consistent with the Graphviz-engine timelines.
"""

import logging
from datetime import timedelta
from typing import Any

from ... import utils
from ...timeline import SEVERITY_COLORS
from .. import metrics, shapes, themes
from ..canvas import SvgCanvas

logger = logging.getLogger(__name__)

MODULE_SLUG = "timeline"

_CANON_SEV = {"critical", "high", "medium", "low", "info"}
# Label stagger tiers: (sign, base offset in px). sign<0 = above marker. Same-side
# tiers are spaced far enough apart to clear a two-line label.
_TIERS = [(-1, 18.0), (1, 20.0), (-1, 46.0), (1, 48.0), (-1, 74.0), (1, 76.0)]
_STAGGER_GAP = 90.0  # min horizontal px before a tier can be reused


class _Bounds:
    """Running envelope of everything drawn, for the final viewBox."""

    def __init__(self) -> None:
        self.min_x = self.min_y = 1e18
        self.max_x = self.max_y = -1e18

    def point(self, x: float, y: float) -> None:
        self.min_x = min(self.min_x, x)
        self.min_y = min(self.min_y, y)
        self.max_x = max(self.max_x, x)
        self.max_y = max(self.max_y, y)

    def rect(self, x: float, y: float, w: float, h: float) -> None:
        self.point(x, y)
        self.point(x + w, y + h)


class _Ops:
    """Deferred draw ops per canvas layer (so the page background is added first)."""

    def __init__(self) -> None:
        self.groups: list = []
        self.edges: list = []
        self.nodes: list = []
        self.badges: list = []
        self.labels: list = []


def _severity_class(severity: str) -> str:
    return f"usv-sev--{severity}" if severity in _CANON_SEV else "usv-sev--info"


def _pick_tier(x: float, last_x: list[float]) -> tuple[int, float]:
    """Greedily assign a stagger tier whose last label is far enough left."""
    for i, (sign, base) in enumerate(_TIERS):
        if x - last_x[i] >= _STAGGER_GAP:
            last_x[i] = x
            return sign, base
    last_x[0] = x
    return _TIERS[0]


def _staggered_label(group, bounds, x: float, cy: float, lines: list[str], size: float, family: str, color: str, last_x: list[float]) -> None:
    """Place a centered label above/below the marker in a free stagger tier."""
    sign, base = _pick_tier(x, last_x)
    text_h = len(lines) * size * metrics.LINE_HEIGHT
    top_y = (cy - base - text_h) if sign < 0 else (cy + base)
    _centered_label(group, bounds, x, top_y, lines, size, family, color)


def _time_scale(viz, axis_length: float):
    """Return (x_of, t_min, total_seconds, tick_fmt) mapping timestamps to px."""
    starts = [e.timestamp for e in viz.events] + [p.start for p in viz.phases]
    ends = [e.end_time for e in viz.events] + [p.end for p in viz.phases]
    t_min, t_max = min(starts), max(ends)
    total = max((t_max - t_min).total_seconds(), 1.0)
    tick_fmt = "%H:%M" if total <= 86400 else "%m-%d %H:%M"

    def x_of(t) -> float:
        return (t - t_min).total_seconds() / total * axis_length

    return x_of, t_min, total, tick_fmt


def _ticks(t_min, total: float, tick_fmt: str, count: int = 5) -> list[tuple[Any, str]]:
    out = []
    for i in range(count):
        frac = i / (count - 1)
        t = t_min + timedelta(seconds=frac * total)
        out.append((t, t.strftime(tick_fmt)))
    return out


def _event_data(ev) -> dict[str, str]:
    data = {
        "node-id": utils.sanitize_node_id(ev.id),
        "label": ev.title,
        "severity": ev.severity,
        "lane": ev.lane,
        "timestamp": ev.timestamp.isoformat(),
    }
    if ev.technique:
        data["technique"] = ev.technique
    return data


def _marker(ev, x: float, y: float, theme, ops: _Ops, bounds: _Bounds) -> Any:
    """Severity marker; returns the node <g> so the caller can add labels to it."""
    tl = theme["timeline"]
    color = SEVERITY_COLORS.get(ev.severity, SEVERITY_COLORS["info"])
    radius = float(tl["marker_radius"])
    group = shapes.group(["usv-node", "usv-event", _severity_class(ev.severity)], _event_data(ev))
    group.append(shapes.dot(x, y, radius, color, stroke=theme["node"]["border"], stroke_width=0.8))
    bounds.rect(x - radius, y - radius, 2 * radius, 2 * radius)
    ops.nodes.append(group)
    return group


def _centered_label(group, bounds: _Bounds, cx: float, top_y: float, lines: list[str], size: float, family: str, color: str) -> None:
    group.extend(shapes.text_lines(cx, top_y, lines, size, color))
    w = max((metrics.measure_text(line, family, size) for line in lines), default=0.0)
    bounds.rect(cx - w / 2, top_y, w, len(lines) * size * metrics.LINE_HEIGHT)


def _anchored_label(group, bounds: _Bounds, x: float, baseline_y: float, text: str, size: float, family: str, color: str, anchor: str) -> None:
    group.append(shapes.anchored_text(x, baseline_y, text, size, color, anchor=anchor))
    w = metrics.measure_text(text, family, size)
    bx = x if anchor == "start" else (x - w if anchor == "end" else x - w / 2)
    bounds.rect(bx, baseline_y - size, w, size * 1.2)


def _phase_bands_vertical(viz, x_of, top: float, bottom: float, theme, ops: _Ops, bounds: _Bounds, size: float, family: str) -> None:
    """Shade phases as vertical time regions with a name label on top."""
    alpha = float(theme["timeline"]["phase_alpha"])
    for ph in viz.phases:
        x0, x1 = x_of(ph.start), x_of(ph.end)
        w = max(x1 - x0, 1.0)
        g = shapes.group(["usv-group", "usv-phase"], {"group-id": ph.name})
        g.append(shapes.band(x0, top, w, bottom - top, ph.color, opacity=alpha))
        ops.groups.append(g)
        _anchored_label(ops.labels, bounds, x0 + w / 2, top - 5, ph.name, size, family, ph.color, "middle")
        bounds.rect(x0, top, w, bottom - top)


def _time_axis_bottom(x_of, ticks, top: float, bottom: float, theme, ops: _Ops, bounds: _Bounds, size: float, family: str) -> None:
    tl = theme["timeline"]
    grid, axis_text = tl["grid_color"], tl["axis_text"]
    for t, lbl in ticks:
        x = x_of(t)
        ops.edges.append(shapes.edge_path(f"M {shapes.fmt(x)} {shapes.fmt(top)} L {shapes.fmt(x)} {shapes.fmt(bottom)}", grid, 1.0, dashed=True))
        _anchored_label(ops.labels, bounds, x, bottom + size + 6, lbl, size, family, axis_text, "middle")


def _legend(viz, theme, ops: _Ops, bounds: _Bounds, right_x: float, top_y: float, size: float, family: str) -> None:
    """Severity legend stacked at the top-right of the plot."""
    from ...timeline import _SEVERITY_ORDER

    present = [s for s in _SEVERITY_ORDER if any(e.severity == s for e in viz.events)]
    y = top_y
    for sev in present:
        color = SEVERITY_COLORS[sev]
        g = shapes.group(["usv-legend", _severity_class(sev)], {"value": sev})
        g.append(shapes.dot(right_x, y, 5.0, color, stroke=theme["node"]["border"], stroke_width=0.6))
        ops.badges.append(g)
        _anchored_label(ops.badges, bounds, right_x + 10, y + size * 0.35, sev.title(), size, family, theme["page"]["text"], "start")
        bounds.rect(right_x - 5, y - 5, 10, 10)
        y += size * 1.5


def _wrap_title(ev, family: str, size: float, max_w: float) -> list[str]:
    lines = metrics.wrap_text(ev.title, family, size, max_w) or [ev.title]
    if ev.technique:
        lines = list(lines) + [ev.technique]
    return lines


# --------------------------------------------------------------------------- modes


def _render_swimlane(viz, theme, ops: _Ops, bounds: _Bounds) -> None:
    tl = theme["timeline"]
    font = theme["font"]
    family, size = font["family"], float(font["size"]) * 0.9
    max_w = float(theme["card"]["max_label_width"])
    axis_length = float(tl["axis_length"])
    lane_h = float(tl["lane_height"])
    x_of, t_min, total, tick_fmt = _time_scale(viz, axis_length)
    ticks = _ticks(t_min, total, tick_fmt)

    lanes = viz.lanes or ["Events"]
    grouped = viz.events_by_lane()
    content_top = 8.0
    content_bottom = content_top + lane_h * len(lanes)

    # Lane background bands (alternating) + lane labels
    lane_band, band_alpha, lane_text = tl["lane_band"], float(tl["lane_band_alpha"]), tl["lane_text"]
    for row, lane in enumerate(lanes):
        y0 = content_top + row * lane_h
        if row % 2:
            ops.groups.append(shapes.band(0.0, y0, axis_length, lane_h, lane_band, opacity=band_alpha))
        _anchored_label(ops.labels, bounds, -12.0, y0 + lane_h / 2 + size * 0.35, lane, float(font["size"]) * 0.92, family, lane_text, "end")
        bounds.rect(0.0, y0, axis_length, lane_h)

    _phase_bands_vertical(viz, x_of, content_top, content_bottom, theme, ops, bounds, float(font["size"]) * 0.85, family)
    _time_axis_bottom(x_of, ticks, content_top, content_bottom, theme, ops, bounds, float(font["size"]) * 0.85, family)

    dur_alpha = float(tl["duration_alpha"])
    for row, lane in enumerate(lanes):
        cy = content_top + row * lane_h + lane_h / 2
        events = grouped.get(lane, [])
        last_x = [-1e18] * len(_TIERS)
        for ev in events:
            x = x_of(ev.timestamp)
            if ev.duration:
                x_end = x_of(ev.end_time)
                color = SEVERITY_COLORS.get(ev.severity, SEVERITY_COLORS["info"])
                ops.edges.append(shapes.band(x, cy - 3.0, max(x_end - x, 2.0), 6.0, color, opacity=dur_alpha, radius=3.0))
                bounds.rect(x, cy - 3.0, max(x_end - x, 2.0), 6.0)
            group = _marker(ev, x, cy, theme, ops, bounds)
            lines = _wrap_title(ev, family, size, max_w)
            _staggered_label(group, bounds, x, cy, lines, size, family, theme["event_text"], last_x)

    _legend(viz, theme, ops, bounds, axis_length + 24.0, content_top + 4.0, float(font["size"]) * 0.85, family)


def _render_gantt(viz, theme, ops: _Ops, bounds: _Bounds) -> None:
    tl = theme["timeline"]
    font = theme["font"]
    family, size = font["family"], float(font["size"]) * 0.9
    axis_length = float(tl["axis_length"])
    row_h = float(tl["row_height"]) + 6.0
    x_of, t_min, total, tick_fmt = _time_scale(viz, axis_length)
    ticks = _ticks(t_min, total, tick_fmt)

    events = viz.events
    content_top = 8.0
    content_bottom = content_top + row_h * len(events)

    # Left gutter = widest event id
    gutter = max((metrics.measure_text(ev.id, family, size) for ev in events), default=0.0) + 14.0

    _phase_bands_vertical(viz, x_of, content_top, content_bottom, theme, ops, bounds, float(font["size"]) * 0.85, family)
    _time_axis_bottom(x_of, ticks, content_top, content_bottom, theme, ops, bounds, float(font["size"]) * 0.85, family)

    min_bar = (viz.time_span() or timedelta(minutes=10)) / max(len(events), 1) * 0.15
    for row, ev in enumerate(events):
        cy = content_top + row * row_h + row_h / 2
        x = x_of(ev.timestamp)
        x_end = x_of(ev.end_time if ev.duration else ev.end_time + min_bar)
        w = max(x_end - x, 3.0)
        color = SEVERITY_COLORS.get(ev.severity, SEVERITY_COLORS["info"])
        group = shapes.group(["usv-node", "usv-event", _severity_class(ev.severity)], _event_data(ev))
        group.append(shapes.band(x, cy - row_h * 0.3, w, row_h * 0.6, color, radius=3.0))
        bounds.rect(x, cy - row_h * 0.3, w, row_h * 0.6)
        ops.nodes.append(group)
        tag = ev.title + (f" [{ev.technique}]" if ev.technique else "")
        _anchored_label(group, bounds, x + 6.0, cy + size * 0.35, tag, size, family, theme["event_text"], "start")
        _anchored_label(ops.labels, bounds, -gutter + 2.0, cy + size * 0.35, ev.id, size * 0.92, family, tl["lane_text"], "start")
        bounds.point(-gutter, cy)

    _legend(viz, theme, ops, bounds, axis_length + 24.0, content_top + 4.0, float(font["size"]) * 0.85, family)


def _render_vertical(viz, theme, ops: _Ops, bounds: _Bounds) -> None:
    tl = theme["timeline"]
    font = theme["font"]
    family, size = font["family"], float(font["size"]) * 0.9
    row_h = float(tl["row_height"])
    events = viz.events
    axis_v = row_h * max(len(events), 1)
    _x_of, t_min, total, tick_fmt = _time_scale(viz, 1.0)  # only need t_min/total for the y mapping
    center_x = 0.0
    content_top = 8.0

    def y_of(t) -> float:
        return content_top + (t - t_min).total_seconds() / total * axis_v

    content_bottom = content_top + axis_v

    # Horizontal phase bands (no name label here: left-side event annotations
    # occupy that gutter — the Matplotlib vertical mode omits phase text too).
    alpha = float(tl["phase_alpha"])
    for ph in viz.phases:
        y0, y1 = y_of(ph.start), y_of(ph.end)
        h = max(y1 - y0, 1.0)
        g = shapes.group(["usv-group", "usv-phase"], {"group-id": ph.name})
        g.append(shapes.band(-260.0, y0, 520.0, h, ph.color, opacity=alpha))
        ops.groups.append(g)
        bounds.rect(-260.0, y0, 520.0, h)

    # Center connector line
    ops.edges.append(shapes.edge_path(f"M {shapes.fmt(center_x)} {shapes.fmt(content_top)} L {shapes.fmt(center_x)} {shapes.fmt(content_bottom)}", tl["connector"], 2.0))
    bounds.rect(center_x - 1, content_top, 2, content_bottom - content_top)

    for i, ev in enumerate(events):
        y = y_of(ev.timestamp)
        group = _marker(ev, center_x, y, theme, ops, bounds)
        side = 1 if i % 2 == 0 else -1
        tag = ev.title + (f" [{ev.technique}]" if ev.technique else "")
        anchor = "start" if side > 0 else "end"
        _anchored_label(group, bounds, center_x + side * 40.0, y + size * 0.35, tag, size, family, theme["event_text"], anchor)
        # Small time stamp under the marker on the opposite side
        _anchored_label(group, bounds, center_x - side * 12.0, y + size * 0.35, ev.timestamp.strftime(tick_fmt), size * 0.85, family, tl["axis_text"], "end" if side > 0 else "start")

    _legend(viz, theme, ops, bounds, 270.0, content_top + 4.0, float(font["size"]) * 0.85, family)


def _render_compact(viz, theme, ops: _Ops, bounds: _Bounds) -> None:
    tl = theme["timeline"]
    font = theme["font"]
    family, size = font["family"], float(font["size"]) * 0.9
    max_w = float(theme["card"]["max_label_width"])
    axis_length = float(tl["axis_length"])
    x_of, t_min, total, tick_fmt = _time_scale(viz, axis_length)
    ticks = _ticks(t_min, total, tick_fmt)

    events = viz.events
    cy = 60.0

    _phase_bands_vertical(viz, x_of, cy - 46.0, cy + 46.0, theme, ops, bounds, float(font["size"]) * 0.85, family)

    ops.edges.append(shapes.edge_path(f"M {shapes.fmt(x_of(t_min))} {shapes.fmt(cy)} L {shapes.fmt(axis_length)} {shapes.fmt(cy)}", tl["connector"], 2.0))
    bounds.rect(0.0, cy - 1, axis_length, 2)

    last_x = [-1e18] * len(_TIERS)
    for ev in events:
        x = x_of(ev.timestamp)
        group = _marker(ev, x, cy, theme, ops, bounds)
        lines = metrics.wrap_text(ev.title, family, size, max_w) or [ev.title]
        _staggered_label(group, bounds, x, cy, lines, size, family, theme["event_text"], last_x)

    _time_axis_bottom(x_of, ticks, cy + 46.0, cy + 46.0, theme, ops, bounds, float(font["size"]) * 0.85, family)


_RENDERERS = {
    "swimlane": _render_swimlane,
    "gantt": _render_gantt,
    "vertical": _render_vertical,
    "compact": _render_compact,
}


def render_svg(viz) -> str:
    """Render an incident timeline instance to SVG text."""
    theme = themes.resolve(viz.style)
    # Event label color: reuse the page text color (markers carry severity).
    theme["event_text"] = theme["page"]["text"]
    mode = getattr(viz, "mode", "swimlane")
    if mode not in _RENDERERS:
        mode = "swimlane"

    canvas = SvgCanvas(MODULE_SLUG, viz.styleid)
    font = theme["font"]
    page = theme["page"]
    effects = theme["effects"]
    css = [f".usv-{MODULE_SLUG} text {{ font-family: {font['family']}; }}"]
    if effects["hover_glow"]:
        css.append(f".usv-{MODULE_SLUG} .usv-event:hover circle {{ stroke-width: 2.2; }}")
    canvas.set_css("\n".join(css))

    ops = _Ops()
    bounds = _Bounds()

    if not viz.events:
        bounds.rect(0.0, 0.0, 240.0, 60.0)
        _anchored_label(ops.labels, bounds, 120.0, 34.0, "No events to display", float(font["size"]), font["family"], "#94a3b8", "middle")
    else:
        _RENDERERS[mode](viz, theme, ops, bounds)

    pad = float(page["padding"])
    min_x, min_y = bounds.min_x - pad, bounds.min_y - pad
    width = (bounds.max_x + pad) - min_x
    height = (bounds.max_y + pad) - min_y
    canvas.finalize(min_x, min_y, width, height)

    # Page background first, then the deferred layer ops in draw order.
    canvas.add("groups", shapes.card(min_x, min_y, width, height, 0, fill=page["background"], stroke="none", stroke_width=0))

    title_cfg = theme["title"]
    title = viz._incident_name() if hasattr(viz, "_incident_name") else ""
    if title_cfg["show"] and title:
        canvas.add("labels", shapes.title_text(min_x + pad * 0.5, min_y + pad * 0.55, str(title), float(title_cfg["size"]), page["text"]))

    for element in ops.groups:
        canvas.add("groups", element)
    for element in ops.edges:
        canvas.add("edges", element)
    for element in ops.nodes:
        canvas.add("nodes", element)
    for element in ops.badges:
        canvas.add("badges", element)
    for element in ops.labels:
        canvas.add("labels", element)

    return canvas.to_string()
