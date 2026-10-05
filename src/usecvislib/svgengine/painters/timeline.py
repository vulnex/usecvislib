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
from itertools import pairwise
from typing import Any

from ... import utils
from ...timeline import SEVERITY_COLORS
from .. import metrics, shapes, themes
from ..canvas import SvgCanvas

logger = logging.getLogger(__name__)

MODULE_SLUG = "timeline"

_CANON_SEV = {"critical", "high", "medium", "low", "info"}
# Label placement: candidate offsets (px from the marker center) tried in
# order, alternating above/below, until a label clears every placed label,
# marker and duration bar.
_LABEL_STEP = 14.0
_LABEL_BASE = 12.0
_LABEL_LEVELS = 14
_LABEL_PAD = 3.0


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


class _LabelPlacer:
    """Places marker labels so that none overlap (lane-local coordinates).

    Obstacles and placed labels are rectangles relative to the marker row
    (y = 0 at the marker centers). Each label tries offsets alternating
    above / below, nearest first, and takes the first free slot.
    """

    def __init__(self) -> None:
        self.rects: list[tuple[float, float, float, float]] = []
        self.up = 0.0  # extent above the marker row
        self.down = 0.0  # extent below

    def block(self, x0: float, y0: float, x1: float, y1: float) -> None:
        self.rects.append((x0, y0, x1, y1))

    def _free(self, r: tuple[float, float, float, float]) -> bool:
        x0, y0, x1, y1 = r
        p = _LABEL_PAD
        return all(x1 + p <= a0 or x0 - p >= a1 or y1 + p <= b0 or y0 - p >= b1 for a0, b0, a1, b1 in self.rects)

    def place(self, x: float, w: float, h: float) -> float:
        """Return the label's top y (lane-local) and reserve its box."""
        candidates = []
        for level in range(_LABEL_LEVELS):
            off = _LABEL_BASE + level * _LABEL_STEP
            candidates.append(-off - h)  # above: label bottom sits `off` above
            candidates.append(off)  # below
        top = candidates[0]
        for cand in candidates:
            if self._free((x - w / 2, cand, x + w / 2, cand + h)):
                top = cand
                break
        self.rects.append((x - w / 2, top, x + w / 2, top + h))
        self.up = max(self.up, -top)
        self.down = max(self.down, top + h)
        return top


def _label_box(lines: list[str], family: str, size: float) -> tuple[float, float]:
    w = max((metrics.measure_text(line, family, size) for line in lines), default=0.0)
    return w, len(lines) * size * metrics.LINE_HEIGHT


def _time_scale(viz, axis_length: float):
    """Return (x_of, t_min, total_seconds, tick_fmt) mapping timestamps to px."""
    starts = [e.timestamp for e in viz.events] + [p.start for p in viz.phases]
    ends = [e.end_time for e in viz.events] + [p.end for p in viz.phases]
    t_min, t_max = min(starts), max(ends)
    # 2% breathing room each side (as Matplotlib's axis margins): the first
    # and last markers sat on the plot edge
    pad = (t_max - t_min) * 0.02
    t_min, t_max = t_min - pad, t_max + pad
    total = max((t_max - t_min).total_seconds(), 1.0)
    tick_fmt = "%H:%M" if total <= 86400 else "%m-%d %H:%M"

    def x_of(t) -> float:
        return (t - t_min).total_seconds() / total * axis_length

    return x_of, t_min, total, tick_fmt


_TICK_STEPS = (
    [60 * m for m in (1, 2, 5, 10, 15, 30)]
    + [3600 * h for h in (1, 2, 3, 6, 12)]
    + [86400 * d for d in (1, 2, 7, 14, 30)]
)


def _ticks(t_min, total: float, tick_fmt: str, target: int = 7) -> list[tuple[Any, str]]:
    """Ticks on round times (e.g. every 1h / 15min), about ``target`` of them.

    Splitting the span into equal parts put ticks at times like 11:07.
    """
    step = next((st for st in _TICK_STEPS if total / st <= target), _TICK_STEPS[-1])
    day_start = t_min.replace(hour=0, minute=0, second=0, microsecond=0)
    offset = (t_min - day_start).total_seconds()
    first = day_start + timedelta(seconds=-(-offset // step) * step)
    t_end = t_min + timedelta(seconds=total)
    out = []
    t = first
    while t <= t_end:
        out.append((t, t.strftime(tick_fmt)))
        t += timedelta(seconds=step)
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


def _centered_label(
    group, bounds: _Bounds, cx: float, top_y: float, lines: list[str], size: float, family: str, color: str
) -> None:
    group.extend(shapes.text_lines(cx, top_y, lines, size, color))
    w = max((metrics.measure_text(line, family, size) for line in lines), default=0.0)
    bounds.rect(cx - w / 2, top_y, w, len(lines) * size * metrics.LINE_HEIGHT)


def _anchored_label(
    group, bounds: _Bounds, x: float, baseline_y: float, text: str, size: float, family: str, color: str, anchor: str
) -> None:
    group.append(shapes.anchored_text(x, baseline_y, text, size, color, anchor=anchor))
    w = metrics.measure_text(text, family, size)
    bx = x if anchor == "start" else (x - w if anchor == "end" else x - w / 2)
    bounds.rect(bx, baseline_y - size, w, size * 1.2)


def _phase_bands_vertical(
    viz, x_of, top: float, bottom: float, theme, ops: _Ops, bounds: _Bounds, size: float, family: str
) -> None:
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


def _time_axis_bottom(
    x_of, ticks, top: float, bottom: float, theme, ops: _Ops, bounds: _Bounds, size: float, family: str
) -> None:
    tl = theme["timeline"]
    grid, axis_text = tl["grid_color"], tl["axis_text"]
    for t, lbl in ticks:
        x = x_of(t)
        ops.edges.append(
            shapes.edge_path(
                f"M {shapes.fmt(x)} {shapes.fmt(top)} L {shapes.fmt(x)} {shapes.fmt(bottom)}", grid, 1.0, dashed=True
            )
        )
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
        _anchored_label(
            ops.badges, bounds, right_x + 10, y + size * 0.35, sev.title(), size, family, theme["page"]["text"], "start"
        )
        bounds.rect(right_x - 5, y - 5, 10, 10)
        y += size * 1.5


def _wrap_title(ev, family: str, size: float, max_w: float) -> list[str]:
    lines = metrics.wrap_text(ev.title, family, size, max_w) or [ev.title]
    if ev.technique:
        lines = [*lines, ev.technique]
    return lines


# --------------------------------------------------------------------------- modes


def _render_swimlane(viz, theme, ops: _Ops, bounds: _Bounds) -> None:
    tl = theme["timeline"]
    font = theme["font"]
    family, size = font["family"], float(font["size"]) * 0.9
    max_w = float(theme["card"]["max_label_width"])
    axis_length = float(tl["axis_length"])
    lane_h = float(tl["lane_height"])
    radius = float(tl["marker_radius"])
    x_of, t_min, total, tick_fmt = _time_scale(viz, axis_length)
    ticks = _ticks(t_min, total, tick_fmt)

    lanes = viz.lanes or ["Events"]
    grouped = viz.events_by_lane()

    # Pass 1: place each lane's labels lane-locally, then size every lane to
    # its labels so they can never spill into a neighbouring lane.
    plans: list[tuple[_LabelPlacer, list]] = []
    for lane in lanes:
        placer = _LabelPlacer()
        lane_events = grouped.get(lane, [])
        for ev in lane_events:
            x = x_of(ev.timestamp)
            placer.block(x - radius, -radius, x + radius, radius)
            if ev.duration:
                placer.block(x, -3.0, max(x_of(ev.end_time), x + 2.0), 3.0)
        items = []
        for ev in lane_events:
            x = x_of(ev.timestamp)
            lines = _wrap_title(ev, family, size, max_w)
            w, h = _label_box(lines, family, size)
            items.append((ev, x, lines, placer.place(x, w, h)))
        plans.append((placer, items))

    lane_pad = 8.0
    content_top = 8.0
    lane_tops, lane_heights, centers = [], [], []
    y = content_top
    for placer, _items in plans:
        height = max(lane_h, placer.up + placer.down + 2 * lane_pad)
        # Marker row sits so the label stack is centered in the lane.
        cy = y + height / 2 + (placer.up - placer.down) / 2
        lane_tops.append(y)
        lane_heights.append(height)
        centers.append(cy)
        y += height
    content_bottom = y

    # Lane background bands (alternating) + lane labels
    lane_band, band_alpha, lane_text = tl["lane_band"], float(tl["lane_band_alpha"]), tl["lane_text"]
    for row, lane in enumerate(lanes):
        y0, height = lane_tops[row], lane_heights[row]
        if row % 2:
            ops.groups.append(shapes.band(0.0, y0, axis_length, height, lane_band, opacity=band_alpha))
        _anchored_label(
            ops.labels,
            bounds,
            -12.0,
            centers[row] + size * 0.35,
            lane,
            float(font["size"]) * 0.92,
            family,
            lane_text,
            "end",
        )
        bounds.rect(0.0, y0, axis_length, height)

    _phase_bands_vertical(
        viz, x_of, content_top, content_bottom, theme, ops, bounds, float(font["size"]) * 0.85, family
    )
    _time_axis_bottom(x_of, ticks, content_top, content_bottom, theme, ops, bounds, float(font["size"]) * 0.85, family)

    dur_alpha = float(tl["duration_alpha"])
    for row, (_placer, items) in enumerate(plans):
        cy = centers[row]
        for ev, x, lines, top in items:
            if ev.duration:
                x_end = x_of(ev.end_time)
                color = SEVERITY_COLORS.get(ev.severity, SEVERITY_COLORS["info"])
                ops.edges.append(
                    shapes.band(x, cy - 3.0, max(x_end - x, 2.0), 6.0, color, opacity=dur_alpha, radius=3.0)
                )
                bounds.rect(x, cy - 3.0, max(x_end - x, 2.0), 6.0)
            group = _marker(ev, x, cy, theme, ops, bounds)
            _centered_label(group, bounds, x, cy + top, lines, size, family, theme["event_text"])

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

    _phase_bands_vertical(
        viz, x_of, content_top, content_bottom, theme, ops, bounds, float(font["size"]) * 0.85, family
    )
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
        # After the bar: inside it, dark text sat on dark severity fills.
        _anchored_label(group, bounds, x + w + 6.0, cy + size * 0.35, tag, size, family, theme["event_text"], "start")
        _anchored_label(
            ops.labels, bounds, -gutter + 2.0, cy + size * 0.35, ev.id, size * 0.92, family, tl["lane_text"], "start"
        )
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

    def y_raw(t) -> float:
        return content_top + (t - t_min).total_seconds() / total * axis_v

    # Events close in time would overlap: enforce a minimum row spacing and
    # map other timestamps (phase bounds) piecewise-linearly between the
    # adjusted event rows, so bands still bracket the right events.
    min_gap = size * 1.9
    ys: list[float] = []
    for ev in events:
        raw = y_raw(ev.timestamp)
        ys.append(max(raw, ys[-1] + min_gap) if ys else raw)
    knots = sorted(zip((y_raw(ev.timestamp) for ev in events), ys, strict=True))

    def y_of(t) -> float:
        raw = y_raw(t)
        if raw <= knots[0][0]:
            return raw + knots[0][1] - knots[0][0]
        for (r0, a0), (r1, a1) in pairwise(knots):
            if raw <= r1:
                return a0 + (a1 - a0) * ((raw - r0) / (r1 - r0) if r1 > r0 else 1.0)
        return raw + knots[-1][1] - knots[-1][0]

    content_bottom = max(content_top + axis_v, ys[-1] + min_gap)

    # Center connector line
    ops.edges.append(
        shapes.edge_path(
            f"M {shapes.fmt(center_x)} {shapes.fmt(content_top)} L {shapes.fmt(center_x)} {shapes.fmt(content_bottom)}",
            tl["connector"],
            2.0,
        )
    )
    bounds.rect(center_x - 1, content_top, 2, content_bottom - content_top)

    for i, ev in enumerate(events):
        y = ys[i]
        group = _marker(ev, center_x, y, theme, ops, bounds)
        side = 1 if i % 2 == 0 else -1
        tag = ev.title + (f" [{ev.technique}]" if ev.technique else "")
        anchor = "start" if side > 0 else "end"
        _anchored_label(
            group, bounds, center_x + side * 40.0, y + size * 0.35, tag, size, family, theme["event_text"], anchor
        )
        # Small time stamp under the marker on the opposite side
        _anchored_label(
            group,
            bounds,
            center_x - side * 12.0,
            y + size * 0.35,
            ev.timestamp.strftime(tick_fmt),
            size * 0.85,
            family,
            tl["axis_text"],
            "end" if side > 0 else "start",
        )

    # Phase bands span the labels actually drawn plus a right-hand column
    # holding each phase's name at the top of its band (names were missing).
    name_size = float(font["size"]) * 0.85
    names_x = bounds.max_x + 20.0
    names_w = max((metrics.measure_text(ph.name, family, name_size) for ph in viz.phases), default=0.0)
    band_x0 = bounds.min_x - 12.0
    band_x1 = names_x + names_w + 12.0 if viz.phases else bounds.max_x + 12.0
    alpha = float(tl["phase_alpha"])
    for ph in viz.phases:
        y0, y1 = y_of(ph.start), y_of(ph.end)
        h = max(y1 - y0, 1.0)
        g = shapes.group(["usv-group", "usv-phase"], {"group-id": ph.name})
        g.append(shapes.band(band_x0, y0, band_x1 - band_x0, h, ph.color, opacity=alpha))
        ops.groups.append(g)
        bounds.rect(band_x0, y0, band_x1 - band_x0, h)
        _anchored_label(
            ops.labels, bounds, names_x, y0 + name_size * 1.2, ph.name, name_size, family, ph.color, "start"
        )

    # Legend right of everything drawn, so it never covers a label.
    _legend(viz, theme, ops, bounds, bounds.max_x + 24.0, content_top + 4.0, float(font["size"]) * 0.85, family)


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
    radius = float(tl["marker_radius"])

    # Place labels first so the phase bands and the axis clear the stack.
    placer = _LabelPlacer()
    for ev in events:
        x = x_of(ev.timestamp)
        placer.block(x - radius, -radius, x + radius, radius)
    placed = []
    for ev in events:
        x = x_of(ev.timestamp)
        lines = metrics.wrap_text(ev.title, family, size, max_w) or [ev.title]
        w, h = _label_box(lines, family, size)
        placed.append((ev, x, lines, placer.place(x, w, h)))
    band_top = cy - max(46.0, placer.up + 8.0)
    band_bottom = cy + max(46.0, placer.down + 8.0)

    _phase_bands_vertical(viz, x_of, band_top, band_bottom, theme, ops, bounds, float(font["size"]) * 0.85, family)

    ops.edges.append(
        shapes.edge_path(
            f"M {shapes.fmt(x_of(t_min))} {shapes.fmt(cy)} L {shapes.fmt(axis_length)} {shapes.fmt(cy)}",
            tl["connector"],
            2.0,
        )
    )
    bounds.rect(0.0, cy - 1, axis_length, 2)

    for ev, x, lines, top in placed:
        group = _marker(ev, x, cy, theme, ops, bounds)
        _centered_label(group, bounds, x, cy + top, lines, size, family, theme["event_text"])

    _time_axis_bottom(x_of, ticks, band_bottom, band_bottom, theme, ops, bounds, float(font["size"]) * 0.85, family)


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
        _anchored_label(
            ops.labels,
            bounds,
            120.0,
            34.0,
            "No events to display",
            float(font["size"]),
            font["family"],
            "#94a3b8",
            "middle",
        )
    else:
        _RENDERERS[mode](viz, theme, ops, bounds)

    pad = float(page["padding"])
    min_x, min_y = bounds.min_x - pad, bounds.min_y - pad
    width = (bounds.max_x + pad) - min_x
    height = (bounds.max_y + pad) - min_y
    canvas.finalize(min_x, min_y, width, height)

    # Page background first, then the deferred layer ops in draw order.
    canvas.add(
        "groups", shapes.card(min_x, min_y, width, height, 0, fill=page["background"], stroke="none", stroke_width=0)
    )

    title_cfg = theme["title"]
    title = viz._incident_name() if hasattr(viz, "_incident_name") else ""
    if title_cfg["show"] and title:
        canvas.add(
            "labels",
            shapes.title_text(
                min_x + pad * 0.5, min_y + pad * 0.55, str(title), float(title_cfg["size"]), page["text"]
            ),
        )

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
