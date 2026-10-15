#
# VULNEX -Universal Security Visualization Library-
#
# File: privilegegradient.py
# Author: Simon Roses Femerling
# Created: 2026-10-15
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Privilege Gradient painter for the SVG engine (mode 6).

Trust zones become clusters ordered left to right by trust level (an
invisible anchor per zone, chained by heavy layout-only edges, as the
Graphviz path does), components become cards filled with their zone's
color, influences become edges styled by type (data solid, feedback dashed,
resource dotted, control thick), and inversions, where a lower-trust
component influences a higher-trust one, are drawn red and labelled with
their severity. A legend row names the influence types and the inversion.

In the drift view (``render_diff``) zones, components and influences carry
their change (``usv-diff--*``, ``data-diff``, ``data-changed``) and each
inversion its status: ``data-inversion`` new / fixed / changed / unchanged, with
``NEW INVERSION``, ``FIXED INVERSION`` and ``~ INVERSION (high → critical)``
labels; a changed one adds ``data-old-severity`` / ``data-old-trust-gap``.

All privilege-gradient semantics live here; the shared general-graph
renderer stays module-agnostic.
"""

import logging
from itertools import pairwise
from typing import Any

from ... import utils
from ...grouping import merged_label
from ...privilegegradient_view import inversion_counts_label, summary_label_lines
from .. import metrics, themes
from ..scene import Scene, SceneEdge, SceneGroup, SceneNode
from .graph import attach_icon, render_graph_svg

logger = logging.getLogger(__name__)

MODULE_SLUG = "privilegegradient"

ANCHOR_PREFIX = "__zone_anchor_"

# Influence type -> (dashed, dash pattern, width factor); color comes from the
# file's influence_types (or the preset on dark themes)
_TYPE_STROKE = {
    "data": (False, None, 1.0),
    "feedback": (True, None, 1.0),
    "resource": (False, "1.5 4", 1.3),
    "control": (False, None, 1.7),
}

_SEVERITY_MARKER = {"critical": "!!!", "high": "!!", "medium": "!"}


def _wrap(label: str, font: dict, size: float, max_w: float) -> list[str]:
    return metrics.wrap_text(str(label), font["family"], size, max_w) or [str(label)]


def inversion_label(severity: str, label: str = "") -> str:
    """The label of an inversion edge: severity markers, plus the influence's own label."""
    marker = _SEVERITY_MARKER.get(severity, "!")
    text = f"{marker} INVERSION {marker}"
    return f"{text} · {label}" if label else text


def _drift_label(viz, view, influence: dict, severity: str, label: str) -> str:
    """An inversion's label in the drift view (NEW / FIXED / changed), as the Graphviz path words it."""
    text = viz.inversion_label(view, influence, severity)
    # A merged edge (collapse) counts its new / fixed / changed inversions
    if counts := inversion_counts_label(view.inversion_counts_of(influence)):
        text = f"{text} {counts}"
    return f"{text} · {label}" if label else text


def _mark(mark) -> tuple[Any, dict[str, str]]:
    """A drift mark's status and its data-* attributes (the changed fields)."""
    if mark is None:
        return None, {}
    return mark.diff, ({"changed": ",".join(mark.changed)} if mark.changed else {})


def _build_scene(viz, theme: dict[str, Any]) -> Scene:
    """Translate the privilege-gradient data into a fully-styled Scene."""
    pg = theme["privilegegradient"]
    font = theme["font"]
    card = theme["card"]
    size = float(font["size"])
    max_w = float(card["max_label_width"])
    pad_x = float(card["padding_x"])
    pad_y = float(card["padding_y"])
    min_w = float(card["min_width"])

    name = viz.inputdata.get("gradient", {}).get("name", "Privilege Gradient Graph")
    scene = Scene(module=MODULE_SLUG, meta={"name": name})

    view = viz.render_view()
    zones = sorted(view.zones.items(), key=lambda item: item[1].get("trust_level", 0))
    anchors: list[str] = []
    for zone_id, zone in zones:
        trust = zone.get("trust_level", 0)
        border = zone.get("border_color", "#999999")
        anchor = ANCHOR_PREFIX + utils.sanitize_node_id(zone_id)
        scene.nodes.append(SceneNode(id=anchor, label="", width=1.0, height=1.0, layout_only=True))
        anchors.append(anchor)
        members = [anchor]

        for comp_id, comp in view.components.items():
            if comp.get("zone") != zone_id:
                continue
            label = comp.get("label", comp_id)
            facts = view.summary_facts(comp_id)
            if facts is not None:
                # A collapsed group: one card with its counts
                lines = [line for text in summary_label_lines(facts) for line in _wrap(text, font, size, max_w)]
            else:
                lines = _wrap(label, font, size, max_w)
            text_w, text_h = metrics.measure_block(lines, font["family"], size)
            # Cards take the zone's color, as in the Graphviz path; a preset
            # with its own component fill (dark themes) keeps the zone in the border
            fill = comp.get("fillcolor") or pg.get("component_fill") or border
            card_border = border if pg.get("component_fill") else pg["component_border"]
            diff, diff_data = _mark(view.marks.get(comp_id))
            kind, group_data = "component", {}
            if facts is not None:
                kind = "group"
                group_data = {
                    "collapsed": "true",
                    "cluster-id": utils.sanitize_node_id(view.group_of(comp_id)),
                    "member-count": str(facts["members"]),
                    "inversion-count": str(facts["inversions"]),
                    **({"max-severity": facts["max_severity"]} if facts.get("max_severity") else {}),
                }
                if facts["inversions"]:
                    card_border = pg["inversion"]
            scene.nodes.append(
                SceneNode(
                    id=comp_id,
                    label=label,
                    kind="node",
                    lines=lines,
                    width=max(min_w, text_w + 2 * pad_x),
                    height=text_h + 2 * pad_y,
                    shape="card",
                    fill=fill,
                    border=card_border,
                    text_color=comp.get("fontcolor") or utils.readable_text_color(fill) or "#ffffff",
                    diff=diff,
                    data={
                        "node-id": utils.sanitize_node_id(comp_id),
                        "label": str(label),
                        "kind": kind,
                        "zone": str(zone_id),
                        "trust-level": str(trust),
                        **({"type": str(comp["type"])} if comp.get("type") else {}),
                        **group_data,
                        **diff_data,
                    },
                )
            )
            if comp.get("image"):
                attach_icon(scene.nodes[-1], comp["image"], theme)
            members.append(comp_id)

        zone_diff, zone_data = _mark(view.marks.get(f"zone:{zone_id}"))
        scene.groups.append(
            SceneGroup(
                id=utils.sanitize_node_id(zone_id),
                label=f"{zone.get('label', zone_id)} (Trust Level {trust})",
                members=members,
                fill=pg.get("zone_fill") or zone.get("color", "#f0f0f0"),
                border=border,
                text_color=pg.get("zone_text") or zone.get("font_color", "#333333"),
                diff=zone_diff,
                data={"zone": str(zone_id), "trust-level": str(trust), **zone_data},
            )
        )
        _add_group_clusters(scene, view, zone_id, zone, pg, border, set(members))

    # Zones left to right by trust: a heavy invisible chain between their anchors
    for left, right in pairwise(anchors):
        scene.edges.append(SceneEdge(src=left, dst=right, kind="layout", layout_only=True, weight=100))

    if not any(not n.layout_only for n in scene.nodes):
        raise utils.RenderError("Privilege gradient has no components to render")

    _build_edges(scene, viz, view, theme)
    return scene


def _add_group_clusters(
    scene: Scene, view, zone_id: str, zone: dict, pg: dict[str, Any], border: str, drawn: set[str]
) -> None:
    """Expanded groups of a zone: dashed clusters nested in the zone's."""
    for group_id, info in view.groups.items():
        members = [m for m in info.members if m in drawn]
        if info.collapsed or view.group_zone.get(group_id) != zone_id or not members:
            continue
        scene.groups.append(
            SceneGroup(
                id=utils.sanitize_node_id(group_id),
                label=info.label,
                members=members,
                fill=info.color or pg.get("zone_fill") or zone.get("color", "#f0f0f0"),
                border=border,
                text_color=pg.get("zone_text") or zone.get("font_color", "#333333"),
                dashed=True,
                parent=utils.sanitize_node_id(zone_id),
                data={"zone": str(zone_id), "collapsed": "false"},
            )
        )


def _type_color(viz, type_id: str, pg: dict[str, Any]) -> str:
    """An influence type's color: the preset's on dark themes, else the file's, else the preset's."""
    preset = pg.get("type_colors", {}).get(type_id)
    configured = viz._influence_types.get(type_id, {}).get("color")
    if pg.get("dark") and preset:
        return preset
    return configured or preset or "#64748b"


def _build_edges(scene: Scene, viz, view, theme: dict[str, Any]) -> None:
    """Influence edges by type; inversions in red with their severity."""
    pg = theme["privilegegradient"]
    drift = viz.diff_marks is not None
    diff_colors = theme.get("diff", {})
    drawn = {n.id for n in scene.nodes if not n.layout_only}
    base_width = float(theme["edge"]["width"])
    inversions = {(inv["from"], inv["to"]): inv for inv in view.inversions}

    for influence in view.influences:
        src, dst = influence.get("from"), influence.get("to")
        if src not in drawn or dst not in drawn:
            continue
        type_id = influence.get("type", "data")
        mark = view.influence_mark(influence)
        # Influences merged by a collapse read "\u00d7N" (and carry data-edge-count)
        label = merged_label(mark, influence.get("label", ""))
        data = {"type": str(type_id)}
        if mark is not None and mark.count > 1:
            data["edge-count"] = str(mark.count)
        diff, diff_data = _mark(mark)
        data.update(diff_data)
        status = view.inversion_of(influence) if drift else None
        if status in ("new", "fixed"):
            data["inversion"] = status
        for count_status, count in view.inversion_counts_of(influence).items():
            data[f"inversion-{count_status}"] = str(count)
        before = view.inversion_before(influence) if status == "changed" else None
        if before is not None:
            data["old-severity"] = str(before["severity"])
            data["old-trust-gap"] = str(before["trust_gap"])
        inversion = inversions.get((src, dst))
        if inversion is not None and status != "fixed":
            data.update(
                {
                    "inversion": status or "true",
                    "severity": inversion["severity"],
                    "trust-gap": str(inversion["trust_gap"]),
                }
            )
            scene.edges.append(
                SceneEdge(
                    src=src,
                    dst=dst,
                    kind="inversion",
                    color=diff_colors.get("modified") if status == "changed" else pg["inversion"],
                    width=float(pg["inversion_width"]),
                    label=(
                        _drift_label(viz, view, influence, inversion["severity"], label)
                        if drift
                        else inversion_label(inversion["severity"], label)
                    ),
                    label_color={"new": diff_colors.get("added"), "changed": diff_colors.get("modified")}.get(
                        status or ""
                    ),
                    diff=diff,
                    data=data,
                )
            )
            continue
        dashed, dash, factor = _TYPE_STROKE.get(type_id, _TYPE_STROKE["data"])
        scene.edges.append(
            SceneEdge(
                src=src,
                dst=dst,
                kind=str(type_id),
                color=_type_color(viz, type_id, pg),
                width=base_width * factor,
                dashed=dashed,
                dash=dash,
                label=_drift_label(viz, view, influence, "", label) if status == "fixed" else (label or None),
                label_color=diff_colors.get("removed") if status == "fixed" else None,
                diff=diff,
                data=data,
            )
        )


def _legend(viz, theme: dict[str, Any]) -> list[tuple]:
    """Legend items: each influence type as a line in its style, then the inversion."""
    pg = theme["privilegegradient"]
    base_width = float(theme["edge"]["width"])
    items: list[tuple] = []
    for type_id, cfg in viz._influence_types.items():
        dashed, dash, factor = _TYPE_STROKE.get(type_id, _TYPE_STROKE["data"])
        line = {"width": base_width * factor, "dashed": dashed, "dash": dash}
        items.append((str(cfg.get("label", type_id)), _type_color(viz, type_id, pg), line))
    items.append(("INVERSION", pg["inversion"], {"width": float(pg["inversion_width"])}))
    return items


def render_svg(viz) -> str:
    """Render a privilege gradient visualization instance to SVG text."""
    theme = themes.resolve(viz.style)
    if getattr(viz, "diff_colors", None):
        theme["diff"] = {**theme["diff"], **viz.diff_colors}
    scene = _build_scene(viz, theme)
    scene.meta["legend"] = _legend(viz, theme)
    if getattr(viz, "diff_marks", None) is not None:
        diff = theme["diff"]
        scene.meta["legend"] += [
            ("+ added", diff["added"]),
            ("\u2212 removed", diff["removed"]),
            ("~ modified", diff["modified"]),
        ]
    pg = theme["privilegegradient"]
    return render_graph_svg(
        viz,
        scene,
        theme,
        MODULE_SLUG,
        rankdir=str(pg.get("rankdir", "LR")),
        nodesep=float(pg.get("nodesep", 0.6)),
        ranksep=float(pg.get("ranksep", 1.0)),
    )
