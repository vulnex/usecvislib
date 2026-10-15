#
# VULNEX -Universal Security Visualization Library-
#
# File: privilegegradient_view.py
# Author: Simon Roses Femerling
# Created: 2026-10-15
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Render view for the Privilege Gradient: what both render engines draw.

The Graphviz path (``PrivilegeGradient._render_impl``) and the SVG painter
(``svgengine/painters/privilegegradient.py``) both draw from a
:class:`GradientView`: the zones, components, influences and inversions to
draw, plus marks for the drift view (``render_diff``) and the groups of
components (Atajo A11).

**Grouping.** Components are grouped by a component field (``group_by``) or
their own ``group`` field. A group never spans zones: the same value in two
zones is two groups, with ids ``<zone>/<value>``. Because every component of
a zone has the same trust level, a group can never hold an inversion between
its own members, and all influences merged into one edge by a collapse run
between the same two zones, so they share one trust gap and severity.
Inversions on the collapsed picture are therefore detected exactly by running
the module's own detection on it.

The view only changes the picture: statistics, inversions and path analysis
keep using the full model loaded by ``PrivilegeGradient``.
"""

import logging
from dataclasses import dataclass, field
from typing import Any, Optional

from .drift import ElementMark, GroupInfo
from .grouping import SUMMARY_PREFIX, collapse_requested, combined_status, groups_to_collapse

logger = logging.getLogger(__name__)

# Component fields that are part of the module's schema, never Graphviz attributes
# ("group" is one in Graphviz: it would straighten edges between same-group nodes)
SCHEMA_FIELDS = ("id", "zone", "description", "type", "group")

SEVERITY_ORDER = ("medium", "high", "critical")


def influence_key(influence: dict[str, Any]) -> str:
    """An influence's identity: ``from->to:type`` (influences have no ids; type defaults to data)."""
    return f"{influence.get('from')}->{influence.get('to')}:{influence.get('type') or 'data'}"


@dataclass
class GradientView:
    """The gradient's sections to draw, and the marks and groups that style them."""

    zones: dict[str, dict]
    components: dict[str, dict]
    influences: list[dict]
    inversions: list[dict]
    marks: dict[str, ElementMark] = field(default_factory=dict)  # "zone:<id>", component or summary id
    edge_marks: dict[tuple, ElementMark] = field(default_factory=dict)  # (from, to, type)
    inversion_status: dict[str, str] = field(default_factory=dict)  # "from->to:type" -> new/fixed/changed/unchanged
    inversions_before: dict[str, dict] = field(default_factory=dict)  # changed ones: earlier severity, trust_gap
    groups: dict[str, GroupInfo] = field(default_factory=dict)  # group id -> members (component ids)
    group_zone: dict[str, str] = field(default_factory=dict)  # group id -> its zone
    merged_from: dict[tuple, list[str]] = field(default_factory=dict)  # merged edge -> member influence keys
    inversion_counts: dict[str, dict[str, int]] = field(default_factory=dict)  # merged edge -> {status: count}

    def influence_mark(self, influence: dict) -> Optional[ElementMark]:
        key = (influence.get("from"), influence.get("to"), influence.get("type") or "data")
        return self.edge_marks.get(key)

    def inversion_of(self, influence: dict) -> Optional[str]:
        return self.inversion_status.get(influence_key(influence))

    def inversion_before(self, influence: dict) -> Optional[dict]:
        """A changed inversion's earlier severity and trust gap."""
        return self.inversions_before.get(influence_key(influence))

    def inversion_counts_of(self, influence: dict) -> dict[str, int]:
        """Drift: how many of a merged edge's influences are new / fixed / changed inversions."""
        return self.inversion_counts.get(influence_key(influence), {})

    def group_of(self, component_id: str) -> Optional[str]:
        mark = self.marks.get(component_id)
        return mark.group if mark is not None else None

    def summary_facts(self, component_id: str) -> Optional[dict[str, Any]]:
        """A collapsed group's summary facts, or None for an ordinary component."""
        mark = self.marks.get(component_id)
        return mark.collapsed if mark is not None else None


def component_groups(components: dict[str, dict], group_by: Optional[str]) -> dict[str, str]:
    """Group id of each grouped component: ``<zone>/<value>``.

    The value is the component's own ``group`` field, else its ``group_by``
    field; components with neither stay ungrouped.
    """
    groups = {}
    for comp_id, comp in components.items():
        if not isinstance(comp, dict):
            continue
        value = comp.get("group")
        if value in (None, "") and group_by:
            value = comp.get(group_by)
        if value in (None, "") or isinstance(value, dict | list):
            continue
        groups[comp_id] = f"{comp.get('zone')}/{value}"
    return groups


def apply_grouping(
    view: GradientView,
    group_by: Optional[str],
    collapse: Any,
    max_nodes: int,
    meta: dict[str, Any],
) -> None:
    """Group the view's components and collapse the chosen groups, in place.

    Args:
        view: The view to group (its components, influences and marks are replaced
            when a group collapses; the loaded data is never modified).
        group_by: Component field to group on (a component's ``group`` wins).
        collapse: False / "none", True / "all", "auto", or group ids.
        max_nodes: Target component count for "auto".
        meta: Per-group settings by group id: ``label``, ``color``, ``collapsed``.
    """
    membership = component_groups(view.components, group_by)
    if not membership:
        if collapse_requested(collapse):
            logger.warning("collapse needs groups (group_by or component 'group' fields); ignored")
        return
    for comp_id, group_id in membership.items():
        info = view.groups.get(group_id)
        if info is None:
            zone = str(view.components[comp_id].get("zone"))
            group_meta = meta.get(group_id)
            group_meta = group_meta if isinstance(group_meta, dict) else {}
            # Default label: the value (the id minus its "<zone>/" prefix; a zone id may hold a "/")
            label = str(group_meta.get("label") or group_id[len(zone) + 1 :])
            info = GroupInfo(id=group_id, label=label, color=group_meta.get("color"))
            view.groups[group_id] = info
            view.group_zone[group_id] = zone
        info.members.append(comp_id)
        view.marks.setdefault(comp_id, ElementMark()).group = group_id

    collapsed = groups_to_collapse(view.groups, meta, collapse, max_nodes, len(view.components))
    if collapsed:
        for group_id in collapsed:
            view.groups[group_id].collapsed = True
        _collapse(view, collapsed)


def _worst(severities: list[str]) -> Optional[str]:
    ranked = [s for s in severities if s in SEVERITY_ORDER]
    return max(ranked, key=SEVERITY_ORDER.index) if ranked else None


def _collapse(view: GradientView, collapsed: list[str]) -> None:
    """Replace each collapsed group's members by one summary component; re-point and merge influences."""
    from .privilegegradient import detect_inversions

    summary_of = {member: SUMMARY_PREFIX + gid for gid in collapsed for member in view.groups[gid].members}

    # Summary facts: members, the inversions they take part in (worst severity), drift counts
    for gid in collapsed:
        info = view.groups[gid]
        members = set(info.members)
        touching = [inv for inv in view.inversions if inv["from"] in members or inv["to"] in members]
        facts: dict[str, Any] = {
            "label": info.label,
            "zone": view.group_zone[gid],
            "members": len(info.members),
            "inversions": len(touching),
            "max_severity": _worst([inv["severity"] for inv in touching]),
        }
        statuses = [m.diff for member in info.members if (m := view.marks.get(member)) is not None and m.diff]
        summary_diff = None
        if statuses:
            for status in ("added", "removed", "modified"):
                facts[status] = statuses.count(status)
            summary_diff = "modified" if any(s != "unchanged" for s in statuses) else "unchanged"
        view.marks[SUMMARY_PREFIX + gid] = ElementMark(group=gid, collapsed=facts, diff=summary_diff)

    # Components: each summary takes the place of its group's first member. A summary
    # carries only what the engines draw (marks hold the facts), so nothing leaks into DOT.
    components: dict[str, dict] = {}
    for comp_id, comp in view.components.items():
        summary = summary_of.get(comp_id)
        if summary is None:
            components[comp_id] = comp
        elif summary not in components:
            facts = view.marks[summary].collapsed
            components[summary] = {"id": summary, "label": facts["label"], "zone": facts["zone"]}
    view.components = components

    # Influences: drop those inside one collapsed group (never inversions), re-point the
    # rest, merge duplicates (same endpoints and type) into one counted edge
    merged: dict[tuple, dict] = {}
    members_of: dict[tuple, list[str]] = {}
    statuses_of: dict[tuple, list[Optional[str]]] = {}
    for influence in view.influences:
        src, dst = influence.get("from"), influence.get("to")
        if src in summary_of and summary_of[src] == summary_of.get(dst):
            continue
        type_id = influence.get("type") or "data"
        key = (summary_of.get(src, src), summary_of.get(dst, dst), type_id)
        if key not in merged:
            merged[key] = {**influence, "from": key[0], "to": key[1]}
        members_of.setdefault(key, []).append(influence_key(influence))
        old_mark = view.edge_marks.get((src, dst, type_id))
        statuses_of.setdefault(key, []).append(old_mark.diff if old_mark else None)
    edge_marks: dict[tuple, ElementMark] = {}
    inversion_status: dict[str, str] = {}
    inversions_before: dict[str, dict] = {}
    for key, member_keys in members_of.items():
        status = combined_status(statuses_of[key])
        if len(member_keys) > 1 or status is not None:
            edge_marks[key] = ElementMark(diff=status, count=len(member_keys))
        if len(member_keys) > 1:
            view.merged_from[key] = member_keys
        _carry_inversion_status(view, key, member_keys, inversion_status, inversions_before)
    view.influences = list(merged.values())
    view.edge_marks = edge_marks
    view.inversion_status = inversion_status
    view.inversions_before = inversions_before

    # Exact on the collapsed picture: a summary sits in its group's zone (module docstring)
    view.inversions = detect_inversions(view.zones, view.components, view.influences)


def _carry_inversion_status(
    view: GradientView,
    key: tuple,
    member_keys: list[str],
    inversion_status: dict[str, str],
    inversions_before: dict[str, dict],
) -> None:
    """Drift: the inversion status of an edge after the collapse, from its member influences.

    The statuses are keyed by influence, so a re-pointed edge takes its
    member's status, a merged edge the status its members share ("mixed" when
    they differ), and a merged edge also counts its new / fixed / changed members.
    """
    statuses = [s for k in member_keys if (s := view.inversion_status.get(k))]
    if not statuses:
        return
    new_key = influence_key({"from": key[0], "to": key[1], "type": key[2]})
    inversion_status[new_key] = statuses[0] if all(s == statuses[0] for s in statuses) else "mixed"
    before = next((view.inversions_before[k] for k in member_keys if k in view.inversions_before), None)
    if before is not None and inversion_status[new_key] == "changed":
        inversions_before[new_key] = before
    if len(member_keys) > 1:
        counts = {s: statuses.count(s) for s in ("new", "fixed", "changed") if s in statuses}
        if counts:
            view.inversion_counts[new_key] = counts


def inversion_counts_label(counts: dict[str, int]) -> str:
    """``(2 new, 1 fixed)`` for a merged edge's inversion changes; empty without any."""
    parts = [f"{counts[s]} {s}" for s in ("new", "fixed", "changed") if counts.get(s)]
    return f"({', '.join(parts)})" if parts else ""


def group_stats(view: GradientView) -> dict[str, dict[str, Any]]:
    """Per-group counts on the full model: zone, members, inversions taking part, worst severity."""
    stats = {}
    for gid, info in view.groups.items():
        members = set(info.members)
        touching = [inv for inv in view.inversions if inv["from"] in members or inv["to"] in members]
        stats[gid] = {
            "label": info.label,
            "zone": view.group_zone[gid],
            "members": len(info.members),
            "inversions": len(touching),
            "max_severity": _worst([inv["severity"] for inv in touching]),
        }
    return stats


def summary_label_lines(facts: dict[str, Any]) -> list[str]:
    """Label lines of a collapsed group's summary component.

    Its name, the member count, the inversions its members take part in with
    the worst severity's markers (``!! 3 inversions``), and in the drift view
    what changed among the members (``+2 ~1``).
    """
    members = facts.get("members", 0)
    lines = [str(facts.get("label", "")), f"{members} component{'' if members == 1 else 's'}"]
    count = facts.get("inversions") or 0
    if count:
        marker = {"critical": "!!!", "high": "!!", "medium": "!"}.get(facts.get("max_severity") or "", "!")
        lines.append(f"{marker} {count} inversion{'' if count == 1 else 's'}")
    changes = [
        f"{sign}{facts[status]}"
        for status, sign in (("added", "+"), ("removed", "\u2212"), ("modified", "~"))
        if facts.get(status)
    ]
    if changes:
        lines.append(" ".join(changes))
    return lines
