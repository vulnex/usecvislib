#
# VULNEX -Universal Security Visualization Library-
#
# File: grouping.py
# Author: Simon Roses Femerling
# Created: 2026-10-15
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Shared pieces of grouping and collapse, used by every module that supports it.

Which groups to collapse (``collapse`` = false / true / a list / "auto" with
``max_nodes``, a group's own ``collapsed`` setting winning), the drift status
of edges merged by a collapse, and the ``\u00d7N`` label of a merged edge. Group
membership and the collapse itself (which elements fold into a summary node)
are module-specific and live in each module's render view.
"""

import logging
from typing import Any, Optional

from .drift import ElementMark, GroupInfo

logger = logging.getLogger(__name__)

# Id prefix of a collapsed group's summary node (double underscore, like the
# kill chain's __slot_ placeholders, so it cannot clash with a sanitized user id)
SUMMARY_PREFIX = "__group_"

DEFAULT_MAX_NODES = 300


def collapse_requested(collapse: Any) -> bool:
    """Whether a ``collapse`` option asks for any collapse at all."""
    if isinstance(collapse, str):
        return collapse.strip().lower() not in ("", "none", "false", "no")
    return bool(collapse)


def groups_to_collapse(
    groups: dict[str, GroupInfo], meta: dict[str, Any], collapse: Any, max_nodes: int, node_count: int
) -> list[str]:
    """Ids of the groups to collapse, in group order.

    Args:
        groups: The groups, in drawing order.
        meta: Per-group settings by group id; a group's ``collapsed`` always wins.
        collapse: False / "none", True / "all", "auto", or group ids (a list or
            a comma-separated string).
        max_nodes: Target node count for "auto".
        node_count: Nodes drawn with no group collapsed (for "auto").
    """
    explicit = {
        gid: bool(m["collapsed"])
        for gid, m in meta.items()
        if isinstance(m, dict) and "collapsed" in m and gid in groups
    }
    chosen: set[str] = set()
    mode = collapse.strip().lower() if isinstance(collapse, str) else collapse
    if mode is True or mode in ("all", "true", "yes"):
        # A one-member group's summary would hide nothing
        chosen = {gid for gid, info in groups.items() if len(info.members) > 1}
    elif mode == "auto":
        chosen = auto_collapse(groups, explicit, max_nodes, node_count)
    elif isinstance(collapse, list | tuple) or (isinstance(collapse, str) and collapse_requested(collapse)):
        wanted = [
            str(g).strip() for g in (collapse.split(",") if isinstance(collapse, str) else collapse) if str(g).strip()
        ]
        unknown = [g for g in wanted if g not in groups]
        if unknown:
            logger.warning(f"collapse: no such group(s): {', '.join(unknown)}")
        chosen = {g for g in wanted if g in groups}
    for gid, value in explicit.items():  # a group's own setting always wins
        (chosen.add if value else chosen.discard)(gid)
    return [gid for gid in groups if gid in chosen]


def auto_collapse(groups: dict[str, GroupInfo], explicit: dict[str, bool], max_nodes: int, node_count: int) -> set[str]:
    """Collapse the largest groups first until at most ``max_nodes`` nodes are drawn."""
    drawn = node_count - sum(len(groups[g].members) - 1 for g, v in explicit.items() if v)
    chosen: set[str] = set()
    candidates = sorted(
        (g for g in groups if g not in explicit and len(groups[g].members) > 1),
        key=lambda g: (-len(groups[g].members), g),
    )
    for gid in candidates:
        if drawn <= max_nodes:
            break
        chosen.add(gid)
        drawn -= len(groups[gid].members) - 1
    if drawn > max_nodes:
        logger.warning(f"collapse='auto': {drawn} nodes remain with every group collapsed (target {max_nodes})")
    return chosen


def combined_status(statuses: list[Optional[str]]) -> Optional[str]:
    """Drift status of edges merged into one: theirs when they agree, otherwise unchanged."""
    known = [s for s in statuses if s]
    if not known:
        return None
    return known[0] if all(s == known[0] for s in known) else "unchanged"


def merged_label(mark: Optional[ElementMark], label: Optional[str] = None) -> Optional[str]:
    """Edge label: ``\u00d7N`` for N edges merged by a collapse, else the edge's own label."""
    if mark is not None and mark.count > 1:
        return f"\u00d7{mark.count}"
    return label
