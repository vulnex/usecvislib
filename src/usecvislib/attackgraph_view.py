#
# VULNEX -Universal Security Visualization Library-
#
# File: attackgraph_view.py
# Author: Simon Roses Femerling
# Created: 2026-10-15
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Render view for the attack graph: what both render engines draw.

The Graphviz path (``AttackGraphs._render_impl``) and the SVG painter
(``svgengine/painters/attackgraphs.py``) both draw from a :class:`RenderView`
instead of walking ``inputdata`` themselves. Features that change *what* is
drawn (grouping and collapse, the drift renderer) and per-element styling
(inferred elements) are built here once, as data plus marks, rather than in
each engine.

Marks are kept beside the data, never inside it: the Graphviz path passes an
element's unknown fields straight through as Graphviz attributes, so private
keys in the data would leak into the DOT output.

The view only changes the picture. Path analysis, centrality and statistics
keep using the full ``inputdata`` and the NetworkX graph built at load time.
"""

import ipaddress
import logging
import re
from collections.abc import Iterator
from typing import Any, Optional

# Shared drift / render marks, re-exported (other modules import them from here).
# An attack graph's edge kinds are "network", "exploit" and "structural".
from .drift import DiffMarks, EdgeKey, ElementMark, GroupInfo, RenderView
from .grouping import (
    DEFAULT_MAX_NODES,
    SUMMARY_PREFIX,
    collapse_requested,
    combined_status,
    groups_to_collapse,
    merged_label,
)

logger = logging.getLogger(__name__)

__all__ = [
    "DEFAULT_MAX_NODES",
    "NODE_SECTIONS",
    "SUMMARY_PREFIX",
    "DiffMarks",
    "EdgeKey",
    "ElementMark",
    "GroupInfo",
    "RenderView",
    "assign_groups",
    "build_view",
    "group_stats",
    "iter_edges",
    "merged_label",
    "node_ids",
    "summary_label_lines",
]

NODE_SECTIONS = ("hosts", "vulnerabilities", "privileges", "services", "exploits")

# group_by = "ip/24" (IPv4, /8-/32) or "ip6/64" (IPv6, /16-/128)
_IP_GROUPING = re.compile(r"^ip(6)?/(\d{1,3})$")


def build_view(
    data: dict[str, Any],
    group_by: Optional[str] = None,
    collapse: Any = None,
    max_nodes: Optional[int] = None,
    diff: Optional[DiffMarks] = None,
    show_unchanged: bool = True,
) -> RenderView:
    """The view of normalized attack-graph data under the render options.

    Each option falls back to the same key in the ``[graph]`` section. With
    no grouping the view is the data as is (no copy), so output is unchanged.

    Args:
        data: Normalized attack-graph sections (dicts keyed by id).
        group_by: Host field to group on, or ``"ip/N"`` / ``"ip6/N"`` to group
            by network. A host's own ``group`` field always wins.
        collapse: ``False``/``"none"`` (default), ``True``/``"all"``, ``"auto"``,
            or group ids (a list, or a comma-separated string).
        max_nodes: Target node count for ``collapse="auto"`` (default 300).
        diff: Change status of each node and edge (drift view, see ``diffrender``).
        show_unchanged: With ``diff``, False draws only changed elements and
            their direct neighbours.

    Raises:
        ValueError: If ``group_by`` is a malformed ``ip/N`` / ``ip6/N`` rule.
    """
    graph = data.get("graph") if isinstance(data.get("graph"), dict) else {}
    group_by = group_by if group_by is not None else graph.get("group_by")
    collapse = collapse if collapse is not None else graph.get("collapse")
    max_nodes = int(max_nodes if max_nodes is not None else graph.get("max_nodes", DEFAULT_MAX_NODES))

    view = RenderView(data=data)
    if diff is not None:
        for node_id, (status, changed) in diff.nodes.items():
            mark = view.nodes.setdefault(node_id, ElementMark())
            mark.diff, mark.changed = status, list(changed)
        for key, status in diff.edges.items():
            view.edges.setdefault(key, ElementMark()).diff = status

    node_group = assign_groups(data, group_by)
    if not node_group:
        if collapse_requested(collapse):
            logger.warning("collapse needs groups (group_by or host 'group' fields); ignored")
    else:
        meta = data.get("groups") if isinstance(data.get("groups"), dict) else {}
        for node_id, group_id in node_group.items():
            info = view.groups.get(group_id)
            if info is None:
                group_meta = meta.get(group_id) if isinstance(meta.get(group_id), dict) else {}
                label = str(group_meta.get("label") or group_id)
                info = GroupInfo(id=group_id, label=label, color=group_meta.get("color"))
                view.groups[group_id] = info
            info.members.append(node_id)
            view.nodes.setdefault(node_id, ElementMark()).group = group_id

        collapsed = groups_to_collapse(view.groups, meta, collapse, max_nodes, len(node_ids(data)))
        if collapsed:
            for group_id in collapsed:
                view.groups[group_id].collapsed = True
            _collapse(view, collapsed)

    if diff is not None and not show_unchanged:
        _changes_only(view)
    return _mark_inferred(view)


def _changes_only(view: RenderView) -> None:
    """Keep changed elements, their direct neighbours, and the hosts of what is kept.

    With nothing changed, everything is kept (an empty picture would only fail to render).
    """
    data = view.data
    drawn = node_ids(data)
    edges = list(iter_edges(data))
    changed = {i for i in drawn if (m := view.nodes.get(i)) is not None and m.diff not in (None, "unchanged")}
    for src, dst, kind in edges:
        mark = view.edges.get((src, dst, kind))
        if mark is not None and mark.diff in ("added", "removed"):
            changed.update((src, dst))
    if not changed:
        logger.info("No changes: drawing the whole graph")
        return
    keep = set(changed)
    for src, dst, _ in edges:
        if src in changed:
            keep.add(dst)
        if dst in changed:
            keep.add(src)
    for section, host_keys in (
        ("vulnerabilities", ("host", "affected_host")),
        ("services", ("host",)),
        ("privileges", ("host",)),
    ):
        for element_id, element in _section_items(data.get(section, {})):
            if element_id in keep and isinstance(element, dict):
                keep.update(element.get(k) for k in host_keys if element.get(k) in drawn)
    keep &= drawn

    new = dict(data)
    for section in ("hosts", "vulnerabilities", "privileges", "services"):
        new[section] = {i: e for i, e in _section_items(data.get(section, {})) if i in keep}
    exploits: dict[str, Any] = {}
    for exploit_id, exploit in _section_items(data.get("exploits", {})):
        if exploit_id not in keep:
            continue
        if isinstance(exploit, dict):
            exploit = {k: v for k, v in exploit.items() if k not in ("precondition", "postcondition")}
            for key in ("precondition", "postcondition"):
                exploit[f"{key}s"] = [e for e in _exploit_conditions(data["exploits"][exploit_id], key) if e in keep]
        exploits[exploit_id] = exploit
    new["exploits"] = exploits
    new["network_edges"] = {
        i: e
        for i, e in _section_items(data.get("network_edges", {}))
        if isinstance(e, dict) and e.get("from") in keep and e.get("to") in keep
    }
    legacy = data.get("network", {})
    new["network"] = (
        {s: [t for t in ts if t in keep] for s, ts in legacy.items() if s in keep and isinstance(ts, list)}
        if isinstance(legacy, dict)
        else {}
    )
    view.data = new
    # Groups list only what is still drawn (Graphviz would otherwise create a bare
    # node for every member a cluster re-mentions)
    for gid in list(view.groups):
        info = view.groups[gid]
        info.members = [m for m in info.members if m in keep]
        if not info.members and not info.collapsed:
            del view.groups[gid]


def _mark_inferred(view: RenderView) -> RenderView:
    """Mark inferred exploits (node and pre/postcondition edges) and inferred network edges.

    Runs on the data the view draws, so after a collapse it sees re-pointed
    edges; a merged edge is inferred only if every edge merged into it was.
    """
    from . import utils

    for exploit_id, exploit in _section_items(view.data.get("exploits", {})):
        if not utils.inferred_state(exploit)[0]:
            continue
        view.nodes.setdefault(exploit_id, ElementMark()).inferred = True
        for pre in _exploit_conditions(exploit, "precondition"):
            view.edges.setdefault((pre, exploit_id, "exploit"), ElementMark()).inferred = True
        for post in _exploit_conditions(exploit, "postcondition"):
            view.edges.setdefault((exploit_id, post, "exploit"), ElementMark()).inferred = True
    for _, edge in _section_items(view.data.get("network_edges", {})):
        if isinstance(edge, dict) and edge.get("from") and edge.get("to") and utils.inferred_state(edge)[0]:
            view.edges.setdefault((edge["from"], edge["to"], "network"), ElementMark()).inferred = True
    return view


def assign_groups(data: dict[str, Any], group_by: Optional[str]) -> dict[str, str]:
    """Group of every grouped element, in section order (hosts first).

    Hosts take their ``group`` field, else the ``group_by`` value; vulnerabilities,
    services and privileges follow their host; an exploit joins a group only when
    all of its pre/postcondition endpoints are in that one group.
    """
    host_group = _host_groups(data, group_by)
    if not host_group:
        return {}
    node_group: dict[str, str] = dict(host_group)
    for section, host_keys in (
        ("vulnerabilities", ("host", "affected_host")),
        ("privileges", ("host",)),
        ("services", ("host",)),
    ):
        for element_id, element in _section_items(data.get(section, {})):
            if not isinstance(element, dict):
                continue
            host = next((element.get(k) for k in host_keys if element.get(k)), None)
            if host in host_group:
                node_group[element_id] = host_group[host]
    for exploit_id, exploit in _section_items(data.get("exploits", {})):
        if not isinstance(exploit, dict):
            continue
        endpoints = _exploit_conditions(exploit, "precondition") + _exploit_conditions(exploit, "postcondition")
        groups = {node_group.get(e) for e in endpoints}
        if endpoints and len(groups) == 1 and None not in groups:
            node_group[exploit_id] = groups.pop()
    return node_group


def _host_groups(data: dict[str, Any], group_by: Optional[str]) -> dict[str, str]:
    """host id -> group id, for hosts that have one."""
    ip_rule = _parse_ip_rule(group_by) if group_by else None
    result: dict[str, str] = {}
    for host_id, host in _section_items(data.get("hosts", {})):
        if not isinstance(host, dict):
            continue
        group = host.get("group")
        if not group and group_by:
            group = _ip_network(host.get("ip"), *ip_rule) if ip_rule else host.get(group_by)
        if group not in (None, "") and not isinstance(group, dict | list):
            result[host_id] = str(group)
    return result


def _parse_ip_rule(group_by: str) -> Optional[tuple[int, int]]:
    """(IP version, prefix) for an ``ip/N`` / ``ip6/N`` rule, None for a plain field name."""
    match = _IP_GROUPING.match(str(group_by).strip())
    if not match:
        if str(group_by).strip().lower().startswith(("ip/", "ip6/")):
            raise ValueError(f"group_by '{group_by}': expected ip/N (8-32) or ip6/N (16-128)")
        return None
    version, prefix = (6, int(match.group(2))) if match.group(1) else (4, int(match.group(2)))
    low, high = (16, 128) if version == 6 else (8, 32)
    if not low <= prefix <= high:
        raise ValueError(f"group_by '{group_by}': the prefix must be {low}-{high} for IPv{version}")
    return version, prefix


def _ip_network(value: Any, version: int, prefix: int) -> Optional[str]:
    """The /prefix network of an address of the given IP version, or None."""
    try:
        address = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None
    if address.version != version:
        return None
    return str(ipaddress.ip_network(f"{address}/{prefix}", strict=False))


def _collapse(view: RenderView, collapsed: list[str]) -> None:
    """Replace each collapsed group's members by one summary node; re-point and merge edges.

    Builds a new ``view.data`` (the input data is not modified).
    """
    from .cvss_unified import get_cvss_score_unified

    data = view.data
    summary_of = {member: SUMMARY_PREFIX + gid for gid in collapsed for member in view.groups[gid].members}

    # Summary facts per group
    for gid in collapsed:
        info = view.groups[gid]
        counts = dict.fromkeys(NODE_SECTIONS, 0)
        max_cvss: Optional[float] = None
        for section in NODE_SECTIONS:
            for element_id, element in _section_items(data.get(section, {})):
                if summary_of.get(element_id) != SUMMARY_PREFIX + gid:
                    continue
                counts[section] += 1
                if section == "vulnerabilities" and isinstance(element, dict):
                    score, _ = get_cvss_score_unified(element.get("cvss"), element.get("cvss_vector"))
                    if score is not None and (max_cvss is None or score > max_cvss):
                        max_cvss = score
        facts = {**counts, "members": len(info.members), "max_cvss": max_cvss, "label": info.label}
        statuses = [m.diff for member in info.members if (m := view.nodes.get(member)) is not None and m.diff]
        summary_diff = None
        if statuses:
            for status in ("added", "removed", "modified"):
                facts[status] = statuses.count(status)
            summary_diff = "modified" if any(s != "unchanged" for s in statuses) else "unchanged"
        view.nodes[SUMMARY_PREFIX + gid] = ElementMark(group=gid, collapsed=facts, diff=summary_diff)

    new: dict[str, Any] = {
        key: value for key, value in data.items() if key not in (*NODE_SECTIONS, "network_edges", "network")
    }

    # Hosts: each summary node takes the place of its group's first host
    hosts: dict[str, Any] = {}
    for host_id, host in _section_items(data.get("hosts", {})):
        summary = summary_of.get(host_id)
        if summary is None:
            hosts[host_id] = host
        elif summary not in hosts:
            hosts[summary] = {"label": view.nodes[summary].collapsed["label"]}
    new["hosts"] = hosts

    for section in ("vulnerabilities", "privileges", "services"):
        new[section] = {i: e for i, e in _section_items(data.get(section, {})) if i not in summary_of}

    def repoint(endpoint: Any) -> Any:
        return summary_of.get(endpoint, endpoint)

    # Exploits: those inside a collapsed group are folded; the rest get re-pointed endpoints
    exploits: dict[str, Any] = {}
    for exploit_id, exploit in _section_items(data.get("exploits", {})):
        if exploit_id in summary_of:
            continue
        if not isinstance(exploit, dict):
            exploits[exploit_id] = exploit
            continue
        updated = {k: v for k, v in exploit.items() if k not in ("precondition", "postcondition")}
        for key in ("precondition", "postcondition"):
            merged: dict[Any, list[Optional[str]]] = {}
            for endpoint in _exploit_conditions(exploit, key):
                original = (endpoint, exploit_id) if key == "precondition" else (exploit_id, endpoint)
                old_mark = view.edges.get((*original, "exploit"))
                merged.setdefault(repoint(endpoint), []).append(old_mark.diff if old_mark else None)
            updated[f"{key}s"] = list(merged)
            for target, statuses in merged.items():
                edge = (target, exploit_id) if key == "precondition" else (exploit_id, target)
                status = combined_status(statuses)
                if len(statuses) > 1 or status is not None:
                    mark = view.edges.setdefault((*edge, "exploit"), ElementMark())
                    mark.count, mark.diff = len(statuses), status
        exploits[exploit_id] = updated
    new["exploits"] = exploits

    # Network edges (the legacy lists folded in, in drawing order): drop edges inside one
    # collapsed group, re-point the rest, merge duplicates
    from . import utils

    network: dict[tuple[Any, Any], dict[str, Any]] = {}
    edge_counts: dict[tuple[Any, Any], int] = {}
    all_inferred: dict[tuple[Any, Any], bool] = {}
    edge_statuses: dict[tuple[Any, Any], list[Optional[str]]] = {}
    originals = [e for _, e in _section_items(data.get("network_edges", {})) if isinstance(e, dict)]
    legacy = data.get("network", {})
    if isinstance(legacy, dict):
        originals += [{"from": s, "to": t} for s, ts in legacy.items() if isinstance(ts, list) for t in ts]
    for edge in originals:
        src, dst = edge.get("from"), edge.get("to")
        if not (src and dst):
            continue
        if src in summary_of and summary_of[src] == summary_of.get(dst):
            continue
        key = (repoint(src), repoint(dst))
        edge_counts[key] = edge_counts.get(key, 0) + 1
        all_inferred[key] = all_inferred.get(key, True) and utils.inferred_state(edge)[0]
        old_mark = view.edges.get((src, dst, "network"))
        edge_statuses.setdefault(key, []).append(old_mark.diff if old_mark else None)
        network.setdefault(key, {**edge, "from": key[0], "to": key[1]})
    new_edges: dict[str, Any] = {}
    for i, (key, edge) in enumerate(network.items()):
        status = combined_status(edge_statuses[key])
        if status is not None:
            view.edges.setdefault((key[0], key[1], "network"), ElementMark()).diff = status
        if edge_counts[key] > 1:
            view.edges.setdefault((key[0], key[1], "network"), ElementMark()).count = edge_counts[key]
            # Merged: inferred only if every merged edge was (one observed edge makes it observed)
            edge = {k: v for k, v in edge.items() if k not in ("inferred", "confidence")}
            if all_inferred[key]:
                edge["inferred"] = True
        new_edges[f"edge_{i}"] = edge
    new["network_edges"] = new_edges
    new["network"] = {}

    view.data = new


def summary_label_lines(mark: ElementMark) -> list[str]:
    """Label lines of a collapsed group's summary node: its name, then member counts."""
    facts = mark.collapsed or {}
    parts = []
    for section, one, many in (
        ("hosts", "host", "hosts"),
        ("vulnerabilities", "vuln", "vulns"),
        ("services", "service", "services"),
    ):
        count = facts.get(section) or 0
        if count:
            parts.append(f"{count} {one if count == 1 else many}")
    name = str(facts.get("label", ""))
    lines = [name, " \u00b7 ".join(parts)] if parts else [name]
    # Drift view: what changed among the members
    changes = [
        f"{sign}{facts[status]}"
        for status, sign in (("added", "+"), ("removed", "\u2212"), ("modified", "~"))
        if facts.get(status)
    ]
    if changes:
        lines.append(" ".join(changes))
    return lines


def group_stats(data: dict[str, Any], group_by: Optional[str] = None) -> dict[str, dict[str, Any]]:
    """Per-group counts for statistics: hosts, vulnerabilities and the highest CVSS."""
    from .cvss_unified import get_cvss_score_unified

    graph = data.get("graph") if isinstance(data.get("graph"), dict) else {}
    node_group = assign_groups(data, group_by if group_by is not None else graph.get("group_by"))
    stats: dict[str, dict[str, Any]] = {}
    for section in ("hosts", "vulnerabilities"):
        for element_id, element in _section_items(data.get(section, {})):
            gid = node_group.get(element_id)
            if gid is None:
                continue
            entry = stats.setdefault(gid, {"hosts": 0, "vulnerabilities": 0, "max_cvss": None})
            entry[section] += 1
            if section == "vulnerabilities" and isinstance(element, dict):
                score, _ = get_cvss_score_unified(element.get("cvss"), element.get("cvss_vector"))
                if score is not None and (entry["max_cvss"] is None or score > entry["max_cvss"]):
                    entry["max_cvss"] = score
    return stats


def _section_items(section: Any) -> list[tuple[Any, Any]]:
    """(id, element) pairs of a section that may still be a list (as the SVG painter accepts)."""
    if isinstance(section, dict):
        return list(section.items())
    if isinstance(section, list):
        return [(item.get("id", f"item_{i}"), item) for i, item in enumerate(section) if isinstance(item, dict)]
    return []


def _exploit_conditions(exploit: dict[str, Any], key: str) -> list[Any]:
    """An exploit's pre- or postconditions: the list form, else the singular field."""
    values = exploit.get(f"{key}s", [])
    if not values and exploit.get(key):
        values = [exploit.get(key)]
    return list(values or [])


def iter_edges(data: dict[str, Any]) -> Iterator[EdgeKey]:
    """Every edge the engines draw, in their drawing order.

    Network edges (explicit, then the legacy ``network`` lists), exploit
    pre/postcondition edges, then the structural host -> vulnerability and
    host -> service links. Edges to ids that no section defines are included:
    the SVG painter skips them, the Graphviz path draws them (Graphviz then
    creates a bare node), and the view leaves that difference alone.
    """
    for _, edge in _section_items(data.get("network_edges", {})):
        if isinstance(edge, dict) and edge.get("from") and edge.get("to"):
            yield (edge["from"], edge["to"], "network")

    network = data.get("network", {})
    if isinstance(network, dict):
        for source, targets in network.items():
            if isinstance(targets, list):
                for target in targets:
                    yield (source, target, "network")

    for exploit_id, exploit in _section_items(data.get("exploits", {})):
        if not isinstance(exploit, dict):
            continue
        for pre in _exploit_conditions(exploit, "precondition"):
            yield (pre, exploit_id, "exploit")
        for post in _exploit_conditions(exploit, "postcondition"):
            yield (exploit_id, post, "exploit")

    for vuln_id, vuln in _section_items(data.get("vulnerabilities", {})):
        host = (vuln.get("host") or vuln.get("affected_host")) if isinstance(vuln, dict) else None
        if host:
            yield (host, vuln_id, "structural")

    for svc_id, svc in _section_items(data.get("services", {})):
        if isinstance(svc, dict) and svc.get("host"):
            yield (svc["host"], svc_id, "structural")


def node_ids(data: dict[str, Any]) -> set[str]:
    """Ids of every element the engines draw as a node."""
    return {node_id for section in NODE_SECTIONS for node_id, _ in _section_items(data.get(section, {}))}
