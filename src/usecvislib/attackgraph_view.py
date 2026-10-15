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

from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any, Optional

# (source id, target id, kind); kind is "network", "exploit" or "structural"
EdgeKey = tuple[str, str, str]

NODE_SECTIONS = ("hosts", "vulnerabilities", "privileges", "services", "exploits")


@dataclass
class ElementMark:
    """Render-only facts about one node or edge."""

    diff: Optional[str] = None  # "added" | "removed" | "modified" | "unchanged"
    changed: list[str] = field(default_factory=list)  # changed fields of a modified element
    inferred: bool = False
    group: Optional[str] = None  # cluster the element sits in
    collapsed: Optional[dict[str, Any]] = None  # summary-node facts: member counts, worst CVSS
    count: int = 1  # edges merged into this one by a collapse


@dataclass
class GroupInfo:
    """A cluster of nodes, drawn expanded or collapsed into one summary node."""

    id: str
    label: str = ""
    color: Optional[str] = None
    members: list[str] = field(default_factory=list)
    collapsed: bool = False


@dataclass
class RenderView:
    """The sections to draw, and the marks and groups that style them."""

    data: dict[str, Any]
    groups: dict[str, GroupInfo] = field(default_factory=dict)
    nodes: dict[str, ElementMark] = field(default_factory=dict)
    edges: dict[EdgeKey, ElementMark] = field(default_factory=dict)

    def node_mark(self, node_id: str) -> Optional[ElementMark]:
        return self.nodes.get(node_id)

    def edge_mark(self, key: EdgeKey) -> Optional[ElementMark]:
        return self.edges.get(key)


def build_view(data: dict[str, Any]) -> RenderView:
    """The view of normalized attack-graph data with no render options: the data as is."""
    return RenderView(data=data)


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
