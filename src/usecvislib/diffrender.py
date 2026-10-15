#
# VULNEX -Universal Security Visualization Library-
#
# File: diffrender.py
# Author: Simon Roses Femerling
# Created: 2026-10-15
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Drift renderer: draw what changed between two versions of a visualization.

``render_diff(old, new, ...)`` merges both versions (so removed elements can
still be drawn), marks every element added / removed / modified / unchanged,
and renders the merged graph with the change shown as borders, fading and a
``+`` / ``-`` / ``~`` chip. It returns the :class:`~usecvislib.diff.DiffResult`
it computed, so one call gives the picture and the change list.

Supported: the attack graph. Other modules raise ``NotImplementedError``.
"""

import copy
import json
import logging
import os
import re
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any, Optional, Union

from .attackgraph_view import NODE_SECTIONS, _exploit_conditions, _section_items, iter_edges
from .diff import DiffResult, VisualizationDiff
from .drift import DiffMarks

logger = logging.getLogger(__name__)

# Modules render_diff() supports; filled in below the adapters (see _ADAPTERS)
SUPPORTED_TYPES: tuple[str, ...] = ()
DIFF_KEYS = ("added", "removed", "modified")

_HEX_COLOR = re.compile(r"^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$")


def resolve_diff_colors(diff_colors: Optional[dict[str, str]]) -> dict[str, str]:
    """Validate user diff colors: keys added / removed / modified, values #rgb or #rrggbb.

    Returns the colors as lowercase ``#rrggbb`` (Graphviz appends an alpha
    channel to them). Keys not given are left to the theme.

    Raises:
        ValueError: On an unknown key or a value that is not a hex color.
    """
    if not diff_colors:
        return {}
    if not isinstance(diff_colors, dict):
        raise ValueError("diff_colors must be a mapping of added / removed / modified to colors")
    unknown = sorted(set(diff_colors) - set(DIFF_KEYS))
    if unknown:
        raise ValueError(f"diff_colors: unknown key(s) {', '.join(unknown)}; use added, removed, modified")
    resolved = {}
    for key, value in diff_colors.items():
        color = str(value).strip()
        if not _HEX_COLOR.match(color):
            raise ValueError(f"diff_colors['{key}']: '{value}' is not a #rrggbb or #rgb color")
        if len(color) == 4:
            color = "#" + "".join(c * 2 for c in color[1:])
        resolved[key] = color.lower()
    return resolved


def parse_diff_colors(text: str) -> dict[str, str]:
    """Parse ``added=#e8590c,modified=#0ea5e9`` (CLI form) and validate it."""
    colors = {}
    for item in filter(None, (part.strip() for part in text.split(","))):
        key, sep, value = item.partition("=")
        if not sep:
            raise ValueError(f"diff colors: expected key=#color, got '{item}'")
        colors[key.strip()] = value.strip()
    return resolve_diff_colors(colors)


def render_diff(
    old: Union[str, Any],
    new: Union[str, Any],
    visualization_type: str = "attack_graph",
    output: str = "drift",
    format: str = "png",
    render_engine: str = "graphviz",
    style: str = "",
    diff_colors: Optional[dict[str, str]] = None,
    ignore_paths: Optional[list[str]] = None,
    show_unchanged: bool = True,
    group_by: Optional[str] = None,
    collapse: Any = None,
    max_nodes: Optional[int] = None,
) -> DiffResult:
    """Render the drift between two versions and return the computed diff.

    Args:
        old: The earlier version: a file path or a loaded visualization instance.
        new: The later version, same forms.
        visualization_type: Only "attack_graph" for now.
        output: Output path without extension.
        format: png, svg or pdf.
        render_engine: "graphviz" (default) or "svg".
        style: Style preset of the module ("" for the engine default).
        diff_colors: Override any of {"added", "removed", "modified"} (hex colors).
        ignore_paths: Path prefixes to ignore, as in ``compare_files()``.
        show_unchanged: False draws only changed elements and their direct neighbours.
        group_by, collapse, max_nodes: Grouping/collapse of the merged graph.

    Returns:
        The DiffResult between the two versions, computed on the same
        normalized data the picture shows (exploit pre/postcondition lists
        compare as sets; network edges are identified by their endpoints).

    Raises:
        NotImplementedError: For an unsupported visualization type.
        ValueError: For invalid diff_colors.
    """
    adapter = _ADAPTERS.get(visualization_type)
    if adapter is None:
        raise NotImplementedError(
            f"render_diff() supports {', '.join(SUPPORTED_TYPES)}; '{visualization_type}' is not supported yet"
        )
    colors = resolve_diff_colors(diff_colors)
    ignore = list(ignore_paths or [])

    old_data = adapter.normalize(adapter.load(old))
    new_data = adapter.normalize(adapter.load(new))
    result = VisualizationDiff(
        SimpleNamespace(inputdata=old_data, _loaded=True, inputfile=_source(old)),
        SimpleNamespace(inputdata=new_data, _loaded=True, inputfile=_source(new)),
    ).compare(ignore_paths=ignore)
    if adapter.metadata is not None:
        result.metadata.update(adapter.metadata(old_data, new_data))
    merged, marks = adapter.merge(old_data, new_data, ignore)

    fd, merged_path = tempfile.mkstemp(suffix=".json", prefix="usecvislib_drift_")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(merged, f)
        viz = adapter.make(
            merged_path,
            output,
            format=format,
            styleid=style,
            render_engine=render_engine,
            group_by=group_by,
            collapse=collapse,
            max_nodes=max_nodes,
        )
        viz.diff_marks = marks
        viz.diff_colors = colors
        viz.show_unchanged = show_unchanged
        viz.build()
    finally:
        os.unlink(merged_path)
    return result


@dataclass(frozen=True)
class _DriftAdapter:
    """What render_diff() needs from a module.

    load: a version (path or instance) -> its loaded data
    normalize: data -> canonical data for comparing (a copy)
    merge: (old, new, ignore_paths) -> (merged data, DiffMarks)
    make: (merged file, output, **render options) -> a visualization instance
        with ``diff_marks`` / ``diff_colors`` / ``show_unchanged`` attributes
    metadata: optional (old, new) -> extra DiffResult metadata
    """

    load: Callable[[Any], dict[str, Any]]
    normalize: Callable[[dict[str, Any]], dict[str, Any]]
    merge: Callable[[dict[str, Any], dict[str, Any], Optional[list[str]]], tuple[dict[str, Any], DiffMarks]]
    make: Callable[..., Any]
    metadata: Optional[Callable[[dict[str, Any], dict[str, Any]], dict[str, Any]]] = None


def _make_attack_graph(path: str, output: str, **options: Any) -> Any:
    from .attackgraphs import AttackGraphs

    return AttackGraphs(path, output, **options)


def _attack_graph_data(version: Union[str, Any]) -> dict[str, Any]:
    """Normalized attack-graph data of a file path or a (loaded or not) AttackGraphs instance."""
    if isinstance(version, str | os.PathLike):
        from .attackgraphs import AttackGraphs

        version = AttackGraphs(str(version), "unused", validate_paths=False)
    if not getattr(version, "_loaded", False):
        version.load()
    version._normalize_data()
    return version.inputdata


def _source(version: Union[str, Any]) -> Optional[str]:
    return str(version) if isinstance(version, str | os.PathLike) else getattr(version, "inputfile", None)


def normalize_attack_graph(data: dict[str, Any]) -> dict[str, Any]:
    """A copy of attack-graph data in one canonical form, for comparing two versions.

    - Exploit pre/postconditions become sorted lists (``preconditions`` /
      ``postconditions``), so reordering or switching forms is not drift.
    - Legacy ``network`` lists become network edges, and every network edge is
      keyed ``"from->to"`` (by its endpoints, not its entry id).
    """
    data = copy.deepcopy(data)
    for section in NODE_SECTIONS:
        data[section] = dict(_section_items(data.get(section, {})))
    for exploit_id, exploit in data["exploits"].items():
        if isinstance(exploit, dict):
            pres = sorted(set(map(str, _exploit_conditions(exploit, "precondition"))))
            posts = sorted(set(map(str, _exploit_conditions(exploit, "postcondition"))))
            exploit.pop("precondition", None)
            exploit.pop("postcondition", None)
            exploit["preconditions"], exploit["postconditions"] = pres, posts
            data["exploits"][exploit_id] = exploit
    edges: dict[str, dict[str, Any]] = {}
    for _, edge in _section_items(data.get("network_edges", {})):
        if isinstance(edge, dict) and edge.get("from") and edge.get("to"):
            edges.setdefault(f"{edge['from']}->{edge['to']}", edge)
    legacy = data.get("network", {})
    if isinstance(legacy, dict):
        for source, targets in legacy.items():
            for target in targets if isinstance(targets, list) else []:
                edges.setdefault(f"{source}->{target}", {"from": source, "to": target})
    data["network_edges"] = edges
    data["network"] = {}
    return data


def merge_attack_graphs(
    old: dict[str, Any], new: dict[str, Any], ignore_paths: Optional[list[str]] = None
) -> tuple[dict[str, Any], DiffMarks]:
    """Union of two normalized attack graphs, and the change status of each element and edge.

    Elements are drawn from the new version, removed ones from the old. A
    modified exploit keeps its old and new pre/postconditions, so removed
    edges are still drawn. Paths matching ``ignore_paths`` count as unchanged.
    """
    ignore = list(ignore_paths or [])
    comparer = VisualizationDiff(
        SimpleNamespace(inputdata={}, _loaded=True), SimpleNamespace(inputdata={}, _loaded=True)
    )

    def ignored(path: str) -> bool:
        return any(path.startswith(prefix) for prefix in ignore)

    merged: dict[str, Any] = {key: value for key, value in new.items() if key not in (*NODE_SECTIONS, "network_edges")}
    merged.setdefault("graph", old.get("graph", {"name": "Attack Graph"}))
    marks = DiffMarks()
    for section in NODE_SECTIONS:
        section_old, section_new = old.get(section, {}), new.get(section, {})
        out: dict[str, Any] = {}
        for element_id in [*section_new, *(i for i in section_old if i not in section_new)]:
            path = f"{section}.{element_id}"
            in_old, in_new = element_id in section_old, element_id in section_new
            element = copy.deepcopy(section_new[element_id] if in_new else section_old[element_id])
            changed: list[str] = []
            if ignored(path):
                status = "unchanged"
            elif not in_old:
                status = "added"
            elif not in_new:
                status = "removed"
            else:
                old_el, new_el = section_old[element_id], section_new[element_id]
                changes = [
                    c
                    for c in comparer._compare_dicts(
                        old_el if isinstance(old_el, dict) else {"value": old_el},
                        new_el if isinstance(new_el, dict) else {"value": new_el},
                        path,
                    )
                    if not ignored(c.path)
                ]
                changed = list(dict.fromkeys(re.split(r"[.\[]", c.path[len(path) + 1 :])[0] for c in changes))
                status = "modified" if changes else "unchanged"
                if section == "exploits" and isinstance(element, dict) and isinstance(old_el, dict):
                    for key in ("preconditions", "postconditions"):
                        kept = list(element.get(key, []))
                        element[key] = kept + [e for e in old_el.get(key, []) if e not in kept]
            out[element_id] = element
            marks.nodes[element_id] = (status, changed)
        merged[section] = out

    edges_new, edges_old = new.get("network_edges", {}), old.get("network_edges", {})
    merged["network_edges"] = {
        **edges_new,
        **{key: edge for key, edge in edges_old.items() if key not in edges_new},
    }
    merged["network"] = {}

    keys_old, keys_new = set(iter_edges(old)), set(iter_edges(new))
    for key in iter_edges(merged):
        if _edge_ignored(key, merged, ignored) or (key in keys_old and key in keys_new):
            marks.edges[key] = "unchanged"
        else:
            marks.edges[key] = "added" if key in keys_new else "removed"
    return merged, marks


def _edge_ignored(key: tuple[str, str, str], merged: dict[str, Any], ignored) -> bool:
    """Whether an ignore path covers the section an edge comes from."""
    src, dst, kind = key
    if kind == "network":
        return ignored("network_edges") or ignored(f"network_edges.{src}->{dst}")
    if kind == "exploit":
        exploit_id = dst if dst in merged.get("exploits", {}) else src
        return ignored(f"exploits.{exploit_id}")
    section = "vulnerabilities" if dst in merged.get("vulnerabilities", {}) else "services"
    return ignored(f"{section}.{dst}")


_ADAPTERS: dict[str, _DriftAdapter] = {
    "attack_graph": _DriftAdapter(
        load=_attack_graph_data,
        normalize=normalize_attack_graph,
        merge=merge_attack_graphs,
        make=_make_attack_graph,
    ),
}
SUPPORTED_TYPES = tuple(_ADAPTERS)
