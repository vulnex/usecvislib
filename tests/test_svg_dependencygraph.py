#
# VULNEX -Universal Security Visualization Library-
#
# File: test_svg_dependencygraph.py
# Author: Simon Roses Femerling
# Created: 2026-09-01
# Last Modified: 2026-09-01
# Version: 0.5.0
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Tests for the Dependency Graph SVG painter (Phase 3, mode 8).

Dependency graphs are general graphs: the SVG painter places nodes and routes
edges with the ``GraphvizJsonLayout`` oracle, so the render tests require the
system Graphviz ``dot`` binary and are skipped when it is absent (the host dev
machine lacks it; the container has it). Engine guards and the CLI dot-format
rejection do not render and run everywhere.

Exact SVG bytes are NOT asserted (Graphviz coordinates drift across ``dot``
versions). Assertions target the interactivity contract, node/edge counts, and
group / external / circular / SLOC semantics.
"""

import glob
import json
import shutil
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from usecvislib.dependencygraph import DependencyGraph
from usecvislib.svgengine.scene import StyleEngineMismatchError

TESTS_DIR = Path(__file__).parent
TEMPLATE_DIR = TESTS_DIR.parent / "templates" / "architecture"
FIXTURE = str(TEMPLATE_DIR / "dependency-graph-example.json")  # internal+external, groups
TEMPLATES = sorted(glob.glob(str(TEMPLATE_DIR / "dependency*")))
SVG_PRESETS = ["sv_default", "sv_dark", "sv_security", "sv_corporate", "sv_minimal"]
SVG_NS = "{http://www.w3.org/2000/svg}"

DOT_AVAILABLE = shutil.which("dot") is not None
requires_dot = pytest.mark.skipif(
    not DOT_AVAILABLE, reason="Graphviz 'dot' binary required for general-graph SVG layout"
)


def _render(inputfile: str, tmp_path, styleid: str = "", name: str = "out") -> str:
    dg = DependencyGraph(inputfile, str(tmp_path / name), format="svg", styleid=styleid, render_engine="svg")
    dg.build()
    return (tmp_path / f"{name}.svg").read_text(encoding="utf-8")


def _write(tmp_path, data: dict, name: str = "in.json") -> str:
    path = tmp_path / name
    path.write_text(json.dumps(data), encoding="utf-8")
    return str(path)


def _loaded(inputfile: str) -> DependencyGraph:
    dg = DependencyGraph(inputfile, "unused")
    dg.load()
    return dg


def _nodes(root):
    return [g for g in root.iter(f"{SVG_NS}g") if "usv-node" in g.get("class", "").split()]


def _edges(root):
    return [g for g in root.iter(f"{SVG_NS}g") if "usv-edge" in g.get("class", "").split()]


def _classes_with_prefix(root, prefix):
    return {
        cls
        for g in root.iter(f"{SVG_NS}g")
        for cls in g.get("class", "").split()
        if cls.startswith(prefix)
    }


# A crafted graph exercising every semantic the template does not: an explicit
# `external` boolean, a parsed circular cycle (list-of-lists form), and the
# three declared weights.
_CRAFTED = {
    "title": "Crafted",
    "modules": [
        {"id": "a", "name": "pkg.a", "group": "core", "sloc": 1000},
        {"id": "b", "name": "pkg.b", "group": "utils", "sloc": 200},
        {"id": "c", "name": "pkg.c", "sloc": 40},  # ungrouped
        {"id": "np", "name": "numpy", "external": True, "version": "1.26"},
    ],
    "dependencies": [
        {"from": "a", "to": "b", "type": "import", "weight": "heavy"},
        {"from": "b", "to": "a", "type": "runtime", "weight": "light"},
        {"from": "a", "to": "np", "type": "framework", "weight": "medium"},
        {"from": "c", "to": "b", "type": "import", "weight": "medium"},
    ],
    "circular": [["a", "b"]],
}


@requires_dot
class TestPresets:
    @pytest.mark.parametrize("preset", SVG_PRESETS)
    def test_fixture_renders_in_preset(self, tmp_path, preset):
        root = ET.fromstring(_render(FIXTURE, tmp_path, styleid=preset, name=preset))
        assert root.get("data-usv-theme") == preset
        assert root.get("data-usv-module") == "dependencygraph"
        assert root.get("data-usv-engine") == "svg"


@requires_dot
class TestTemplates:
    @pytest.mark.parametrize("template", TEMPLATES, ids=[Path(t).stem for t in TEMPLATES])
    def test_template_renders_unmodified(self, tmp_path, template):
        root = ET.fromstring(_render(template, tmp_path, name=Path(template).stem))
        assert _nodes(root), "every dependency-graph template has at least one node"


@requires_dot
class TestInteractivityContract:
    def test_node_count_matches_data(self, tmp_path):
        root = ET.fromstring(_render(FIXTURE, tmp_path))
        assert len(_nodes(root)) == len(_loaded(FIXTURE)._modules)

    def test_edge_count_matches_data(self, tmp_path):
        root = ET.fromstring(_render(FIXTURE, tmp_path))
        assert len(_edges(root)) == len(_loaded(FIXTURE)._dependencies)

    def test_nodes_carry_contract(self, tmp_path):
        root = ET.fromstring(_render(FIXTURE, tmp_path))
        nodes = _nodes(root)
        assert nodes
        for g in nodes:
            assert g.get("data-node-id"), "every node needs data-node-id"
            assert g.get("data-label"), "every node needs data-label"
            assert g.get("data-kind"), "every node needs data-kind"

    def test_node_kind_classes_present(self, tmp_path):
        root = ET.fromstring(_render(FIXTURE, tmp_path))
        kinds = {c.removeprefix("usv-node--") for c in _classes_with_prefix(root, "usv-node--")}
        # template mixes internal modules and external deps
        assert {"module", "external"} <= kinds

    def test_edges_carry_contract(self, tmp_path):
        root = ET.fromstring(_render(FIXTURE, tmp_path))
        edges = _edges(root)
        assert edges
        for g in edges:
            assert g.get("data-from") and g.get("data-to")

    def test_no_active_content(self, tmp_path):
        content = _render(FIXTURE, tmp_path)
        assert "<script" not in content
        assert "foreignObject" not in content
        assert "onclick" not in content and "onload" not in content
        assert "url(http" not in content
        assert "@import" not in content


@requires_dot
class TestSemantics:
    def test_circular_edges_labelled(self, tmp_path):
        root = ET.fromstring(_render(_write(tmp_path, _CRAFTED), tmp_path, name="crafted"))
        edge_kinds = {c.removeprefix("usv-edge--") for c in _classes_with_prefix(root, "usv-edge--")}
        assert "circular" in edge_kinds and "dependency" in edge_kinds
        # both directions of the a<->b cycle are flagged
        circular = [
            g for g in _edges(root) if "usv-edge--circular" in g.get("class", "").split()
        ]
        assert len(circular) == 2
        text = _render(_write(tmp_path, _CRAFTED, "c2.json"), tmp_path, name="c2")
        assert "circular" in text  # the ⚠ circular edge label is painted

    def test_external_node_styled_from_boolean(self, tmp_path):
        root = ET.fromstring(_render(_write(tmp_path, _CRAFTED), tmp_path, name="crafted"))
        externals = [g for g in _nodes(root) if "usv-node--external" in g.get("class", "").split()]
        assert len(externals) == 1
        assert externals[0].get("data-node-id") == "np"

    def test_sloc_label_rendered(self, tmp_path):
        content = _render(_write(tmp_path, _CRAFTED), tmp_path, name="crafted")
        assert "1,000 SLOC" in content  # grouped module carries its SLOC line

    def test_deterministic_across_runs(self, tmp_path):
        assert _render(FIXTURE, tmp_path, name="one") == _render(FIXTURE, tmp_path, name="two")


class TestGraphvizPath:
    """Graphviz-path semantics (DOT source only, so no dot binary needed)."""

    @staticmethod
    def _dot(inputfile: str, styleid: str = "") -> str:
        dg = DependencyGraph(inputfile, "unused", styleid=styleid)
        dg.render()
        return dg.graph.source

    def test_template_dict_form_cycle_parsed(self):
        # The template writes {cycle = [...], severity = ...}; it used to be
        # dropped silently, so no circular edge was ever highlighted.
        dg = _loaded(FIXTURE)
        assert dg._circular == [["utils", "settings"]]
        assert "circular" in self._dot(FIXTURE)

    def test_external_boolean_honoured(self):
        dg = _loaded(FIXTURE)
        assert dg.get_stats()["external_count"] == sum(1 for m in dg._modules.values() if m.get("external"))
        line = next(ln for ln in self._dot(FIXTURE).splitlines() if ln.strip().startswith("graphviz "))
        assert "dashed" in line  # external_module preset style, not a group-colored internal card

    def test_outline_preset_keeps_readable_text(self):
        # dg_minimal nodes are unfilled: forcing the white group text made
        # every label white-on-white.
        source = self._dot(FIXTURE, "dg_minimal")
        assert "fontcolor=white" not in source


class TestEngineGuards:
    """Engine/style guards do not render, so they run without the dot binary."""

    def test_graphviz_preset_rejected_under_svg_engine(self, tmp_path):
        with pytest.raises(StyleEngineMismatchError):
            _render(FIXTURE, tmp_path, styleid="dg_default")

    def test_svg_preset_rejected_under_graphviz_engine(self):
        with pytest.raises(StyleEngineMismatchError):
            DependencyGraph(FIXTURE, "unused", styleid="sv_default", render_engine="graphviz").load()

    def test_complexity_guard_runs_before_layout(self, monkeypatch, tmp_path):
        # The SVG engine skips _render_impl, so the shared graph painter must
        # enforce check_graph_complexity itself. Patch it to raise and confirm
        # the render trips it before the dot-requiring layout runs.
        import usecvislib.utils as u

        def _boom(nodes, edges, **kwargs):
            raise ValueError(f"COMPLEXITY {nodes}/{edges}")

        monkeypatch.setattr(u, "check_graph_complexity", _boom)
        with pytest.raises(ValueError, match="COMPLEXITY"):
            _render(FIXTURE, tmp_path)


@requires_dot
class TestRasterOutputs:
    @pytest.fixture(autouse=True)
    def _require_cairosvg(self):
        pytest.importorskip("cairosvg")

    def test_png_output(self, tmp_path):
        DependencyGraph(FIXTURE, str(tmp_path / "o"), format="png", render_engine="svg").build()
        assert (tmp_path / "o.png").read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"

    def test_pdf_output(self, tmp_path):
        DependencyGraph(FIXTURE, str(tmp_path / "o"), format="pdf", render_engine="svg").build()
        assert (tmp_path / "o.pdf").read_bytes()[:5] == b"%PDF-"


class TestCli:
    @requires_dot
    def test_cli_svg_engine_end_to_end(self, tmp_path):
        from usecvislib import usecvis

        rc = usecvis.main(
            ["-i", FIXTURE, "-o", str(tmp_path / "cli"), "-f", "svg", "-m", "8", "--render-engine", "svg"]
        )
        assert rc == 0
        assert 'data-usv-engine="svg"' in (tmp_path / "cli.svg").read_text(encoding="utf-8")

    def test_cli_rejects_dot_format_under_svg(self, tmp_path):
        from usecvislib import usecvis

        with pytest.raises(SystemExit) as exc:
            usecvis.main(["-i", FIXTURE, "-o", str(tmp_path / "x"), "-f", "dot", "-m", "8", "--render-engine", "svg"])
        assert exc.value.code == 2


@requires_dot
class TestGroupClusters:
    def test_one_cluster_per_group(self, tmp_path):
        # The SVG engine conveyed groups by color only; Graphviz draws boxes.
        root = ET.fromstring(_render(FIXTURE, tmp_path))
        clusters = {g.get("data-cluster-id") for g in root.iter(f"{SVG_NS}g") if "usv-cluster" in g.get("class", "")}
        groups = {m.get("group") for m in _loaded(FIXTURE)._modules.values() if m.get("group")}
        assert len(clusters) == len(groups)


class TestCouplingPreset:
    def test_coupling_heat_colors_by_degree(self):
        # dg_coupling's documented intent: high-connection modules are warmer.
        dg = DependencyGraph(FIXTURE, "unused", styleid="dg_coupling")
        dg.load()
        degree = {}
        for dep in dg._dependencies:
            for end in (dep["from"], dep["to"]):
                degree[end] = degree.get(end, 0) + 1
        hottest = max(degree, key=degree.get)
        coolest = min((m for m in dg._modules if m in degree), key=degree.get)
        assert dg._coupling_color(hottest) != dg._coupling_color(coolest)
        assert dg._coupling_color(hottest) == "#c01e1e"
