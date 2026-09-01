#
# VULNEX -Universal Security Visualization Library-
#
# File: test_svg_maestro.py
# Author: Simon Roses Femerling
# Created: 2026-09-01
# Last Modified: 2026-09-01
# Version: 0.5.0
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Tests for the MAESTRO agent-centric graph SVG painter (Phase 3, mode 12).

The SVG engine renders MAESTRO's ``graph`` view: agents clustered into their
primary MAESTRO layer, cross-layer threats as directed chain edges. It is a
general graph with layer clusters, so render tests require the system ``dot``
binary and are skipped when it is absent (host lacks it; container has it).
View guards and engine/style guards do not render and run everywhere.

Exact SVG bytes are NOT asserted (Graphviz coordinates drift across ``dot``
versions). Assertions target the interactivity contract, agent/cluster/chain
semantics, and the layered/heatmap view guard. The layered architecture and
heatmap views are Graphviz/Matplotlib-only and are not covered here.
"""

import glob
import shutil
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from usecvislib.maestro import MaestroThreatModel
from usecvislib.svgengine.scene import EngineNotSupportedError, StyleEngineMismatchError

TESTS_DIR = Path(__file__).parent
TEMPLATE_DIR = TESTS_DIR.parent / "templates" / "maestro"
FIXTURE = str(TEMPLATE_DIR / "financial-trading-chain.toml")  # 5 agents, cross-layer chains
TEMPLATES = sorted(glob.glob(str(TEMPLATE_DIR / "*.toml")))
SVG_PRESETS = ["sv_default", "sv_dark", "sv_security", "sv_corporate", "sv_minimal"]
SVG_NS = "{http://www.w3.org/2000/svg}"

DOT_AVAILABLE = shutil.which("dot") is not None
requires_dot = pytest.mark.skipif(
    not DOT_AVAILABLE, reason="Graphviz 'dot' binary required for general-graph SVG layout"
)


def _render(inputfile: str, tmp_path, styleid: str = "", name: str = "out", view: str = "graph") -> str:
    mm = MaestroThreatModel(inputfile, str(tmp_path / name), format="svg", styleid=styleid, view=view, render_engine="svg")
    mm.build()
    return (tmp_path / f"{name}.svg").read_text(encoding="utf-8")


def _loaded(inputfile: str) -> MaestroThreatModel:
    mm = MaestroThreatModel(inputfile, "unused", view="graph")
    mm.load()
    return mm


def _by_class(root, cls):
    return [g for g in root.iter(f"{SVG_NS}g") if cls in g.get("class", "").split()]


def _classes_with_prefix(root, prefix):
    return {
        c
        for g in root.iter(f"{SVG_NS}g")
        for c in g.get("class", "").split()
        if c.startswith(prefix)
    }


@requires_dot
class TestPresets:
    @pytest.mark.parametrize("preset", SVG_PRESETS)
    def test_fixture_renders_in_preset(self, tmp_path, preset):
        root = ET.fromstring(_render(FIXTURE, tmp_path, styleid=preset, name=preset))
        assert root.get("data-usv-theme") == preset
        assert root.get("data-usv-module") == "maestro"
        assert root.get("data-usv-engine") == "svg"


@requires_dot
class TestTemplates:
    @pytest.mark.parametrize("template", TEMPLATES, ids=[Path(t).stem for t in TEMPLATES])
    def test_template_renders_in_graph_view(self, tmp_path, template):
        root = ET.fromstring(_render(template, tmp_path, name=Path(template).stem))
        assert _by_class(root, "usv-node"), "every MAESTRO template has at least one agent"


@requires_dot
class TestInteractivityContract:
    def test_every_agent_is_a_node(self, tmp_path):
        root = ET.fromstring(_render(FIXTURE, tmp_path))
        assert len(_by_class(root, "usv-node")) == len(_loaded(FIXTURE).agents)

    def test_nodes_carry_contract(self, tmp_path):
        root = ET.fromstring(_render(FIXTURE, tmp_path))
        nodes = _by_class(root, "usv-node")
        assert nodes
        for g in nodes:
            assert g.get("data-node-id") and g.get("data-label")
            assert g.get("data-kind") == "agent"
            assert g.get("data-layer"), "every agent records its MAESTRO layer"

    def test_chain_edges_present(self, tmp_path):
        root = ET.fromstring(_render(FIXTURE, tmp_path))
        kinds = {c.removeprefix("usv-edge--") for c in _classes_with_prefix(root, "usv-edge--")}
        assert "chain" in kinds  # the trading-chain fixture has cross-layer chains

    def test_edges_carry_endpoints(self, tmp_path):
        root = ET.fromstring(_render(FIXTURE, tmp_path))
        for g in _by_class(root, "usv-edge"):
            assert g.get("data-from") and g.get("data-to")

    def test_no_active_content(self, tmp_path):
        content = _render(FIXTURE, tmp_path)
        assert "<script" not in content
        assert "foreignObject" not in content
        assert "onclick" not in content and "onload" not in content
        assert "url(http" not in content
        assert "@import" not in content


@requires_dot
class TestLayerClusters:
    def test_agents_clustered_by_layer(self, tmp_path):
        root = ET.fromstring(_render(FIXTURE, tmp_path))
        clusters = _by_class(root, "usv-cluster")
        assert clusters, "non-Security layers with agents render as clusters"
        for c in clusters:
            assert c.get("data-cluster-id") and c.get("data-label")

    def test_severity_classes_are_canonical(self, tmp_path):
        root = ET.fromstring(_render(FIXTURE, tmp_path))
        seen = {c.removeprefix("usv-sev--") for c in _classes_with_prefix(root, "usv-sev--")}
        assert seen <= {"critical", "high", "medium", "low"}


class TestViewGuard:
    """The view guard raises before the layout oracle, so it needs no dot."""

    @pytest.mark.parametrize("view", ["layered", "heatmap"])
    def test_non_graph_views_rejected_under_svg(self, tmp_path, view):
        with pytest.raises(EngineNotSupportedError):
            _render(FIXTURE, tmp_path, view=view)


class TestEngineGuards:
    def test_graphviz_preset_rejected_under_svg_engine(self, tmp_path):
        with pytest.raises(StyleEngineMismatchError):
            _render(FIXTURE, tmp_path, styleid="ma_default")

    def test_svg_preset_rejected_under_graphviz_engine(self):
        with pytest.raises(StyleEngineMismatchError):
            MaestroThreatModel(FIXTURE, "unused", styleid="sv_default", view="graph", render_engine="graphviz").load()

    def test_complexity_guard_runs_before_layout(self, monkeypatch, tmp_path):
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
        MaestroThreatModel(FIXTURE, str(tmp_path / "o"), format="png", view="graph", render_engine="svg").build()
        assert (tmp_path / "o.png").read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"

    def test_pdf_output(self, tmp_path):
        MaestroThreatModel(FIXTURE, str(tmp_path / "o"), format="pdf", view="graph", render_engine="svg").build()
        assert (tmp_path / "o.pdf").read_bytes()[:5] == b"%PDF-"


class TestCli:
    @requires_dot
    def test_cli_svg_engine_graph_view(self, tmp_path):
        from usecvislib import usecvis

        rc = usecvis.main(
            ["-i", FIXTURE, "-o", str(tmp_path / "cli"), "-f", "svg", "-m", "12", "-v", "graph", "--render-engine", "svg"]
        )
        assert rc == 0
        assert 'data-usv-module="maestro"' in (tmp_path / "cli.svg").read_text(encoding="utf-8")

    def test_cli_rejects_dot_format_under_svg(self, tmp_path):
        from usecvislib import usecvis

        with pytest.raises(SystemExit) as exc:
            usecvis.main(
                ["-i", FIXTURE, "-o", str(tmp_path / "x"), "-f", "dot", "-m", "12", "-v", "graph", "--render-engine", "svg"]
            )
        assert exc.value.code == 2
