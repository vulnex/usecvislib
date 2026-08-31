#
# VULNEX -Universal Security Visualization Library-
#
# File: test_svg_attackgraphs.py
# Author: Simon Roses Femerling
# Created: 2026-08-31
# Last Modified: 2026-08-31
# Version: 0.5.0
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Tests for the Attack Graph SVG painter (Phase 3 pilot, mode 3).

Attack graphs are general graphs: the SVG painter places nodes and routes
edges with the ``GraphvizJsonLayout`` oracle, so the render tests require the
system Graphviz ``dot`` binary and are skipped when it is absent (the host
dev machine lacks it; the container has it). Tests that do not render — engine
guards and the CLI dot-format rejection — run everywhere.

Unlike the native-layout painters, exact SVG bytes are NOT asserted: Graphviz
coordinates drift across ``dot`` versions. Assertions target the interactivity
contract, node/edge counts, kind/severity semantics, and safety instead.
"""

import glob
import shutil
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from usecvislib.attackgraphs import AttackGraphs
from usecvislib.cvss_unified import get_cvss_score_unified as get_cvss_score
from usecvislib.svgengine.scene import StyleEngineMismatchError

TESTS_DIR = Path(__file__).parent
TEMPLATE_DIR = TESTS_DIR.parent / "templates" / "attack-graphs"
FIXTURE = str(TEMPLATE_DIR / "cloud.toml")  # hosts+vulns+privs+services+exploits, all 3 edge kinds
TEMPLATES = sorted(glob.glob(str(TEMPLATE_DIR / "*")))
SVG_PRESETS = ["sv_default", "sv_dark", "sv_security", "sv_corporate", "sv_minimal"]
SVG_NS = "{http://www.w3.org/2000/svg}"

VALID_SEVERITIES = {"critical", "high", "medium", "low", "none"}
NODE_SECTIONS = ("hosts", "vulnerabilities", "privileges", "services", "exploits")

DOT_AVAILABLE = shutil.which("dot") is not None
requires_dot = pytest.mark.skipif(
    not DOT_AVAILABLE, reason="Graphviz 'dot' binary required for general-graph SVG layout"
)


def _render(inputfile: str, tmp_path, styleid: str = "", name: str = "out") -> str:
    ag = AttackGraphs(inputfile, str(tmp_path / name), format="svg", styleid=styleid, render_engine="svg")
    ag.build()
    return (tmp_path / f"{name}.svg").read_text(encoding="utf-8")


def _loaded(inputfile: str) -> AttackGraphs:
    """A loaded instance (inputdata normalized) for computing expected counts."""
    ag = AttackGraphs(inputfile, "unused")
    ag.load()
    return ag


def _expected_node_count(ag: AttackGraphs) -> int:
    return sum(len(ag.inputdata.get(section, {})) for section in NODE_SECTIONS)


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


@requires_dot
class TestPresets:
    @pytest.mark.parametrize("preset", SVG_PRESETS)
    def test_fixture_renders_in_preset(self, tmp_path, preset):
        root = ET.fromstring(_render(FIXTURE, tmp_path, styleid=preset, name=preset))
        assert root.get("data-usv-theme") == preset
        assert root.get("data-usv-module") == "attackgraph"
        assert root.get("data-usv-engine") == "svg"


@requires_dot
class TestTemplates:
    @pytest.mark.parametrize("template", TEMPLATES, ids=[Path(t).stem for t in TEMPLATES])
    def test_template_renders_unmodified(self, tmp_path, template):
        root = ET.fromstring(_render(template, tmp_path, name=Path(template).stem))
        assert _nodes(root), "every attack-graph template has at least one node"


@requires_dot
class TestInteractivityContract:
    def test_node_count_matches_data(self, tmp_path):
        root = ET.fromstring(_render(FIXTURE, tmp_path))
        assert len(_nodes(root)) == _expected_node_count(_loaded(FIXTURE))

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
        # cloud fixture exercises every node kind
        assert {"host", "vulnerability", "privilege", "service", "exploit"} <= kinds

    def test_edge_kind_classes_present(self, tmp_path):
        root = ET.fromstring(_render(FIXTURE, tmp_path))
        kinds = {c.removeprefix("usv-edge--") for c in _classes_with_prefix(root, "usv-edge--")}
        assert {"network", "exploit", "structural"} <= kinds

    def test_severity_classes_are_canonical(self, tmp_path):
        root = ET.fromstring(_render(FIXTURE, tmp_path))
        seen = {c.removeprefix("usv-sev--") for c in _classes_with_prefix(root, "usv-sev--")}
        assert seen  # fixture has scored vulnerabilities
        assert seen <= VALID_SEVERITIES

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
    def test_cvss_badges_for_scored_vulns(self, tmp_path):
        root = ET.fromstring(_render(FIXTURE, tmp_path))
        ag = _loaded(FIXTURE)
        expected = 0
        for vuln in ag.inputdata.get("vulnerabilities", {}).values():
            if not isinstance(vuln, dict):
                continue
            score, _ = get_cvss_score(vuln.get("cvss"), vuln.get("cvss_vector"))
            if score is not None and score > 0:
                expected += 1
        badges = [g for g in root.iter(f"{SVG_NS}g") if "usv-badge" in g.get("class", "").split()]
        assert len(badges) == expected
        for b in badges:
            assert b.get("data-value")

    def test_deterministic_across_runs(self, tmp_path):
        # Same dot version + same input is byte-stable within a run.
        assert _render(FIXTURE, tmp_path, name="one") == _render(FIXTURE, tmp_path, name="two")


class TestEngineGuards:
    """Engine/style guards do not render, so they run without the dot binary."""

    def test_graphviz_preset_rejected_under_svg_engine(self, tmp_path):
        with pytest.raises(StyleEngineMismatchError):
            _render(FIXTURE, tmp_path, styleid="ag_default")

    def test_svg_preset_rejected_under_graphviz_engine(self):
        with pytest.raises(StyleEngineMismatchError):
            AttackGraphs(FIXTURE, "unused", styleid="sv_default", render_engine="graphviz").load()


@requires_dot
class TestRasterOutputs:
    @pytest.fixture(autouse=True)
    def _require_cairosvg(self):
        pytest.importorskip("cairosvg")

    def test_png_output(self, tmp_path):
        AttackGraphs(FIXTURE, str(tmp_path / "o"), format="png", render_engine="svg").build()
        assert (tmp_path / "o.png").read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"

    def test_pdf_output(self, tmp_path):
        AttackGraphs(FIXTURE, str(tmp_path / "o"), format="pdf", render_engine="svg").build()
        assert (tmp_path / "o.pdf").read_bytes()[:5] == b"%PDF-"


class TestCli:
    @requires_dot
    def test_cli_svg_engine_end_to_end(self, tmp_path):
        from usecvislib import usecvis

        rc = usecvis.main(
            ["-i", FIXTURE, "-o", str(tmp_path / "cli"), "-f", "svg", "-m", "3", "--render-engine", "svg"]
        )
        assert rc == 0
        assert 'data-usv-engine="svg"' in (tmp_path / "cli.svg").read_text(encoding="utf-8")

    def test_cli_rejects_dot_format_under_svg(self, tmp_path):
        from usecvislib import usecvis

        with pytest.raises(SystemExit) as exc:
            usecvis.main(["-i", FIXTURE, "-o", str(tmp_path / "x"), "-f", "dot", "-m", "3", "--render-engine", "svg"])
        assert exc.value.code == 2
