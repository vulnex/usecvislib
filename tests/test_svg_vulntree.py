#
# VULNEX -Universal Security Visualization Library-
#
# File: test_svg_vulntree.py
# Author: Simon Roses Femerling
# Created: 2026-08-28
# Last Modified: 2026-08-28
# Version: 0.5.0
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Tests for the Vulnerability Dependency Tree SVG painter (Phase 2, mode 11)."""

import glob
import os
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from usecvislib.svgengine.scene import StyleEngineMismatchError
from usecvislib.vulntree import SUPPORTED_MODES, VulnDependencyTree

TESTS_DIR = Path(__file__).parent
TEMPLATE_DIR = TESTS_DIR.parent / "templates" / "vuln-trees"
FIXTURE = str(TEMPLATE_DIR / "java_log4shell.tml")  # 6 deps, 1 exploited CVE, direct+transitive mix
TEMPLATES = sorted(glob.glob(str(TEMPLATE_DIR / "*")))
SVG_PRESETS = ["sv_default", "sv_dark", "sv_security", "sv_corporate", "sv_minimal"]
SVG_NS = "{http://www.w3.org/2000/svg}"

VALID_SEVERITIES = {"critical", "high", "medium", "low", "none"}


def _render(inputfile: str, tmp_path, styleid: str = "", mode: str = "tree", name: str = "out") -> str:
    vt = VulnDependencyTree(
        inputfile, str(tmp_path / name), format="svg", styleid=styleid, mode=mode, render_engine="svg"
    )
    vt.build()
    return (tmp_path / f"{name}.svg").read_text(encoding="utf-8")


def _loaded(inputfile: str, mode: str = "tree") -> VulnDependencyTree:
    """A loaded instance, for computing expected counts independent of the SVG."""
    vt = VulnDependencyTree(inputfile, "unused", mode=mode)
    vt.load()
    return vt


def _nodes(root):
    return [g for g in root.iter(f"{SVG_NS}g") if "usv-node" in g.get("class", "").split()]


def _edges(root):
    return [g for g in root.iter(f"{SVG_NS}g") if "usv-edge" in g.get("class", "").split()]


class TestPresets:
    @pytest.mark.parametrize("preset", SVG_PRESETS)
    def test_fixture_renders_in_preset(self, tmp_path, preset):
        root = ET.fromstring(_render(FIXTURE, tmp_path, styleid=preset))
        assert root.get("data-usv-theme") == preset
        assert root.get("data-usv-module") == "vulntree"


class TestTemplates:
    @pytest.mark.parametrize("template", TEMPLATES, ids=[Path(t).stem for t in TEMPLATES])
    @pytest.mark.parametrize("mode", SUPPORTED_MODES)
    def test_template_renders_unmodified(self, tmp_path, template, mode):
        ET.fromstring(_render(template, tmp_path, mode=mode, name=f"{Path(template).stem}_{mode}"))


class TestInteractivityContract:
    def test_node_count_matches_visible(self, tmp_path):
        root = ET.fromstring(_render(FIXTURE, tmp_path))
        assert len(_nodes(root)) == len(_loaded(FIXTURE)._visible_nodes())

    def test_nodes_carry_contract(self, tmp_path):
        root = ET.fromstring(_render(FIXTURE, tmp_path))
        nodes = _nodes(root)
        assert nodes
        for g in nodes:
            assert g.get("data-node-id"), "every node needs data-node-id"
            assert g.get("data-label"), "every node needs data-label"
            assert g.get("data-direct") in ("true", "false")

    def test_severity_classes_are_canonical(self, tmp_path):
        root = ET.fromstring(_render(FIXTURE, tmp_path))
        seen = {
            cls.removeprefix("usv-sev--")
            for g in root.iter(f"{SVG_NS}g")
            for cls in g.get("class", "").split()
            if cls.startswith("usv-sev--")
        }
        assert seen  # fixture has vulnerable packages
        assert seen <= VALID_SEVERITIES

    def test_edges_carry_contract(self, tmp_path):
        root = ET.fromstring(_render(FIXTURE, tmp_path))
        vt = _loaded(FIXTURE)
        visible = vt._visible_nodes()
        expected = sum(
            1 for dep_id in visible for child in vt.dependencies[dep_id].dependencies if child in visible
        )
        edges = _edges(root)
        assert len(edges) == expected
        for g in edges:
            assert g.get("data-from") and g.get("data-to")

    def test_no_active_content(self, tmp_path):
        content = _render(FIXTURE, tmp_path)
        assert "<script" not in content
        assert "foreignObject" not in content
        assert "onclick" not in content and "onload" not in content
        assert "url(http" not in content
        assert "@import" not in content


class TestSemantics:
    def test_exploited_edge_marked(self, tmp_path):
        root = ET.fromstring(_render(FIXTURE, tmp_path))
        exploited = [g for g in _edges(root) if "usv-edge--exploited" in g.get("class", "").split()]
        assert exploited, "fixture has a known-exploited CVE, so at least one edge must be marked"

    def test_direct_nodes_marked(self, tmp_path):
        root = ET.fromstring(_render(FIXTURE, tmp_path))
        vt = _loaded(FIXTURE)
        visible = vt._visible_nodes()
        expected_direct = sum(1 for dep_id in visible if vt.dependencies[dep_id].direct)
        direct = [g for g in _nodes(root) if "usv-node--direct" in g.get("class", "").split()]
        assert len(direct) == expected_direct

    def test_cvss_badges_for_vulnerable_nodes(self, tmp_path):
        root = ET.fromstring(_render(FIXTURE, tmp_path))
        vt = _loaded(FIXTURE)
        visible = vt._visible_nodes()
        expected = sum(
            1 for dep_id in visible if vt.dependencies[dep_id].vulnerabilities and vt.dependencies[dep_id].max_cvss > 0
        )
        badges = [g for g in root.iter(f"{SVG_NS}g") if "usv-badge" in g.get("class", "").split()]
        assert len(badges) == expected
        for b in badges:
            assert b.get("data-value")

    def test_mode_pruning_reduces_nodes(self, tmp_path):
        full = len(_nodes(ET.fromstring(_render(FIXTURE, tmp_path, mode="tree", name="t"))))
        vuln = len(_nodes(ET.fromstring(_render(FIXTURE, tmp_path, mode="vulnerable_only", name="v"))))
        crit = len(_nodes(ET.fromstring(_render(FIXTURE, tmp_path, mode="critical_path", name="c"))))
        assert vuln <= full and crit <= vuln

    def test_deterministic_across_runs(self, tmp_path):
        assert _render(FIXTURE, tmp_path, name="one") == _render(FIXTURE, tmp_path, name="two")


class TestEngineGuards:
    def test_graphviz_preset_rejected_under_svg_engine(self, tmp_path):
        with pytest.raises(StyleEngineMismatchError):
            _render(FIXTURE, tmp_path, styleid="vt_default")

    def test_svg_preset_rejected_under_graphviz_engine(self):
        with pytest.raises(StyleEngineMismatchError):
            VulnDependencyTree(FIXTURE, "unused", styleid="sv_default", render_engine="graphviz").load()


class TestRasterOutputs:
    @pytest.fixture(autouse=True)
    def _require_cairosvg(self):
        pytest.importorskip("cairosvg")

    def test_png_output(self, tmp_path):
        VulnDependencyTree(FIXTURE, str(tmp_path / "o"), format="png", render_engine="svg").build()
        assert (tmp_path / "o.png").read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"

    def test_pdf_output(self, tmp_path):
        VulnDependencyTree(FIXTURE, str(tmp_path / "o"), format="pdf", render_engine="svg").build()
        assert (tmp_path / "o.pdf").read_bytes()[:5] == b"%PDF-"


class TestCli:
    def test_cli_svg_engine_end_to_end(self, tmp_path):
        from usecvislib import usecvis

        rc = usecvis.main(
            ["-i", FIXTURE, "-o", str(tmp_path / "cli"), "-f", "svg", "-m", "11", "--render-engine", "svg"]
        )
        assert rc == 0
        assert 'data-usv-engine="svg"' in (tmp_path / "cli.svg").read_text(encoding="utf-8")

    def test_cli_rejects_dot_format_under_svg(self, tmp_path):
        from usecvislib import usecvis

        with pytest.raises(SystemExit) as exc:
            usecvis.main(["-i", FIXTURE, "-o", str(tmp_path / "x"), "-f", "dot", "-m", "11", "--render-engine", "svg"])
        assert exc.value.code == 2


class TestRowSkippingEdges:
    def test_skip_edge_does_not_run_through_intermediate_node(self, tmp_path):
        # express -> qs and express -> body-parser -> qs: qs sits below
        # body-parser, and the express -> qs drop used to hide behind it.
        import re

        root = ET.fromstring(_render(str(TEMPLATE_DIR / "npm_supply_chain.tml"), tmp_path))
        ns = "{http://www.w3.org/2000/svg}"
        rects = {}
        for g in root.iter(f"{ns}g"):
            if "usv-node" in g.get("class", "").split():
                r = g.find(f"{ns}rect")
                if r is not None:
                    x, y = float(r.get("x")), float(r.get("y"))
                    rects[g.get("data-node-id")] = (x, y, x + float(r.get("width")), y + float(r.get("height")))
        edge = next(g for g in root.iter(f"{ns}g") if g.get("data-from") == "express" and g.get("data-to") == "qs")
        d = edge.find(f"{ns}path").get("d")
        nums = [float(v) for v in re.findall(r"-?\d+(?:\.\d+)?", d)]
        points = list(zip(nums[0::2], nums[1::2], strict=False))
        x0, y0, x1, y1 = rects["body-parser"]
        for (ax, ay), (bx, by) in zip(points, points[1:], strict=False):
            if abs(ax - bx) < 0.5:  # vertical run
                lo, hi = sorted((ay, by))
                assert not (x0 < ax < x1 and lo < y1 and hi > y0), "edge runs through body-parser"


class TestCleanPackageFill:
    def test_preset_clean_fill_applied(self, tmp_path):
        # Clean packages ignored the preset and were always #4caf50.
        content = _render(FIXTURE, tmp_path, styleid="sv_dark")
        assert "#2e7d32" in content


class TestDeterministicOutput:
    # Nodes and edges were emitted in set order, which follows the
    # per-process string hash seed: the same input gave different SVG bytes
    # from one run to the next.
    def test_visible_nodes_follow_declaration_order(self):
        vt = _loaded(str(TEMPLATE_DIR / "npm_supply_chain.tml"))
        declared = list(vt.dependencies)
        visible = vt._visible_nodes()
        assert visible == [d for d in declared if d in visible]

    @pytest.mark.parametrize("mode", SUPPORTED_MODES)
    def test_same_svg_under_any_hash_seed(self, tmp_path, mode):
        script = (
            "import sys; from usecvislib.vulntree import VulnDependencyTree as V;"
            "V(sys.argv[1], sys.argv[2], format='svg', mode=sys.argv[3], render_engine='svg').build()"
        )
        outputs = set()
        for seed in ("1", "2", "3"):
            out = tmp_path / f"seed{seed}"
            env = {**os.environ, "PYTHONHASHSEED": seed, "PYTHONPATH": str(TESTS_DIR.parent / "src")}
            subprocess.run(
                [sys.executable, "-c", script, str(TEMPLATE_DIR / "npm_supply_chain.tml"), str(out), mode],
                env=env,
                check=True,
            )
            outputs.add((tmp_path / f"seed{seed}.svg").read_text(encoding="utf-8"))
        assert len(outputs) == 1
