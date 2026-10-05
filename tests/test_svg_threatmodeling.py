#
# VULNEX -Universal Security Visualization Library-
#
# File: test_svg_threatmodeling.py
# Author: Simon Roses Femerling
# Created: 2026-09-01
# Last Modified: 2026-09-01
# Version: 0.5.0
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Tests for the Data Flow Diagram SVG painter (Phase 3, mode 1).

The DFD is a general graph whose trust boundaries become Graphviz
``cluster_*`` subgraphs (drawn as dashed cluster rectangles), so the SVG
painter routes nodes/edges AND reads cluster bounding boxes back via the
``GraphvizJsonLayout`` oracle — render tests require the system ``dot`` binary
and are skipped when it is absent (host lacks it; container has it). Engine
guards and the CLI dot-format rejection do not render and run everywhere.

Exact SVG bytes are NOT asserted (Graphviz coordinates drift across ``dot``
versions). Assertions target the interactivity contract, element/flow/boundary
counts, and element-type / dashed-boundary semantics. This painter renders the
DFD diagram only; STRIDE analysis is unaffected and untested here.
"""

import glob
import json
import shutil
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from usecvislib.svgengine.scene import StyleEngineMismatchError
from usecvislib.threatmodeling import ThreatModeling

TESTS_DIR = Path(__file__).parent
TEMPLATE_DIR = TESTS_DIR.parent / "templates" / "threat-models"
FIXTURE = str(TEMPLATE_DIR / "banking_api.json")  # externals+processes+datastores, 7 boundaries, 28 flows
TEMPLATES = sorted(glob.glob(str(TEMPLATE_DIR / "*.json")))
SVG_PRESETS = ["sv_default", "sv_dark", "sv_security", "sv_corporate", "sv_minimal"]
SVG_NS = "{http://www.w3.org/2000/svg}"
ELEMENT_SECTIONS = ("externals", "processes", "datastores")

DOT_AVAILABLE = shutil.which("dot") is not None
requires_dot = pytest.mark.skipif(
    not DOT_AVAILABLE, reason="Graphviz 'dot' binary required for general-graph SVG layout"
)


def _render(inputfile: str, tmp_path, styleid: str = "", name: str = "out") -> str:
    tm = ThreatModeling(inputfile, str(tmp_path / name), format="svg", styleid=styleid, render_engine="svg")
    tm.build()
    return (tmp_path / f"{name}.svg").read_text(encoding="utf-8")


def _write(tmp_path, data: dict, name: str = "in.json") -> str:
    path = tmp_path / name
    path.write_text(json.dumps(data), encoding="utf-8")
    return str(path)


def _loaded(inputfile: str) -> ThreatModeling:
    tm = ThreatModeling(inputfile, "unused")
    tm.load()
    return tm


def _expected_nodes(tm: ThreatModeling) -> int:
    return sum(len(tm.inputdata.get(s, {})) for s in ELEMENT_SECTIONS)


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
        assert root.get("data-usv-module") == "dfd"
        assert root.get("data-usv-engine") == "svg"


@requires_dot
class TestTemplates:
    @pytest.mark.parametrize("template", TEMPLATES, ids=[Path(t).stem for t in TEMPLATES])
    def test_template_renders_unmodified(self, tmp_path, template):
        root = ET.fromstring(_render(template, tmp_path, name=Path(template).stem))
        assert _by_class(root, "usv-node"), "every threat-model template has at least one DFD element"


@requires_dot
class TestInteractivityContract:
    def test_node_count_matches_data(self, tmp_path):
        root = ET.fromstring(_render(FIXTURE, tmp_path))
        assert len(_by_class(root, "usv-node")) == _expected_nodes(_loaded(FIXTURE))

    def test_edge_count_matches_data(self, tmp_path):
        root = ET.fromstring(_render(FIXTURE, tmp_path))
        assert len(_by_class(root, "usv-edge")) == len(_loaded(FIXTURE).inputdata.get("dataflows", {}))

    def test_nodes_carry_contract(self, tmp_path):
        root = ET.fromstring(_render(FIXTURE, tmp_path))
        nodes = _by_class(root, "usv-node")
        assert nodes
        for g in nodes:
            assert g.get("data-node-id") and g.get("data-label") and g.get("data-kind")

    def test_element_type_classes_present(self, tmp_path):
        root = ET.fromstring(_render(FIXTURE, tmp_path))
        kinds = {c.removeprefix("usv-node--") for c in _classes_with_prefix(root, "usv-node--")}
        assert {"external", "process", "datastore"} <= kinds

    def test_dataflow_edges_carry_endpoints(self, tmp_path):
        root = ET.fromstring(_render(FIXTURE, tmp_path))
        edges = _by_class(root, "usv-edge")
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
class TestTrustBoundaries:
    def test_boundary_becomes_dashed_cluster(self, tmp_path):
        root = ET.fromstring(_render(FIXTURE, tmp_path))
        clusters = _by_class(root, "usv-cluster")
        assert clusters, "trust boundaries render as clusters"
        # every boundary rect is dashed
        for c in clusters:
            rect = c.find(f"{SVG_NS}rect")
            assert rect is not None and rect.get("stroke-dasharray")
            assert c.get("data-cluster-id") and c.get("data-label")

    def test_cluster_count_matches_populated_boundaries(self, tmp_path):
        root = ET.fromstring(_render(FIXTURE, tmp_path))
        tm = _loaded(FIXTURE)
        node_ids = set()
        for s in ELEMENT_SECTIONS:
            node_ids |= set(tm.inputdata.get(s, {}).keys())
        expected = sum(
            1
            for b in tm.inputdata.get("boundaries", {}).values()
            if isinstance(b, dict) and any(e in node_ids for e in b.get("elements", []))
        )
        assert len(_by_class(root, "usv-cluster")) == expected

    def test_flow_labels_rendered(self, tmp_path):
        # A crafted model with a distinctive flow label.
        data = {
            "model": {"name": "Crafted"},
            "externals": {"user": {"label": "User"}},
            "processes": {"api": {"label": "API"}},
            "datastores": {"db": {"label": "DB"}},
            "dataflows": {"f1": {"from": "user", "to": "api", "label": "LOGIN-REQ"}},
            "boundaries": {"dmz": {"label": "DMZ", "elements": ["api", "db"]}},
        }
        content = _render(_write(tmp_path, data), tmp_path, name="crafted")
        assert "LOGIN-REQ" in content
        assert "DMZ" in content  # boundary label painted


class TestEngineGuards:
    """Engine/style guards do not render, so they run without the dot binary."""

    def test_graphviz_preset_rejected_under_svg_engine(self, tmp_path):
        with pytest.raises(StyleEngineMismatchError):
            _render(FIXTURE, tmp_path, styleid="tm_default")

    def test_svg_preset_rejected_under_graphviz_engine(self):
        with pytest.raises(StyleEngineMismatchError):
            ThreatModeling(FIXTURE, "unused", styleid="sv_default", render_engine="graphviz").load()

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
        ThreatModeling(FIXTURE, str(tmp_path / "o"), format="png", render_engine="svg").build()
        assert (tmp_path / "o.png").read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"

    def test_pdf_output(self, tmp_path):
        ThreatModeling(FIXTURE, str(tmp_path / "o"), format="pdf", render_engine="svg").build()
        assert (tmp_path / "o.pdf").read_bytes()[:5] == b"%PDF-"


class TestCli:
    @requires_dot
    def test_cli_svg_engine_end_to_end(self, tmp_path):
        from usecvislib import usecvis

        rc = usecvis.main(
            ["-i", FIXTURE, "-o", str(tmp_path / "cli"), "-f", "svg", "-m", "1", "--render-engine", "svg"]
        )
        assert rc == 0
        assert 'data-usv-engine="svg"' in (tmp_path / "cli.svg").read_text(encoding="utf-8")

    def test_cli_rejects_dot_format_under_svg(self, tmp_path):
        from usecvislib import usecvis

        with pytest.raises(SystemExit) as exc:
            usecvis.main(["-i", FIXTURE, "-o", str(tmp_path / "x"), "-f", "dot", "-m", "1", "--render-engine", "svg"])
        assert exc.value.code == 2


@requires_dot
class TestIcons:
    def test_icon_template_embeds_images(self, tmp_path):
        # The SVG engine used to ignore `image`, drawing plain shapes only.
        template = str(TEMPLATE_DIR / "web_app_icons.toml")
        tm = _loaded(template)
        expected = sum(
            1
            for section in ("externals", "processes", "datastores")
            for elem in tm.inputdata.get(section, {}).values()
            if isinstance(elem, dict) and elem.get("image")
        )
        assert expected > 0
        root = ET.fromstring(_render(template, tmp_path))
        images = [el for el in root.iter(f"{SVG_NS}image") if el.get("href", "").startswith("data:image/")]
        assert len(images) == expected
