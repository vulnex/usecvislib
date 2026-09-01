#
# VULNEX -Universal Security Visualization Library-
#
# File: test_svg_componentdiagram.py
# Author: Simon Roses Femerling
# Created: 2026-09-01
# Last Modified: 2026-09-01
# Version: 0.5.0
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Tests for the Component Diagram SVG painter (Phase 3, mode 7).

Component diagrams are general graphs whose layers become Graphviz
``cluster_*`` subgraphs, so the SVG painter places nodes, routes edges, AND
reads back cluster bounding boxes via the ``GraphvizJsonLayout`` oracle — the
render tests require the system ``dot`` binary and are skipped when it is
absent (the host lacks it; the container has it). Engine guards and the CLI
dot-format rejection do not render and run everywhere.

Exact SVG bytes are NOT asserted (Graphviz coordinates drift across ``dot``
versions). Assertions target the interactivity contract, node/edge/cluster
counts, and type/connection semantics.
"""

import glob
import json
import shutil
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from usecvislib.componentdiagram import ComponentDiagram
from usecvislib.svgengine.scene import StyleEngineMismatchError

TESTS_DIR = Path(__file__).parent
TEMPLATE_DIR = TESTS_DIR.parent / "templates" / "architecture"
FIXTURE = str(TEMPLATE_DIR / "component-diagram-example.json")  # multi-layer, typed components
TEMPLATES = sorted(glob.glob(str(TEMPLATE_DIR / "component*")))
SVG_PRESETS = ["sv_default", "sv_dark", "sv_security", "sv_corporate", "sv_minimal"]
SVG_NS = "{http://www.w3.org/2000/svg}"

DOT_AVAILABLE = shutil.which("dot") is not None
requires_dot = pytest.mark.skipif(
    not DOT_AVAILABLE, reason="Graphviz 'dot' binary required for general-graph SVG layout"
)


def _render(inputfile: str, tmp_path, styleid: str = "", name: str = "out") -> str:
    cd = ComponentDiagram(inputfile, str(tmp_path / name), format="svg", styleid=styleid, render_engine="svg")
    cd.build()
    return (tmp_path / f"{name}.svg").read_text(encoding="utf-8")


def _write(tmp_path, data: dict, name: str = "in.json") -> str:
    path = tmp_path / name
    path.write_text(json.dumps(data), encoding="utf-8")
    return str(path)


def _loaded(inputfile: str) -> ComponentDiagram:
    cd = ComponentDiagram(inputfile, "unused")
    cd.load()
    return cd


def _by_class(root, cls):
    return [g for g in root.iter(f"{SVG_NS}g") if cls in g.get("class", "").split()]


def _classes_with_prefix(root, prefix):
    return {
        c
        for g in root.iter(f"{SVG_NS}g")
        for c in g.get("class", "").split()
        if c.startswith(prefix)
    }


# A crafted diagram exercising the connection styles the template omits.
_CRAFTED = {
    "title": "Crafted",
    "layers": [
        {"name": "Edge", "components": [{"id": "lb", "name": "Load Balancer", "type": "service"}]},
        {"name": "Store", "components": [{"id": "db", "name": "Database", "type": "database"}]},
    ],
    "connections": [
        {"from": "lb", "to": "db", "style": "bidirectional", "label": "rw"},
        {"from": "db", "to": "lb", "style": "event"},
    ],
}


@requires_dot
class TestPresets:
    @pytest.mark.parametrize("preset", SVG_PRESETS)
    def test_fixture_renders_in_preset(self, tmp_path, preset):
        root = ET.fromstring(_render(FIXTURE, tmp_path, styleid=preset, name=preset))
        assert root.get("data-usv-theme") == preset
        assert root.get("data-usv-module") == "componentdiagram"
        assert root.get("data-usv-engine") == "svg"


@requires_dot
class TestTemplates:
    @pytest.mark.parametrize("template", TEMPLATES, ids=[Path(t).stem for t in TEMPLATES])
    def test_template_renders_unmodified(self, tmp_path, template):
        root = ET.fromstring(_render(template, tmp_path, name=Path(template).stem))
        assert _by_class(root, "usv-node"), "every component template has at least one node"


@requires_dot
class TestInteractivityContract:
    def test_node_count_matches_data(self, tmp_path):
        root = ET.fromstring(_render(FIXTURE, tmp_path))
        assert len(_by_class(root, "usv-node")) == len(_loaded(FIXTURE)._components)

    def test_edge_count_matches_data(self, tmp_path):
        root = ET.fromstring(_render(FIXTURE, tmp_path))
        assert len(_by_class(root, "usv-edge")) == len(_loaded(FIXTURE)._connections)

    def test_nodes_carry_contract(self, tmp_path):
        root = ET.fromstring(_render(FIXTURE, tmp_path))
        nodes = _by_class(root, "usv-node")
        assert nodes
        for g in nodes:
            assert g.get("data-node-id") and g.get("data-label") and g.get("data-kind")
            assert g.get("data-layer"), "every component records its layer"

    def test_node_type_classes_present(self, tmp_path):
        root = ET.fromstring(_render(FIXTURE, tmp_path))
        kinds = {c.removeprefix("usv-node--") for c in _classes_with_prefix(root, "usv-node--")}
        # example architecture mixes frontend/cli/service/database types
        assert {"frontend", "service", "database"} <= kinds

    def test_no_active_content(self, tmp_path):
        content = _render(FIXTURE, tmp_path)
        assert "<script" not in content
        assert "foreignObject" not in content
        assert "onclick" not in content and "onload" not in content
        assert "url(http" not in content
        assert "@import" not in content


@requires_dot
class TestClusters:
    def test_cluster_per_populated_layer(self, tmp_path):
        root = ET.fromstring(_render(FIXTURE, tmp_path))
        clusters = _by_class(root, "usv-cluster")
        expected = sum(1 for lyr in _loaded(FIXTURE)._layers if lyr.get("components"))
        assert len(clusters) == expected
        for c in clusters:
            assert c.get("data-cluster-id") and c.get("data-label")

    def test_cluster_has_rect_and_label(self, tmp_path):
        root = ET.fromstring(_render(FIXTURE, tmp_path))
        cluster = _by_class(root, "usv-cluster")[0]
        assert cluster.find(f"{SVG_NS}rect") is not None
        assert cluster.find(f"{SVG_NS}text") is not None  # painted layer label

    def test_cluster_labels_match_layers(self, tmp_path):
        root = ET.fromstring(_render(FIXTURE, tmp_path))
        labels = {c.get("data-label") for c in _by_class(root, "usv-cluster")}
        layer_names = {lyr.get("name") for lyr in _loaded(FIXTURE)._layers if lyr.get("components")}
        assert labels == layer_names


@requires_dot
class TestConnectionSemantics:
    def test_connection_style_classes(self, tmp_path):
        root = ET.fromstring(_render(_write(tmp_path, _CRAFTED), tmp_path, name="crafted"))
        kinds = {c.removeprefix("usv-edge--") for c in _classes_with_prefix(root, "usv-edge--")}
        assert {"bidirectional", "event"} <= kinds

    def test_deterministic_across_runs(self, tmp_path):
        assert _render(FIXTURE, tmp_path, name="one") == _render(FIXTURE, tmp_path, name="two")


class TestEngineGuards:
    """Engine/style guards do not render, so they run without the dot binary."""

    def test_graphviz_preset_rejected_under_svg_engine(self, tmp_path):
        with pytest.raises(StyleEngineMismatchError):
            _render(FIXTURE, tmp_path, styleid="cd_default")

    def test_svg_preset_rejected_under_graphviz_engine(self):
        with pytest.raises(StyleEngineMismatchError):
            ComponentDiagram(FIXTURE, "unused", styleid="sv_default", render_engine="graphviz").load()

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
        ComponentDiagram(FIXTURE, str(tmp_path / "o"), format="png", render_engine="svg").build()
        assert (tmp_path / "o.png").read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"

    def test_pdf_output(self, tmp_path):
        ComponentDiagram(FIXTURE, str(tmp_path / "o"), format="pdf", render_engine="svg").build()
        assert (tmp_path / "o.pdf").read_bytes()[:5] == b"%PDF-"


class TestCli:
    @requires_dot
    def test_cli_svg_engine_end_to_end(self, tmp_path):
        from usecvislib import usecvis

        rc = usecvis.main(
            ["-i", FIXTURE, "-o", str(tmp_path / "cli"), "-f", "svg", "-m", "7", "--render-engine", "svg"]
        )
        assert rc == 0
        assert 'data-usv-engine="svg"' in (tmp_path / "cli.svg").read_text(encoding="utf-8")

    def test_cli_rejects_dot_format_under_svg(self, tmp_path):
        from usecvislib import usecvis

        with pytest.raises(SystemExit) as exc:
            usecvis.main(["-i", FIXTURE, "-o", str(tmp_path / "x"), "-f", "dot", "-m", "7", "--render-engine", "svg"])
        assert exc.value.code == 2
