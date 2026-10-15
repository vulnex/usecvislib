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

    @pytest.mark.parametrize("template", TEMPLATES, ids=lambda p: Path(p).name)
    def test_services_linked_to_hosts(self, template, tmp_path):
        # Parity with the Graphviz path: services used to float unconnected.
        root = ET.fromstring(_render(template, tmp_path))
        drawn = {(g.get("data-from"), g.get("data-to")) for g in _edges(root)}
        for svc_id, svc in _loaded(template).inputdata.get("services", {}).items():
            if isinstance(svc, dict) and svc.get("host"):
                assert (svc["host"], svc_id) in drawn, f"service {svc_id} not linked to host {svc['host']}"

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

    def test_oracle_reserves_edge_label_space(self):
        # Short edges between wide nodes used to get no room for their label,
        # which was then centered between the nodes and painted over by them.
        from usecvislib.svgengine.layout import GraphvizJsonLayout
        from usecvislib.svgengine.scene import Scene, SceneEdge, SceneNode

        scene = Scene(module="t")
        for nid in ("a", "b", "c"):
            scene.nodes.append(SceneNode(id=nid, label=nid, width=160, height=40))
        for src, dst in (("a", "b"), ("b", "c"), ("a", "c")):
            scene.edges.append(
                SceneEdge(src=src, dst=dst, label="a fairly long edge label", label_width=150, label_height=15)
            )
        GraphvizJsonLayout(rankdir="LR", nodesep=0.1, ranksep=0.1).solve(scene)

        for edge in scene.edges:
            assert edge.label_pos is not None
            lx, ly = edge.label_pos
            for node in scene.nodes:
                overlap_x = abs(lx - node.x) < (edge.label_width + node.width) / 2
                overlap_y = abs(ly - node.y) < (edge.label_height + node.height) / 2
                assert not (overlap_x and overlap_y), f"label of {edge.src}->{edge.dst} overlaps node {node.id}"

    def test_edge_labels_paint_above_nodes(self, tmp_path):
        root = ET.fromstring(_render(FIXTURE, tmp_path))
        order = [g.get("class", "") for g in root.iter(f"{SVG_NS}g")]
        labels = [i for i, c in enumerate(order) if "usv-edge-label" in c.split()]
        nodes = [i for i, c in enumerate(order) if "usv-node" in c.split()]
        assert labels and nodes
        assert min(labels) > max(nodes)


class TestEngineGuards:
    """Engine/style guards do not render, so they run without the dot binary."""

    def test_graphviz_preset_rejected_under_svg_engine(self, tmp_path):
        with pytest.raises(StyleEngineMismatchError):
            _render(FIXTURE, tmp_path, styleid="ag_default")

    def test_svg_preset_rejected_under_graphviz_engine(self):
        with pytest.raises(StyleEngineMismatchError):
            AttackGraphs(FIXTURE, "unused", styleid="sv_default", render_engine="graphviz").load()

    def test_complexity_guard_runs_before_layout(self, monkeypatch, tmp_path):
        # The SVG engine skips _render_impl, so the shared graph painter must
        # enforce check_graph_complexity itself. Patch it to raise and confirm
        # the render trips it before the dot-requiring layout runs (so this
        # test needs no dot binary).
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


@requires_dot
class TestIcons:
    def test_icon_template_embeds_images(self, tmp_path):
        # The SVG engine used to ignore `image`, drawing plain cards only.
        template = str(TEMPLATE_DIR / "cloud_icons.toml")
        ag = _loaded(template)
        expected = sum(
            1
            for section in ("hosts", "vulnerabilities", "privileges", "services")
            for item in ag.inputdata.get(section, {}).values()
            if isinstance(item, dict) and item.get("image")
        )
        assert expected > 0
        root = ET.fromstring(_render(template, tmp_path))
        images = [el for el in root.iter(f"{SVG_NS}image") if el.get("href", "").startswith("data:image/")]
        assert len(images) == expected


# =============================================================================
# "Confirmed by N sources" badge (findings merged from several tools)
# =============================================================================

MULTI_SOURCE = """
[graph]
name = "Merged findings"

[hosts.web01]
label = "web01"
sources = ["nmap", "masscan"]

[vulnerabilities.cve1]
label = "CVE-2021-41773"
host = "web01"
cvss = 9.8
sources = ["nuclei", "nessus", "nmap"]

[vulnerabilities.cve2]
label = "Weak TLS"
host = "web01"
cvss = 5.3
sources = ["sslscan"]

[privileges.root]
label = "root on web01"
source_count = 2
"""


@pytest.fixture
def multi_source(tmp_path):
    path = tmp_path / "multi.toml"
    path.write_text(MULTI_SOURCE, encoding="utf-8")
    return str(path)


def _source_badges(svg: str) -> list[str]:
    root = ET.fromstring(svg)
    return sorted(
        g.get("data-value") for g in root.iter(f"{SVG_NS}g") if "usv-badge--sources" in g.get("class", "").split()
    )


@requires_dot
class TestSourcesBadge:
    def test_badge_only_for_two_or_more_sources(self, multi_source, tmp_path):
        assert _source_badges(_render(multi_source, tmp_path)) == ["✓2", "✓2", "✓3"]

    def test_nodes_carry_source_data(self, multi_source, tmp_path):
        root = ET.fromstring(_render(multi_source, tmp_path))
        nodes = {g.get("data-node-id"): g for g in root.iter(f"{SVG_NS}g") if "usv-node" in g.get("class", "").split()}
        assert nodes["cve1"].get("data-sources") == "nuclei,nessus,nmap"
        assert nodes["cve1"].get("data-source-count") == "3"
        assert nodes["cve2"].get("data-source-count") == "1"
        assert nodes["root"].get("data-source-count") == "2" and nodes["root"].get("data-sources") is None

    def test_templates_without_sources_have_no_badge(self, tmp_path):
        assert _source_badges(_render(FIXTURE, tmp_path)) == []

    def test_theme_can_turn_it_off(self, multi_source, tmp_path, monkeypatch):
        from usecvislib.svgengine import themes

        original = themes.resolve

        def resolve(style):
            theme = original(style)
            theme["badges"]["sources"] = False
            return theme

        monkeypatch.setattr(themes, "resolve", resolve)
        assert _source_badges(_render(multi_source, tmp_path)) == []


def test_graphviz_label_names_the_source_count(multi_source):
    # The Graphviz path writes the count into the label (no dot needed to check the source)
    ag = AttackGraphs(multi_source, "unused")
    ag.load()
    ag.render()
    source = ag.graph.source
    assert source.count("✓ 2 sources") == 2 and source.count("✓ 3 sources") == 1
    assert "sslscan" not in source and "source_count" not in source  # data fields are not node attributes
