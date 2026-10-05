#
# VULNEX -Universal Security Visualization Library-
#
# File: test_svg_attacktrees.py
# Author: Simon Roses Femerling
# Created: 2026-08-08
# Last Modified: 2026-08-08
# Version: 0.4.1
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Tests for the Attack Trees SVG painter (pilot module)."""

import glob
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from usecvislib.attacktrees import AttackTrees

TESTS_DIR = Path(__file__).parent
FIXTURE = str(TESTS_DIR / "enterattacktrees.tml")
TEMPLATES = sorted(glob.glob(str(TESTS_DIR.parent / "templates" / "attack-trees" / "*")))
SVG_PRESETS = ["sv_default", "sv_dark", "sv_neon", "sv_corporate", "sv_minimal"]
SVG_NS = "{http://www.w3.org/2000/svg}"

VALID_SEVERITIES = {"critical", "high", "medium", "low", "none"}


def _render(inputfile: str, tmp_path, styleid: str = "", name: str = "out") -> str:
    at = AttackTrees(inputfile, str(tmp_path / name), format="svg", styleid=styleid, render_engine="svg")
    at.build()
    return (tmp_path / f"{name}.svg").read_text(encoding="utf-8")


class TestPresets:
    @pytest.mark.parametrize("preset", SVG_PRESETS)
    def test_fixture_renders_in_preset(self, tmp_path, preset):
        content = _render(FIXTURE, tmp_path, styleid=preset)
        root = ET.fromstring(content)
        assert root.get("data-usv-theme") == preset


class TestTemplates:
    @pytest.mark.parametrize("template", TEMPLATES, ids=[Path(t).stem for t in TEMPLATES])
    def test_template_renders_unmodified(self, tmp_path, template):
        content = _render(template, tmp_path)
        ET.fromstring(content)  # valid XML/SVG


class TestInteractivityContract:
    def test_node_groups_carry_contract(self, tmp_path):
        root = ET.fromstring(_render(FIXTURE, tmp_path))
        node_groups = [g for g in root.iter(f"{SVG_NS}g") if "usv-node" in g.get("class", "").split()]
        assert len(node_groups) == 13  # fixture node count
        for g in node_groups:
            assert g.get("data-node-id"), "every node needs data-node-id"
            assert g.get("data-label"), "every node needs data-label"

    def test_severity_classes_are_canonical(self, tmp_path):
        root = ET.fromstring(_render(FIXTURE, tmp_path))
        seen = set()
        for g in root.iter(f"{SVG_NS}g"):
            for cls in g.get("class", "").split():
                if cls.startswith("usv-sev--"):
                    seen.add(cls.removeprefix("usv-sev--"))
        assert seen  # fixture has CVSS-scored nodes
        assert seen <= VALID_SEVERITIES

    def test_edge_groups_carry_contract(self, tmp_path):
        root = ET.fromstring(_render(FIXTURE, tmp_path))
        edges = [g for g in root.iter(f"{SVG_NS}g") if "usv-edge" in g.get("class", "").split()]
        assert len(edges) == 12  # fixture edge count
        for g in edges:
            assert g.get("data-from") and g.get("data-to")

    def test_badges_present_for_cvss_nodes(self, tmp_path):
        root = ET.fromstring(_render(FIXTURE, tmp_path))
        badges = [g for g in root.iter(f"{SVG_NS}g") if "usv-badge" in g.get("class", "").split()]
        assert len(badges) == 9  # fixture nodes with cvss or cvss_vector
        for b in badges:
            assert b.get("data-value")

    def test_no_active_content(self, tmp_path):
        content = _render(FIXTURE, tmp_path)
        assert "<script" not in content
        assert "foreignObject" not in content
        assert "onclick" not in content and "onload" not in content
        assert "url(http" not in content
        assert "@import" not in content


class TestSemantics:
    def test_template_overrides_honored_on_default_preset_only(self, tmp_path):
        default = _render(FIXTURE, tmp_path, styleid="sv_default", name="d")
        dark = _render(FIXTURE, tmp_path, styleid="sv_dark", name="k")
        # fixture sets color="lightblue" on "Learn Combo" (no CVSS)
        assert "lightblue" in default
        assert "lightblue" not in dark

    def test_cvss_label_annotation_mirrors_graphviz(self, tmp_path):
        content = _render(FIXTURE, tmp_path)
        assert "(CVSS: 5.5 - Medium)" in content  # explicit cvss value
        assert "(CVSS: 4.2 - Medium)*" in content  # vector-derived score marked with *

    def test_dashed_edge_override(self, tmp_path):
        root = ET.fromstring(_render(FIXTURE, tmp_path))
        dashed = [p for p in root.iter(f"{SVG_NS}path") if p.get("stroke-dasharray")]
        assert len(dashed) == 1  # one dashed edge in fixture
        assert dashed[0].get("stroke") == "red"

    def test_lr_orientation(self, tmp_path):
        src = Path(FIXTURE).read_text(encoding="utf-8")
        lr_file = tmp_path / "lr.tml"
        lr_file.write_text(src.replace('root = "Open Safe"', 'root = "Open Safe"\nparams = {rankdir = "LR"}'))
        root = ET.fromstring(_render(str(lr_file), tmp_path, name="lr"))
        nodes = {g.get("data-label"): g for g in root.iter(f"{SVG_NS}g") if "usv-node" in g.get("class", "").split()}
        assert nodes  # rendered; layout invariants covered in test_svgengine

    def test_deterministic_across_runs(self, tmp_path):
        one = _render(FIXTURE, tmp_path, name="one")
        two = _render(FIXTURE, tmp_path, name="two")
        assert one == two


class TestRasterOutputs:
    @pytest.fixture(autouse=True)
    def _require_cairosvg(self):
        pytest.importorskip("cairosvg")

    def test_png_output(self, tmp_path):
        AttackTrees(FIXTURE, str(tmp_path / "o"), format="png", render_engine="svg").build()
        assert (tmp_path / "o.png").read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"

    def test_pdf_output(self, tmp_path):
        AttackTrees(FIXTURE, str(tmp_path / "o"), format="pdf", render_engine="svg").build()
        assert (tmp_path / "o.pdf").read_bytes()[:5] == b"%PDF-"


class TestCli:
    def test_cli_svg_engine_end_to_end(self, tmp_path):
        from usecvislib import usecvis

        rc = usecvis.main(
            ["-i", FIXTURE, "-o", str(tmp_path / "cli"), "-f", "svg", "-m", "0", "--render-engine", "svg"]
        )
        assert rc == 0
        assert 'data-usv-engine="svg"' in (tmp_path / "cli.svg").read_text(encoding="utf-8")

    def test_cli_rejects_invalid_engine(self, tmp_path):
        from usecvislib import usecvis

        with pytest.raises(SystemExit) as exc:
            usecvis.main(["-i", FIXTURE, "-o", str(tmp_path / "x"), "--render-engine", "webgl"])
        assert exc.value.code == 2

    def test_cli_rejects_svg_engine_for_other_modes(self, tmp_path):
        from usecvislib import usecvis

        with pytest.raises(SystemExit) as exc:
            usecvis.main(["-i", FIXTURE, "-o", str(tmp_path / "x"), "-m", "1", "--render-engine", "svg"])
        assert exc.value.code == 2

    def test_cli_rejects_shine_with_svg_engine(self, tmp_path):
        from usecvislib import usecvis

        with pytest.raises(SystemExit) as exc:
            usecvis.main(["-i", FIXTURE, "-o", str(tmp_path / "x"), "-f", "svg", "--render-engine", "svg", "--shine"])
        assert exc.value.code == 2


class TestImageNodes:
    ICONS_TEMPLATE = str(TESTS_DIR.parent / "templates" / "attack-trees" / "aws_cloud_security_icons.toml")

    def test_icons_embedded_as_data_uris(self, tmp_path):
        content = _render(self.ICONS_TEMPLATE, tmp_path)
        assert content.count("data:image/") >= 3
        # Self-contained: no local filesystem or external references leak
        assert "/Users/" not in content and "file:" not in content and "url(http" not in content

    def test_image_nodes_render_plain_with_page_text(self, tmp_path):
        root = ET.fromstring(_render(self.ICONS_TEMPLATE, tmp_path))
        image_nodes = [
            g
            for g in root.iter(f"{SVG_NS}g")
            if "usv-node" in g.get("class", "").split() and g.find(f"{SVG_NS}image") is not None
        ]
        assert image_nodes
        for g in image_nodes:
            # Icon nodes have no card body (Graphviz parity: attrs cleared)
            assert g.find(f"{SVG_NS}rect") is None
            # Template fontcolor="white" is ignored for icon nodes; text
            # uses the page contrast color instead
            for text in g.iter(f"{SVG_NS}text"):
                assert text.get("fill") != "white"

    def test_image_failure_degrades_gracefully(self, tmp_path):
        src = (
            Path(FIXTURE)
            .read_text(encoding="utf-8")
            .replace(
                '"Pick Lock" = { style="filled", shape="box",',
                '"Pick Lock" = { image="bundled:no/such/icon", style="filled", shape="box",',
                1,
            )
        )
        broken = tmp_path / "broken_icon.tml"
        broken.write_text(src)
        content = _render(str(broken), tmp_path, name="broken")
        assert "data:image/" not in content  # icon skipped, node still rendered
        assert "Pick Lock" in content


class TestDagRoutingAndLayout:
    """Collector rails, barycenter placement, chain alignment, edge labels."""

    INSIDER = str(TESTS_DIR.parent / "templates" / "attack-trees" / "insider_threat.tml")
    RANSOMWARE = str(TESTS_DIR.parent / "templates" / "attack-trees" / "ransomware_attack.tml")
    NETINFRA = str(TESTS_DIR.parent / "templates" / "attack-trees" / "network_infrastructure_with_icons.toml")

    @staticmethod
    def _node_centers(root) -> dict:
        centers = {}
        for g in root.iter(f"{SVG_NS}g"):
            if "usv-node" not in g.get("class", "").split():
                continue
            rect = g.find(f"{SVG_NS}rect")
            polygon = g.find(f"{SVG_NS}polygon")
            if rect is not None:
                centers[g.get("data-label")] = float(rect.get("x")) + float(rect.get("width")) / 2
            elif polygon is not None:  # chamfer/diamond bodies
                xs = [float(point.split(",")[0]) for point in polygon.get("points").split()]
                centers[g.get("data-label")] = (min(xs) + max(xs)) / 2
        return centers

    def test_one_collector_rail_and_one_arrow_per_sink(self, tmp_path):
        root = ET.fromstring(_render(self.INSIDER, tmp_path))
        merges = [g for g in root.iter(f"{SVG_NS}g") if "usv-rail--merge" in g.get("class", "").split()]
        assert sorted(g.get("data-to") for g in merges) == [
            "Business Disruption",
            "Competitor Advantage",
            "Sell Data",
        ]
        for g in merges:
            arrowed = [p for p in g.iter(f"{SVG_NS}path") if p.get("marker-end")]
            assert len(arrowed) == 1, "each sink gets exactly one arrowed stem"
        # Parents whose children all feed shared sinks must not keep private
        # per-parent rails (the old behavior stacked four parallel rails)
        plain_rails = {g.get("data-from") for g in root.iter(f"{SVG_NS}g") if g.get("class") == "usv-rail"}
        assert plain_rails.isdisjoint({"Copy to USB", "Email to Personal", "Cloud Upload", "Screenshot/Photo"})

    def test_crossings_get_junction_dots_or_hops(self, tmp_path):
        """Lines passing through a rail are disambiguated: dot if joined, gap if crossed."""
        root = ET.fromstring(_render(self.INSIDER, tmp_path))
        centers = self._node_centers(root)

        def groups(cls):
            return [g for g in root.iter(f"{SVG_NS}g") if g.get("class") == cls]

        dot_xs = sorted(float(g.find(f"{SVG_NS}circle").get("cx")) for g in groups("usv-junction"))
        # Leaves feeding BOTH Sell Data and Competitor Advantage pass through the
        # upper rail on their way to the lower one (Copy to USB joins at a rail end).
        expected_dots = sorted(centers[n] for n in ("Email to Personal", "Cloud Upload", "Screenshot/Photo"))
        assert dot_xs == pytest.approx(expected_dots, abs=0.05)

        hop_xs = sorted(float(g.findall(f"{SVG_NS}path")[1].get("d").split()[1]) for g in groups("usv-hop"))
        # Modify Records only feeds Business Disruption and crosses the Sell Data
        # rail; the Sell Data stem crosses the Competitor Advantage rail.
        expected_hops = sorted([centers["Modify Records"], centers["Sell Data"]])
        assert hop_xs == pytest.approx(expected_hops, abs=0.05)

    def test_pure_tree_has_no_crossing_markers(self, tmp_path):
        content = _render(self.RANSOMWARE, tmp_path)
        assert "usv-junction" not in content and "usv-hop" not in content

    def test_multi_parent_sinks_sit_at_parent_barycenter(self, tmp_path):
        from usecvislib import utils

        data = utils.ReadConfigFile(self.INSIDER)
        parents: dict = {}
        for parent, kids in data["edges"].items():
            for kid in kids:
                parents.setdefault(kid["to"], []).append(parent)
        centers = self._node_centers(ET.fromstring(_render(self.INSIDER, tmp_path)))
        for sink, sink_parents in parents.items():
            if len(sink_parents) < 2:
                continue
            bary = sum(centers[p] for p in sink_parents) / len(sink_parents)
            assert abs(centers[sink] - bary) < 1.0, f"{sink} not centered under its parents"

    def test_single_child_chain_stays_straight(self, tmp_path):
        centers = self._node_centers(ET.fromstring(_render(self.RANSOMWARE, tmp_path)))
        assert abs(centers["Deploy Ransomware"] - centers["Initial Access"]) < 0.01
        spine = [centers[n] for n in ("Execution", "Lateral Movement", "Data Exfiltration", "Encrypt Files")]
        assert max(spine) - min(spine) < 0.01

    def test_edge_labels_rendered_with_halo(self, tmp_path):
        root = ET.fromstring(_render(self.NETINFRA, tmp_path))
        labels = [g for g in root.iter(f"{SVG_NS}g") if g.get("class") == "usv-edge-label"]
        assert len(labels) == 10  # 3x OR + 7 severity labels in the template
        seen = []
        for g in labels:
            texts = list(g.iter(f"{SVG_NS}text"))
            # Halo copy under the fill copy (paint-order is not portable)
            assert len(texts) == 2 and texts[0].text == texts[1].text
            seen.append(texts[1].text)
        assert sorted(seen) == ["CRITICAL", "HIGH", "HIGH", "HIGH", "HIGH", "HIGH", "MEDIUM", "OR", "OR", "OR"]

    def test_gate_chips_rendered(self, tmp_path):
        root = ET.fromstring(_render(self.NETINFRA, tmp_path))
        chips = [g for g in root.iter(f"{SVG_NS}g") if "usv-badge--gate" in g.get("class", "").split()]
        assert [g.get("data-value") for g in chips] == ["OR", "OR", "OR"]  # the three tier nodes

    def test_octagon_maps_to_chamfer_card(self, tmp_path):
        root = ET.fromstring(_render(self.INSIDER, tmp_path))
        chamfers = [
            g
            for g in root.iter(f"{SVG_NS}g")
            if "usv-node" in g.get("class", "").split() and g.find(f"{SVG_NS}polygon") is not None
        ]
        # The three octagon outcome nodes keep a distinct (cut-corner) body
        assert sorted(g.get("data-label") for g in chamfers) == [
            "Business Disruption",
            "Competitor Advantage",
            "Sell Data",
        ]

    def test_row_gaps_adapt_to_band_complexity(self, tmp_path):
        root = ET.fromstring(_render(self.RANSOMWARE, tmp_path))
        tops: dict = {}
        bottoms: dict = {}
        for g in root.iter(f"{SVG_NS}g"):
            if "usv-node" not in g.get("class", "").split():
                continue
            body = g.find(f"{SVG_NS}rect")
            if body is None:
                body = g.find(f"{SVG_NS}polygon")
                ys = [float(p.split(",")[1]) for p in body.get("points").split()]
                top, bottom = min(ys), max(ys)
            else:
                top = float(body.get("y"))
                bottom = top + float(body.get("height"))
            tops[g.get("data-label")] = top
            bottoms[g.get("data-label")] = bottom
        # Simple chain band: one track, compressed well below the 76px v_gap
        assert tops["Encrypt Files"] - bottoms["Data Exfiltration"] < 60
        # Merge band into Execution still gets room for its rail
        assert tops["Execution"] - bottoms["Malicious Attachment"] >= 36
