#
# VULNEX -Universal Security Visualization Library-
#
# File: test_killchain.py
# Author: Simon Roses Femerling
# Created: 2026-08-09
# Last Modified: 2026-08-09
# Version: 0.4.1
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Tests for the Kill Chain / MITRE ATT&CK module (CLI mode 9)."""

import glob
import json
import shutil
import xml.etree.ElementTree as ET
from itertools import pairwise
from pathlib import Path

import pytest

from usecvislib.killchain import (
    ATTACK_TACTIC_ORDER,
    KILL_CHAIN_ORDER,
    IncidentMapping,
    KillChain,
    KillChainError,
    Technique,
)

TESTS_DIR = Path(__file__).parent
TEMPLATES = sorted(glob.glob(str(TESTS_DIR.parent / "templates" / "kill-chains" / "*")))
APT = str(TESTS_DIR.parent / "templates" / "kill-chains" / "apt_intrusion.tml")
RANSOM = str(TESTS_DIR.parent / "templates" / "kill-chains" / "ransomware_attack.tml")
INSIDER = str(TESTS_DIR.parent / "templates" / "kill-chains" / "insider_exfiltration.tml")
SVG_NS = "{http://www.w3.org/2000/svg}"


def _render_svg(inputfile, tmp_path, styleid="", name="out"):
    kc = KillChain(inputfile, str(tmp_path / name), format="svg", styleid=styleid, render_engine="svg")
    kc.build()
    return (tmp_path / f"{name}.svg").read_text(encoding="utf-8")


class TestModel:
    def test_coverage_score(self):
        assert Technique("T1", "n", "Delivery").coverage_score == 0.0
        assert Technique("T1", "n", "Delivery", detected=True).coverage_score == 0.5
        assert Technique("T1", "n", "Delivery", detected=True, mitigated=True).coverage_score == 1.0

    def test_framework_axes(self, tmp_path):
        kc = KillChain(APT, str(tmp_path / "o"), render_engine="svg")
        kc.load()
        assert kc.framework == "kill_chain"
        assert kc.phase_order == KILL_CHAIN_ORDER

        kc2 = KillChain(RANSOM, str(tmp_path / "o2"), render_engine="svg")
        kc2.load()
        assert kc2.framework == "attack"
        assert kc2.phase_order == ATTACK_TACTIC_ORDER

        kc3 = KillChain(INSIDER, str(tmp_path / "o3"), render_engine="svg")
        kc3.load()
        assert kc3.framework == "custom"
        assert kc3.phase_order == ["Access", "Collection", "Staging", "Exfiltration", "Cover Tracks"]

    def test_custom_without_phases_errors(self, tmp_path):
        bad = tmp_path / "bad.tml"
        bad.write_text('[killchain]\nname="x"\nframework="custom"\n[techniques."A"]\nname="a"\nphase="P"\n')
        with pytest.raises(KillChainError):
            KillChain(str(bad), str(tmp_path / "o"), render_engine="svg").load()

    def test_phase_aliases_and_case(self, tmp_path):
        src = tmp_path / "alias.tml"
        src.write_text(
            '[killchain]\nname="x"\nframework="kill_chain"\n'
            '[techniques."A"]\nname="a"\nphase="recon"\n'
            '[techniques."B"]\nname="b"\nphase="c2"\n'
            '[techniques."C"]\nname="c"\nphase="DELIVERY"\n'
        )
        kc = KillChain(str(src), str(tmp_path / "o"), render_engine="svg")
        kc.load()
        assert kc.techniques["A"].phase == "Reconnaissance"
        assert kc.techniques["B"].phase == "Command and Control"
        assert kc.techniques["C"].phase == "Delivery"

    def test_unknown_phase_warns_and_falls_back(self, tmp_path):
        src = tmp_path / "unk.tml"
        src.write_text('[killchain]\nname="x"\n[techniques."A"]\nname="a"\nphase="Nonsense"\n')
        kc = KillChain(str(src), str(tmp_path / "o"), render_engine="svg")
        kc.load()
        assert kc.techniques["A"].phase == KILL_CHAIN_ORDER[0]
        assert any("Nonsense" in w for w in kc.warnings)

    def test_stats_and_coverage(self, tmp_path):
        kc = KillChain(APT, str(tmp_path / "o"), render_engine="svg")
        kc.load()
        stats = kc.get_stats()
        assert stats["total_techniques"] == 10
        assert stats["framework"] == "kill_chain"
        assert 0.0 < stats["detection_coverage"] <= 1.0
        assert len(stats["active_phases"]) == 7

    def test_coverage_gap_analysis(self, tmp_path):
        kc = KillChain(APT, str(tmp_path / "o"), render_engine="svg")
        kc.load()
        gaps = kc.analyze_coverage_gaps()
        assert "T1589" in gaps["undetected"]  # detected=false in template
        assert "T1203" in gaps["critical_gaps"]  # critical + no coverage

    def test_validate_flags_unknown_incident_technique(self, tmp_path):
        src = tmp_path / "inc.tml"
        src.write_text(
            '[killchain]\nname="x"\n[techniques."A"]\nname="a"\nphase="Delivery"\n'
            '[[incidents]]\nid="I1"\nname="i"\ntechniques=["A","GHOST"]\n'
        )
        kc = KillChain(str(src), str(tmp_path / "o"), render_engine="svg")
        kc.load()
        errors = kc.validate()
        assert any("GHOST" in e for e in errors)


class TestSvgEngine:
    @pytest.fixture(autouse=True)
    def _require_cairosvg(self):
        pytest.importorskip("cairosvg")

    @pytest.mark.parametrize("template", TEMPLATES, ids=[Path(t).stem for t in TEMPLATES])
    def test_template_renders(self, tmp_path, template):
        ET.fromstring(_render_svg(template, tmp_path))  # valid SVG

    def test_phase_headers_present_and_ordered(self, tmp_path):
        root = ET.fromstring(_render_svg(APT, tmp_path))
        phases = [g.get("data-phase") for g in root.iter(f"{SVG_NS}g") if "usv-phase" in g.get("class", "").split()]
        assert phases == KILL_CHAIN_ORDER  # all 7, in order

    def test_technique_cards_carry_coverage(self, tmp_path):
        root = ET.fromstring(_render_svg(APT, tmp_path))
        techs = [g for g in root.iter(f"{SVG_NS}g") if "usv-node--technique" in g.get("class", "").split()]
        assert len(techs) == 10
        covers = {g.get("data-coverage") for g in techs}
        assert covers <= {"covered", "partial", "gap"}
        assert "covered" in covers and "gap" in covers  # template has both

    def test_flow_and_incident_edges(self, tmp_path):
        root = ET.fromstring(_render_svg(APT, tmp_path))
        flows = [g for g in root.iter(f"{SVG_NS}g") if "usv-flow" in g.get("class", "").split()]
        assert len(flows) == 6  # 7 phases -> 6 connectors
        incidents = [g for g in root.iter(f"{SVG_NS}g") if "usv-edge--incident" in g.get("class", "").split()]
        assert len(incidents) == 5  # 6-technique path -> 5 edges

    @pytest.mark.parametrize("template", TEMPLATES, ids=[Path(t).stem for t in TEMPLATES])
    def test_flow_lines_never_pass_behind_unrelated_cards(self, tmp_path, template):
        # Regression: cards stacked in declared order put e.g. T1547.001 on
        # the T1059.001 -> T1055 line, so it looked connected. With the shared
        # row planner, flows run straight along their row through empty slots.
        from usecvislib.utils import sanitize_node_id

        root = ET.fromstring(_render_svg(template, tmp_path))
        cards = {}
        for g in root.iter(f"{SVG_NS}g"):
            if "usv-node--technique" in g.get("class", "").split():
                rect = g.find(f"{SVG_NS}rect")
                x, y, w, h = (float(rect.get(k)) for k in ("x", "y", "width", "height"))
                cards[g.get("data-node-id")] = (x, y, x + w, y + h)
        for g in root.iter(f"{SVG_NS}g"):
            if "usv-edge--incident" not in g.get("class", "").split():
                continue
            src, dst = sanitize_node_id(g.get("data-from")), sanitize_node_id(g.get("data-to"))
            (sx1, sy1, sx2, sy2), (dx1, dy1, dx2, dy2) = cards[src], cards[dst]
            if (sx1 + sx2) / 2 == pytest.approx((dx1 + dx2) / 2):
                continue  # same-phase step: vertical, covered separately
            line_y = (sy1 + sy2) / 2
            assert line_y == pytest.approx((dy1 + dy2) / 2), f"{src} -> {dst} should run straight"
            for other, (ox1, oy1, ox2, oy2) in cards.items():
                if other in (src, dst):
                    continue
                between = ox1 < max(dx1, sx1) and ox2 > min(sx2, dx2)
                assert not (between and oy1 < line_y < oy2), f"{src} -> {dst} passes behind {other}"

    def test_same_phase_step_is_side_bracket(self, tmp_path):
        # A vertical arrow in the gap between stacked cards was only a few px
        # long; the step now brackets the cards' left edges.
        import re

        root = ET.fromstring(_render_svg(RANSOM, tmp_path))
        edge = next(g for g in root.iter(f"{SVG_NS}g") if g.get("data-from") == "T1490" and g.get("data-to") == "T1486")
        nums = [float(v) for v in re.findall(r"-?\d+(?:\.\d+)?", edge.find(f"{SVG_NS}path").get("d"))]
        xs, ys = nums[0::2], nums[1::2]
        assert min(xs) < xs[0], "bracket runs out to the left of the cards"
        assert ys[-1] - ys[0] > 30, "T1486 sits well below T1490 (not a few-px stub)"

    def test_coverage_legend_present(self, tmp_path):
        content = _render_svg(APT, tmp_path)
        assert "usv-legend" in content and "D = detected" in content

    def test_no_active_content(self, tmp_path):
        content = _render_svg(APT, tmp_path)
        assert "<script" not in content and "onclick" not in content
        assert 'data-usv-engine="svg"' in content

    def test_deterministic(self, tmp_path):
        assert _render_svg(APT, tmp_path, name="a") == _render_svg(APT, tmp_path, name="b")

    def test_png_output(self, tmp_path):
        KillChain(APT, str(tmp_path / "o"), format="png", render_engine="svg").build()
        assert (tmp_path / "o.png").read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"


class TestGraphvizEngine:
    def test_render_builds_phase_clusters(self, tmp_path):
        kc = KillChain(APT, str(tmp_path / "o"), format="svg", styleid="kc_default")
        kc.load()
        kc.render()
        src = kc.dot.source
        assert src.count("subgraph cluster_") == 7
        assert "T1566" in src

    def test_technique_nodes_live_inside_their_cluster(self, tmp_path):
        # Regression: nodes were added to the root graph, so every technique
        # piled into one column instead of its phase cluster.
        kc = KillChain(APT, str(tmp_path / "o"), format="svg", styleid="kc_default")
        kc.load()
        kc.render()
        src = kc.dot.source
        # The Delivery technique T1566 must appear within the Delivery cluster
        # block, not at the root graph level.
        delivery_start = src.index("subgraph cluster_Delivery")
        next_cluster = src.index("subgraph cluster_", delivery_start + 1)
        assert "T1566" in src[delivery_start:next_cluster]

    def test_labels_are_html_and_not_bracket_codes(self, tmp_path):
        kc = KillChain(APT, str(tmp_path / "o"), format="svg", styleid="kc_default")
        kc.load()
        kc.render()
        src = kc.dot.source
        assert "<TABLE" in src  # HTML-like labels
        assert "Detected + Mitigated" in src  # readable coverage line
        assert "[D-]" not in src and "[DM]" not in src  # no cryptic codes

    def test_phases_get_equal_slot_counts(self, tmp_path):
        # Every phase cluster holds the same number of row slots (techniques
        # plus invisible placeholders) so the phase boxes align.
        kc = KillChain(RANSOM, str(tmp_path / "o"), format="svg", styleid="kc_default")
        kc.load()
        kc.render()
        blocks = kc.dot.source.split("subgraph cluster_")[1:]
        counts = {block.count("[label=") for block in blocks}
        assert len(counts) == 1

    def test_skip_edges_thread_through_placeholders(self, tmp_path):
        kc = KillChain(APT, str(tmp_path / "o"), format="svg", styleid="kc_default")
        kc.load()
        kc.render()
        src = kc.dot.source
        # T1595 (Reconnaissance) -> T1566 (Delivery) skips Weaponization:
        # it must route through a Weaponization placeholder slot.
        assert "T1595 -> __slot_Weaponization_" in src

    @pytest.mark.skipif(shutil.which("dot") is None, reason="requires the Graphviz dot binary")
    @pytest.mark.parametrize("template", TEMPLATES, ids=[Path(t).stem for t in TEMPLATES])
    def test_phase_boxes_align_and_flows_run_straight(self, tmp_path, template):
        kc = KillChain(template, str(tmp_path / "o"), format="svg", styleid="kc_default")
        kc.load()
        kc.render()
        layout = json.loads(kc.dot.pipe("json0"))
        boxes = [o["bb"] for o in layout["objects"] if o.get("name", "").startswith("cluster_")]
        tops = {round(float(bb.split(",")[3]), 1) for bb in boxes}
        bottoms = {round(float(bb.split(",")[1]), 1) for bb in boxes}
        assert len(tops) == 1 and len(bottoms) == 1, "phase boxes must share top and bottom"
        y = {o["name"]: float(o["pos"].split(",")[1]) for o in layout["objects"] if "pos" in o}
        # Every shipped template's incident is a forward chain: each flow edge
        # (including through skipped phases) must be one horizontal line.
        phase_of = {tech.id: tech.phase for tech in kc.techniques.values()}
        for incident in kc.incidents:
            for src, dst in pairwise(incident.techniques):
                if phase_of[src] != phase_of[dst]:  # same-phase steps are vertical
                    assert y[src] == pytest.approx(y[dst]), f"{src} -> {dst} should run straight"
        names = {o["_gvid"]: o["name"] for o in layout["objects"]}
        for edge in layout["edges"]:
            tail, head = names[edge["tail"]], names[edge["head"]]
            if edge.get("style") != "invis" and phase_of.get(tail, tail) != phase_of.get(head, head):
                ys = {round(float(p.split(",")[1]), 1) for p in edge["pos"].removeprefix("e,").split()}
                assert len(ys) == 1, "flow edges must not dip (no off-center parallel edges)"

    def test_pass_through_placeholder_bridges_the_line(self, tmp_path):
        kc = KillChain(APT, str(tmp_path / "o"), format="svg", styleid="kc_default")
        kc.load()
        kc.render()
        src = kc.dot.source
        bridge = next(line for line in src.splitlines() if line.strip().startswith("__slot_Weaponization_0 "))
        assert "fixedsize=shape" in bridge and "style=filled" in bridge
        filler = next(line for line in src.splitlines() if line.strip().startswith("__slot_Delivery_1 "))
        assert "style=invis" in filler

    def test_same_phase_step_stays_stacked(self, tmp_path):
        # T1490 -> T1486 are both Impact: a ranking edge would open a new
        # column inside the Impact box, so it must not constrain ranks.
        kc = KillChain(RANSOM, str(tmp_path / "o"), format="svg", styleid="kc_default")
        kc.load()
        kc.render()
        edge = next(line for line in kc.dot.source.splitlines() if line.strip().startswith("T1490 -> T1486"))
        assert "constraint=false" in edge

    def test_svg_preset_rejected_on_graphviz(self, tmp_path):
        from usecvislib.svgengine import StyleEngineMismatchError

        with pytest.raises(StyleEngineMismatchError):
            KillChain(APT, str(tmp_path / "o"), styleid="sv_default", render_engine="graphviz")


class TestCli:
    def test_cli_svg_mode9(self, tmp_path):
        from usecvislib import usecvis

        rc = usecvis.main(["-i", APT, "-o", str(tmp_path / "c"), "-f", "svg", "-m", "9", "--render-engine", "svg"])
        assert rc == 0
        assert 'data-usv-engine="svg"' in (tmp_path / "c.svg").read_text(encoding="utf-8")

    def test_cli_rejects_svg_for_unsupported_mode(self, tmp_path):
        from usecvislib import usecvis

        with pytest.raises(SystemExit) as exc:
            usecvis.main(["-i", APT, "-o", str(tmp_path / "x"), "-m", "1", "--render-engine", "svg"])
        assert exc.value.code == 2


def test_incident_dataclass_defaults():
    inc = IncidentMapping(incident_id="I", name="n")
    assert inc.techniques == [] and inc.threat_actor is None


class TestBuilder:
    def test_builder_roundtrips_through_kill_chain(self, tmp_path):
        from usecvislib import KillChainBuilder

        builder = (
            KillChainBuilder("Built Chain", framework="kill_chain")
            .add_technique("T1", "Scan", "Reconnaissance", detected=True)
            .add_technique("T2", "Phish", "Delivery", severity="high", detected=True, mitigated=True)
            .add_incident("I1", ["T1", "T2"], name="Path")
        )
        data = builder.build()
        assert data["killchain"]["framework"] == "kill_chain"
        assert set(data["techniques"]) == {"T1", "T2"}

        kc = builder.to_kill_chain(str(tmp_path / "b"), format="svg", render_engine="svg")
        kc.build()
        stats = kc.get_stats()
        assert stats["total_techniques"] == 2
        assert stats["total_incidents"] == 1
        assert (tmp_path / "b.svg").exists()

    def test_builder_custom_framework_phases(self):
        from usecvislib import KillChainBuilder

        data = KillChainBuilder("Custom", framework="custom", phases=["A", "B"]).build()
        assert data["killchain"]["phases"] == ["A", "B"]


class TestSvgCardText:
    def test_partial_coverage_cards_use_dark_text(self, tmp_path):
        # White text on the amber "partial" card read at about 2:1.
        import xml.etree.ElementTree as ET

        ns = "{http://www.w3.org/2000/svg}"
        root = ET.fromstring(_render_svg(APT, tmp_path))
        partial = [g for g in root.iter(f"{ns}g") if "usv-cover--partial" in g.get("class", "").split()]
        assert partial, "fixture should have partially covered techniques"
        for g in partial:
            fills = {t.get("fill") for t in g.iter(f"{ns}text")}
            assert fills == {"#1f2937"}
