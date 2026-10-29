#
# VULNEX -Universal Security Visualization Library-
#
# File: test_inferred.py
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
#

"""Inferred (hypothesis) elements are drawn so they never read as observed (Atajo A4).

An element is inferred when ``inferred = true`` or ``confidence = "hypothesis"``
(for a timeline event's technique tag: ``technique_inferred`` /
``technique_confidence``). Attack-graph exploits and network edges, kill-chain
techniques and timeline technique tags support it, in both render engines.
"""

import copy
import json
import shutil
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from usecvislib.attackgraph_view import SUMMARY_PREFIX, build_view
from usecvislib.attackgraphs import AttackGraphs
from usecvislib.killchain import KillChain
from usecvislib.timeline import IncidentTimeline
from usecvislib.utils import inferred_state

SVG_NS = "{http://www.w3.org/2000/svg}"
ATLAS = Path(__file__).parent.parent / "templates" / "kill-chains" / "atlas_agent_prompt_injection.tml"
requires_dot = pytest.mark.skipif(shutil.which("dot") is None, reason="SVG-engine graph layout needs Graphviz 'dot'")

GRAPH = {
    "graph": {"name": "g"},
    "hosts": {"attacker": {}, "web01": {"zone": "dmz"}, "web02": {"zone": "dmz"}, "db01": {"zone": "data"}},
    "privileges": {"p_web": {"host": "web01"}, "p_db": {"host": "db01"}},
    "exploits": {
        "observed": {"label": "Observed", "precondition": "attacker", "postcondition": "p_web"},
        "proposed": {"label": "Proposed", "precondition": "p_web", "postcondition": "p_db", "inferred": True},
    },
    "network_edges": {
        "e1": {"from": "attacker", "to": "web01"},
        "e2": {"from": "web01", "to": "db01", "confidence": "hypothesis"},
        "e3": {"from": "web02", "to": "db01", "inferred": True},
    },
}


class TestInferredState:
    @pytest.mark.parametrize(
        "element,expected",
        [
            ({"inferred": True}, (True, None)),
            ({"inferred": "yes"}, (True, None)),
            ({"confidence": "hypothesis"}, (True, "hypothesis")),
            ({"confidence": "Inferred"}, (True, "Inferred")),
            ({"inferred": True, "confidence": "medium"}, (True, "medium")),
            ({"confidence": "high"}, (False, "high")),
            ({"inferred": False}, (False, None)),
            ({}, (False, None)),
            ("not a dict", (False, None)),
        ],
    )
    def test_fields(self, element, expected):
        assert inferred_state(element) == expected

    def test_prefix(self):
        assert inferred_state({"technique_inferred": True}, "technique_") == (True, None)
        assert inferred_state({"inferred": True}, "technique_") == (False, None)


class TestAttackGraphView:
    def test_marks(self):
        view = build_view(copy.deepcopy(GRAPH))
        assert view.node_mark("proposed").inferred and view.node_mark("observed") is None
        assert view.edge_mark(("p_web", "proposed", "exploit")).inferred
        assert view.edge_mark(("proposed", "p_db", "exploit")).inferred
        assert view.edge_mark(("web01", "db01", "network")).inferred  # confidence = hypothesis
        assert view.edge_mark(("attacker", "web01", "network")) is None

    def test_merged_edge_is_inferred_only_if_all_were(self):
        view = build_view(copy.deepcopy(GRAPH), group_by="zone", collapse=["dmz"])
        merged = view.edge_mark((SUMMARY_PREFIX + "dmz", "db01", "network"))
        assert merged.count == 2 and merged.inferred  # e2 and e3 are both inferred
        data = copy.deepcopy(GRAPH)
        data["network_edges"]["e3"].pop("inferred")
        merged = build_view(data, group_by="zone", collapse=["dmz"]).edge_mark(
            (SUMMARY_PREFIX + "dmz", "db01", "network")
        )
        assert merged.count == 2 and not merged.inferred  # one observed edge makes it observed


@pytest.fixture
def graph_file(tmp_path):
    path = tmp_path / "g.json"
    path.write_text(json.dumps(GRAPH), encoding="utf-8")
    return str(path)


class TestAttackGraphGraphviz:
    def test_dot_attributes(self, graph_file, tmp_path):
        ag = AttackGraphs(graph_file, str(tmp_path / "o"))
        ag.load()
        ag.render()
        lines = ag.graph.source.splitlines()
        proposed = next(line for line in lines if line.strip().startswith("proposed ["))
        assert "(inferred)" in proposed and "dashed,filled" in proposed
        observed = next(line for line in lines if line.strip().startswith("observed ["))
        assert "(inferred)" not in observed and "dashed" not in observed
        inferred_edges = [line for line in lines if "->" in line and "arrowhead=empty" in line]
        assert len(inferred_edges) == 4  # 2 exploit edges + 2 network edges
        assert "attacker -> web01" in next(line for line in lines if "attacker -> web01" in line)
        assert "arrowhead=empty" not in next(line for line in lines if "attacker -> web01" in line)


@requires_dot
class TestAttackGraphSvg:
    def test_classes_and_data(self, graph_file, tmp_path):
        ag = AttackGraphs(graph_file, str(tmp_path / "o"), format="svg", render_engine="svg")
        ag.build()
        root = ET.fromstring((tmp_path / "o.svg").read_text(encoding="utf-8"))
        groups = list(root.iter(f"{SVG_NS}g"))
        nodes = [g for g in groups if "usv-node--inferred" in g.get("class", "").split()]
        assert [g.get("data-node-id") for g in nodes] == ["proposed"]
        assert nodes[0].get("data-inferred") == "true"
        assert any(el.get("stroke-dasharray") for el in nodes[0])
        edges = {(g.get("data-from"), g.get("data-to")) for g in groups if "usv-edge--inferred" in g.get("class", "")}
        assert edges == {("p_web", "proposed"), ("proposed", "p_db"), ("web01", "db01"), ("web02", "db01")}


class TestKillChain:
    def test_parse_and_stats(self, tmp_path):
        kc = KillChain(str(ATLAS), str(tmp_path / "o"), render_engine="svg")
        kc.load()
        tech = kc.techniques["AML.T0080"]
        assert tech.inferred and tech.confidence == "hypothesis"
        assert not kc.techniques["AML.T0051.001"].inferred
        assert kc.get_stats()["inferred_techniques"] == 1

    def test_graphviz_card(self, tmp_path):
        kc = KillChain(str(ATLAS), str(tmp_path / "o"))
        kc.load()
        kc.render()
        line = next(line for line in kc.dot.source.splitlines() if "AML.T0080" in line and "label=" in line)
        assert "No coverage \u00b7 <I>(inferred)</I>" in line and "dashed" in line
        assert line.count("<TR>") == 3  # same row count as other cards: phase boxes stay aligned
        assert 'fillcolor="#' in line and line.split('fillcolor="')[1][7:9] == "99"  # faded fill

    def test_svg_card(self, tmp_path):
        kc = KillChain(str(ATLAS), str(tmp_path / "o"), format="svg", render_engine="svg")
        kc.build()
        root = ET.fromstring((tmp_path / "o.svg").read_text(encoding="utf-8"))
        cards = [g for g in root.iter(f"{SVG_NS}g") if "usv-node--inferred" in g.get("class", "").split()]
        assert [g.get("data-node-id") for g in cards] == ["AML_T0080"]
        card = cards[0]
        assert card.get("data-confidence") == "hypothesis"
        body = card.find(f"{SVG_NS}rect")
        # The card fades, its label stays opaque in a color that reads on it
        assert body.get("opacity") == "0.6" and card.get("opacity") is None
        assert body.get("stroke-dasharray")
        assert card.find(f"{SVG_NS}text").get("fill") == "#1f2937"
        assert "(inferred)" in "".join(card.itertext())
        assert "usv-cover--gap" in card.get("class")  # coverage color kept


TIMELINE = """
[incident]
name = "Tags"

[[events]]
timestamp = "2026-10-01T09:00:00"
title = "Login"
technique = "T1078"

[[events]]
timestamp = "2026-10-01T09:30:00"
title = "Process"
technique = "T1059"
technique_confidence = "hypothesis"

[[events]]
timestamp = "2026-10-01T10:00:00"
title = "No tag"
technique_inferred = true
"""


class TestTimeline:
    @pytest.fixture
    def timeline(self, tmp_path):
        path = tmp_path / "t.toml"
        path.write_text(TIMELINE, encoding="utf-8")
        return str(path)

    def test_labels_and_stats(self, timeline, tmp_path):
        tl = IncidentTimeline(timeline, str(tmp_path / "o"))
        tl.load()
        labels = [ev.technique_label for ev in tl.events]
        assert labels == ["T1078", "T1059 (inferred)", None]  # no tag: nothing to mark
        assert tl.get_stats()["inferred_tags"] == 1

    @pytest.mark.parametrize("mode", ["swimlane", "gantt", "vertical"])  # compact shows titles only
    def test_svg_engine(self, timeline, tmp_path, mode):
        tl = IncidentTimeline(timeline, str(tmp_path / "o"), format="svg", render_engine="svg", mode=mode)
        tl.build()
        svg = (tmp_path / "o.svg").read_text(encoding="utf-8")
        assert "T1059 (inferred)" in svg and "T1078 (inferred)" not in svg
        assert 'data-technique-inferred="true"' in svg

    @pytest.mark.parametrize("mode", ["swimlane", "gantt", "vertical"])  # compact shows titles only
    def test_matplotlib(self, timeline, tmp_path, mode):
        tl = IncidentTimeline(timeline, str(tmp_path / "o"), format="svg", mode=mode)
        tl.build()
        assert "T1059 (inferred)" in (tmp_path / "o.svg").read_text(encoding="utf-8")


def test_builders_pass_the_flag_through(tmp_path):
    from usecvislib.builders import AttackGraphBuilder, KillChainBuilder

    ag = AttackGraphBuilder("b").add_host("a", "A").add_host("b", "B").add_network_edge("a", "b", inferred=True)
    assert ag.build()["network_edges"][0]["inferred"] is True
    kc = KillChainBuilder("k").add_technique("T1", "One", "Delivery", inferred=True)
    assert kc.build()["techniques"]["T1"]["inferred"] is True


def test_compact_timeline_keeps_the_flag_in_data(tmp_path):
    # Compact mode shows titles only, but its markers still carry the tag and the flag
    path = tmp_path / "t.toml"
    path.write_text(TIMELINE, encoding="utf-8")
    tl = IncidentTimeline(str(path), str(tmp_path / "o"), format="svg", render_engine="svg", mode="compact")
    tl.build()
    svg = (tmp_path / "o.svg").read_text(encoding="utf-8")
    assert 'data-technique-inferred="true"' in svg and 'data-technique-confidence="hypothesis"' in svg


class TestApiStats:
    @pytest.fixture
    def client(self):
        import os
        import sys

        sys.path.insert(0, str(Path(__file__).parent.parent / "api"))
        os.environ["USECVISLIB_AUTH_ENABLED"] = "false"
        from fastapi.testclient import TestClient

        from api.config import limiter
        from api.main import app

        limiter.reset()
        yield TestClient(app)
        limiter.reset()

    def test_kill_chain_inferred_techniques(self, client):
        response = client.post("/analyze/kill-chain", files={"file": ("atlas.tml", ATLAS.read_bytes())})
        assert response.status_code == 200
        assert response.json()["inferred_techniques"] == 1

    def test_timeline_inferred_tags(self, client):
        response = client.post("/analyze/timeline", files={"file": ("t.toml", TIMELINE.encode())})
        assert response.status_code == 200
        assert response.json()["inferred_tags"] == 1
