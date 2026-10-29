#
# VULNEX -Universal Security Visualization Library-
#
# File: test_attackgraph_grouping.py
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
#

"""Attack-graph grouping and collapse.

Grouping is opt-in (graph.group_by or the group_by render option): hosts are
clustered, and collapsed groups are drawn as one summary node with their
edges re-pointed and merged. Analysis keeps using the full data.
"""

import copy
import json
import logging
import shutil
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from usecvislib.attackgraph_view import SUMMARY_PREFIX, assign_groups, build_view, iter_edges, node_ids
from usecvislib.attackgraphs import AttackGraphError, AttackGraphs

TEMPLATE = Path(__file__).parent.parent / "templates" / "attack-graphs" / "segmented_enterprise.toml"
SVG_NS = "{http://www.w3.org/2000/svg}"
requires_dot = pytest.mark.skipif(shutil.which("dot") is None, reason="SVG-engine layout needs Graphviz 'dot'")


def _graph(**sections):
    return {"graph": {"name": "g"}, **sections}


# Two zones; web01 has a finding, a service and a privilege; db01 and db02 share a zone
SAMPLE = _graph(
    hosts={
        "attacker": {"label": "Attacker"},
        "web01": {"label": "web01", "zone": "dmz", "ip": "10.0.1.10"},
        "web02": {"label": "web02", "zone": "dmz", "ip": "10.0.1.11"},
        "db01": {"label": "db01", "zone": "data", "ip": "10.0.2.10"},
        "db02": {"label": "db02", "zone": "data", "ip": "10.0.2.11", "group": "special"},
    },
    vulnerabilities={"f1": {"label": "Finding 1", "host": "web01", "cvss": 9.1}},
    services={"s1": {"label": "HTTPS", "host": "web01", "port": 443}},
    privileges={
        "p_web": {"label": "user on web01", "host": "web01"},
        "p_db": {"label": "admin on db01", "host": "db01"},
    },
    exploits={
        "x_inside": {"label": "inside", "precondition": "f1", "postcondition": "p_web"},
        "x_cross": {"label": "cross", "preconditions": ["p_web", "f1"], "postcondition": "p_db"},
    },
    network_edges={
        "e1": {"from": "attacker", "to": "web01"},
        "e2": {"from": "attacker", "to": "web02"},
        "e3": {"from": "web01", "to": "web02"},
        "e4": {"from": "web01", "to": "db01", "label": "sql"},
        "e5": {"from": "web02", "to": "db01"},
    },
)


def _without_explicit_group(data=SAMPLE):
    """SAMPLE minus db02's own `group` field (which turns grouping on by itself)."""
    data = copy.deepcopy(data)
    data["hosts"]["db02"].pop("group")
    return data


def _view(data=SAMPLE, **options):
    return build_view(copy.deepcopy(data), **options)


class TestMembership:
    def test_opt_in_without_group_by(self):
        data = _without_explicit_group()
        view = build_view(data)
        assert view.data is data and view.groups == {} and view.nodes == {}

    def test_hosts_by_field_explicit_group_wins(self):
        groups = assign_groups(SAMPLE, "zone")
        assert groups["web01"] == groups["web02"] == "dmz"
        assert groups["db01"] == "data" and groups["db02"] == "special"
        assert "attacker" not in groups  # no zone: stays outside clusters

    def test_elements_follow_their_host(self):
        groups = assign_groups(SAMPLE, "zone")
        assert groups["f1"] == groups["s1"] == groups["p_web"] == "dmz"
        assert groups["p_db"] == "data"

    def test_exploit_joins_only_a_single_group(self):
        groups = assign_groups(SAMPLE, "zone")
        assert groups["x_inside"] == "dmz"  # f1 -> p_web, both in the DMZ
        assert "x_cross" not in groups  # DMZ -> data

    def test_group_meta_label_and_color(self):
        data = copy.deepcopy(SAMPLE)
        data["groups"] = {"dmz": {"label": "DMZ", "color": "#fde68a"}}
        info = build_view(data, group_by="zone").groups["dmz"]
        assert (info.label, info.color) == ("DMZ", "#fde68a")
        assert info.members == ["web01", "web02", "f1", "p_web", "s1", "x_inside"]

    def test_group_by_from_graph_section(self):
        data = copy.deepcopy(SAMPLE)
        data["graph"]["group_by"] = "zone"
        assert set(build_view(data).groups) == {"dmz", "data", "special"}


class TestIpGrouping:
    def test_ipv4_networks(self):
        groups = assign_groups(SAMPLE, "ip/24")
        assert groups["web01"] == groups["web02"] == "10.0.1.0/24"
        assert groups["db01"] == "10.0.2.0/24"
        assert "attacker" not in groups  # no ip

    def test_ipv6_and_version_filter(self):
        data = _graph(hosts={"a": {"ip": "2001:db8::1"}, "b": {"ip": "2001:db8::2"}, "c": {"ip": "10.0.0.1"}})
        assert assign_groups(data, "ip6/64") == {"a": "2001:db8::/64", "b": "2001:db8::/64"}
        assert assign_groups(data, "ip/16") == {"c": "10.0.0.0/16"}

    @pytest.mark.parametrize("rule", ["ip/7", "ip/33", "ip6/8", "ip/x"])
    def test_invalid_rules(self, rule):
        with pytest.raises(ValueError):
            assign_groups(SAMPLE, rule)

    def test_invalid_rule_is_an_attack_graph_error(self, tmp_path):
        path = tmp_path / "g.json"
        path.write_text(json.dumps(SAMPLE), encoding="utf-8")
        ag = AttackGraphs(str(path), str(tmp_path / "o"), group_by="ip/40")
        ag.load()
        with pytest.raises(AttackGraphError, match="8-32"):
            ag.render()


class TestCollapseChoice:
    def test_all_skips_single_member_groups(self):
        view = _view(group_by="zone", collapse=True)
        assert {g for g, i in view.groups.items() if i.collapsed} == {"dmz", "data"}
        assert not view.groups["special"].collapsed  # db02 alone

    @pytest.mark.parametrize("collapse", [["data"], "data", " data , nope "])
    def test_named_groups(self, collapse, caplog):
        with caplog.at_level(logging.WARNING):
            view = _view(group_by="zone", collapse=collapse)
        assert [g for g, i in view.groups.items() if i.collapsed] == ["data"]
        assert ("nope" in caplog.text) == ("nope" in str(collapse))

    def test_group_setting_wins(self):
        data = copy.deepcopy(SAMPLE)
        data["groups"] = {"dmz": {"collapsed": False}, "special": {"collapsed": True}}
        view = build_view(data, group_by="zone", collapse="all")
        assert {g for g, i in view.groups.items() if i.collapsed} == {"data", "special"}

    def test_auto_collapses_largest_first(self):
        assert len(node_ids(SAMPLE)) == 11
        view = _view(group_by="zone", collapse="auto", max_nodes=8)
        assert [g for g, i in view.groups.items() if i.collapsed] == ["dmz"]  # 6 members -> 1
        assert len(node_ids(view.data)) <= 8

    def test_auto_within_target_collapses_nothing(self):
        view = _view(group_by="zone", collapse="auto", max_nodes=300)
        assert view.data is not None and not any(i.collapsed for i in view.groups.values())

    def test_auto_warns_when_target_unreachable(self, caplog):
        with caplog.at_level(logging.WARNING):
            _view(group_by="zone", collapse="auto", max_nodes=2)
        assert "remain" in caplog.text

    def test_explicit_group_field_turns_grouping_on(self):
        assert set(_view().groups) == {"special"}  # db02's own group, no group_by

    def test_collapse_without_groups_is_ignored(self, caplog):
        with caplog.at_level(logging.WARNING):
            view = _view(_without_explicit_group(), collapse="all")
        assert view.groups == {} and "collapse needs groups" in caplog.text

    @pytest.mark.parametrize("collapse", [False, "none", None])
    def test_no_collapse(self, collapse):
        data = copy.deepcopy(SAMPLE)
        view = build_view(data, group_by="zone", collapse=collapse)
        assert view.data is data  # expanded groups draw the data as is


class TestCollapsedData:
    def test_summary_takes_first_member_position(self):
        view = _view(group_by="zone", collapse=["dmz"])
        summary = SUMMARY_PREFIX + "dmz"
        assert list(view.data["hosts"]) == ["attacker", summary, "db01", "db02"]
        facts = view.node_mark(summary).collapsed
        assert facts["hosts"] == 2 and facts["vulnerabilities"] == 1 and facts["services"] == 1
        assert facts["max_cvss"] == 9.1 and facts["members"] == 6

    def test_members_folded(self):
        data = _view(group_by="zone", collapse=["dmz"]).data
        assert data["vulnerabilities"] == {} and data["services"] == {}
        assert set(data["privileges"]) == {"p_db"}
        assert set(data["exploits"]) == {"x_cross"}  # x_inside folded into the DMZ

    def test_edges_repointed_merged_and_dropped(self):
        view = _view(group_by="zone", collapse=["dmz"])
        summary = SUMMARY_PREFIX + "dmz"
        edges = list(iter_edges(view.data))
        # attacker->web01 and attacker->web02 merge; web01->web02 is inside the DMZ and dropped
        assert edges.count(("attacker", summary, "network")) == 1
        assert view.edge_mark(("attacker", summary, "network")).count == 2
        assert view.edge_mark((summary, "db01", "network")).count == 2
        # x_cross: both preconditions are now the summary node
        assert view.data["exploits"]["x_cross"]["preconditions"] == [summary]
        assert view.edge_mark((summary, "x_cross", "exploit")).count == 2
        assert (summary, summary, "network") not in edges

    def test_legacy_network_lists_are_folded_in(self):
        data = copy.deepcopy(SAMPLE)
        data["network_edges"] = {}
        data["network"] = {"attacker": ["web01", "web02"]}
        view = build_view(data, group_by="zone", collapse=["dmz"])
        assert list(iter_edges(view.data))[:1] == [("attacker", SUMMARY_PREFIX + "dmz", "network")]
        assert view.data["network"] == {}

    def test_input_is_not_modified(self):
        data = copy.deepcopy(SAMPLE)
        before = copy.deepcopy(data)
        build_view(data, group_by="zone", collapse="all")
        assert data == before


@pytest.fixture
def sample_file(tmp_path):
    path = tmp_path / "sample.json"
    path.write_text(json.dumps(SAMPLE), encoding="utf-8")
    return str(path)


class TestGraphvizEngine:
    def _source(self, path, tmp_path, **options):
        ag = AttackGraphs(path, str(tmp_path / "o"), **options)
        ag.load()
        ag.render()
        return ag.graph.source

    def test_expanded_groups_are_clusters(self, sample_file, tmp_path):
        source = self._source(sample_file, tmp_path, group_by="zone")
        assert "subgraph cluster_dmz" in source and "subgraph cluster_data" in source
        assert "folder" not in source

    def test_collapsed_group_is_a_folder_node(self, sample_file, tmp_path):
        source = self._source(sample_file, tmp_path, group_by="zone", collapse=["dmz"])
        assert "__group_dmz" in source and "shape=folder" in source and "max CVSS 9.1" in source
        assert "cluster_dmz" not in source and 'label="\u00d72"' in source

    def test_analysis_keeps_the_full_graph(self, sample_file, tmp_path):
        ag = AttackGraphs(sample_file, str(tmp_path / "o"), group_by="zone", collapse="all")
        ag.load()
        ag.render()
        assert ag.get_stats()["total_hosts"] == 5
        assert ag.shortest_path("attacker", "db01")


def test_size_check_counts_what_is_drawn(tmp_path):
    hosts = {f"h{i}": {"label": f"h{i}", "zone": f"z{i % 4}"} for i in range(10_001)}
    path = tmp_path / "big.json"
    path.write_text(json.dumps(_graph(hosts=hosts)), encoding="utf-8")
    full = AttackGraphs(str(path), str(tmp_path / "o"))
    full.load()
    with pytest.raises(ValueError, match="nodes"):
        full.render()
    collapsed = AttackGraphs(str(path), str(tmp_path / "o"), group_by="zone", collapse="all")
    collapsed.load()
    collapsed.render()  # 4 summary nodes
    assert collapsed.graph.source.count("shape=folder") == 4


def test_stats_groups(sample_file):
    ag = AttackGraphs(sample_file, "unused", group_by="zone")
    ag.load()
    assert ag.get_stats()["groups"]["dmz"] == {"hosts": 2, "vulnerabilities": 1, "max_cvss": 9.1}
    plain_file = Path(sample_file).with_name("plain.json")
    plain_file.write_text(json.dumps(_without_explicit_group()), encoding="utf-8")
    plain = AttackGraphs(str(plain_file), "unused")
    plain.load()
    assert "groups" not in plain.get_stats()


def test_builder(tmp_path):
    from usecvislib.builders import AttackGraphBuilder

    builder = AttackGraphBuilder("Built")
    builder.add_host("a", "A", zone="dmz").add_host("b", "B", zone="dmz").add_host("c", "C", zone="lan")
    builder.set_grouping("zone", collapse="all").add_group("dmz", label="DMZ", collapsed=False)
    data = builder.build()
    assert data["graph"]["group_by"] == "zone" and data["groups"]["dmz"] == {"label": "DMZ", "collapsed": False}
    ag = builder.to_attack_graph(str(tmp_path / "o"))
    ag.load()
    view = ag.render_view()
    assert not view.groups["dmz"].collapsed and view.groups["dmz"].label == "DMZ"


def test_template_groups_by_zone():
    ag = AttackGraphs(str(TEMPLATE), "unused")
    ag.load()
    view = ag.render_view()
    assert list(view.groups) == ["dmz", "users", "servers", "mgmt"]
    assert view.groups["users"].label == "User LAN"


@requires_dot
class TestSvgEngine:
    def _svg(self, path, tmp_path, **options):
        ag = AttackGraphs(path, str(tmp_path / "o"), format="svg", render_engine="svg", **options)
        ag.build()
        return ET.fromstring((tmp_path / "o.svg").read_text(encoding="utf-8"))

    def test_expanded_clusters(self, sample_file, tmp_path):
        root = self._svg(sample_file, tmp_path, group_by="zone")
        clusters = {g.get("data-cluster-id"): g for g in root.iter(f"{SVG_NS}g") if "usv-cluster" in g.get("class", "")}
        assert set(clusters) == {"dmz", "data", "special"}
        assert all(g.get("data-collapsed") == "false" for g in clusters.values())

    def test_summary_node_and_merged_edges(self, sample_file, tmp_path):
        root = self._svg(sample_file, tmp_path, group_by="zone", collapse=["dmz"])
        groups = [g for g in root.iter(f"{SVG_NS}g") if "usv-node--group" in g.get("class", "").split()]
        assert len(groups) == 1
        node = groups[0]
        assert node.get("data-collapsed") == "true" and node.get("data-cluster-id") == "dmz"
        assert (node.get("data-hosts"), node.get("data-vulnerabilities"), node.get("data-max-cvss")) == (
            "2",
            "1",
            "9.1",
        )
        counts = sorted(g.get("data-edge-count") for g in root.iter(f"{SVG_NS}g") if g.get("data-edge-count"))
        assert counts == ["2", "2", "2"]


class TestApi:
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

    def _upload(self):
        return {"file": ("segmented.toml", TEMPLATE.read_bytes())}

    def test_analyze_reports_groups(self, client):
        response = client.post("/analyze/attack-graph", params={"group_by": "ip/24"}, files=self._upload())
        assert response.status_code == 200
        assert response.json()["groups"]["10.0.10.0/24"]["hosts"] == 14

    def test_invalid_group_rule_is_400(self, client):
        response = client.post("/visualize/attack-graph", params={"group_by": "ip/99"}, files=self._upload())
        assert response.status_code == 400 and "8-32" in response.json()["detail"]

    @requires_dot
    @pytest.mark.parametrize("engine", ["graphviz", "svg"])
    def test_visualize_collapsed(self, client, engine):
        params = {"collapse": "auto", "max_nodes": 40, "render_engine": engine, "format": "svg"}
        response = client.post("/visualize/attack-graph", params=params, files=self._upload())
        assert response.status_code == 200
        assert "User LAN" in response.text and "Server VLAN" in response.text


@requires_dot
def test_cli_grouping_flags(tmp_path):
    import os
    import subprocess
    import sys

    env = {**os.environ, "PYTHONPATH": str(Path(__file__).parent.parent / "src")}
    out = subprocess.run(
        [sys.executable, "-m", "usecvislib.usecvis", "-m", "3", "-i", str(TEMPLATE), "-o", str(tmp_path / "g"),
         "-f", "svg", "--group-by", "ip/24", "--collapse", "auto", "--max-nodes", "40"],
        capture_output=True, text=True, env=env, cwd=tmp_path,
    )  # fmt: skip
    assert out.returncode == 0, out.stderr
    dot = (tmp_path / "g.svg").read_text(encoding="utf-8")
    assert "10.0.10.0/24" in dot  # the User LAN subnet, collapsed into a summary node

    bad = subprocess.run(
        [sys.executable, "-m", "usecvislib.usecvis", "-m", "3", "-i", str(TEMPLATE), "-o", str(tmp_path / "b"),
         "--group-by", "ip/99"],
        capture_output=True, text=True, env=env, cwd=tmp_path,
    )  # fmt: skip
    assert bad.returncode != 0 and "8-32" in (bad.stdout + bad.stderr)
