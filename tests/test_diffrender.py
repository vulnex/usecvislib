#
# VULNEX -Universal Security Visualization Library-
#
# File: test_diffrender.py
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
#

"""Drift renderer: draw what changed between two attack-graph versions (Atajo A5)."""

import copy
import json
import os
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from usecvislib import AttackGraphs, render_diff
from usecvislib.attackgraph_view import SUMMARY_PREFIX, build_view
from usecvislib.diffrender import merge_attack_graphs, normalize_attack_graph, parse_diff_colors, resolve_diff_colors

SVG_NS = "{http://www.w3.org/2000/svg}"
REPO = Path(__file__).parent.parent
requires_dot = pytest.mark.skipif(shutil.which("dot") is None, reason="rendering needs Graphviz 'dot'")

OLD = {
    "graph": {"name": "Engagement"},
    "hosts": {
        "attacker": {"label": "Attacker"},
        "web01": {"label": "web01", "zone": "dmz"},
        "web02": {"label": "web02", "zone": "dmz"},
        "db01": {"label": "db01", "zone": "data"},
        "siem01": {"label": "siem01", "zone": "data"},
    },
    "vulnerabilities": {"f1": {"label": "Finding 1", "host": "web01", "cvss": 5.3}},
    "privileges": {"p_web": {"label": "user on web01", "host": "web01"}, "p_db": {"label": "db admin", "host": "db01"}},
    "exploits": {"x1": {"label": "Step 1", "preconditions": ["f1", "attacker"], "postcondition": "p_web"}},
    "network_edges": {
        "e1": {"from": "attacker", "to": "web01"},
        "e2": {"from": "web01", "to": "db01"},
        "e3": {"from": "db01", "to": "siem01"},
    },
}

NEW = copy.deepcopy(OLD)
del NEW["hosts"]["siem01"]  # removed (and its edge)
NEW["hosts"]["web03"] = {"label": "web03", "zone": "dmz"}  # added
NEW["vulnerabilities"]["f1"]["cvss"] = 9.1  # modified
NEW["vulnerabilities"]["f2"] = {"label": "Finding 2", "host": "web03", "cvss": 7.0}  # added
NEW["exploits"]["x1"]["preconditions"] = ["attacker", "f1"]  # reordered: not drift
NEW["network_edges"] = {
    "renamed": {"from": "attacker", "to": "web01"},  # new entry id, same endpoints: not drift
    "e2": {"from": "web01", "to": "db01"},
    "e4": {"from": "attacker", "to": "web03"},  # added
}
del NEW["network_edges"]["e2"]  # removed edge web01 -> db01


@pytest.fixture
def versions(tmp_path):
    old, new = tmp_path / "day1.json", tmp_path / "day2.json"
    old.write_text(json.dumps(OLD), encoding="utf-8")
    new.write_text(json.dumps(NEW), encoding="utf-8")
    return str(old), str(new)


def _merged(ignore=None):
    return merge_attack_graphs(normalize_attack_graph(OLD), normalize_attack_graph(NEW), ignore)


class TestColors:
    def test_resolve(self):
        assert resolve_diff_colors({"added": "#E8590C", "modified": "#0af"}) == {
            "added": "#e8590c",
            "modified": "#00aaff",
        }
        assert resolve_diff_colors(None) == {}

    @pytest.mark.parametrize("colors", [{"added": "red"}, {"added": "#12345"}, {"new": "#123456"}, ["#123456"]])
    def test_invalid(self, colors):
        with pytest.raises(ValueError):
            resolve_diff_colors(colors)

    def test_parse_cli_form(self):
        assert parse_diff_colors("added=#e8590c, modified=#0ea5e9") == {"added": "#e8590c", "modified": "#0ea5e9"}
        with pytest.raises(ValueError, match="key=#color"):
            parse_diff_colors("added")


class TestNormalize:
    def test_exploit_conditions_become_sorted_lists(self):
        data = normalize_attack_graph({"exploits": {"x": {"precondition": "b", "postconditions": ["z", "a", "z"]}}})
        assert data["exploits"]["x"] == {"preconditions": ["b"], "postconditions": ["a", "z"]}

    def test_network_edges_keyed_by_endpoints(self):
        data = normalize_attack_graph({"network_edges": {"e9": {"from": "a", "to": "b"}}, "network": {"a": ["c"]}})
        assert set(data["network_edges"]) == {"a->b", "a->c"} and data["network"] == {}

    def test_input_unchanged(self):
        before = copy.deepcopy(OLD)
        normalize_attack_graph(OLD)
        assert before == OLD


class TestMerge:
    def test_node_status(self):
        _, marks = _merged()
        status = {node_id: s for node_id, (s, _) in marks.nodes.items()}
        assert status["web03"] == status["f2"] == "added"
        assert status["siem01"] == "removed"
        assert status["f1"] == "modified" and marks.nodes["f1"][1] == ["cvss"]
        assert status["x1"] == status["web01"] == "unchanged"  # reordered preconditions are not drift

    def test_removed_elements_are_drawn_from_the_old_version(self):
        merged, _ = _merged()
        assert merged["hosts"]["siem01"] == OLD["hosts"]["siem01"]
        assert merged["vulnerabilities"]["f1"]["cvss"] == 9.1  # modified: drawn as new

    def test_edge_status(self):
        _, marks = _merged()
        assert marks.edges[("attacker", "web01", "network")] == "unchanged"  # renamed entry, same endpoints
        assert marks.edges[("attacker", "web03", "network")] == "added"
        assert marks.edges[("web01", "db01", "network")] == "removed"
        assert marks.edges[("db01", "siem01", "network")] == "removed"  # edge of a removed host
        assert marks.edges[("web03", "f2", "structural")] == "added"

    def test_modified_exploit_keeps_old_and_new_edges(self):
        old, new = copy.deepcopy(OLD), copy.deepcopy(OLD)
        new["exploits"]["x1"]["postcondition"] = "p_db"
        merged, marks = merge_attack_graphs(normalize_attack_graph(old), normalize_attack_graph(new))
        assert merged["exploits"]["x1"]["postconditions"] == ["p_db", "p_web"]
        assert marks.edges[("x1", "p_web", "exploit")] == "removed"
        assert marks.edges[("x1", "p_db", "exploit")] == "added"
        assert marks.nodes["x1"] == ("modified", ["postconditions"])

    def test_ignore_paths(self):
        _, marks = _merged(["vulnerabilities.f1.cvss", "hosts.siem01"])
        assert marks.nodes["f1"][0] == "unchanged" and marks.nodes["siem01"][0] == "unchanged"


class TestView:
    def test_changes_only_keeps_changes_neighbours_and_hosts(self):
        merged, marks = _merged()
        view = build_view(merged, diff=marks, show_unchanged=False)
        assert set(view.data["hosts"]) == {"attacker", "web01", "web03", "db01", "siem01"}
        assert "p_db" not in view.data["privileges"]  # unchanged, no changed neighbour

    def test_changes_only_prunes_groups(self):
        merged, marks = _merged()
        view = build_view(merged, group_by="zone", diff=marks, show_unchanged=False)
        assert all(
            m in set().union(*[set(view.data[s]) for s in ("hosts", "vulnerabilities", "privileges")])
            for info in view.groups.values()
            for m in info.members
        )

    def test_no_changes_draws_everything(self):
        data = normalize_attack_graph(OLD)
        merged, marks = merge_attack_graphs(data, copy.deepcopy(data))
        assert build_view(merged, diff=marks, show_unchanged=False).data is merged

    def test_collapsed_group_summarizes_changes(self):
        merged, marks = _merged()
        view = build_view(merged, group_by="zone", collapse="all", diff=marks)
        dmz = view.node_mark(SUMMARY_PREFIX + "dmz")
        assert dmz.diff == "modified" and dmz.collapsed["added"] == 2 and dmz.collapsed["modified"] == 1
        assert view.node_mark(SUMMARY_PREFIX + "data").collapsed["removed"] == 1


class TestGraphviz:
    def _source(self, versions, tmp_path, colors=None):
        merged, marks = _merged()
        path = tmp_path / "merged.json"
        path.write_text(json.dumps(merged), encoding="utf-8")
        ag = AttackGraphs(str(path), str(tmp_path / "o"))
        ag.diff_marks, ag.diff_colors = marks, colors
        ag.load()
        ag.render()
        return ag.graph.source

    def test_marks_and_legend(self, versions, tmp_path):
        source = self._source(versions, tmp_path)
        line = next(line for line in source.splitlines() if line.strip().startswith("web03 "))
        assert '"+ web03"' in line and "penwidth=3" in line and "#d6336c" in line
        removed = next(line for line in source.splitlines() if line.strip().startswith("siem01 "))
        assert "dashed" in removed and "\u2212 siem01" in removed
        # The fill fades; the label does not (white on the faded fill was unreadable)
        assert re.search(r'fillcolor="#[0-9a-f]{6}59"', removed)
        assert "fontcolor=\"#1f2937\"" in removed
        assert "+ added" in source and "~ modified" in source  # legend in the title

    def test_diff_colors_override(self, versions, tmp_path):
        source = self._source(versions, tmp_path, {"added": "#e8590c"})
        assert "#e8590c" in source and "#d6336c" not in source


class TestRenderDiff:
    def test_unsupported_type(self, versions, tmp_path):
        with pytest.raises(NotImplementedError, match="attack_graph"):
            render_diff(*versions, visualization_type="kill_chain", output=str(tmp_path / "o"))

    def test_invalid_colors_fail_before_rendering(self, versions, tmp_path):
        with pytest.raises(ValueError):
            render_diff(*versions, output=str(tmp_path / "o"), diff_colors={"added": "pink"})

    @requires_dot
    @pytest.mark.parametrize("engine", ["graphviz", "svg"])
    def test_returns_the_diff_and_writes_the_image(self, versions, tmp_path, engine):
        result = render_diff(*versions, output=str(tmp_path / "drift"), format="svg", render_engine=engine)
        assert (tmp_path / "drift.svg").exists()
        # web03, f2, attacker->web03 / siem01, web01->db01, db01->siem01 / f1.cvss
        assert result.summary == {"added": 3, "removed": 3, "modified": 1, "total": 7}

    @requires_dot
    def test_toml_dates(self, tmp_path):
        """Unquoted TOML dates load as date objects; the merged graph must still serialize."""
        body = """[graph]
name = "Dated"
[hosts.a]
label = "a"
[hosts.b]
label = "b"
[vulnerabilities.v]
label = "v"
host = "b"
discovered = %s
[network_edges.e]
from = "a"
to = "b"
"""
        old, new = tmp_path / "old.toml", tmp_path / "new.toml"
        old.write_text(body % "2026-10-01", encoding="utf-8")
        new.write_text(body % "2026-10-02", encoding="utf-8")
        result = render_diff(str(old), str(new), output=str(tmp_path / "d"), format="svg", render_engine="svg")
        assert result.summary["modified"] == 1
        assert (tmp_path / "d.svg").exists()

    @requires_dot
    def test_accepts_instances(self, versions, tmp_path):
        old = AttackGraphs(versions[0], "unused")
        result = render_diff(old, AttackGraphs(versions[1], "unused"), output=str(tmp_path / "d"), format="svg")
        assert result.has_changes

    @requires_dot
    def test_svg_contract(self, versions, tmp_path):
        render_diff(*versions, output=str(tmp_path / "d"), format="svg", render_engine="svg", group_by="zone")
        root = ET.fromstring((tmp_path / "d.svg").read_text(encoding="utf-8"))
        groups = list(root.iter(f"{SVG_NS}g"))
        nodes = {g.get("data-node-id"): g for g in groups if "usv-node" in g.get("class", "").split()}
        assert "usv-diff--added" in nodes["web03"].get("class")
        siem = nodes["siem01"]
        assert siem.get("data-diff") == "removed"
        # The body fades, the label stays opaque and readable
        assert siem[0].get("opacity") == "0.35" and siem.get("opacity") is None
        assert siem.find(f"{SVG_NS}text").get("fill") == "#1f2937"
        assert nodes["f1"].get("data-changed") == "cvss"
        assert nodes["web01"].get("data-diff") == "unchanged"
        assert sorted(g.get("data-value") for g in groups if "usv-badge--diff" in g.get("class", "")) == [
            "+", "+", "~", "\u2212",
        ]  # fmt: skip
        assert any("usv-legend" in g.get("class", "") for g in groups)
        removed_edges = [g for g in groups if "usv-edge" in g.get("class", "") and g.get("data-diff") == "removed"]
        assert {(g.get("data-from"), g.get("data-to")) for g in removed_edges} == {
            ("web01", "db01"),
            ("db01", "siem01"),
        }


@requires_dot
def test_cli(versions, tmp_path):
    env = {**os.environ, "PYTHONPATH": str(REPO / "src")}
    out = subprocess.run(
        [sys.executable, "-m", "usecvislib.usecvis", "-m", "3", "-i", versions[1], "--diff", versions[0],
         "-o", str(tmp_path / "drift"), "-f", "svg", "--changes-only", "--diff-colors", "added=#e8590c"],
        capture_output=True, text=True, env=env, cwd=tmp_path,
    )  # fmt: skip
    assert out.returncode == 0, out.stderr
    assert "Added: 3  Removed: 3  Modified: 1" in out.stdout
    assert "#e8590c" in (tmp_path / "drift.svg").read_text(encoding="utf-8")


class TestApi:
    @pytest.fixture
    def client(self):
        sys.path.insert(0, str(REPO / "api"))
        os.environ["USECVISLIB_AUTH_ENABLED"] = "false"
        from fastapi.testclient import TestClient

        from api.config import limiter
        from api.main import app

        limiter.reset()
        yield TestClient(app)
        limiter.reset()

    def _files(self, versions):
        return {
            "old_file": ("day1.json", Path(versions[0]).read_bytes()),
            "new_file": ("day2.json", Path(versions[1]).read_bytes()),
        }

    def test_summary_header_is_readable_cross_origin(self, client):
        from api.config import ALLOWED_ORIGINS

        response = client.options(
            "/diff/render",
            headers={"Origin": ALLOWED_ORIGINS[0], "Access-Control-Request-Method": "POST"},
        )
        assert response.status_code == 200
        from api.main import app

        cors = next(m for m in app.user_middleware if m.cls.__name__ == "CORSMiddleware")
        assert "X-Diff-Summary" in cors.kwargs["expose_headers"]

    def test_bad_colors_400(self, client, versions):
        response = client.post("/diff/render", files=self._files(versions), data={"diff_colors": '{"added": "red"}'})
        assert response.status_code == 400 and "added" in response.json()["detail"]

    @requires_dot
    def test_render(self, client, versions):
        response = client.post(
            "/diff/render",
            params={"format": "svg", "render_engine": "svg", "show_unchanged": "false"},
            files=self._files(versions),
            data={"diff_colors": '{"modified": "#0ea5e9"}'},
        )
        assert response.status_code == 200 and "image/svg+xml" in response.headers["content-type"]
        assert json.loads(response.headers["X-Diff-Summary"])["added"] == 3
        assert "#0ea5e9" in response.text


def test_faded_only_appends_alpha_to_full_hex_colors():
    # A preset could give the removed color as #rgb or a name: appending the
    # alpha suffix to those produced an invalid Graphviz color
    from usecvislib.drift import faded

    assert faded("#94a3b8") == "#94a3b859"
    assert faded("#abc") == "#abc" and faded("grey") == "grey"
