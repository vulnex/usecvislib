#
# VULNEX -Universal Security Visualization Library-
#
# File: test_privilegegradient_grouping.py
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
#

"""Grouping and collapse for the Privilege Gradient (Atajo A11): the render view."""

import json
import shutil
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from usecvislib.grouping import SUMMARY_PREFIX
from usecvislib.privilegegradient import PrivilegeGradient, PrivilegeGradientError
from usecvislib.privilegegradient_view import component_groups, summary_label_lines
from usecvislib.svgengine import themes
from usecvislib.svgengine.painters import privilegegradient as painter

SVG_NS = "{http://www.w3.org/2000/svg}"
TEMPLATE = Path(__file__).parent.parent / "templates" / "privilege-gradient" / "ad_tiers_grouped.tml"
requires_dot = pytest.mark.skipif(shutil.which("dot") is None, reason="SVG-engine layout needs Graphviz 'dot'")

WS = SUMMARY_PREFIX + "tier2/workstation"
SRV = SUMMARY_PREFIX + "tier1/server"

AD = {
    "gradient": {"name": "AD tiers"},
    "zones": [
        {"id": "tier2", "label": "Tier 2", "trust_level": 0},
        {"id": "tier1", "label": "Tier 1", "trust_level": 1},
        {"id": "tier0", "label": "Tier 0", "trust_level": 2},
    ],
    "components": [
        {"id": "ws1", "zone": "tier2", "role": "workstation"},
        {"id": "ws2", "zone": "tier2", "role": "workstation"},
        {"id": "ws3", "zone": "tier2", "role": "workstation"},
        {"id": "kiosk", "zone": "tier2"},  # no role: ungrouped
        {"id": "jump", "zone": "tier2", "role": "server"},  # "server" in tier 2: its own group
        {"id": "srv1", "zone": "tier1", "role": "server"},
        {"id": "srv2", "zone": "tier1", "role": "server"},
        {"id": "dc1", "zone": "tier0", "role": "dc"},
    ],
    "influences": [
        {"from": "ws1", "to": "srv1", "type": "data"},  # inversion, merged with ws2 -> srv1
        {"from": "ws2", "to": "srv1", "type": "data"},
        {"from": "ws3", "to": "srv2", "type": "control"},  # same endpoints after collapse, other type
        {"from": "ws1", "to": "ws2", "type": "data"},  # inside a group: dropped on collapse
        {"from": "srv1", "to": "dc1", "type": "control"},
        {"from": "ws1", "to": "dc1", "type": "control", "label": "RDP"},  # high inversion
        {"from": "kiosk", "to": "ws1", "type": "data"},
        {"from": "dc1", "to": "srv1", "type": "control"},  # downward: not an inversion
    ],
}


def _pg(tmp_path, data=AD, **options):
    path = tmp_path / "ad.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    pg = PrivilegeGradient(str(path), str(tmp_path / "o"), **options)
    pg.load()
    return pg


class TestMembership:
    def test_group_by_field_split_per_zone(self, tmp_path):
        groups = component_groups(_pg(tmp_path)._components, "role")
        assert groups["ws1"] == "tier2/workstation" and groups["jump"] == "tier2/server"
        assert groups["srv1"] == "tier1/server" and "kiosk" not in groups

    def test_own_group_wins(self):
        components = {"a": {"zone": "z", "role": "x", "group": "ops"}, "b": {"zone": "z", "role": "x"}}
        assert component_groups(components, "role") == {"a": "z/ops", "b": "z/x"}
        assert component_groups(components, None) == {"a": "z/ops"}


class TestView:
    def test_without_grouping_the_view_is_the_data(self, tmp_path):
        pg = _pg(tmp_path)
        view = pg.render_view()
        assert view.components is pg._components and not view.groups

    def test_expanded_groups(self, tmp_path):
        view = _pg(tmp_path, group_by="role").render_view()
        assert list(view.groups) == ["tier2/workstation", "tier2/server", "tier1/server", "tier0/dc"]
        assert view.groups["tier2/workstation"].members == ["ws1", "ws2", "ws3"]
        assert view.groups["tier2/workstation"].label == "workstation"
        assert view.group_zone["tier1/server"] == "tier1"
        assert view.group_of("ws2") == "tier2/workstation" and view.group_of("kiosk") is None
        assert len(view.components) == 8 and not any(g.collapsed for g in view.groups.values())

    def test_file_options(self, tmp_path):
        data = {**AD, "gradient": {"name": "AD", "group_by": "role", "collapse": True}}
        assert WS in _pg(tmp_path, data).render_view().components

    def test_render_options_override_the_file(self, tmp_path):
        data = {**AD, "gradient": {"name": "AD", "group_by": "role", "collapse": True}}
        assert WS not in _pg(tmp_path, data, collapse=False).render_view().components


class TestCollapse:
    @pytest.fixture
    def view(self, tmp_path):
        return _pg(tmp_path, group_by="role", collapse=True).render_view()

    def test_multi_member_groups_collapse(self, view):
        assert list(view.components) == [WS, "kiosk", "jump", SRV, "dc1"]  # summary in its first member's place
        assert view.components[WS] == {"id": WS, "label": "workstation", "zone": "tier2"}
        assert view.groups["tier2/workstation"].collapsed and not view.groups["tier0/dc"].collapsed

    def test_influences_are_repointed_merged_and_internal_ones_dropped(self, view):
        edges = [(i["from"], i["to"], i["type"]) for i in view.influences]
        assert edges == [
            (WS, SRV, "data"), (WS, SRV, "control"), (SRV, "dc1", "control"),
            (WS, "dc1", "control"), ("kiosk", WS, "data"), ("dc1", SRV, "control"),
        ]  # fmt: skip
        assert view.edge_marks[(WS, SRV, "data")].count == 2
        assert view.merged_from[(WS, SRV, "data")] == ["ws1->srv1:data", "ws2->srv1:data"]
        assert (WS, SRV, "control") not in view.edge_marks  # one edge, no drift: no mark
        assert next(i for i in view.influences if i["to"] == "dc1" and i["from"] == WS)["label"] == "RDP"

    def test_inversions_detected_on_the_collapsed_picture(self, view):
        found = {(i["from"], i["to"], i["influence_type"]): i["severity"] for i in view.inversions}
        assert found == {
            (WS, SRV, "data"): "medium",
            (WS, SRV, "control"): "medium",
            (SRV, "dc1", "control"): "medium",
            (WS, "dc1", "control"): "high",
        }

    def test_summary_facts(self, view):
        facts = view.summary_facts(WS)
        assert facts == {
            "label": "workstation", "zone": "tier2", "members": 3, "inversions": 4, "max_severity": "high",
        }  # fmt: skip
        # ws1 -> srv1, ws2 -> srv1, ws3 -> srv2 and srv1 -> dc1, all medium
        assert view.summary_facts(SRV)["inversions"] == 4 and view.summary_facts(SRV)["max_severity"] == "medium"
        assert view.summary_facts("kiosk") is None

    def test_full_model_is_untouched(self, tmp_path):
        pg = _pg(tmp_path, group_by="role", collapse=True)
        pg.render_view()
        assert len(pg._components) == 8 and len(pg._inversions) == 5


class TestCollapseChoice:
    def test_list(self, tmp_path):
        view = _pg(tmp_path, group_by="role", collapse="tier1/server").render_view()
        assert SRV in view.components and WS not in view.components

    def test_group_settings(self, tmp_path):
        data = {**AD, "groups": {"tier2/workstation": {"label": "Tier 2 workstations", "collapsed": False}}}
        view = _pg(tmp_path, data, group_by="role", collapse=True).render_view()
        assert WS not in view.components and SRV in view.components
        assert view.groups["tier2/workstation"].label == "Tier 2 workstations"

    def test_group_settings_as_tables(self, tmp_path):
        data = {**AD, "groups": [{"id": "tier1/server", "collapsed": True}]}
        assert SRV in _pg(tmp_path, data, group_by="role").render_view().components

    def test_auto(self, tmp_path):
        # 8 components; collapsing the 3 workstations reaches 6
        view = _pg(tmp_path, group_by="role", collapse="auto", max_nodes=6).render_view()
        assert WS in view.components and SRV not in view.components

    def test_collapse_without_groups_warns(self, tmp_path, caplog):
        view = _pg(tmp_path, collapse=True).render_view()
        assert len(view.components) == 8 and "collapse needs groups" in caplog.text


def test_zone_id_with_a_slash(tmp_path):
    data = {
        "gradient": {"name": "g"},
        "zones": [{"id": "corp/lan", "trust_level": 0}],
        "components": [{"id": "a", "zone": "corp/lan", "role": "ws"}],
    }
    view = _pg(tmp_path, data, group_by="role").render_view()
    assert view.groups["corp/lan/ws"].label == "ws"


def test_group_stats(tmp_path):
    data = {**AD, "groups": {"tier1/server": {"label": "Member servers"}}}
    stats = _pg(tmp_path, data, group_by="role").get_stats()
    assert stats["groups"]["tier2/workstation"] == {
        "label": "workstation", "zone": "tier2", "members": 3, "inversions": 4, "max_severity": "high",
    }  # fmt: skip
    assert stats["groups"]["tier1/server"]["label"] == "Member servers"
    assert "groups" not in _pg(tmp_path).get_stats()


def test_summary_label_lines():
    facts = {"label": "ws", "members": 3, "inversions": 2, "max_severity": "critical", "added": 1, "removed": 2}
    assert summary_label_lines(facts) == ["ws", "3 components", "!!! 2 inversions", "+1 \u22122"]
    assert summary_label_lines({"label": "one", "members": 1, "inversions": 0}) == ["one", "1 component"]


class TestGraphviz:
    @staticmethod
    def _source(tmp_path, **options):
        pg = _pg(tmp_path, group_by="role", **options)
        pg.render()
        return pg.graph.source

    @staticmethod
    def _line(source, start):
        return next(line for line in source.splitlines() if line.strip().startswith(start))

    def test_summary_card(self, tmp_path):
        source = self._source(tmp_path, collapse=True)
        card = self._line(source, "__group_tier2_workstation [")
        assert 'label="workstation\\n3 components\\n!! 4 inversions"' in card
        assert "shape=folder" in card and 'color="#cc0000"' in card and "penwidth=2.5" in card
        assert "ws2" not in source

    def test_merged_edge_label(self, tmp_path):
        source = self._source(tmp_path, collapse=True)
        assert "\u00d72" in self._line(source, "__group_tier2_workstation -> __group_tier1_server")

    def test_expanded_groups_are_nested_clusters(self, tmp_path):
        source = self._source(tmp_path)
        tier1 = source[source.index("subgraph cluster_tier1 {") : source.index("subgraph cluster_tier0 {")]
        assert "subgraph cluster_tier1_server {" in tier1 and "label=server" in tier1 and "dashed" in tier1
        nested = tier1[tier1.index("subgraph cluster_tier1_server") :]
        assert "srv1 [" in nested and "srv2 [" in nested

    def test_grouping_field_is_not_a_graphviz_attribute(self, tmp_path):
        assert "role=" not in self._source(tmp_path)

    def test_group_field_is_not_a_graphviz_attribute(self, tmp_path):
        data = {**AD, "components": [{**c, "group": "g1"} for c in AD["components"]]}
        pg = _pg(tmp_path, data)
        pg.render()
        assert "group=" not in pg.graph.source


class TestSizeLimit:
    @staticmethod
    def _big(n):
        return {
            "gradient": {"name": "big"},
            "zones": [{"id": "z", "trust_level": 0}],
            "components": [{"id": f"c{i}", "zone": "z", "role": "host"} for i in range(n)],
        }

    def test_too_many_components_fail_fast(self, tmp_path):
        with pytest.raises(PrivilegeGradientError, match="10001 nodes.*group_by"):
            _pg(tmp_path, self._big(10001)).render_view()

    def test_collapsed_they_render(self, tmp_path):
        view = _pg(tmp_path, self._big(10001), group_by="role", collapse="auto").render_view()
        assert list(view.components) == [SUMMARY_PREFIX + "z/host"]


class TestSvgScene:
    @staticmethod
    def _scene(tmp_path, **options):
        pg = _pg(tmp_path, group_by="role", **options)
        return painter._build_scene(pg, themes.resolve(pg.style))

    def test_summary_card(self, tmp_path):
        card = self._scene(tmp_path, collapse=True).node_by_id(WS)
        assert card.lines == ["workstation", "3 components", "!! 4 inversions"]
        assert card.data["kind"] == "group"
        assert card.data["collapsed"] == "true" and card.data["cluster-id"] == "tier2_workstation"
        assert card.data["member-count"] == "3" and card.data["inversion-count"] == "4"
        assert card.data["max-severity"] == "high"

    def test_summary_border_is_the_inversion_color(self, tmp_path):
        pg = _pg(tmp_path, group_by="role", collapse=True)
        theme = themes.resolve(pg.style)
        scene = painter._build_scene(pg, theme)
        assert scene.node_by_id(WS).border == theme["privilegegradient"]["inversion"]

    def test_nested_clusters(self, tmp_path):
        scene = self._scene(tmp_path)
        nested = {g.id: g for g in scene.groups if g.parent}
        assert set(nested) == {"tier2_workstation", "tier2_server", "tier1_server", "tier0_dc"}
        assert nested["tier1_server"].parent == "tier1" and nested["tier1_server"].dashed
        assert nested["tier1_server"].members == ["srv1", "srv2"]
        assert nested["tier1_server"].data == {"zone": "tier1", "collapsed": "false"}

    def test_merged_edge(self, tmp_path):
        scene = self._scene(tmp_path, collapse=True)
        edge = next(e for e in scene.edges if (e.src, e.dst, e.data.get("type")) == (WS, SRV, "data"))
        assert edge.data["edge-count"] == "2" and edge.label.endswith("\u00d72")


@requires_dot
def test_template_svg_contract(tmp_path):
    pg = PrivilegeGradient(str(TEMPLATE), str(tmp_path / "o"), format="svg", render_engine="svg")
    pg.build()
    root = ET.fromstring((tmp_path / "o.svg").read_text(encoding="utf-8"))
    groups = list(root.iter(f"{SVG_NS}g"))
    summary = next(g for g in groups if "usv-node--group" in g.get("class", ""))
    assert summary.get("data-collapsed") == "true" and summary.get("data-member-count") == "5"
    assert summary.get("data-cluster-id") == "tier2_workstation"
    clusters = [g for g in groups if "usv-cluster" in g.get("class", "") and g.get("data-collapsed") == "false"]
    assert {g.get("data-cluster-id") for g in clusters} >= {"tier1_app_server", "tier0_domain_controller"}
    assert any(g.get("data-edge-count") == "2" for g in groups)


def test_builder():
    from usecvislib.builders import PrivilegeGradientBuilder

    builder = (
        PrivilegeGradientBuilder("AD", use_default_zones=False)
        .add_zone("tier2", "Tier 2", 0)
        .add_component("ws1", "WS 1", "tier2", role="workstation")
        .add_component("ws2", "WS 2", "tier2", role="workstation")
        .set_grouping("role", collapse="auto", max_nodes=50)
        .add_group("tier2/workstation", label="Workstations", collapsed=True)
    )
    data = builder.build()
    assert data["gradient"]["group_by"] == "role" and data["gradient"]["collapse"] == "auto"
    assert data["gradient"]["max_nodes"] == 50
    assert data["groups"] == {"tier2/workstation": {"label": "Workstations", "collapsed": True}}
    pg = builder.to_privilege_gradient("unused")
    pg.load()
    assert pg.render_view().summary_facts(WS)["label"] == "Workstations"


@requires_dot
def test_cli(tmp_path):
    import os
    import subprocess
    import sys

    path = tmp_path / "ad.json"
    path.write_text(json.dumps(AD), encoding="utf-8")
    env = {**os.environ, "PYTHONPATH": str(Path(__file__).parent.parent / "src")}
    out = subprocess.run(
        [sys.executable, "-m", "usecvislib.usecvis", "-m", "6", "-i", str(path), "-o", str(tmp_path / "o"),
         "-f", "svg", "--render-engine", "svg", "--group-by", "role", "--collapse", "tier2/workstation"],
        capture_output=True, text=True, env=env, cwd=tmp_path,
    )  # fmt: skip
    assert out.returncode == 0, out.stderr
    assert "tier2/workstation: 3 components, 4 inversions" in out.stdout
    assert 'data-cluster-id="tier2_workstation"' in (tmp_path / "o.svg").read_text(encoding="utf-8")


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

    @staticmethod
    def _file(data=AD):
        return {"file": ("ad.json", json.dumps(data).encode())}

    def test_analyze_groups(self, client):
        response = client.post("/analyze/privilege-gradient", params={"group_by": "role"}, files=self._file())
        assert response.status_code == 200, response.text
        assert response.json()["groups"]["tier2/workstation"] == {
            "label": "workstation", "zone": "tier2", "members": 3, "inversions": 4, "max_severity": "high",
        }  # fmt: skip

    def test_size_limit_is_a_client_error(self, client):
        response = client.post("/visualize/privilege-gradient", files=self._file(TestSizeLimit._big(10001)))
        assert response.status_code == 400 and "group_by" in response.json()["detail"]

    @requires_dot
    def test_visualize_grouped(self, client):
        response = client.post(
            "/visualize/privilege-gradient",
            params={"format": "svg", "render_engine": "svg", "group_by": "role", "collapse": "all"},
            files=self._file(),
        )
        assert response.status_code == 200, response.text
        assert 'data-collapsed="true"' in response.text and 'data-edge-count="2"' in response.text
