#
# VULNEX -Universal Security Visualization Library-
#
# File: test_privilegegradient_grouping.py
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
#

"""Grouping and collapse for the Privilege Gradient (Atajo A11): the render view."""

import json

import pytest

from usecvislib.grouping import SUMMARY_PREFIX
from usecvislib.privilegegradient import PrivilegeGradient
from usecvislib.privilegegradient_view import component_groups

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


class TestGraphviz:
    def test_collapsed_summary_is_drawn(self, tmp_path):
        pg = _pg(tmp_path, group_by="role", collapse=True)
        pg.render()
        source = pg.graph.source
        assert "workstation" in source and "ws2" not in source

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
        with pytest.raises(ValueError, match="10001 nodes"):
            _pg(tmp_path, self._big(10001)).render_view()

    def test_collapsed_they_render(self, tmp_path):
        view = _pg(tmp_path, self._big(10001), group_by="role", collapse="auto").render_view()
        assert list(view.components) == [SUMMARY_PREFIX + "z/host"]
