#
# VULNEX -Universal Security Visualization Library-
#
# File: test_privilegegradient_keep.py
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
#

"""Kept components in collapsed Privilege-Gradient groups (Atajo A12): the render view."""

import json
import shutil

import pytest

from tests.test_privilegegradient_grouping import AD, SRV, WS
from usecvislib.privilegegradient import PrivilegeGradient
from usecvislib.privilegegradient_view import GradientView, kept_components, summary_label_lines

requires_dot = pytest.mark.skipif(shutil.which("dot") is None, reason="rendering needs Graphviz 'dot'")

# AD plus three workstations without inversions: with keep = "inversions", ws1-ws3
# (all in inversions) stay drawn and ws4-ws6 fold into the card
AD_CLEAN_WS = {
    **AD,
    "components": AD["components"] + [{"id": f"ws{i}", "zone": "tier2", "role": "workstation"} for i in (4, 5, 6)],
}


def _pg(tmp_path, data=AD, **options):
    path = tmp_path / "ad.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    pg = PrivilegeGradient(str(path), str(tmp_path / "o"), group_by="role", **options)
    pg.load()
    return pg


class TestKeptSet:
    def test_inversion_endpoints(self, tmp_path):
        view = GradientView({}, {c["id"]: c for c in AD["components"]}, AD["influences"], _pg(tmp_path)._inversions)
        assert kept_components(view, "inversions", None) == {"ws1", "ws2", "ws3", "srv1", "srv2", "dc1"}

    def test_drift_endpoints_of_fixed_inversions(self):
        # A fixed inversion is no inversion in the merged picture: its status keeps it named
        view = GradientView({}, {"a": {}, "b": {}, "c": {}}, [], [], inversion_status={"a->b:data": "fixed"})
        assert kept_components(view, "inversions", None) == {"a", "b"}

    def test_ids_and_warnings(self, caplog):
        view = GradientView({}, {"a": {}, "b": {}}, [], [])
        assert kept_components(view, None, ["a", "zz"]) == {"a"}
        assert "zz" in caplog.text
        assert kept_components(view, "everything", None) == set()
        assert "unknown value 'everything'" in caplog.text


class TestKeepIds:
    def test_kept_member_stays_drawn(self, tmp_path):
        view = _pg(tmp_path, collapse=True, keep_ids=["ws1"]).render_view()
        assert "ws1" in view.components and WS in view.components
        assert view.kept == {"ws1"} and view.group_of("ws1") == "tier2/workstation"

    def test_card_counts_folded_members(self, tmp_path):
        facts = _pg(tmp_path, collapse=True, keep_ids=["ws1"]).render_view().summary_facts(WS)
        # ws2 -> srv1 and ws3 -> srv2 (ws1's own inversions are drawn on ws1)
        assert facts["members"] == 2 and facts["kept"] == 1 and facts["inversions"] == 2
        assert summary_label_lines(facts) == ["workstation", "2 components", "1 shown separately", "! 2 inversions"]

    def test_kept_member_keeps_its_influences(self, tmp_path):
        view = _pg(tmp_path, collapse=True, keep_ids=["ws1"]).render_view()
        edges = {(i["from"], i["to"], i["type"]) for i in view.influences}
        assert ("ws1", SRV, "data") in edges and ("ws1", "dc1", "control") in edges
        assert ("ws1", WS, "data") in edges  # ws1 -> ws2: a kept member to its own group's card
        assert ("kiosk", "ws1", "data") in edges
        assert (WS, SRV, "data") in edges and (WS, SRV, "data") not in view.edge_marks  # only ws2 -> srv1: no merge
        found = {(i["from"], i["to"], i["influence_type"]) for i in view.inversions}
        assert ("ws1", "dc1", "control") in found and ("ws1", WS, "data") not in found

    def test_file_options(self, tmp_path):
        data = {**AD, "gradient": {"name": "AD", "collapse": True, "keep_ids": "ws1, ws2"}}
        view = _pg(tmp_path, data).render_view()
        assert view.kept == {"ws1", "ws2"}
        assert WS not in view.components  # one foldable member left: not collapsed by true

    def test_render_options_override_the_file(self, tmp_path):
        data = {**AD, "gradient": {"name": "AD", "collapse": True, "keep_ids": ["ws1", "ws2"]}}
        assert _pg(tmp_path, data, keep_ids=[]).render_view().kept == set()


class TestKeepInversions:
    def test_only_clean_members_fold(self, tmp_path):
        view = _pg(tmp_path, AD_CLEAN_WS, collapse=True, keep="inversions").render_view()
        facts = view.summary_facts(WS)
        assert facts["members"] == 3 and facts["kept"] == 3 and facts["inversions"] == 0
        assert {"ws1", "ws2", "ws3"} <= set(view.components)
        assert not {"ws4", "ws5", "ws6"} & set(view.components)

    def test_group_with_every_member_kept_is_not_collapsed(self, tmp_path):
        # srv1 and srv2 both take part in inversions
        view = _pg(tmp_path, AD_CLEAN_WS, collapse=True, keep="inversions").render_view()
        assert SRV not in view.components and not view.groups["tier1/server"].collapsed

    def test_auto_counts_kept_members(self, tmp_path):
        # 11 components; folding ws4-ws6 into one card draws 9
        view = _pg(tmp_path, AD_CLEAN_WS, collapse="auto", max_nodes=9, keep="inversions").render_view()
        assert WS in view.components and len(view.components) == 9

    def test_full_model_is_untouched(self, tmp_path):
        pg = _pg(tmp_path, AD_CLEAN_WS, collapse=True, keep="inversions")
        pg.render_view()
        assert len(pg._inversions) == 5
        assert pg.get_stats()["groups"]["tier2/workstation"]["members"] == 6


class TestOneFoldableMember:
    def test_true_and_auto_skip_the_group(self, tmp_path):
        for collapse in (True, "auto"):
            view = _pg(tmp_path, collapse=collapse, max_nodes=1, keep_ids=["ws1", "ws2"]).render_view()
            assert WS not in view.components

    def test_explicit_collapse_still_applies(self, tmp_path):
        view = _pg(tmp_path, collapse="tier2/workstation", keep_ids=["ws1", "ws2"]).render_view()
        assert view.summary_facts(WS)["members"] == 1

    def test_nothing_to_fold(self, tmp_path):
        view = _pg(tmp_path, collapse="tier2/workstation", keep_ids=["ws1", "ws2", "ws3"]).render_view()
        assert WS not in view.components and not view.groups["tier2/workstation"].collapsed


class TestGraphviz:
    def test_frame_holds_card_and_kept_members(self, tmp_path):
        pg = _pg(tmp_path, collapse=True, keep_ids=["ws1"])
        pg.render()
        source = pg.graph.source
        frame = source[source.index("subgraph cluster_tier2_workstation {") :]
        frame = frame[: frame.index("}")]
        assert "__group_tier2_workstation [" in frame and "ws1 [" in frame
        assert "dashed" in frame and "label=workstation" in frame

    def test_without_kept_members_the_card_is_bare(self, tmp_path):
        pg = _pg(tmp_path, collapse=True)
        pg.render()
        assert "cluster_tier2_workstation" not in pg.graph.source


class TestSvgScene:
    @staticmethod
    def _scene(tmp_path, **options):
        from usecvislib.svgengine import themes
        from usecvislib.svgengine.painters import privilegegradient as painter

        pg = _pg(tmp_path, **options)
        return painter._build_scene(pg, themes.resolve(pg.style))

    def test_frame(self, tmp_path):
        scene = self._scene(tmp_path, collapse=True, keep_ids=["ws1"])
        frame = next(g for g in scene.groups if g.id == "tier2_workstation")
        assert frame.members == [WS, "ws1"] and frame.parent == "tier2" and frame.dashed
        assert frame.data == {"zone": "tier2", "collapsed": "true", "kept-count": "1"}

    def test_card_and_kept_member_data(self, tmp_path):
        scene = self._scene(tmp_path, collapse=True, keep_ids=["ws1"])
        assert scene.node_by_id(WS).data["kept-count"] == "1"
        kept = scene.node_by_id("ws1").data
        assert kept["kept"] == "true" and kept["cluster-id"] == "tier2_workstation"
        assert "kept" not in scene.node_by_id("kiosk").data

    def test_kept_member_of_an_expanded_group_is_ordinary(self, tmp_path):
        scene = self._scene(tmp_path, keep_ids=["ws1"])  # nothing collapsed
        assert "kept" not in scene.node_by_id("ws1").data


def test_builder():
    from usecvislib.builders import PrivilegeGradientBuilder

    data = (
        PrivilegeGradientBuilder("AD")
        .set_grouping("role", collapse=True, keep="inversions", keep_ids=("ws_0101",))
        .build()
    )
    assert data["gradient"]["keep"] == "inversions" and data["gradient"]["keep_ids"] == ["ws_0101"]


# Drift: ws5 -> app9 is an inversion; app9 moves down to tier 2, which fixes it (the
# influence stays). ws5 has no other inversion, so only the fixed status keeps it named.
AD_FIX_OLD = {
    **AD_CLEAN_WS,
    "components": AD_CLEAN_WS["components"] + [{"id": "app9", "zone": "tier1", "role": "app"}],
    "influences": AD_CLEAN_WS["influences"] + [{"from": "ws5", "to": "app9", "type": "data"}],
}
AD_FIX_NEW = {
    **AD_FIX_OLD,
    "components": [{**c, "zone": "tier2"} if c["id"] == "app9" else c for c in AD_FIX_OLD["components"]],
}


def _versions(tmp_path):
    old, new = tmp_path / "v1.json", tmp_path / "v2.json"
    old.write_text(json.dumps(AD_FIX_OLD), encoding="utf-8")
    new.write_text(json.dumps(AD_FIX_NEW), encoding="utf-8")
    return str(old), str(new)


@requires_dot
def test_render_diff_keeps_fixed_inversion_endpoints(tmp_path):
    from usecvislib import render_diff

    result = render_diff(
        *_versions(tmp_path), "privilege_gradient", output=str(tmp_path / "d"), format="svg",
        render_engine="svg", group_by="role", collapse=True, keep="inversions",
    )  # fmt: skip
    assert [(i["from"], i["to"]) for i in result.metadata["inversions"]["fixed"]] == [("ws5", "app9")]
    svg = (tmp_path / "d.svg").read_text(encoding="utf-8")
    assert 'data-node-id="ws5"' in svg  # its violation was fixed: still named
    assert 'data-node-id="ws6"' not in svg  # clean: folded into the card


@requires_dot
def test_render_diff_attack_graph_ignores_keep(tmp_path, caplog):
    from usecvislib import render_diff

    old = tmp_path / "a1.json"
    old.write_text(json.dumps({"graph": {"name": "g"}, "hosts": {"h": {"label": "h"}}}), encoding="utf-8")
    render_diff(str(old), str(old), output=str(tmp_path / "d"), format="svg", keep_ids=["h"])
    assert "privilege gradients only" in caplog.text


@requires_dot
def test_cli(tmp_path):
    import os
    import subprocess
    import sys
    from pathlib import Path

    path = tmp_path / "ad.json"
    path.write_text(json.dumps(AD), encoding="utf-8")
    env = {**os.environ, "PYTHONPATH": str(Path(__file__).parent.parent / "src")}
    out = subprocess.run(
        [sys.executable, "-m", "usecvislib.usecvis", "-m", "6", "-i", str(path), "-o", str(tmp_path / "o"),
         "-f", "svg", "--render-engine", "svg", "--group-by", "role", "--collapse", "all",
         "--keep-ids", "ws1"],
        capture_output=True, text=True, env=env, cwd=tmp_path,
    )  # fmt: skip
    assert out.returncode == 0, out.stderr
    svg = (tmp_path / "o.svg").read_text(encoding="utf-8")
    assert 'data-kept="true"' in svg and 'data-kept-count="1"' in svg


class TestApi:
    @pytest.fixture
    def client(self):
        import os
        import sys
        from pathlib import Path

        sys.path.insert(0, str(Path(__file__).parent.parent / "api"))
        os.environ["USECVISLIB_AUTH_ENABLED"] = "false"
        from fastapi.testclient import TestClient

        from api.config import limiter
        from api.main import app

        limiter.reset()
        yield TestClient(app)
        limiter.reset()

    @requires_dot
    def test_visualize_keep_ids(self, client):
        response = client.post(
            "/visualize/privilege-gradient",
            params={"format": "svg", "render_engine": "svg", "group_by": "role", "collapse": "all", "keep_ids": "ws1"},
            files={"file": ("ad.json", json.dumps(AD).encode())},
        )
        assert response.status_code == 200, response.text
        assert 'data-kept="true"' in response.text and 'data-kept-count="1"' in response.text

    @requires_dot
    def test_diff_render_keep(self, client, tmp_path):
        from pathlib import Path

        old, new = _versions(tmp_path)
        response = client.post(
            "/diff/render",
            params={
                "format": "svg",
                "render_engine": "svg",
                "group_by": "role",
                "collapse": "all",
                "keep": "inversions",
            },
            files={"old_file": ("v1.json", Path(old).read_bytes()), "new_file": ("v2.json", Path(new).read_bytes())},
        )
        assert response.status_code == 200, response.text
        assert 'data-node-id="ws5"' in response.text and 'data-node-id="ws6"' not in response.text
