#
# VULNEX -Universal Security Visualization Library-
#
# File: test_diffrender_privilegegradient.py
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
#

"""Drift renderer for the Privilege Gradient (Atajo A9): zones, components,
influences and the inversions (tiering violations) that appeared or were fixed."""

import copy
import json
import os
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from usecvislib import render_diff
from usecvislib.diffrender import (
    SUPPORTED_TYPES,
    influence_key,
    merge_privilege_gradients,
    normalize_privilege_gradient,
    privilege_gradient_inversion_changes,
)
from usecvislib.privilegegradient import PrivilegeGradient, detect_inversions

SVG_NS = "{http://www.w3.org/2000/svg}"
REPO = Path(__file__).parent.parent
requires_dot = pytest.mark.skipif(shutil.which("dot") is None, reason="rendering needs Graphviz 'dot'")

OLD = {
    "gradient": {"name": "Tiers"},
    "zones": [
        {"id": "low", "label": "Low", "trust_level": 0, "color": "#ffcccc", "border_color": "#cc0000"},
        {"id": "mid", "label": "Mid", "trust_level": 1, "color": "#ffe0b2", "border_color": "#e65100"},
        {"id": "high", "label": "High", "trust_level": 2, "color": "#c8e6c9", "border_color": "#2e7d32"},
        {"id": "legacy", "label": "Legacy", "trust_level": 1, "color": "#eeeeee", "border_color": "#666666"},
    ],
    "components": [
        {"id": "a", "label": "Client", "zone": "low"},
        {"id": "b", "label": "App", "zone": "mid"},
        {"id": "c", "label": "DB", "zone": "high"},
        {"id": "d", "label": "Worker", "zone": "mid"},
        {"id": "l", "label": "Old box", "zone": "legacy"},
    ],
    "influence_types": [
        {"id": "data", "label": "Data", "color": "#3498db"},
        {"id": "control", "label": "Control", "color": "#8e44ad"},
        {"id": "resource", "label": "Resource", "color": "#27ae60"},
        {"id": "feedback", "label": "Feedback", "color": "#e67e22"},
    ],
    "influences": [
        {"from": "a", "to": "b", "type": "data", "label": "HTTP"},  # inversion in both versions
        {"from": "b", "to": "c", "type": "data", "label": "SQL"},  # inversion fixed by moving c down
        {"from": "c", "to": "d", "type": "control"},  # type changes: removed + added
        {"from": "d", "to": "l", "type": "feedback"},  # removed with l
    ],
}

NEW = copy.deepcopy(OLD)
NEW["zones"] = [z for z in NEW["zones"] if z["id"] != "legacy"]  # removed zone
NEW["zones"].append({"id": "vault", "label": "Vault", "trust_level": 3, "color": "#e3f2fd", "border_color": "#1565c0"})
NEW["components"] = [c for c in NEW["components"] if c["id"] != "l"]  # removed component
NEW["components"][2]["zone"] = "mid"  # c moves down a tier: modified, fixes b -> c
NEW["components"].append({"id": "e", "label": "HSM", "zone": "vault"})  # added
NEW["influences"] = [
    {"from": "a", "to": "b", "type": "data", "label": "HTTPS"},  # modified label
    {"from": "b", "to": "c", "type": "data", "label": "SQL"},
    {"from": "c", "to": "d", "type": "resource"},
    {"from": "d", "to": "e", "type": "data", "label": "Keys"},  # new inversion, gap 2
]


@pytest.fixture
def versions(tmp_path):
    old, new = tmp_path / "v1.json", tmp_path / "v2.json"
    old.write_text(json.dumps(OLD), encoding="utf-8")
    new.write_text(json.dumps(NEW), encoding="utf-8")
    return str(old), str(new)


def _normalized():
    return normalize_privilege_gradient(OLD), normalize_privilege_gradient(NEW)


def _merged(ignore=None):
    return merge_privilege_gradients(*_normalized(), ignore)


def test_supported():
    assert "privilege_gradient" in SUPPORTED_TYPES


class TestNormalize:
    def test_sections_keyed_by_identity(self):
        data = normalize_privilege_gradient(OLD)
        assert set(data["zones"]) == {"low", "mid", "high", "legacy"}
        assert set(data["components"]) == {"a", "b", "c", "d", "l"}
        assert "c->d:control" in data["influences"]

    def test_influence_type_defaults_to_data(self):
        assert influence_key({"from": "x", "to": "y"}) == "x->y:data"

    def test_input_unchanged(self):
        before = copy.deepcopy(OLD)
        normalize_privilege_gradient(OLD)
        assert before == OLD

    def test_zone_less_versions_compare_equal(self, tmp_path):
        # Default zones are filled in (by loading) before comparing
        from usecvislib.diffrender import _privilege_gradient_data

        path = tmp_path / "pg.json"
        path.write_text(json.dumps({"components": [{"id": "a", "zone": "Z0"}, {"id": "b", "zone": "Z2"}]}))
        data = normalize_privilege_gradient(_privilege_gradient_data(str(path)))
        assert len(data["zones"]) == 5
        assert data == normalize_privilege_gradient(_privilege_gradient_data(str(path)))


class TestMerge:
    def test_node_status(self):
        _, marks = _merged()
        status = {key: mark[0] for key, mark in marks.nodes.items()}
        assert status["zone:legacy"] == "removed" and status["zone:vault"] == "added"
        assert status["zone:low"] == "unchanged"
        assert status["l"] == "removed" and status["e"] == "added" and status["a"] == "unchanged"
        assert marks.nodes["c"] == ("modified", ["zone"])

    def test_influence_status(self):
        _, marks = _merged()
        assert marks.edges[("a", "b", "data")] == "modified"
        assert marks.edges[("b", "c", "data")] == "unchanged"
        # A type change is one removed and one added influence (VULNEX decision 1)
        assert marks.edges[("c", "d", "control")] == "removed"
        assert marks.edges[("c", "d", "resource")] == "added"
        assert marks.edges[("d", "l", "feedback")] == "removed"

    def test_removed_elements_are_drawn_from_the_old_version(self):
        merged, _ = _merged()
        assert {z["id"] for z in merged["zones"]} >= {"legacy", "vault"}
        assert next(c for c in merged["components"] if c["id"] == "c")["zone"] == "mid"  # drawn in its new zone
        assert any(i["from"] == "d" and i["to"] == "l" for i in merged["influences"])

    def test_inversion_status(self):
        _, marks = _merged()
        assert marks.extra["inversions"] == {
            "a->b:data": "unchanged",
            "b->c:data": "fixed",
            "d->e:data": "new",
        }


def test_inversion_metadata():
    changes = privilege_gradient_inversion_changes(*_normalized())["inversions"]
    assert [(i["from"], i["to"], i["severity"]) for i in changes["new"]] == [("d", "e", "high")]
    assert [(i["from"], i["to"]) for i in changes["fixed"]] == [("b", "c")]
    assert changes["changed"] == []  # a -> b keeps its gap


# Atajo A10: inversions that persist with another severity or trust gap. Raising
# the top zone from trust 3 to 4 turns y -> w from high (gap 2) into critical
# (gap 3), and x -> w from gap 3 into gap 4 (critical both times).
RETIER_OLD = {
    "gradient": {"name": "Re-tier"},
    "zones": [
        {"id": "z0", "label": "Edge", "trust_level": 0},
        {"id": "z1", "label": "Servers", "trust_level": 1},
        {"id": "z2", "label": "Core", "trust_level": 3},
    ],
    "components": [{"id": "x", "zone": "z0"}, {"id": "y", "zone": "z1"}, {"id": "w", "zone": "z2"}],
    "influences": [
        {"from": "x", "to": "y", "type": "data"},
        {"from": "y", "to": "w", "type": "control", "label": "admin"},
        {"from": "x", "to": "w", "type": "data"},
    ],
}
RETIER_NEW = copy.deepcopy(RETIER_OLD)
RETIER_NEW["zones"][2]["trust_level"] = 4


@pytest.fixture
def retier(tmp_path):
    old, new = tmp_path / "r1.json", tmp_path / "r2.json"
    old.write_text(json.dumps(RETIER_OLD), encoding="utf-8")
    new.write_text(json.dumps(RETIER_NEW), encoding="utf-8")
    return str(old), str(new)


class TestChangedInversions:
    def _normalized(self):
        return normalize_privilege_gradient(RETIER_OLD), normalize_privilege_gradient(RETIER_NEW)

    def test_metadata(self):
        changes = privilege_gradient_inversion_changes(*self._normalized())["inversions"]
        assert changes["new"] == [] and changes["fixed"] == []
        assert changes["changed"] == [
            {"from": "y", "to": "w", "influence_type": "control", "from_zone": "z1", "to_zone": "z2",
             "old_severity": "high", "new_severity": "critical", "old_trust_gap": 2, "new_trust_gap": 3,
             "label": "admin"},
            {"from": "x", "to": "w", "influence_type": "data", "from_zone": "z0", "to_zone": "z2",
             "old_severity": "critical", "new_severity": "critical", "old_trust_gap": 3, "new_trust_gap": 4,
             "label": ""},
        ]  # fmt: skip

    def test_marks(self):
        _, marks = merge_privilege_gradients(*self._normalized())
        assert marks.extra["inversions"] == {
            "x->y:data": "unchanged",
            "y->w:control": "changed",
            "x->w:data": "changed",
        }
        assert marks.extra["inversions_before"] == {
            "y->w:control": {"severity": "high", "trust_gap": 2},
            "x->w:data": {"severity": "critical", "trust_gap": 3},
        }

    def test_graphviz(self, tmp_path):
        merged, marks = merge_privilege_gradients(*self._normalized())
        path = tmp_path / "m.json"
        path.write_text(json.dumps(merged), encoding="utf-8")
        pg = PrivilegeGradient(str(path), str(tmp_path / "o"))
        pg.diff_marks = marks
        pg.load()
        pg.render()
        lines = pg.graph.source.splitlines()
        severity = next(line for line in lines if line.strip().startswith("y -> w"))
        assert "~ INVERSION (high \u2192 critical)" in severity and "#7c3aed" in severity
        gap = next(line for line in lines if line.strip().startswith("x -> w"))
        assert "~ INVERSION (critical, gap 3 \u2192 4)" in gap
        assert "~ INVERSION" not in next(line for line in lines if line.strip().startswith("x -> y"))
        # The zone's border shows the change; its cards keep the zone color
        card = next(line for line in lines if line.strip().startswith("w ["))
        assert "#7c3aed" not in card

    def test_changes_only_keeps_changed_inversions(self, tmp_path):
        merged, marks = merge_privilege_gradients(*self._normalized())
        path = tmp_path / "m.json"
        path.write_text(json.dumps(merged), encoding="utf-8")
        pg = PrivilegeGradient(str(path), str(tmp_path / "o"))
        pg.diff_marks, pg.show_unchanged = marks, False
        pg.load()
        assert set(pg.drift_view().components) == {"x", "y", "w"}

    @requires_dot
    def test_svg(self, retier, tmp_path):
        render_diff(*retier, "privilege_gradient", output=str(tmp_path / "d"), format="svg", render_engine="svg")
        root = ET.fromstring((tmp_path / "d.svg").read_text(encoding="utf-8"))
        edges = {
            (g.get("data-from"), g.get("data-to")): g
            for g in root.iter(f"{SVG_NS}g")
            if "usv-edge" in g.get("class", "").split()
        }
        changed = edges[("y", "w")]
        assert changed.get("data-inversion") == "changed" and changed.get("data-severity") == "critical"
        assert changed.get("data-old-severity") == "high" and changed.get("data-old-trust-gap") == "2"
        assert edges[("x", "y")].get("data-inversion") == "unchanged"
        assert "data-old-severity" not in edges[("x", "y")].attrib
        text = " ".join(t.text or "" for t in root.iter(f"{SVG_NS}text"))
        assert "~ INVERSION (high \u2192 critical) · admin" in text

    @requires_dot
    def test_cli(self, retier, tmp_path):
        env = {**os.environ, "PYTHONPATH": str(REPO / "src")}
        out = subprocess.run(
            [sys.executable, "-m", "usecvislib.usecvis", "-m", "6", "-i", retier[1], "--diff", retier[0],
             "-o", str(tmp_path / "drift"), "-f", "svg"],
            capture_output=True, text=True, env=env, cwd=tmp_path,
        )  # fmt: skip
        assert out.returncode == 0, out.stderr
        assert "Changed inversion: y -> w (high -> critical)" in out.stdout
        assert "Changed inversion: x -> w (critical, gap 3 -> 4)" in out.stdout


def test_detect_inversions_matches_the_class():
    pg = PrivilegeGradient(str(REPO / "templates" / "privilege-gradient" / "corporate_network.tml"), "unused")
    pg.load()
    assert detect_inversions(pg._zones, pg._components, pg._influences) == pg._inversions


def _viz(tmp_path, colors=None, show_unchanged=True):
    merged, marks = _merged()
    path = tmp_path / "merged.json"
    path.write_text(json.dumps(merged), encoding="utf-8")
    pg = PrivilegeGradient(str(path), str(tmp_path / "o"))
    pg.diff_marks, pg.diff_colors, pg.show_unchanged = marks, colors, show_unchanged
    pg.load()
    return pg


class TestView:
    def test_without_a_drift_the_view_is_the_data(self, tmp_path):
        pg = PrivilegeGradient(str(REPO / "templates" / "privilege-gradient" / "corporate_network.tml"), "unused")
        pg.load()
        view = pg.drift_view()
        assert view.components is pg._components and not view.marks and not view.inversion_status

    def test_changes_only(self, tmp_path):
        view = _viz(tmp_path, show_unchanged=False).drift_view()
        # Every component here is a change or next to one (a is on the modified a -> b)
        assert set(view.components) == {"a", "b", "c", "d", "e", "l"}
        assert "legacy" in view.zones and "vault" in view.zones

    def test_changes_only_drops_untouched_parts(self, tmp_path):
        merged, marks = _merged()
        merged["components"].append({"id": "far", "zone": "low"})
        merged["components"].append({"id": "far2", "zone": "low"})
        merged["influences"].append({"from": "far", "to": "far2", "type": "data"})
        marks.nodes["far"] = marks.nodes["far2"] = ("unchanged", [])
        marks.edges[("far", "far2", "data")] = "unchanged"
        path = tmp_path / "m.json"
        path.write_text(json.dumps(merged), encoding="utf-8")
        pg = PrivilegeGradient(str(path), str(tmp_path / "o"))
        pg.diff_marks, pg.show_unchanged = marks, False
        pg.load()
        view = pg.drift_view()
        assert "far" not in view.components and "far2" not in view.components
        assert all("far" not in (i["from"], i["to"]) for i in view.influences)


class TestGraphviz:
    def _source(self, tmp_path, colors=None):
        pg = _viz(tmp_path, colors)
        pg.render()
        return pg.graph.source

    @staticmethod
    def _line(source, start):
        return next(line for line in source.splitlines() if line.strip().startswith(start))

    def test_zones(self, tmp_path):
        source = self._source(tmp_path)
        assert "\u2212 Legacy" in source and "+ Vault" in source
        legacy = source[source.index("cluster_legacy") :].split("}", 1)[0]
        assert "#94a3b8" in legacy and "#eeeeee59" in legacy  # removed border, faded fill

    def test_components(self, tmp_path):
        source = self._source(tmp_path)
        assert '"+ HSM"' in self._line(source, "e ") and "#d6336c" in self._line(source, "e ")
        assert '"~ DB"' in self._line(source, "c ") and 'tooltip="changed: zone"' in self._line(source, "c ")
        assert "dashed" in self._line(source, "l ")

    def test_influences_and_inversions(self, tmp_path):
        source = self._source(tmp_path)
        assert "NEW INVERSION" in self._line(source, "d -> e")
        fixed = self._line(source, "b -> c")
        assert "FIXED INVERSION" in fixed and "#94a3b8" in fixed
        assert "!! INVERSION" not in fixed
        assert "! INVERSION !" in self._line(source, "a -> b")  # still an inversion
        assert "dashed" in self._line(source, "d -> l")
        assert "+ added" in source and "~ modified" in source  # legend in the title

    def test_modified_influence_takes_the_modified_color(self, tmp_path):
        merged, marks = _merged()
        marks.extra["inversions"].pop("a->b:data")
        merged["zones"] = [dict(z, trust_level=1) if z["id"] == "low" else z for z in merged["zones"]]
        path = tmp_path / "m.json"
        path.write_text(json.dumps(merged), encoding="utf-8")
        pg = PrivilegeGradient(str(path), str(tmp_path / "o"))
        pg.diff_marks = marks
        pg.load()
        pg.render()
        assert "#7c3aed" in self._line(pg.graph.source, "a -> b")

    def test_diff_colors_override(self, tmp_path):
        source = self._source(tmp_path, {"added": "#e8590c"})
        assert "#e8590c" in source and "#d6336c" not in source


class TestRenderDiff:
    @requires_dot
    @pytest.mark.parametrize("engine", ["graphviz", "svg"])
    def test_returns_the_diff_and_inversions(self, versions, tmp_path, engine):
        result = render_diff(
            *versions, "privilege_gradient", output=str(tmp_path / "d"), format="svg", render_engine=engine
        )
        assert (tmp_path / "d.svg").exists()
        assert result.has_changes
        assert [(i["from"], i["to"]) for i in result.metadata["inversions"]["new"]] == [("d", "e")]
        assert [(i["from"], i["to"]) for i in result.metadata["inversions"]["fixed"]] == [("b", "c")]

    @requires_dot
    def test_grouping_options_group_the_merged_gradient(self, versions, tmp_path):
        # Grouped by their zone field, the mid zone's b, c, d collapse into one card (A11)
        render_diff(
            *versions, "privilege_gradient", output=str(tmp_path / "d"), format="svg", render_engine="svg",
            group_by="zone", collapse=True,
        )  # fmt: skip
        svg = (tmp_path / "d.svg").read_text(encoding="utf-8")
        assert 'data-cluster-id="mid_mid"' in svg and 'data-collapsed="true"' in svg

    @requires_dot
    def test_svg_contract(self, versions, tmp_path):
        render_diff(*versions, "privilege_gradient", output=str(tmp_path / "d"), format="svg", render_engine="svg")
        root = ET.fromstring((tmp_path / "d.svg").read_text(encoding="utf-8"))
        groups = list(root.iter(f"{SVG_NS}g"))
        clusters = {g.get("data-zone"): g for g in groups if "usv-cluster" in g.get("class", "")}
        assert "usv-diff--removed" in clusters["legacy"].get("class") and clusters["legacy"].get("opacity") == "0.35"
        assert clusters["vault"].get("data-diff") == "added"
        assert clusters["low"].get("data-diff") == "unchanged"
        nodes = {g.get("data-node-id"): g for g in groups if "usv-node" in g.get("class", "").split()}
        assert nodes["e"].get("data-diff") == "added" and nodes["c"].get("data-changed") == "zone"
        edges = {
            (g.get("data-from"), g.get("data-to"), g.get("data-type")): g
            for g in groups
            if "usv-edge" in g.get("class", "").split()
        }
        assert edges[("d", "e", "data")].get("data-inversion") == "new"
        assert edges[("b", "c", "data")].get("data-inversion") == "fixed"
        assert edges[("a", "b", "data")].get("data-inversion") == "unchanged"
        assert edges[("a", "b", "data")].get("data-diff") == "modified"
        assert edges[("c", "d", "control")].get("data-diff") == "removed"
        assert edges[("c", "d", "resource")].get("data-diff") == "added"
        text = " ".join(t.text or "" for t in root.iter(f"{SVG_NS}text"))
        assert "NEW INVERSION" in text and "FIXED INVERSION" in text and "+ added" in text


@requires_dot
def test_cli(versions, tmp_path):
    env = {**os.environ, "PYTHONPATH": str(REPO / "src")}
    out = subprocess.run(
        [sys.executable, "-m", "usecvislib.usecvis", "-m", "6", "-i", versions[1], "--diff", versions[0],
         "-o", str(tmp_path / "drift"), "-f", "svg", "--render-engine", "svg"],
        capture_output=True, text=True, env=env, cwd=tmp_path,
    )  # fmt: skip
    assert out.returncode == 0, out.stderr
    assert "New inversion: d -> e (high)" in out.stdout and "Fixed inversion: b -> c" in out.stdout
    assert (tmp_path / "drift.svg").exists()


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

    def test_inversions_header_is_readable_cross_origin(self, client):
        from api.main import app

        cors = next(m for m in app.user_middleware if m.cls.__name__ == "CORSMiddleware")
        assert "X-Diff-Inversions" in cors.kwargs["expose_headers"]

    @requires_dot
    def test_render_auto_detects_the_mode(self, client, versions):
        response = client.post(
            "/diff/render",
            params={"format": "svg", "render_engine": "svg", "style": "pg_dark"},
            files={
                "old_file": ("v1.json", Path(versions[0]).read_bytes()),
                "new_file": ("v2.json", Path(versions[1]).read_bytes()),
            },
        )
        assert response.status_code == 200, response.text
        assert json.loads(response.headers["X-Diff-Summary"])["total"] > 0
        assert json.loads(response.headers["X-Diff-Inversions"]) == {
            "new": [{"from": "d", "to": "e", "type": "data", "severity": "high", "trust_gap": 2}],
            "fixed": [{"from": "b", "to": "c", "type": "data", "severity": "medium", "trust_gap": 1}],
            "changed": [],
        }
        assert 'data-inversion="new"' in response.text

    @requires_dot
    def test_changed_inversions_header(self, client, retier):
        response = client.post(
            "/diff/render",
            params={"format": "svg"},
            files={
                "old_file": ("r1.json", Path(retier[0]).read_bytes()),
                "new_file": ("r2.json", Path(retier[1]).read_bytes()),
            },
        )
        assert response.status_code == 200, response.text
        changed = json.loads(response.headers["X-Diff-Inversions"])["changed"]
        assert changed[0] == {
            "from": "y", "to": "w", "type": "control",
            "old_severity": "high", "new_severity": "critical", "old_trust_gap": 2, "new_trust_gap": 3,
        }  # fmt: skip
