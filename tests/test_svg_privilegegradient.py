#
# VULNEX -Universal Security Visualization Library-
#
# File: test_svg_privilegegradient.py
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
#

"""Privilege Gradient painter for the SVG engine (mode 6)."""

import os
import shutil
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from usecvislib.privilegegradient import PrivilegeGradient
from usecvislib.svgengine import themes
from usecvislib.svgengine.layout import GraphvizJsonLayout
from usecvislib.svgengine.painters import privilegegradient as painter
from usecvislib.svgengine.scene import SceneEdge
from usecvislib.utils import ConfigModel

TEMPLATE_DIR = Path(__file__).parent.parent / "templates" / "privilege-gradient"
TEMPLATES = sorted(p.name for p in TEMPLATE_DIR.iterdir() if p.is_file())
CORPORATE = str(TEMPLATE_DIR / "corporate_network.tml")
GOLDEN_DIR = Path(__file__).parent / "golden" / "privilegegradient" / "svg"
SVG_PRESETS = ["sv_default", "sv_dark", "sv_security", "sv_corporate", "sv_minimal"]
SVG_NS = "{http://www.w3.org/2000/svg}"
UPDATE = os.environ.get("USECVISLIB_UPDATE_GOLDEN") == "1"
requires_dot = pytest.mark.skipif(shutil.which("dot") is None, reason="SVG-engine layout needs Graphviz 'dot'")


def _loaded(path=CORPORATE, styleid=""):
    pg = PrivilegeGradient(path, "unused", styleid=styleid, render_engine="svg")
    pg.load()
    return pg


def _scene(path=CORPORATE, styleid=""):
    pg = _loaded(path, styleid)
    return pg, painter._build_scene(pg, themes.resolve(pg.style))


class TestScene:
    def test_zones_are_clusters_in_trust_order_with_anchors(self):
        pg, scene = _scene()
        assert [g.data["zone"] for g in scene.groups] == ["internet", "dmz", "corporate", "datacenter"]
        assert scene.groups[1].label == "DMZ (Trust Level 1)"
        anchors = [n for n in scene.nodes if n.layout_only]
        assert [a.id for a in anchors] == [
            painter.ANCHOR_PREFIX + z for z in ("internet", "dmz", "corporate", "datacenter")
        ]
        chain = [e for e in scene.edges if e.layout_only]
        assert [(e.src, e.dst) for e in chain] == list(zip([a.id for a in anchors], [a.id for a in anchors][1:], strict=False))
        assert all(e.weight == 100 for e in chain)

    def test_components_take_their_zone_color(self):
        pg, scene = _scene()
        waf = scene.node_by_id("waf")
        assert waf.fill == pg._zones["dmz"]["border_color"]
        assert waf.data["zone"] == "dmz" and waf.data["trust-level"] == "1"

    def test_influence_styles_by_type(self):
        _, scene = _scene()
        kinds = {e.kind: e for e in scene.edges if not e.layout_only}
        assert kinds["feedback"].dashed and kinds["resource"].dash == "1.5 4"
        assert kinds["control"].width > kinds["data"].width

    def test_inversions(self):
        pg, scene = _scene()
        inversions = [e for e in scene.edges if e.kind == "inversion"]
        assert len(inversions) == len(pg._inversions)
        direct_sql = next(e for e in inversions if (e.src, e.dst) == ("web_server", "db_server"))
        assert direct_sql.label == "!! INVERSION !! · Direct SQL"
        assert direct_sql.data == {"type": "data", "inversion": "true", "severity": "high", "trust-gap": "2"}

    def test_dark_preset_moves_zone_color_to_borders(self):
        pg, scene = _scene(styleid="sv_dark")
        waf = scene.node_by_id("waf")
        assert waf.fill == "#2e2e52" and waf.border == pg._zones["dmz"]["border_color"]
        assert scene.groups[1].fill == "#1b2238"

    def test_legend_lines(self):
        pg = _loaded()
        legend = painter._legend(pg, themes.resolve(pg.style))
        labels = [item[0] for item in legend]
        assert labels[-1] == "INVERSION" and "Resource" in labels
        resource = next(item for item in legend if item[0] == "Resource")
        assert resource[2]["dash"] == "1.5 4"

    def test_default_zones_without_a_zones_section(self, tmp_path):
        path = tmp_path / "pg.toml"
        path.write_text(
            '[gradient]\nname = "g"\n[[components]]\nid = "a"\nzone = "Z0"\n[[components]]\nid = "b"\nzone = "Z4"\n'
            '[[influences]]\nfrom = "a"\nto = "b"\ntype = "control"\n',
            encoding="utf-8",
        )
        _, scene = _scene(str(path))
        assert len(scene.groups) == 5  # the five default zones, empty ones kept by their anchors
        assert [e.kind for e in scene.edges if not e.layout_only] == ["inversion"]


class TestLayoutOnly:
    def test_oracle_attributes(self):
        edge = SceneEdge(src="a", dst="b", layout_only=True, weight=100)
        assert GraphvizJsonLayout._edge_attrs(edge) == " [style=invis, weight=100]"
        assert GraphvizJsonLayout._edge_attrs(SceneEdge(src="a", dst="b")) == ""


def test_every_svg_preset_is_tested():
    presets = {p for p in ConfigModel(PrivilegeGradient.STYLE_FILE).config if p.startswith("sv_")}
    assert presets == set(SVG_PRESETS)


def _svg(path, tmp_path, styleid=""):
    pg = PrivilegeGradient(path, str(tmp_path / "o"), format="svg", styleid=styleid, render_engine="svg")
    pg.style.setdefault("font", {})["family"] = "DejaVu Sans"
    pg.build()
    return (tmp_path / "o.svg").read_text(encoding="utf-8")


@requires_dot
class TestRender:
    def test_svg_contract(self, tmp_path):
        root = ET.fromstring(_svg(CORPORATE, tmp_path))
        groups = list(root.iter(f"{SVG_NS}g"))
        clusters = [g for g in groups if "usv-cluster" in g.get("class", "")]
        # Zones run left to right by trust level
        rects = {g.get("data-zone"): float(g.find(f"{SVG_NS}rect").get("x")) for g in clusters}
        assert rects["internet"] < rects["dmz"] < rects["corporate"]
        assert rects["dmz"] < rects["datacenter"]
        nodes = [g.get("data-node-id") for g in groups if "usv-node" in g.get("class", "").split()]
        assert not any(n.startswith(painter.ANCHOR_PREFIX) for n in nodes)  # anchors are never painted
        assert not any("usv-edge--layout" in g.get("class", "") for g in groups)
        inversions = [g for g in groups if "usv-edge--inversion" in g.get("class", "")]
        assert inversions and all(g.get("data-severity") for g in inversions)
        assert any(el.get("stroke-dasharray") == "1.5 4" for el in root.iter(f"{SVG_NS}path"))
        assert any("usv-legend" in g.get("class", "") for g in groups)

    @pytest.mark.parametrize("template", TEMPLATES)
    def test_golden_per_template(self, tmp_path, template):
        self._check(_svg(str(TEMPLATE_DIR / template), tmp_path), GOLDEN_DIR / f"{template}.sv_default.svg")

    @pytest.mark.parametrize("styleid", SVG_PRESETS[1:])
    def test_golden_per_preset(self, tmp_path, styleid):
        self._check(_svg(CORPORATE, tmp_path, styleid), GOLDEN_DIR / f"corporate_network.tml.{styleid}.svg")

    @staticmethod
    def _check(actual, golden):
        if UPDATE:
            golden.parent.mkdir(parents=True, exist_ok=True)
            golden.write_text(actual, encoding="utf-8")
        assert golden.exists(), "run with USECVISLIB_UPDATE_GOLDEN=1 (in the container)"
        assert actual == golden.read_text(encoding="utf-8")

    def test_api_render_engine(self, tmp_path):
        import sys

        sys.path.insert(0, str(Path(__file__).parent.parent / "api"))
        os.environ["USECVISLIB_AUTH_ENABLED"] = "false"
        from fastapi.testclient import TestClient

        from api.config import limiter
        from api.main import app

        limiter.reset()
        response = TestClient(app).post(
            "/visualize/privilege-gradient",
            params={"format": "svg", "render_engine": "svg"},
            files={"file": ("pg.tml", Path(CORPORATE).read_bytes())},
        )
        limiter.reset()
        assert response.status_code == 200 and 'data-usv-engine="svg"' in response.text
