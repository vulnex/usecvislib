#
# VULNEX -Universal Security Visualization Library-
#
# File: test_svgengine.py
# Author: Simon Roses Femerling
# Created: 2026-08-08
# Last Modified: 2026-08-08
# Version: 0.4.1
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Tests for the SVG engine core: metrics, canvas, themes, layout, wiring."""

import xml.etree.ElementTree as ET
from itertools import pairwise
from pathlib import Path

import pytest

from usecvislib.svgengine import EngineNotSupportedError, StyleEngineMismatchError, metrics, themes
from usecvislib.svgengine import canvas as canvas_mod
from usecvislib.svgengine.canvas import SvgCanvas
from usecvislib.svgengine.layout import TidyTreeLayout
from usecvislib.svgengine.scene import Scene, SceneEdge, SceneNode

TESTS_DIR = Path(__file__).parent
FIXTURE = str(TESTS_DIR / "enterattacktrees.tml")
GOLDEN_DIR = TESTS_DIR / "golden" / "svg"

FAMILY = "DejaVu Sans"  # bundled with matplotlib: cross-platform stable


class TestMetrics:
    def test_longer_text_is_wider(self):
        short = metrics.measure_text("abc", FAMILY, 12)
        long = metrics.measure_text("abcdefghij", FAMILY, 12)
        assert 0 < short < long

    def test_empty_text_is_zero(self):
        assert metrics.measure_text("", FAMILY, 12) == 0.0

    def test_wrap_respects_max_width(self):
        text = "one two three four five six seven eight"
        max_width = metrics.measure_text("one two three", FAMILY, 12) + 1
        lines = metrics.wrap_text(text, FAMILY, 12, max_width)
        assert len(lines) > 1
        assert all(metrics.measure_text(line, FAMILY, 12) <= max_width for line in lines)

    def test_wrap_honors_hard_breaks(self):
        assert metrics.wrap_text("a\\nb", FAMILY, 12, 10_000) == ["a", "b"]
        assert metrics.wrap_text("a\nb", FAMILY, 12, 10_000) == ["a", "b"]

    def test_oversized_word_kept_whole(self):
        lines = metrics.wrap_text("supercalifragilistic", FAMILY, 12, 5)
        assert lines == ["supercalifragilistic"]

    def test_block_height_scales_with_lines(self):
        _, h1 = metrics.measure_block(["a"], FAMILY, 12)
        _, h3 = metrics.measure_block(["a", "b", "c"], FAMILY, 12)
        assert h3 == pytest.approx(3 * h1)

    def test_unknown_family_falls_back(self):
        # Must not raise; falls back to DejaVu
        assert metrics.measure_text("abc", "NoSuchFontFamily12345", 12) > 0


class TestCanvas:
    def _build(self):
        c = SvgCanvas("testmod", "sv_default")
        grad = c.gradient("#111111", "#222222")
        c.shadow()
        c.add("nodes", ET.Element("rect", {"x": "0", "y": "0", "width": "10", "height": "10", "fill": grad}))
        c.set_css(".usv-node { stroke: red; }")
        c.finalize(0, 0, 100, 50)
        return c.to_string()

    def test_deterministic(self):
        assert self._build() == self._build()

    def test_root_contract_attributes(self):
        root = ET.fromstring(self._build())
        assert root.get("data-usv-engine") == "svg"
        assert root.get("data-usv-module") == "testmod"
        assert root.get("data-usv-theme") == "sv_default"
        assert "usv-svg" in root.get("class")

    def test_defs_deduplicated(self):
        c = SvgCanvas("m", "s")
        url1 = c.gradient("#a1a1a1", "#b2b2b2")
        url2 = c.gradient("#a1a1a1", "#b2b2b2")
        url3 = c.gradient("#c3c3c3", "#b2b2b2")
        assert url1 == url2 != url3
        assert len(c._defs) == 2

    def test_finalize_required(self):
        c = SvgCanvas("m", "s")
        with pytest.raises(ValueError):
            c.to_string()

    def test_fmt_precision(self):
        assert canvas_mod.fmt(10.0) == "10"
        assert canvas_mod.fmt(10.456) == "10.46"
        assert canvas_mod.fmt(-0.5) == "-0.5"


class TestThemes:
    def test_parse_fill_gradient(self):
        assert themes.parse_fill("gradient:#aa>#bb") == ("gradient", "#aa", "#bb")

    def test_parse_fill_solid(self):
        assert themes.parse_fill("#abc") == ("solid", "#abc")
        assert themes.parse_fill("gradient:broken") == ("solid", "gradient:broken")

    def test_resolve_merges_defaults(self):
        theme = themes.resolve({"node": {"fill": "#fff"}})
        assert theme["node"]["fill"] == "#fff"
        assert theme["node"]["border"] == themes.DEFAULTS["node"]["border"]
        assert theme["page"]["padding"] == themes.DEFAULTS["page"]["padding"]

    def test_require_svg_theme(self):
        themes.require_svg_theme({"meta": {"engine": "svg"}}, "sv_x")
        with pytest.raises(StyleEngineMismatchError):
            themes.require_svg_theme({"node": {}}, "at_default")

    def test_reject_svg_theme(self):
        themes.reject_svg_theme({"node": {}}, "at_default")
        with pytest.raises(StyleEngineMismatchError):
            themes.reject_svg_theme({"meta": {"engine": "svg"}}, "sv_default")


def _tree_scene(shape: dict[str, list[str]], widths: dict[str, float] | None = None) -> Scene:
    scene = Scene(module="test")
    ids = set(shape) | {c for kids in shape.values() for c in kids}
    for node_id in sorted(ids):
        scene.nodes.append(SceneNode(id=node_id, label=node_id, width=(widths or {}).get(node_id, 80), height=40))
    for parent, kids in shape.items():
        for kid in kids:
            scene.edges.append(SceneEdge(src=parent, dst=kid))
    return scene


class TestTidyTreeLayout:
    def _assert_no_overlap(self, scene: Scene):
        by_y: dict[float, list[SceneNode]] = {}
        for node in scene.nodes:
            by_y.setdefault(node.y, []).append(node)
        for row in by_y.values():
            row.sort(key=lambda n: n.x)
            for a, b in pairwise(row):
                assert a.x + a.width / 2 <= b.x - b.width / 2 + 0.01, f"overlap: {a.id} / {b.id}"

    def test_parent_centered_and_no_overlap(self):
        scene = _tree_scene({"r": ["a", "b", "c"], "a": ["a1", "a2"], "c": ["c1"]})
        TidyTreeLayout().solve(scene, "r")
        self._assert_no_overlap(scene)
        r = scene.node_by_id("r")
        a, c = scene.node_by_id("a"), scene.node_by_id("c")
        assert r.x == pytest.approx((a.x + c.x) / 2)
        assert r.y < a.y

    def test_wide_parent_narrow_children(self):
        scene = _tree_scene({"r": ["a", "b"]}, widths={"r": 500, "a": 40, "b": 40})
        TidyTreeLayout().solve(scene, "r")
        self._assert_no_overlap(scene)

    def test_deep_chain_no_recursion_error(self):
        shape = {f"n{i}": [f"n{i + 1}"] for i in range(1500)}
        scene = _tree_scene(shape)
        TidyTreeLayout().solve(scene, "n0")
        assert scene.node_by_id("n1500").y > scene.node_by_id("n0").y

    def test_lr_orientation_swaps_axes(self):
        scene = _tree_scene({"r": ["a", "b"]})
        TidyTreeLayout(orientation="LR").solve(scene, "r")
        r, a = scene.node_by_id("r"), scene.node_by_id("a")
        assert a.x > r.x  # depth grows along x
        self_by_x = sorted([scene.node_by_id("a"), scene.node_by_id("b")], key=lambda n: n.y)
        assert self_by_x[0].y + self_by_x[0].height / 2 <= self_by_x[1].y - self_by_x[1].height / 2 + 0.01

    def test_orphans_are_placed(self):
        scene = _tree_scene({"r": ["a"]})
        scene.nodes.append(SceneNode(id="orphan", label="o", width=80, height=40))
        TidyTreeLayout().solve(scene, "r")
        orphan = scene.node_by_id("orphan")
        assert orphan.y > scene.node_by_id("a").y  # placed below the tree

    def test_multi_parent_child_placed_once(self):
        scene = _tree_scene({"r": ["a", "b"], "a": ["shared"], "b": ["shared"]})
        TidyTreeLayout().solve(scene, "r")
        self._assert_no_overlap(scene)


class TestEngineWiring:
    def test_unsupported_module_raises(self, tmp_path):
        from usecvislib.threatmodeling import ThreatModeling

        with pytest.raises(EngineNotSupportedError):
            ThreatModeling(FIXTURE, str(tmp_path / "x"), "svg", render_engine="svg")

    def test_dot_format_raises(self, tmp_path):
        from usecvislib.attacktrees import AttackTrees

        with pytest.raises(EngineNotSupportedError):
            AttackTrees(FIXTURE, str(tmp_path / "x"), format="dot", render_engine="svg")

    def test_invalid_engine_raises(self, tmp_path):
        from usecvislib import utils
        from usecvislib.attacktrees import AttackTrees

        with pytest.raises(utils.ConfigError):
            AttackTrees(FIXTURE, str(tmp_path / "x"), render_engine="webgl")

    def test_style_mismatch_both_directions(self, tmp_path):
        from usecvislib.attacktrees import AttackTrees

        with pytest.raises(StyleEngineMismatchError):
            AttackTrees(FIXTURE, str(tmp_path / "x"), format="svg", styleid="at_default", render_engine="svg")
        with pytest.raises(StyleEngineMismatchError):
            AttackTrees(FIXTURE, str(tmp_path / "x"), format="svg", styleid="sv_default")

    def test_svg_default_styleid(self, tmp_path):
        from usecvislib.attacktrees import AttackTrees

        at = AttackTrees(FIXTURE, str(tmp_path / "out"), format="svg", render_engine="svg")
        assert at.styleid == "sv_default"

    def test_builder_passthrough(self, tmp_path):
        from usecvislib.builders import AttackTreeBuilder

        builder = AttackTreeBuilder("T", "root1")
        builder.add_node("root1", "Root").add_node("leaf1", "Leaf", cvss=8.1).add_edge("root1", "leaf1")
        builder.to_attack_tree(str(tmp_path / "b"), format="svg", render_engine="svg").build()
        content = (tmp_path / "b.svg").read_text(encoding="utf-8")
        assert 'data-usv-engine="svg"' in content
        assert "usv-sev--high" in content

    def test_batch_passthrough(self, tmp_path):
        from usecvislib.batch import BatchProcessor

        bp = BatchProcessor("attack_tree", str(tmp_path), format="svg", render_engine="svg")
        result = bp.process_files([FIXTURE])
        assert result.success_count == 1
        out = next(tmp_path.glob("*.svg")).read_text(encoding="utf-8")
        assert 'data-usv-engine="svg"' in out


class TestGolden:
    def test_golden_attack_tree_dejavu(self, tmp_path):
        """Byte-stable output for a DejaVu-pinned theme (cross-platform)."""
        from usecvislib.attacktrees import AttackTrees

        at = AttackTrees(FIXTURE, str(tmp_path / "out"), format="svg", render_engine="svg")
        at.style["font"]["family"] = FAMILY
        at.build()
        golden = (GOLDEN_DIR / "enterattacktrees_sv_default_dejavu.svg").read_text(encoding="utf-8")
        assert (tmp_path / "out.svg").read_text(encoding="utf-8") == golden


class TestLinearLayout:
    def test_sequence_spacing_tb(self):
        from usecvislib.svgengine.layout import LinearLayout

        scene = _tree_scene({})
        for i in range(3):
            scene.nodes.append(SceneNode(id=f"n{i}", label=f"n{i}", width=80, height=40))
        LinearLayout(gap=20).solve(scene, ["n0", "n1", "n2"])
        n0, n1, n2 = (scene.node_by_id(f"n{i}") for i in range(3))
        assert n0.y < n1.y < n2.y
        assert n1.y - n0.y == pytest.approx(60)  # 40 height + 20 gap
        assert n0.x == n1.x == n2.x == 0.0

    def test_lr_orientation(self):
        from usecvislib.svgengine.layout import LinearLayout

        scene = _tree_scene({})
        scene.nodes.append(SceneNode(id="a", label="a", width=80, height=40))
        scene.nodes.append(SceneNode(id="b", label="b", width=120, height=40))
        LinearLayout(gap=10, orientation="LR").solve(scene)
        a, b = scene.node_by_id("a"), scene.node_by_id("b")
        assert b.x - a.x == pytest.approx(80 / 2 + 10 + 120 / 2)
        assert a.y == b.y == 0.0

    def test_unknown_id_skipped_and_missing_appended(self):
        from usecvislib.svgengine.layout import LinearLayout

        scene = _tree_scene({})
        scene.nodes.append(SceneNode(id="a", label="a", width=80, height=40))
        scene.nodes.append(SceneNode(id="b", label="b", width=80, height=40))
        LinearLayout().solve(scene, ["ghost", "b"])  # a not listed
        assert scene.node_by_id("b").y < scene.node_by_id("a").y  # b first, a appended


class TestStackLayout:
    def test_bands_stack_and_items_row(self):
        from usecvislib.svgengine.layout import StackLayout

        scene = _tree_scene({})
        for nid in ("a1", "a2", "b1"):
            scene.nodes.append(SceneNode(id=nid, label=nid, width=100, height=40))
        StackLayout(band_gap=30, item_gap=20).solve(scene, [["a1", "a2"], ["b1"]])
        a1, a2, b1 = (scene.node_by_id(n) for n in ("a1", "a2", "b1"))
        assert a1.y == a2.y  # same band
        assert b1.y - a1.y == pytest.approx(40 + 30)  # band height + gap
        assert a2.x - a1.x == pytest.approx(120)  # width + item gap
        assert (a1.x + a2.x) / 2 == pytest.approx(0.0)  # band centered
        assert b1.x == pytest.approx(0.0)

    def test_unassigned_nodes_get_final_band(self):
        from usecvislib.svgengine.layout import StackLayout

        scene = _tree_scene({})
        scene.nodes.append(SceneNode(id="a", label="a", width=100, height=40))
        scene.nodes.append(SceneNode(id="stray", label="s", width=100, height=40))
        StackLayout().solve(scene, [["a"]])
        assert scene.node_by_id("stray").y > scene.node_by_id("a").y

    def test_lr_orientation(self):
        from usecvislib.svgengine.layout import StackLayout

        scene = _tree_scene({})
        scene.nodes.append(SceneNode(id="a", label="a", width=100, height=40))
        scene.nodes.append(SceneNode(id="b", label="b", width=100, height=40))
        StackLayout(orientation="LR").solve(scene, [["a"], ["b"]])
        assert scene.node_by_id("b").x > scene.node_by_id("a").x


class TestAxisLayout:
    def test_values_scale_onto_axis(self):
        from usecvislib.svgengine.layout import AxisLayout

        scene = _tree_scene({})
        for nid in ("t0", "t5", "t10"):
            scene.nodes.append(SceneNode(id=nid, label=nid, width=10, height=20))
        AxisLayout(axis_length=100).solve(scene, {"t0": 0, "t5": 5, "t10": 10})
        assert scene.node_by_id("t0").x == pytest.approx(0)
        assert scene.node_by_id("t5").x == pytest.approx(50)
        assert scene.node_by_id("t10").x == pytest.approx(100)
        # No overlap at width 10: all fit in one lane
        assert scene.node_by_id("t0").y == scene.node_by_id("t10").y

    def test_overlapping_values_use_lanes(self):
        from usecvislib.svgengine.layout import AxisLayout

        scene = _tree_scene({})
        for nid in ("a", "b"):
            scene.nodes.append(SceneNode(id=nid, label=nid, width=200, height=30))
        AxisLayout(axis_length=100, lane_gap=10).solve(scene, {"a": 0, "b": 1})
        a, b = scene.node_by_id("a"), scene.node_by_id("b")
        assert a.y != b.y  # wide nodes at close values: second lane
        assert b.y - a.y == pytest.approx(40)  # lane height 30 + gap 10

    def test_equal_values_stack_deterministically(self):
        from usecvislib.svgengine.layout import AxisLayout

        scene = _tree_scene({})
        for nid in ("first", "second"):
            scene.nodes.append(SceneNode(id=nid, label=nid, width=50, height=20))
        AxisLayout(axis_length=100).solve(scene, {"first": 3, "second": 3})
        assert scene.node_by_id("first").y < scene.node_by_id("second").y

    def test_missing_value_placed_at_start(self):
        from usecvislib.svgengine.layout import AxisLayout

        scene = _tree_scene({})
        for nid in ("a", "novalue"):
            scene.nodes.append(SceneNode(id=nid, label=nid, width=10, height=20))
        AxisLayout(axis_length=100).solve(scene, {"a": 10})
        assert scene.node_by_id("novalue").x == pytest.approx(0)

    def test_single_value_span(self):
        from usecvislib.svgengine.layout import AxisLayout

        scene = _tree_scene({})
        scene.nodes.append(SceneNode(id="only", label="o", width=10, height=20))
        AxisLayout(axis_length=100).solve(scene, {"only": 42})
        assert scene.node_by_id("only").x == pytest.approx(0)


class TestImages:
    def test_bundled_icon_embeds_as_data_uri(self):
        from usecvislib.svgengine.images import resolve_data_uri

        uri = resolve_data_uri("bundled:aws/Security-Identity-Compliance/Identity-and-Access-Management", "n1")
        assert uri is not None
        assert uri.startswith("data:image/")
        assert ";base64," in uri

    def test_unresolvable_reference_returns_none(self):
        from usecvislib.svgengine.images import resolve_data_uri

        assert resolve_data_uri("bundled:no/such/icon-xyz", "n1") is None
        assert resolve_data_uri("/nonexistent/path/img.png", "n1") is None

    def test_unsupported_extension_returns_none(self, tmp_path):
        from usecvislib.svgengine.images import resolve_data_uri

        bad = tmp_path / "img.webp"
        bad.write_bytes(b"RIFF")
        assert resolve_data_uri(str(bad), "n1") is None

    def test_oversized_image_refused(self, tmp_path, monkeypatch):
        from usecvislib import utils
        from usecvislib.svgengine import images as images_mod

        big = tmp_path / "big.png"
        big.write_bytes(b"\x89PNG\r\n\x1a\n" + b"0" * 100)
        monkeypatch.setattr(utils, "IMAGE_MAX_SIZE", 10)
        monkeypatch.setattr(utils, "resolve_image_reference", lambda ref: big)
        assert images_mod.resolve_data_uri(str(big), "n1") is None

    def test_multi_parent_barycenter(self):
        # A shared child (DAG) centers under ALL its parents, not just the
        # tree-attachment parent (Graphviz-style barycenter placement).
        scene = _tree_scene({"r": ["a", "b", "c"], "a": ["shared"], "c": ["shared"]})
        TidyTreeLayout().solve(scene, "r")
        a, c, shared = scene.node_by_id("a"), scene.node_by_id("c"), scene.node_by_id("shared")
        assert shared.x == pytest.approx((a.x + c.x) / 2)
