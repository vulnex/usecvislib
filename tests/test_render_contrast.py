#
# VULNEX -Universal Security Visualization Library-
#
# File: test_render_contrast.py
# Author: Simon Roses Femerling
# Created: 2026-10-05
# Last Modified: 2026-10-05
# Version: 0.6.0
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Label contrast and dark-preset page colors found by a visual review."""

import itertools
from pathlib import Path

import pytest

from usecvislib import utils
from usecvislib.attacktrees import AttackTrees

TEMPLATES = Path(__file__).parent.parent / "templates"


@pytest.mark.parametrize(
    "fill,expected",
    [
        ("#f9a825", "#1f2937"),  # amber: dark text
        ("#fff9c4", "#1f2937"),
        ("#cc0000", "#ffffff"),
        ("#1565c0", "#ffffff"),
        ("#000", "#ffffff"),
    ],
)
def test_readable_text_color(fill, expected):
    assert utils.readable_text_color(fill) == expected


@pytest.mark.parametrize("fill", ["red", "", None, "gradient:#000>#fff"])
def test_readable_text_color_ignores_non_hex(fill):
    assert utils.readable_text_color(fill) is None


@pytest.mark.parametrize(
    "fill,background,opacity,expected",
    [
        ("#e74c3c", "#ffffff", 0.5, "#f3a69e"),
        ("#e74c3c", "white", 0.5, "#f3a69e"),  # named page colors
        ("#000", "#fff", 0.0, "#ffffff"),
        ("#123456", "transparent", 1.0, "#123456"),
    ],
)
def test_blend_color(fill, background, opacity, expected):
    assert utils.blend_color(fill, background, opacity) == expected


def test_blend_color_ignores_other_forms():
    assert utils.blend_color("gradient:#000>#fff", "#ffffff", 0.5) is None


def test_icon_nodes_keep_their_font():
    attrs = {"label": "Server", "image": "bundled:aws/ec2", "fontname": "Consolas", "fontsize": "11"}
    utils.process_node_image(attrs, "srv")
    if "image" in attrs:  # icon not bundled in this install
        pytest.skip("bundled icon unavailable")
    assert attrs.get("fontname") == "Consolas" and attrs.get("fontsize") == "11"


@pytest.mark.parametrize("styleid", ["at_neon", "at_hacker"])
def test_dark_attack_tree_presets_paint_the_page(tmp_path, styleid):
    # These presets drew dark nodes on a white page (no graph bgcolor).
    src = TEMPLATES / "attack-trees" / "ransomware_attack.tml"
    at = AttackTrees(str(src), str(tmp_path / "o"), "dot", styleid)
    at.load().render()
    assert "bgcolor" in at.dot.source


def test_maestro_severity_preset_tints_graph_view(tmp_path):
    from usecvislib.maestro import MaestroThreatModel

    src = TEMPLATES / "maestro" / "multi-agent-support.toml"
    m = MaestroThreatModel(str(src), str(tmp_path / "o"), "dot", "ma_severity", view="graph", validate_paths=False)
    m.load().render()
    tints = set(MaestroThreatModel._SEVERITY_TINTS.values())
    assert any(f'fillcolor="{t}"' in m.graph.source for t in tints)


def test_coupling_preset_has_a_legend(tmp_path):
    from usecvislib.dependencygraph import DependencyGraph

    src = TEMPLATES / "architecture" / "dependency-graph-example.json"
    dg = DependencyGraph(str(src), str(tmp_path / "o"), "dot", "dg_coupling")
    dg.load().render()
    assert "_coupling_legend" in dg.graph.source


def test_svg_dependency_presets_have_distinct_group_palettes():
    from usecvislib.utils import tomllib  # tomli on Python 3.10

    from usecvislib import dependencygraph

    path = Path(dependencygraph.__file__).parent / "models" / "config_dependencygraph.tml"
    presets = tomllib.loads(path.read_text(encoding="utf-8"))
    palettes = [
        tuple(sorted(v.get("dependencygraph", {}).get("groups", {}).items()))
        for k, v in presets.items()
        if k.startswith("sv_") and k != "sv_default"
    ]
    assert all(palettes) and len(set(palettes)) == len(palettes)


def test_merge_trunk_detours_around_a_card_in_between():
    from usecvislib.svgengine.painters.attacktrees import _trunk_detour
    from usecvislib.svgengine.scene import SceneNode

    member = SceneNode(id="a", label="a", x=100, y=50, width=80, height=40)
    blocker = SceneNode(id="b", label="b", x=90, y=150, width=100, height=40)
    sink = SceneNode(id="c", label="c", x=200, y=250, width=80, height=40)

    def cross_of(n):
        return n.x

    def start_of(n):
        return n.y + n.height / 2

    def bbox_top(n):
        return n.y - n.height / 2

    cross, jog = _trunk_detour([member, blocker, sink], member, sink, cross_of, start_of, bbox_top, False)
    assert jog is not None and 70 < jog < 130
    assert cross > blocker.x + blocker.width / 2  # nearer (right) side, clear of the card
    # nothing in the way: straight trunk
    assert _trunk_detour([member, sink], member, sink, cross_of, start_of, bbox_top, False) == (100, None)


def test_middle_child_centred_under_parent():
    # "Exploit Vulnerability" sat right of "Initial Access": the shared
    # subtree below inflated its left sibling's extent.
    from usecvislib.svgengine.layout import TidyTreeLayout
    from usecvislib.svgengine.scene import Scene, SceneEdge, SceneNode

    scene = Scene(module="t")
    for nid in ("root", "a", "b", "c", "a1", "s", "s1", "s2"):
        scene.nodes.append(SceneNode(id=nid, label=nid, width=120, height=40))
    for src, dst in (
        ("root", "a"),
        ("root", "b"),
        ("root", "c"),
        ("a", "a1"),
        ("a1", "s"),
        ("b", "s"),
        ("c", "s"),
        ("s", "s1"),
        ("s", "s2"),
    ):
        scene.edges.append(SceneEdge(src=src, dst=dst))
    TidyTreeLayout().solve(scene, "root")
    root, a, b, c = (scene.node_by_id(n) for n in ("root", "a", "b", "c"))
    assert abs(b.x - root.x) < 1.0
    assert abs((b.x - a.x) - (c.x - b.x)) < 1.0
    xs = sorted(n.x for n in scene.nodes if n.y == b.y)
    assert all(x2 - x1 >= 120 for x1, x2 in itertools.pairwise(xs))  # no overlap


def test_svg_symbol_lines_get_a_symbol_font():
    from usecvislib.svgengine import shapes

    # cairosvg has no per-glyph fallback: Carlito lacks U+26A0 and drew a box
    warn = shapes.anchored_text(0, 0, "⚠ circular", 10, "#000", anchor="middle")
    assert shapes.SYMBOL_FONT in warn.get("style", "")
    assert warn.text == "⚠ circular" and len(warn) == 0
    assert shapes.anchored_text(0, 0, "plain ×2 · text", 10, "#000").get("style") is None


def _cluster_layout(edge_x):
    """A -Tjson-like layout: one cluster titled at the left of its top band, one vertical edge at ``edge_x``."""
    return {
        "objects": [{"name": "cluster_a", "label": "Zone", "bb": "0,0,300,100", "lp": "28,90", "lwidth": "0.5", "lheight": "0.25"}],
        "edges": [{"_draw_": [{"op": "b", "points": [[edge_x, 0], [edge_x, 40], [edge_x, 80], [edge_x, 120]]}]}],
    }


def test_cluster_title_moves_off_a_crossing_edge():
    assert utils.cluster_label_positions(_cluster_layout(28)) == {"cluster_a": "c"}
    assert utils.cluster_label_positions(_cluster_layout(150)) == {}  # nothing crosses: stays
    layout = _cluster_layout(28)
    layout["objects"][0]["bb"] = "0,0,50,100"  # the title fills the band: nowhere to go
    assert utils.cluster_label_positions(layout) == {}


def test_place_cluster_labels_sets_labeljust(monkeypatch):
    graphviz = pytest.importorskip("graphviz")
    import shutil

    if not shutil.which("dot"):
        pytest.skip("Graphviz dot not installed")
    g = graphviz.Digraph()
    with g.subgraph(name="cluster_z") as c:
        c.attr(label="Zone", labeljust="l")
        c.node("a")
    g.node("b")
    monkeypatch.setattr(utils, "cluster_label_positions", lambda layout: {"cluster_z": "r"})
    placed = utils.place_cluster_labels(g)
    lines = placed.source.split("\n")
    at = next(i for i, line in enumerate(lines) if line.strip().startswith("subgraph cluster_z"))
    # after the cluster's own attributes, so it overrides their labeljust=l
    assert "labeljust=l" in lines[at + 1] and lines[at + 2].strip() == "labeljust=r"
    placed.pipe(format="json")  # still valid DOT
    monkeypatch.setattr(utils, "cluster_label_positions", lambda layout: {})
    assert utils.place_cluster_labels(g) is g


def test_raster_output_gets_a_higher_dpi():
    graphviz = pytest.importorskip("graphviz")
    g = graphviz.Digraph(format="png")
    g.edge("a", "b")
    assert "dpi=192" in utils.with_raster_dpi(g).source
    g.format = "svg"
    assert utils.with_raster_dpi(g) is g  # vector output keeps its coordinates
    g.format = "png"
    g.attr(dpi="72")
    assert utils.with_raster_dpi(g) is g  # a graph's own dpi wins
