#
# VULNEX -Universal Security Visualization Library-
#
# File: test_attackgraph_view.py
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
#

"""The attack-graph render view, and that it describes what each engine draws.

Grouping, collapse and drift marks will be keyed on the view's node ids and
edge keys, so ``iter_edges`` / ``node_ids`` must list exactly the edges and
nodes each engine draws, in the same order. (Byte-exact output is guarded
separately by ``test_attackgraph_golden.py``.)
"""

import re
import tempfile
from pathlib import Path

import pytest

from usecvislib import utils
from usecvislib.attackgraph_view import ElementMark, GroupInfo, RenderView, iter_edges, node_ids
from usecvislib.attackgraphs import AttackGraphs
from usecvislib.svgengine import themes
from usecvislib.svgengine.painters import attackgraphs as painter

TEMPLATE_DIR = Path(__file__).parent.parent / "templates" / "attack-graphs"
TEMPLATES = sorted(p.name for p in TEMPLATE_DIR.iterdir() if p.is_file())

_DOT_EDGE = re.compile(r'^\s*("(?:[^"\\]|\\.)*"|[^\s"]+) -> ("(?:[^"\\]|\\.)*"|[^\s"]+)', re.M)


def _loaded(template: str, **kwargs) -> AttackGraphs:
    ag = AttackGraphs(str(TEMPLATE_DIR / template), str(Path(tempfile.gettempdir()) / "view"), **kwargs)
    ag.load()
    return ag


def _unquote(dot_id: str) -> str:
    return dot_id[1:-1] if dot_id.startswith('"') else dot_id


class TestView:
    def test_without_options_the_view_is_the_data(self):
        ag = _loaded("cloud.toml")
        view = ag.render_view()
        assert isinstance(view, RenderView)
        assert view.data is ag.inputdata
        assert view.groups == {} and view.nodes == {} and view.edges == {}
        assert view.node_mark("attacker") is None
        assert view.edge_mark(("a", "b", "network")) is None

    def test_view_normalizes_list_sections(self, tmp_path):
        src = tmp_path / "lists.json"
        src.write_text(
            '{"graph": {"name": "g"}, "hosts": [{"id": "h1", "label": "H1"}],'
            ' "vulnerabilities": [{"id": "v1", "host": "h1"}]}',
            encoding="utf-8",
        )
        ag = AttackGraphs(str(src), str(tmp_path / "o"))
        ag.load()
        data = ag.render_view().data
        assert set(data["hosts"]) == {"h1"} and set(data["vulnerabilities"]) == {"v1"}
        assert list(iter_edges(data)) == [("h1", "v1", "structural")]

    def test_marks_and_groups_default_empty(self):
        mark = ElementMark()
        assert mark.diff is None and mark.changed == [] and not mark.inferred and mark.count == 1
        assert GroupInfo("dmz").members == [] and not GroupInfo("dmz").collapsed


@pytest.mark.parametrize("template", TEMPLATES)
def test_view_lists_what_the_svg_engine_draws(template):
    ag = _loaded(template, format="svg", render_engine="svg")
    scene = painter._build_scene(ag, themes.resolve(ag.style))
    data = ag.render_view().data
    drawn = node_ids(data)
    assert {node.id for node in scene.nodes} == drawn
    # The SVG painter skips edges whose endpoints are not drawn
    expected = [key for key in iter_edges(data) if key[0] in drawn and key[1] in drawn]
    assert [(e.src, e.dst, e.kind) for e in scene.edges] == expected


@pytest.mark.parametrize("template", TEMPLATES)
def test_view_lists_what_the_graphviz_engine_draws(template):
    ag = _loaded(template, format="png")
    ag.render()
    drawn = [(_unquote(a), _unquote(b)) for a, b in _DOT_EDGE.findall(ag.graph.source)]
    # The Graphviz path draws every edge, including ones to undefined ids
    expected = [(utils.sanitize_node_id(src), utils.sanitize_node_id(dst)) for src, dst, _ in iter_edges(ag.inputdata)]
    assert drawn == expected


def test_cluster_data_attributes_reach_the_svg():
    from usecvislib.svgengine.canvas import SvgCanvas
    from usecvislib.svgengine.painters.graph import _paint_clusters
    from usecvislib.svgengine.scene import Scene, SceneGroup

    scene = Scene(module="test")
    scene.groups.append(
        SceneGroup(id="dmz", label="DMZ", members=["a"], width=10, height=10, data={"collapsed": "false"})
    )
    canvas = SvgCanvas("test", "sv_default")
    _paint_clusters(scene, canvas, themes.resolve({}))
    canvas.finalize(0, 0, 100, 100)
    svg = canvas.to_string()
    assert 'data-cluster-id="dmz"' in svg and 'data-collapsed="false"' in svg
