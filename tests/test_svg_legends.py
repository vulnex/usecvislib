#
# VULNEX -Universal Security Visualization Library-
#
# File: test_svg_legends.py
# Author: Simon Roses Femerling
# Created: 2026-10-29
# Last Modified: 2026-10-29
# Version: 0.6.0
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""SVG-engine legends: attack trees, attack graphs and threat-model DFDs explain their colors and lines."""

import shutil
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from usecvislib.attackgraphs import AttackGraphs
from usecvislib.attacktrees import AttackTrees
from usecvislib.svgengine.painters import graph as graph_painter
from usecvislib.threatmodeling import ThreatModeling

SVG_NS = "{http://www.w3.org/2000/svg}"
TEMPLATES = Path(__file__).parent.parent / "templates"
requires_dot = pytest.mark.skipif(shutil.which("dot") is None, reason="Graphviz dot not installed")


def _legend_text(svg: str) -> list[str]:
    root = ET.fromstring(svg)
    return [
        "".join(t.itertext())
        for g in root.iter(f"{SVG_NS}g")
        if "usv-legend" in g.get("class", "").split()
        for t in g.iter(f"{SVG_NS}text")
    ]


def _build(cls, template, tmp_path, **kwargs) -> str:
    viz = cls(str(template), str(tmp_path / "o"), format="svg", render_engine="svg", **kwargs)
    viz.build()
    return (tmp_path / "o.svg").read_text(encoding="utf-8")


@requires_dot
def test_attack_graph_legend_lists_what_is_drawn(tmp_path):
    labels = _legend_text(_build(AttackGraphs, TEMPLATES / "attack-graphs" / "corporate_network.tml", tmp_path))
    for expected in ("Host", "Exploit", "Critical vulnerability", "Attack step", "Network path"):
        assert expected in labels
    assert "Medium vulnerability" not in labels  # no medium vulnerability in this template
    assert "* CVSS computed from the vector" in labels


@requires_dot
def test_threat_model_legend(tmp_path):
    labels = _legend_text(_build(ThreatModeling, TEMPLATES / "threat-models" / "ecommerce_platform.tml", tmp_path))
    assert labels == ["External entity", "Process", "Data store", "Trust boundary", "Data flow"]


def test_attack_tree_legend(tmp_path):
    labels = _legend_text(_build(AttackTrees, TEMPLATES / "attack-trees" / "aws_cloud_security.toml", tmp_path))
    assert labels[:3] == ["Critical (CVSS)", "High (CVSS)", "Medium (CVSS)"]
    assert any(label.startswith("AND:") for label in labels)


def test_legend_can_be_turned_off(tmp_path, monkeypatch):
    from usecvislib.svgengine import themes

    resolve = themes.resolve

    def no_legend(style):
        theme = resolve(style)
        theme["legend"] = {"show": False}
        return theme

    monkeypatch.setattr(themes, "resolve", no_legend)
    assert _legend_text(_build(AttackTrees, TEMPLATES / "attack-trees" / "aws_cloud_security.toml", tmp_path)) == []


def test_wide_legends_wrap():
    theme = {"font": {"family": "DejaVu Sans", "size": 13}}
    items = [(f"Item number {i}", "#000000") for i in range(12)]
    rows = graph_painter.wrap_legend(theme, items, 500.0)
    assert len(rows) > 1 and sum(len(r) for r in rows) == 12
    assert all(sum(graph_painter._legend_item_width(theme, it) for it in row) <= 500.0 for row in rows if len(row) > 1)
