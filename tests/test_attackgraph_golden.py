#
# VULNEX -Universal Security Visualization Library-
#
# File: test_attackgraph_golden.py
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
#

"""Byte-exact golden output for the attack graph, both render engines.

Guards refactors of the attack-graph render paths (the render view for the
grouping and drift features): with no new options set, the output must not
change at all.

- Graphviz engine: the generated DOT source, compared without running ``dot``.
- SVG engine: the finished SVG (its layout needs ``dot``), font pinned to
  DejaVu Sans like the attack-tree golden.

Regenerate after an intended output change with::

    USECVISLIB_UPDATE_GOLDEN=1 python -m pytest tests/test_attackgraph_golden.py

The SVG goldens need ``dot``: regenerate them in the API container.
"""

import os
import re
import shutil
import tempfile
from pathlib import Path

import pytest

from usecvislib.attackgraphs import AttackGraphs

TESTS_DIR = Path(__file__).parent
TEMPLATE_DIR = TESTS_DIR.parent / "templates" / "attack-graphs"
GOLDEN_DIR = TESTS_DIR / "golden" / "attackgraph"
TEMPLATES = sorted(p.name for p in TEMPLATE_DIR.iterdir() if p.is_file())
ALL_SECTIONS = "cloud.toml"  # hosts, vulns, privileges, services, exploits, all edge kinds

GRAPHVIZ_PRESETS = [
    "ag_default", "ag_dark", "ag_security", "ag_network", "ag_minimal", "ag_neon", "ag_corporate", "ag_hacker",
    "ag_blueprint", "ag_plain", "ag_nordic", "ag_amethyst", "ag_steel", "ag_glacier", "ag_terra", "ag_doc_light",
]  # fmt: skip
SVG_PRESETS = ["sv_default", "sv_dark", "sv_security", "sv_corporate", "sv_minimal"]

FAMILY = "DejaVu Sans"
UPDATE = os.environ.get("USECVISLIB_UPDATE_GOLDEN") == "1"
requires_dot = pytest.mark.skipif(shutil.which("dot") is None, reason="SVG-engine layout needs Graphviz 'dot'")

# Converted and resized icons live in a per-machine cache directory, under a file
# name hashed from the icon's absolute path: both vary by machine
_ICON_CACHE = re.compile(r"[^\"\s]*usecvislib_icon_cache/[0-9a-f]+")


def _check(actual: str, golden: Path) -> None:
    if UPDATE:
        golden.parent.mkdir(parents=True, exist_ok=True)
        golden.write_text(actual, encoding="utf-8")
        return
    assert golden.exists(), f"missing golden {golden.name}: run with USECVISLIB_UPDATE_GOLDEN=1"
    assert actual == golden.read_text(encoding="utf-8"), f"output differs from {golden.name}"


def _dot_source(template: str, styleid: str) -> str:
    ag = AttackGraphs(str(TEMPLATE_DIR / template), os.path.join(tempfile.gettempdir(), "golden"), format="png", styleid=styleid)
    ag.load()
    ag.render()
    return _ICON_CACHE.sub("<ICON_CACHE>/<hash>", ag.graph.source)


def _svg(template: str, styleid: str, tmp_path: Path) -> str:
    ag = AttackGraphs(str(TEMPLATE_DIR / template), str(tmp_path / "out"), format="svg", styleid=styleid, render_engine="svg")
    ag.style.setdefault("font", {})["family"] = FAMILY
    ag.build()
    return (tmp_path / "out.svg").read_text(encoding="utf-8")


@pytest.mark.parametrize("template", TEMPLATES)
def test_dot_source_per_template(template):
    _check(_dot_source(template, "ag_default"), GOLDEN_DIR / "dot" / f"{template}.ag_default.dot")


@pytest.mark.parametrize("styleid", GRAPHVIZ_PRESETS[1:])
def test_dot_source_per_preset(styleid):
    _check(_dot_source(ALL_SECTIONS, styleid), GOLDEN_DIR / "dot" / f"{ALL_SECTIONS}.{styleid}.dot")


@requires_dot
@pytest.mark.parametrize("template", TEMPLATES)
def test_svg_engine_per_template(template, tmp_path):
    _check(_svg(template, "sv_default", tmp_path), GOLDEN_DIR / "svg" / f"{template}.sv_default.svg")


@requires_dot
@pytest.mark.parametrize("styleid", SVG_PRESETS[1:])
def test_svg_engine_per_preset(styleid, tmp_path):
    _check(_svg(ALL_SECTIONS, styleid, tmp_path), GOLDEN_DIR / "svg" / f"{ALL_SECTIONS}.{styleid}.svg")


def test_every_preset_is_covered():
    from usecvislib.utils import ConfigModel

    presets = set(ConfigModel(AttackGraphs.STYLE_FILE).config)
    assert presets == set(GRAPHVIZ_PRESETS) | set(SVG_PRESETS), "a preset was added or removed: update the golden lists"
