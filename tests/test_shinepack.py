#
# VULNEX -Universal Security Visualization Library-
#
# File: test_shinepack.py
# Author: Simon Roses Femerling
# Created: 2026-08-08
# Last Modified: 2026-08-08
# Version: 0.4.1
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Tests for the SVG shine pack (Phase 0 of the SVG engine)."""

import shutil
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from usecvislib import usecvis
from usecvislib.svgengine import ShineError, apply_shine, apply_shine_file
from usecvislib.svgengine.shinepack import FILTER_ID, SHINE_MARKER, SVG_NS

TESTS_DIR = Path(__file__).parent

# Minimal Graphviz-shaped SVG: one node (filled polygon + text), one edge
# (unfilled path), a forwarded extra class on the node group.
MINIMAL_SVG = (
    '<?xml version="1.0" encoding="UTF-8" standalone="no"?>\n'
    '<svg xmlns="http://www.w3.org/2000/svg" width="120" height="60" viewBox="0 0 120 60">\n'
    '<g class="graph">\n'
    '<g id="node1" class="node custom-tag">\n'
    "<title>a</title>\n"
    '<polygon fill="#3d5a80" stroke="#1e3a5f" points="10,10 110,10 110,50 10,50"/>\n'
    '<text text-anchor="middle" x="60" y="35" font-family="Times,serif" font-size="14.00">Node A</text>\n'
    "</g>\n"
    '<g id="edge1" class="edge">\n'
    '<path fill="none" stroke="black" d="M10,10 L50,50"/>\n'
    "</g>\n"
    "</g>\n"
    "</svg>\n"
)


def _q(name: str) -> str:
    return f"{{{SVG_NS}}}{name}"


class TestApplyShine:
    def test_output_is_valid_svg_with_marker(self):
        out = apply_shine(MINIMAL_SVG)
        root = ET.fromstring(out)
        assert root.tag == _q("svg")
        assert root.get(SHINE_MARKER) == "1"

    def test_injects_style_and_shadow_defs(self):
        out = apply_shine(MINIMAL_SVG)
        root = ET.fromstring(out)
        styles = root.findall(_q("style"))
        assert len(styles) == 1
        assert "font-family" in styles[0].text
        filters = root.findall(f"{_q('defs')}/{_q('filter')}")
        assert len(filters) == 1
        assert filters[0].get("id") == FILTER_ID

    def test_shadow_applied_to_filled_node_shapes_only(self):
        out = apply_shine(MINIMAL_SVG)
        root = ET.fromstring(out)
        polygons = [e for e in root.iter(_q("polygon")) if e.get("filter")]
        assert len(polygons) == 1
        # Edge path has fill="none" and lives outside a .node group: untouched
        assert all(e.get("filter") is None for e in root.iter(_q("path")))

    def test_class_attributes_preserved(self):
        out = apply_shine(MINIMAL_SVG)
        root = ET.fromstring(out)
        node_groups = [g for g in root.iter(_q("g")) if "custom-tag" in g.get("class", "").split()]
        assert len(node_groups) == 1
        assert "node" in node_groups[0].get("class").split()

    def test_idempotent(self):
        once = apply_shine(MINIMAL_SVG)
        twice = apply_shine(once)
        assert once == twice

    def test_deterministic(self):
        assert apply_shine(MINIMAL_SVG) == apply_shine(MINIMAL_SVG)

    def test_shadow_disabled(self):
        out = apply_shine(MINIMAL_SVG, shadow=False)
        root = ET.fromstring(out)
        assert root.findall(_q("defs")) == []
        assert all(e.get("filter") is None for e in root.iter())

    def test_hover_disabled(self):
        out = apply_shine(MINIMAL_SVG, hover=False)
        root = ET.fromstring(out)
        assert ":hover" not in root.findall(_q("style"))[0].text

    def test_no_active_content_injected(self):
        out = apply_shine(MINIMAL_SVG)
        assert "<script" not in out
        assert "foreignObject" not in out
        assert "@import" not in out
        assert "url(http" not in out

    def test_rejects_non_xml(self):
        with pytest.raises(ShineError):
            apply_shine("this is not svg")

    def test_rejects_non_svg_xml(self):
        with pytest.raises(ShineError):
            apply_shine("<html><body/></html>")


class TestApplyShineFile:
    def test_roundtrip_and_in_place_idempotency(self, tmp_path):
        svg_file = tmp_path / "out.svg"
        svg_file.write_text(MINIMAL_SVG, encoding="utf-8")

        apply_shine_file(str(svg_file))
        first = svg_file.read_text(encoding="utf-8")
        assert SHINE_MARKER in first

        apply_shine_file(str(svg_file))
        assert svg_file.read_text(encoding="utf-8") == first

    def test_rejects_non_svg_extension(self, tmp_path):
        png_file = tmp_path / "out.png"
        png_file.write_bytes(b"\x89PNG")
        with pytest.raises(ShineError):
            apply_shine_file(str(png_file))

    def test_rejects_missing_file(self, tmp_path):
        with pytest.raises(ShineError):
            apply_shine_file(str(tmp_path / "missing.svg"))


class TestCliShine:
    def test_shine_requires_svg_format(self, tmp_path):
        with pytest.raises(SystemExit) as exc:
            usecvis.main(
                ["-i", str(TESTS_DIR / "enterattacktrees.tml"), "-o", str(tmp_path / "out"), "-f", "png", "--shine"]
            )
        assert exc.value.code == 2

    def test_shine_rejects_unsupported_mode(self, tmp_path):
        with pytest.raises(SystemExit) as exc:
            usecvis.main(
                [
                    "-i",
                    str(TESTS_DIR / "enterattacktrees.tml"),
                    "-o",
                    str(tmp_path / "out"),
                    "-f",
                    "svg",
                    "-m",
                    "4",
                    "--shine",
                ]
            )
        assert exc.value.code == 2

    @pytest.mark.skipif(shutil.which("dot") is None, reason="Graphviz not installed")
    def test_end_to_end_attack_tree_shine(self, tmp_path):
        output = tmp_path / "shined"
        rc = usecvis.main(
            ["-i", str(TESTS_DIR / "enterattacktrees.tml"), "-o", str(output), "-f", "svg", "-m", "0", "--shine"]
        )
        assert rc == 0
        content = (tmp_path / "shined.svg").read_text(encoding="utf-8")
        assert SHINE_MARKER in content
        assert FILTER_ID in content
        ET.fromstring(content)  # still valid SVG
