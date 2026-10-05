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
