#
# VULNEX -Universal Security Visualization Library-
#
# File: test_privilegegradient_golden.py
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
#

"""Byte-exact golden output for the Privilege Gradient (mode 6).

Guards the Graphviz render path while the drift renderer and the
SVG-engine painter are added: with no new options set, the output must not
change at all. The Graphviz goldens are the generated DOT source, compared
without running ``dot``.

Regenerate after an intended output change with::

    USECVISLIB_UPDATE_GOLDEN=1 python -m pytest tests/test_privilegegradient_golden.py
"""

import os
import tempfile
from pathlib import Path

import pytest

from usecvislib.privilegegradient import PrivilegeGradient
from usecvislib.utils import ConfigModel

TESTS_DIR = Path(__file__).parent
TEMPLATE_DIR = TESTS_DIR.parent / "templates" / "privilege-gradient"
GOLDEN_DIR = TESTS_DIR / "golden" / "privilegegradient"
TEMPLATES = sorted(p.name for p in TEMPLATE_DIR.iterdir() if p.is_file())
PRESET_TEMPLATE = "corporate_network.tml"
GRAPHVIZ_PRESETS = ["pg_default", "pg_dark", "pg_security", "pg_neon", "pg_corporate"]
UPDATE = os.environ.get("USECVISLIB_UPDATE_GOLDEN") == "1"


def _check(actual: str, golden: Path) -> None:
    if UPDATE:
        golden.parent.mkdir(parents=True, exist_ok=True)
        golden.write_text(actual, encoding="utf-8")
        return
    assert golden.exists(), f"missing golden {golden.name}: run with USECVISLIB_UPDATE_GOLDEN=1"
    assert actual == golden.read_text(encoding="utf-8"), f"output differs from {golden.name}"


def _dot_source(template: str, styleid: str) -> str:
    pg = PrivilegeGradient(
        str(TEMPLATE_DIR / template), os.path.join(tempfile.gettempdir(), "golden"), format="png", styleid=styleid
    )
    pg.load()
    pg.render()
    return pg.graph.source


@pytest.mark.parametrize("template", TEMPLATES)
def test_dot_source_per_template(template):
    _check(_dot_source(template, "pg_default"), GOLDEN_DIR / "dot" / f"{template}.pg_default.dot")


@pytest.mark.parametrize("styleid", GRAPHVIZ_PRESETS[1:])
def test_dot_source_per_preset(styleid):
    _check(_dot_source(PRESET_TEMPLATE, styleid), GOLDEN_DIR / "dot" / f"{PRESET_TEMPLATE}.{styleid}.dot")


def test_every_preset_is_covered():
    presets = {p for p in ConfigModel(PrivilegeGradient.STYLE_FILE).config if not p.startswith("sv_")}
    assert presets == set(GRAPHVIZ_PRESETS), "a preset was added or removed: update the golden lists"
