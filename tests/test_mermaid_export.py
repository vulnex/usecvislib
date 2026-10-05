#
# VULNEX -Universal Security Visualization Library-
#
# File: test_mermaid_export.py
# Author: Simon Roses Femerling
# Created: 2026-10-05
# Last Modified: 2026-10-05
# Version: 0.6.0
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Every template converts to Mermaid (``--convert mermaid``) with a real converter.

Edge labels with punctuation broke Mermaid's parser, a node named "end" closed
a subgraph, timeline gantt dates were unparsable, and six modules fell back to
a useless key summary.
"""

import re
import shutil
from pathlib import Path

import pytest

from usecvislib.mermaid import detect_visualization_type, sanitize_node_id, serialize_to_mermaid
from usecvislib.utils import parse_content

TEMPLATES = Path(__file__).parent.parent / "templates"
FORMATS = {".toml": "toml", ".tml": "toml", ".json": "json", ".yaml": "yaml"}
ALL = sorted(
    p for p in TEMPLATES.rglob("*") if p.suffix in FORMATS and p.name != "binvis_config.toml"
)


def _export(path: Path) -> tuple[str, str]:
    data = parse_content(path.read_text(encoding="utf-8"), FORMATS[path.suffix])
    kind = detect_visualization_type(data)
    return kind, serialize_to_mermaid(data, diagram_type=kind)


@pytest.mark.parametrize("path", ALL, ids=lambda p: str(p.relative_to(TEMPLATES)))
def test_template_has_a_real_converter(path):
    kind, mmd = _export(path)
    assert kind != "unknown"
    assert mmd.strip()


@pytest.mark.parametrize("path", ALL, ids=lambda p: str(p.relative_to(TEMPLATES)))
def test_flowchart_labels_are_quoted(path):
    kind, mmd = _export(path)
    if kind == "mermaid_source" or not mmd.lstrip().startswith(("flowchart", "graph")):
        return  # hand-written Mermaid passes through unchanged
    for line in mmd.splitlines():
        # edge labels: -->|...| must be quoted
        for label in re.findall(r"[-=.]+>\|([^|]*)\|", line):
            assert label.startswith('"') and label.endswith('"'), line
        assert not re.match(r"\s*end\[", line), f"reserved id 'end' used as a node: {line}"


def test_reserved_ids_renamed():
    assert sanitize_node_id("end") == "end_node"
    assert sanitize_node_id("Start") == "Start"


def test_timeline_gantt_dates_match_format():
    _, mmd = _export(TEMPLATES / "timelines" / "ransomware_incident.tml")
    assert "dateFormat YYYY-MM-DD HH:mm:ss" in mmd
    for line in mmd.splitlines():
        if re.search(r"\d{4}-\d{2}-\d{2}", line):
            assert re.search(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", line), line
            title = line.split(":", 1)[0]
            assert title.strip() and ":" not in title


@pytest.mark.skipif(shutil.which("mmdc") is None, reason="mermaid-cli (mmdc) not installed")
@pytest.mark.parametrize("path", ALL, ids=lambda p: str(p.relative_to(TEMPLATES)))
def test_export_renders_with_mmdc(path, tmp_path):
    from usecvislib.mermaiddiagrams import MermaidDiagrams

    _, mmd = _export(path)
    md = MermaidDiagrams()
    md.load_from_string(mmd, format="mermaid")
    result = md.render(str(tmp_path / "out"), format="svg")
    assert Path(result.output_path).stat().st_size > 0
