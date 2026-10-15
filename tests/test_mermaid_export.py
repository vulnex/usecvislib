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
# Binary-analysis config and metric trends are charts, not graphs: no Mermaid form
ALL = sorted(
    p
    for p in TEMPLATES.rglob("*")
    if p.suffix in FORMATS and p.name != "binvis_config.toml" and "trends" not in p.relative_to(TEMPLATES).parts
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


def test_angle_brackets_use_entity_codes():
    from usecvislib.mermaid import escape_label

    assert escape_label("<<device>> web") == "#lt;#lt;device#gt;#gt; web"


def test_attack_graph_uses_module_schema():
    _, mmd = _export(TEMPLATES / "attack-graphs" / "simple_network.tml")
    # network_edges, singular precondition/postcondition, affected_host
    assert "attacker -.->" in mmd
    assert "==>" in mmd
    assert "vuln_web_rce --> webserver" in mmd


def test_threat_model_uses_labels():
    _, mmd = _export(TEMPLATES / "threat-models" / "banking_api.tml")
    assert '["mTLS Mobile API"]' not in mmd and '|"mTLS Mobile API"|' in mmd
    assert re.search(r'subgraph internet\["(?!internet")', mmd)


def test_timeline_keeps_every_event_once():
    path = TEMPLATES / "timelines" / "ransomware_incident.tml"
    data = parse_content(path.read_text(encoding="utf-8"), "toml")
    _, mmd = _export(path)
    task_lines = [ln for ln in mmd.splitlines() if re.search(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", ln)]
    assert len(task_lines) == len(data["events"])


def test_custom_diagram_shapes_and_edge_label_fields():
    _, mmd = _export(TEMPLATES / "custom-diagrams" / "general" / "flowchart.toml")
    assert 'validate{"Valid?"}' in mmd and 'start(["Start"])' in mmd


def test_killchain_export_groups_phases_with_ids():
    _, mmd = _export(TEMPLATES / "kill-chains" / "apt_intrusion.tml")
    assert 'subgraph phase_0["Reconnaissance"]' in mmd
    assert '"T1595: Active Scanning (D)"' in mmd
    assert '|"Operation Nightfall"|' in mmd


def test_maestro_export_includes_assets():
    _, mmd = _export(TEMPLATES / "maestro" / "single-agent-rag.toml")
    assert "asset_" in mmd and '[("' in mmd
