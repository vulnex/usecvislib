#
# VULNEX -Universal Security Visualization Library-
#
# File: test_api_qa_pass.py
# Author: Simon Roses Femerling
# Created: 2026-10-05
# Last Modified: 2026-10-05
# Version: 0.6.0
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""API regressions found by an exhaustive pass over endpoints and parameters."""

import io
import os
import shutil
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))
os.environ["USECVISLIB_AUTH_ENABLED"] = "false"

from fastapi.testclient import TestClient

from api.main import app

client = TestClient(app)
TEMPLATES = Path(__file__).parent.parent / "templates"
DOT = shutil.which("dot") is not None


def _file(path: Path, field: str = "file"):
    return (field, (path.name, io.BytesIO(path.read_bytes()), "application/octet-stream"))


def test_maestro_svg_heatmap_is_a_client_error():
    src = TEMPLATES / "maestro" / "single-agent-rag.toml"
    r = client.post("/visualize/maestro?render_engine=svg&view=heatmap", files=[_file(src)])
    assert r.status_code == 400
    assert "heatmap" in r.json()["detail"]


def test_threat_library_lists_and_filters():
    r = client.get("/threats/library?limit=5")
    assert r.status_code == 200, r.text
    assert r.json()["total"] > 5
    r = client.get("/threats/library?element_type=Process&limit=500")
    assert r.status_code == 200, r.text
    assert r.json()["total"] > 0


@pytest.mark.skipif(not DOT, reason="Graphviz 'dot' binary required")
@pytest.mark.parametrize(
    "source_type,path",
    [
        ("attack_tree", "attack-trees/ransomware_attack.tml"),
        ("attack_graph", "attack-graphs/corporate_network.tml"),
        ("threat_model", "threat-models/banking_api.tml"),
    ],
)
def test_custom_diagram_import(source_type, path):
    src = TEMPLATES / path
    if not src.exists():
        pytest.skip(f"template {path} missing")
    r = client.post(f"/custom-diagrams/import?source_type={source_type}&format=svg", files=[_file(src)])
    assert r.status_code == 200, r.text
    assert b"<svg" in r.content


def test_batch_unsupported_mode_is_400():
    src = TEMPLATES / "attack-trees" / "ransomware_attack.tml"
    r = client.post("/batch/visualize?mode=binary", files=[_file(src, "files")])
    assert r.status_code == 400


@pytest.mark.skipif(not DOT, reason="Graphviz 'dot' binary required")
def test_batch_accepts_svg_engine_presets():
    src = TEMPLATES / "attack-trees" / "ransomware_attack.tml"
    r = client.post("/batch/visualize?mode=attack_tree&format=svg&style=sv_default", files=[_file(src, "files")])
    assert r.status_code == 200, r.text
    assert r.json()["success_count"] == 1, r.json()


@pytest.mark.skipif(not DOT, reason="Graphviz 'dot' binary required")
def test_cloud_dot_output_is_dot():
    pytest.importorskip("diagrams")
    src = TEMPLATES / "cloud" / "aws" / "web-application.toml"
    r = client.post("/visualize/cloud?format=dot", files=[_file(src)])
    assert r.status_code == 200, r.text
    assert r.content.lstrip().startswith((b"digraph", b"graph", b"strict"))


def test_cloud_providers_match_icon_enum():
    providers = client.get("/cloud/providers").json()["providers"]
    assert all({"id", "name"} <= set(p) for p in providers)
    for p in providers:
        # every listed provider is accepted by /cloud/icons (422 = rejected)
        assert client.get(f"/cloud/icons?provider={p['id']}").status_code != 422, p


@pytest.mark.skipif(not DOT, reason="Graphviz 'dot' binary required")
def test_custom_diagram_keeps_file_style_and_survives_ortho_crash():
    src = TEMPLATES / "custom-diagrams" / "software" / "deployment-diagram.toml"
    # no style: the template's own preset is used
    assert client.post("/custom-diagrams/visualize?format=svg", files=[_file(src)]).status_code == 200
    # cd_default made Graphviz's ortho router abort (SIGABRT); polyline fallback
    r = client.post("/custom-diagrams/visualize?format=svg&style=cd_default", files=[_file(src)])
    assert r.status_code == 200, r.text


@pytest.mark.skipif(not DOT, reason="Graphviz 'dot' binary required")
def test_custom_diagram_from_template_applies_style():
    base = "/custom-diagrams/from-template?template_id=general/flowchart&format=svg"
    plain = client.post(base)
    dark = client.post(base + "&style=cd_dark")
    assert plain.status_code == dark.status_code == 200
    assert plain.content != dark.content
