#
# VULNEX -Universal Security Visualization Library-
#
# File: test_api_all_modes.py
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
#

"""Batch, export and compare cover every file-based module.

The three endpoints used to handle only the first three or four modules.
They now share the library's module registry, so each module's bundled
templates must detect, export, compare and batch-render.
"""

import glob
import io
import os
import shutil
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))
os.environ["USECVISLIB_AUTH_ENABLED"] = "false"

from fastapi.testclient import TestClient

from api.config import limiter
from api.main import app
from api.routers.utilities import _CONFIG_MODES, _detect_config_mode
from api.schemas import VisualizationMode
from usecvislib.utils import ReadConfigFile

client = TestClient(app)

HAVE_DOT = shutil.which("dot") is not None

TEMPLATES = os.path.join(os.path.dirname(__file__), "..", "templates")

# Templates for each config mode, and a key its config always has
MODE_TEMPLATES = {
    "attack_tree": ("attack-trees/*", "tree"),
    "attack_graph": ("attack-graphs/*", "graph"),
    "threat_model": ("threat-models/*", "model"),
    "privilege_gradient": ("privilege-gradient/*", "zones"),
    "component_diagram": ("architecture/*component*", "layers"),
    "dependency_graph": ("architecture/*depend*", "modules"),
    "kill_chain": ("kill-chains/*", "killchain"),
    "incident_timeline": ("timelines/*", "incident"),
    "vuln_tree": ("vuln-trees/*", "dependencies"),
    "maestro": ("maestro/*", "agents"),
}

# Rendered without Graphviz (Matplotlib)
NO_DOT_MODES = {"incident_timeline"}


def templates_for(mode):
    pattern, _ = MODE_TEMPLATES[mode]
    return sorted(glob.glob(os.path.join(TEMPLATES, pattern)))


def upload(path, field="file"):
    with open(path, "rb") as f:
        return {field: (os.path.basename(path), f.read())}


@pytest.fixture(autouse=True)
def reset_rate_limits():
    limiter.reset()
    yield
    limiter.reset()


def test_every_registry_module_has_a_mode():
    assert {m.value for m in _CONFIG_MODES} == set(MODE_TEMPLATES)


@pytest.mark.parametrize("mode", MODE_TEMPLATES)
def test_templates_detect_as_their_mode(mode):
    paths = templates_for(mode)
    assert paths
    for path in paths:
        assert _detect_config_mode(ReadConfigFile(path)) == VisualizationMode(mode), path


@pytest.mark.parametrize("mode", MODE_TEMPLATES)
def test_export_auto_detects_mode(mode):
    _, key = MODE_TEMPLATES[mode]
    response = client.post("/export/data", params={"format": "json"}, files=upload(templates_for(mode)[0]))
    assert response.status_code == 200, response.text
    assert f'"{key}"' in response.json()["content"]


@pytest.mark.parametrize("mode", MODE_TEMPLATES)
def test_export_sections_listed(mode):
    response = client.get("/export/sections", params={"mode": mode})
    assert response.status_code == 200
    _, key = MODE_TEMPLATES[mode]
    assert key in response.json()["sections"]


@pytest.mark.parametrize("mode", MODE_TEMPLATES)
def test_compare_identical_has_no_changes(mode):
    path = templates_for(mode)[0]
    files = {**upload(path, "old_file"), **upload(path, "new_file")}
    response = client.post("/diff/compare", files=files)
    assert response.status_code == 200, response.text
    assert response.json()["has_changes"] is False


@pytest.mark.parametrize("mode", MODE_TEMPLATES)
def test_compare_with_explicit_mode(mode):
    paths = templates_for(mode)
    files = {**upload(paths[0], "old_file"), **upload(paths[-1], "new_file")}
    response = client.post("/diff/compare", params={"mode": mode}, files=files)
    assert response.status_code == 200, response.text
    assert response.json()["has_changes"] is (len(paths) > 1)


@pytest.mark.parametrize(
    "mode",
    [
        pytest.param(m, marks=pytest.mark.skipif(not HAVE_DOT and m not in NO_DOT_MODES, reason="needs dot"))
        for m in MODE_TEMPLATES
    ],
)
def test_batch_renders_every_template(mode):
    paths = templates_for(mode)[:3]
    files = [("files", next(iter(upload(p).values()))) for p in paths]
    response = client.post("/batch/visualize", params={"mode": mode, "format": "png"}, files=files)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["success_count"] == len(paths), [r["error"] for r in body["results"] if not r["success"]]
    assert all(r["image_data"] for r in body["results"])


class TestBinaryBatch:
    def test_one_chart_per_file(self):
        files = [
            ("files", ("random.bin", os.urandom(4096))),
            ("files", ("text.txt", b"hello world " * 400)),
        ]
        response = client.post(
            "/batch/visualize", params={"mode": "binary", "visualization_type": "digraph"}, files=files
        )
        assert response.status_code == 200
        results = {r["filename"]: r for r in response.json()["results"]}
        assert results["random.bin"]["output_file"] == "random_digraph.png"
        assert all(r["success"] and r["image_data"] for r in results.values())
        assert results["text.txt"]["stats"]["printable_percentage"] > 90

    def test_empty_file_fails_only_that_item(self):
        files = [("files", ("empty.bin", b"")), ("files", ("data.bin", io.BytesIO(os.urandom(2048)).getvalue()))]
        response = client.post("/batch/visualize", params={"mode": "binary"}, files=files)
        results = {r["filename"]: r for r in response.json()["results"]}
        assert results["empty.bin"]["error"] == "Uploaded file is empty"
        assert results["data.bin"]["success"]

    def test_all_charts_rejected(self):
        files = [("files", ("a.bin", b"abc"))]
        response = client.post("/batch/visualize", params={"mode": "binary", "visualization_type": "all"}, files=files)
        assert response.status_code == 400


def test_batch_rejects_modes_without_a_file_module():
    files = [("files", ("diagram.toml", b"[cloud]\n"))]
    for mode in ("cloud", "mermaid"):
        response = client.post("/batch/visualize", params={"mode": mode}, files=files)
        assert response.status_code == 400
