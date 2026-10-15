#
# VULNEX -Universal Security Visualization Library-
#
# File: test_api_error_handling.py
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
#

"""Status codes and temp-file cleanup shared by every upload endpoint.

The routers share ``handle_errors`` / ``TempFiles`` (api/helpers.py). Before
that, most of them turned the 400/413 from the upload checks, and the 504
from a render timeout, into a generic 500.
"""

import os
import sys
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))
os.environ["USECVISLIB_AUTH_ENABLED"] = "false"

from fastapi.testclient import TestClient

from api.config import MAX_CONFIG_FILE_SIZE, TEMP_DIR, limiter
from api.main import app

client = TestClient(app)

# Every endpoint that takes one config upload as "file" and no other
# required field
CONFIG_UPLOAD_ENDPOINTS = [
    "/visualize/attack-tree",
    "/analyze/attack-tree",
    "/validate/attack-tree",
    "/visualize/attack-graph",
    "/analyze/attack-graph",
    "/analyze/attack-surface",
    "/analyze/centrality",
    "/analyze/chokepoints",
    "/analyze/critical-nodes",
    "/analyze/graph-metrics",
    "/validate/attack-graph",
    "/visualize/threat-model",
    "/analyze/threat-model",
    "/analyze/stride",
    "/report/threat-model",
    "/visualize/component-diagram",
    "/analyze/component-diagram",
    "/validate/component-diagram",
    "/visualize/dependency-graph",
    "/analyze/dependency-graph",
    "/validate/dependency-graph",
    "/visualize/privilege-gradient",
    "/analyze/privilege-gradient",
    "/analyze/inversions",
    "/validate/privilege-gradient",
    "/visualize/kill-chain",
    "/analyze/kill-chain",
    "/validate/kill-chain",
    "/visualize/timeline",
    "/analyze/timeline",
    "/validate/timeline",
    "/visualize/vuln-tree",
    "/analyze/vuln-tree",
    "/validate/vuln-tree",
    "/visualize/maestro",
    "/analyze/maestro",
    "/analyze/maestro/threats",
    "/validate/maestro",
    "/analyze/cloud",
    "/analyze/mermaid",
]

SIMPLE_TREE = b'[tree]\nname = "T"\nroot = "Goal"\n\n[nodes]\n"Goal" = {}\n'


def leftover_temp_files():
    return [name for name in os.listdir(TEMP_DIR) if name.startswith(("upload_", "output_"))]


@pytest.fixture(autouse=True)
def no_leftovers():
    # These tests send many requests: keep the rate limits out of them, and
    # leave the other test files their full quota
    limiter.reset()
    before = set(leftover_temp_files())
    yield
    assert set(leftover_temp_files()) <= before
    limiter.reset()


@pytest.mark.parametrize("endpoint", CONFIG_UPLOAD_ENDPOINTS)
def test_unsupported_extension_is_400(endpoint):
    response = client.post(endpoint, files={"file": ("model.exe", b"a")})
    assert response.status_code == 400


@pytest.mark.parametrize("endpoint", CONFIG_UPLOAD_ENDPOINTS)
def test_oversized_upload_is_413(endpoint):
    response = client.post(endpoint, files={"file": ("model.toml", b"x" * (MAX_CONFIG_FILE_SIZE + 1))})
    assert response.status_code == 413


@pytest.mark.parametrize("endpoint", CONFIG_UPLOAD_ENDPOINTS)
def test_malformed_config_is_400(endpoint):
    response = client.post(endpoint, files={"file": ("model.toml", b"[[[not toml")})
    assert response.status_code == 400


@pytest.mark.parametrize(
    "params", [{"mode": "attack_tree"}, {"mode": "threat_model"}], ids=["attack_tree", "threat_model"]
)
def test_export_malformed_config_is_400(params):
    response = client.post("/export/data", params=params, files={"file": ("model.toml", b"[[[not toml")})
    assert response.status_code == 400


def test_render_timeout_is_504_and_late_output_is_removed(monkeypatch):
    from api.routers import attack_trees

    written = []

    def slow_build(self):
        time.sleep(0.3)
        path = f"{self.outputfile}.png"
        with open(path, "wb") as f:
            f.write(b"late")
        written.append(path)

    monkeypatch.setattr(attack_trees, "REQUEST_TIMEOUT_VISUALIZE", 0.05)
    monkeypatch.setattr(attack_trees.AttackTrees, "BuildAttackTree", slow_build)

    response = client.post("/visualize/attack-tree", files={"file": ("tree.toml", SIMPLE_TREE)})
    assert response.status_code == 504

    deadline = time.time() + 3
    while not written and time.time() < deadline:
        time.sleep(0.05)
    time.sleep(0.1)
    assert written and not os.path.exists(written[0])
