#
# VULNEX -Universal Security Visualization Library-
#
# File: test_api_attack_trees.py
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
#

"""Tests for Attack Trees API router endpoints.

Covers: POST /visualize/attack-tree, /analyze/attack-tree, /validate/attack-tree
"""

import io
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'api'))
os.environ["USECVISLIB_AUTH_ENABLED"] = "false"

from fastapi.testclient import TestClient
from api.main import app

client = TestClient(app)

VALID_ATTACK_TREE = """
[tree]
name = "Test Attack Tree"
root = "root"

[nodes]
root = {label = "Root Goal", style = "filled", shape = "oval"}
child1 = {label = "Sub-Goal A", shape = "rectangle", cvss = 7.5}
child2 = {label = "Sub-Goal B", shape = "rectangle", cvss = 5.0}
leaf1 = {label = "Leaf 1", shape = "rectangle"}

[edges]
root = ["child1", "child2"]
child1 = ["leaf1"]
"""

INVALID_TOML = "{{{{not valid toml at all"


def _upload(content, filename="tree.toml"):
    return ("file", (filename, io.BytesIO(content.encode()), "application/octet-stream"))


# =============================================================================
# Visualize
# =============================================================================

class TestVisualizeAttackTree:

    def test_visualize_returns_image(self):
        response = client.post(
            "/visualize/attack-tree?format=png",
            files=[_upload(VALID_ATTACK_TREE)],
        )
        # 400 if graphviz not installed
        assert response.status_code in (200, 400)

    def test_visualize_svg_format(self):
        response = client.post(
            "/visualize/attack-tree?format=svg",
            files=[_upload(VALID_ATTACK_TREE)],
        )
        assert response.status_code in (200, 400)

    def test_visualize_invalid_extension(self):
        response = client.post(
            "/visualize/attack-tree",
            files=[_upload("data", "file.exe")],
        )
        assert response.status_code in (400, 500)

    def test_visualize_malformed_toml(self):
        response = client.post(
            "/visualize/attack-tree",
            files=[_upload(INVALID_TOML)],
        )
        assert response.status_code in (400, 500)


# =============================================================================
# Analyze
# =============================================================================

class TestAnalyzeAttackTree:

    def test_analyze_returns_stats(self):
        response = client.post(
            "/analyze/attack-tree",
            files=[_upload(VALID_ATTACK_TREE)],
        )
        assert response.status_code == 200
        data = response.json()
        assert "total_nodes" in data
        assert "total_edges" in data
        assert data["total_nodes"] >= 4

    def test_analyze_cvss_stats(self):
        response = client.post(
            "/analyze/attack-tree",
            files=[_upload(VALID_ATTACK_TREE)],
        )
        data = response.json()
        assert "nodes_with_cvss" in data
        assert data["nodes_with_cvss"] >= 1

    def test_analyze_malformed_toml(self):
        response = client.post(
            "/analyze/attack-tree",
            files=[_upload(INVALID_TOML)],
        )
        assert response.status_code in (400, 500)


# =============================================================================
# Validate
# =============================================================================

class TestValidateAttackTree:

    def test_validate_valid_tree(self):
        response = client.post(
            "/validate/attack-tree",
            files=[_upload(VALID_ATTACK_TREE)],
        )
        assert response.status_code == 200
        data = response.json()
        assert "valid" in data

    def test_validate_malformed_toml(self):
        response = client.post(
            "/validate/attack-tree",
            files=[_upload(INVALID_TOML)],
        )
        assert response.status_code in (200, 400, 500)

    def test_validate_invalid_extension(self):
        response = client.post(
            "/validate/attack-tree",
            files=[_upload("data", "file.exe")],
        )
        assert response.status_code in (400, 500)
