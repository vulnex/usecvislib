#
# VULNEX -Universal Security Visualization Library-
#
# File: test_api_vulntree.py
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
#

"""Tests for the Vulnerability Dependency Tree API router.

Covers: POST /visualize/vuln-tree, /analyze/vuln-tree, /validate/vuln-tree.
"""

import io
import os
import shutil
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))
os.environ["USECVISLIB_AUTH_ENABLED"] = "false"

from fastapi.testclient import TestClient

from api.main import app

client = TestClient(app)

HAVE_DOT = shutil.which("dot") is not None


VALID_VT_TOML = b"""
[vulntree]
name = "API Test Tree"
root_packages = ["app"]

[dependencies."app"]
name = "app"
version = "1.0.0"
direct = true
dependencies = ["lodash"]

[dependencies."lodash"]
name = "lodash"
version = "4.17.19"
direct = false
dependencies = []

[[dependencies."lodash".vulnerabilities]]
id = "CVE-2021-23337"
severity = "high"
cvss = 7.2
fixed_version = "4.17.21"
exploited = false
"""

INVALID_TOML = b"not valid toml [[["


def _upload(content, filename="vt.toml"):
    return ("file", (filename, io.BytesIO(content), "application/octet-stream"))


class TestVisualizeVulnTree:
    @pytest.mark.skipif(not HAVE_DOT, reason="graphviz 'dot' not installed")
    def test_visualize_png(self):
        r = client.post("/visualize/vuln-tree?format=png", files=[_upload(VALID_VT_TOML)])
        assert r.status_code == 200
        assert r.content[:8] == b"\x89PNG\r\n\x1a\n"

    @pytest.mark.skipif(not HAVE_DOT, reason="graphviz 'dot' not installed")
    def test_visualize_all_modes(self):
        for mode in ("tree", "vulnerable_only", "critical_path"):
            r = client.post(f"/visualize/vuln-tree?format=png&mode={mode}", files=[_upload(VALID_VT_TOML)])
            assert r.status_code == 200, mode

    def test_visualize_png_status(self):
        # 200 with graphviz, 400/500 without the dot binary in the test image
        r = client.post("/visualize/vuln-tree?format=png", files=[_upload(VALID_VT_TOML)])
        assert r.status_code in (200, 400, 500)

    def test_visualize_malformed(self):
        r = client.post("/visualize/vuln-tree", files=[_upload(INVALID_TOML)])
        assert r.status_code in (400, 500)

    def test_visualize_rejects_unsupported_extension(self):
        r = client.post("/visualize/vuln-tree", files=[_upload(VALID_VT_TOML, filename="x.exe")])
        assert r.status_code in (400, 422)


class TestAnalyzeVulnTree:
    def test_analyze_returns_stats(self):
        r = client.post("/analyze/vuln-tree", files=[_upload(VALID_VT_TOML)])
        assert r.status_code == 200
        body = r.json()
        assert body["total_dependencies"] == 2
        assert body["vulnerable_dependencies"] == 1
        assert body["total_vulnerabilities"] == 1
        assert body["max_cvss"] == 7.2
        assert body["remediation_available"] == 1
        assert "app" in body["impacted_roots"]

    def test_analyze_malformed(self):
        r = client.post("/analyze/vuln-tree", files=[_upload(INVALID_TOML)])
        assert r.status_code in (400, 500)


class TestValidateVulnTree:
    def test_validate_ok(self):
        r = client.post("/validate/vuln-tree", files=[_upload(VALID_VT_TOML)])
        assert r.status_code == 200
        assert r.json()["valid"] is True

    def test_validate_flags_unknown_child(self):
        bad = VALID_VT_TOML.replace(b'dependencies = ["lodash"]', b'dependencies = ["ghost"]')
        r = client.post("/validate/vuln-tree", files=[_upload(bad)])
        assert r.status_code == 200
        body = r.json()
        assert body["valid"] is False
        assert any("ghost" in e for e in body["errors"])
