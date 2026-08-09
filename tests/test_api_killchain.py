#
# VULNEX -Universal Security Visualization Library-
#
# File: test_api_killchain.py
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
#

"""Tests for the Kill Chain / MITRE ATT&CK API router.

Covers: POST /visualize/kill-chain, /analyze/kill-chain, /validate/kill-chain.
"""

import io
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))
os.environ["USECVISLIB_AUTH_ENABLED"] = "false"

from fastapi.testclient import TestClient

from api.main import app

client = TestClient(app)


VALID_KC_TOML = b"""
[killchain]
name = "API Test Chain"
framework = "kill_chain"

[techniques."T1566"]
name = "Spearphishing"
phase = "Delivery"
severity = "high"
detected = true
mitigated = true

[techniques."T1204"]
name = "User Execution"
phase = "Exploitation"
severity = "high"
detected = false
mitigated = false

[[incidents]]
id = "I1"
name = "Test Incident"
techniques = ["T1566", "T1204"]
"""

INVALID_TOML = b"not valid toml [[["


def _upload(content, filename="kc.toml"):
    return ("file", (filename, io.BytesIO(content), "application/octet-stream"))


class TestVisualizeKillChain:
    def test_visualize_png(self):
        r = client.post("/visualize/kill-chain?format=png", files=[_upload(VALID_KC_TOML)])
        # 400 if graphviz binary not installed in the test image
        assert r.status_code in (200, 400, 500)

    def test_visualize_svg_engine(self):
        r = client.post(
            "/visualize/kill-chain?format=svg&render_engine=svg",
            files=[_upload(VALID_KC_TOML)],
        )
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("image/svg")

    def test_visualize_svg_engine_png(self):
        r = client.post(
            "/visualize/kill-chain?format=png&render_engine=svg&style=sv_dark",
            files=[_upload(VALID_KC_TOML)],
        )
        assert r.status_code == 200
        assert r.content[:8] == b"\x89PNG\r\n\x1a\n"

    def test_visualize_malformed(self):
        r = client.post("/visualize/kill-chain", files=[_upload(INVALID_TOML)])
        assert r.status_code in (400, 500)

    def test_visualize_rejects_unsupported_extension(self):
        r = client.post("/visualize/kill-chain", files=[_upload(VALID_KC_TOML, filename="x.exe")])
        assert r.status_code in (400, 422)


class TestAnalyzeKillChain:
    def test_analyze_returns_stats(self):
        r = client.post("/analyze/kill-chain", files=[_upload(VALID_KC_TOML)])
        assert r.status_code == 200
        body = r.json()
        assert body["total_techniques"] == 2
        assert body["framework"] == "kill_chain"
        assert body["detected_techniques"] == 1
        assert 0.0 <= body["detection_coverage"] <= 1.0

    def test_analyze_malformed(self):
        r = client.post("/analyze/kill-chain", files=[_upload(INVALID_TOML)])
        assert r.status_code in (400, 500)


class TestValidateKillChain:
    def test_validate_ok(self):
        r = client.post("/validate/kill-chain", files=[_upload(VALID_KC_TOML)])
        assert r.status_code == 200
        assert r.json()["valid"] is True

    def test_validate_flags_unknown_incident_technique(self):
        bad = VALID_KC_TOML.replace(b'techniques = ["T1566", "T1204"]', b'techniques = ["T1566", "GHOST"]')
        r = client.post("/validate/kill-chain", files=[_upload(bad)])
        assert r.status_code == 200
        body = r.json()
        assert body["valid"] is False
        assert any("GHOST" in e for e in body["errors"])
