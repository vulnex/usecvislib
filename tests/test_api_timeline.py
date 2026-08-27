#
# VULNEX -Universal Security Visualization Library-
#
# File: test_api_timeline.py
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
#

"""Tests for the Incident Timeline API router.

Covers: POST /visualize/timeline, /analyze/timeline, /validate/timeline.
"""

import io
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))
os.environ["USECVISLIB_AUTH_ENABLED"] = "false"

from fastapi.testclient import TestClient

from api.main import app

client = TestClient(app)


VALID_TL_TOML = b"""
[incident]
name = "API Test Incident"
id = "INC-9"
analyst = "SOC"

[[phases]]
name = "Detection"
start = "2026-01-15T08:00:00Z"
end = "2026-01-15T10:00:00Z"
color = "#e74c3c"

[[phases]]
name = "Containment"
start = "2026-01-15T10:00:00Z"
end = "2026-01-15T12:00:00Z"
color = "#27ae60"

[[events]]
id = "EVT-1"
timestamp = "2026-01-15T08:32:00Z"
title = "Phishing opened"
severity = "high"
lane = "Workstation"
technique = "T1566.001"
duration = "2m"

[[events]]
id = "EVT-2"
timestamp = "2026-01-15T09:05:00Z"
title = "C2 beacon"
severity = "critical"
lane = "Network"
"""

INVALID_TOML = b"not valid toml [[["


def _upload(content, filename="tl.toml"):
    return ("file", (filename, io.BytesIO(content), "application/octet-stream"))


class TestVisualizeTimeline:
    def test_visualize_png(self):
        r = client.post("/visualize/timeline?format=png", files=[_upload(VALID_TL_TOML)])
        assert r.status_code == 200
        assert r.content[:8] == b"\x89PNG\r\n\x1a\n"

    def test_visualize_svg(self):
        r = client.post("/visualize/timeline?format=svg", files=[_upload(VALID_TL_TOML)])
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("image/svg")

    def test_visualize_all_modes(self):
        for mode in ("swimlane", "gantt", "vertical", "compact"):
            r = client.post(f"/visualize/timeline?format=png&mode={mode}", files=[_upload(VALID_TL_TOML)])
            assert r.status_code == 200, mode

    def test_visualize_style_preset(self):
        r = client.post("/visualize/timeline?format=png&style=tl_dark", files=[_upload(VALID_TL_TOML)])
        assert r.status_code == 200

    def test_visualize_malformed(self):
        r = client.post("/visualize/timeline", files=[_upload(INVALID_TOML)])
        assert r.status_code in (400, 500)

    def test_visualize_rejects_unsupported_extension(self):
        r = client.post("/visualize/timeline", files=[_upload(VALID_TL_TOML, filename="x.exe")])
        assert r.status_code in (400, 422)


class TestAnalyzeTimeline:
    def test_analyze_returns_stats(self):
        r = client.post("/analyze/timeline", files=[_upload(VALID_TL_TOML)])
        assert r.status_code == 200
        body = r.json()
        assert body["total_events"] == 2
        assert body["total_phases"] == 2
        assert body["tagged_events"] == 1
        assert body["severity_distribution"]["critical"] == 1

    def test_analyze_response_metrics(self):
        r = client.post("/analyze/timeline", files=[_upload(VALID_TL_TOML)])
        assert r.status_code == 200
        rm = r.json()["response_metrics"]
        assert rm["time_to_detect"] is not None

    def test_analyze_malformed(self):
        r = client.post("/analyze/timeline", files=[_upload(INVALID_TOML)])
        assert r.status_code in (400, 500)


class TestValidateTimeline:
    def test_validate_ok(self):
        r = client.post("/validate/timeline", files=[_upload(VALID_TL_TOML)])
        assert r.status_code == 200
        assert r.json()["valid"] is True

    def test_validate_flags_no_events(self):
        empty = b'[incident]\nname = "x"\nevents = []\n'
        r = client.post("/validate/timeline", files=[_upload(empty)])
        assert r.status_code == 200
        body = r.json()
        assert body["valid"] is False
        assert any("No events" in e for e in body["errors"])
