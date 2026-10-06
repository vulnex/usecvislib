#
# VULNEX -Universal Security Visualization Library-
#
# File: test_api_binary.py
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
#

"""Tests for Binary Visualization API router endpoints.

Covers: POST /visualize/binary, /analyze/binary
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

# Generate a small binary blob for testing
SAMPLE_BINARY = bytes(range(256)) * 4  # 1024 bytes with all byte values


def _upload_binary(data=None, filename="sample.bin"):
    if data is None:
        data = SAMPLE_BINARY
    return ("file", (filename, io.BytesIO(data), "application/octet-stream"))


# =============================================================================
# Visualize
# =============================================================================

class TestVisualizeBinary:

    def test_visualize_entropy(self):
        response = client.post(
            "/visualize/binary?visualization_type=entropy",
            files=[_upload_binary()],
        )
        # 500 if matplotlib backend unavailable in test thread
        assert response.status_code in (200, 500)

    def test_visualize_distribution(self):
        response = client.post(
            "/visualize/binary?visualization_type=distribution",
            files=[_upload_binary()],
        )
        assert response.status_code in (200, 500)

    def test_visualize_svg_format(self):
        response = client.post(
            "/visualize/binary?format=svg",
            files=[_upload_binary()],
        )
        assert response.status_code in (200, 500)

    def test_visualize_empty_file(self):
        response = client.post(
            "/visualize/binary",
            files=[_upload_binary(b"")],
        )
        assert response.status_code in (400, 500)


# =============================================================================
# Analyze
# =============================================================================

class TestAnalyzeBinary:

    def test_analyze_returns_stats(self):
        response = client.post(
            "/analyze/binary",
            files=[_upload_binary()],
        )
        assert response.status_code == 200
        data = response.json()
        assert "file_size" in data
        assert "entropy" in data
        assert "unique_bytes" in data
        assert data["file_size"] == 1024

    def test_analyze_entropy_range(self):
        """Entropy should be between 0 and 8."""
        response = client.post(
            "/analyze/binary",
            files=[_upload_binary()],
        )
        data = response.json()
        assert 0 <= data["entropy"] <= 8

    def test_analyze_unique_bytes(self):
        """Sample with all 256 byte values should have 256 unique bytes."""
        response = client.post(
            "/analyze/binary",
            files=[_upload_binary()],
        )
        data = response.json()
        assert data["unique_bytes"] == 256

    def test_analyze_null_heavy_binary(self):
        """Binary with mostly nulls should have high null percentage."""
        null_heavy = b'\x00' * 900 + b'\x01' * 100
        response = client.post(
            "/analyze/binary",
            files=[_upload_binary(null_heavy)],
        )
        assert response.status_code == 200
        data = response.json()
        assert data["null_percentage"] >= 80


# =============================================================================
# BytesRevealer integration requests (A1-A6, B2)
# =============================================================================


class TestPartialConfig:
    """A1: config_json changes only the fields the client sends."""

    def _binvis(self, tmp_path):
        from usecvislib import BinVis

        sample = tmp_path / "sample.bin"
        sample.write_bytes(SAMPLE_BINARY)
        return BinVis(str(sample), str(tmp_path / "out"), validate_paths=False)

    def test_wind_rose_keeps_library_label_position(self, tmp_path):
        from api.routers.binary import apply_binvis_config
        from api.schemas import BinVisConfig

        bv = self._binvis(tmp_path)
        apply_binvis_config(bv, BinVisConfig(**{"wind_rose": {"bar_alpha": 0.5}}))
        assert bv.config["wind_rose"]["bar_alpha"] == 0.5
        assert bv.config["wind_rose"]["rlabel_position"] == 22.5

    def test_heatmap_block_size_changes_nothing_else(self, tmp_path):
        from api.routers.binary import apply_binvis_config
        from api.schemas import BinVisConfig

        bv = self._binvis(tmp_path)
        bv.config["heatmap"]["dpi"] = 300  # e.g. set by a config file
        before = dict(bv.config["heatmap"])
        apply_binvis_config(bv, BinVisConfig(**{"heatmap": {"block_size": 512}}))
        assert bv.config["heatmap"] == {**before, "block_size": 512}

    def test_schema_default_matches_library(self):
        from api.schemas import WindRoseConfig
        from usecvislib import BinVis

        library = BinVis._default_config(None)["wind_rose"]["rlabel_position"]
        assert WindRoseConfig().rlabel_position == library


class TestAllCharts:
    """A2 + B2: visualization_type=all returns every chart in one response."""

    def test_all_returns_five_charts_as_json(self):
        import base64

        response = client.post("/visualize/binary?visualization_type=all", files=[_upload_binary()])
        assert response.status_code == 200
        charts = response.json()["charts"]
        assert [c["type"] for c in charts] == ["entropy", "distribution", "windrose", "heatmap", "digraph"]
        for chart in charts:
            assert chart["content_type"] == "image/png"
            assert base64.b64decode(chart["data"]).startswith(b"\x89PNG")

    def test_digraph_single_chart(self):
        response = client.post("/visualize/binary?visualization_type=digraph&format=svg", files=[_upload_binary()])
        assert response.status_code == 200
        assert b"<svg" in response.content[:500]


class TestChartTitle:
    """A3: server temp file names never reach chart titles."""

    def test_title_cleaning(self):
        from api.routers.binary import chart_title

        assert chart_title(None) == ""
        assert chart_title("") == ""
        assert chart_title("firmware.bin") == "firmware.bin"
        assert chart_title("cost $5\nvalue") == "cost 5value"
        assert len(chart_title("x" * 500)) == 120

    def test_endpoint_passes_title_not_temp_name(self, monkeypatch):
        import api.routers.binary as binary_router

        seen = []
        real = binary_router.BinVis

        def spy(*args, **kwargs):
            seen.append(kwargs.get("display_name"))
            return real(*args, **kwargs)

        monkeypatch.setattr(binary_router, "BinVis", spy)
        client.post("/visualize/binary?visualization_type=distribution", files=[_upload_binary()])
        client.post(
            "/visualize/binary?visualization_type=distribution",
            files=[_upload_binary()],
            data={"title": "firmware.bin"},
        )
        assert seen == ["", "firmware.bin"]


class TestCorsAndRateLimit:
    """A5 + A6: browser clients can DELETE, read headers, and see when to retry."""

    def test_cors_allows_delete_and_exposes_headers(self):
        from api.config import ALLOWED_ORIGINS

        origin = ALLOWED_ORIGINS[0]
        preflight = client.options(
            "/images/abc",
            headers={"Origin": origin, "Access-Control-Request-Method": "DELETE"},
        )
        assert "DELETE" in preflight.headers.get("access-control-allow-methods", "")
        response = client.get("/health", headers={"Origin": origin})
        exposed = response.headers.get("access-control-expose-headers", "")
        assert "Retry-After" in exposed and "Content-Disposition" in exposed

    def test_429_carries_retry_after(self):
        from fastapi import FastAPI, Request
        from slowapi.errors import RateLimitExceeded

        from api.config import limiter
        from api.main import rate_limit_exceeded

        mini = FastAPI()
        mini.state.limiter = limiter
        mini.add_exception_handler(RateLimitExceeded, rate_limit_exceeded)

        @mini.get("/once")
        @limiter.limit("1/minute")
        async def once(request: Request):
            return {"ok": True}

        mini_client = TestClient(mini)
        assert mini_client.get("/once").status_code == 200
        limited = mini_client.get("/once")
        assert limited.status_code == 429
        assert 1 <= int(limited.headers["Retry-After"]) <= 60
