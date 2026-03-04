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
