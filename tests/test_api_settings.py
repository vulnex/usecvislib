#
# VULNEX -Universal Security Visualization Library-
#
# File: test_api_settings.py
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
#

"""Tests for Settings API router endpoints.

Covers: GET /settings, PUT /settings, POST /settings/cvss/enable-all,
POST /settings/cvss/disable-all, POST /settings/reset
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'api'))
os.environ["USECVISLIB_AUTH_ENABLED"] = "false"

from fastapi.testclient import TestClient
from api.main import app

client = TestClient(app)


# =============================================================================
# GET /settings
# =============================================================================

class TestGetSettings:

    def test_returns_settings(self):
        response = client.get("/settings")
        assert response.status_code == 200
        data = response.json()
        assert "cvss_display" in data

    def test_cvss_display_structure(self):
        data = client.get("/settings").json()
        cvss = data["cvss_display"]
        assert "enabled" in cvss
        assert "attack_tree" in cvss
        assert "attack_graph" in cvss
        assert "threat_model" in cvss


# =============================================================================
# PUT /settings
# =============================================================================

class TestUpdateSettings:

    def test_update_cvss_settings(self):
        response = client.put("/settings", json={
            "cvss_display": {
                "enabled": True,
                "attack_tree": True,
                "attack_graph": False,
                "threat_model": True
            }
        })
        assert response.status_code == 200
        data = response.json()
        assert data["cvss_display"]["enabled"] is True
        assert data["cvss_display"]["attack_graph"] is False

    def test_settings_persist_after_update(self):
        """Updated settings should persist on subsequent GET."""
        client.put("/settings", json={
            "cvss_display": {
                "enabled": False,
                "attack_tree": False,
                "attack_graph": False,
                "threat_model": False
            }
        })
        data = client.get("/settings").json()
        assert data["cvss_display"]["enabled"] is False


# =============================================================================
# CVSS Enable/Disable All
# =============================================================================

class TestCVSSToggle:

    def test_enable_all(self):
        response = client.post("/settings/cvss/enable-all")
        assert response.status_code == 200
        data = response.json()
        cvss = data["cvss_display"]
        assert cvss["enabled"] is True
        assert cvss["attack_tree"] is True
        assert cvss["attack_graph"] is True
        assert cvss["threat_model"] is True

    def test_disable_all(self):
        response = client.post("/settings/cvss/disable-all")
        assert response.status_code == 200
        data = response.json()
        cvss = data["cvss_display"]
        assert cvss["enabled"] is False

    def test_enable_then_disable(self):
        """Enable all then disable, verify state changes."""
        client.post("/settings/cvss/enable-all")
        data1 = client.get("/settings").json()
        assert data1["cvss_display"]["enabled"] is True

        client.post("/settings/cvss/disable-all")
        data2 = client.get("/settings").json()
        assert data2["cvss_display"]["enabled"] is False


# =============================================================================
# Reset
# =============================================================================

class TestResetSettings:

    def test_reset_returns_defaults(self):
        # Change settings first
        client.post("/settings/cvss/disable-all")
        # Reset
        response = client.post("/settings/reset")
        assert response.status_code == 200
        data = response.json()
        assert "cvss_display" in data

    def test_reset_restores_enabled(self):
        """After reset, CVSS should be back to defaults."""
        client.post("/settings/cvss/disable-all")
        client.post("/settings/reset")
        data = client.get("/settings").json()
        # Default is enabled
        assert data["cvss_display"]["enabled"] is True
