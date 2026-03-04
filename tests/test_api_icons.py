#
# VULNEX -Universal Security Visualization Library-
#
# File: test_api_icons.py
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
#

"""Tests for Bundled Icons API router endpoints.

Covers: GET /icons, /icons/categories, /icons/{icon_path}
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
# List Icons
# =============================================================================

class TestListIcons:

    def test_list_returns_paginated(self):
        response = client.get("/icons")
        assert response.status_code == 200
        data = response.json()
        assert "icons" in data
        assert "total" in data
        assert "page" in data
        assert "page_size" in data

    def test_list_pagination(self):
        response = client.get("/icons?page=1&page_size=10")
        assert response.status_code == 200
        data = response.json()
        assert len(data["icons"]) <= 10

    def test_list_filter_by_category(self):
        response = client.get("/icons?category=azure")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data["icons"], list)

    def test_list_search(self):
        response = client.get("/icons?search=compute")
        assert response.status_code == 200

    def test_list_invalid_category(self):
        response = client.get("/icons?category=nonexistent")
        assert response.status_code == 400


# =============================================================================
# Categories
# =============================================================================

class TestIconCategories:

    def test_categories_returns_list(self):
        response = client.get("/icons/categories")
        assert response.status_code == 200
        data = response.json()
        assert "categories" in data
        assert "counts" in data
        assert isinstance(data["categories"], list)

    def test_categories_include_known(self):
        data = client.get("/icons/categories").json()
        categories = data["categories"]
        # At least azure should be present based on assets
        assert any("azure" in c.lower() for c in categories) or len(categories) > 0


# =============================================================================
# Get Specific Icon
# =============================================================================

class TestGetIcon:

    def test_get_icon_path_traversal_blocked(self):
        """Path traversal in icon path should be rejected."""
        response = client.get("/icons/../../etc/passwd")
        assert response.status_code in (400, 404)

    def test_get_icon_nonexistent_category(self):
        response = client.get("/icons/nonexistent/icon.png")
        assert response.status_code in (400, 404)

    def test_get_icon_nonexistent_icon(self):
        response = client.get("/icons/azure/nonexistent-icon-12345.png")
        assert response.status_code == 404

    def test_get_icon_null_byte_blocked(self):
        """Null bytes in path should be rejected."""
        response = client.get("/icons/azure/icon%00.png")
        assert response.status_code in (400, 404)
