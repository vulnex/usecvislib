#
# VULNEX -Universal Security Visualization Library-
#
# File: test_api_auth.py
# Author: Claude Code
# Created: 2025-12-30
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
#

"""Tests for API Authentication.

This module tests the API authentication system:
- Auth disabled mode (all requests pass through)
- Auth enabled with valid/invalid API keys
- Multiple API keys support
- Startup validation (fail-fast when no keys configured)
- Excluded paths (docs always accessible)
"""

import pytest
import os
import sys
from unittest.mock import patch

# Add the api directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'api'))


# =============================================================================
# Auth Module Unit Tests
# =============================================================================

class TestAuthConfiguration:
    """Test auth configuration and key management."""

    def test_get_configured_keys_single_key(self):
        """Test getting configured keys with single key."""
        with patch.dict(os.environ, {
            "USECVISLIB_API_KEY": "test-key-123",
            "USECVISLIB_API_KEYS": ""
        }, clear=False):
            # Need to reload the module to pick up new env vars
            import importlib
            import api.auth as auth_module
            importlib.reload(auth_module)

            keys = auth_module.get_configured_keys()
            assert "test-key-123" in keys
            assert len(keys) == 1

    def test_get_configured_keys_multiple_keys(self):
        """Test getting configured keys with multiple keys."""
        with patch.dict(os.environ, {
            "USECVISLIB_API_KEY": "",
            "USECVISLIB_API_KEYS": "key1,key2,key3"
        }, clear=False):
            import importlib
            import api.auth as auth_module
            importlib.reload(auth_module)

            keys = auth_module.get_configured_keys()
            assert "key1" in keys
            assert "key2" in keys
            assert "key3" in keys
            assert len(keys) == 3

    def test_get_configured_keys_combined(self):
        """Test keys from both env vars are combined."""
        with patch.dict(os.environ, {
            "USECVISLIB_API_KEY": "single-key",
            "USECVISLIB_API_KEYS": "key1,key2"
        }, clear=False):
            import importlib
            import api.auth as auth_module
            importlib.reload(auth_module)

            keys = auth_module.get_configured_keys()
            assert "single-key" in keys
            assert "key1" in keys
            assert "key2" in keys
            assert len(keys) == 3

    def test_get_configured_keys_no_duplicates(self):
        """Test that duplicate keys are handled."""
        with patch.dict(os.environ, {
            "USECVISLIB_API_KEY": "same-key",
            "USECVISLIB_API_KEYS": "same-key,other-key"
        }, clear=False):
            import importlib
            import api.auth as auth_module
            importlib.reload(auth_module)

            keys = auth_module.get_configured_keys()
            # same-key should only appear once
            assert keys.count("same-key") == 1
            assert "other-key" in keys

    def test_generate_example_key_format(self):
        """Test that generated keys have correct format."""
        import api.auth as auth_module

        key = auth_module.generate_example_key()
        assert key.startswith("usecvis_")
        assert len(key) > 20  # Should be reasonably long

    def test_generate_example_key_uniqueness(self):
        """Test that generated keys are unique."""
        import api.auth as auth_module

        keys = [auth_module.generate_example_key() for _ in range(10)]
        assert len(set(keys)) == 10  # All should be unique


class TestStartupValidation:
    """Test startup configuration validation."""

    def test_validate_auth_disabled(self, capsys):
        """Test validation passes when auth is disabled."""
        with patch.dict(os.environ, {
            "USECVISLIB_AUTH_ENABLED": "false",
            "USECVISLIB_API_KEY": "",
            "USECVISLIB_API_KEYS": ""
        }, clear=False):
            import importlib
            import api.auth as auth_module
            importlib.reload(auth_module)

            # Should not raise
            auth_module.validate_auth_config()

    def test_validate_auth_enabled_with_key(self):
        """Test validation passes when auth enabled with key."""
        with patch.dict(os.environ, {
            "USECVISLIB_AUTH_ENABLED": "true",
            "USECVISLIB_API_KEY": "valid-key",
            "USECVISLIB_API_KEYS": ""
        }, clear=False):
            import importlib
            import api.auth as auth_module
            importlib.reload(auth_module)

            # Should not raise
            auth_module.validate_auth_config()

    def test_validate_auth_enabled_without_key_fails(self):
        """Test validation fails when auth enabled but no keys."""
        with patch.dict(os.environ, {
            "USECVISLIB_AUTH_ENABLED": "true",
            "USECVISLIB_API_KEY": "",
            "USECVISLIB_API_KEYS": ""
        }, clear=False):
            import importlib
            import api.auth as auth_module
            importlib.reload(auth_module)

            with pytest.raises(SystemExit) as exc_info:
                auth_module.validate_auth_config()
            assert exc_info.value.code == 1


# =============================================================================
# API Integration Tests - Auth Disabled
# =============================================================================

class TestAuthDisabled:
    """Test API behavior with authentication disabled."""

    @pytest.fixture(autouse=True)
    def setup_auth_disabled(self):
        """Set up auth disabled environment."""
        with patch.dict(os.environ, {
            "USECVISLIB_AUTH_ENABLED": "false",
            "USECVISLIB_API_KEY": "",
            "USECVISLIB_API_KEYS": ""
        }, clear=False):
            # Reload modules to pick up env changes
            import importlib
            import api.auth
            import api.main
            importlib.reload(api.auth)
            importlib.reload(api.main)

            from fastapi.testclient import TestClient
            from api.main import app
            self.client = TestClient(app)
            yield

    def test_health_without_key(self):
        """Health endpoint accessible without key when auth disabled."""
        response = self.client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"

    def test_styles_without_key(self):
        """Styles endpoint accessible without key when auth disabled."""
        response = self.client.get("/styles")
        assert response.status_code == 200

    def test_docs_accessible(self):
        """Docs endpoint always accessible."""
        response = self.client.get("/docs")
        assert response.status_code == 200


# =============================================================================
# API Integration Tests - Auth Enabled
# =============================================================================

class TestAuthEnabled:
    """Test API behavior with authentication enabled."""

    @pytest.fixture(autouse=True)
    def setup_auth_enabled(self):
        """Set up auth enabled environment with test key."""
        with patch.dict(os.environ, {
            "USECVISLIB_AUTH_ENABLED": "true",
            "USECVISLIB_API_KEY": "test-api-key-12345",
            "USECVISLIB_API_KEYS": ""
        }, clear=False):
            # Reload modules to pick up env changes
            import importlib
            import api.auth
            import api.main
            importlib.reload(api.auth)
            importlib.reload(api.main)

            from fastapi.testclient import TestClient
            from api.main import app
            self.client = TestClient(app)
            self.valid_key = "test-api-key-12345"
            yield

    def test_health_without_key_returns_401(self):
        """Health endpoint returns 401 without key when auth enabled."""
        response = self.client.get("/health")
        assert response.status_code == 401
        data = response.json()
        assert "Missing API key" in data["detail"]

    def test_health_with_invalid_key_returns_401(self):
        """Health endpoint returns 401 with invalid key."""
        response = self.client.get(
            "/health",
            headers={"X-API-Key": "wrong-key"}
        )
        assert response.status_code == 401
        data = response.json()
        assert "Invalid API key" in data["detail"]

    def test_health_with_valid_key_returns_200(self):
        """Health endpoint returns 200 with valid key."""
        response = self.client.get(
            "/health",
            headers={"X-API-Key": self.valid_key}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"

    def test_styles_with_valid_key(self):
        """Styles endpoint works with valid key."""
        response = self.client.get(
            "/styles",
            headers={"X-API-Key": self.valid_key}
        )
        assert response.status_code == 200

    def test_docs_accessible_without_key(self):
        """Docs endpoint accessible without key even when auth enabled."""
        response = self.client.get("/docs")
        assert response.status_code == 200

    def test_openapi_accessible_without_key(self):
        """OpenAPI schema accessible without key."""
        response = self.client.get("/openapi.json")
        assert response.status_code == 200

    def test_redoc_accessible_without_key(self):
        """ReDoc accessible without key."""
        response = self.client.get("/redoc")
        assert response.status_code == 200

    def test_icons_list_accessible_without_key(self):
        """Icons list endpoint accessible without key (needed for gallery)."""
        response = self.client.get("/icons")
        assert response.status_code == 200

    def test_icons_categories_accessible_without_key(self):
        """Icons categories endpoint accessible without key (needed for gallery)."""
        response = self.client.get("/icons/categories")
        assert response.status_code == 200

    def test_icon_file_accessible_without_key(self):
        """Icon file serving accessible without key (<img> tags can't pass headers)."""
        # Request any icon path - even if file doesn't exist, should get 404 not 401
        response = self.client.get("/icons/test/nonexistent")
        # Should be 404 (not found) not 401 (unauthorized)
        assert response.status_code != 401


# =============================================================================
# Multiple Keys Tests
# =============================================================================

class TestMultipleKeys:
    """Test multiple API keys support."""

    @pytest.fixture(autouse=True)
    def setup_multiple_keys(self):
        """Set up auth with multiple keys."""
        with patch.dict(os.environ, {
            "USECVISLIB_AUTH_ENABLED": "true",
            "USECVISLIB_API_KEY": "",
            "USECVISLIB_API_KEYS": "key-alpha,key-beta,key-gamma"
        }, clear=False):
            import importlib
            import api.auth
            import api.main
            importlib.reload(api.auth)
            importlib.reload(api.main)

            from fastapi.testclient import TestClient
            from api.main import app
            self.client = TestClient(app)
            yield

    def test_first_key_works(self):
        """First configured key should work."""
        response = self.client.get(
            "/health",
            headers={"X-API-Key": "key-alpha"}
        )
        assert response.status_code == 200

    def test_second_key_works(self):
        """Second configured key should work."""
        response = self.client.get(
            "/health",
            headers={"X-API-Key": "key-beta"}
        )
        assert response.status_code == 200

    def test_third_key_works(self):
        """Third configured key should work."""
        response = self.client.get(
            "/health",
            headers={"X-API-Key": "key-gamma"}
        )
        assert response.status_code == 200

    def test_unlisted_key_fails(self):
        """Key not in the list should fail."""
        response = self.client.get(
            "/health",
            headers={"X-API-Key": "key-delta"}
        )
        assert response.status_code == 401


# =============================================================================
# Security Tests
# =============================================================================

class TestSecurityFeatures:
    """Test security-related features."""

    @pytest.fixture(autouse=True)
    def setup_auth(self):
        """Set up auth enabled environment."""
        with patch.dict(os.environ, {
            "USECVISLIB_AUTH_ENABLED": "true",
            "USECVISLIB_API_KEY": "secure-test-key",
            "USECVISLIB_API_KEYS": ""
        }, clear=False):
            import importlib
            import api.auth
            import api.main
            importlib.reload(api.auth)
            importlib.reload(api.main)

            from fastapi.testclient import TestClient
            from api.main import app
            self.client = TestClient(app)
            yield

    def test_401_includes_www_authenticate_header(self):
        """401 response should include WWW-Authenticate header."""
        response = self.client.get("/health")
        assert response.status_code == 401
        assert "WWW-Authenticate" in response.headers

    def test_error_message_doesnt_reveal_valid_keys(self):
        """Error messages should not reveal valid keys."""
        response = self.client.get(
            "/health",
            headers={"X-API-Key": "wrong-key"}
        )
        assert response.status_code == 401
        data = response.json()
        # Should not contain the actual key
        assert "secure-test-key" not in data["detail"]
        assert "secure-test-key" not in str(response.headers)

    def test_empty_key_rejected(self):
        """Empty API key should be rejected."""
        response = self.client.get(
            "/health",
            headers={"X-API-Key": ""}
        )
        assert response.status_code == 401

    def test_whitespace_key_rejected(self):
        """Whitespace-only API key should be rejected."""
        response = self.client.get(
            "/health",
            headers={"X-API-Key": "   "}
        )
        assert response.status_code == 401


# =============================================================================
# OpenAPI Schema Tests
# =============================================================================

class TestOpenAPISchema:
    """Test OpenAPI schema includes security information."""

    @pytest.fixture(autouse=True)
    def setup_auth(self):
        """Set up auth enabled environment."""
        with patch.dict(os.environ, {
            "USECVISLIB_AUTH_ENABLED": "true",
            "USECVISLIB_API_KEY": "test-key",
            "USECVISLIB_API_KEYS": ""
        }, clear=False):
            import importlib
            import api.auth
            import api.main
            importlib.reload(api.auth)
            # Reset openapi schema cache
            api.main.app.openapi_schema = None
            importlib.reload(api.main)

            from fastapi.testclient import TestClient
            from api.main import app
            self.client = TestClient(app)
            yield

    def test_openapi_has_security_scheme(self):
        """OpenAPI schema should include security scheme when auth enabled."""
        response = self.client.get("/openapi.json")
        assert response.status_code == 200

        data = response.json()
        assert "components" in data
        assert "securitySchemes" in data["components"]
        assert "ApiKeyAuth" in data["components"]["securitySchemes"]

    def test_security_scheme_is_api_key_type(self):
        """Security scheme should be apiKey type in header."""
        response = self.client.get("/openapi.json")
        data = response.json()

        scheme = data["components"]["securitySchemes"]["ApiKeyAuth"]
        assert scheme["type"] == "apiKey"
        assert scheme["in"] == "header"
        assert scheme["name"] == "X-API-Key"

    def test_global_security_applied(self):
        """Global security should be applied to schema."""
        response = self.client.get("/openapi.json")
        data = response.json()

        assert "security" in data
        assert {"ApiKeyAuth": []} in data["security"]
