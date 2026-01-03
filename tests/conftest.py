#
# VULNEX -Universal Security Visualization Library-
#
# File: conftest.py
# Author: Claude Code
# Created: 2025-12-30
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
#

"""Pytest configuration for test suite.

This module provides shared fixtures and configuration for all tests.
It must be loaded before any test modules to ensure proper environment setup.
"""

import os
import pytest

# =============================================================================
# Environment Setup
# =============================================================================

# Set auth disabled by default for tests (individual tests can override)
# This must happen before any imports of the API module
os.environ.setdefault("USECVISLIB_AUTH_ENABLED", "false")


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture(scope="session")
def auth_disabled():
    """Fixture that ensures auth is disabled for the session."""
    original = os.environ.get("USECVISLIB_AUTH_ENABLED")
    os.environ["USECVISLIB_AUTH_ENABLED"] = "false"
    yield
    if original is not None:
        os.environ["USECVISLIB_AUTH_ENABLED"] = original
    else:
        os.environ.pop("USECVISLIB_AUTH_ENABLED", None)


@pytest.fixture
def auth_enabled():
    """Fixture that enables auth for a specific test."""
    original = os.environ.get("USECVISLIB_AUTH_ENABLED")
    os.environ["USECVISLIB_AUTH_ENABLED"] = "true"
    yield
    if original is not None:
        os.environ["USECVISLIB_AUTH_ENABLED"] = original
    else:
        os.environ.pop("USECVISLIB_AUTH_ENABLED", None)
