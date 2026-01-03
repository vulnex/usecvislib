#
# VULNEX -Universal Security Visualization Library-
#
# File: test_settings.py
# Author: Simon Roses Femerling
# Created: 2025-12-26
# Last Modified: 2025-12-26
# Version: 0.3.1
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Tests for the settings module (CVSS display settings)."""

import pytest
from usecvislib.settings import (
    DisplaySettings,
    get_settings,
    is_cvss_enabled,
    get_cvss_display_settings,
    set_cvss_display_settings,
)


class TestDisplaySettings:
    """Test the DisplaySettings class."""

    def setup_method(self):
        """Reset settings before each test."""
        settings = get_settings()
        settings.reset()

    def teardown_method(self):
        """Reset settings after each test."""
        settings = get_settings()
        settings.reset()

    def test_singleton_pattern(self):
        """Test that DisplaySettings uses singleton pattern."""
        settings1 = DisplaySettings()
        settings2 = DisplaySettings()
        assert settings1 is settings2

    def test_default_cvss_settings(self):
        """Test default CVSS display settings."""
        settings = get_settings()
        cvss = settings.get_cvss_display()

        assert cvss["enabled"] is True
        assert cvss["attack_tree"] is True
        assert cvss["attack_graph"] is True
        assert cvss["threat_model"] is True

    def test_set_cvss_display(self):
        """Test setting CVSS display settings."""
        settings = get_settings()

        settings.set_cvss_display({
            "enabled": False,
            "attack_tree": False,
            "attack_graph": True,
        })

        cvss = settings.get_cvss_display()
        assert cvss["enabled"] is False
        assert cvss["attack_tree"] is False
        assert cvss["attack_graph"] is True
        assert cvss["threat_model"] is True  # Not changed

    def test_is_cvss_enabled_global(self):
        """Test global CVSS enabled check."""
        settings = get_settings()

        assert settings.is_cvss_enabled() is True

        settings.set_cvss_enabled(False)
        assert settings.is_cvss_enabled() is False

    def test_is_cvss_enabled_per_type(self):
        """Test per-type CVSS enabled check."""
        settings = get_settings()

        assert settings.is_cvss_enabled("attack_tree") is True
        assert settings.is_cvss_enabled("attack_graph") is True
        assert settings.is_cvss_enabled("threat_model") is True

        settings.set_cvss_enabled(False, "attack_tree")
        assert settings.is_cvss_enabled("attack_tree") is False
        assert settings.is_cvss_enabled("attack_graph") is True

    def test_global_toggle_overrides_type(self):
        """Test that global toggle overrides type-specific settings."""
        settings = get_settings()

        # Enable attack_tree but disable globally
        settings.set_cvss_enabled(True, "attack_tree")
        settings.set_cvss_enabled(False)  # Global

        # Should be False because global is disabled
        assert settings.is_cvss_enabled("attack_tree") is False

    def test_enable_cvss_all(self):
        """Test enabling CVSS for all types."""
        settings = get_settings()

        # First disable all
        settings.disable_cvss_all()
        assert settings.is_cvss_enabled() is False

        # Enable all
        settings.enable_cvss_all()
        assert settings.is_cvss_enabled() is True
        assert settings.is_cvss_enabled("attack_tree") is True
        assert settings.is_cvss_enabled("attack_graph") is True
        assert settings.is_cvss_enabled("threat_model") is True

    def test_disable_cvss_all(self):
        """Test disabling CVSS for all types."""
        settings = get_settings()

        settings.disable_cvss_all()

        assert settings.is_cvss_enabled() is False
        assert settings.is_cvss_enabled("attack_tree") is False
        assert settings.is_cvss_enabled("attack_graph") is False
        assert settings.is_cvss_enabled("threat_model") is False

    def test_reset(self):
        """Test resetting settings to defaults."""
        settings = get_settings()

        # Modify settings
        settings.disable_cvss_all()
        assert settings.is_cvss_enabled() is False

        # Reset
        settings.reset()

        # Should be back to defaults
        assert settings.is_cvss_enabled() is True
        assert settings.is_cvss_enabled("attack_tree") is True

    def test_to_dict(self):
        """Test exporting settings to dictionary."""
        settings = get_settings()
        data = settings.to_dict()

        assert "cvss_display" in data
        assert data["cvss_display"]["enabled"] is True

    def test_from_dict(self):
        """Test importing settings from dictionary."""
        settings = get_settings()

        settings.from_dict({
            "cvss_display": {
                "enabled": False,
                "attack_tree": False,
            }
        })

        assert settings.is_cvss_enabled() is False
        assert settings.is_cvss_enabled("attack_tree") is False

    def test_normalize_viz_type(self):
        """Test that viz_type is normalized correctly."""
        settings = get_settings()

        # Should handle hyphen and underscore
        assert settings.is_cvss_enabled("attack_tree") is True
        assert settings.is_cvss_enabled("attack-tree") is True

        # Should be case-insensitive
        assert settings.is_cvss_enabled("ATTACK_TREE") is True


class TestConvenienceFunctions:
    """Test the module-level convenience functions."""

    def setup_method(self):
        """Reset settings before each test."""
        settings = get_settings()
        settings.reset()

    def teardown_method(self):
        """Reset settings after each test."""
        settings = get_settings()
        settings.reset()

    def test_is_cvss_enabled_function(self):
        """Test the is_cvss_enabled convenience function."""
        assert is_cvss_enabled() is True
        assert is_cvss_enabled("attack_tree") is True

        set_cvss_display_settings({"enabled": False})
        assert is_cvss_enabled() is False

    def test_get_cvss_display_settings_function(self):
        """Test the get_cvss_display_settings convenience function."""
        settings = get_cvss_display_settings()

        assert isinstance(settings, dict)
        assert "enabled" in settings
        assert settings["enabled"] is True

    def test_set_cvss_display_settings_function(self):
        """Test the set_cvss_display_settings convenience function."""
        set_cvss_display_settings({
            "enabled": False,
            "attack_graph": False,
        })

        settings = get_cvss_display_settings()
        assert settings["enabled"] is False
        assert settings["attack_graph"] is False
        assert settings["attack_tree"] is True  # Not changed


class TestIntegrationWithVisualization:
    """Test that settings integrate correctly with visualization modules."""

    def setup_method(self):
        """Reset settings before each test."""
        settings = get_settings()
        settings.reset()

    def teardown_method(self):
        """Reset settings after each test."""
        settings = get_settings()
        settings.reset()

    def test_attack_tree_respects_settings(self):
        """Test that attack tree module respects CVSS settings."""
        from usecvislib.settings import is_cvss_enabled

        # Initially enabled
        assert is_cvss_enabled("attack_tree") is True

        # Disable for attack trees
        set_cvss_display_settings({"attack_tree": False})
        assert is_cvss_enabled("attack_tree") is False

    def test_attack_graph_respects_settings(self):
        """Test that attack graph module respects CVSS settings."""
        from usecvislib.settings import is_cvss_enabled

        # Initially enabled
        assert is_cvss_enabled("attack_graph") is True

        # Disable for attack graphs
        set_cvss_display_settings({"attack_graph": False})
        assert is_cvss_enabled("attack_graph") is False

    def test_threat_model_respects_settings(self):
        """Test that threat model module respects CVSS settings."""
        from usecvislib.settings import is_cvss_enabled

        # Initially enabled
        assert is_cvss_enabled("threat_model") is True

        # Disable for threat models
        set_cvss_display_settings({"threat_model": False})
        assert is_cvss_enabled("threat_model") is False
