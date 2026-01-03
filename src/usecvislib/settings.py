#
# VULNEX -Universal Security Visualization Library-
#
# File: settings.py
# Author: Simon Roses Femerling
# Created: 2025-12-26
# Last Modified: 2025-12-26
# Version: 0.3.1
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Settings management for USecVisLib.

This module provides centralized management of display settings,
particularly for CVSS visibility in different visualization types.
"""

from copy import deepcopy
from typing import Any, Dict, Optional

from .constants import DEFAULT_CVSS_DISPLAY, VisualizationType


class DisplaySettings:
    """Manager for visualization display settings.

    Handles CVSS display toggles for different visualization types.
    Settings can be toggled globally or per visualization type.
    """

    _instance: Optional['DisplaySettings'] = None

    def __new__(cls) -> 'DisplaySettings':
        """Singleton pattern to ensure consistent settings across modules."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self) -> None:
        """Initialize settings with defaults."""
        if self._initialized:
            return
        self._cvss_display: Dict[str, bool] = deepcopy(DEFAULT_CVSS_DISPLAY)
        self._initialized = True

    def reset(self) -> None:
        """Reset all settings to defaults."""
        self._cvss_display = deepcopy(DEFAULT_CVSS_DISPLAY)

    # CVSS Display Settings

    def get_cvss_display(self) -> Dict[str, bool]:
        """Get all CVSS display settings.

        Returns:
            Dictionary with CVSS display settings for each visualization type.
        """
        return deepcopy(self._cvss_display)

    def set_cvss_display(self, settings: Dict[str, bool]) -> None:
        """Update CVSS display settings.

        Args:
            settings: Dictionary with settings to update. Can include:
                - enabled: Global CVSS toggle
                - attack_tree: CVSS for attack trees
                - attack_graph: CVSS for attack graphs
                - threat_model: CVSS for threat models
        """
        for key, value in settings.items():
            if key in self._cvss_display:
                self._cvss_display[key] = bool(value)

    def is_cvss_enabled(self, viz_type: Optional[str] = None) -> bool:
        """Check if CVSS display is enabled for a visualization type.

        Args:
            viz_type: Visualization type to check. If None, returns global setting.
                      Valid values: 'attack_tree', 'attack_graph', 'threat_model'

        Returns:
            True if CVSS should be displayed, False otherwise.
        """
        # Global toggle must be enabled
        if not self._cvss_display.get("enabled", True):
            return False

        # If no specific type, just return global
        if viz_type is None:
            return True

        # Normalize viz_type
        viz_type = viz_type.lower().replace("-", "_")

        # Check type-specific setting
        return self._cvss_display.get(viz_type, True)

    def set_cvss_enabled(
        self,
        enabled: bool,
        viz_type: Optional[str] = None
    ) -> None:
        """Enable or disable CVSS display.

        Args:
            enabled: Whether to enable CVSS display.
            viz_type: Specific visualization type, or None for global setting.
        """
        if viz_type is None:
            self._cvss_display["enabled"] = enabled
        else:
            viz_type = viz_type.lower().replace("-", "_")
            if viz_type in self._cvss_display:
                self._cvss_display[viz_type] = enabled

    def enable_cvss_all(self) -> None:
        """Enable CVSS display for all visualization types."""
        for key in self._cvss_display:
            self._cvss_display[key] = True

    def disable_cvss_all(self) -> None:
        """Disable CVSS display for all visualization types."""
        for key in self._cvss_display:
            self._cvss_display[key] = False

    def to_dict(self) -> Dict[str, Any]:
        """Export all settings as a dictionary.

        Returns:
            Dictionary containing all display settings.
        """
        return {
            "cvss_display": deepcopy(self._cvss_display),
        }

    def from_dict(self, data: Dict[str, Any]) -> None:
        """Import settings from a dictionary.

        Args:
            data: Dictionary containing settings to import.
        """
        if "cvss_display" in data:
            self.set_cvss_display(data["cvss_display"])


# Global settings instance
_settings = DisplaySettings()


def get_settings() -> DisplaySettings:
    """Get the global settings instance.

    Returns:
        The global DisplaySettings singleton instance.
    """
    return _settings


def is_cvss_enabled(viz_type: Optional[str] = None) -> bool:
    """Convenience function to check if CVSS is enabled.

    Args:
        viz_type: Visualization type to check, or None for global.

    Returns:
        True if CVSS should be displayed.
    """
    return _settings.is_cvss_enabled(viz_type)


def get_cvss_display_settings() -> Dict[str, bool]:
    """Convenience function to get CVSS display settings.

    Returns:
        Dictionary with CVSS display settings.
    """
    return _settings.get_cvss_display()


def set_cvss_display_settings(settings: Dict[str, bool]) -> None:
    """Convenience function to update CVSS display settings.

    Args:
        settings: Dictionary with settings to update.
    """
    _settings.set_cvss_display(settings)
