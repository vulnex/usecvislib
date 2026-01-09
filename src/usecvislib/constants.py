#
# VULNEX -Universal Security Visualization Library-
#
# File: constants.py
# Author: Simon Roses Femerling
# Created: 2025-12-25
# Last Modified: 2025-12-25
# Version: 0.3.1
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Constants and enumerations for USecVisLib.

This module provides centralized constants, enumerations, and default
values used throughout the library.
"""

from enum import Enum, auto
from typing import Any, Dict, List, Optional, Set, Tuple


class OutputFormat(str, Enum):
    """Supported output formats for visualizations."""
    PNG = "png"
    PDF = "pdf"
    SVG = "svg"
    DOT = "dot"

    @classmethod
    def values(cls) -> List[str]:
        """Get all format values as a list."""
        return [f.value for f in cls]

    @classmethod
    def from_string(cls, value: str) -> 'OutputFormat':
        """Convert string to OutputFormat enum.

        Args:
            value: Format string (case-insensitive).

        Returns:
            OutputFormat enum value.

        Raises:
            ValueError: If format is not supported.
        """
        value = value.lower()
        for fmt in cls:
            if fmt.value == value:
                return fmt
        raise ValueError(f"Unsupported output format: {value}")


class ConfigFormat(str, Enum):
    """Supported configuration file formats."""
    TOML = "toml"
    JSON = "json"
    YAML = "yaml"
    MERMAID = "mermaid"


class NodeType(str, Enum):
    """Node types for attack graphs."""
    HOST = "host"
    VULNERABILITY = "vulnerability"
    PRIVILEGE = "privilege"
    SERVICE = "service"
    EXPLOIT = "exploit"


class NodeTypePrefix(str, Enum):
    """Node type prefixes for internal identification in attack graphs."""
    HOST = "H"
    VULNERABILITY = "V"
    PRIVILEGE = "P"
    SERVICE = "S"


class GateType(str, Enum):
    """Gate types for attack trees."""
    AND = "AND"
    OR = "OR"


class ElementType(str, Enum):
    """Element types for threat models."""
    PROCESS = "process"
    DATASTORE = "datastore"
    EXTERNAL = "external"
    DATAFLOW = "dataflow"
    BOUNDARY = "boundary"


class STRIDECategory(str, Enum):
    """STRIDE threat categories for threat modeling."""
    SPOOFING = "Spoofing"
    TAMPERING = "Tampering"
    REPUDIATION = "Repudiation"
    INFORMATION_DISCLOSURE = "Information Disclosure"
    DENIAL_OF_SERVICE = "Denial of Service"
    ELEVATION_OF_PRIVILEGE = "Elevation of Privilege"

    @classmethod
    def from_element_type(cls, element_type: ElementType) -> List['STRIDECategory']:
        """Get applicable STRIDE categories for an element type.

        Args:
            element_type: The DFD element type.

        Returns:
            List of applicable STRIDE threat categories.
        """
        mapping = {
            ElementType.EXTERNAL: [cls.SPOOFING, cls.REPUDIATION],
            ElementType.PROCESS: [
                cls.SPOOFING, cls.TAMPERING, cls.REPUDIATION,
                cls.INFORMATION_DISCLOSURE, cls.DENIAL_OF_SERVICE,
                cls.ELEVATION_OF_PRIVILEGE
            ],
            ElementType.DATASTORE: [
                cls.TAMPERING, cls.REPUDIATION,
                cls.INFORMATION_DISCLOSURE, cls.DENIAL_OF_SERVICE
            ],
            ElementType.DATAFLOW: [
                cls.TAMPERING, cls.INFORMATION_DISCLOSURE,
                cls.DENIAL_OF_SERVICE
            ],
        }
        return mapping.get(element_type, [])


class BinaryVisualization(str, Enum):
    """Binary visualization types."""
    ENTROPY = "entropy"
    DISTRIBUTION = "distribution"
    WINDROSE = "windrose"
    HEATMAP = "heatmap"
    ALL = "all"

    @classmethod
    def values(cls) -> List[str]:
        """Get all visualization types as a list."""
        return [v.value for v in cls]


class ThreatModelEngine(str, Enum):
    """Available threat modeling engines."""
    USECVISLIB = "usecvislib"
    PYTM = "pytm"


# File extension mappings
EXTENSION_FORMAT_MAP: Dict[str, ConfigFormat] = {
    ".toml": ConfigFormat.TOML,
    ".tml": ConfigFormat.TOML,
    ".json": ConfigFormat.JSON,
    ".yaml": ConfigFormat.YAML,
    ".yml": ConfigFormat.YAML,
}

# Allowed configuration file extensions
CONFIG_EXTENSIONS: List[str] = ['.toml', '.tml', '.json', '.yaml', '.yml']

# Sensitive system paths that should not be written to
# SECURITY: Comprehensive list of paths that should never be written to
# NOTE: /var/tmp, /tmp, and /private/var/folders are excluded as they are temp dirs
SENSITIVE_PATHS: List[str] = [
    # Core system directories
    '/etc', '/usr', '/bin', '/sbin', '/root', '/boot', '/lib',
    # Linux kernel/process filesystems
    '/proc', '/sys', '/dev',
    # Library directories
    '/lib64', '/lib32',
    # Optional/third-party software
    '/opt',
    # macOS-specific system paths (but not /private/var/folders which is temp)
    '/private/etc', '/System', '/Library',
    # Snap/Flatpak paths
    '/snap',
    # Specific /var subdirectories (not /var itself to allow /var/tmp)
    '/var/log', '/var/run', '/var/lib', '/var/spool', '/var/cache',
    # Specific /private/var subdirectories (not /private/var/folders which is temp)
    '/private/var/log', '/private/var/run', '/private/var/db', '/private/var/root',
]

# Visualization types for settings
class VisualizationType(str, Enum):
    """Visualization types for display settings."""
    ATTACK_TREE = "attack_tree"
    ATTACK_GRAPH = "attack_graph"
    THREAT_MODEL = "threat_model"
    BINVIS = "binvis"

    @classmethod
    def values(cls) -> List[str]:
        """Get all visualization types as a list."""
        return [v.value for v in cls]


# Default CVSS display settings
DEFAULT_CVSS_DISPLAY: Dict[str, bool] = {
    "enabled": True,  # Global toggle
    "attack_tree": True,
    "attack_graph": True,
    "threat_model": True,
}

# Default values
DEFAULTS: Dict[str, any] = {
    "output_format": OutputFormat.PNG,
    "styles": {
        "attack_tree": "at_default",
        "attack_graph": "ag_default",
        "threat_model": "tm_default",
        "binvis": "bv_default",
    },
    "max_file_sizes": {
        "config": 10 * 1024 * 1024,       # 10 MB
        "binary": 100 * 1024 * 1024,      # 100 MB
    },
    "style_files": {
        "attack_tree": "config_attacktrees.tml",
        "attack_graph": "config_attackgraphs.tml",
        "threat_model": "config_threatmodeling.tml",
        "binvis": "config_binvis.tml",
    },
    "cvss_display": DEFAULT_CVSS_DISPLAY,
}

# Default graph attributes
DEFAULT_GRAPH_ATTRS: Dict[str, str] = {
    "fontname": "Arial",
    "fontsize": "12",
    "rankdir": "TB",
    "splines": "true",
    "nodesep": "0.5",
    "ranksep": "0.5",
}

# Default node attributes
DEFAULT_NODE_ATTRS: Dict[str, str] = {
    "fontname": "Arial",
    "fontsize": "10",
    "shape": "box",
    "style": "filled",
}

# Default edge attributes
DEFAULT_EDGE_ATTRS: Dict[str, str] = {
    "fontname": "Arial",
    "fontsize": "9",
}

# Color schemes
COLORS: Dict[str, Dict[str, str]] = {
    "attack_tree": {
        "root": "#e74c3c",
        "node": "#3498db",
        "leaf": "#27ae60",
        "edge": "#34495e",
        "and_gate": "#f39c12",
        "or_gate": "#9b59b6",
    },
    "attack_graph": {
        "host": "#3498db",
        "vulnerability": "#e74c3c",
        "privilege": "#2ecc71",
        "service": "#f39c12",
        "exploit": "#9b59b6",
        "edge": "#34495e",
        "attack_path": "#e74c3c",
    },
    "threat_model": {
        "process": "#3498db",
        "datastore": "#2ecc71",
        "external": "#95a5a6",
        "dataflow": "#34495e",
        "boundary": "#e74c3c",
    },
}

# Risk levels
class RiskLevel(str, Enum):
    """Risk level classifications."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


RISK_COLORS: Dict[RiskLevel, str] = {
    RiskLevel.CRITICAL: "#8b0000",
    RiskLevel.HIGH: "#e74c3c",
    RiskLevel.MEDIUM: "#f39c12",
    RiskLevel.LOW: "#27ae60",
    RiskLevel.INFO: "#3498db",
}

# CVSS score to risk level mapping
def cvss_to_risk_level(cvss_score: float) -> RiskLevel:
    """Convert CVSS score to risk level.

    Args:
        cvss_score: CVSS score (0.0 - 10.0).

    Returns:
        Corresponding risk level.
    """
    if cvss_score >= 9.0:
        return RiskLevel.CRITICAL
    elif cvss_score >= 7.0:
        return RiskLevel.HIGH
    elif cvss_score >= 4.0:
        return RiskLevel.MEDIUM
    elif cvss_score >= 0.1:
        return RiskLevel.LOW
    else:
        return RiskLevel.INFO


def cvss_to_color(cvss_score: float) -> str:
    """Convert CVSS score directly to a color hex code.

    Args:
        cvss_score: CVSS score (0.0 - 10.0).

    Returns:
        Hex color code corresponding to the CVSS severity.
    """
    risk_level = cvss_to_risk_level(cvss_score)
    return RISK_COLORS[risk_level]


def validate_cvss_score(cvss_score: Any) -> Tuple[bool, Optional[float], Optional[str]]:
    """Validate a CVSS score value.

    Args:
        cvss_score: Value to validate (should be a number 0.0-10.0).

    Returns:
        Tuple of (is_valid, normalized_score, error_message).
        - is_valid: True if the score is valid
        - normalized_score: The score as a float if valid, None otherwise
        - error_message: Error description if invalid, None otherwise
    """
    if cvss_score is None:
        return True, None, None  # None is valid (optional field)

    try:
        score = float(cvss_score)
    except (TypeError, ValueError):
        return False, None, f"CVSS score must be a number, got: {type(cvss_score).__name__}"

    if score < 0.0 or score > 10.0:
        return False, None, f"CVSS score must be between 0.0 and 10.0, got: {score}"

    return True, round(score, 1), None


# CVSS severity labels for display
CVSS_SEVERITY_LABELS: Dict[RiskLevel, str] = {
    RiskLevel.CRITICAL: "Critical",
    RiskLevel.HIGH: "High",
    RiskLevel.MEDIUM: "Medium",
    RiskLevel.LOW: "Low",
    RiskLevel.INFO: "None",
}


def cvss_to_severity_label(cvss_score: float) -> str:
    """Convert CVSS score to a human-readable severity label.

    Args:
        cvss_score: CVSS score (0.0 - 10.0).

    Returns:
        Severity label string (Critical, High, Medium, Low, None).
    """
    risk_level = cvss_to_risk_level(cvss_score)
    return CVSS_SEVERITY_LABELS[risk_level]
