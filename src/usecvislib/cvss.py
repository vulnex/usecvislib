#
# VULNEX -Universal Security Visualization Library-
#
# File: cvss.py
# Author: Simon Roses Femerling
# Created: 2025-12-26
# Last Modified: 2025-12-26
# Version: 0.3.1
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""CVSS (Common Vulnerability Scoring System) support module.

This module provides parsing and calculation for CVSS 3.1 vector strings,
allowing users to specify vulnerability severity using standard CVSS notation.

Example vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
"""

from dataclasses import dataclass
from enum import Enum
from typing import Dict, Optional, Tuple, Any
import re


class CVSSVersion(str, Enum):
    """Supported CVSS versions."""
    V3_0 = "3.0"
    V3_1 = "3.1"


class AttackVector(str, Enum):
    """CVSS Attack Vector (AV) metric."""
    NETWORK = "N"      # 0.85
    ADJACENT = "A"     # 0.62
    LOCAL = "L"        # 0.55
    PHYSICAL = "P"     # 0.20


class AttackComplexity(str, Enum):
    """CVSS Attack Complexity (AC) metric."""
    LOW = "L"          # 0.77
    HIGH = "H"         # 0.44


class PrivilegesRequired(str, Enum):
    """CVSS Privileges Required (PR) metric."""
    NONE = "N"         # 0.85 (unchanged) / 0.85 (changed)
    LOW = "L"          # 0.62 (unchanged) / 0.68 (changed)
    HIGH = "H"         # 0.27 (unchanged) / 0.50 (changed)


class UserInteraction(str, Enum):
    """CVSS User Interaction (UI) metric."""
    NONE = "N"         # 0.85
    REQUIRED = "R"     # 0.62


class Scope(str, Enum):
    """CVSS Scope (S) metric."""
    UNCHANGED = "U"
    CHANGED = "C"


class Impact(str, Enum):
    """CVSS Confidentiality/Integrity/Availability (C/I/A) impact metrics."""
    NONE = "N"         # 0.00
    LOW = "L"          # 0.22
    HIGH = "H"         # 0.56


# Metric value mappings for score calculation
AV_VALUES: Dict[AttackVector, float] = {
    AttackVector.NETWORK: 0.85,
    AttackVector.ADJACENT: 0.62,
    AttackVector.LOCAL: 0.55,
    AttackVector.PHYSICAL: 0.20,
}

AC_VALUES: Dict[AttackComplexity, float] = {
    AttackComplexity.LOW: 0.77,
    AttackComplexity.HIGH: 0.44,
}

# PR values depend on Scope
PR_VALUES_UNCHANGED: Dict[PrivilegesRequired, float] = {
    PrivilegesRequired.NONE: 0.85,
    PrivilegesRequired.LOW: 0.62,
    PrivilegesRequired.HIGH: 0.27,
}

PR_VALUES_CHANGED: Dict[PrivilegesRequired, float] = {
    PrivilegesRequired.NONE: 0.85,
    PrivilegesRequired.LOW: 0.68,
    PrivilegesRequired.HIGH: 0.50,
}

UI_VALUES: Dict[UserInteraction, float] = {
    UserInteraction.NONE: 0.85,
    UserInteraction.REQUIRED: 0.62,
}

IMPACT_VALUES: Dict[Impact, float] = {
    Impact.NONE: 0.00,
    Impact.LOW: 0.22,
    Impact.HIGH: 0.56,
}


@dataclass
class CVSSVector:
    """Parsed CVSS 3.x vector with all metrics.

    Attributes:
        version: CVSS version (3.0 or 3.1)
        attack_vector: Attack Vector (AV) metric
        attack_complexity: Attack Complexity (AC) metric
        privileges_required: Privileges Required (PR) metric
        user_interaction: User Interaction (UI) metric
        scope: Scope (S) metric
        confidentiality: Confidentiality Impact (C) metric
        integrity: Integrity Impact (I) metric
        availability: Availability Impact (A) metric
        raw_string: Original vector string
    """
    version: CVSSVersion
    attack_vector: AttackVector
    attack_complexity: AttackComplexity
    privileges_required: PrivilegesRequired
    user_interaction: UserInteraction
    scope: Scope
    confidentiality: Impact
    integrity: Impact
    availability: Impact
    raw_string: str = ""

    def calculate_score(self) -> float:
        """Calculate the CVSS base score from vector metrics.

        Returns:
            CVSS base score (0.0 - 10.0)
        """
        # Get metric values
        av = AV_VALUES[self.attack_vector]
        ac = AC_VALUES[self.attack_complexity]
        ui = UI_VALUES[self.user_interaction]

        # PR depends on scope
        if self.scope == Scope.CHANGED:
            pr = PR_VALUES_CHANGED[self.privileges_required]
        else:
            pr = PR_VALUES_UNCHANGED[self.privileges_required]

        # Impact values
        c = IMPACT_VALUES[self.confidentiality]
        i = IMPACT_VALUES[self.integrity]
        a = IMPACT_VALUES[self.availability]

        # Calculate Impact Sub Score (ISS)
        iss = 1 - ((1 - c) * (1 - i) * (1 - a))

        # Calculate Impact
        if self.scope == Scope.UNCHANGED:
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * pow(iss - 0.02, 15)

        # Calculate Exploitability
        exploitability = 8.22 * av * ac * pr * ui

        # Calculate Base Score
        if impact <= 0:
            return 0.0

        if self.scope == Scope.UNCHANGED:
            base_score = min(impact + exploitability, 10)
        else:
            base_score = min(1.08 * (impact + exploitability), 10)

        # Round up to 1 decimal place (CVSS spec)
        return self._round_up(base_score)

    @staticmethod
    def _round_up(value: float) -> float:
        """Round up to 1 decimal place per CVSS specification."""
        import math
        return math.ceil(value * 10) / 10

    def to_dict(self) -> Dict[str, Any]:
        """Convert vector to dictionary representation."""
        return {
            "version": self.version.value,
            "vector_string": self.raw_string,
            "attack_vector": self.attack_vector.value,
            "attack_complexity": self.attack_complexity.value,
            "privileges_required": self.privileges_required.value,
            "user_interaction": self.user_interaction.value,
            "scope": self.scope.value,
            "confidentiality": self.confidentiality.value,
            "integrity": self.integrity.value,
            "availability": self.availability.value,
            "base_score": self.calculate_score(),
        }


# Regex pattern for CVSS 3.x vector string
CVSS_VECTOR_PATTERN = re.compile(
    r'^CVSS:(?P<version>3\.[01])/'
    r'AV:(?P<av>[NALP])/'
    r'AC:(?P<ac>[LH])/'
    r'PR:(?P<pr>[NLH])/'
    r'UI:(?P<ui>[NR])/'
    r'S:(?P<s>[UC])/'
    r'C:(?P<c>[NLH])/'
    r'I:(?P<i>[NLH])/'
    r'A:(?P<a>[NLH])$',
    re.IGNORECASE
)


def parse_cvss_vector(vector_string: str) -> Tuple[bool, Optional[CVSSVector], Optional[str]]:
    """Parse a CVSS 3.x vector string.

    Args:
        vector_string: CVSS vector string (e.g., "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

    Returns:
        Tuple of (success, parsed_vector, error_message)
        - success: True if parsing succeeded
        - parsed_vector: CVSSVector object if successful, None otherwise
        - error_message: Error description if failed, None otherwise

    Example:
        >>> success, vector, error = parse_cvss_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        >>> if success:
        ...     print(f"Score: {vector.calculate_score()}")
        Score: 9.8
    """
    if not vector_string:
        return False, None, "Empty vector string"

    # Normalize to uppercase for matching
    vector_upper = vector_string.strip().upper()

    match = CVSS_VECTOR_PATTERN.match(vector_upper)
    if not match:
        return False, None, f"Invalid CVSS vector format: {vector_string}"

    try:
        version = CVSSVersion(match.group('version'))

        vector = CVSSVector(
            version=version,
            attack_vector=AttackVector(match.group('av')),
            attack_complexity=AttackComplexity(match.group('ac')),
            privileges_required=PrivilegesRequired(match.group('pr')),
            user_interaction=UserInteraction(match.group('ui')),
            scope=Scope(match.group('s')),
            confidentiality=Impact(match.group('c')),
            integrity=Impact(match.group('i')),
            availability=Impact(match.group('a')),
            raw_string=vector_string.strip(),
        )

        return True, vector, None

    except ValueError as e:
        return False, None, f"Invalid metric value in vector: {e}"


def calculate_cvss_from_vector(vector_string: str) -> Tuple[bool, Optional[float], Optional[str]]:
    """Calculate CVSS score from a vector string.

    Convenience function that parses a vector and returns the score.

    Args:
        vector_string: CVSS vector string

    Returns:
        Tuple of (success, score, error_message)

    Example:
        >>> success, score, error = calculate_cvss_from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        >>> print(score)
        9.8
    """
    success, vector, error = parse_cvss_vector(vector_string)
    if not success:
        return False, None, error

    return True, vector.calculate_score(), None


def validate_cvss_vector(vector_string: str) -> Tuple[bool, Optional[str]]:
    """Validate a CVSS vector string without calculating score.

    Args:
        vector_string: CVSS vector string to validate

    Returns:
        Tuple of (is_valid, error_message)
    """
    success, _, error = parse_cvss_vector(vector_string)
    return success, error


def get_cvss_score(cvss_value: Any, cvss_vector: Optional[str] = None) -> Tuple[Optional[float], Optional[str]]:
    """Get CVSS score from either a numeric value or vector string.

    This is the main entry point for CVSS score resolution. It handles:
    - Numeric CVSS scores (0.0-10.0)
    - CVSS vector strings (calculated to score)
    - Both provided (vector takes precedence for calculation)

    Args:
        cvss_value: Numeric CVSS score or None
        cvss_vector: CVSS vector string or None

    Returns:
        Tuple of (score, error_message)
        - score: The CVSS score (0.0-10.0) or None if invalid
        - error_message: Error description if invalid, None otherwise

    Example:
        >>> score, error = get_cvss_score(None, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        >>> print(score)
        9.8
        >>> score, error = get_cvss_score(8.5, None)
        >>> print(score)
        8.5
    """
    # If vector is provided, use it
    if cvss_vector:
        success, score, error = calculate_cvss_from_vector(cvss_vector)
        if success:
            return score, None
        return None, error

    # Fall back to numeric value
    if cvss_value is not None:
        try:
            score = float(cvss_value)
            if 0.0 <= score <= 10.0:
                return score, None
            return None, f"CVSS score must be between 0.0 and 10.0, got: {score}"
        except (TypeError, ValueError):
            return None, f"CVSS score must be a number, got: {type(cvss_value).__name__}"

    return None, None  # No CVSS provided (valid case)


# Common CVSS vector examples for reference
CVSS_EXAMPLES = {
    "critical_network_rce": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",  # 10.0
    "high_network_auth": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",     # 8.8
    "medium_local_privesc": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",  # 5.5
    "low_physical_dos": "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:L",      # 1.6
}
