#
# VULNEX -Universal Security Visualization Library-
#
# File: cvss_unified.py
# Author: Simon Roses Femerling
# Created: 2025-01-15
# Last Modified: 2025-01-15
# Version: 0.4.0
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Unified CVSS interface supporting both CVSS 3.1 and 4.0.

This module provides a version-agnostic interface for parsing and calculating
CVSS scores. It automatically detects the CVSS version from the vector string
prefix and routes to the appropriate implementation.

Example:
    >>> from usecvislib.cvss_unified import parse_vector, calculate_score
    >>> # Works with both versions
    >>> vector_31 = parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    >>> vector_40 = parse_vector("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
"""

from typing import Union, Optional, Tuple, Any
import re

from .cvss import (
    CVSSVector,
    parse_cvss_vector,
    calculate_cvss_from_vector as calculate_cvss31_from_vector,
    validate_cvss_vector as validate_cvss31_vector,
)
from .cvss4 import (
    CVSSVector4,
    parse_cvss4_vector,
    calculate_cvss4_from_vector,
    validate_cvss4_vector,
)


# Type alias for any CVSS vector
CVSSVectorType = Union[CVSSVector, CVSSVector4]


def detect_cvss_version(vector_string: str) -> Optional[str]:
    """Detect CVSS version from vector string prefix.

    Args:
        vector_string: CVSS vector string

    Returns:
        Version string ("3.0", "3.1", or "4.0") or None if unrecognized
    """
    if not vector_string:
        return None

    vector_upper = vector_string.strip().upper()

    if vector_upper.startswith("CVSS:4.0/"):
        return "4.0"
    elif vector_upper.startswith("CVSS:3.1/"):
        return "3.1"
    elif vector_upper.startswith("CVSS:3.0/"):
        return "3.0"

    return None


def parse_vector(vector_string: str) -> Tuple[bool, Optional[CVSSVectorType], Optional[str]]:
    """Parse a CVSS vector string (auto-detects version).

    This function automatically detects whether the vector is CVSS 3.x or 4.0
    and routes to the appropriate parser.

    Args:
        vector_string: CVSS vector string (3.0, 3.1, or 4.0 format)

    Returns:
        Tuple of (success, parsed_vector, error_message)
        - success: True if parsing succeeded
        - parsed_vector: CVSSVector (3.x) or CVSSVector4 (4.0) if successful
        - error_message: Error description if failed

    Example:
        >>> success, vector, error = parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        >>> if success:
        ...     print(f"Score: {vector.calculate_score()}")
    """
    if not vector_string:
        return False, None, "Empty vector string"

    version = detect_cvss_version(vector_string)

    if version == "4.0":
        return parse_cvss4_vector(vector_string)
    elif version in ("3.0", "3.1"):
        return parse_cvss_vector(vector_string)
    else:
        return False, None, f"Unrecognized CVSS version in vector: {vector_string}"


def calculate_score(vector: CVSSVectorType) -> float:
    """Calculate CVSS score from a parsed vector.

    Args:
        vector: Parsed CVSS vector (CVSSVector or CVSSVector4)

    Returns:
        CVSS score (0.0 - 10.0)
    """
    return vector.calculate_score()


def calculate_score_from_vector(vector_string: str) -> Tuple[bool, Optional[float], Optional[str]]:
    """Calculate CVSS score from a vector string (auto-detects version).

    Args:
        vector_string: CVSS vector string

    Returns:
        Tuple of (success, score, error_message)

    Example:
        >>> success, score, error = calculate_score_from_vector(
        ...     "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
        >>> print(score)
        9.3
    """
    if not vector_string:
        return False, None, "Empty vector string"

    version = detect_cvss_version(vector_string)

    if version == "4.0":
        return calculate_cvss4_from_vector(vector_string)
    elif version in ("3.0", "3.1"):
        return calculate_cvss31_from_vector(vector_string)
    else:
        return False, None, f"Unrecognized CVSS version in vector: {vector_string}"


def validate_vector(vector_string: str) -> Tuple[bool, Optional[str]]:
    """Validate a CVSS vector string (auto-detects version).

    Args:
        vector_string: CVSS vector string to validate

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not vector_string:
        return False, "Empty vector string"

    version = detect_cvss_version(vector_string)

    if version == "4.0":
        return validate_cvss4_vector(vector_string)
    elif version in ("3.0", "3.1"):
        return validate_cvss31_vector(vector_string)
    else:
        return False, f"Unrecognized CVSS version in vector: {vector_string}"


def get_cvss_score_unified(
    cvss_value: Any,
    cvss_vector: Optional[str] = None
) -> Tuple[Optional[float], Optional[str]]:
    """Get CVSS score from either a numeric value or vector string (any version).

    This is the main entry point for CVSS score resolution. It handles:
    - Numeric CVSS scores (0.0-10.0)
    - CVSS 3.x vector strings
    - CVSS 4.0 vector strings
    - Both provided (vector takes precedence for calculation)

    Args:
        cvss_value: Numeric CVSS score or None
        cvss_vector: CVSS vector string (any version) or None

    Returns:
        Tuple of (score, error_message)
        - score: The CVSS score (0.0-10.0) or None if invalid
        - error_message: Error description if invalid, None otherwise

    Example:
        >>> score, error = get_cvss_score_unified(None,
        ...     "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
        >>> print(score)
        9.3
    """
    # If vector is provided, use it
    if cvss_vector:
        success, score, error = calculate_score_from_vector(cvss_vector)
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


def get_vector_version(vector: CVSSVectorType) -> str:
    """Get the CVSS version of a parsed vector.

    Args:
        vector: Parsed CVSS vector

    Returns:
        Version string ("3.0", "3.1", or "4.0")
    """
    if isinstance(vector, CVSSVector4):
        return "4.0"
    elif isinstance(vector, CVSSVector):
        return vector.version.value
    else:
        return "unknown"


def is_cvss4_vector(vector_string: str) -> bool:
    """Check if a vector string is CVSS 4.0 format.

    Args:
        vector_string: CVSS vector string

    Returns:
        True if CVSS 4.0, False otherwise
    """
    return detect_cvss_version(vector_string) == "4.0"


def is_cvss3_vector(vector_string: str) -> bool:
    """Check if a vector string is CVSS 3.x format.

    Args:
        vector_string: CVSS vector string

    Returns:
        True if CVSS 3.0 or 3.1, False otherwise
    """
    version = detect_cvss_version(vector_string)
    return version in ("3.0", "3.1")
