#
# VULNEX -Universal Security Visualization Library-
#
# File: test_cvss.py
# Author: Simon Roses Femerling
# Created: 2025-12-26
# Last Modified: 2025-12-26
# Version: 0.3.1
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Unit tests for the CVSS module."""

import pytest
from src.usecvislib.cvss import (
    CVSSVector,
    CVSSVersion,
    AttackVector,
    AttackComplexity,
    PrivilegesRequired,
    UserInteraction,
    Scope,
    Impact,
    parse_cvss_vector,
    calculate_cvss_from_vector,
    validate_cvss_vector,
    get_cvss_score,
    CVSS_EXAMPLES,
)
from src.usecvislib.constants import (
    cvss_to_color,
    cvss_to_severity_label,
    cvss_to_risk_level,
    validate_cvss_score,
    RiskLevel,
)


class TestCVSSVectorParsing:
    """Tests for CVSS vector string parsing."""

    def test_parse_valid_vector_v31(self):
        """Test parsing a valid CVSS 3.1 vector."""
        vector_str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        success, vector, error = parse_cvss_vector(vector_str)

        assert success is True
        assert error is None
        assert vector is not None
        assert vector.version == CVSSVersion.V3_1
        assert vector.attack_vector == AttackVector.NETWORK
        assert vector.attack_complexity == AttackComplexity.LOW
        assert vector.privileges_required == PrivilegesRequired.NONE
        assert vector.user_interaction == UserInteraction.NONE
        assert vector.scope == Scope.UNCHANGED
        assert vector.confidentiality == Impact.HIGH
        assert vector.integrity == Impact.HIGH
        assert vector.availability == Impact.HIGH

    def test_parse_valid_vector_v30(self):
        """Test parsing a valid CVSS 3.0 vector."""
        vector_str = "CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:C/C:L/I:L/A:N"
        success, vector, error = parse_cvss_vector(vector_str)

        assert success is True
        assert error is None
        assert vector.version == CVSSVersion.V3_0
        assert vector.attack_vector == AttackVector.LOCAL
        assert vector.attack_complexity == AttackComplexity.HIGH
        assert vector.privileges_required == PrivilegesRequired.HIGH
        assert vector.user_interaction == UserInteraction.REQUIRED
        assert vector.scope == Scope.CHANGED
        assert vector.confidentiality == Impact.LOW
        assert vector.integrity == Impact.LOW
        assert vector.availability == Impact.NONE

    def test_parse_case_insensitive(self):
        """Test that parsing is case insensitive."""
        vector_str = "cvss:3.1/av:n/ac:l/pr:n/ui:n/s:u/c:h/i:h/a:h"
        success, vector, error = parse_cvss_vector(vector_str)

        assert success is True
        assert vector.attack_vector == AttackVector.NETWORK

    def test_parse_invalid_format(self):
        """Test parsing an invalid vector format."""
        invalid_vectors = [
            "invalid",
            "CVSS:3.1",
            "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # Invalid AV
            "CVSS:2.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # Invalid version
            "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # Missing CVSS prefix
            "",
            None,
        ]

        for vec in invalid_vectors:
            success, vector, error = parse_cvss_vector(vec)
            assert success is False, f"Expected failure for: {vec}"
            assert vector is None
            assert error is not None

    def test_parse_all_attack_vectors(self):
        """Test all attack vector values."""
        base = "CVSS:3.1/AV:{}/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

        for av_value, expected in [("N", AttackVector.NETWORK),
                                    ("A", AttackVector.ADJACENT),
                                    ("L", AttackVector.LOCAL),
                                    ("P", AttackVector.PHYSICAL)]:
            success, vector, _ = parse_cvss_vector(base.format(av_value))
            assert success is True
            assert vector.attack_vector == expected


class TestCVSSScoreCalculation:
    """Tests for CVSS score calculation."""

    def test_calculate_critical_score(self):
        """Test calculation of a critical (10.0) score."""
        vector_str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
        success, score, error = calculate_cvss_from_vector(vector_str)

        assert success is True
        assert score == 10.0

    def test_calculate_high_score(self):
        """Test calculation of a high score."""
        vector_str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        success, score, error = calculate_cvss_from_vector(vector_str)

        assert success is True
        assert score == 9.8

    def test_calculate_medium_score(self):
        """Test calculation of a medium score."""
        vector_str = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
        success, score, error = calculate_cvss_from_vector(vector_str)

        assert success is True
        assert 4.0 <= score < 7.0

    def test_calculate_low_score(self):
        """Test calculation of a low score."""
        vector_str = "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:L"
        success, score, error = calculate_cvss_from_vector(vector_str)

        assert success is True
        assert score < 4.0

    def test_calculate_zero_impact(self):
        """Test that zero impact results in 0.0 score."""
        vector_str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
        success, score, error = calculate_cvss_from_vector(vector_str)

        assert success is True
        assert score == 0.0

    def test_scope_changed_affects_score(self):
        """Test that scope change affects score calculation."""
        unchanged = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
        changed = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"

        _, score_unchanged, _ = calculate_cvss_from_vector(unchanged)
        _, score_changed, _ = calculate_cvss_from_vector(changed)

        # Changed scope should result in higher score
        assert score_changed > score_unchanged

    def test_known_cvss_examples(self):
        """Test known CVSS example vectors."""
        expected_scores = {
            "critical_network_rce": 10.0,
            "high_network_auth": 8.8,
            "medium_local_privesc": 5.5,
        }

        for name, expected in expected_scores.items():
            vector = CVSS_EXAMPLES[name]
            success, score, _ = calculate_cvss_from_vector(vector)
            assert success is True
            assert score == expected, f"{name}: expected {expected}, got {score}"


class TestCVSSValidation:
    """Tests for CVSS validation functions."""

    def test_validate_valid_vector(self):
        """Test validation of valid vectors."""
        valid_vectors = [
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:C/C:L/I:L/A:N",
        ]

        for vec in valid_vectors:
            is_valid, error = validate_cvss_vector(vec)
            assert is_valid is True
            assert error is None

    def test_validate_invalid_vector(self):
        """Test validation of invalid vectors."""
        is_valid, error = validate_cvss_vector("invalid_vector")
        assert is_valid is False
        assert error is not None

    def test_validate_cvss_score_valid(self):
        """Test validation of valid numeric CVSS scores."""
        valid_scores = [0.0, 0.1, 5.5, 7.5, 9.9, 10.0]

        for score in valid_scores:
            is_valid, normalized, error = validate_cvss_score(score)
            assert is_valid is True
            assert error is None

    def test_validate_cvss_score_invalid(self):
        """Test validation of invalid numeric CVSS scores."""
        invalid_scores = [-1.0, -0.1, 10.1, 15.0, 100]

        for score in invalid_scores:
            is_valid, normalized, error = validate_cvss_score(score)
            assert is_valid is False
            assert error is not None

    def test_validate_cvss_score_none(self):
        """Test that None is valid (optional field)."""
        is_valid, normalized, error = validate_cvss_score(None)
        assert is_valid is True
        assert normalized is None
        assert error is None

    def test_validate_cvss_score_invalid_type(self):
        """Test validation of invalid types."""
        invalid_types = ["high", "critical", [], {}]

        for val in invalid_types:
            is_valid, normalized, error = validate_cvss_score(val)
            assert is_valid is False
            assert error is not None


class TestGetCVSSScore:
    """Tests for the get_cvss_score function."""

    def test_numeric_score_only(self):
        """Test with numeric score only."""
        score, error = get_cvss_score(8.5, None)
        assert score == 8.5
        assert error is None

    def test_vector_only(self):
        """Test with vector string only."""
        score, error = get_cvss_score(None, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert score == 9.8
        assert error is None

    def test_both_provided_vector_precedence(self):
        """Test that vector takes precedence when both provided."""
        score, error = get_cvss_score(5.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        # Vector should be used, resulting in 9.8, not 5.0
        assert score == 9.8
        assert error is None

    def test_neither_provided(self):
        """Test with neither value provided."""
        score, error = get_cvss_score(None, None)
        assert score is None
        assert error is None  # Valid case - no CVSS

    def test_invalid_numeric(self):
        """Test with invalid numeric score."""
        score, error = get_cvss_score(15.0, None)
        assert score is None
        assert error is not None

    def test_invalid_vector(self):
        """Test with invalid vector."""
        score, error = get_cvss_score(None, "invalid")
        assert score is None
        assert error is not None


class TestCVSSColorAndLabels:
    """Tests for CVSS color coding and severity labels."""

    def test_cvss_to_color(self):
        """Test color mapping for CVSS scores."""
        # Critical
        assert cvss_to_color(10.0) == "#8b0000"
        assert cvss_to_color(9.0) == "#8b0000"

        # High
        assert cvss_to_color(8.9) == "#e74c3c"
        assert cvss_to_color(7.0) == "#e74c3c"

        # Medium
        assert cvss_to_color(6.9) == "#f39c12"
        assert cvss_to_color(4.0) == "#f39c12"

        # Low
        assert cvss_to_color(3.9) == "#27ae60"
        assert cvss_to_color(0.1) == "#27ae60"

        # None/Info
        assert cvss_to_color(0.0) == "#3498db"

    def test_cvss_to_severity_label(self):
        """Test severity label mapping."""
        assert cvss_to_severity_label(10.0) == "Critical"
        assert cvss_to_severity_label(9.0) == "Critical"
        assert cvss_to_severity_label(8.5) == "High"
        assert cvss_to_severity_label(7.0) == "High"
        assert cvss_to_severity_label(5.0) == "Medium"
        assert cvss_to_severity_label(4.0) == "Medium"
        assert cvss_to_severity_label(2.0) == "Low"
        assert cvss_to_severity_label(0.1) == "Low"
        assert cvss_to_severity_label(0.0) == "None"

    def test_cvss_to_risk_level(self):
        """Test risk level mapping."""
        assert cvss_to_risk_level(10.0) == RiskLevel.CRITICAL
        assert cvss_to_risk_level(9.0) == RiskLevel.CRITICAL
        assert cvss_to_risk_level(7.5) == RiskLevel.HIGH
        assert cvss_to_risk_level(5.0) == RiskLevel.MEDIUM
        assert cvss_to_risk_level(2.0) == RiskLevel.LOW
        assert cvss_to_risk_level(0.0) == RiskLevel.INFO


class TestCVSSVectorMethods:
    """Tests for CVSSVector class methods."""

    def test_to_dict(self):
        """Test CVSSVector.to_dict() method."""
        vector_str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        success, vector, _ = parse_cvss_vector(vector_str)

        result = vector.to_dict()

        assert result["version"] == "3.1"
        assert result["attack_vector"] == "N"
        assert result["attack_complexity"] == "L"
        assert result["privileges_required"] == "N"
        assert result["user_interaction"] == "N"
        assert result["scope"] == "U"
        assert result["confidentiality"] == "H"
        assert result["integrity"] == "H"
        assert result["availability"] == "H"
        assert result["base_score"] == 9.8

    def test_raw_string_preserved(self):
        """Test that raw_string is preserved."""
        original = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        success, vector, _ = parse_cvss_vector(original)

        assert vector.raw_string == original


class TestCVSSEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_physical_attack_vector(self):
        """Test physical attack vector (lowest exploitability)."""
        vector_str = "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:H/I:H/A:H"
        success, score, _ = calculate_cvss_from_vector(vector_str)

        assert success is True
        assert score < 7.0  # Should be significantly reduced

    def test_changed_scope_with_low_impact(self):
        """Test changed scope with low impact values."""
        vector_str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:L"
        success, score, _ = calculate_cvss_from_vector(vector_str)

        assert success is True
        assert 5.0 <= score <= 9.0  # Changed scope increases score significantly

    def test_all_low_metrics(self):
        """Test with all metrics at lowest exploitability."""
        vector_str = "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L"
        success, score, _ = calculate_cvss_from_vector(vector_str)

        assert success is True
        assert score < 4.0

    def test_score_rounding(self):
        """Test that scores are properly rounded up."""
        # CVSS spec requires rounding up to 1 decimal place
        vector_str = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
        success, score, _ = calculate_cvss_from_vector(vector_str)

        assert success is True
        # Score should be a clean decimal
        assert score == round(score, 1)
