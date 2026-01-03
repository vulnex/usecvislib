#
# VULNEX -Universal Security Visualization Library-
#
# File: test_results.py
# Author: Simon Roses Femerling
# Created: 2025-12-25
# Last Modified: 2025-12-25
# Version: 0.3.1
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Unit tests for results module."""

import os
import sys
import pytest

# Add src to path for testing
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from usecvislib.results import (
    Severity,
    ValidationIssue,
    ValidationResult,
    AnalysisResult,
    PathResult,
    CriticalNode,
    CriticalNodeResult,
    STRIDEThreat,
    STRIDEResult,
    BinaryAnalysisResult,
    RenderResult,
)


class TestSeverity:
    """Tests for Severity enum."""

    def test_severity_values(self):
        """Test severity enum values."""
        assert Severity.CRITICAL.value == "critical"
        assert Severity.ERROR.value == "error"
        assert Severity.WARNING.value == "warning"
        assert Severity.INFO.value == "info"


class TestValidationIssue:
    """Tests for ValidationIssue dataclass."""

    def test_basic_issue(self):
        """Test creating a basic validation issue."""
        issue = ValidationIssue("Test error", Severity.ERROR)
        assert issue.message == "Test error"
        assert issue.severity == Severity.ERROR
        assert issue.location is None
        assert issue.suggestion is None

    def test_issue_with_all_fields(self):
        """Test creating an issue with all fields."""
        issue = ValidationIssue(
            "Missing node",
            Severity.WARNING,
            location="nodes.target",
            suggestion="Add the missing node"
        )
        assert issue.location == "nodes.target"
        assert issue.suggestion == "Add the missing node"

    def test_issue_str(self):
        """Test string representation of issue."""
        issue = ValidationIssue("Test", Severity.ERROR)
        assert "ERROR" in str(issue)
        assert "Test" in str(issue)


class TestValidationResult:
    """Tests for ValidationResult dataclass."""

    def test_valid_result(self):
        """Test creating a valid result."""
        result = ValidationResult(is_valid=True)
        assert result.is_valid is True
        assert len(result.issues) == 0
        assert len(result.errors) == 0
        assert len(result.warnings) == 0

    def test_invalid_result_with_errors(self):
        """Test result with errors."""
        result = ValidationResult(
            is_valid=False,
            issues=[
                ValidationIssue("Error 1", Severity.ERROR),
                ValidationIssue("Error 2", Severity.ERROR),
            ]
        )
        assert result.is_valid is False
        assert len(result.errors) == 2

    def test_mixed_issues(self):
        """Test result with mixed severity issues."""
        result = ValidationResult(
            is_valid=False,
            issues=[
                ValidationIssue("Critical", Severity.CRITICAL),
                ValidationIssue("Error", Severity.ERROR),
                ValidationIssue("Warning", Severity.WARNING),
                ValidationIssue("Info", Severity.INFO),
            ]
        )
        assert len(result.critical) == 1
        assert len(result.errors) == 2  # Critical + Error
        assert len(result.warnings) == 1
        assert len(result.info) == 1

    def test_merge_results(self):
        """Test merging validation results."""
        result1 = ValidationResult(
            is_valid=True,
            issues=[ValidationIssue("Warning", Severity.WARNING)]
        )
        result2 = ValidationResult(
            is_valid=False,
            issues=[ValidationIssue("Error", Severity.ERROR)]
        )
        merged = result1.merge(result2)
        assert merged.is_valid is False
        assert len(merged.issues) == 2

    def test_add_issue(self):
        """Test adding issues to result."""
        result = ValidationResult(is_valid=True)
        result.add_issue("Warning", Severity.WARNING)
        assert result.is_valid is True
        assert len(result.issues) == 1

        result.add_issue("Error", Severity.ERROR)
        assert result.is_valid is False
        assert len(result.issues) == 2

    def test_to_dict(self):
        """Test dictionary conversion."""
        result = ValidationResult(
            is_valid=True,
            issues=[ValidationIssue("Test", Severity.WARNING)]
        )
        d = result.to_dict()
        assert d["is_valid"] is True
        assert d["warning_count"] == 1
        assert len(d["issues"]) == 1


class TestAnalysisResult:
    """Tests for AnalysisResult dataclass."""

    def test_basic_result(self):
        """Test creating basic analysis result."""
        result = AnalysisResult(stats={"nodes": 10, "edges": 15})
        assert result.stats["nodes"] == 10
        assert result.risk_score is None
        assert result.risk_level == "unknown"

    def test_risk_levels(self):
        """Test risk level classification."""
        assert AnalysisResult(stats={}, risk_score=9.5).risk_level == "critical"
        assert AnalysisResult(stats={}, risk_score=7.5).risk_level == "high"
        assert AnalysisResult(stats={}, risk_score=5.0).risk_level == "medium"
        assert AnalysisResult(stats={}, risk_score=2.0).risk_level == "low"
        assert AnalysisResult(stats={}, risk_score=0.0).risk_level == "none"

    def test_add_recommendation(self):
        """Test adding recommendations."""
        result = AnalysisResult(stats={})
        result.add_recommendation("Fix vulnerability")
        result.add_recommendation("Update firewall")
        assert len(result.recommendations) == 2

    def test_to_dict(self):
        """Test dictionary conversion."""
        result = AnalysisResult(
            stats={"count": 5},
            risk_score=8.0,
            recommendations=["Fix it"]
        )
        d = result.to_dict()
        assert d["risk_level"] == "high"
        assert len(d["recommendations"]) == 1


class TestPathResult:
    """Tests for PathResult dataclass."""

    def test_no_paths(self):
        """Test result with no paths found."""
        result = PathResult(source="a", target="b")
        assert result.found is False
        assert result.total_paths == 0
        assert result.shortest_length is None

    def test_with_paths(self):
        """Test result with paths found."""
        result = PathResult(
            source="a",
            target="c",
            paths=[["a", "b", "c"], ["a", "c"]]
        )
        assert result.found is True
        assert result.total_paths == 2
        assert result.shortest_path == ["a", "c"]
        assert result.shortest_length == 2
        assert result.max_length == 3

    def test_paths_by_length(self):
        """Test filtering paths by length."""
        result = PathResult(
            source="a",
            target="d",
            paths=[["a", "b", "c", "d"], ["a", "c", "d"], ["a", "d"]]
        )
        assert len(result.paths_by_length(2)) == 1
        assert len(result.paths_by_length(3)) == 1
        assert len(result.paths_by_length(4)) == 1

    def test_iterator(self):
        """Test iterating over paths."""
        paths = [["a", "b"], ["a", "c"]]
        result = PathResult(source="a", target="b", paths=paths)
        for i, path in enumerate(result):
            assert path == paths[i]

    def test_to_dict(self):
        """Test dictionary conversion."""
        result = PathResult(
            source="a",
            target="b",
            paths=[["a", "b"]]
        )
        d = result.to_dict()
        assert d["source"] == "a"
        assert d["found"] is True


class TestCriticalNode:
    """Tests for CriticalNode dataclass."""

    def test_basic_node(self):
        """Test creating a basic critical node."""
        node = CriticalNode(
            node_id="web",
            label="Web Server",
            node_type="host",
            in_degree=3,
            out_degree=2
        )
        assert node.total_degree == 5
        assert node.node_id == "web"

    def test_to_dict(self):
        """Test dictionary conversion."""
        node = CriticalNode(
            node_id="db",
            label="Database",
            node_type="host",
            in_degree=5,
            out_degree=1,
            criticality_score=0.8
        )
        d = node.to_dict()
        assert d["id"] == "db"
        assert d["total_degree"] == 6


class TestCriticalNodeResult:
    """Tests for CriticalNodeResult dataclass."""

    def test_empty_result(self):
        """Test empty critical node result."""
        result = CriticalNodeResult()
        assert len(result) == 0
        assert result.top(5) == []

    def test_with_nodes(self):
        """Test result with critical nodes."""
        nodes = [
            CriticalNode("a", "Node A", "host", 5, 3, 0.9),
            CriticalNode("b", "Node B", "host", 3, 2, 0.7),
            CriticalNode("c", "Node C", "vuln", 2, 1, 0.5),
        ]
        result = CriticalNodeResult(nodes=nodes)
        assert len(result) == 3
        assert len(result.top(2)) == 2

    def test_filter_by_type(self):
        """Test filtering by node type."""
        nodes = [
            CriticalNode("a", "A", "host", 1, 1, 0.5),
            CriticalNode("b", "B", "vuln", 1, 1, 0.5),
            CriticalNode("c", "C", "host", 1, 1, 0.5),
        ]
        result = CriticalNodeResult(nodes=nodes)
        hosts = result.by_type("host")
        assert len(hosts) == 2

    def test_above_threshold(self):
        """Test filtering by threshold."""
        nodes = [
            CriticalNode("a", "A", "host", 1, 1, 0.9),
            CriticalNode("b", "B", "host", 1, 1, 0.5),
            CriticalNode("c", "C", "host", 1, 1, 0.3),
        ]
        result = CriticalNodeResult(nodes=nodes)
        high = result.above_threshold(0.7)
        assert len(high) == 1


class TestSTRIDEThreat:
    """Tests for STRIDEThreat dataclass."""

    def test_basic_threat(self):
        """Test creating a basic STRIDE threat."""
        threat = STRIDEThreat(
            category="Spoofing",
            element="User Login",
            threat="Attacker impersonates user",
            mitigation="Use MFA"
        )
        assert threat.category == "Spoofing"
        assert threat.severity == "medium"
        assert threat.confidence == 1.0

    def test_to_dict(self):
        """Test dictionary conversion."""
        threat = STRIDEThreat(
            category="Tampering",
            element="Data",
            threat="Data modification",
            mitigation="Use signatures",
            severity="high"
        )
        d = threat.to_dict()
        assert d["severity"] == "high"


class TestSTRIDEResult:
    """Tests for STRIDEResult dataclass."""

    def test_empty_result(self):
        """Test empty STRIDE result."""
        result = STRIDEResult()
        assert result.total_count == 0
        assert result.categories == []

    def test_with_threats(self):
        """Test result with threats."""
        result = STRIDEResult()
        result.add_threat(STRIDEThreat("Spoofing", "Login", "Threat1", "Fix1"))
        result.add_threat(STRIDEThreat("Spoofing", "API", "Threat2", "Fix2"))
        result.add_threat(STRIDEThreat("Tampering", "Data", "Threat3", "Fix3"))

        assert result.total_count == 3
        assert len(result.categories) == 2
        assert len(result.for_category("Spoofing")) == 2

    def test_filter_by_severity(self):
        """Test filtering by severity."""
        result = STRIDEResult(threats={
            "Spoofing": [
                STRIDEThreat("Spoofing", "A", "T1", "M1", severity="high"),
                STRIDEThreat("Spoofing", "B", "T2", "M2", severity="low"),
            ]
        })
        high = result.by_severity("high")
        assert len(high) == 1

    def test_filter_by_element(self):
        """Test filtering by element."""
        result = STRIDEResult(threats={
            "Spoofing": [
                STRIDEThreat("Spoofing", "Login", "T1", "M1"),
                STRIDEThreat("Spoofing", "API", "T2", "M2"),
            ],
            "Tampering": [
                STRIDEThreat("Tampering", "Login", "T3", "M3"),
            ]
        })
        login_threats = result.for_element("Login")
        assert len(login_threats) == 2

    def test_summary(self):
        """Test summary generation."""
        result = STRIDEResult(threats={
            "Spoofing": [STRIDEThreat("Spoofing", "A", "T", "M")],
            "Tampering": [STRIDEThreat("Tampering", "B", "T", "M")],
        })
        summary = result.summary()
        assert summary["Spoofing"] == 1
        assert summary["Tampering"] == 1


class TestBinaryAnalysisResult:
    """Tests for BinaryAnalysisResult dataclass."""

    def test_basic_result(self):
        """Test basic binary analysis result."""
        result = BinaryAnalysisResult(
            file_path="/path/to/file",
            file_size=1024,
            entropy=7.2
        )
        assert result.is_likely_compressed is True
        assert result.is_likely_encrypted is False
        assert result.entropy_classification == "high"

    def test_entropy_classifications(self):
        """Test entropy classification levels."""
        assert BinaryAnalysisResult("", 0, 7.8).entropy_classification == "very_high"
        assert BinaryAnalysisResult("", 0, 7.2).entropy_classification == "high"
        assert BinaryAnalysisResult("", 0, 6.0).entropy_classification == "medium"
        assert BinaryAnalysisResult("", 0, 3.0).entropy_classification == "low"
        assert BinaryAnalysisResult("", 0, 1.0).entropy_classification == "very_low"

    def test_to_dict(self):
        """Test dictionary conversion."""
        result = BinaryAnalysisResult(
            file_path="/file.bin",
            file_size=2048,
            entropy=7.9
        )
        d = result.to_dict()
        assert d["is_likely_encrypted"] is True
        assert d["entropy_classification"] == "very_high"


class TestRenderResult:
    """Tests for RenderResult dataclass."""

    def test_successful_render(self):
        """Test successful render result."""
        result = RenderResult(
            success=True,
            output_path="/output/file.png",
            format="png",
            duration_ms=150.5
        )
        assert result.success is True
        assert result.output_path == "/output/file.png"

    def test_failed_render(self):
        """Test failed render result."""
        result = RenderResult(
            success=False,
            warnings=["Missing graphviz"]
        )
        assert result.success is False
        assert len(result.warnings) == 1

    def test_to_dict(self):
        """Test dictionary conversion."""
        result = RenderResult(success=True, format="svg")
        d = result.to_dict()
        assert d["success"] is True
        assert d["format"] == "svg"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
