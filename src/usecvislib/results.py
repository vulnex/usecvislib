#
# VULNEX -Universal Security Visualization Library-
#
# File: results.py
# Author: Simon Roses Femerling
# Created: 2025-12-25
# Last Modified: 2025-12-25
# Version: 0.3.1
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""
Result and data classes for USecVisLib operations.

This module provides structured result objects for various operations
including validation, analysis, path finding, and threat modeling.
These classes provide a consistent API for accessing operation results.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Iterator
from enum import Enum


class Severity(str, Enum):
    """Severity levels for validation issues."""
    CRITICAL = "critical"
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


@dataclass
class TemplateMetadata:
    """Metadata information from a template file.

    These fields provide context about the template including version,
    authorship, and compatibility information.

    Attributes:
        name: Template name.
        description: Template description.
        engineversion: USecVisLib engine version compatibility.
        version: Template file version.
        type: Template type (Attack Tree, Attack Graph, Threat Model).
        date: Template creation date.
        last_modified: Last modification date.
        author: Author name.
        email: Author email.
        url: Author URL.
    """
    name: str = ""
    description: str = ""
    engineversion: str = ""
    version: str = ""
    type: str = ""
    date: str = ""
    last_modified: str = ""
    author: str = ""
    email: str = ""
    url: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert metadata to dictionary.

        Returns:
            Dictionary representation of metadata.
        """
        return {
            "name": self.name,
            "description": self.description,
            "engineversion": self.engineversion,
            "version": self.version,
            "type": self.type,
            "date": self.date,
            "last_modified": self.last_modified,
            "author": self.author,
            "email": self.email,
            "url": self.url,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any], root_key: str = "") -> 'TemplateMetadata':
        """Create TemplateMetadata from a dictionary.

        Args:
            data: Dictionary containing template data.
            root_key: Root key to look for metadata (tree, graph, model).
                     If empty, searches common keys.

        Returns:
            TemplateMetadata instance.
        """
        # Determine root section
        if root_key and root_key in data:
            root = data[root_key]
        else:
            # Search common root keys
            for key in ['tree', 'graph', 'model']:
                if key in data:
                    root = data[key]
                    break
            else:
                root = data

        return cls(
            name=root.get('name', ''),
            description=root.get('description', ''),
            engineversion=root.get('engineversion', ''),
            version=root.get('version', ''),
            type=root.get('type', ''),
            date=root.get('date', ''),
            last_modified=root.get('last_modified', ''),
            author=root.get('author', ''),
            email=root.get('email', ''),
            url=root.get('url', ''),
        )

    def has_metadata(self) -> bool:
        """Check if any metadata fields are populated.

        Returns:
            True if at least one metadata field is set.
        """
        return any([
            self.engineversion,
            self.version,
            self.type,
            self.date,
            self.author,
        ])


@dataclass
class ValidationIssue:
    """A single validation issue.

    Attributes:
        message: Description of the issue.
        severity: Severity level of the issue.
        location: Optional location in the data (e.g., "hosts.webserver").
        suggestion: Optional suggestion for fixing the issue.
    """
    message: str
    severity: Severity
    location: Optional[str] = None
    suggestion: Optional[str] = None

    def __str__(self) -> str:
        parts = [f"[{self.severity.value.upper()}] {self.message}"]
        if self.location:
            parts.append(f" at {self.location}")
        if self.suggestion:
            parts.append(f" (suggestion: {self.suggestion})")
        return "".join(parts)


@dataclass
class ValidationResult:
    """Result of a validation operation.

    Attributes:
        is_valid: Whether the validation passed (no errors).
        issues: List of validation issues found.
    """
    is_valid: bool
    issues: List[ValidationIssue] = field(default_factory=list)

    @property
    def errors(self) -> List[ValidationIssue]:
        """Get all error-level issues."""
        return [i for i in self.issues if i.severity in (Severity.ERROR, Severity.CRITICAL)]

    @property
    def warnings(self) -> List[ValidationIssue]:
        """Get all warning-level issues."""
        return [i for i in self.issues if i.severity == Severity.WARNING]

    @property
    def info(self) -> List[ValidationIssue]:
        """Get all info-level issues."""
        return [i for i in self.issues if i.severity == Severity.INFO]

    @property
    def critical(self) -> List[ValidationIssue]:
        """Get all critical-level issues."""
        return [i for i in self.issues if i.severity == Severity.CRITICAL]

    def merge(self, other: 'ValidationResult') -> 'ValidationResult':
        """Merge two validation results.

        Args:
            other: Another ValidationResult to merge with this one.

        Returns:
            New ValidationResult with combined issues.
        """
        return ValidationResult(
            is_valid=self.is_valid and other.is_valid,
            issues=self.issues + other.issues
        )

    def add_issue(
        self,
        message: str,
        severity: Severity = Severity.ERROR,
        location: Optional[str] = None,
        suggestion: Optional[str] = None
    ) -> 'ValidationResult':
        """Add an issue to the result.

        Args:
            message: Description of the issue.
            severity: Severity level.
            location: Optional location in data.
            suggestion: Optional fix suggestion.

        Returns:
            Self for method chaining.
        """
        self.issues.append(ValidationIssue(message, severity, location, suggestion))
        if severity in (Severity.ERROR, Severity.CRITICAL):
            self.is_valid = False
        return self

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "is_valid": self.is_valid,
            "error_count": len(self.errors),
            "warning_count": len(self.warnings),
            "issues": [
                {
                    "message": i.message,
                    "severity": i.severity.value,
                    "location": i.location,
                    "suggestion": i.suggestion
                }
                for i in self.issues
            ]
        }


@dataclass
class AnalysisResult:
    """Result of an analysis operation.

    Attributes:
        stats: Dictionary of statistical metrics.
        recommendations: List of recommendations based on analysis.
        risk_score: Optional overall risk score (0-10).
        metadata: Additional metadata about the analysis.
    """
    stats: Dict[str, Any]
    recommendations: List[str] = field(default_factory=list)
    risk_score: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def risk_level(self) -> str:
        """Get risk level as string based on risk_score."""
        if self.risk_score is None:
            return "unknown"
        if self.risk_score >= 9.0:
            return "critical"
        if self.risk_score >= 7.0:
            return "high"
        if self.risk_score >= 4.0:
            return "medium"
        if self.risk_score >= 0.1:
            return "low"
        return "none"

    def add_recommendation(self, recommendation: str) -> 'AnalysisResult':
        """Add a recommendation.

        Args:
            recommendation: Recommendation text.

        Returns:
            Self for method chaining.
        """
        self.recommendations.append(recommendation)
        return self

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "stats": self.stats,
            "recommendations": self.recommendations,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "metadata": self.metadata
        }


@dataclass
class PathResult:
    """Result of path finding operation.

    Attributes:
        source: Starting node ID.
        target: Target node ID.
        paths: List of all paths found (each path is a list of node IDs).
        shortest_path: The shortest path found (if any).
        shortest_length: Length of the shortest path.
        total_cost: Optional total cost for weighted paths.
    """
    source: str
    target: str
    paths: List[List[str]] = field(default_factory=list)
    shortest_path: Optional[List[str]] = None
    shortest_length: Optional[int] = None
    total_cost: Optional[float] = None

    def __post_init__(self):
        """Calculate shortest path if not provided."""
        if self.paths and self.shortest_path is None:
            self.shortest_path = min(self.paths, key=len) if self.paths else None
            self.shortest_length = len(self.shortest_path) if self.shortest_path else None

    @property
    def total_paths(self) -> int:
        """Get total number of paths found."""
        return len(self.paths)

    @property
    def found(self) -> bool:
        """Check if any path was found."""
        return len(self.paths) > 0

    @property
    def max_length(self) -> Optional[int]:
        """Get length of the longest path."""
        if not self.paths:
            return None
        return max(len(p) for p in self.paths)

    def paths_by_length(self, length: int) -> List[List[str]]:
        """Get all paths of a specific length.

        Args:
            length: Desired path length.

        Returns:
            List of paths with the specified length.
        """
        return [p for p in self.paths if len(p) == length]

    def __iter__(self) -> Iterator[List[str]]:
        """Iterate over all paths."""
        return iter(self.paths)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "source": self.source,
            "target": self.target,
            "found": self.found,
            "total_paths": self.total_paths,
            "shortest_length": self.shortest_length,
            "shortest_path": self.shortest_path,
            "total_cost": self.total_cost,
            "paths": self.paths
        }


@dataclass
class CriticalNode:
    """A single critical node in the graph.

    Attributes:
        node_id: The node identifier.
        label: Human-readable label.
        node_type: Type of node (host, vulnerability, etc.).
        in_degree: Number of incoming edges.
        out_degree: Number of outgoing edges.
        criticality_score: Calculated criticality score.
        metadata: Additional node metadata.
    """
    node_id: str
    label: str
    node_type: str
    in_degree: int = 0
    out_degree: int = 0
    criticality_score: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def total_degree(self) -> int:
        """Get total degree (in + out)."""
        return self.in_degree + self.out_degree

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "id": self.node_id,
            "label": self.label,
            "type": self.node_type,
            "in_degree": self.in_degree,
            "out_degree": self.out_degree,
            "total_degree": self.total_degree,
            "criticality_score": self.criticality_score,
            **self.metadata
        }


@dataclass
class CriticalNodeResult:
    """Result of critical node analysis.

    Attributes:
        nodes: List of critical nodes, sorted by criticality.
        analysis_method: Method used for analysis.
        metadata: Additional analysis metadata.
    """
    nodes: List[CriticalNode] = field(default_factory=list)
    analysis_method: str = "degree_centrality"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def top(self, n: int = 5) -> List[CriticalNode]:
        """Get top N most critical nodes.

        Args:
            n: Number of nodes to return.

        Returns:
            List of top N critical nodes.
        """
        return self.nodes[:n]

    def by_type(self, node_type: str) -> List[CriticalNode]:
        """Get critical nodes of a specific type.

        Args:
            node_type: Type of nodes to filter.

        Returns:
            List of nodes matching the type.
        """
        return [n for n in self.nodes if n.node_type == node_type]

    def above_threshold(self, threshold: float) -> List[CriticalNode]:
        """Get nodes above a criticality threshold.

        Args:
            threshold: Minimum criticality score.

        Returns:
            List of nodes above the threshold.
        """
        return [n for n in self.nodes if n.criticality_score >= threshold]

    def __iter__(self) -> Iterator[CriticalNode]:
        """Iterate over all critical nodes."""
        return iter(self.nodes)

    def __len__(self) -> int:
        """Get number of critical nodes."""
        return len(self.nodes)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "analysis_method": self.analysis_method,
            "node_count": len(self.nodes),
            "nodes": [n.to_dict() for n in self.nodes],
            "metadata": self.metadata
        }


@dataclass
class STRIDEThreat:
    """A single STRIDE threat.

    Attributes:
        category: STRIDE category (Spoofing, Tampering, etc.).
        element: Affected data flow element.
        threat: Description of the threat.
        mitigation: Suggested mitigation.
        severity: Threat severity level.
        confidence: Confidence in the threat identification (0-1).
    """
    category: str
    element: str
    threat: str
    mitigation: str
    severity: str = "medium"
    confidence: float = 1.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "category": self.category,
            "element": self.element,
            "threat": self.threat,
            "mitigation": self.mitigation,
            "severity": self.severity,
            "confidence": self.confidence
        }


@dataclass
class STRIDEResult:
    """Result of STRIDE analysis.

    Attributes:
        threats: Dictionary mapping categories to threat lists.
        metadata: Additional analysis metadata.
    """
    threats: Dict[str, List[STRIDEThreat]] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def total_count(self) -> int:
        """Get total number of threats."""
        return sum(len(t) for t in self.threats.values())

    @property
    def categories(self) -> List[str]:
        """Get list of threat categories with threats."""
        return list(self.threats.keys())

    def by_severity(self, severity: str) -> List[STRIDEThreat]:
        """Get all threats of a specific severity.

        Args:
            severity: Severity level to filter.

        Returns:
            List of threats with the specified severity.
        """
        result = []
        for category_threats in self.threats.values():
            result.extend(t for t in category_threats if t.severity == severity)
        return result

    def for_element(self, element: str) -> List[STRIDEThreat]:
        """Get all threats for a specific element.

        Args:
            element: Element name to filter.

        Returns:
            List of threats affecting the element.
        """
        result = []
        for category_threats in self.threats.values():
            result.extend(t for t in category_threats if t.element == element)
        return result

    def for_category(self, category: str) -> List[STRIDEThreat]:
        """Get all threats in a specific STRIDE category.

        Args:
            category: STRIDE category (e.g., "Spoofing").

        Returns:
            List of threats in the category.
        """
        return self.threats.get(category, [])

    def add_threat(self, threat: STRIDEThreat) -> 'STRIDEResult':
        """Add a threat to the result.

        Args:
            threat: Threat to add.

        Returns:
            Self for method chaining.
        """
        if threat.category not in self.threats:
            self.threats[threat.category] = []
        self.threats[threat.category].append(threat)
        return self

    def summary(self) -> Dict[str, int]:
        """Get summary of threats by category.

        Returns:
            Dictionary mapping categories to threat counts.
        """
        return {cat: len(threats) for cat, threats in self.threats.items()}

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "total_count": self.total_count,
            "by_category": self.summary(),
            "threats": {
                cat: [t.to_dict() for t in threats]
                for cat, threats in self.threats.items()
            },
            "metadata": self.metadata
        }


@dataclass
class BinaryAnalysisResult:
    """Result of binary file analysis.

    Attributes:
        file_path: Path to the analyzed file.
        file_size: Size of the file in bytes.
        entropy: Overall entropy value (0-8).
        stats: Additional statistics.
        sections: Analysis of different file sections.
        metadata: Additional metadata.
    """
    file_path: str
    file_size: int
    entropy: float
    stats: Dict[str, Any] = field(default_factory=dict)
    sections: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_likely_encrypted(self) -> bool:
        """Check if file is likely encrypted based on entropy."""
        return self.entropy >= 7.5

    @property
    def is_likely_compressed(self) -> bool:
        """Check if file is likely compressed based on entropy."""
        return 7.0 <= self.entropy < 7.5

    @property
    def entropy_classification(self) -> str:
        """Classify the entropy level."""
        if self.entropy >= 7.5:
            return "very_high"
        if self.entropy >= 7.0:
            return "high"
        if self.entropy >= 5.0:
            return "medium"
        if self.entropy >= 2.0:
            return "low"
        return "very_low"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "file_path": self.file_path,
            "file_size": self.file_size,
            "entropy": self.entropy,
            "entropy_classification": self.entropy_classification,
            "is_likely_encrypted": self.is_likely_encrypted,
            "is_likely_compressed": self.is_likely_compressed,
            "stats": self.stats,
            "sections": self.sections,
            "metadata": self.metadata
        }


@dataclass
class RenderResult:
    """Result of a render operation.

    Attributes:
        success: Whether rendering succeeded.
        output_path: Path to the output file.
        format: Output format used.
        duration_ms: Time taken to render in milliseconds.
        warnings: Any warnings generated during rendering.
        metadata: Additional rendering metadata.
    """
    success: bool
    output_path: Optional[str] = None
    format: Optional[str] = None
    duration_ms: Optional[float] = None
    warnings: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "success": self.success,
            "output_path": self.output_path,
            "format": self.format,
            "duration_ms": self.duration_ms,
            "warnings": self.warnings,
            "metadata": self.metadata
        }
