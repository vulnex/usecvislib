#
# VULNEX -Universal Security Visualization Library-
#
# File: __init__.py
# Author: Simon Roses Femerling
# Created: 2025-01-01
# Last Modified: 2025-12-25
# Version: 0.4.1
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Universal Security Visualization Library (USecVisLib).

A Python library for creating security visualizations including:
- Attack Trees: Hierarchical attack scenario diagrams
- Attack Graphs: Network attack path visualization and analysis
- Threat Modeling: Data Flow Diagrams with STRIDE analysis
- Binary Visualization: Entropy, distribution, and pattern analysis
- Custom Diagrams: Flexible, schema-driven diagram visualization
- Mermaid Diagrams: Render Mermaid syntax to images via mermaid-cli
- Cloud Diagrams: Cloud architecture diagrams with provider icons
- Privilege Gradient Graphs: Trust zone visualization with inversion detection

Example usage:
    >>> from usecvislib import AttackTrees
    >>> at = AttackTrees("attack.tml", "output", "png")
    >>> at.BuildAttackTree()

    >>> from usecvislib import AttackGraphs
    >>> ag = AttackGraphs("network.tml", "output", "png")
    >>> ag.BuildAttackGraph()

    >>> from usecvislib import BinVis
    >>> bv = BinVis("binary.exe", "analysis", "png")
    >>> bv.BuildBinVis("entropy")

    >>> from usecvislib import ThreatModeling
    >>> tm = ThreatModeling("threat.tml", "diagram", "png")
    >>> tm.BuildThreatModel()

    >>> from usecvislib import CustomDiagrams
    >>> cd = CustomDiagrams()
    >>> cd.load("diagram.toml")
    >>> cd.BuildCustomDiagram(output="diagram.png")

    >>> from usecvislib import MermaidDiagrams
    >>> md = MermaidDiagrams()
    >>> md.load("diagram.mmd")
    >>> md.render("output", format="png")

    >>> from usecvislib import CloudDiagrams
    >>> cloud = CloudDiagrams()
    >>> cloud.load("architecture.toml")
    >>> cloud.render("output", format="png")
"""

__version__ = "0.4.1"
__author__ = "VULNEX"

from .async_support import (
    AsyncBatchProcessor,
    AsyncVisualization,
    async_wrap,
    process_files_async,
)
from .attackgraphs import AttackGraphError, AttackGraphs
from .attacktrees import AttackTreeError, AttackTrees
from .base import VisualizationBase
from .batch import (
    BatchProcessor,
    BatchResult,
    process_batch,
)
from .binvis import BinVis
from .builders import (
    AttackGraphBuilder,
    AttackTreeBuilder,
    ComponentDiagramBuilder,
    DependencyGraphBuilder,
    PrivilegeGradientBuilder,
    ThreatModelBuilder,
)
from .clouddiagrams import (
    CloudCluster,
    CloudDiagramConfig,
    CloudDiagramError,
    CloudDiagramResult,
    CloudDiagrams,
    CloudEdge,
    CloudNode,
    DiagramsNotInstalledError,
    IconNotFoundError,
)
from .componentdiagram import ComponentDiagram, ComponentDiagramError
from .constants import (
    COLORS,
    DEFAULT_CVSS_DISPLAY,
    DEFAULTS,
    BinaryVisualization,
    ConfigFormat,
    ElementType,
    GateType,
    NodeType,
    OutputFormat,
    RiskLevel,
    STRIDECategory,
    ThreatModelEngine,
    VisualizationType,
)
from .customdiagrams import CustomDiagramError, CustomDiagrams
from .cvss import (
    CVSSVector,
    CVSSVersion,
    calculate_cvss_from_vector,
    get_cvss_score,
    parse_cvss_vector,
    validate_cvss_vector,
)
from .cvss4 import (
    CVSSVector4,
    calculate_cvss4_from_vector,
    parse_cvss4_vector,
    validate_cvss4_vector,
)
from .cvss_unified import (
    calculate_score_from_vector as calculate_cvss_from_vector_unified,
)
from .cvss_unified import (
    detect_cvss_version,
    get_cvss_score_unified,
    is_cvss3_vector,
    is_cvss4_vector,
)
from .cvss_unified import (
    parse_vector as parse_cvss_vector_unified,
)
from .cvss_unified import (
    validate_vector as validate_cvss_vector_unified,
)
from .dependencygraph import DependencyGraph, DependencyGraphError
from .diff import (
    Change,
    ChangeType,
    DiffResult,
    VisualizationDiff,
    compare_files,
)
from .exporters import (
    Exporter,
    ExportMixin,
    ReportGenerator,
)
from .maestro import (
    Agent as MaestroAgent,
)
from .maestro import (
    ArchitecturePattern,
    AutonomyLevel,
    CrossLayerThreat,
    MaestroError,
    MaestroLayer,
    MaestroThreatModel,
    ThreatStatus,
)
from .maestro import (
    Asset as MaestroAsset,
)
from .maestro import (
    Mitigation as MaestroMitigation,
)
from .maestro import (
    Threat as MaestroThreat,
)
from .mermaid import (
    MERMAID_FILE_EXTENSION,
    MermaidDiagramType,
    MermaidDirection,
    detect_visualization_type,
    serialize_to_mermaid,
)
from .mermaiddiagrams import (
    MermaidCLINotFoundError,
    MermaidConfig,
    MermaidDiagrams,
    MermaidError,
    MermaidResult,
    MermaidSyntaxError,
)
from .privilegegradient import PrivilegeGradient, PrivilegeGradientError
from .results import (
    # Analysis
    AnalysisResult,
    # Binary analysis
    BinaryAnalysisResult,
    CriticalNode,
    CriticalNodeResult,
    PathResult,
    # Rendering
    RenderResult,
    # Enums
    Severity,
    STRIDEResult,
    # Threat modeling
    STRIDEThreat,
    # Metadata
    TemplateMetadata,
    # Validation
    ValidationIssue,
    ValidationResult,
)
from .settings import (
    DisplaySettings,
    get_cvss_display_settings,
    get_settings,
    is_cvss_enabled,
    set_cvss_display_settings,
)
from .threatmodeling import ThreatModeling
from .utils import (
    AnalysisError,
    ConfigError,
    # Configuration
    ConfigModel,
    FileError,
    ReadTomlFile,
    RenderError,
    SecurityError,
    StyleManager,
    # Exception hierarchy
    USecVisLibError,
    ValidationError,
    # Caching utilities
    cached_result,
    # Logging
    configure_logging,
    content_hash,
    escape_dot_label,
    file_hash,
    get_logger,
    merge_dicts,
    process_node_image,
    sanitize_node_id,
    stringify_dict,
    validate_image_path,
    # Security utilities
    validate_input_path,
    validate_output_path,
)

__all__ = [
    "COLORS",
    "DEFAULTS",
    "DEFAULT_CVSS_DISPLAY",
    "MERMAID_FILE_EXTENSION",
    "AnalysisError",
    "AnalysisResult",
    "ArchitecturePattern",
    "AsyncBatchProcessor",
    # Async support
    "AsyncVisualization",
    "AttackGraphBuilder",
    "AttackGraphError",
    "AttackGraphs",
    # Builder Classes
    "AttackTreeBuilder",
    "AttackTreeError",
    # Visualization Classes
    "AttackTrees",
    "AutonomyLevel",
    # Batch processing
    "BatchProcessor",
    "BatchResult",
    "BinVis",
    "BinaryAnalysisResult",
    "BinaryVisualization",
    # CVSS 3.x support
    "CVSSVector",
    # CVSS 4.0 support
    "CVSSVector4",
    "CVSSVersion",
    "Change",
    # Diff/comparison
    "ChangeType",
    "CloudCluster",
    # Cloud diagram support classes
    "CloudDiagramConfig",
    "CloudDiagramError",
    "CloudDiagramResult",
    "CloudDiagrams",
    "CloudEdge",
    "CloudNode",
    "ComponentDiagram",
    "ComponentDiagramBuilder",
    "ComponentDiagramError",
    "ConfigError",
    "ConfigFormat",
    # Configuration
    "ConfigModel",
    "CriticalNode",
    "CriticalNodeResult",
    "CrossLayerThreat",
    "CustomDiagramError",
    "CustomDiagrams",
    "DependencyGraph",
    "DependencyGraphBuilder",
    "DependencyGraphError",
    "DiagramsNotInstalledError",
    "DiffResult",
    # Settings
    "DisplaySettings",
    "ElementType",
    # Export utilities
    "ExportMixin",
    "Exporter",
    "FileError",
    "GateType",
    "IconNotFoundError",
    # MAESTRO support classes
    "MaestroAgent",
    "MaestroAsset",
    "MaestroError",
    "MaestroLayer",
    "MaestroMitigation",
    "MaestroThreat",
    "MaestroThreatModel",
    "MermaidCLINotFoundError",
    # Mermaid support classes
    "MermaidConfig",
    "MermaidDiagramType",
    "MermaidDiagrams",
    "MermaidDirection",
    "MermaidError",
    "MermaidResult",
    "MermaidSyntaxError",
    "NodeType",
    # Enums and Constants
    "OutputFormat",
    "PathResult",
    "PrivilegeGradient",
    "PrivilegeGradientBuilder",
    "PrivilegeGradientError",
    # Configuration functions
    "ReadTomlFile",
    "RenderError",
    "RenderResult",
    "ReportGenerator",
    "RiskLevel",
    "STRIDECategory",
    "STRIDEResult",
    "STRIDEThreat",
    "SecurityError",
    # Result Classes
    "Severity",
    "StyleManager",
    "TemplateMetadata",
    "ThreatModelBuilder",
    "ThreatModelEngine",
    "ThreatModeling",
    "ThreatStatus",
    # Exception hierarchy
    "USecVisLibError",
    "ValidationError",
    "ValidationIssue",
    "ValidationResult",
    # Base class
    "VisualizationBase",
    "VisualizationDiff",
    "VisualizationType",
    "__author__",
    # Metadata
    "__version__",
    "async_wrap",
    # Caching utilities
    "cached_result",
    "calculate_cvss4_from_vector",
    "calculate_cvss_from_vector",
    "calculate_cvss_from_vector_unified",
    "compare_files",
    # Logging
    "configure_logging",
    "content_hash",
    "detect_cvss_version",
    "detect_visualization_type",
    "escape_dot_label",
    "file_hash",
    "get_cvss_display_settings",
    "get_cvss_score",
    "get_cvss_score_unified",
    "get_logger",
    "get_settings",
    "is_cvss3_vector",
    "is_cvss4_vector",
    "is_cvss_enabled",
    "merge_dicts",
    "parse_cvss4_vector",
    "parse_cvss_vector",
    # CVSS unified interface
    "parse_cvss_vector_unified",
    "process_batch",
    "process_files_async",
    "process_node_image",
    "sanitize_node_id",
    # Mermaid support
    "serialize_to_mermaid",
    "set_cvss_display_settings",
    "stringify_dict",
    "validate_cvss4_vector",
    "validate_cvss_vector",
    "validate_cvss_vector_unified",
    "validate_image_path",
    # Security utilities
    "validate_input_path",
    "validate_output_path",
]
