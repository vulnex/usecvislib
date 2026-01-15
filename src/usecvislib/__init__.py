#
# VULNEX -Universal Security Visualization Library-
#
# File: __init__.py
# Author: Simon Roses Femerling
# Created: 2025-01-01
# Last Modified: 2025-12-25
# Version: 0.3.2
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

__version__ = "0.3.2"
__author__ = "VulnEx"

from .attacktrees import AttackTrees, AttackTreeError
from .attackgraphs import AttackGraphs, AttackGraphError
from .binvis import BinVis
from .threatmodeling import ThreatModeling
from .customdiagrams import CustomDiagrams, CustomDiagramError
from .mermaiddiagrams import (
    MermaidDiagrams,
    MermaidError,
    MermaidCLINotFoundError,
    MermaidSyntaxError,
    MermaidConfig,
    MermaidResult,
)
from .clouddiagrams import (
    CloudDiagrams,
    CloudDiagramError,
    DiagramsNotInstalledError,
    IconNotFoundError,
    CloudDiagramConfig,
    CloudNode,
    CloudEdge,
    CloudCluster,
    CloudDiagramResult,
)
from .base import VisualizationBase
from .constants import (
    OutputFormat,
    ConfigFormat,
    NodeType,
    GateType,
    ElementType,
    STRIDECategory,
    BinaryVisualization,
    ThreatModelEngine,
    RiskLevel,
    DEFAULTS,
    COLORS,
)
from .utils import (
    # Configuration
    ConfigModel,
    ReadTomlFile,
    merge_dicts,
    stringify_dict,
    # Exception hierarchy
    USecVisLibError,
    ConfigError,
    FileError,
    SecurityError,
    ValidationError,
    RenderError,
    AnalysisError,
    # Security utilities
    validate_input_path,
    validate_output_path,
    validate_image_path,
    process_node_image,
    escape_dot_label,
    sanitize_node_id,
    # Logging
    configure_logging,
    get_logger,
    # Caching utilities
    cached_result,
    content_hash,
    file_hash,
    StyleManager,
)
from .results import (
    # Enums
    Severity,
    # Metadata
    TemplateMetadata,
    # Validation
    ValidationIssue,
    ValidationResult,
    # Analysis
    AnalysisResult,
    PathResult,
    CriticalNode,
    CriticalNodeResult,
    # Threat modeling
    STRIDEThreat,
    STRIDEResult,
    # Binary analysis
    BinaryAnalysisResult,
    # Rendering
    RenderResult,
)
from .builders import (
    AttackTreeBuilder,
    AttackGraphBuilder,
    ThreatModelBuilder,
)
from .batch import (
    BatchProcessor,
    BatchResult,
    process_batch,
)
from .exporters import (
    ExportMixin,
    Exporter,
    ReportGenerator,
)
from .async_support import (
    AsyncVisualization,
    async_wrap,
    AsyncBatchProcessor,
    process_files_async,
)
from .diff import (
    ChangeType,
    Change,
    DiffResult,
    VisualizationDiff,
    compare_files,
)
from .cvss import (
    CVSSVector,
    CVSSVersion,
    parse_cvss_vector,
    calculate_cvss_from_vector,
    validate_cvss_vector,
    get_cvss_score,
)
from .mermaid import (
    serialize_to_mermaid,
    detect_visualization_type,
    MermaidDiagramType,
    MermaidDirection,
    MERMAID_FILE_EXTENSION,
)
from .settings import (
    DisplaySettings,
    get_settings,
    is_cvss_enabled,
    get_cvss_display_settings,
    set_cvss_display_settings,
)
from .constants import (
    VisualizationType,
    DEFAULT_CVSS_DISPLAY,
)

__all__ = [
    # Visualization Classes
    "AttackTrees",
    "AttackGraphs",
    "BinVis",
    "ThreatModeling",
    "CustomDiagrams",
    "MermaidDiagrams",
    "CloudDiagrams",
    # Base class
    "VisualizationBase",
    # Builder Classes
    "AttackTreeBuilder",
    "AttackGraphBuilder",
    "ThreatModelBuilder",
    # Result Classes
    "Severity",
    "TemplateMetadata",
    "ValidationIssue",
    "ValidationResult",
    "AnalysisResult",
    "PathResult",
    "CriticalNode",
    "CriticalNodeResult",
    "STRIDEThreat",
    "STRIDEResult",
    "BinaryAnalysisResult",
    "RenderResult",
    # Configuration
    "ConfigModel",
    # Enums and Constants
    "OutputFormat",
    "ConfigFormat",
    "NodeType",
    "GateType",
    "ElementType",
    "STRIDECategory",
    "BinaryVisualization",
    "ThreatModelEngine",
    "RiskLevel",
    "DEFAULTS",
    "COLORS",
    # Exception hierarchy
    "USecVisLibError",
    "AttackTreeError",
    "AttackGraphError",
    "CustomDiagramError",
    "MermaidError",
    "MermaidCLINotFoundError",
    "MermaidSyntaxError",
    "CloudDiagramError",
    "DiagramsNotInstalledError",
    "IconNotFoundError",
    "ConfigError",
    "FileError",
    "SecurityError",
    "ValidationError",
    "RenderError",
    "AnalysisError",
    # Mermaid support classes
    "MermaidConfig",
    "MermaidResult",
    # Cloud diagram support classes
    "CloudDiagramConfig",
    "CloudNode",
    "CloudEdge",
    "CloudCluster",
    "CloudDiagramResult",
    # Configuration functions
    "ReadTomlFile",
    "merge_dicts",
    "stringify_dict",
    # Security utilities
    "validate_input_path",
    "validate_output_path",
    "validate_image_path",
    "process_node_image",
    "escape_dot_label",
    "sanitize_node_id",
    # Caching utilities
    "cached_result",
    "content_hash",
    "file_hash",
    "StyleManager",
    # Logging
    "configure_logging",
    "get_logger",
    # Batch processing
    "BatchProcessor",
    "BatchResult",
    "process_batch",
    # Export utilities
    "ExportMixin",
    "Exporter",
    "ReportGenerator",
    # Async support
    "AsyncVisualization",
    "async_wrap",
    "AsyncBatchProcessor",
    "process_files_async",
    # Diff/comparison
    "ChangeType",
    "Change",
    "DiffResult",
    "VisualizationDiff",
    "compare_files",
    # CVSS support
    "CVSSVector",
    "CVSSVersion",
    "parse_cvss_vector",
    "calculate_cvss_from_vector",
    "validate_cvss_vector",
    "get_cvss_score",
    # Mermaid support
    "serialize_to_mermaid",
    "detect_visualization_type",
    "MermaidDiagramType",
    "MermaidDirection",
    "MERMAID_FILE_EXTENSION",
    # Settings
    "DisplaySettings",
    "get_settings",
    "is_cvss_enabled",
    "get_cvss_display_settings",
    "set_cvss_display_settings",
    "VisualizationType",
    "DEFAULT_CVSS_DISPLAY",
    # Metadata
    "__version__",
    "__author__",
]
