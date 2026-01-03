#
# VULNEX -Universal Security Visualization Library-
#
# File: schemas.py
# Author: Simon Roses Femerling
# Created: 2025-01-01
# Last Modified: 2025-12-27
# Version: 0.3.1
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Pydantic schemas for API request/response models."""

from enum import Enum
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


class OutputFormat(str, Enum):
    """Supported output formats."""
    PNG = "png"
    PDF = "pdf"
    SVG = "svg"


class AttackTreeStyle(str, Enum):
    """Available attack tree styles."""
    DEFAULT = "at_default"
    WHITE_BLACK = "at_white_black"
    BLACK_WHITE = "at_black_white"
    CORPORATE = "at_corporate"
    NEON = "at_neon"
    PASTEL = "at_pastel"
    FOREST = "at_forest"
    FIRE = "at_fire"
    BLUEPRINT = "at_blueprint"
    SUNSET = "at_sunset"
    HACKER = "at_hacker"
    MINIMAL = "at_minimal"
    PLAIN = "at_plain"


class ThreatModelStyle(str, Enum):
    """Available threat modeling styles."""
    DEFAULT = "tm_default"
    STRIDE = "tm_stride"
    DARK = "tm_dark"
    CORPORATE = "tm_corporate"
    NEON = "tm_neon"
    MINIMAL = "tm_minimal"
    OCEAN = "tm_ocean"
    SUNSET = "tm_sunset"
    FOREST = "tm_forest"
    BLUEPRINT = "tm_blueprint"
    HACKER = "tm_hacker"
    PLAIN = "tm_plain"


class ThreatModelEngine(str, Enum):
    """Available threat modeling engines."""
    USECVISLIB = "usecvislib"
    PYTM = "pytm"


class BinVisStyle(str, Enum):
    """Available binary visualization styles."""
    DEFAULT = "bv_default"
    DARK = "bv_dark"
    SECURITY = "bv_security"
    OCEAN = "bv_ocean"
    FOREST = "bv_forest"
    SUNSET = "bv_sunset"
    CYBER = "bv_cyber"
    MINIMAL = "bv_minimal"
    CORPORATE = "bv_corporate"
    FIRE = "bv_fire"
    PURPLE = "bv_purple"
    RAINBOW = "bv_rainbow"


class BinVisType(str, Enum):
    """Binary visualization types."""
    ALL = "all"
    ENTROPY = "entropy"
    DISTRIBUTION = "distribution"
    WINDROSE = "windrose"
    HEATMAP = "heatmap"


# =============================================================================
# Binary Visualization Configuration Schemas
# =============================================================================

class EntropyThreshold(BaseModel):
    """Entropy threshold line configuration."""
    value: float = Field(default=7.5, description="Threshold value (0-8)", ge=0, le=8)
    color: str = Field(default="r", description="Line color (matplotlib color)")
    style: str = Field(default="--", description="Line style (--, -, :, -.)")
    alpha: float = Field(default=0.5, description="Line transparency (0-1)", ge=0, le=1)
    label: str = Field(default="", description="Legend label for threshold")


class EntropyConfig(BaseModel):
    """Configuration for entropy analysis visualization."""
    window_size: int = Field(default=256, description="Sliding window size in bytes", gt=0)
    step: int = Field(default=64, description="Step size for sliding window", gt=0)
    dpi: int = Field(default=150, description="Output image DPI", gt=0)
    show_thresholds: bool = Field(default=True, description="Show threshold lines")
    thresholds: List[EntropyThreshold] = Field(
        default=[
            EntropyThreshold(value=7.5, color="r", style="--", alpha=0.5, label="High entropy (compressed/encrypted)"),
            EntropyThreshold(value=4.0, color="g", style="--", alpha=0.5, label="Medium entropy (code)"),
            EntropyThreshold(value=1.0, color="b", style="--", alpha=0.5, label="Low entropy (sparse data)")
        ],
        description="Threshold lines to display"
    )
    fill_alpha: float = Field(default=0.3, description="Fill area transparency (0-1)", ge=0, le=1)
    show_grid: bool = Field(default=True, description="Show grid lines")
    grid_alpha: float = Field(default=0.3, description="Grid transparency (0-1)", ge=0, le=1)

    class Config:
        json_schema_extra = {
            "example": {
                "window_size": 256,
                "step": 64,
                "show_thresholds": True,
                "fill_alpha": 0.3
            }
        }


class DistributionRegion(BaseModel):
    """Byte distribution region highlight configuration."""
    start: int = Field(default=0, description="Start byte value (0-255)", ge=0, le=255)
    end: int = Field(default=31, description="End byte value (0-255)", ge=0, le=255)
    color: str = Field(default="red", description="Region highlight color")
    alpha: float = Field(default=0.1, description="Region transparency (0-1)", ge=0, le=1)
    label: str = Field(default="", description="Legend label for region")


class ByteDistributionConfig(BaseModel):
    """Configuration for byte distribution visualization."""
    bar_width: float = Field(default=1.0, description="Width of histogram bars", gt=0)
    bar_alpha: float = Field(default=0.7, description="Bar transparency (0-1)", ge=0, le=1)
    dpi: int = Field(default=150, description="Output image DPI", gt=0)
    show_regions: bool = Field(default=True, description="Show region highlights")
    regions: List[DistributionRegion] = Field(
        default=[
            DistributionRegion(start=0, end=31, color="red", alpha=0.1, label="Control chars"),
            DistributionRegion(start=32, end=126, color="green", alpha=0.1, label="Printable ASCII"),
            DistributionRegion(start=127, end=255, color="blue", alpha=0.1, label="Extended")
        ],
        description="Regions to highlight"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "bar_width": 1.0,
                "bar_alpha": 0.7,
                "show_regions": True
            }
        }


class WindRoseConfig(BaseModel):
    """Configuration for wind rose visualization."""
    bar_alpha: float = Field(default=0.7, description="Bar transparency (0-1)", ge=0, le=1)
    dpi: int = Field(default=150, description="Output image DPI", gt=0)
    rticks: List[float] = Field(
        default=[0.25, 0.5, 0.75, 1.0],
        description="Radial tick positions"
    )
    rlabel_position: float = Field(default=0, description="Radial label position in degrees")

    class Config:
        json_schema_extra = {
            "example": {
                "bar_alpha": 0.7,
                "rticks": [0.25, 0.5, 0.75, 1.0]
            }
        }


class HeatmapConfig(BaseModel):
    """Configuration for heatmap visualization."""
    block_size: int = Field(default=256, description="Width of heatmap in bytes", gt=0)
    dpi: int = Field(default=150, description="Output image DPI", gt=0)
    interpolation: str = Field(default="nearest", description="Interpolation method (nearest, bilinear, bicubic)")
    aspect: str = Field(default="auto", description="Aspect ratio (auto, equal)")
    show_colorbar: bool = Field(default=True, description="Show colorbar")
    colorbar_label: str = Field(default="Byte Value", description="Colorbar label text")

    class Config:
        json_schema_extra = {
            "example": {
                "block_size": 256,
                "interpolation": "nearest",
                "show_colorbar": True
            }
        }


class BinVisConfig(BaseModel):
    """Complete binary visualization configuration."""
    entropy_analysis: Optional[EntropyConfig] = Field(default=None, description="Entropy analysis settings")
    byte_distribution: Optional[ByteDistributionConfig] = Field(default=None, description="Byte distribution settings")
    wind_rose: Optional[WindRoseConfig] = Field(default=None, description="Wind rose settings")
    heatmap: Optional[HeatmapConfig] = Field(default=None, description="Heatmap settings")

    class Config:
        json_schema_extra = {
            "example": {
                "entropy_analysis": {
                    "window_size": 512,
                    "step": 128,
                    "show_thresholds": True
                },
                "heatmap": {
                    "block_size": 512,
                    "show_colorbar": True
                }
            }
        }


class AttackGraphStyle(str, Enum):
    """Available attack graph styles."""
    DEFAULT = "ag_default"
    DARK = "ag_dark"
    SECURITY = "ag_security"
    NETWORK = "ag_network"
    MINIMAL = "ag_minimal"
    NEON = "ag_neon"
    CORPORATE = "ag_corporate"
    HACKER = "ag_hacker"
    BLUEPRINT = "ag_blueprint"
    PLAIN = "ag_plain"


class VisualizationMode(str, Enum):
    """Visualization modes."""
    ATTACK_TREE = "attack_tree"
    ATTACK_GRAPH = "attack_graph"
    THREAT_MODEL = "threat_model"
    CUSTOM_DIAGRAM = "custom_diagram"
    BINARY = "binary"


class ConfigFormat(str, Enum):
    """Supported configuration file formats for conversion."""
    TOML = "toml"
    JSON = "json"
    YAML = "yaml"
    MERMAID = "mermaid"


class AttackTreeRequest(BaseModel):
    """Request model for attack tree visualization."""
    format: OutputFormat = Field(default=OutputFormat.PNG, description="Output image format")
    style: AttackTreeStyle = Field(default=AttackTreeStyle.DEFAULT, description="Style preset")

    class Config:
        json_schema_extra = {
            "example": {
                "format": "png",
                "style": "at_default"
            }
        }


class ThreatModelRequest(BaseModel):
    """Request model for threat model visualization."""
    format: OutputFormat = Field(default=OutputFormat.PNG, description="Output image format")
    style: ThreatModelStyle = Field(default=ThreatModelStyle.DEFAULT, description="Style preset")
    engine: ThreatModelEngine = Field(default=ThreatModelEngine.USECVISLIB, description="Threat modeling engine")
    generate_report: bool = Field(default=False, description="Generate STRIDE report")

    class Config:
        json_schema_extra = {
            "example": {
                "format": "png",
                "style": "tm_default",
                "engine": "usecvislib",
                "generate_report": False
            }
        }


class BinaryVisRequest(BaseModel):
    """Request model for binary visualization."""
    format: OutputFormat = Field(default=OutputFormat.PNG, description="Output image format")
    style: BinVisStyle = Field(default=BinVisStyle.DEFAULT, description="Style preset")
    visualization_type: BinVisType = Field(default=BinVisType.ENTROPY, description="Type of visualization")
    config: Optional[BinVisConfig] = Field(
        default=None,
        description="Optional visualization configuration parameters"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "format": "png",
                "style": "bv_default",
                "visualization_type": "entropy",
                "config": {
                    "entropy_analysis": {
                        "window_size": 512,
                        "step": 128
                    }
                }
            }
        }


class CVSSSeverity(str, Enum):
    """CVSS severity levels based on score ranges."""
    CRITICAL = "Critical"  # 9.0 - 10.0
    HIGH = "High"          # 7.0 - 8.9
    MEDIUM = "Medium"      # 4.0 - 6.9
    LOW = "Low"            # 0.1 - 3.9
    NONE = "None"          # 0.0


class VulnerabilityInput(BaseModel):
    """Vulnerability input model with CVSS validation."""
    id: str = Field(description="Unique vulnerability identifier")
    label: str = Field(description="Display label for the vulnerability")
    description: Optional[str] = Field(default=None, description="Detailed description")
    cvss: Optional[float] = Field(
        default=None,
        description="CVSS score (0.0-10.0)",
        ge=0.0,
        le=10.0
    )
    affected_host: Optional[str] = Field(default=None, description="Host ID this vulnerability affects")
    cwe: Optional[str] = Field(default=None, description="CWE identifier (e.g., CWE-79)")

    class Config:
        json_schema_extra = {
            "example": {
                "id": "vuln_sql_injection",
                "label": "SQL Injection",
                "description": "SQL injection vulnerability in login form",
                "cvss": 8.5,
                "affected_host": "webserver",
                "cwe": "CWE-89"
            }
        }


class AttackGraphRequest(BaseModel):
    """Request model for attack graph visualization."""
    format: OutputFormat = Field(default=OutputFormat.PNG, description="Output image format")
    style: AttackGraphStyle = Field(default=AttackGraphStyle.DEFAULT, description="Style preset")

    class Config:
        json_schema_extra = {
            "example": {
                "format": "png",
                "style": "ag_default"
            }
        }


class TemplateMetadata(BaseModel):
    """Template metadata information."""
    name: str = Field(default="", description="Template name")
    description: str = Field(default="", description="Template description")
    engineversion: str = Field(default="", description="USecVisLib engine version compatibility")
    version: str = Field(default="", description="Template file version")
    type: str = Field(default="", description="Template type (Attack Tree, Attack Graph, Threat Model)")
    date: str = Field(default="", description="Template creation date")
    last_modified: str = Field(default="", description="Last modification date")
    author: str = Field(default="", description="Author name")
    email: str = Field(default="", description="Author email")
    url: str = Field(default="", description="Author URL")


class TreeStats(BaseModel):
    """Attack tree statistics response."""
    name: str
    root: str
    total_nodes: int
    total_edges: int
    leaf_nodes: int
    internal_nodes: int
    # CVSS statistics
    nodes_with_cvss: int = Field(default=0, description="Number of nodes with CVSS scores")
    average_cvss: float = Field(default=0.0, description="Average CVSS score across nodes")
    max_cvss: float = Field(default=0.0, description="Maximum CVSS score in tree")
    critical_nodes: int = Field(default=0, description="Number of critical severity nodes (CVSS >= 9.0)")
    high_risk_nodes: int = Field(default=0, description="Number of high risk nodes (CVSS >= 7.0)")
    metadata: Optional[TemplateMetadata] = Field(default=None, description="Template metadata")


class GraphStats(BaseModel):
    """Attack graph statistics response."""
    name: str
    total_hosts: int
    total_vulnerabilities: int
    total_privileges: int
    total_services: int
    total_exploits: int
    network_edges: int
    exploit_edges: int
    total_nodes: int
    total_edges: int
    average_cvss: float
    critical_vulnerabilities: int
    metadata: Optional[TemplateMetadata] = Field(default=None, description="Template metadata")


class CriticalNode(BaseModel):
    """Critical node in attack graph."""
    id: str
    label: str
    type: str
    in_degree: int
    out_degree: int
    total_degree: int
    criticality_score: int


class AttackPath(BaseModel):
    """Attack path result."""
    path: List[str]
    length: int


class AttackPathsResponse(BaseModel):
    """Response for attack path analysis."""
    source: str
    target: str
    paths: List[AttackPath]
    total_paths: int
    shortest_path_length: Optional[int] = None


class ModelStats(BaseModel):
    """Threat model statistics response."""
    total_processes: int
    total_datastores: int
    total_externals: int
    total_dataflows: int
    total_boundaries: int
    flows_crossing_boundaries: int
    total_elements: int
    # CVSS statistics
    total_threats: int = Field(default=0, description="Total number of identified threats")
    threats_with_cvss: int = Field(default=0, description="Number of threats with CVSS scores")
    average_cvss: float = Field(default=0.0, description="Average CVSS score across threats")
    max_cvss: float = Field(default=0.0, description="Maximum CVSS score")
    critical_threats: int = Field(default=0, description="Number of critical severity threats (CVSS >= 9.0)")
    high_threats: int = Field(default=0, description="Number of high severity threats (CVSS >= 7.0)")
    metadata: Optional[TemplateMetadata] = Field(default=None, description="Template metadata")


class FileStats(BaseModel):
    """Binary file statistics response."""
    file_size: int
    entropy: float
    unique_bytes: int
    null_percentage: float
    printable_percentage: float
    high_byte_percentage: float


class StrideCategory(BaseModel):
    """STRIDE threat category."""
    element: str
    threat: str
    mitigation: str
    cvss: Optional[float] = Field(default=None, description="CVSS score for this threat (0.0-10.0)", ge=0.0, le=10.0)
    severity: Optional[str] = Field(default=None, description="Severity label (Critical, High, Medium, Low, None)")


class StrideReport(BaseModel):
    """STRIDE analysis report."""
    model_name: str
    spoofing: List[StrideCategory]
    tampering: List[StrideCategory]
    repudiation: List[StrideCategory]
    information_disclosure: List[StrideCategory]
    denial_of_service: List[StrideCategory]
    elevation_of_privilege: List[StrideCategory]


class ErrorResponse(BaseModel):
    """Error response model."""
    detail: str
    error_type: str

    class Config:
        json_schema_extra = {
            "example": {
                "detail": "Invalid TOML file format",
                "error_type": "ValidationError"
            }
        }


class AuthErrorResponse(BaseModel):
    """Authentication error response."""
    detail: str

    class Config:
        json_schema_extra = {
            "example": {
                "detail": "Missing API key. Include header: X-API-Key: <your-key>"
            }
        }


class HealthResponse(BaseModel):
    """Health check response."""
    status: str
    version: str
    modules: Dict[str, bool]


class ConvertResponse(BaseModel):
    """Format conversion response."""
    content: str = Field(description="Converted file content")
    source_format: str = Field(description="Source format detected")
    target_format: str = Field(description="Target format converted to")
    filename: str = Field(description="Suggested filename for download")

    class Config:
        json_schema_extra = {
            "example": {
                "content": "[tree]\nname = \"Example\"\n",
                "source_format": "json",
                "target_format": "toml",
                "filename": "config.toml"
            }
        }


class ReportFormat(str, Enum):
    """Supported report output formats."""
    MARKDOWN = "markdown"
    HTML = "html"


class ReportResponse(BaseModel):
    """Threat model report response."""
    content: str = Field(description="Report content")
    format: str = Field(description="Report format (markdown or html)")
    filename: str = Field(description="Suggested filename for download")

    class Config:
        json_schema_extra = {
            "example": {
                "content": "# Threat Model Report\n\n...",
                "format": "markdown",
                "filename": "threat_model_report.md"
            }
        }


class ThreatLibraryItem(BaseModel):
    """Single threat from PyTM threat library."""
    id: str = Field(description="Threat identifier")
    description: str = Field(description="Threat description")
    severity: str = Field(description="Threat severity level")
    target: List[str] = Field(default=[], description="Target element types")
    condition: str = Field(default="", description="Condition for threat applicability")
    prerequisites: str = Field(default="", description="Prerequisites for threat")
    mitigations: str = Field(default="", description="Recommended mitigations")
    references: List[str] = Field(default=[], description="Reference links")


class ThreatLibraryResponse(BaseModel):
    """Threat library response."""
    total: int = Field(description="Total number of threats in library")
    threats: List[ThreatLibraryItem] = Field(description="List of threats")
    pytm_available: bool = Field(description="Whether PyTM is installed")


# =============================================================================
# Batch Processing Schemas
# =============================================================================

class BatchItemResult(BaseModel):
    """Result for a single file in batch processing."""
    filename: str = Field(description="Input filename")
    success: bool = Field(description="Whether processing succeeded")
    output_file: Optional[str] = Field(default=None, description="Output filename if successful")
    error: Optional[str] = Field(default=None, description="Error message if failed")
    stats: Optional[Dict[str, Any]] = Field(default=None, description="Statistics if collected")
    image_data: Optional[str] = Field(default=None, description="Base64-encoded image data for download")


class BatchResponse(BaseModel):
    """Batch processing response."""
    total: int = Field(description="Total files processed")
    success_count: int = Field(description="Number of successful files")
    failure_count: int = Field(description="Number of failed files")
    success_rate: float = Field(description="Success rate (0.0 to 1.0)")
    results: List[BatchItemResult] = Field(description="Individual file results")
    aggregate_stats: Optional[Dict[str, Any]] = Field(default=None, description="Aggregate statistics")

    class Config:
        json_schema_extra = {
            "example": {
                "total": 3,
                "success_count": 2,
                "failure_count": 1,
                "success_rate": 0.67,
                "results": [
                    {"filename": "file1.toml", "success": True, "output_file": "file1.png"},
                    {"filename": "file2.toml", "success": True, "output_file": "file2.png"},
                    {"filename": "file3.toml", "success": False, "error": "Invalid format"}
                ]
            }
        }


# =============================================================================
# Export Schemas
# =============================================================================

class ExportFormat(str, Enum):
    """Supported export formats."""
    JSON = "json"
    CSV = "csv"
    YAML = "yaml"
    MARKDOWN = "markdown"
    MERMAID = "mermaid"


class ExportResponse(BaseModel):
    """Export response."""
    content: str = Field(description="Exported content")
    format: str = Field(description="Export format used")
    filename: str = Field(description="Suggested filename")
    rows: Optional[int] = Field(default=None, description="Number of rows (for CSV)")

    class Config:
        json_schema_extra = {
            "example": {
                "content": "[{\"id\": \"host1\", \"label\": \"Web Server\"}]",
                "format": "json",
                "filename": "hosts.json",
                "rows": 5
            }
        }


# =============================================================================
# Diff/Comparison Schemas
# =============================================================================

class ChangeType(str, Enum):
    """Type of change detected."""
    ADDED = "added"
    REMOVED = "removed"
    MODIFIED = "modified"


class ChangeItem(BaseModel):
    """A single change between two versions."""
    change_type: ChangeType = Field(description="Type of change")
    path: str = Field(description="Path to changed element")
    old_value: Optional[Any] = Field(default=None, description="Previous value")
    new_value: Optional[Any] = Field(default=None, description="New value")
    description: Optional[str] = Field(default=None, description="Human-readable description")


class DiffSummary(BaseModel):
    """Summary of changes."""
    added: int = Field(description="Number of additions")
    removed: int = Field(description="Number of removals")
    modified: int = Field(description="Number of modifications")
    total: int = Field(description="Total changes")


class DiffResponse(BaseModel):
    """Diff comparison response."""
    has_changes: bool = Field(description="Whether any changes were detected")
    summary: DiffSummary = Field(description="Summary of changes")
    old_source: Optional[str] = Field(default=None, description="Old file name")
    new_source: Optional[str] = Field(default=None, description="New file name")
    changes: List[ChangeItem] = Field(description="List of all changes")
    report: Optional[str] = Field(default=None, description="Markdown report if requested")

    class Config:
        json_schema_extra = {
            "example": {
                "has_changes": True,
                "summary": {"added": 2, "removed": 1, "modified": 3, "total": 6},
                "old_source": "network_v1.toml",
                "new_source": "network_v2.toml",
                "changes": [
                    {"change_type": "added", "path": "hosts.newserver", "new_value": {"label": "New Server"}}
                ]
            }
        }


# =============================================================================
# Validation Result Schemas
# =============================================================================

class ValidationSeverity(str, Enum):
    """Validation issue severity."""
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


class ValidationIssue(BaseModel):
    """A single validation issue."""
    severity: ValidationSeverity = Field(description="Issue severity")
    message: str = Field(description="Issue message")
    location: Optional[str] = Field(default=None, description="Location in config")
    suggestion: Optional[str] = Field(default=None, description="Suggested fix")


class ValidationResponse(BaseModel):
    """Enhanced validation response."""
    valid: bool = Field(description="Whether config is valid (no errors)")
    error_count: int = Field(description="Number of errors")
    warning_count: int = Field(description="Number of warnings")
    issues: List[ValidationIssue] = Field(description="List of all issues")

    class Config:
        json_schema_extra = {
            "example": {
                "valid": False,
                "error_count": 1,
                "warning_count": 2,
                "issues": [
                    {"severity": "error", "message": "Missing required field 'root'", "location": "[tree]"},
                    {"severity": "warning", "message": "Orphan node detected", "location": "nodes.unused"}
                ]
            }
        }


# =============================================================================
# Display Settings Schemas
# =============================================================================

class CVSSDisplaySettings(BaseModel):
    """CVSS display toggle settings for different visualization types."""
    enabled: bool = Field(
        default=True,
        description="Global toggle - if False, CVSS is hidden in all visualizations"
    )
    attack_tree: bool = Field(
        default=True,
        description="Show CVSS scores and coloring in attack tree visualizations"
    )
    attack_graph: bool = Field(
        default=True,
        description="Show CVSS scores and coloring in attack graph visualizations"
    )
    threat_model: bool = Field(
        default=True,
        description="Show CVSS scores in threat model reports"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "enabled": True,
                "attack_tree": True,
                "attack_graph": True,
                "threat_model": False
            }
        }


class DisplaySettingsRequest(BaseModel):
    """Request model for updating display settings."""
    cvss_display: Optional[CVSSDisplaySettings] = Field(
        default=None,
        description="CVSS display settings"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "cvss_display": {
                    "enabled": True,
                    "attack_tree": True,
                    "attack_graph": False,
                    "threat_model": True
                }
            }
        }


class DisplaySettingsResponse(BaseModel):
    """Response model for display settings."""
    cvss_display: CVSSDisplaySettings = Field(description="Current CVSS display settings")

    class Config:
        json_schema_extra = {
            "example": {
                "cvss_display": {
                    "enabled": True,
                    "attack_tree": True,
                    "attack_graph": True,
                    "threat_model": True
                }
            }
        }


# =============================================================================
# NetworkX Graph Analysis Schemas
# =============================================================================

class CentralityNode(BaseModel):
    """Node with centrality scores."""
    id: str = Field(description="Node identifier")
    label: str = Field(description="Node label")
    type: str = Field(description="Node type (host, vulnerability, etc.)")
    betweenness_centrality: Optional[float] = Field(default=None, description="Betweenness centrality score")
    closeness_centrality: Optional[float] = Field(default=None, description="Closeness centrality score")
    pagerank: Optional[float] = Field(default=None, description="PageRank score")


class CentralityResponse(BaseModel):
    """Response for centrality analysis."""
    nodes: List[CentralityNode] = Field(description="Nodes with centrality scores")
    algorithm: str = Field(description="Algorithm used (betweenness, closeness, pagerank, or all)")
    total_nodes: int = Field(description="Total nodes in graph")

    class Config:
        json_schema_extra = {
            "example": {
                "nodes": [
                    {"id": "webserver", "label": "Web Server", "type": "host", "betweenness_centrality": 0.45}
                ],
                "algorithm": "betweenness",
                "total_nodes": 15
            }
        }


class GraphMetricsResponse(BaseModel):
    """Response for graph metrics analysis."""
    num_nodes: int = Field(description="Total number of nodes")
    num_edges: int = Field(description="Total number of edges")
    density: float = Field(description="Graph density (0 to 1)")
    diameter: Optional[int] = Field(default=None, description="Graph diameter (longest shortest path)")
    num_strongly_connected_components: int = Field(description="Number of SCCs")
    largest_scc_size: int = Field(description="Size of largest SCC")
    num_cycles: int = Field(description="Number of simple cycles")
    is_dag: bool = Field(description="Whether graph is a DAG (no cycles)")
    node_types: Dict[str, int] = Field(description="Count of nodes by type")

    class Config:
        json_schema_extra = {
            "example": {
                "num_nodes": 15,
                "num_edges": 22,
                "density": 0.098,
                "diameter": 5,
                "num_strongly_connected_components": 3,
                "largest_scc_size": 8,
                "num_cycles": 2,
                "is_dag": False,
                "node_types": {"host": 4, "vulnerability": 6, "privilege": 3, "service": 2}
            }
        }


class ChokepointNode(BaseModel):
    """Critical chokepoint node."""
    id: str = Field(description="Node identifier")
    label: str = Field(description="Node label")
    type: str = Field(description="Node type")
    betweenness_score: float = Field(description="Betweenness centrality score")
    in_degree: int = Field(description="Number of incoming edges")
    out_degree: int = Field(description="Number of outgoing edges")
    is_critical: bool = Field(description="Whether node exceeds critical threshold")


class ChokepointsResponse(BaseModel):
    """Response for chokepoint analysis."""
    chokepoints: List[ChokepointNode] = Field(description="Critical chokepoint nodes")
    total_analyzed: int = Field(description="Total nodes analyzed")

    class Config:
        json_schema_extra = {
            "example": {
                "chokepoints": [
                    {"id": "firewall", "label": "Firewall", "type": "host",
                     "betweenness_score": 0.65, "in_degree": 3, "out_degree": 5, "is_critical": True}
                ],
                "total_analyzed": 15
            }
        }


class AttackSurfaceNode(BaseModel):
    """Attack surface entry point node."""
    id: str = Field(description="Node identifier")
    label: str = Field(description="Node label")
    type: str = Field(description="Node type")
    out_degree: int = Field(description="Number of outgoing edges")
    reachable_nodes: int = Field(description="Number of nodes reachable from this entry point")


class AttackSurfaceResponse(BaseModel):
    """Response for attack surface analysis."""
    entry_points: List[AttackSurfaceNode] = Field(description="Attack surface entry points")
    total_attack_surface: int = Field(description="Total number of entry points")

    class Config:
        json_schema_extra = {
            "example": {
                "entry_points": [
                    {"id": "internet", "label": "Internet", "type": "external",
                     "out_degree": 3, "reachable_nodes": 12}
                ],
                "total_attack_surface": 2
            }
        }


class VulnerabilityImpactResponse(BaseModel):
    """Response for vulnerability impact analysis."""
    id: str = Field(description="Vulnerability identifier")
    label: str = Field(description="Vulnerability label")
    cvss: float = Field(description="Base CVSS score")
    reachable_nodes: int = Field(description="Nodes reachable from this vulnerability")
    privilege_targets: int = Field(description="Privilege escalation targets reachable")
    attack_paths_through: int = Field(description="Number of paths through this vulnerability")
    impact_score: float = Field(description="Calculated impact score (0-10)")
    error: Optional[str] = Field(default=None, description="Error message if vulnerability not found")

    class Config:
        json_schema_extra = {
            "example": {
                "id": "rce_vuln",
                "label": "Remote Code Execution",
                "cvss": 9.8,
                "reachable_nodes": 8,
                "privilege_targets": 3,
                "attack_paths_through": 5,
                "impact_score": 10.0
            }
        }


# =============================================================================
# Custom Diagrams Schemas
# =============================================================================

class CustomDiagramStyle(str, Enum):
    """Available custom diagram styles."""
    DEFAULT = "cd_default"
    DARK = "cd_dark"
    BLUEPRINT = "cd_blueprint"
    CORPORATE = "cd_corporate"
    MINIMAL = "cd_minimal"
    NEON = "cd_neon"


class CustomDiagramLayout(str, Enum):
    """Available layout engines for custom diagrams."""
    HIERARCHICAL = "hierarchical"
    RADIAL = "radial"
    FORCE = "force"
    CIRCULAR = "circular"
    GRID = "grid"


class CustomDiagramDirection(str, Enum):
    """Graph direction options."""
    TB = "TB"  # Top to Bottom
    BT = "BT"  # Bottom to Top
    LR = "LR"  # Left to Right
    RL = "RL"  # Right to Left


class ShapeInfo(BaseModel):
    """Shape information."""
    id: str = Field(description="Shape identifier")
    name: str = Field(description="Human-readable name")
    category: str = Field(description="Shape category")
    description: Optional[str] = Field(default=None, description="Shape description")
    shape: str = Field(default="box", description="Graphviz shape type (box, ellipse, diamond, etc.)")
    fillcolor: Optional[str] = Field(default=None, description="Shape fill color")
    bordercolor: Optional[str] = Field(default=None, description="Shape border color")
    fontcolor: Optional[str] = Field(default=None, description="Font color for labels")
    style: Optional[str] = Field(default=None, description="Graphviz style (filled, rounded, etc.)")
    tags: List[str] = Field(default=[], description="Shape tags")
    custom: bool = Field(default=False, description="Whether this is a custom shape")

    class Config:
        json_schema_extra = {
            "example": {
                "id": "server",
                "name": "Server",
                "category": "security",
                "description": "Server or compute instance",
                "shape": "box3d",
                "fillcolor": "#4A90D9",
                "fontcolor": "white",
                "style": "filled",
                "tags": ["infrastructure", "compute"],
                "custom": False
            }
        }


class ShapeListResponse(BaseModel):
    """Response for listing shapes."""
    shapes: List[ShapeInfo] = Field(description="Available shapes")
    total: int = Field(description="Total number of shapes")
    categories: List[str] = Field(description="Available categories")


class TemplateInfo(BaseModel):
    """Template information."""
    id: str = Field(description="Template identifier (category/name)")
    name: str = Field(description="Human-readable name")
    category: str = Field(description="Template category")
    description: Optional[str] = Field(default="", description="Template description")
    filename: str = Field(description="Template filename")
    node_count: int = Field(default=0, description="Number of example nodes in template")
    edge_count: int = Field(default=0, description="Number of example edges in template")

    class Config:
        json_schema_extra = {
            "example": {
                "id": "software/architecture",
                "name": "Architecture",
                "category": "software",
                "description": "Software architecture diagram template",
                "filename": "architecture.toml",
                "node_count": 5,
                "edge_count": 4
            }
        }


class TemplateListResponse(BaseModel):
    """Response for listing templates."""
    templates: List[TemplateInfo] = Field(description="Available templates")
    total: int = Field(description="Total number of templates")
    categories: List[str] = Field(description="Available categories")


class NodeSchema(BaseModel):
    """Node type schema definition."""
    shape: str = Field(description="Shape identifier")
    required_fields: List[str] = Field(default=["name"], description="Required fields")
    optional_fields: List[str] = Field(default=[], description="Optional fields")
    style: Dict[str, str] = Field(default={}, description="Default style attributes")
    label_template: str = Field(default="{name}", description="Label template")

    class Config:
        json_schema_extra = {
            "example": {
                "shape": "server",
                "required_fields": ["name"],
                "optional_fields": ["ip", "os"],
                "style": {"fillcolor": "#3498DB", "fontcolor": "white"},
                "label_template": "{name}"
            }
        }


class EdgeSchema(BaseModel):
    """Edge type schema definition."""
    style: str = Field(default="solid", description="Edge style (solid, dashed, dotted)")
    color: str = Field(default="#333333", description="Edge color")
    arrowhead: str = Field(default="vee", description="Arrow head style")
    label_field: Optional[str] = Field(default=None, description="Field to use for edge label")

    class Config:
        json_schema_extra = {
            "example": {
                "style": "solid",
                "color": "#333333",
                "arrowhead": "vee",
                "label_field": "protocol"
            }
        }


class DiagramNode(BaseModel):
    """Node instance in a diagram."""
    id: str = Field(description="Unique node identifier")
    type: str = Field(description="Node type (must match schema)")
    name: str = Field(description="Node name/label")
    # Additional fields are allowed

    class Config:
        extra = "allow"
        json_schema_extra = {
            "example": {
                "id": "web_server",
                "type": "server",
                "name": "Web Server",
                "ip": "10.0.1.10"
            }
        }


class DiagramEdge(BaseModel):
    """Edge instance in a diagram."""
    from_node: str = Field(alias="from", description="Source node ID")
    to_node: str = Field(alias="to", description="Target node ID")
    type: str = Field(description="Edge type (must match schema)")
    label: Optional[str] = Field(default=None, description="Optional edge label")

    class Config:
        populate_by_name = True
        extra = "allow"
        json_schema_extra = {
            "example": {
                "from": "web_server",
                "to": "database",
                "type": "connection",
                "label": "SQL"
            }
        }


class DiagramCluster(BaseModel):
    """Cluster/subgraph definition."""
    id: str = Field(description="Cluster identifier")
    label: str = Field(description="Cluster label")
    nodes: List[str] = Field(description="Node IDs in this cluster")
    style: Dict[str, str] = Field(default={}, description="Cluster style")

    class Config:
        json_schema_extra = {
            "example": {
                "id": "backend",
                "label": "Backend Services",
                "nodes": ["api", "database", "cache"],
                "style": {"color": "#3498DB", "style": "dashed"}
            }
        }


class DiagramSettings(BaseModel):
    """Diagram settings."""
    title: str = Field(default="Custom Diagram", description="Diagram title")
    description: Optional[str] = Field(default=None, description="Diagram description")
    layout: CustomDiagramLayout = Field(default=CustomDiagramLayout.HIERARCHICAL, description="Layout engine")
    direction: CustomDiagramDirection = Field(default=CustomDiagramDirection.TB, description="Graph direction")
    style: CustomDiagramStyle = Field(default=CustomDiagramStyle.DEFAULT, description="Style preset")
    splines: str = Field(default="ortho", description="Edge routing (ortho, polyline, curved)")
    nodesep: float = Field(default=0.5, description="Node separation", ge=0.1, le=5.0)
    ranksep: float = Field(default=1.0, description="Rank separation", ge=0.1, le=5.0)

    class Config:
        json_schema_extra = {
            "example": {
                "title": "System Architecture",
                "description": "High-level system overview",
                "layout": "hierarchical",
                "direction": "TB",
                "style": "cd_default"
            }
        }


class CustomDiagramSchema(BaseModel):
    """Schema definition for custom diagrams."""
    nodes: Dict[str, NodeSchema] = Field(description="Node type definitions")
    edges: Dict[str, EdgeSchema] = Field(default={}, description="Edge type definitions")

    class Config:
        json_schema_extra = {
            "example": {
                "nodes": {
                    "server": {
                        "shape": "server",
                        "required_fields": ["name"],
                        "style": {"fillcolor": "#3498DB"}
                    }
                },
                "edges": {
                    "connection": {
                        "style": "solid",
                        "color": "#333333"
                    }
                }
            }
        }


class CustomDiagramRequest(BaseModel):
    """Request model for custom diagram visualization."""
    diagram: DiagramSettings = Field(default_factory=DiagramSettings, description="Diagram settings")
    schema_def: CustomDiagramSchema = Field(alias="schema", description="Schema definition")
    nodes: List[DiagramNode] = Field(description="Node instances")
    edges: List[DiagramEdge] = Field(default=[], description="Edge instances")
    clusters: List[DiagramCluster] = Field(default=[], description="Cluster definitions")
    format: OutputFormat = Field(default=OutputFormat.PNG, description="Output format")

    class Config:
        populate_by_name = True
        json_schema_extra = {
            "example": {
                "diagram": {
                    "title": "Simple Architecture",
                    "layout": "hierarchical",
                    "direction": "LR"
                },
                "schema": {
                    "nodes": {
                        "server": {"shape": "server", "required_fields": ["name"]},
                        "database": {"shape": "database", "required_fields": ["name"]}
                    },
                    "edges": {
                        "connection": {"style": "solid", "color": "#333333"}
                    }
                },
                "nodes": [
                    {"id": "web", "type": "server", "name": "Web Server"},
                    {"id": "db", "type": "database", "name": "Database"}
                ],
                "edges": [
                    {"from": "web", "to": "db", "type": "connection"}
                ],
                "format": "png"
            }
        }


class CustomDiagramValidateRequest(BaseModel):
    """Request for validating a custom diagram configuration."""
    diagram: Optional[DiagramSettings] = Field(default=None, description="Diagram settings")
    schema_def: Optional[CustomDiagramSchema] = Field(alias="schema", default=None, description="Schema definition")
    nodes: List[DiagramNode] = Field(default=[], description="Node instances")
    edges: List[DiagramEdge] = Field(default=[], description="Edge instances")
    clusters: List[DiagramCluster] = Field(default=[], description="Cluster definitions")

    class Config:
        populate_by_name = True


class ValidationError(BaseModel):
    """Validation error detail."""
    field: str = Field(description="Field that failed validation")
    message: str = Field(description="Error message")
    severity: str = Field(default="error", description="Severity (error, warning)")


class CustomDiagramValidateResponse(BaseModel):
    """Response for diagram validation."""
    valid: bool = Field(description="Whether the diagram is valid")
    errors: List[str] = Field(default=[], description="Validation errors")
    warnings: List[str] = Field(default=[], description="Validation warnings")
    node_count: int = Field(default=0, description="Number of nodes in diagram")
    edge_count: int = Field(default=0, description="Number of edges in diagram")
    cluster_count: int = Field(default=0, description="Number of clusters in diagram")

    class Config:
        json_schema_extra = {
            "example": {
                "valid": True,
                "errors": [],
                "warnings": ["Node type 'custom' has no required_fields defined"],
                "node_count": 5,
                "edge_count": 4,
                "cluster_count": 1
            }
        }


class CustomDiagramStatsResponse(BaseModel):
    """Statistics about a custom diagram."""
    title: str = Field(default="Custom Diagram", description="Diagram title")
    total_nodes: int = Field(default=0, description="Number of nodes")
    total_edges: int = Field(default=0, description="Number of edges")
    total_clusters: int = Field(default=0, description="Number of clusters")
    node_types: Dict[str, int] = Field(default={}, description="Count by node type")
    edge_types: Dict[str, int] = Field(default={}, description="Count by edge type")
    layout: str = Field(default="hierarchical", description="Layout algorithm")
    direction: str = Field(default="TB", description="Graph direction")

    class Config:
        json_schema_extra = {
            "example": {
                "title": "System Architecture",
                "total_nodes": 5,
                "total_edges": 4,
                "total_clusters": 2,
                "node_types": {"server": 3, "database": 2},
                "edge_types": {"connection": 4},
                "layout": "hierarchical",
                "direction": "TB"
            }
        }


class CustomDiagramFromTemplateRequest(BaseModel):
    """Request to create diagram from template."""
    template_id: str = Field(description="Template identifier (category/name)")
    format: OutputFormat = Field(default=OutputFormat.PNG, description="Output format")

    class Config:
        json_schema_extra = {
            "example": {
                "template_id": "software/architecture",
                "format": "png"
            }
        }


class CustomDiagramImportRequest(BaseModel):
    """Request to import from other visualization types."""
    source_type: str = Field(description="Source type: attack_tree, attack_graph, threat_model")
    format: OutputFormat = Field(default=OutputFormat.PNG, description="Output format")

    class Config:
        json_schema_extra = {
            "example": {
                "source_type": "attack_tree",
                "format": "png"
            }
        }


# =============================================================================
# Image Upload Schemas
# =============================================================================

class ImageUploadResponse(BaseModel):
    """Response from image upload endpoint."""
    image_id: str = Field(description="Unique identifier for the uploaded image")
    filename: str = Field(description="Original filename")
    size: int = Field(description="File size in bytes")
    content_type: str = Field(description="MIME content type")

    class Config:
        json_schema_extra = {
            "example": {
                "image_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                "filename": "server_icon.png",
                "size": 4096,
                "content_type": "image/png"
            }
        }


class ImageInfoResponse(BaseModel):
    """Response with image information."""
    image_id: str = Field(description="Image identifier")
    exists: bool = Field(description="Whether the image exists")
    size: int = Field(description="File size in bytes")
    content_type: str = Field(description="MIME content type")
    created_at: str = Field(description="Creation timestamp (ISO format)")

    class Config:
        json_schema_extra = {
            "example": {
                "image_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                "exists": True,
                "size": 4096,
                "content_type": "image/png",
                "created_at": "2025-12-30T10:30:00Z"
            }
        }


class ImageDeleteResponse(BaseModel):
    """Response from image delete endpoint."""
    deleted: bool = Field(description="Whether the image was successfully deleted")
    image_id: str = Field(description="Image identifier that was deleted")

    class Config:
        json_schema_extra = {
            "example": {
                "deleted": True,
                "image_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
            }
        }


class ImageListResponse(BaseModel):
    """Response listing uploaded images."""
    images: List[ImageInfoResponse] = Field(description="List of uploaded images")
    total: int = Field(description="Total number of images")

    class Config:
        json_schema_extra = {
            "example": {
                "images": [
                    {
                        "image_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                        "exists": True,
                        "size": 4096,
                        "content_type": "image/png",
                        "created_at": "2025-12-30T10:30:00Z"
                    }
                ],
                "total": 1
            }
        }


# =============================================================================
# Bundled Icons Schemas
# =============================================================================

class BundledIconInfo(BaseModel):
    """Information about a bundled icon."""
    id: str = Field(description="Icon identifier (category/subcategory/name)")
    name: str = Field(description="Icon name without extension")
    category: str = Field(description="Icon category (azure, aws, bootstrap)")
    subcategory: Optional[str] = Field(default=None, description="Icon subcategory (e.g., Compute, Database)")
    filename: str = Field(description="Full filename with extension")
    format: str = Field(description="Image format (png, svg, etc.)")
    size: int = Field(description="File size in bytes")

    class Config:
        json_schema_extra = {
            "example": {
                "id": "aws/Compute/EC2",
                "name": "EC2",
                "category": "aws",
                "subcategory": "Compute",
                "filename": "EC2.png",
                "format": "png",
                "size": 4096
            }
        }


class BundledIconsListResponse(BaseModel):
    """Response listing bundled icons with pagination."""
    icons: List[BundledIconInfo] = Field(description="List of bundled icons")
    categories: List[str] = Field(description="Available icon categories")
    subcategories: List[str] = Field(default=[], description="Available subcategories for filtered category")
    total: int = Field(description="Total number of icons matching filters")
    page: int = Field(default=1, description="Current page number")
    page_size: int = Field(default=50, description="Number of icons per page")
    total_pages: int = Field(default=1, description="Total number of pages")
    has_more: bool = Field(default=False, description="Whether more pages are available")

    class Config:
        json_schema_extra = {
            "example": {
                "icons": [
                    {
                        "id": "aws/Compute/EC2",
                        "name": "EC2",
                        "category": "aws",
                        "subcategory": "Compute",
                        "filename": "EC2.png",
                        "format": "png",
                        "size": 4096
                    }
                ],
                "categories": ["azure", "aws", "bootstrap"],
                "subcategories": ["Compute", "Database", "Storage"],
                "total": 311,
                "page": 1,
                "page_size": 50,
                "total_pages": 7,
                "has_more": True
            }
        }


class BundledIconsCategoriesResponse(BaseModel):
    """Response listing bundled icon categories."""
    categories: List[str] = Field(description="Available icon categories")
    counts: Dict[str, int] = Field(description="Number of icons per category")

    class Config:
        json_schema_extra = {
            "example": {
                "categories": ["infrastructure", "security", "threats", "network", "identity"],
                "counts": {
                    "infrastructure": 10,
                    "security": 8,
                    "threats": 5,
                    "network": 7,
                    "identity": 4
                }
            }
        }
