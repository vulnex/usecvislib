#
# VULNEX -Universal Security Visualization Library-
#
# File: routers/utilities.py
# Description: Utility API endpoints (health, styles, formats, engines, convert,
#              reports, threats, batch, export, diff, templates, progress, demo jobs)
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
#

import asyncio
import base64
import json
import logging
import os
import shutil
import time
import uuid
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, File, HTTPException, Query, Request, UploadFile
from fastapi.responses import StreamingResponse

from usecvislib import AttackGraphs, AttackTrees, CustomDiagrams, ThreatModeling
from usecvislib import __version__ as lib_version
from usecvislib.diff import VisualizationDiff
from usecvislib.exporters import Exporter
from usecvislib.threatmodeling import PyTMWrapper
from usecvislib.utils import ConfigError, FileError, ReadConfigFile, detect_format
from usecvislib.utils import convert_format as utils_convert_format

from ..config import (
    ENABLE_TRACEBACK_LOGGING,
    FORMAT_EXTENSIONS,
    RATE_LIMIT_ANALYZE,
    RATE_LIMIT_DEFAULT,
    RATE_LIMIT_VISUALIZE,
    REQUEST_TIMEOUT_VISUALIZE,
    TEMP_DIR,
    TEMPLATE_EXTENSIONS,
    TEMPLATES_DIR,
    limiter,
)
from ..helpers import (
    cleanup_files,
    clear_progress,
    get_progress,
    get_template_format,
    run_sync_with_timeout,
    sanitize_filename_for_log,
    save_upload_file,
    update_progress,
    validate_config_file_extension,
    validate_path_component,
)
from ..schemas import (
    AttackGraphStyle,
    AttackTreeStyle,
    BatchItemResult,
    BatchResponse,
    BinVisStyle,
    ChangeItem,
    ChangeType,
    ConfigFormat,
    ConvertResponse,
    CustomDiagramStyle,
    DiffResponse,
    DiffSummary,
    ExportFormat,
    ExportResponse,
    HealthResponse,
    OutputFormat,
    PrivilegeGradientStyle,
    ReportFormat,
    ReportResponse,
    ThreatLibraryItem,
    ThreatLibraryResponse,
    ThreatModelEngine,
    ThreatModelStyle,
    VisualizationMode,
)

logger = logging.getLogger("usecvislib.api")

router = APIRouter()


# =============================================================================
# Health Check
# =============================================================================


@router.get("/health", response_model=HealthResponse, tags=["System"], summary="Health check endpoint")
@limiter.limit(RATE_LIMIT_DEFAULT)
async def health_check(
    request: Request,
    details: bool = Query(False, description="Include version and module details (may expose sensitive info)"),
):
    """Check API health and module availability.

    Performs runtime checks on critical dependencies (graphviz, temp directory).
    SECURITY: By default, only returns status to prevent information disclosure.
    Pass ?details=true to include version and module information.
    """
    # Runtime dependency checks
    checks_passed = True
    check_details = {}

    # Check graphviz (dot executable)
    graphviz_ok = shutil.which("dot") is not None
    checks_passed = checks_passed and graphviz_ok
    check_details["graphviz"] = graphviz_ok

    # Check temp directory is writable
    try:
        temp_test = os.path.join(TEMP_DIR, ".health_check")
        with open(temp_test, "w") as f:
            f.write("ok")
        os.unlink(temp_test)
        check_details["temp_dir"] = True
    except Exception:
        checks_passed = False
        check_details["temp_dir"] = False

    status = "healthy" if checks_passed else "degraded"

    if details:
        return HealthResponse(
            status=status,
            version=lib_version,
            modules={
                "attack_trees": True,
                "attack_graphs": True,
                "threat_modeling": True,
                "binary_visualization": True,
                "custom_diagrams": True,
                **check_details,
            },
        )
    else:
        # SECURITY: Minimal response to prevent information disclosure
        return HealthResponse(status=status)


# =============================================================================
# Styles, Formats, Engines
# =============================================================================


@router.get("/styles", tags=["Configuration"], summary="Get available styles")
@limiter.limit(RATE_LIMIT_DEFAULT)
async def get_available_styles(request: Request):
    """Get all available style presets for each visualization type."""
    return {
        "attack_tree": [s.value for s in AttackTreeStyle],
        "attack_graph": [s.value for s in AttackGraphStyle],
        "threat_model": [s.value for s in ThreatModelStyle],
        "custom_diagram": [s.value for s in CustomDiagramStyle],
        "binary_visualization": [s.value for s in BinVisStyle],
        "privilege_gradient": [s.value for s in PrivilegeGradientStyle],
    }


@router.get("/formats", tags=["Configuration"], summary="Get supported output formats")
@limiter.limit(RATE_LIMIT_DEFAULT)
async def get_supported_formats(request: Request):
    """Get all supported output formats."""
    return {
        "formats": [f.value for f in OutputFormat],
        "default": OutputFormat.PNG.value,
    }


@router.get("/engines", tags=["Configuration"], summary="Get available threat modeling engines")
@limiter.limit(RATE_LIMIT_DEFAULT)
async def get_available_engines(request: Request):
    """Get all available threat modeling engines and their status."""
    pytm_available = ThreatModeling.is_pytm_available()
    return {
        "engines": [e.value for e in ThreatModelEngine],
        "default": ThreatModelEngine.USECVISLIB.value,
        "pytm_available": pytm_available,
        "descriptions": {
            "usecvislib": "Native USecVisLib engine with custom styling support",
            "pytm": "OWASP PyTM framework for comprehensive threat analysis"
            + (" (not installed)" if not pytm_available else ""),
        },
    }


# =============================================================================
# Format Conversion
# =============================================================================


@router.post(
    "/convert",
    response_model=ConvertResponse,
    tags=["Conversion"],
    summary="Convert configuration file between formats",
)
@limiter.limit(RATE_LIMIT_ANALYZE)
async def convert_config_format(
    request: Request,
    file: UploadFile = File(..., description="Configuration file to convert (TOML, JSON, or YAML)"),
    target_format: ConfigFormat = Query(..., description="Target format to convert to"),
):
    """
    Convert a configuration file from one format to another.

    Supports conversion between:
    - **TOML** (.toml, .tml)
    - **JSON** (.json)
    - **YAML** (.yaml, .yml)
    - **Mermaid** (.mmd) - output only, for diagram generation

    The source format is auto-detected from the file extension.

    Example use cases:
    - Convert YAML threat models to TOML for CLI usage
    - Convert TOML attack trees to JSON for programmatic processing
    - Standardize team configurations to a single format
    - **Export to Mermaid** for browser-based diagrams or documentation

    Note: Mermaid is an output-only format. The diagram type is auto-detected
    from the configuration structure (attack tree, threat model, etc.).
    """
    input_path = None

    try:
        # Validate file extension
        validate_config_file_extension(file.filename)
        input_path = save_upload_file(file)

        # Detect source format from extension
        source_format = detect_format(file.filename)

        # Read file content
        with open(input_path, encoding="utf-8") as f:
            content = f.read()

        # Convert format
        converted_content = utils_convert_format(content, source_format, target_format.value)

        # Generate suggested filename
        base_name = os.path.splitext(file.filename)[0]
        suggested_filename = f"{base_name}{FORMAT_EXTENSIONS[target_format.value]}"

        logger.info(
            f"Converted {sanitize_filename_for_log(file.filename)} from {source_format} to {target_format.value}"
        )

        return ConvertResponse(
            content=converted_content,
            source_format=source_format,
            target_format=target_format.value,
            filename=suggested_filename,
        )

    except (FileError, ConfigError) as e:
        logger.warning(f"Conversion failed: {e}")
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        logger.error(f"Conversion error: {e}")
        logger.error(f"Conversion failed: {e!s}", exc_info=ENABLE_TRACEBACK_LOGGING)
        raise HTTPException(status_code=500, detail="Conversion failed") from e
    finally:
        cleanup_files(input_path)


# =============================================================================
# Report Generation
# =============================================================================


@router.post(
    "/report/threat-model", response_model=ReportResponse, tags=["Reports"], summary="Generate threat model report"
)
@limiter.limit(RATE_LIMIT_ANALYZE)
async def generate_threat_model_report(
    request: Request,
    file: UploadFile = File(..., description="Threat model configuration file (TOML, JSON, or YAML)"),
    format: ReportFormat = Query(ReportFormat.MARKDOWN, description="Report output format"),
):
    """
    Generate a comprehensive threat model report.

    Includes:
    - Executive summary with element counts
    - System components documentation
    - STRIDE threat analysis with mitigations
    - Security property audit

    Supports Markdown and HTML output formats.
    """
    input_path = None

    try:
        validate_config_file_extension(file.filename)
        input_path = save_upload_file(file)

        # Read and parse the configuration
        inputdata = ReadConfigFile(input_path)

        # Create PyTM wrapper and generate report
        wrapper = PyTMWrapper(inputdata, os.path.join(TEMP_DIR, "pytm_output"), "png")

        if format == ReportFormat.MARKDOWN:
            content = wrapper.generate_markdown_report()
            ext = ".md"
        else:
            content = wrapper.generate_html_report()
            ext = ".html"

        base_name = os.path.splitext(file.filename)[0]
        suggested_filename = f"{base_name}_report{ext}"

        logger.info(f"Generated {format.value} report for {sanitize_filename_for_log(file.filename)}")

        return ReportResponse(content=content, format=format.value, filename=suggested_filename)

    except (FileError, ConfigError) as e:
        logger.warning(f"Report generation failed: {e}")
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        logger.error(f"Report generation error: {e}")
        logger.error(f"Report generation failed: {e!s}", exc_info=ENABLE_TRACEBACK_LOGGING)
        raise HTTPException(status_code=500, detail="Report generation failed") from e
    finally:
        cleanup_files(input_path)


# =============================================================================
# Threat Library
# =============================================================================


@router.get(
    "/threats/library", response_model=ThreatLibraryResponse, tags=["Threats"], summary="Get PyTM threat library"
)
@limiter.limit(RATE_LIMIT_DEFAULT)
async def get_threat_library(
    request: Request,
    element_type: Optional[str] = Query(
        None, description="Filter by element type (Process, Server, Datastore, Dataflow, etc.)"
    ),
    limit: int = Query(100, ge=1, le=500, description="Maximum number of threats to return"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
):
    """
    Access PyTM's threat library database.

    The threat library contains hundreds of security threats with:
    - Threat descriptions and severity levels
    - Target element types
    - Prerequisites and conditions
    - Recommended mitigations
    - References

    Use `element_type` to filter threats applicable to specific element types.
    """
    try:
        # Create a minimal wrapper to access threat library
        wrapper = PyTMWrapper({}, os.path.join(TEMP_DIR, "pytm_output"), "png")

        if element_type:
            all_threats = wrapper.get_threats_by_element_type(element_type)
        else:
            all_threats = wrapper.get_threat_library()

        # Apply pagination
        total = len(all_threats)
        paginated = all_threats[offset : offset + limit]

        # Convert to schema objects
        threat_items = []
        for t in paginated:
            target = t.get("target", [])
            if isinstance(target, str):
                target = [target]
            refs = t.get("references", [])
            if isinstance(refs, str):
                refs = [refs] if refs else []

            threat_items.append(
                ThreatLibraryItem(
                    id=str(t.get("id", "")),
                    description=str(t.get("description", "")),
                    severity=str(t.get("severity", "Unknown")),
                    target=target,
                    condition=str(t.get("condition", "")),
                    prerequisites=str(t.get("prerequisites", "")),
                    mitigations=str(t.get("mitigations", "")),
                    references=refs,
                )
            )

        return ThreatLibraryResponse(total=total, threats=threat_items, pytm_available=wrapper._pytm_available)

    except Exception as e:
        logger.error(f"Threat library error: {e}")
        logger.error(f"Failed to access threat library: {e!s}", exc_info=ENABLE_TRACEBACK_LOGGING)
        raise HTTPException(status_code=500, detail="Failed to access threat library") from e


@router.get("/threats/element-types", tags=["Threats"], summary="Get available element types for threat filtering")
@limiter.limit(RATE_LIMIT_DEFAULT)
async def get_threat_element_types(request: Request):
    """
    Get list of element types that can be used to filter the threat library.
    """
    return {
        "element_types": ["Process", "Server", "Lambda", "Datastore", "Dataflow", "Actor", "ExternalEntity", "Boundary"]
    }


# =============================================================================
# Batch Processing
# =============================================================================


@router.post(
    "/batch/visualize",
    response_model=BatchResponse,
    tags=["Batch Processing"],
    summary="Process multiple files in batch",
)
@limiter.limit(RATE_LIMIT_VISUALIZE)
async def batch_visualize(
    request: Request,
    background_tasks: BackgroundTasks,
    files: list[UploadFile] = File(..., description="Multiple configuration files to process"),
    mode: VisualizationMode = Query(..., description="Visualization mode"),
    format: OutputFormat = Query(default=OutputFormat.PNG, description="Output format"),
    style: Optional[str] = Query(default=None, description="Style preset"),
    collect_stats: bool = Query(default=True, description="Collect statistics for each file"),
):
    """
    Process multiple configuration files in batch.

    Upload multiple TOML/JSON/YAML files and process them all at once.
    Returns success/failure status for each file along with aggregate statistics.

    Supported modes:
    - **attack_tree**: Process attack tree configurations
    - **attack_graph**: Process attack graph configurations
    - **threat_model**: Process threat model configurations
    - **custom_diagram**: Process custom diagram configurations
    """
    if len(files) > 20:
        raise HTTPException(status_code=400, detail="Maximum 20 files allowed per batch")

    input_paths = []
    results = []

    try:
        # Save all uploaded files
        for file in files:
            try:
                validate_config_file_extension(file.filename)
                path = save_upload_file(file)
                input_paths.append((file.filename, path))
            except HTTPException as e:
                results.append(BatchItemResult(filename=file.filename, success=False, error=str(e.detail)))

        # Determine module type from mode
        module_map = {
            VisualizationMode.ATTACK_TREE: "attack_tree",
            VisualizationMode.ATTACK_GRAPH: "attack_graph",
            VisualizationMode.THREAT_MODEL: "threat_model",
            VisualizationMode.CUSTOM_DIAGRAM: "custom_diagram",
        }
        module_type = module_map.get(mode)
        if not module_type:
            raise HTTPException(status_code=400, detail=f"Batch processing not supported for mode: {mode.value}")

        # Create output directory for batch
        batch_output_dir = os.path.join(TEMP_DIR, f"batch_{os.urandom(8).hex()}")
        os.makedirs(batch_output_dir, exist_ok=True)

        # Process each file with per-item timeout
        # SECURITY: Prevents single slow file from blocking entire batch
        for filename, input_path in input_paths:
            try:
                output_base = os.path.join(batch_output_dir, os.path.splitext(filename)[0])

                if mode == VisualizationMode.ATTACK_TREE:
                    viz = AttackTrees(input_path, output_base, format=format.value, styleid=style or "at_default")
                    await run_sync_with_timeout(
                        viz.BuildAttackTree, REQUEST_TIMEOUT_VISUALIZE, f"batch attack tree ({filename})"
                    )
                    stats = viz.get_tree_stats() if collect_stats else None
                elif mode == VisualizationMode.ATTACK_GRAPH:
                    viz = AttackGraphs(input_path, output_base, format=format.value, styleid=style or "ag_default")
                    await run_sync_with_timeout(
                        viz.BuildAttackGraph, REQUEST_TIMEOUT_VISUALIZE, f"batch attack graph ({filename})"
                    )
                    stats = viz.get_graph_stats() if collect_stats else None
                elif mode == VisualizationMode.THREAT_MODEL:
                    viz = ThreatModeling(input_path, output_base, format=format.value, styleid=style or "tm_default")
                    await run_sync_with_timeout(
                        viz.BuildThreatModel, REQUEST_TIMEOUT_VISUALIZE, f"batch threat model ({filename})"
                    )
                    stats = viz.get_model_stats() if collect_stats else None
                elif mode == VisualizationMode.CUSTOM_DIAGRAM:
                    cd = CustomDiagrams()
                    cd.load(input_path)
                    # Override style if specified
                    if style and cd.settings:
                        cd.settings.style = style
                    await run_sync_with_timeout(
                        lambda cd=cd, output_base=output_base: cd.BuildCustomDiagram(
                            output=output_base, output_format=format.value
                        ),
                        REQUEST_TIMEOUT_VISUALIZE,
                        f"batch custom diagram ({filename})",
                    )
                    stats = cd.get_stats() if collect_stats else None
                else:
                    stats = None

                output_file = f"{os.path.splitext(filename)[0]}.{format.value}"
                output_path = f"{output_base}.{format.value}"

                # Read the generated file and encode as base64 for download
                image_data = None
                if os.path.exists(output_path):
                    with open(output_path, "rb") as f:
                        image_data = base64.b64encode(f.read()).decode("utf-8")

                results.append(
                    BatchItemResult(
                        filename=filename, success=True, output_file=output_file, stats=stats, image_data=image_data
                    )
                )

            except Exception as e:
                results.append(BatchItemResult(filename=filename, success=False, error=str(e)))

        # Calculate aggregate stats
        success_count = sum(1 for r in results if r.success)
        failure_count = len(results) - success_count
        success_rate = success_count / len(results) if results else 0.0

        # Aggregate stats from successful results
        aggregate_stats = None
        if collect_stats:
            stats_list = [r.stats for r in results if r.success and r.stats]
            if stats_list:
                aggregate_stats = {"file_count": len(stats_list)}
                # Sum up common numeric stats
                for key in ["total_nodes", "total_edges", "total_hosts", "total_vulnerabilities"]:
                    values = [s.get(key, 0) for s in stats_list if key in s]
                    if values:
                        aggregate_stats[key] = sum(values)

        # Schedule cleanup
        background_tasks.add_task(cleanup_files, *[p for _, p in input_paths])
        background_tasks.add_task(shutil.rmtree, batch_output_dir, True)

        return BatchResponse(
            total=len(results),
            success_count=success_count,
            failure_count=failure_count,
            success_rate=success_rate,
            results=results,
            aggregate_stats=aggregate_stats,
        )

    except Exception as e:
        # Cleanup on error
        for _, path in input_paths:
            cleanup_files(path)
        logger.error(f"Batch processing failed: {e!s}", exc_info=ENABLE_TRACEBACK_LOGGING)
        raise HTTPException(status_code=500, detail="Batch processing failed") from e


# =============================================================================
# Export
# =============================================================================


@router.post(
    "/export/data",
    response_model=ExportResponse,
    tags=["Export"],
    summary="Export visualization data to various formats",
)
@limiter.limit(RATE_LIMIT_ANALYZE)
async def export_data(
    request: Request,
    file: UploadFile = File(..., description="Configuration file to export data from"),
    mode: Optional[VisualizationMode] = Query(
        default=None, description="Visualization mode (auto-detected if not specified)"
    ),
    format: ExportFormat = Query(default=ExportFormat.JSON, description="Export format"),
    section: Optional[str] = Query(
        default=None, description="Specific section to export (e.g., 'hosts', 'vulnerabilities')"
    ),
    include_stats: bool = Query(default=True, description="Include statistics in export"),
):
    """
    Export visualization data to JSON, CSV, YAML, Markdown, or Mermaid format.

    Mode is auto-detected from the file content if not specified.

    For attack graphs, available sections include:
    - hosts, vulnerabilities, privileges, services, exploits

    For threat models:
    - processes, datastores, externals, dataflows, boundaries

    For attack trees:
    - nodes, edges
    """
    input_path = None

    try:
        validate_config_file_extension(file.filename)
        input_path = save_upload_file(file)

        # Auto-detect mode if not specified
        if mode is None:
            raw_data = ReadConfigFile(input_path)
            # Detect based on data structure
            if "graph" in raw_data or "hosts" in raw_data or "vulnerabilities" in raw_data:
                mode = VisualizationMode.ATTACK_GRAPH
            elif "model" in raw_data or "dataflows" in raw_data or "processes" in raw_data:
                mode = VisualizationMode.THREAT_MODEL
            elif "tree" in raw_data or ("nodes" in raw_data and "edges" in raw_data):
                mode = VisualizationMode.ATTACK_TREE
            else:
                # Default to attack tree for generic node/edge structures
                mode = VisualizationMode.ATTACK_TREE

        # Load the data based on mode
        if mode == VisualizationMode.ATTACK_TREE:
            viz = AttackTrees(input_path, "unused")
            viz.load()
            data = viz.inputdata
            stats = viz.get_tree_stats() if include_stats else None
        elif mode == VisualizationMode.ATTACK_GRAPH:
            viz = AttackGraphs(input_path, "unused")
            viz.load()
            data = viz.inputdata
            stats = viz.get_graph_stats() if include_stats else None
        elif mode == VisualizationMode.THREAT_MODEL:
            viz = ThreatModeling(input_path, "unused")
            viz.load()
            data = viz.inputdata
            stats = viz.get_model_stats() if include_stats else None
        else:
            raise HTTPException(status_code=400, detail=f"Export not supported for mode: {mode.value}")

        # Extract section if specified
        if section:
            if section not in data:
                available = [k for k in data if isinstance(data[k], (list, dict))]
                raise HTTPException(status_code=400, detail=f"Section '{section}' not found. Available: {available}")
            export_data_content = data[section]
        else:
            export_data_content = {"data": data}
            if stats:
                export_data_content["stats"] = stats

        # Generate filename
        base_name = os.path.splitext(file.filename)[0]
        section_suffix = f"_{section}" if section else ""

        # Export based on format
        rows = None
        if format == ExportFormat.JSON:
            content = Exporter.to_json(export_data_content, pretty=True)
            filename = f"{base_name}{section_suffix}.json"
        elif format == ExportFormat.CSV:
            # CSV only works for list data
            if isinstance(export_data_content, list):
                csv_data = export_data_content
            elif isinstance(export_data_content, dict) and section:
                csv_data = export_data_content if isinstance(export_data_content, list) else [export_data_content]
            else:
                raise HTTPException(
                    status_code=400, detail="CSV export requires a section with list data (e.g., 'hosts', 'nodes')"
                )
            # Write to temp file and read back
            temp_csv = os.path.join(TEMP_DIR, f"export_{os.urandom(4).hex()}.csv")
            rows = Exporter.to_csv(csv_data, temp_csv)
            with open(temp_csv) as f:
                content = f.read()
            cleanup_files(temp_csv)
            filename = f"{base_name}{section_suffix}.csv"
        elif format == ExportFormat.YAML:
            content = Exporter.to_yaml(export_data_content)
            filename = f"{base_name}{section_suffix}.yaml"
        elif format == ExportFormat.MARKDOWN:
            if isinstance(export_data_content, list):
                content = Exporter.to_markdown_table(export_data_content)
            else:
                # Convert dict to simple markdown
                lines = [f"# {base_name} Export\n"]
                if stats:
                    lines.append("## Statistics\n")
                    for k, v in stats.items():
                        lines.append(f"- **{k}**: {v}")
                    lines.append("\n## Data\n")
                lines.append(f"```yaml\n{Exporter.to_yaml(export_data_content)}```")
                content = "\n".join(lines)
            filename = f"{base_name}{section_suffix}.md"
        elif format == ExportFormat.MERMAID:
            # Mermaid export - convert data to Mermaid diagram syntax
            from usecvislib.mermaid import detect_visualization_type, serialize_to_mermaid

            vis_type = detect_visualization_type(data)
            content = serialize_to_mermaid(data, diagram_type=vis_type)
            filename = f"{base_name}{section_suffix}.mmd"
        else:
            raise HTTPException(status_code=400, detail=f"Unknown format: {format.value}")

        logger.info(f"Exported {sanitize_filename_for_log(file.filename)} to {format.value}")

        return ExportResponse(content=content, format=format.value, filename=filename, rows=rows)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Export error: {e}")
        logger.error(f"Export failed: {e!s}", exc_info=ENABLE_TRACEBACK_LOGGING)
        raise HTTPException(status_code=500, detail="Export failed") from e
    finally:
        cleanup_files(input_path)


@router.get("/export/sections", tags=["Export"], summary="Get available export sections for a visualization mode")
async def get_export_sections(mode: VisualizationMode = Query(..., description="Visualization mode")):
    """
    Get the available sections that can be exported for each visualization mode.
    """
    sections = {
        VisualizationMode.ATTACK_TREE: ["tree", "nodes", "edges"],
        VisualizationMode.ATTACK_GRAPH: [
            "graph",
            "hosts",
            "vulnerabilities",
            "privileges",
            "services",
            "exploits",
            "network_edges",
        ],
        VisualizationMode.THREAT_MODEL: ["model", "processes", "datastores", "externals", "dataflows", "boundaries"],
        VisualizationMode.BINARY: [],
    }
    return {"mode": mode.value, "sections": sections.get(mode, []), "note": "Use section=null to export all data"}


# =============================================================================
# Diff/Comparison
# =============================================================================


@router.post(
    "/diff/compare", response_model=DiffResponse, tags=["Comparison"], summary="Compare two configuration files"
)
@limiter.limit(RATE_LIMIT_ANALYZE)
async def compare_configs(
    request: Request,
    old_file: UploadFile = File(..., description="Old/baseline configuration file"),
    new_file: UploadFile = File(..., description="New/updated configuration file"),
    mode: Optional[VisualizationMode] = Query(
        default=None, description="Visualization mode (auto-detected if not provided)"
    ),
    include_report: bool = Query(default=False, description="Include markdown report in response"),
    generate_report: bool = Query(default=False, description="Alias for include_report (for frontend compatibility)"),
    ignore_paths: Optional[str] = Query(
        default=None, description="Comma-separated paths to ignore (e.g., 'metadata,timestamps')"
    ),
):
    """
    Compare two configuration files and identify changes.

    Returns a detailed diff showing:
    - Added elements (new in the updated file)
    - Removed elements (deleted from the old file)
    - Modified elements (changed between versions)

    The visualization mode is auto-detected from the file content if not provided.

    Useful for:
    - Tracking threat model evolution
    - Auditing security configuration changes
    - Version control for attack scenarios
    """
    old_path = None
    new_path = None

    # Support both parameter names for report generation
    should_include_report = include_report or generate_report

    try:
        # Validate and save both files
        validate_config_file_extension(old_file.filename)
        validate_config_file_extension(new_file.filename)

        old_path = save_upload_file(old_file)
        new_path = save_upload_file(new_file)

        # Auto-detect mode if not provided
        if mode is None:
            from usecvislib.mermaid import detect_visualization_type

            old_data = ReadConfigFile(old_path)
            detected_type = detect_visualization_type(old_data)
            logger.info(f"Auto-detected visualization type: {detected_type}")

            if detected_type == "attack_tree":
                mode = VisualizationMode.ATTACK_TREE
            elif detected_type == "attack_graph":
                mode = VisualizationMode.ATTACK_GRAPH
            elif detected_type == "threat_model":
                mode = VisualizationMode.THREAT_MODEL
            else:
                raise HTTPException(
                    status_code=400,
                    detail=f"Could not auto-detect visualization type. Please specify 'mode' parameter. Detected: {detected_type}",
                )

        # Create visualization instances based on mode
        if mode == VisualizationMode.ATTACK_TREE:
            old_viz = AttackTrees(old_path, "old_output", validate_paths=False)
            new_viz = AttackTrees(new_path, "new_output", validate_paths=False)
        elif mode == VisualizationMode.ATTACK_GRAPH:
            old_viz = AttackGraphs(old_path, "old_output", validate_paths=False)
            new_viz = AttackGraphs(new_path, "new_output", validate_paths=False)
        elif mode == VisualizationMode.THREAT_MODEL:
            old_viz = ThreatModeling(old_path, "old_output", validate_paths=False)
            new_viz = ThreatModeling(new_path, "new_output", validate_paths=False)
        else:
            raise HTTPException(status_code=400, detail=f"Comparison not supported for mode: {mode.value}")

        # Parse ignore paths
        ignore_list = None
        if ignore_paths:
            ignore_list = [p.strip() for p in ignore_paths.split(",")]

        # Perform comparison
        diff = VisualizationDiff(old_viz, new_viz)
        result = diff.compare(ignore_paths=ignore_list)

        # Build response
        changes = []
        for change in result.changes:
            changes.append(
                ChangeItem(
                    change_type=ChangeType(change.change_type.value),
                    path=change.path,
                    old_value=change.old_value,
                    new_value=change.new_value,
                    description=change.description,
                )
            )

        summary = DiffSummary(
            added=result.summary["added"],
            removed=result.summary["removed"],
            modified=result.summary["modified"],
            total=result.summary["total"],
        )

        report = None
        if should_include_report:
            report = diff.summary_report(include_details=True)

        logger.info(
            f"Compared {sanitize_filename_for_log(old_file.filename)} vs {sanitize_filename_for_log(new_file.filename)}: {summary.total} changes"
        )

        return DiffResponse(
            has_changes=result.has_changes,
            summary=summary,
            old_source=old_file.filename,
            new_source=new_file.filename,
            changes=changes,
            report=report,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Comparison error: {e}")
        logger.error(f"Comparison failed: {e!s}", exc_info=ENABLE_TRACEBACK_LOGGING)
        raise HTTPException(status_code=500, detail="Comparison failed") from e
    finally:
        cleanup_files(old_path, new_path)


# =============================================================================
# Templates
# =============================================================================


def find_template_file(template_dir: str, template_id: str) -> Optional[str]:
    """Find a template file by ID, checking all supported extensions.

    SECURITY: Validates template_id to prevent path traversal attacks.
    """
    # SECURITY: Validate template_id has no path traversal attempts
    if not validate_path_component(template_id):
        logger.warning(f"Invalid template_id rejected: {template_id}")
        return None

    base_dir = Path(template_dir).resolve()

    for ext in TEMPLATE_EXTENSIONS:
        path = Path(template_dir) / f"{template_id}{ext}"

        # SECURITY: Verify the resolved path stays within template directory
        try:
            resolved = path.resolve()
            if not resolved.is_relative_to(base_dir):
                logger.warning(f"Path traversal attempt blocked: {template_id}")
                return None
            # SECURITY: Reject symlinks
            if resolved.is_symlink():
                logger.warning(f"Symlink rejected: {template_id}")
                return None
            if resolved.exists() and resolved.is_file():
                return str(resolved)
        except (ValueError, RuntimeError):
            continue

    return None


@router.get("/templates", tags=["Templates"], summary="List available templates")
@limiter.limit(RATE_LIMIT_DEFAULT)
async def list_templates(request: Request):
    """List all available templates for attack trees and threat models."""
    templates = {"attack_trees": [], "threat_models": []}

    # Scan attack tree templates
    at_dir = os.path.join(TEMPLATES_DIR, "attack-trees")
    if os.path.exists(at_dir):
        for f in os.listdir(at_dir):
            if f.endswith(TEMPLATE_EXTENSIONS):
                # Extract base name without extension
                base_name = os.path.splitext(f)[0]
                name = base_name.replace("_", " ").title()
                templates["attack_trees"].append(
                    {"id": base_name, "name": name, "filename": f, "format": get_template_format(f)}
                )

    # Scan threat model templates
    tm_dir = os.path.join(TEMPLATES_DIR, "threat-models")
    if os.path.exists(tm_dir):
        for f in os.listdir(tm_dir):
            if f.endswith(TEMPLATE_EXTENSIONS):
                base_name = os.path.splitext(f)[0]
                name = base_name.replace("_", " ").title()
                templates["threat_models"].append(
                    {"id": base_name, "name": name, "filename": f, "format": get_template_format(f)}
                )

    logger.info(
        f"Listed templates: {len(templates['attack_trees'])} attack trees, {len(templates['threat_models'])} threat models"
    )
    return templates


@router.get("/templates/attack-tree/{template_id}", tags=["Templates"], summary="Get attack tree template")
async def get_attack_tree_template(template_id: str):
    """Get a specific attack tree template by ID."""
    template_dir = os.path.join(TEMPLATES_DIR, "attack-trees")
    template_path = find_template_file(template_dir, template_id)

    if not template_path:
        logger.warning(f"Template not found: {template_id}")
        raise HTTPException(status_code=404, detail=f"Template '{template_id}' not found")

    with open(template_path) as f:
        content = f.read()

    filename = os.path.basename(template_path)
    logger.info(f"Served attack tree template: {template_id} ({filename})")
    return {"id": template_id, "type": "attack_tree", "format": get_template_format(filename), "content": content}


@router.get("/templates/threat-model/{template_id}", tags=["Templates"], summary="Get threat model template")
async def get_threat_model_template(template_id: str):
    """Get a specific threat model template by ID."""
    template_dir = os.path.join(TEMPLATES_DIR, "threat-models")
    template_path = find_template_file(template_dir, template_id)

    if not template_path:
        logger.warning(f"Template not found: {template_id}")
        raise HTTPException(status_code=404, detail=f"Template '{template_id}' not found")

    with open(template_path) as f:
        content = f.read()

    filename = os.path.basename(template_path)
    logger.info(f"Served threat model template: {template_id} ({filename})")
    return {"id": template_id, "type": "threat_model", "format": get_template_format(filename), "content": content}


# =============================================================================
# Progress Tracking (SSE)
# =============================================================================


async def progress_event_generator(job_id: str, timeout: int = 60):
    """Generate SSE events for job progress.

    SECURITY: Default timeout reduced from 300s to 60s to prevent connection exhaustion.
    """
    start_time = time.time()
    last_data = None

    while True:
        # Check timeout
        if time.time() - start_time > timeout:
            yield f"data: {json.dumps({'status': 'timeout', 'message': 'Progress tracking timed out'})}\n\n"
            break

        progress = get_progress(job_id)

        if progress:
            # Only send if data changed
            if progress != last_data:
                yield f"data: {json.dumps(progress)}\n\n"
                last_data = progress.copy()

            # If completed or failed, stop streaming
            if progress.get("status") in ("completed", "failed"):
                break

        await asyncio.sleep(0.5)


@router.get("/progress/{job_id}", tags=["System"], summary="Stream job progress via SSE")
@limiter.limit("10/minute")
async def stream_progress(request: Request, job_id: str):
    """
    Stream progress updates for a long-running job using Server-Sent Events (SSE).

    Connect to this endpoint with an EventSource to receive real-time progress updates.

    Example JavaScript:
    ```javascript
    const eventSource = new EventSource('/progress/job-123');
    eventSource.onmessage = (event) => {
        const progress = JSON.parse(event.data);
        console.log(`${progress.step}: ${progress.percentage}%`);
    };
    ```
    """
    logger.info(f"SSE connection opened for job: {job_id}")
    return StreamingResponse(
        progress_event_generator(job_id),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive", "X-Accel-Buffering": "no"},
    )


@router.post("/jobs/start-demo", tags=["System"], summary="Start a demo job for testing progress")
@limiter.limit(RATE_LIMIT_DEFAULT)
async def start_demo_job(request: Request, background_tasks: BackgroundTasks):
    """
    Start a demo job that simulates a long-running operation.
    Returns a job_id that can be used to track progress via /progress/{job_id}.

    SECURITY: Job IDs use full UUIDs to prevent enumeration attacks.
    """
    # SECURITY: Use full UUID to prevent job ID enumeration
    job_id = f"demo-{uuid.uuid4().hex}"

    async def demo_job():
        steps = ["Initializing", "Processing", "Analyzing", "Generating", "Finalizing"]
        for i, step in enumerate(steps):
            update_progress(job_id, step, (i + 1) * 20, 100, "running")
            await asyncio.sleep(1)
        update_progress(job_id, "Complete", 100, 100, "completed")
        await asyncio.sleep(5)  # Keep result for 5 seconds
        clear_progress(job_id)

    # Run in background (fire-and-forget demo job)
    asyncio.create_task(demo_job())  # noqa: RUF006

    logger.info(f"Started demo job: {job_id}")
    return {"job_id": job_id, "progress_url": f"/progress/{job_id}"}
