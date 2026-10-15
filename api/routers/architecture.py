#
# VULNEX -Universal Security Visualization Library-
#
# File: routers/architecture.py
# Description: Architecture Diagram API endpoints (Component Diagram + Dependency Graph)
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
#

import logging
import os

from fastapi import APIRouter, BackgroundTasks, File, Query, Request, UploadFile
from fastapi.responses import FileResponse

from usecvislib import ComponentDiagram, DependencyGraph
from usecvislib.componentdiagram import ComponentDiagramError
from usecvislib.dependencygraph import DependencyGraphError
from usecvislib.utils import ConfigError, FileError

from ..config import (
    RATE_LIMIT_ANALYZE,
    RATE_LIMIT_VISUALIZE,
    REQUEST_TIMEOUT_VISUALIZE,
    TEMP_DIR,
    limiter,
)
from ..helpers import (
    TempFiles,
    file_response,
    handle_errors,
    resolve_images_to_temp,
    run_sync_with_timeout,
    save_upload_file,
    validate_config_file_extension,
)
from ..schemas import (
    ComponentDiagramStats,
    ComponentDiagramStyle,
    DependencyGraphStats,
    DependencyGraphStyle,
    OutputFormat,
    RenderEngine,
    TemplateMetadata,
)

logger = logging.getLogger("usecvislib.api")

router = APIRouter(tags=["Architecture Diagrams"])

# Errors in the uploaded definition: reported to the client as 400
_COMPONENT_CLIENT_ERRORS = (ComponentDiagramError, FileError, ConfigError)
_DEPENDENCY_CLIENT_ERRORS = (DependencyGraphError, FileError, ConfigError)


# =============================================================================
# Component Diagram Endpoints
# =============================================================================


@router.post(
    "/visualize/component-diagram",
    summary="Generate component diagram visualization",
    response_class=FileResponse,
    responses={
        200: {
            "content": {
                "image/png": {},
                "image/svg+xml": {},
                "application/pdf": {},
            },
            "description": "Generated visualization image",
        }
    },
)
@limiter.limit(RATE_LIMIT_VISUALIZE)
async def visualize_component_diagram(
    request: Request,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(..., description="Configuration file containing component diagram definition"),
    format: OutputFormat = Query(default=OutputFormat.PNG, description="Output format"),
    style: ComponentDiagramStyle = Query(default=ComponentDiagramStyle.DEFAULT, description="Style preset"),
    render_engine: RenderEngine = Query(
        default=RenderEngine.GRAPHVIZ,
        description="Rendering engine: graphviz (default) or svg (modern cards over a Graphviz-computed layout, sv_* styles)",
    ),
):
    """
    Generate a component diagram visualization from an uploaded configuration file.

    The configuration file should contain:
    - `title` field with diagram name
    - `layers[]` array with layer definitions containing components
    - `connections[]` array with connections between components
    """
    temps = TempFiles()
    with handle_errors(temps, _COMPONENT_CLIENT_ERRORS):
        validate_config_file_extension(file.filename)
        input_path = temps.add(save_upload_file(file))
        output_base = temps.add_prefix(os.path.join(TEMP_DIR, f"output_{os.urandom(8).hex()}"))
        input_for_viz = resolve_images_to_temp(input_path, temps)

        styleid = style.value
        if render_engine == RenderEngine.SVG and style == ComponentDiagramStyle.DEFAULT:
            styleid = ""  # let the engine pick sv_default

        cd = ComponentDiagram(
            input_for_viz, output_base, format=format.value, styleid=styleid, render_engine=render_engine.value
        )
        await run_sync_with_timeout(
            cd.BuildComponentDiagram,
            REQUEST_TIMEOUT_VISUALIZE,
            "component diagram visualization",
            on_abandon=temps.cleanup,
        )

        return file_response(
            f"{output_base}.{format.value}", format, f"component_diagram.{format.value}", temps, background_tasks
        )


@router.post(
    "/analyze/component-diagram", response_model=ComponentDiagramStats, summary="Analyze component diagram structure"
)
@limiter.limit(RATE_LIMIT_ANALYZE)
async def analyze_component_diagram(
    request: Request,
    file: UploadFile = File(..., description="Configuration file containing component diagram definition"),
):
    """
    Analyze a component diagram and return statistics without generating visualization.

    Returns layer counts, component counts, connection counts, and components per layer.
    """
    temps = TempFiles()
    with handle_errors(temps, _COMPONENT_CLIENT_ERRORS):
        validate_config_file_extension(file.filename)
        input_path = temps.add(save_upload_file(file))
        cd = ComponentDiagram(input_path, "unused")
        stats = cd.get_stats()

        metadata_obj = cd.get_metadata()
        stats["metadata"] = TemplateMetadata(
            name=metadata_obj.name,
            description=metadata_obj.description,
            engineversion=metadata_obj.engineversion,
            version=metadata_obj.version,
            type=metadata_obj.type,
            date=metadata_obj.date,
            last_modified=metadata_obj.last_modified,
            author=metadata_obj.author,
            email=metadata_obj.email,
            url=metadata_obj.url,
        )

        return ComponentDiagramStats(**stats)


@router.post("/validate/component-diagram", summary="Validate component diagram structure")
@limiter.limit(RATE_LIMIT_ANALYZE)
async def validate_component_diagram(
    request: Request,
    file: UploadFile = File(..., description="Configuration file containing component diagram definition"),
):
    """
    Validate a component diagram structure and return any errors found.

    Checks for:
    - Missing required sections (layers, components)
    - Undefined component references in connections
    - Unknown component types or connection styles
    """
    temps = TempFiles()
    with handle_errors(temps, _COMPONENT_CLIENT_ERRORS):
        validate_config_file_extension(file.filename)
        input_path = temps.add(save_upload_file(file))
        cd = ComponentDiagram(input_path, "unused")
        errors = cd.validate()

        return {"valid": len(errors) == 0, "errors": errors}


# =============================================================================
# Dependency Graph Endpoints
# =============================================================================


@router.post(
    "/visualize/dependency-graph",
    summary="Generate dependency graph visualization",
    response_class=FileResponse,
    responses={
        200: {
            "content": {
                "image/png": {},
                "image/svg+xml": {},
                "application/pdf": {},
            },
            "description": "Generated visualization image",
        }
    },
)
@limiter.limit(RATE_LIMIT_VISUALIZE)
async def visualize_dependency_graph(
    request: Request,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(..., description="Configuration file containing dependency graph definition"),
    format: OutputFormat = Query(default=OutputFormat.PNG, description="Output format"),
    style: DependencyGraphStyle = Query(default=DependencyGraphStyle.DEFAULT, description="Style preset"),
    render_engine: RenderEngine = Query(
        default=RenderEngine.GRAPHVIZ,
        description="Rendering engine: graphviz (default) or svg (modern cards over a Graphviz-computed layout, sv_* styles)",
    ),
):
    """
    Generate a dependency graph visualization from an uploaded configuration file.

    The configuration file should contain:
    - `title` field with diagram name
    - `modules[]` array with module definitions
    - `dependencies[]` array with dependency edges
    - `circular[]` array with circular dependency cycles (optional)
    """
    temps = TempFiles()
    with handle_errors(temps, _DEPENDENCY_CLIENT_ERRORS):
        validate_config_file_extension(file.filename)
        input_path = temps.add(save_upload_file(file))
        output_base = temps.add_prefix(os.path.join(TEMP_DIR, f"output_{os.urandom(8).hex()}"))
        input_for_viz = resolve_images_to_temp(input_path, temps)

        styleid = style.value
        if render_engine == RenderEngine.SVG and style == DependencyGraphStyle.DEFAULT:
            styleid = ""  # let the engine pick sv_default

        dg = DependencyGraph(
            input_for_viz, output_base, format=format.value, styleid=styleid, render_engine=render_engine.value
        )
        await run_sync_with_timeout(
            dg.BuildDependencyGraph,
            REQUEST_TIMEOUT_VISUALIZE,
            "dependency graph visualization",
            on_abandon=temps.cleanup,
        )

        return file_response(
            f"{output_base}.{format.value}", format, f"dependency_graph.{format.value}", temps, background_tasks
        )


@router.post(
    "/analyze/dependency-graph", response_model=DependencyGraphStats, summary="Analyze dependency graph structure"
)
@limiter.limit(RATE_LIMIT_ANALYZE)
async def analyze_dependency_graph(
    request: Request,
    file: UploadFile = File(..., description="Configuration file containing dependency graph definition"),
):
    """
    Analyze a dependency graph and return statistics without generating visualization.

    Returns module counts, dependency counts, circular dependency counts, and group info.
    """
    temps = TempFiles()
    with handle_errors(temps, _DEPENDENCY_CLIENT_ERRORS):
        validate_config_file_extension(file.filename)
        input_path = temps.add(save_upload_file(file))
        dg = DependencyGraph(input_path, "unused")
        stats = dg.get_stats()

        metadata_obj = dg.get_metadata()
        stats["metadata"] = TemplateMetadata(
            name=metadata_obj.name,
            description=metadata_obj.description,
            engineversion=metadata_obj.engineversion,
            version=metadata_obj.version,
            type=metadata_obj.type,
            date=metadata_obj.date,
            last_modified=metadata_obj.last_modified,
            author=metadata_obj.author,
            email=metadata_obj.email,
            url=metadata_obj.url,
        )

        return DependencyGraphStats(**stats)


@router.post("/validate/dependency-graph", summary="Validate dependency graph structure")
@limiter.limit(RATE_LIMIT_ANALYZE)
async def validate_dependency_graph(
    request: Request,
    file: UploadFile = File(..., description="Configuration file containing dependency graph definition"),
):
    """
    Validate a dependency graph structure and return any errors found.

    Checks for:
    - Missing modules
    - Undefined module references in dependencies
    - Circular references that don't match defined dependencies
    """
    temps = TempFiles()
    with handle_errors(temps, _DEPENDENCY_CLIENT_ERRORS):
        validate_config_file_extension(file.filename)
        input_path = temps.add(save_upload_file(file))
        dg = DependencyGraph(input_path, "unused")
        errors = dg.validate()

        return {"valid": len(errors) == 0, "errors": errors}
