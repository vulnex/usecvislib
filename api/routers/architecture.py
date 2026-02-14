#
# VULNEX -Universal Security Visualization Library-
#
# File: routers/architecture.py
# Description: Architecture Diagram API endpoints (Component Diagram + Dependency Graph)
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
#

import os
import logging

from fastapi import APIRouter, File, UploadFile, Query, BackgroundTasks, Request, HTTPException
from fastapi.responses import FileResponse

from usecvislib import ComponentDiagram, DependencyGraph
from usecvislib.componentdiagram import ComponentDiagramError
from usecvislib.dependencygraph import DependencyGraphError
from usecvislib.utils import FileError, ConfigError, ReadConfigFile

from ..config import (
    limiter, RATE_LIMIT_VISUALIZE, RATE_LIMIT_ANALYZE,
    ENABLE_TRACEBACK_LOGGING, TEMP_DIR,
    REQUEST_TIMEOUT_VISUALIZE,
)
from ..helpers import (
    save_upload_file, cleanup_files, get_content_type,
    validate_config_file_extension, resolve_image_references,
    write_config_file, run_sync_with_timeout,
)
from ..schemas import (
    OutputFormat, ComponentDiagramStyle, DependencyGraphStyle,
    ComponentDiagramStats, DependencyGraphStats, TemplateMetadata,
)

logger = logging.getLogger("usecvislib.api")

router = APIRouter(tags=["Architecture Diagrams"])


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
            "description": "Generated visualization image"
        }
    }
)
@limiter.limit(RATE_LIMIT_VISUALIZE)
async def visualize_component_diagram(
    request: Request,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(..., description="Configuration file containing component diagram definition"),
    format: OutputFormat = Query(default=OutputFormat.PNG, description="Output format"),
    style: ComponentDiagramStyle = Query(default=ComponentDiagramStyle.DEFAULT, description="Style preset"),
):
    """
    Generate a component diagram visualization from an uploaded configuration file.

    The configuration file should contain:
    - `title` field with diagram name
    - `layers[]` array with layer definitions containing components
    - `connections[]` array with connections between components
    """
    input_path = None
    output_path = None
    modified_input_path = None

    try:
        validate_config_file_extension(file.filename)
        input_path = save_upload_file(file)
        output_base = os.path.join(TEMP_DIR, f"output_{os.urandom(8).hex()}")

        try:
            config_data = ReadConfigFile(input_path)
            config_data = resolve_image_references(config_data)
            base, ext = os.path.splitext(input_path)
            modified_input_path = f"{base}_resolved{ext}"
            write_config_file(modified_input_path, config_data, ext)
            input_for_viz = modified_input_path
        except Exception as e:
            logger.debug(f"Image resolution skipped: {e}")
            input_for_viz = input_path

        cd = ComponentDiagram(input_for_viz, output_base, format=format.value, styleid=style.value)
        await run_sync_with_timeout(
            cd.BuildComponentDiagram,
            REQUEST_TIMEOUT_VISUALIZE,
            "component diagram visualization"
        )

        output_path = f"{output_base}.{format.value}"

        if not os.path.exists(output_path):
            cleanup_files(input_path, modified_input_path)
            raise HTTPException(status_code=500, detail="Failed to generate visualization")

        background_tasks.add_task(cleanup_files, input_path, modified_input_path, output_path)

        return FileResponse(
            path=output_path,
            media_type=get_content_type(format),
            filename=f"component_diagram.{format.value}",
        )

    except ComponentDiagramError as e:
        cleanup_files(input_path, modified_input_path, output_path)
        raise HTTPException(status_code=400, detail=str(e))
    except (FileError, ConfigError) as e:
        cleanup_files(input_path, modified_input_path, output_path)
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        cleanup_files(input_path, modified_input_path, output_path)
        logger.error(f"Internal error: {str(e)}", exc_info=ENABLE_TRACEBACK_LOGGING)
        raise HTTPException(status_code=500, detail="An internal error occurred")


@router.post(
    "/analyze/component-diagram",
    response_model=ComponentDiagramStats,
    summary="Analyze component diagram structure"
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
    input_path = None

    try:
        validate_config_file_extension(file.filename)
        input_path = save_upload_file(file)
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

    except ComponentDiagramError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Internal error: {str(e)}", exc_info=ENABLE_TRACEBACK_LOGGING)
        raise HTTPException(status_code=500, detail="An internal error occurred")
    finally:
        cleanup_files(input_path)


@router.post(
    "/validate/component-diagram",
    summary="Validate component diagram structure"
)
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
    input_path = None

    try:
        validate_config_file_extension(file.filename)
        input_path = save_upload_file(file)
        cd = ComponentDiagram(input_path, "unused")
        errors = cd.validate()

        return {
            "valid": len(errors) == 0,
            "errors": errors
        }

    except ComponentDiagramError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Internal error: {str(e)}", exc_info=ENABLE_TRACEBACK_LOGGING)
        raise HTTPException(status_code=500, detail="An internal error occurred")
    finally:
        cleanup_files(input_path)


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
            "description": "Generated visualization image"
        }
    }
)
@limiter.limit(RATE_LIMIT_VISUALIZE)
async def visualize_dependency_graph(
    request: Request,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(..., description="Configuration file containing dependency graph definition"),
    format: OutputFormat = Query(default=OutputFormat.PNG, description="Output format"),
    style: DependencyGraphStyle = Query(default=DependencyGraphStyle.DEFAULT, description="Style preset"),
):
    """
    Generate a dependency graph visualization from an uploaded configuration file.

    The configuration file should contain:
    - `title` field with diagram name
    - `modules[]` array with module definitions
    - `dependencies[]` array with dependency edges
    - `circular[]` array with circular dependency cycles (optional)
    """
    input_path = None
    output_path = None
    modified_input_path = None

    try:
        validate_config_file_extension(file.filename)
        input_path = save_upload_file(file)
        output_base = os.path.join(TEMP_DIR, f"output_{os.urandom(8).hex()}")

        try:
            config_data = ReadConfigFile(input_path)
            config_data = resolve_image_references(config_data)
            base, ext = os.path.splitext(input_path)
            modified_input_path = f"{base}_resolved{ext}"
            write_config_file(modified_input_path, config_data, ext)
            input_for_viz = modified_input_path
        except Exception as e:
            logger.debug(f"Image resolution skipped: {e}")
            input_for_viz = input_path

        dg = DependencyGraph(input_for_viz, output_base, format=format.value, styleid=style.value)
        await run_sync_with_timeout(
            dg.BuildDependencyGraph,
            REQUEST_TIMEOUT_VISUALIZE,
            "dependency graph visualization"
        )

        output_path = f"{output_base}.{format.value}"

        if not os.path.exists(output_path):
            cleanup_files(input_path, modified_input_path)
            raise HTTPException(status_code=500, detail="Failed to generate visualization")

        background_tasks.add_task(cleanup_files, input_path, modified_input_path, output_path)

        return FileResponse(
            path=output_path,
            media_type=get_content_type(format),
            filename=f"dependency_graph.{format.value}",
        )

    except DependencyGraphError as e:
        cleanup_files(input_path, modified_input_path, output_path)
        raise HTTPException(status_code=400, detail=str(e))
    except (FileError, ConfigError) as e:
        cleanup_files(input_path, modified_input_path, output_path)
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        cleanup_files(input_path, modified_input_path, output_path)
        logger.error(f"Internal error: {str(e)}", exc_info=ENABLE_TRACEBACK_LOGGING)
        raise HTTPException(status_code=500, detail="An internal error occurred")


@router.post(
    "/analyze/dependency-graph",
    response_model=DependencyGraphStats,
    summary="Analyze dependency graph structure"
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
    input_path = None

    try:
        validate_config_file_extension(file.filename)
        input_path = save_upload_file(file)
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

    except DependencyGraphError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Internal error: {str(e)}", exc_info=ENABLE_TRACEBACK_LOGGING)
        raise HTTPException(status_code=500, detail="An internal error occurred")
    finally:
        cleanup_files(input_path)


@router.post(
    "/validate/dependency-graph",
    summary="Validate dependency graph structure"
)
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
    input_path = None

    try:
        validate_config_file_extension(file.filename)
        input_path = save_upload_file(file)
        dg = DependencyGraph(input_path, "unused")
        errors = dg.validate()

        return {
            "valid": len(errors) == 0,
            "errors": errors
        }

    except DependencyGraphError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Internal error: {str(e)}", exc_info=ENABLE_TRACEBACK_LOGGING)
        raise HTTPException(status_code=500, detail="An internal error occurred")
    finally:
        cleanup_files(input_path)
