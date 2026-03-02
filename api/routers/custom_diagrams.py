#
# VULNEX -Universal Security Visualization Library-
#
# File: routers/custom_diagrams.py
# Description: Custom Diagrams API endpoints
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
#

import logging
import os
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, File, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse

from usecvislib import AttackGraphs, AttackTrees, CustomDiagrams, ThreatModeling
from usecvislib.attackgraphs import AttackGraphError
from usecvislib.attacktrees import AttackTreeError
from usecvislib.customdiagrams import CustomDiagramError
from usecvislib.shapes import ShapeRegistry
from usecvislib.utils import ConfigError, FileError, ReadConfigFile

from ..config import (
    CUSTOM_DIAGRAMS_TEMPLATES_DIR,
    ENABLE_TRACEBACK_LOGGING,
    RATE_LIMIT_ANALYZE,
    RATE_LIMIT_DEFAULT,
    RATE_LIMIT_VISUALIZE,
    REQUEST_TIMEOUT_VISUALIZE,
    TEMP_DIR,
    limiter,
)
from ..helpers import (
    cleanup_files,
    get_content_type,
    resolve_image_references,
    run_sync_with_timeout,
    save_upload_file,
    validate_config_file_extension,
    validate_path_component,
    write_config_file,
)
from ..schemas import (
    CustomDiagramLayout,
    CustomDiagramStatsResponse,
    CustomDiagramStyle,
    CustomDiagramValidateResponse,
    OutputFormat,
    ShapeInfo,
    ShapeListResponse,
    TemplateInfo,
    TemplateListResponse,
    VisualizationMode,
)

logger = logging.getLogger("usecvislib.api")

router = APIRouter(tags=["Custom Diagrams"])


@router.get(
    "/custom-diagrams/shapes",
    response_model=ShapeListResponse,
    summary="List available shapes"
)
@limiter.limit(RATE_LIMIT_DEFAULT)
async def list_shapes(
    request: Request,
    category: Optional[str] = Query(default=None, description="Filter by category (basic, flowchart, network, uml, icons, custom)"),
):
    """
    List all available shapes for custom diagrams.

    Shapes are organized into categories:
    - **basic**: Rectangle, ellipse, diamond, etc.
    - **flowchart**: Start, end, decision, process shapes
    - **network**: Router, server, firewall, cloud icons
    - **uml**: Class, interface, actor shapes
    - **icons**: Various icon shapes
    - **custom**: User-defined shapes

    Each shape has properties like fill color, border style, and label positioning.
    """
    registry = ShapeRegistry.get_instance()
    all_shapes = registry.list_shapes()

    shapes = []
    for shape in all_shapes:
        shape_category = shape.category.value if hasattr(shape.category, 'value') else str(shape.category)
        if category and shape_category != category:
            continue

        # Get attributes from graphviz and default_style dictionaries
        graphviz_attrs = shape.graphviz if shape.graphviz else {}
        style_attrs = shape.default_style if shape.default_style else {}

        shapes.append(ShapeInfo(
            id=shape.id,
            name=shape.name,
            category=shape_category,
            description=shape.description or "",
            shape=graphviz_attrs.get("shape", "box"),
            fillcolor=style_attrs.get("fillcolor"),
            bordercolor=style_attrs.get("color") or style_attrs.get("bordercolor"),
            fontcolor=style_attrs.get("fontcolor"),
            style=graphviz_attrs.get("style"),
        ))

    # Get available categories
    categories = list(set(s.category for s in shapes))

    logger.info(f"Listed {len(shapes)} shapes" + (f" in category '{category}'" if category else ""))

    return ShapeListResponse(
        shapes=shapes,
        total=len(shapes),
        categories=sorted(categories)
    )


@router.get(
    "/custom-diagrams/shapes/{shape_id}",
    response_model=ShapeInfo,
    summary="Get shape details"
)
@limiter.limit(RATE_LIMIT_DEFAULT)
async def get_shape(
    request: Request,
    shape_id: str,
):
    """Get detailed information about a specific shape."""
    registry = ShapeRegistry.get_instance()
    shape = registry.get_shape(shape_id)

    if not shape:
        raise HTTPException(status_code=404, detail=f"Shape '{shape_id}' not found")

    shape_category = shape.category.value if hasattr(shape.category, 'value') else str(shape.category)

    # Get attributes from graphviz and default_style dictionaries
    graphviz_attrs = shape.graphviz if shape.graphviz else {}
    style_attrs = shape.default_style if shape.default_style else {}

    return ShapeInfo(
        id=shape.id,
        name=shape.name,
        category=shape_category,
        description=shape.description or "",
        shape=graphviz_attrs.get("shape", "box"),
        fillcolor=style_attrs.get("fillcolor"),
        bordercolor=style_attrs.get("color") or style_attrs.get("bordercolor"),
        fontcolor=style_attrs.get("fontcolor"),
        style=graphviz_attrs.get("style"),
    )


@router.get(
    "/custom-diagrams/templates",
    response_model=TemplateListResponse,
    summary="List custom diagram templates"
)
@limiter.limit(RATE_LIMIT_DEFAULT)
async def list_custom_diagram_templates(
    request: Request,
    category: Optional[str] = Query(default=None, description="Filter by category (general, software, network, security, business)"),
):
    """
    List all available custom diagram templates.

    Templates provide pre-configured schemas and example nodes/edges for common diagram types:

    - **general**: Flowchart, mindmap, hierarchy, timeline
    - **software**: Architecture, class diagram, sequence diagram, component diagram
    - **network**: Network topology, data flow, infrastructure
    - **security**: Risk matrix, incident flow, access control
    - **business**: Process flow, swimlane, org chart

    Each template includes a schema definition, styling, and example elements.
    """
    templates = []

    if not os.path.exists(CUSTOM_DIAGRAMS_TEMPLATES_DIR):
        return TemplateListResponse(templates=[], total=0, categories=[])

    categories_found = set()

    for category_dir in os.listdir(CUSTOM_DIAGRAMS_TEMPLATES_DIR):
        category_path = os.path.join(CUSTOM_DIAGRAMS_TEMPLATES_DIR, category_dir)
        if not os.path.isdir(category_path) or category_dir.startswith('.') or category_dir == '__pycache__':
            continue

        if category and category_dir != category:
            continue

        categories_found.add(category_dir)

        for template_file in os.listdir(category_path):
            if not template_file.endswith('.toml'):
                continue

            template_path = os.path.join(category_path, template_file)
            template_id = os.path.splitext(template_file)[0]

            # Load template to get metadata
            try:
                cd = CustomDiagrams()
                cd.load(template_path)

                templates.append(TemplateInfo(
                    id=f"{category_dir}/{template_id}",
                    name=cd.settings.title if cd.settings else template_id.replace('-', ' ').title(),
                    category=category_dir,
                    description=getattr(cd.settings, 'description', '') if cd.settings else '',
                    filename=template_file,
                    node_count=len(cd.nodes),
                    edge_count=len(cd.edges),
                ))
            except Exception as e:
                logger.warning(f"Failed to load template {template_path}: {e}")
                # Add basic info even if loading fails
                templates.append(TemplateInfo(
                    id=f"{category_dir}/{template_id}",
                    name=template_id.replace('-', ' ').title(),
                    category=category_dir,
                    description='',
                    filename=template_file,
                    node_count=0,
                    edge_count=0,
                ))

    logger.info(f"Listed {len(templates)} custom diagram templates" + (f" in category '{category}'" if category else ""))

    return TemplateListResponse(
        templates=templates,
        total=len(templates),
        categories=sorted(categories_found)
    )


@router.get(
    "/custom-diagrams/templates/{template_id:path}",
    summary="Get custom diagram template content"
)
@limiter.limit(RATE_LIMIT_DEFAULT)
async def get_custom_diagram_template(
    request: Request,
    template_id: str,
):
    """
    Get a specific custom diagram template by ID.

    Template ID format: `category/template_name` (e.g., `software/architecture`)
    """
    # Parse template ID
    parts = template_id.split('/')
    if len(parts) != 2:
        raise HTTPException(status_code=400, detail="Invalid template ID format. Use 'category/template_name'")

    category, template_name = parts

    # SECURITY: Validate each path component to prevent path traversal
    if not validate_path_component(category) or not validate_path_component(template_name):
        logger.warning(f"Path traversal attempt blocked in custom diagram template: {template_id}")
        raise HTTPException(status_code=400, detail="Invalid template ID")

    base_dir = Path(CUSTOM_DIAGRAMS_TEMPLATES_DIR).resolve()
    template_path = Path(CUSTOM_DIAGRAMS_TEMPLATES_DIR) / category / f"{template_name}.toml"

    # SECURITY: Verify path stays within templates directory
    try:
        resolved_path = template_path.resolve()
        if not resolved_path.is_relative_to(base_dir):
            logger.warning(f"Path traversal attempt blocked: {template_id}")
            raise HTTPException(status_code=400, detail="Invalid template ID")
        # SECURITY: Reject symlinks
        if resolved_path.is_symlink():
            logger.warning(f"Symlink rejected: {template_id}")
            raise HTTPException(status_code=400, detail="Invalid template")
    except (ValueError, RuntimeError):
        raise HTTPException(status_code=400, detail="Invalid template ID") from None

    if not resolved_path.exists():
        raise HTTPException(status_code=404, detail=f"Template '{template_id}' not found")

    with open(resolved_path) as f:
        content = f.read()

    logger.info(f"Served custom diagram template: {template_id}")

    return {
        "id": template_id,
        "category": category,
        "name": template_name,
        "format": "toml",
        "content": content
    }


@router.post(
    "/custom-diagrams/visualize",
    summary="Generate custom diagram visualization",
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
async def visualize_custom_diagram(
    request: Request,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(..., description="TOML/JSON/YAML file containing custom diagram definition"),
    format: OutputFormat = Query(default=OutputFormat.PNG, description="Output format"),
    style: CustomDiagramStyle = Query(default=CustomDiagramStyle.DEFAULT, description="Style preset"),
):
    """
    Generate a custom diagram visualization from an uploaded configuration file.

    The configuration file should contain:
    - `[diagram]` section with title, layout, and direction settings
    - `[schema]` section defining node types and edge types
    - `[[nodes]]` array with node instances
    - `[[edges]]` array with edge connections
    - `[[clusters]]` array (optional) for grouping nodes

    Example TOML structure:
    ```toml
    [diagram]
    title = "My Custom Diagram"
    layout = "hierarchical"
    direction = "TB"

    [schema.nodes.process]
    shape = "box"
    fillcolor = "#E3F2FD"

    [[nodes]]
    id = "node1"
    type = "process"
    label = "Process A"

    [[edges]]
    from = "node1"
    to = "node2"
    label = "connects"
    ```
    """
    input_path = None
    output_path = None
    modified_input_path = None

    try:
        validate_config_file_extension(file.filename)
        input_path = save_upload_file(file)
        output_base = os.path.join(TEMP_DIR, f"output_{os.urandom(8).hex()}")

        # Read and parse config to resolve image_id references
        try:
            config_data = ReadConfigFile(input_path)
            config_data = resolve_image_references(config_data)

            # Keep a valid extension for the resolved file
            base, ext = os.path.splitext(input_path)
            modified_input_path = f"{base}_resolved{ext}"
            write_config_file(modified_input_path, config_data, ext)
            input_for_viz = modified_input_path
        except Exception as e:
            logger.debug(f"Image resolution skipped: {e}")
            input_for_viz = input_path

        # Create CustomDiagrams instance and build visualization
        cd = CustomDiagrams()
        cd.load(input_for_viz)

        # Override style if specified via API parameter
        if style and cd.settings:
            cd.settings.style = style.value

        # Build the diagram with timeout protection
        # SECURITY: Prevents resource exhaustion from complex diagrams
        result = await run_sync_with_timeout(
            lambda: cd.BuildCustomDiagram(
                output=output_base,
                output_format=format.value,
                validate=True
            ),
            REQUEST_TIMEOUT_VISUALIZE,
            "custom diagram visualization"
        )
        output_path = result.output_path

        if not output_path or not os.path.exists(output_path):
            cleanup_files(input_path, modified_input_path)
            raise HTTPException(status_code=500, detail="Failed to generate visualization")

        background_tasks.add_task(cleanup_files, input_path, modified_input_path, output_path)

        return FileResponse(
            path=output_path,
            media_type=get_content_type(format),
            filename=f"custom_diagram.{format.value}",
        )

    except CustomDiagramError as e:
        cleanup_files(input_path, modified_input_path, output_path)
        raise HTTPException(status_code=400, detail=str(e)) from e
    except (FileError, ConfigError) as e:
        cleanup_files(input_path, modified_input_path, output_path)
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        cleanup_files(input_path, modified_input_path, output_path)
        logger.error(f"Custom diagram visualization error: {e}")
        logger.error(f"Internal error: {e!s}", exc_info=ENABLE_TRACEBACK_LOGGING)
        raise HTTPException(status_code=500, detail="An internal error occurred") from e


@router.post(
    "/custom-diagrams/validate",
    response_model=CustomDiagramValidateResponse,
    summary="Validate custom diagram configuration"
)
@limiter.limit(RATE_LIMIT_ANALYZE)
async def validate_custom_diagram(
    request: Request,
    file: UploadFile = File(..., description="TOML/JSON/YAML file containing custom diagram definition"),
):
    """
    Validate a custom diagram configuration without generating visualization.

    Checks for:
    - Valid schema structure (node types, edge types)
    - Node references in edges
    - Required fields
    - Type consistency

    Returns validation result with any errors or warnings found.
    """
    input_path = None

    try:
        validate_config_file_extension(file.filename)
        input_path = save_upload_file(file)

        cd = CustomDiagrams()
        cd.load(input_path)
        result = cd.validate(raise_on_error=False)

        return CustomDiagramValidateResponse(
            valid=result.get("valid", False),
            errors=result.get("errors", []),
            warnings=result.get("warnings", []),
            node_count=len(cd.nodes),
            edge_count=len(cd.edges),
            cluster_count=len(cd.clusters) if cd.clusters else 0,
        )

    except CustomDiagramError as e:
        return CustomDiagramValidateResponse(
            valid=False,
            errors=[str(e)],
            warnings=[],
            node_count=0,
            edge_count=0,
            cluster_count=0,
        )
    except (FileError, ConfigError) as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        logger.error(f"Custom diagram validation error: {e}")
        logger.error(f"Internal error: {e!s}", exc_info=ENABLE_TRACEBACK_LOGGING)
        raise HTTPException(status_code=500, detail="An internal error occurred") from e
    finally:
        cleanup_files(input_path)


@router.post(
    "/custom-diagrams/stats",
    response_model=CustomDiagramStatsResponse,
    summary="Get custom diagram statistics"
)
@limiter.limit(RATE_LIMIT_ANALYZE)
async def get_custom_diagram_stats(
    request: Request,
    file: UploadFile = File(..., description="TOML/JSON/YAML file containing custom diagram definition"),
):
    """
    Analyze a custom diagram and return statistics.

    Returns:
    - Node and edge counts
    - Node type distribution
    - Edge type distribution
    - Cluster information
    - Connectivity metrics
    """
    input_path = None

    try:
        validate_config_file_extension(file.filename)
        input_path = save_upload_file(file)

        cd = CustomDiagrams()
        cd.load(input_path)
        cd.validate(raise_on_error=False)
        stats = cd.get_stats()

        return CustomDiagramStatsResponse(
            total_nodes=stats.get("total_nodes", 0),
            total_edges=stats.get("total_edges", 0),
            total_clusters=stats.get("total_clusters", 0),
            node_types=stats.get("node_types", {}),
            edge_types=stats.get("edge_types", {}),
            title=stats.get("title", "Custom Diagram"),
            layout=stats.get("layout", "hierarchical"),
            direction=stats.get("direction", "TB"),
        )

    except CustomDiagramError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except (FileError, ConfigError) as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        logger.error(f"Custom diagram stats error: {e}")
        logger.error(f"Internal error: {e!s}", exc_info=ENABLE_TRACEBACK_LOGGING)
        raise HTTPException(status_code=500, detail="An internal error occurred") from e
    finally:
        cleanup_files(input_path)


@router.post(
    "/custom-diagrams/from-template",
    summary="Create custom diagram from template",
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
async def custom_diagram_from_template(
    request: Request,
    background_tasks: BackgroundTasks,
    template_id: str = Query(..., description="Template ID (e.g., 'software/architecture')"),
    format: OutputFormat = Query(default=OutputFormat.PNG, description="Output format"),
    style: CustomDiagramStyle = Query(default=CustomDiagramStyle.DEFAULT, description="Style preset"),
):
    """
    Generate a custom diagram from a built-in template.

    Use this endpoint to quickly generate example diagrams using pre-defined templates.

    Available templates can be listed using GET /custom-diagrams/templates
    """
    output_path = None

    try:
        # Parse template ID
        parts = template_id.split('/')
        if len(parts) != 2:
            raise HTTPException(status_code=400, detail="Invalid template ID format. Use 'category/template_name'")

        category, template_name = parts

        # SECURITY: Validate each path component to prevent path traversal
        if not validate_path_component(category) or not validate_path_component(template_name):
            logger.warning(f"Path traversal attempt blocked in custom diagram template: {template_id}")
            raise HTTPException(status_code=400, detail="Invalid template ID")

        base_dir = Path(CUSTOM_DIAGRAMS_TEMPLATES_DIR).resolve()
        template_path = Path(CUSTOM_DIAGRAMS_TEMPLATES_DIR) / category / f"{template_name}.toml"

        # SECURITY: Verify resolved path stays within templates directory
        try:
            resolved_path = template_path.resolve()
            if not resolved_path.is_relative_to(base_dir):
                logger.warning(f"Path traversal attempt blocked: {template_id}")
                raise HTTPException(status_code=400, detail="Invalid template ID")
            if resolved_path.is_symlink():
                logger.warning(f"Symlink rejected: {template_id}")
                raise HTTPException(status_code=400, detail="Invalid template")
        except (ValueError, RuntimeError):
            raise HTTPException(status_code=400, detail="Invalid template ID") from None

        if not resolved_path.exists():
            raise HTTPException(status_code=404, detail=f"Template '{template_id}' not found")

        output_base = os.path.join(TEMP_DIR, f"output_{os.urandom(8).hex()}")

        # Create CustomDiagrams instance and build visualization
        cd = CustomDiagrams()
        cd.load(str(resolved_path))

        # Build the diagram with timeout protection
        # SECURITY: Prevents resource exhaustion from complex templates
        result = await run_sync_with_timeout(
            lambda: cd.BuildCustomDiagram(
                output=output_base,
                output_format=format.value,
                validate=True
            ),
            REQUEST_TIMEOUT_VISUALIZE,
            "custom diagram template visualization"
        )
        output_path = result.output_path

        if not output_path or not os.path.exists(output_path):
            raise HTTPException(status_code=500, detail="Failed to generate visualization")

        background_tasks.add_task(cleanup_files, output_path)

        return FileResponse(
            path=output_path,
            media_type=get_content_type(format),
            filename=f"{template_name}.{format.value}",
        )

    except CustomDiagramError as e:
        cleanup_files(output_path)
        raise HTTPException(status_code=400, detail=str(e)) from e
    except HTTPException:
        raise
    except Exception as e:
        cleanup_files(output_path)
        logger.error(f"Custom diagram from template error: {e}")
        logger.error(f"Internal error: {e!s}", exc_info=ENABLE_TRACEBACK_LOGGING)
        raise HTTPException(status_code=500, detail="An internal error occurred") from e


@router.post(
    "/custom-diagrams/import",
    summary="Import from another visualization type",
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
async def import_to_custom_diagram(
    request: Request,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(..., description="Configuration file to import"),
    source_type: VisualizationMode = Query(..., description="Source visualization type"),
    format: OutputFormat = Query(default=OutputFormat.PNG, description="Output format"),
    style: CustomDiagramStyle = Query(default=CustomDiagramStyle.DEFAULT, description="Style preset"),
):
    """
    Import data from another visualization type and render as custom diagram.

    Converts existing visualizations to custom diagram format:
    - **attack_tree**: Converts attack tree nodes and edges
    - **attack_graph**: Converts hosts, vulnerabilities, exploits to nodes
    - **threat_model**: Converts DFD elements (processes, datastores, externals)

    This allows applying custom styling and schema to existing security models.
    """
    input_path = None
    output_path = None

    try:
        validate_config_file_extension(file.filename)
        input_path = save_upload_file(file)
        output_base = os.path.join(TEMP_DIR, f"output_{os.urandom(8).hex()}")

        # Create CustomDiagrams from source type
        cd = CustomDiagrams()

        if source_type == VisualizationMode.ATTACK_TREE:
            at = AttackTrees(input_path, "unused")
            cd.from_attack_tree(at)
        elif source_type == VisualizationMode.ATTACK_GRAPH:
            ag = AttackGraphs(input_path, "unused")
            ag.load()
            cd.from_attack_graph(ag)
        elif source_type == VisualizationMode.THREAT_MODEL:
            tm = ThreatModeling(input_path, "unused")
            tm.load()
            cd.from_threat_model(tm)
        else:
            raise HTTPException(status_code=400, detail=f"Import from '{source_type.value}' is not supported")

        # Build the diagram with timeout protection
        # SECURITY: Prevents resource exhaustion from complex imported diagrams
        result = await run_sync_with_timeout(
            lambda: cd.BuildCustomDiagram(
                output=output_base,
                output_format=format.value,
                validate=True
            ),
            REQUEST_TIMEOUT_VISUALIZE,
            "custom diagram import visualization"
        )
        output_path = result.output_path

        if not output_path or not os.path.exists(output_path):
            cleanup_files(input_path)
            raise HTTPException(status_code=500, detail="Failed to generate visualization")

        background_tasks.add_task(cleanup_files, input_path, output_path)

        return FileResponse(
            path=output_path,
            media_type=get_content_type(format),
            filename=f"imported_diagram.{format.value}",
        )

    except CustomDiagramError as e:
        cleanup_files(input_path, output_path)
        raise HTTPException(status_code=400, detail=str(e)) from e
    except (AttackTreeError, AttackGraphError) as e:
        cleanup_files(input_path, output_path)
        raise HTTPException(status_code=400, detail=str(e)) from e
    except (FileError, ConfigError) as e:
        cleanup_files(input_path, output_path)
        raise HTTPException(status_code=400, detail=str(e)) from e
    except HTTPException:
        raise
    except Exception as e:
        cleanup_files(input_path, output_path)
        logger.error(f"Custom diagram import error: {e}")
        logger.error(f"Internal error: {e!s}", exc_info=ENABLE_TRACEBACK_LOGGING)
        raise HTTPException(status_code=500, detail="An internal error occurred") from e


@router.get(
    "/custom-diagrams/styles",
    summary="Get available custom diagram styles"
)
@limiter.limit(RATE_LIMIT_DEFAULT)
async def get_custom_diagram_styles(request: Request):
    """Get all available style presets for custom diagrams."""
    return {
        "styles": [s.value for s in CustomDiagramStyle],
        "default": CustomDiagramStyle.DEFAULT.value,
        "descriptions": {
            CustomDiagramStyle.DEFAULT.value: "Default clean style with blue tones",
            CustomDiagramStyle.DARK.value: "Dark mode with light text on dark backgrounds",
            CustomDiagramStyle.BLUEPRINT.value: "Technical blueprint style with grid background",
            CustomDiagramStyle.MINIMAL.value: "Minimal black and white style",
            CustomDiagramStyle.NEON.value: "Vibrant neon style with glowing effects",
            CustomDiagramStyle.CORPORATE.value: "Professional corporate styling",
        }
    }


@router.get(
    "/custom-diagrams/layouts",
    summary="Get available layout algorithms"
)
@limiter.limit(RATE_LIMIT_DEFAULT)
async def get_custom_diagram_layouts(request: Request):
    """Get all available layout algorithms for custom diagrams."""
    return {
        "layouts": [l.value for l in CustomDiagramLayout],
        "default": CustomDiagramLayout.HIERARCHICAL.value,
        "descriptions": {
            CustomDiagramLayout.HIERARCHICAL.value: "Top-down or left-right tree layout (dot)",
            CustomDiagramLayout.CIRCULAR.value: "Circular arrangement of nodes (circo)",
            CustomDiagramLayout.FORCE.value: "Force-directed graph layout (neato)",
            CustomDiagramLayout.RADIAL.value: "Radial layout from center (twopi)",
            CustomDiagramLayout.GRID.value: "Grid-based layout (osage)",
        }
    }
