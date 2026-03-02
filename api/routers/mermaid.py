#
# VULNEX -Universal Security Visualization Library-
#
# File: routers/mermaid.py
# Description: Mermaid Diagrams API endpoints
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
#

import logging
import os
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, File, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse

from usecvislib.mermaiddiagrams import MermaidCLINotFoundError, MermaidDiagrams, MermaidError, MermaidSyntaxError

from ..config import (
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
    run_sync_with_timeout,
    save_upload_file,
    validate_path_component,
)
from ..schemas import (
    MermaidDiagramType,
    MermaidOutputFormat,
    MermaidStats,
    MermaidTemplateContentResponse,
    MermaidTemplateInfo,
    MermaidTemplateListResponse,
    MermaidTheme,
    MermaidValidateResponse,
)

logger = logging.getLogger("usecvislib.api")

router = APIRouter(tags=["Mermaid Diagrams"])


@router.post(
    "/visualize/mermaid",
    summary="Render Mermaid diagram",
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
async def visualize_mermaid(
    request: Request,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(..., description="Mermaid source file (.mmd, .toml, .json, .yaml)"),
    format: MermaidOutputFormat = Query(default=MermaidOutputFormat.PNG, description="Output format"),
    theme: MermaidTheme = Query(default=MermaidTheme.DEFAULT, description="Mermaid theme"),
    background: str = Query(default="white", description="Background color (white, transparent, or hex)"),
    width: int = Query(default=800, ge=100, le=4000, description="Output width in pixels"),
    height: int = Query(default=600, ge=100, le=4000, description="Output height in pixels"),
):
    """
    Render a Mermaid diagram from an uploaded file.

    Supports multiple input formats:
    - `.mmd` - Raw Mermaid syntax
    - `.toml`, `.json`, `.yaml` - Configuration files with `[mermaid]` section

    Example TOML structure:
    ```toml
    [mermaid]
    title = "My Diagram"
    theme = "default"
    source = \"\"\"
    flowchart TD
        A[Start] --> B{Decision}
        B -->|Yes| C[End]
    \"\"\"
    ```

    Requires mermaid-cli (mmdc) to be installed:
    ```bash
    npm install -g @mermaid-js/mermaid-cli
    ```
    """
    input_path = None
    output_path = None

    try:
        # Validate file extension
        ext = os.path.splitext(file.filename)[1].lower() if file.filename else ""
        if ext not in {".mmd", ".toml", ".tml", ".json", ".yaml", ".yml"}:
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported file extension: {ext}. Use .mmd, .toml, .json, .yaml"
            )

        # Save uploaded file
        input_path = save_upload_file(file)
        output_base = os.path.join(TEMP_DIR, f"mermaid_{os.urandom(8).hex()}")

        # Create MermaidDiagrams instance
        md = MermaidDiagrams(
            theme=theme.value,
            validate_cli=True
        )

        # Load the file
        md.load(input_path)

        # Render with timeout protection (pass width/height/background to render)
        await run_sync_with_timeout(
            lambda: md.render(
                output_base,
                format=format.value,
                width=width,
                height=height,
                background=background
            ),
            REQUEST_TIMEOUT_VISUALIZE,
            "mermaid rendering"
        )

        output_path = f"{output_base}.{format.value}"

        if not os.path.exists(output_path):
            cleanup_files(input_path)
            raise HTTPException(status_code=500, detail="Failed to generate Mermaid diagram")

        # Schedule cleanup after response is sent
        background_tasks.add_task(cleanup_files, input_path, output_path)

        content_types = {
            "png": "image/png",
            "svg": "image/svg+xml",
            "pdf": "application/pdf"
        }

        return FileResponse(
            path=output_path,
            media_type=content_types.get(format.value, "image/png"),
            filename=f"mermaid_diagram.{format.value}",
        )

    except MermaidCLINotFoundError as e:
        cleanup_files(input_path, output_path)
        raise HTTPException(
            status_code=503,
            detail="Mermaid CLI (mmdc) not installed. Run: npm install -g @mermaid-js/mermaid-cli"
        ) from e
    except MermaidSyntaxError as e:
        cleanup_files(input_path, output_path)
        logger.warning(f"Mermaid syntax error: {e!s}")
        raise HTTPException(status_code=400, detail="Mermaid syntax error in the provided diagram definition") from e
    except MermaidError as e:
        cleanup_files(input_path, output_path)
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        cleanup_files(input_path, output_path)
        logger.error(f"Mermaid rendering error: {e!s}", exc_info=ENABLE_TRACEBACK_LOGGING)
        raise HTTPException(status_code=500, detail="An internal error occurred") from e


@router.post(
    "/analyze/mermaid",
    response_model=MermaidValidateResponse,
    summary="Validate Mermaid diagram"
)
@limiter.limit(RATE_LIMIT_ANALYZE)
async def analyze_mermaid(
    request: Request,
    file: UploadFile = File(..., description="Mermaid source file (.mmd, .toml, .json, .yaml)"),
):
    """
    Validate a Mermaid diagram and return statistics without rendering.

    Returns detected diagram type, line count, and validation errors if any.
    """
    input_path = None

    try:
        # Validate file extension
        ext = os.path.splitext(file.filename)[1].lower() if file.filename else ""
        if ext not in {".mmd", ".toml", ".tml", ".json", ".yaml", ".yml"}:
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported file extension: {ext}. Use .mmd, .toml, .json, .yaml"
            )

        # Save uploaded file
        input_path = save_upload_file(file)

        # Create MermaidDiagrams instance (skip CLI validation for analysis only)
        md = MermaidDiagrams(validate_cli=False)
        md.load(input_path)

        # Get statistics
        stats = md.get_stats()

        # Try to validate if CLI is available
        errors = []
        try:
            md._cli_validated = True
            errors = md.validate()
        except MermaidCLINotFoundError:
            pass  # CLI not available, skip validation

        cleanup_files(input_path)

        return MermaidValidateResponse(
            valid=len(errors) == 0,
            errors=errors,
            diagram_type=stats.get("diagram_type"),
            stats=MermaidStats(
                title=stats.get("title", ""),
                diagram_type=stats.get("diagram_type", "unknown"),
                line_count=stats.get("line_count", 0),
                char_count=stats.get("char_count", 0),
                non_empty_lines=stats.get("non_empty_lines", 0),
                loaded=True
            )
        )

    except MermaidError as e:
        cleanup_files(input_path)
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        cleanup_files(input_path)
        logger.error(f"Mermaid analysis error: {e!s}", exc_info=ENABLE_TRACEBACK_LOGGING)
        raise HTTPException(status_code=500, detail="An internal error occurred") from e


@router.get(
    "/mermaid/templates",
    response_model=MermaidTemplateListResponse,
    summary="List Mermaid templates"
)
@limiter.limit(RATE_LIMIT_DEFAULT)
async def list_mermaid_templates(
    request: Request,
    category: Optional[str] = Query(default=None, description="Filter by category")
):
    """
    List available Mermaid diagram templates.

    Templates are organized by category (flowcharts, sequence, security, etc.)
    """
    try:
        categories = MermaidDiagrams.list_template_categories()
        all_templates = MermaidDiagrams.list_templates(category=category)

        templates = [
            MermaidTemplateInfo(
                name=t.get("name", ""),
                category=t.get("category", ""),
                path=t.get("path", ""),
                diagram_type=t.get("diagram_type")
            )
            for t in all_templates
        ]

        return MermaidTemplateListResponse(
            templates=templates,
            categories=categories,
            total=len(templates)
        )
    except Exception as e:
        logger.error(f"Error listing Mermaid templates: {e!s}", exc_info=ENABLE_TRACEBACK_LOGGING)
        raise HTTPException(status_code=500, detail="Failed to list templates") from e


@router.get(
    "/mermaid/template/{category}/{name}",
    response_model=MermaidTemplateContentResponse,
    summary="Get Mermaid template content"
)
@limiter.limit(RATE_LIMIT_DEFAULT)
async def get_mermaid_template(
    request: Request,
    category: str,
    name: str
):
    """
    Get the content of a specific Mermaid template.

    Returns the template content along with metadata.
    """
    try:
        template_id = f"{category}/{name}"

        # SECURITY: Validate each path component to prevent path traversal
        if not validate_path_component(category) or not validate_path_component(name):
            logger.warning(f"Path traversal attempt blocked in mermaid template: {template_id}")
            raise HTTPException(status_code=400, detail="Invalid template ID")

        templates_dir = MermaidDiagrams.get_templates_dir()
        base_dir = templates_dir.resolve()

        # Try .toml first, then .mmd
        template_path = templates_dir / category / f"{name}.toml"
        if not template_path.exists():
            template_path = templates_dir / category / f"{name}.mmd"

        if not template_path.exists():
            raise HTTPException(status_code=404, detail=f"Template not found: {template_id}")

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

        # Read the template content
        content = resolved_path.read_text()

        # Detect diagram type
        diagram_type = None
        if template_path.suffix == ".mmd":
            # Raw Mermaid file - detect type from content
            first_line = content.strip().split('\n')[0] if content.strip() else ""
            for dtype in ['flowchart', 'graph', 'sequenceDiagram', 'classDiagram',
                         'stateDiagram', 'erDiagram', 'gantt', 'pie', 'mindmap',
                         'timeline', 'gitGraph']:
                if first_line.startswith(dtype):
                    diagram_type = dtype
                    break
        else:
            # TOML file - try to extract mermaid source and detect type
            try:
                import tomllib
                data = tomllib.loads(content)
                source = data.get('mermaid', {}).get('source', '')
                if source:
                    first_line = source.strip().split('\n')[0]
                    for dtype in ['flowchart', 'graph', 'sequenceDiagram', 'classDiagram',
                                 'stateDiagram', 'erDiagram', 'gantt', 'pie', 'mindmap',
                                 'timeline', 'gitGraph']:
                        if first_line.startswith(dtype):
                            diagram_type = dtype
                            break
            except Exception:
                pass

        return MermaidTemplateContentResponse(
            id=template_id,
            name=name.replace("-", " ").title(),
            category=category,
            content=content,
            diagram_type=diagram_type,
            filename=template_path.name
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting Mermaid template: {e!s}", exc_info=ENABLE_TRACEBACK_LOGGING)
        raise HTTPException(status_code=500, detail="Failed to get template") from e


@router.get(
    "/mermaid/themes",
    summary="List Mermaid themes"
)
@limiter.limit(RATE_LIMIT_DEFAULT)
async def list_mermaid_themes(request: Request):
    """
    List available Mermaid themes.
    """
    return {
        "themes": [t.value for t in MermaidTheme],
        "default": MermaidTheme.DEFAULT.value
    }


@router.get(
    "/mermaid/types",
    summary="List Mermaid diagram types"
)
@limiter.limit(RATE_LIMIT_DEFAULT)
async def list_mermaid_types(request: Request):
    """
    List supported Mermaid diagram types.
    """
    return {
        "types": [t.value for t in MermaidDiagramType],
        "descriptions": {
            "flowchart": "Flow charts and process diagrams",
            "graph": "General graphs (alias for flowchart)",
            "sequenceDiagram": "Sequence diagrams for interactions",
            "classDiagram": "UML class diagrams",
            "stateDiagram-v2": "State machine diagrams",
            "erDiagram": "Entity-relationship diagrams",
            "gantt": "Gantt charts for project timelines",
            "pie": "Pie charts",
            "quadrantChart": "Quadrant charts",
            "requirementDiagram": "Requirements diagrams",
            "gitGraph": "Git branch visualization",
            "mindmap": "Mind maps",
            "timeline": "Timeline diagrams",
            "zenuml": "ZenUML sequence diagrams",
            "sankey-beta": "Sankey diagrams",
            "xychart-beta": "XY charts",
            "block-beta": "Block diagrams",
            "packet-beta": "Packet diagrams",
            "kanban": "Kanban boards",
            "architecture-beta": "Architecture diagrams"
        }
    }
