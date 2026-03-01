#
# VULNEX -Universal Security Visualization Library-
#
# File: routers/cloud.py
# Description: Cloud Diagrams API endpoints
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
#

import os
import logging
from typing import Optional

from fastapi import APIRouter, File, UploadFile, Query, BackgroundTasks, Request, HTTPException
from fastapi.responses import FileResponse

from usecvislib.clouddiagrams import CloudDiagrams, CloudDiagramError, DiagramsNotInstalledError, IconNotFoundError

from ..config import (
    limiter, RATE_LIMIT_VISUALIZE, RATE_LIMIT_ANALYZE, RATE_LIMIT_DEFAULT,
    ENABLE_TRACEBACK_LOGGING, TEMP_DIR,
    REQUEST_TIMEOUT_VISUALIZE,
)
from ..helpers import (
    save_upload_file, cleanup_files, validate_config_file_extension,
    run_sync_with_timeout, sanitize_filename_for_log,
    validate_path_component,
)
from ..schemas import (
    CloudProvider, CloudOutputFormat, CloudDiagramDirection,
    CloudStats, CloudValidateResponse,
    CloudIconInfo, CloudIconsListResponse,
    CloudProvidersResponse,
    CloudTemplateInfo, CloudTemplateListResponse,
    CloudTemplateContentResponse, CloudPythonCodeResponse,
)

logger = logging.getLogger("usecvislib.api")

router = APIRouter(tags=["Cloud Diagrams"])


@router.post(
    "/visualize/cloud",
    summary="Render cloud architecture diagram",
    response_class=FileResponse,
    responses={
        200: {
            "content": {
                "image/png": {},
                "image/svg+xml": {},
                "application/pdf": {},
            },
            "description": "Generated cloud diagram image"
        }
    }
)
@limiter.limit(RATE_LIMIT_VISUALIZE)
async def visualize_cloud(
    request: Request,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(..., description="Cloud diagram config file (.toml, .json, .yaml)"),
    format: CloudOutputFormat = Query(default=CloudOutputFormat.PNG, description="Output format"),
    direction: CloudDiagramDirection = Query(default=CloudDiagramDirection.TB, description="Layout direction"),
    show_legend: bool = Query(default=False, description="Show diagram legend"),
):
    """
    Render a cloud architecture diagram from an uploaded configuration file.

    Supports providers: AWS, Azure, GCP, Kubernetes, On-Premise, and more.

    Example TOML structure:
    ```toml
    [cloud]
    title = "AWS Web Application"
    direction = "LR"

    [[cloud.nodes]]
    id = "lb"
    label = "Load Balancer"
    provider = "aws"
    service = "network.ELB"

    [[cloud.nodes]]
    id = "web"
    label = "Web Servers"
    provider = "aws"
    service = "compute.EC2"

    [[cloud.edges]]
    from = "lb"
    to = "web"
    label = "HTTP"
    ```

    Requires the `diagrams` Python package:
    ```bash
    pip install diagrams
    ```
    """
    input_path = None
    output_path = None

    try:
        # Validate file extension
        validate_config_file_extension(file.filename)

        # Save uploaded file
        input_path = save_upload_file(file)
        output_base = os.path.join(TEMP_DIR, f"cloud_{os.urandom(8).hex()}")

        # Create CloudDiagrams instance
        cd = CloudDiagrams(validate_diagrams=True)

        # Load the file
        cd.load(input_path)

        # Override direction if specified (after load, which sets from config)
        if direction:
            cd.config.direction = direction.value

        # Render with timeout protection (show=False to not open viewer)
        await run_sync_with_timeout(
            lambda: cd.render(
                output_base,
                format=format.value if format != CloudOutputFormat.DOT else "png",
                show=False
            ),
            REQUEST_TIMEOUT_VISUALIZE,
            "cloud diagram rendering"
        )

        # Determine actual output path (diagrams library adds extension)
        if format == CloudOutputFormat.DOT:
            # For DOT format, generate the .dot file
            dot_path = f"{output_base}.dot"
            cd.save_python(dot_path.replace('.dot', '.py'))  # Save Python code as alternative
            output_path = f"{output_base}.png"  # diagrams creates png
        else:
            output_path = f"{output_base}.{format.value}"

        if not os.path.exists(output_path):
            cleanup_files(input_path)
            raise HTTPException(status_code=500, detail="Failed to generate cloud diagram")

        # Schedule cleanup after response is sent
        background_tasks.add_task(cleanup_files, input_path, output_path)

        content_types = {
            "png": "image/png",
            "jpg": "image/jpeg",
            "svg": "image/svg+xml",
            "pdf": "application/pdf",
            "dot": "text/plain"
        }

        return FileResponse(
            path=output_path,
            media_type=content_types.get(format.value, "image/png"),
            filename=f"cloud_diagram.{format.value}",
        )

    except DiagramsNotInstalledError as e:
        cleanup_files(input_path, output_path)
        raise HTTPException(
            status_code=503,
            detail="Python diagrams library not installed. Run: pip install diagrams"
        )
    except IconNotFoundError as e:
        cleanup_files(input_path, output_path)
        raise HTTPException(status_code=400, detail=f"Icon not found: {str(e)}")
    except CloudDiagramError as e:
        cleanup_files(input_path, output_path)
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        cleanup_files(input_path, output_path)
        logger.error(f"Cloud diagram rendering error: {str(e)}", exc_info=ENABLE_TRACEBACK_LOGGING)
        raise HTTPException(status_code=500, detail="An internal error occurred")


@router.post(
    "/analyze/cloud",
    response_model=CloudValidateResponse,
    summary="Validate cloud diagram"
)
@limiter.limit(RATE_LIMIT_ANALYZE)
async def analyze_cloud(
    request: Request,
    file: UploadFile = File(..., description="Cloud diagram config file (.toml, .json, .yaml)"),
):
    """
    Validate a cloud diagram configuration and return statistics without rendering.

    Returns node count, edge count, cluster count, and validation errors.
    """
    input_path = None

    try:
        # Validate file extension
        validate_config_file_extension(file.filename)

        # Save uploaded file
        input_path = save_upload_file(file)

        # Create CloudDiagrams instance
        cd = CloudDiagrams(validate_diagrams=False)
        cd.load(input_path)

        # Get statistics
        stats = cd.get_stats()

        # Validate configuration
        errors = cd.validate()

        cleanup_files(input_path)

        return CloudValidateResponse(
            valid=len(errors) == 0,
            errors=errors,
            stats=CloudStats(
                title=stats.get("title", ""),
                node_count=stats.get("node_count", 0),
                edge_count=stats.get("edge_count", 0),
                cluster_count=stats.get("cluster_count", 0),
                providers_used=stats.get("providers_used", []),
                loaded=True
            )
        )

    except CloudDiagramError as e:
        cleanup_files(input_path)
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        cleanup_files(input_path)
        logger.error(f"Cloud diagram analysis error: {str(e)}", exc_info=ENABLE_TRACEBACK_LOGGING)
        raise HTTPException(status_code=500, detail="An internal error occurred")


@router.get(
    "/cloud/providers",
    response_model=CloudProvidersResponse,
    summary="List cloud providers"
)
@limiter.limit(RATE_LIMIT_DEFAULT)
async def list_cloud_providers(request: Request):
    """
    List all available cloud providers for diagrams.
    """
    try:
        providers = CloudDiagrams.list_providers()
        return CloudProvidersResponse(providers=providers)
    except DiagramsNotInstalledError:
        # Return static list if diagrams not installed
        return CloudProvidersResponse(providers=[
            {"name": "aws", "description": "Amazon Web Services"},
            {"name": "azure", "description": "Microsoft Azure"},
            {"name": "gcp", "description": "Google Cloud Platform"},
            {"name": "k8s", "description": "Kubernetes"},
            {"name": "onprem", "description": "On-Premises"},
            {"name": "alibabacloud", "description": "Alibaba Cloud"},
            {"name": "oci", "description": "Oracle Cloud Infrastructure"},
            {"name": "digitalocean", "description": "DigitalOcean"},
            {"name": "openstack", "description": "OpenStack"},
            {"name": "firebase", "description": "Firebase"},
            {"name": "generic", "description": "Generic icons"},
            {"name": "programming", "description": "Programming languages"},
            {"name": "saas", "description": "SaaS services"},
        ])


@router.get(
    "/cloud/icons",
    response_model=CloudIconsListResponse,
    summary="List cloud diagram icons"
)
@limiter.limit(RATE_LIMIT_DEFAULT)
async def list_cloud_icons(
    request: Request,
    provider: CloudProvider = Query(..., description="Cloud provider"),
    category: Optional[str] = Query(default=None, description="Filter by category (e.g., compute, database)")
):
    """
    List available icons for a specific cloud provider.

    Use the `category` parameter to filter by service category
    (e.g., compute, database, network, storage).
    """
    try:
        icons_list = CloudDiagrams.list_icons(provider.value, category=category)
        icons = [
            CloudIconInfo(
                name=icon.get("name", ""),
                provider=provider.value,
                category=icon.get("category", ""),
                full_path=icon.get("full_path", "")
            )
            for icon in icons_list
        ]
        return CloudIconsListResponse(
            icons=icons,
            provider=provider.value,
            category=category,
            total=len(icons)
        )
    except DiagramsNotInstalledError:
        raise HTTPException(
            status_code=503,
            detail="Python diagrams library not installed. Run: pip install diagrams"
        )
    except Exception as e:
        logger.error(f"Error listing cloud icons: {str(e)}", exc_info=ENABLE_TRACEBACK_LOGGING)
        raise HTTPException(status_code=500, detail="Failed to list icons")


@router.get(
    "/cloud/templates",
    response_model=CloudTemplateListResponse,
    summary="List cloud diagram templates"
)
@limiter.limit(RATE_LIMIT_DEFAULT)
async def list_cloud_templates(
    request: Request,
    category: Optional[str] = Query(default=None, description="Filter by category (e.g., aws, kubernetes, security)")
):
    """
    List available cloud diagram templates.

    Templates are organized by category (aws, kubernetes, security, etc.)
    """
    try:
        categories = CloudDiagrams.list_template_categories()
        all_templates = CloudDiagrams.list_templates(category=category)

        templates = [
            CloudTemplateInfo(
                name=t.get("name", ""),
                category=t.get("category", ""),
                path=t.get("path", ""),
                providers=t.get("providers", [])
            )
            for t in all_templates
        ]

        return CloudTemplateListResponse(
            templates=templates,
            categories=categories,
            total=len(templates)
        )
    except Exception as e:
        logger.error(f"Error listing cloud templates: {str(e)}", exc_info=ENABLE_TRACEBACK_LOGGING)
        raise HTTPException(status_code=500, detail="Failed to list templates")


@router.get(
    "/cloud/template/{category}/{name}",
    response_model=CloudTemplateContentResponse,
    summary="Get cloud template content"
)
@limiter.limit(RATE_LIMIT_DEFAULT)
async def get_cloud_template(
    request: Request,
    category: str,
    name: str
):
    """
    Get the content of a specific cloud diagram template.

    Returns the template content along with metadata.
    """
    try:
        template_id = f"{category}/{name}"

        # SECURITY: Validate each path component to prevent path traversal
        if not validate_path_component(category) or not validate_path_component(name):
            logger.warning(f"Path traversal attempt blocked in cloud template: {template_id}")
            raise HTTPException(status_code=400, detail="Invalid template ID")

        templates_dir = CloudDiagrams.get_templates_dir()
        base_dir = templates_dir.resolve()

        # Try .toml first, then .yaml, then .json
        template_path = None
        for ext in [".toml", ".yaml", ".yml", ".json"]:
            candidate = templates_dir / category / f"{name}{ext}"
            if candidate.exists():
                template_path = candidate
                break

        if not template_path:
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
            raise HTTPException(status_code=400, detail="Invalid template ID")

        # Read the template content
        content = resolved_path.read_text()

        # Detect providers used
        providers = []
        content_lower = content.lower()
        for provider in ["aws", "azure", "gcp", "k8s", "onprem", "oci", "alibabacloud"]:
            if provider in content_lower:
                providers.append(provider)

        return CloudTemplateContentResponse(
            id=template_id,
            name=name.replace("-", " ").replace("_", " ").title(),
            category=category,
            content=content,
            filename=template_path.name,
            providers=providers
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting cloud template: {str(e)}", exc_info=ENABLE_TRACEBACK_LOGGING)
        raise HTTPException(status_code=500, detail="Failed to get template")


@router.post(
    "/cloud/generate-code",
    response_model=CloudPythonCodeResponse,
    summary="Generate Python code from config"
)
@limiter.limit(RATE_LIMIT_ANALYZE)
async def generate_cloud_code(
    request: Request,
    file: UploadFile = File(..., description="Cloud diagram config file (.toml, .json, .yaml)"),
):
    """
    Generate Python code from a cloud diagram configuration.

    The generated code uses the `diagrams` library and can be executed
    standalone to produce the diagram.
    """
    input_path = None

    try:
        # Validate file extension
        validate_config_file_extension(file.filename)

        # Save uploaded file
        input_path = save_upload_file(file)

        # Create CloudDiagrams instance
        cd = CloudDiagrams(validate_diagrams=False)
        cd.load(input_path)

        # Generate Python code
        code = cd.to_python_code()

        cleanup_files(input_path)

        # Generate suggested filename from config title
        title = cd.config.title if cd.config else "cloud_diagram"
        filename = f"{title.lower().replace(' ', '_')}.py"

        return CloudPythonCodeResponse(
            code=code,
            filename=filename
        )

    except CloudDiagramError as e:
        cleanup_files(input_path)
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        cleanup_files(input_path)
        logger.error(f"Cloud code generation error: {str(e)}", exc_info=ENABLE_TRACEBACK_LOGGING)
        raise HTTPException(status_code=500, detail="An internal error occurred")
