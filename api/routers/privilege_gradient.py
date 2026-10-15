#
# VULNEX -Universal Security Visualization Library-
#
# File: routers/privilege_gradient.py
# Description: Privilege Gradient Graph API endpoints
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
#

import logging
import os

from fastapi import APIRouter, BackgroundTasks, File, Query, Request, UploadFile
from fastapi.responses import FileResponse

from usecvislib import PrivilegeGradient
from usecvislib.privilegegradient import PrivilegeGradientError
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
    GradientStats,
    InversionsResponse,
    OutputFormat,
    PrivilegeGradientStyle,
    TemplateMetadata,
)

logger = logging.getLogger("usecvislib.api")

router = APIRouter(tags=["Privilege Gradient Graphs"])

# Errors in the uploaded definition: reported to the client as 400
_CLIENT_ERRORS = (PrivilegeGradientError, FileError, ConfigError)


@router.post(
    "/visualize/privilege-gradient",
    summary="Generate privilege gradient graph visualization",
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
async def visualize_privilege_gradient(
    request: Request,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(..., description="Configuration file containing privilege gradient definition"),
    format: OutputFormat = Query(default=OutputFormat.PNG, description="Output format"),
    style: PrivilegeGradientStyle = Query(default=PrivilegeGradientStyle.DEFAULT, description="Style preset"),
):
    """
    Generate a privilege gradient graph visualization from an uploaded configuration file.

    The configuration file should contain:
    - `[gradient]` section with name and description
    - `[[zones]]` section with trust zones
    - `[[components]]` section with system components
    - `[[influence_types]]` section with influence type definitions (optional)
    - `[[influences]]` section with influence edges between components
    """
    temps = TempFiles()
    with handle_errors(temps, _CLIENT_ERRORS):
        validate_config_file_extension(file.filename)
        input_path = temps.add(save_upload_file(file))
        output_base = temps.add_prefix(os.path.join(TEMP_DIR, f"output_{os.urandom(8).hex()}"))
        input_for_viz = resolve_images_to_temp(input_path, temps)

        pg = PrivilegeGradient(input_for_viz, output_base, format=format.value, styleid=style.value)
        await run_sync_with_timeout(
            pg.BuildPrivilegeGradient,
            REQUEST_TIMEOUT_VISUALIZE,
            "privilege gradient visualization",
            on_abandon=temps.cleanup,
        )

        return file_response(
            f"{output_base}.{format.value}", format, f"privilege_gradient.{format.value}", temps, background_tasks
        )


@router.post(
    "/analyze/privilege-gradient", response_model=GradientStats, summary="Analyze privilege gradient graph structure"
)
@limiter.limit(RATE_LIMIT_ANALYZE)
async def analyze_privilege_gradient(
    request: Request,
    file: UploadFile = File(..., description="Configuration file containing privilege gradient definition"),
):
    """
    Analyze a privilege gradient graph and return statistics without generating visualization.

    Returns zone counts, component counts, influence counts, and inversion details.
    """
    temps = TempFiles()
    with handle_errors(temps, _CLIENT_ERRORS):
        validate_config_file_extension(file.filename)
        input_path = temps.add(save_upload_file(file))
        pg = PrivilegeGradient(input_path, "unused")
        stats = pg.get_stats()

        metadata_obj = pg.get_metadata()
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

        return GradientStats(**stats)


@router.post("/analyze/inversions", response_model=InversionsResponse, summary="Detect privilege gradient inversions")
@limiter.limit(RATE_LIMIT_ANALYZE)
async def analyze_inversions(
    request: Request,
    file: UploadFile = File(..., description="Configuration file containing privilege gradient definition"),
):
    """
    Detect privilege gradient inversions in the configuration.

    Returns all inversions with severity classification based on trust gap:
    - **critical**: Trust gap >= 3
    - **high**: Trust gap >= 2
    - **medium**: Trust gap = 1
    """
    temps = TempFiles()
    with handle_errors(temps, _CLIENT_ERRORS):
        validate_config_file_extension(file.filename)
        input_path = temps.add(save_upload_file(file))
        pg = PrivilegeGradient(input_path, "unused")
        pg.load()

        inversions = pg.detect_inversions()
        summary = pg.get_inversion_summary()

        return InversionsResponse(
            total=summary["total"],
            by_severity=summary["by_severity"],
            inversions=inversions,
        )


@router.post("/validate/privilege-gradient", summary="Validate privilege gradient graph structure")
@limiter.limit(RATE_LIMIT_ANALYZE)
async def validate_privilege_gradient(
    request: Request,
    file: UploadFile = File(..., description="Configuration file containing privilege gradient definition"),
):
    """
    Validate a privilege gradient graph structure and return any errors found.

    Checks for:
    - Missing required sections
    - Undefined zone references
    - Invalid component or influence references
    - Duplicate IDs
    """
    temps = TempFiles()
    with handle_errors(temps, _CLIENT_ERRORS):
        validate_config_file_extension(file.filename)
        input_path = temps.add(save_upload_file(file))
        pg = PrivilegeGradient(input_path, "unused")
        errors = pg.validate()

        return {"valid": len(errors) == 0, "errors": errors}
