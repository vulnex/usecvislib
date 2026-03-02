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

from fastapi import APIRouter, BackgroundTasks, File, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse

from usecvislib import PrivilegeGradient
from usecvislib.privilegegradient import PrivilegeGradientError
from usecvislib.utils import ConfigError, FileError, ReadConfigFile

from ..config import (
    ENABLE_TRACEBACK_LOGGING,
    RATE_LIMIT_ANALYZE,
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
    write_config_file,
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
            "description": "Generated visualization image"
        }
    }
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

        pg = PrivilegeGradient(input_for_viz, output_base, format=format.value, styleid=style.value)
        await run_sync_with_timeout(
            pg.BuildPrivilegeGradient,
            REQUEST_TIMEOUT_VISUALIZE,
            "privilege gradient visualization"
        )

        output_path = f"{output_base}.{format.value}"

        if not os.path.exists(output_path):
            cleanup_files(input_path, modified_input_path)
            raise HTTPException(status_code=500, detail="Failed to generate visualization")

        background_tasks.add_task(cleanup_files, input_path, modified_input_path, output_path)

        return FileResponse(
            path=output_path,
            media_type=get_content_type(format),
            filename=f"privilege_gradient.{format.value}",
        )

    except PrivilegeGradientError as e:
        cleanup_files(input_path, modified_input_path, output_path)
        raise HTTPException(status_code=400, detail=str(e)) from e
    except (FileError, ConfigError) as e:
        cleanup_files(input_path, modified_input_path, output_path)
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        cleanup_files(input_path, modified_input_path, output_path)
        logger.error(f"Internal error: {e!s}", exc_info=ENABLE_TRACEBACK_LOGGING)
        raise HTTPException(status_code=500, detail="An internal error occurred") from e


@router.post(
    "/analyze/privilege-gradient",
    response_model=GradientStats,
    summary="Analyze privilege gradient graph structure"
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
    input_path = None

    try:
        validate_config_file_extension(file.filename)
        input_path = save_upload_file(file)
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

    except PrivilegeGradientError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        logger.error(f"Internal error: {e!s}", exc_info=ENABLE_TRACEBACK_LOGGING)
        raise HTTPException(status_code=500, detail="An internal error occurred") from e
    finally:
        cleanup_files(input_path)


@router.post(
    "/analyze/inversions",
    response_model=InversionsResponse,
    summary="Detect privilege gradient inversions"
)
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
    input_path = None

    try:
        validate_config_file_extension(file.filename)
        input_path = save_upload_file(file)
        pg = PrivilegeGradient(input_path, "unused")
        pg.load()

        inversions = pg.detect_inversions()
        summary = pg.get_inversion_summary()

        return InversionsResponse(
            total=summary["total"],
            by_severity=summary["by_severity"],
            inversions=inversions,
        )

    except PrivilegeGradientError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        logger.error(f"Internal error: {e!s}", exc_info=ENABLE_TRACEBACK_LOGGING)
        raise HTTPException(status_code=500, detail="An internal error occurred") from e
    finally:
        cleanup_files(input_path)


@router.post(
    "/validate/privilege-gradient",
    summary="Validate privilege gradient graph structure"
)
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
    input_path = None

    try:
        validate_config_file_extension(file.filename)
        input_path = save_upload_file(file)
        pg = PrivilegeGradient(input_path, "unused")
        errors = pg.validate()

        return {
            "valid": len(errors) == 0,
            "errors": errors
        }

    except PrivilegeGradientError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        logger.error(f"Internal error: {e!s}", exc_info=ENABLE_TRACEBACK_LOGGING)
        raise HTTPException(status_code=500, detail="An internal error occurred") from e
    finally:
        cleanup_files(input_path)
