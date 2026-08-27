#
# VULNEX -Universal Security Visualization Library-
#
# File: routers/vulntree.py
# Description: Vulnerability Dependency Tree API endpoints (mode 11)
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
#

import logging
import os

from fastapi import APIRouter, BackgroundTasks, File, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse

from usecvislib.utils import ConfigError, FileError
from usecvislib.vulntree import VulnDependencyTree, VulnTreeError

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
    run_sync_with_timeout,
    save_upload_file,
    validate_config_file_extension,
)
from ..schemas import (
    OutputFormat,
    TemplateMetadata,
    VulnTreeMode,
    VulnTreeStats,
    VulnTreeStyle,
)

logger = logging.getLogger("usecvislib.api")

router = APIRouter(tags=["Vulnerability Tree"])


@router.post(
    "/visualize/vuln-tree",
    summary="Generate vulnerability dependency tree visualization",
    response_class=FileResponse,
    responses={
        200: {
            "content": {"image/png": {}, "image/svg+xml": {}, "application/pdf": {}},
            "description": "Generated visualization image",
        }
    },
)
@limiter.limit(RATE_LIMIT_VISUALIZE)
async def visualize_vuln_tree(
    request: Request,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(..., description="Config file with a [dependencies] table and optional [vulntree] section"),
    format: OutputFormat = Query(default=OutputFormat.PNG, description="Output format"),
    style: VulnTreeStyle = Query(default=VulnTreeStyle.DEFAULT, description="Style preset"),
    mode: VulnTreeMode = Query(default=VulnTreeMode.TREE, description="Render mode"),
):
    """Generate a vulnerability dependency tree from an uploaded file.

    The file declares a ``[dependencies.*]`` table (name, version, child
    ``dependencies``, and ``[[...vulnerabilities]]``) plus an optional
    ``[vulntree]`` section (name, ``root_packages``). Node fill is driven by
    each package's highest CVE severity.
    """
    input_path = None
    output_path = None

    try:
        validate_config_file_extension(file.filename)
        input_path = save_upload_file(file)
        output_base = os.path.join(TEMP_DIR, f"output_{os.urandom(8).hex()}")

        vt = VulnDependencyTree(input_path, output_base, format=format.value, styleid=style.value, mode=mode.value)
        await run_sync_with_timeout(vt.build, REQUEST_TIMEOUT_VISUALIZE, "vulnerability tree visualization")

        output_path = f"{output_base}.{format.value}"
        if not os.path.exists(output_path):
            cleanup_files(input_path)
            raise HTTPException(status_code=500, detail="Failed to generate visualization")

        background_tasks.add_task(cleanup_files, input_path, output_path)
        return FileResponse(
            path=output_path,
            media_type=get_content_type(format),
            filename=f"vuln_tree.{format.value}",
        )

    except VulnTreeError as e:
        cleanup_files(input_path, output_path)
        raise HTTPException(status_code=400, detail=str(e)) from e
    except (FileError, ConfigError) as e:
        cleanup_files(input_path, output_path)
        raise HTTPException(status_code=400, detail=str(e)) from e
    except HTTPException:
        raise
    except Exception as e:
        cleanup_files(input_path, output_path)
        logger.error(f"Internal error: {e!s}", exc_info=ENABLE_TRACEBACK_LOGGING)
        raise HTTPException(status_code=500, detail="An internal error occurred") from e


@router.post("/analyze/vuln-tree", response_model=VulnTreeStats, summary="Analyze vulnerability dependency tree")
@limiter.limit(RATE_LIMIT_ANALYZE)
async def analyze_vuln_tree(
    request: Request,
    file: UploadFile = File(..., description="Config file with a [dependencies] table and optional [vulntree] section"),
):
    """Return dependency counts, severity distribution and impact propagation."""
    input_path = None
    try:
        validate_config_file_extension(file.filename)
        input_path = save_upload_file(file)
        vt = VulnDependencyTree(input_path, "unused")
        stats = vt.get_stats()

        metadata_obj = vt.get_metadata()
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
        return VulnTreeStats(**stats)

    except VulnTreeError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except (FileError, ConfigError) as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        logger.error(f"Internal error: {e!s}", exc_info=ENABLE_TRACEBACK_LOGGING)
        raise HTTPException(status_code=500, detail="An internal error occurred") from e
    finally:
        cleanup_files(input_path)


@router.post("/validate/vuln-tree", summary="Validate vulnerability dependency tree structure")
@limiter.limit(RATE_LIMIT_ANALYZE)
async def validate_vuln_tree(
    request: Request,
    file: UploadFile = File(..., description="Config file with a [dependencies] table and optional [vulntree] section"),
):
    """Validate a vulnerability tree configuration and return any errors/warnings."""
    input_path = None
    try:
        validate_config_file_extension(file.filename)
        input_path = save_upload_file(file)
        vt = VulnDependencyTree(input_path, "unused")
        errors = vt.validate()
        return {"valid": len(errors) == 0, "errors": errors}

    except VulnTreeError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except (FileError, ConfigError) as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        logger.error(f"Internal error: {e!s}", exc_info=ENABLE_TRACEBACK_LOGGING)
        raise HTTPException(status_code=500, detail="An internal error occurred") from e
    finally:
        cleanup_files(input_path)
