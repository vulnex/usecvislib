#
# VULNEX -Universal Security Visualization Library-
#
# File: routers/attack_trees.py
# Description: Attack Trees API endpoints
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
#

import os
import logging

from fastapi import APIRouter, File, UploadFile, Query, BackgroundTasks, Request

from usecvislib import AttackTrees
from usecvislib.attacktrees import AttackTreeError
from usecvislib.utils import FileError, ConfigError, ReadConfigFile
from fastapi import HTTPException
from fastapi.responses import FileResponse

from ..config import (
    limiter, RATE_LIMIT_VISUALIZE, RATE_LIMIT_ANALYZE,
    ENABLE_TRACEBACK_LOGGING, TEMP_DIR,
    REQUEST_TIMEOUT_VISUALIZE,
)
from ..helpers import (
    save_upload_file, cleanup_files, get_content_type,
    validate_config_file_extension, resolve_image_references,
    write_config_file, run_sync_with_timeout, sanitize_filename_for_log,
)
from ..schemas import (
    OutputFormat, AttackTreeStyle, TreeStats, TemplateMetadata,
)

logger = logging.getLogger("usecvislib.api")

router = APIRouter(tags=["Attack Trees"])


@router.post(
    "/visualize/attack-tree",
    summary="Generate attack tree visualization",
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
async def visualize_attack_tree(
    request: Request,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(..., description="TOML file containing attack tree definition"),
    format: OutputFormat = Query(default=OutputFormat.PNG, description="Output format"),
    style: AttackTreeStyle = Query(default=AttackTreeStyle.DEFAULT, description="Style preset"),
):
    """
    Generate an attack tree visualization from an uploaded TOML file.

    The TOML file should contain:
    - `[tree]` section with name and root node
    - `[nodes]` section with node definitions
    - `[edges]` section with connections

    Example TOML structure:
    ```toml
    [tree]
    name = "Attack Tree"
    root = "Goal"

    [nodes]
    "Goal" = {style="filled", fillcolor="red"}
    "Attack" = {}

    [edges]
    "Goal" = [{to = "Attack"}]
    ```
    """
    input_path = None
    output_path = None
    modified_input_path = None

    try:
        # Save uploaded file
        validate_config_file_extension(file.filename)
        input_path = save_upload_file(file)
        output_base = os.path.join(TEMP_DIR, f"output_{os.urandom(8).hex()}")

        # Read and parse config to resolve image_id references
        try:
            config_data = ReadConfigFile(input_path)
            config_data = resolve_image_references(config_data)

            # Write modified config to a temp file in the same format
            base, ext = os.path.splitext(input_path)
            modified_input_path = f"{base}_resolved{ext}"
            write_config_file(modified_input_path, config_data, ext)
            input_for_viz = modified_input_path
        except Exception as e:
            logger.debug(f"Image resolution skipped: {e}")
            input_for_viz = input_path

        # Generate visualization with timeout protection
        # SECURITY: Prevents resource exhaustion from complex/slow visualizations
        at = AttackTrees(input_for_viz, output_base, format=format.value, styleid=style.value)
        await run_sync_with_timeout(
            at.BuildAttackTree,
            REQUEST_TIMEOUT_VISUALIZE,
            "attack tree visualization"
        )

        output_path = f"{output_base}.{format.value}"

        if not os.path.exists(output_path):
            cleanup_files(input_path, modified_input_path)
            raise HTTPException(status_code=500, detail="Failed to generate visualization")

        # Schedule cleanup after response is sent
        background_tasks.add_task(cleanup_files, input_path, modified_input_path, output_path)

        return FileResponse(
            path=output_path,
            media_type=get_content_type(format),
            filename=f"attack_tree.{format.value}",
        )

    except AttackTreeError as e:
        cleanup_files(input_path, output_path)
        raise HTTPException(status_code=400, detail=str(e))
    except (FileError, ConfigError) as e:
        cleanup_files(input_path, output_path)
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        cleanup_files(input_path, output_path)
        logger.error(f"Internal error: {str(e)}", exc_info=ENABLE_TRACEBACK_LOGGING)
        raise HTTPException(status_code=500, detail="An internal error occurred")


@router.post(
    "/analyze/attack-tree",
    response_model=TreeStats,
    summary="Analyze attack tree structure"
)
@limiter.limit(RATE_LIMIT_ANALYZE)
async def analyze_attack_tree(
    request: Request,
    file: UploadFile = File(..., description="TOML file containing attack tree definition"),
):
    """
    Analyze an attack tree and return statistics without generating visualization.

    Returns node counts, edge counts, and structural information.
    """
    input_path = None

    try:
        validate_config_file_extension(file.filename)
        input_path = save_upload_file(file)
        at = AttackTrees(input_path, "unused")
        stats = at.get_tree_stats()

        # Get metadata
        metadata_obj = at.get_metadata()
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

        return TreeStats(**stats)

    except AttackTreeError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Internal error: {str(e)}", exc_info=ENABLE_TRACEBACK_LOGGING)
        raise HTTPException(status_code=500, detail="An internal error occurred")
    finally:
        cleanup_files(input_path)


@router.post(
    "/validate/attack-tree",
    summary="Validate attack tree structure"
)
@limiter.limit(RATE_LIMIT_ANALYZE)
async def validate_attack_tree(
    request: Request,
    file: UploadFile = File(..., description="TOML file containing attack tree definition"),
):
    """
    Validate an attack tree structure and return any errors found.

    Checks for:
    - Missing required sections
    - Orphan nodes
    - Undefined edge targets
    - Invalid root node
    """
    input_path = None

    try:
        validate_config_file_extension(file.filename)
        input_path = save_upload_file(file)
        at = AttackTrees(input_path, "unused")
        errors = at.validate()

        return {
            "valid": len(errors) == 0,
            "errors": errors
        }

    except AttackTreeError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Internal error: {str(e)}", exc_info=ENABLE_TRACEBACK_LOGGING)
        raise HTTPException(status_code=500, detail="An internal error occurred")
    finally:
        cleanup_files(input_path)
