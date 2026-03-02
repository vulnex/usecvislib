#
# VULNEX -Universal Security Visualization Library-
#
# File: routers/attack_trees.py
# Description: Attack Trees API endpoints
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
#

import logging
import os

from fastapi import APIRouter, BackgroundTasks, File, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse

from usecvislib import AttackTrees
from usecvislib.attacktrees import AttackTreeError
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
    AttackTreeStyle,
    OutputFormat,
    TemplateMetadata,
    TreeStats,
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
        raise HTTPException(status_code=400, detail=str(e)) from e
    except (FileError, ConfigError) as e:
        cleanup_files(input_path, output_path)
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        cleanup_files(input_path, output_path)
        logger.error(f"Internal error: {e!s}", exc_info=ENABLE_TRACEBACK_LOGGING)
        raise HTTPException(status_code=500, detail="An internal error occurred") from e


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
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        logger.error(f"Internal error: {e!s}", exc_info=ENABLE_TRACEBACK_LOGGING)
        raise HTTPException(status_code=500, detail="An internal error occurred") from e
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
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        logger.error(f"Internal error: {e!s}", exc_info=ENABLE_TRACEBACK_LOGGING)
        raise HTTPException(status_code=500, detail="An internal error occurred") from e
    finally:
        cleanup_files(input_path)
