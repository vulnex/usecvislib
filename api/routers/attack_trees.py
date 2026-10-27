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

from fastapi import APIRouter, BackgroundTasks, File, Query, Request, UploadFile
from fastapi.responses import FileResponse

from usecvislib import AttackTrees
from usecvislib.attacktrees import AttackTreeError
from usecvislib.utils import ConfigError, FileError

from ..auth import request_api_key
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
    AttackTreeStyle,
    OutputFormat,
    RenderEngine,
    TemplateMetadata,
    TreeStats,
)

logger = logging.getLogger("usecvislib.api")

router = APIRouter(tags=["Attack Trees"])

# Errors in the uploaded definition: reported to the client as 400
_CLIENT_ERRORS = (AttackTreeError, FileError, ConfigError)


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
            "description": "Generated visualization image",
        }
    },
)
@limiter.limit(RATE_LIMIT_VISUALIZE)
async def visualize_attack_tree(
    request: Request,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(..., description="TOML file containing attack tree definition"),
    format: OutputFormat = Query(default=OutputFormat.PNG, description="Output format"),
    style: AttackTreeStyle = Query(default=AttackTreeStyle.DEFAULT, description="Style preset"),
    render_engine: RenderEngine = Query(
        default=RenderEngine.GRAPHVIZ,
        description="Rendering engine: graphviz (default) or svg (modern hand-painted output, sv_* styles)",
    ),
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
    temps = TempFiles()
    with handle_errors(temps, _CLIENT_ERRORS):
        validate_config_file_extension(file.filename)
        input_path = temps.add(save_upload_file(file))
        output_base = temps.add_prefix(os.path.join(TEMP_DIR, f"output_{os.urandom(8).hex()}"))
        input_for_viz = resolve_images_to_temp(input_path, temps, request_api_key(request))

        styleid = style.value
        if render_engine == RenderEngine.SVG and style == AttackTreeStyle.DEFAULT:
            styleid = ""
        at = AttackTrees(
            input_for_viz, output_base, format=format.value, styleid=styleid, render_engine=render_engine.value
        )
        await run_sync_with_timeout(
            at.BuildAttackTree, REQUEST_TIMEOUT_VISUALIZE, "attack tree visualization", on_abandon=temps.cleanup
        )

        return file_response(
            f"{output_base}.{format.value}", format, f"attack_tree.{format.value}", temps, background_tasks
        )


@router.post("/analyze/attack-tree", response_model=TreeStats, summary="Analyze attack tree structure")
@limiter.limit(RATE_LIMIT_ANALYZE)
async def analyze_attack_tree(
    request: Request,
    file: UploadFile = File(..., description="TOML file containing attack tree definition"),
):
    """
    Analyze an attack tree and return statistics without generating visualization.

    Returns node counts, edge counts, and structural information.
    """
    temps = TempFiles()
    with handle_errors(temps, _CLIENT_ERRORS):
        validate_config_file_extension(file.filename)
        input_path = temps.add(save_upload_file(file))
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


@router.post("/validate/attack-tree", summary="Validate attack tree structure")
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
    temps = TempFiles()
    with handle_errors(temps, _CLIENT_ERRORS):
        validate_config_file_extension(file.filename)
        input_path = temps.add(save_upload_file(file))
        at = AttackTrees(input_path, "unused")
        errors = at.validate()

        return {"valid": len(errors) == 0, "errors": errors}
