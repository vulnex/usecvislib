#
# VULNEX -Universal Security Visualization Library-
#
# File: routers/killchain.py
# Description: Kill Chain / MITRE ATT&CK API endpoints (mode 9)
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
#

import logging
import os

from fastapi import APIRouter, BackgroundTasks, File, Query, Request, UploadFile
from fastapi.responses import FileResponse

from usecvislib.killchain import KillChain, KillChainError
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
    run_sync_with_timeout,
    save_upload_file,
    validate_config_file_extension,
)
from ..schemas import (
    KillChainStats,
    KillChainStyle,
    OutputFormat,
    RenderEngine,
    TemplateMetadata,
)

logger = logging.getLogger("usecvislib.api")

router = APIRouter(tags=["Kill Chain"])

# Errors in the uploaded definition: reported to the client as 400
_CLIENT_ERRORS = (KillChainError, FileError, ConfigError)

# SVG engine defaults to sv_default when a Graphviz default style is requested.
_SVG_STYLE_VALUES = {s.value for s in KillChainStyle if s.value.startswith("sv_")}


@router.post(
    "/visualize/kill-chain",
    summary="Generate kill chain visualization",
    response_class=FileResponse,
    responses={
        200: {
            "content": {"image/png": {}, "image/svg+xml": {}, "application/pdf": {}},
            "description": "Generated visualization image",
        }
    },
)
@limiter.limit(RATE_LIMIT_VISUALIZE)
async def visualize_kill_chain(
    request: Request,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(..., description="Config file with a [killchain] section and techniques"),
    format: OutputFormat = Query(default=OutputFormat.PNG, description="Output format"),
    style: KillChainStyle = Query(default=KillChainStyle.DEFAULT, description="Style preset"),
    render_engine: RenderEngine = Query(
        default=RenderEngine.GRAPHVIZ,
        description="Rendering engine: graphviz (default) or svg (modern swimlane, sv_* styles)",
    ),
):
    """Generate a kill chain / MITRE ATT&CK visualization from an uploaded file.

    The file declares a ``[killchain]`` section (name + framework), a
    ``[techniques.*]`` table, and optional ``[[incidents]]`` paths. Coverage
    flags (``detected`` / ``mitigated``) drive the detection heat coloring.
    """
    temps = TempFiles()
    with handle_errors(temps, _CLIENT_ERRORS):
        validate_config_file_extension(file.filename)
        input_path = temps.add(save_upload_file(file))
        output_base = temps.add_prefix(os.path.join(TEMP_DIR, f"output_{os.urandom(8).hex()}"))

        styleid = style.value
        if render_engine == RenderEngine.SVG and style == KillChainStyle.DEFAULT:
            styleid = ""  # let the engine pick sv_default

        kc = KillChain(input_path, output_base, format=format.value, styleid=styleid, render_engine=render_engine.value)
        await run_sync_with_timeout(
            kc.build, REQUEST_TIMEOUT_VISUALIZE, "kill chain visualization", on_abandon=temps.cleanup
        )

        return file_response(
            f"{output_base}.{format.value}", format, f"kill_chain.{format.value}", temps, background_tasks
        )


@router.post("/analyze/kill-chain", response_model=KillChainStats, summary="Analyze kill chain coverage")
@limiter.limit(RATE_LIMIT_ANALYZE)
async def analyze_kill_chain(
    request: Request,
    file: UploadFile = File(..., description="Config file with a [killchain] section and techniques"),
):
    """Return kill chain statistics and detection/mitigation coverage."""
    temps = TempFiles()
    with handle_errors(temps, _CLIENT_ERRORS):
        validate_config_file_extension(file.filename)
        input_path = temps.add(save_upload_file(file))
        kc = KillChain(input_path, "unused")
        stats = kc.get_stats()

        metadata_obj = kc.get_metadata()
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
        return KillChainStats(**stats)


@router.post("/validate/kill-chain", summary="Validate kill chain structure")
@limiter.limit(RATE_LIMIT_ANALYZE)
async def validate_kill_chain(
    request: Request,
    file: UploadFile = File(..., description="Config file with a [killchain] section and techniques"),
):
    """Validate a kill chain configuration and return any errors/warnings."""
    temps = TempFiles()
    with handle_errors(temps, _CLIENT_ERRORS):
        validate_config_file_extension(file.filename)
        input_path = temps.add(save_upload_file(file))
        kc = KillChain(input_path, "unused")
        errors = kc.validate()
        return {"valid": len(errors) == 0, "errors": errors}
