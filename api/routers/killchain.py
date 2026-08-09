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

from fastapi import APIRouter, BackgroundTasks, File, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse

from usecvislib.killchain import KillChain, KillChainError
from usecvislib.utils import ConfigError, FileError

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
    KillChainStats,
    KillChainStyle,
    OutputFormat,
    RenderEngine,
    TemplateMetadata,
)

logger = logging.getLogger("usecvislib.api")

router = APIRouter(tags=["Kill Chain"])

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
    input_path = None
    output_path = None

    try:
        validate_config_file_extension(file.filename)
        input_path = save_upload_file(file)
        output_base = os.path.join(TEMP_DIR, f"output_{os.urandom(8).hex()}")

        styleid = style.value
        if render_engine == RenderEngine.SVG and style == KillChainStyle.DEFAULT:
            styleid = ""  # let the engine pick sv_default

        kc = KillChain(input_path, output_base, format=format.value, styleid=styleid, render_engine=render_engine.value)
        await run_sync_with_timeout(kc.build, REQUEST_TIMEOUT_VISUALIZE, "kill chain visualization")

        output_path = f"{output_base}.{format.value}"
        if not os.path.exists(output_path):
            cleanup_files(input_path)
            raise HTTPException(status_code=500, detail="Failed to generate visualization")

        background_tasks.add_task(cleanup_files, input_path, output_path)
        return FileResponse(
            path=output_path,
            media_type=get_content_type(format),
            filename=f"kill_chain.{format.value}",
        )

    except KillChainError as e:
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


@router.post("/analyze/kill-chain", response_model=KillChainStats, summary="Analyze kill chain coverage")
@limiter.limit(RATE_LIMIT_ANALYZE)
async def analyze_kill_chain(
    request: Request,
    file: UploadFile = File(..., description="Config file with a [killchain] section and techniques"),
):
    """Return kill chain statistics and detection/mitigation coverage."""
    input_path = None
    try:
        validate_config_file_extension(file.filename)
        input_path = save_upload_file(file)
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

    except KillChainError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except (FileError, ConfigError) as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        logger.error(f"Internal error: {e!s}", exc_info=ENABLE_TRACEBACK_LOGGING)
        raise HTTPException(status_code=500, detail="An internal error occurred") from e
    finally:
        cleanup_files(input_path)


@router.post("/validate/kill-chain", summary="Validate kill chain structure")
@limiter.limit(RATE_LIMIT_ANALYZE)
async def validate_kill_chain(
    request: Request,
    file: UploadFile = File(..., description="Config file with a [killchain] section and techniques"),
):
    """Validate a kill chain configuration and return any errors/warnings."""
    input_path = None
    try:
        validate_config_file_extension(file.filename)
        input_path = save_upload_file(file)
        kc = KillChain(input_path, "unused")
        errors = kc.validate()
        return {"valid": len(errors) == 0, "errors": errors}

    except KillChainError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except (FileError, ConfigError) as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        logger.error(f"Internal error: {e!s}", exc_info=ENABLE_TRACEBACK_LOGGING)
        raise HTTPException(status_code=500, detail="An internal error occurred") from e
    finally:
        cleanup_files(input_path)
