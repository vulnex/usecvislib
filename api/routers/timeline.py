#
# VULNEX -Universal Security Visualization Library-
#
# File: routers/timeline.py
# Description: Incident Timeline API endpoints (mode 10)
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
#

import logging
import os

from fastapi import APIRouter, BackgroundTasks, File, Query, Request, UploadFile
from fastapi.responses import FileResponse

from usecvislib.timeline import IncidentTimeline, TimelineError
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
    OutputFormat,
    RenderEngine,
    TemplateMetadata,
    TimelineMode,
    TimelineStats,
    TimelineStyle,
)

logger = logging.getLogger("usecvislib.api")

router = APIRouter(tags=["Incident Timeline"])

# Errors in the uploaded definition: reported to the client as 400
_CLIENT_ERRORS = (TimelineError, FileError, ConfigError)


@router.post(
    "/visualize/timeline",
    summary="Generate incident timeline visualization",
    response_class=FileResponse,
    responses={
        200: {
            "content": {"image/png": {}, "image/svg+xml": {}, "application/pdf": {}},
            "description": "Generated visualization image",
        }
    },
)
@limiter.limit(RATE_LIMIT_VISUALIZE)
async def visualize_timeline(
    request: Request,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(
        ..., description="Config file with an [incident] section, [[events]] and optional [[phases]]"
    ),
    format: OutputFormat = Query(default=OutputFormat.PNG, description="Output format"),
    style: TimelineStyle = Query(default=TimelineStyle.DEFAULT, description="Style preset"),
    mode: TimelineMode = Query(default=TimelineMode.SWIMLANE, description="Render mode"),
    render_engine: RenderEngine = Query(
        default=RenderEngine.GRAPHVIZ,
        description="Rendering engine: graphviz (Matplotlib, default) or svg (modern, sv_* styles)",
    ),
):
    """Generate an incident timeline visualization from an uploaded file.

    The file declares an ``[incident]`` section (name/id/analyst), a list of
    ``[[events]]`` (timestamp, title, severity, lane, optional duration and
    ATT&CK technique) and optional ``[[phases]]`` response bands.
    """
    temps = TempFiles()
    with handle_errors(temps, _CLIENT_ERRORS):
        validate_config_file_extension(file.filename)
        input_path = temps.add(save_upload_file(file))
        output_base = temps.add_prefix(os.path.join(TEMP_DIR, f"output_{os.urandom(8).hex()}"))

        styleid = style.value
        if render_engine == RenderEngine.SVG and style == TimelineStyle.DEFAULT:
            styleid = ""  # let the engine pick sv_default

        tl = IncidentTimeline(
            input_path,
            output_base,
            format=format.value,
            styleid=styleid,
            mode=mode.value,
            render_engine=render_engine.value,
        )
        await run_sync_with_timeout(
            tl.build, REQUEST_TIMEOUT_VISUALIZE, "timeline visualization", on_abandon=temps.cleanup
        )

        return file_response(
            f"{output_base}.{format.value}", format, f"timeline.{format.value}", temps, background_tasks
        )


@router.post("/analyze/timeline", response_model=TimelineStats, summary="Analyze incident timeline")
@limiter.limit(RATE_LIMIT_ANALYZE)
async def analyze_timeline(
    request: Request,
    file: UploadFile = File(
        ..., description="Config file with an [incident] section, [[events]] and optional [[phases]]"
    ),
):
    """Return timeline statistics, severity distribution and response metrics."""
    temps = TempFiles()
    with handle_errors(temps, _CLIENT_ERRORS):
        validate_config_file_extension(file.filename)
        input_path = temps.add(save_upload_file(file))
        tl = IncidentTimeline(input_path, "unused")
        stats = tl.get_stats()

        metadata_obj = tl.get_metadata()
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
        return TimelineStats(**stats)


@router.post("/validate/timeline", summary="Validate incident timeline structure")
@limiter.limit(RATE_LIMIT_ANALYZE)
async def validate_timeline(
    request: Request,
    file: UploadFile = File(
        ..., description="Config file with an [incident] section, [[events]] and optional [[phases]]"
    ),
):
    """Validate an incident timeline configuration and return any errors/warnings."""
    temps = TempFiles()
    with handle_errors(temps, _CLIENT_ERRORS):
        validate_config_file_extension(file.filename)
        input_path = temps.add(save_upload_file(file))
        tl = IncidentTimeline(input_path, "unused")
        errors = tl.validate()
        return {"valid": len(errors) == 0, "errors": errors}
