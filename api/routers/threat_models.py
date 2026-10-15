#
# VULNEX -Universal Security Visualization Library-
#
# File: routers/threat_models.py
# Description: Threat Modeling API endpoints
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
#

import logging
import os

from fastapi import APIRouter, BackgroundTasks, File, Query, Request, UploadFile
from fastapi.responses import FileResponse

from usecvislib import ThreatModeling
from usecvislib.utils import ConfigError, FileError, ValidationError

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
    ModelStats,
    OutputFormat,
    RenderEngine,
    StrideCategory,
    StrideReport,
    TemplateMetadata,
    ThreatModelEngine,
    ThreatModelStyle,
)

logger = logging.getLogger("usecvislib.api")

router = APIRouter(tags=["Threat Modeling"])

# Errors in the uploaded definition: reported to the client as 400
_CLIENT_ERRORS = (FileError, ConfigError, ValidationError)


@router.post(
    "/visualize/threat-model",
    summary="Generate threat model visualization",
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
async def visualize_threat_model(
    request: Request,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(..., description="TOML file containing threat model definition"),
    format: OutputFormat = Query(default=OutputFormat.PNG, description="Output format"),
    style: ThreatModelStyle = Query(default=ThreatModelStyle.DEFAULT, description="Style preset"),
    engine: ThreatModelEngine = Query(
        default=ThreatModelEngine.USECVISLIB, description="Threat modeling engine (usecvislib or pytm)"
    ),
    render_engine: RenderEngine = Query(
        default=RenderEngine.GRAPHVIZ,
        description="Rendering engine: graphviz (default) or svg (modern cards over a Graphviz-computed layout, sv_* styles)",
    ),
):
    """
    Generate a Data Flow Diagram from an uploaded threat model TOML file.

    The TOML file should contain:
    - `[model]` section with name
    - `[externals]` section with external entities
    - `[processes]` section with processes
    - `[datastores]` section with data stores
    - `[dataflows]` section with connections
    - `[boundaries]` section (optional) for trust boundaries

    Engines:
    - **usecvislib**: Native engine with custom styling support
    - **pytm**: OWASP PyTM framework for comprehensive threat analysis
    """
    temps = TempFiles()
    with handle_errors(temps, _CLIENT_ERRORS):
        validate_config_file_extension(file.filename)
        input_path = temps.add(save_upload_file(file))
        output_base = temps.add_prefix(os.path.join(TEMP_DIR, f"output_{os.urandom(8).hex()}"))

        # Read and parse config to resolve image_id references
        input_for_viz = resolve_images_to_temp(input_path, temps)

        styleid = style.value
        if render_engine == RenderEngine.SVG and style == ThreatModelStyle.DEFAULT:
            styleid = ""  # let the engine pick sv_default

        tm = ThreatModeling(
            input_for_viz,
            output_base,
            format=format.value,
            styleid=styleid,
            engine=engine.value,
            render_engine=render_engine.value,
        )
        # SECURITY: Timeout protection for complex threat models
        await run_sync_with_timeout(
            tm.BuildThreatModel, REQUEST_TIMEOUT_VISUALIZE, "threat model visualization", on_abandon=temps.cleanup
        )

        return file_response(
            f"{output_base}.{format.value}", format, f"threat_model.{format.value}", temps, background_tasks
        )


@router.post("/analyze/threat-model", response_model=ModelStats, summary="Analyze threat model structure")
@limiter.limit(RATE_LIMIT_ANALYZE)
async def analyze_threat_model(
    request: Request,
    file: UploadFile = File(..., description="TOML file containing threat model definition"),
):
    """
    Analyze a threat model and return statistics without generating visualization.
    """
    temps = TempFiles()
    with handle_errors(temps, _CLIENT_ERRORS):
        validate_config_file_extension(file.filename)
        input_path = temps.add(save_upload_file(file))
        tm = ThreatModeling(input_path, "unused")
        tm.load()
        stats = tm.get_model_stats()

        # Get metadata
        metadata_obj = tm.get_metadata()
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

        return ModelStats(**stats)


@router.post("/analyze/stride", response_model=StrideReport, summary="Perform STRIDE threat analysis")
@limiter.limit(RATE_LIMIT_ANALYZE)
async def analyze_stride(
    request: Request,
    file: UploadFile = File(..., description="TOML file containing threat model definition"),
):
    """
    Perform STRIDE threat analysis on the uploaded threat model.

    STRIDE categories:
    - **Spoofing**: Identity-related threats
    - **Tampering**: Data modification threats
    - **Repudiation**: Action denial threats
    - **Information Disclosure**: Data exposure threats
    - **Denial of Service**: Availability threats
    - **Elevation of Privilege**: Authorization threats
    """
    temps = TempFiles()
    with handle_errors(temps, _CLIENT_ERRORS):
        validate_config_file_extension(file.filename)
        input_path = temps.add(save_upload_file(file))
        tm = ThreatModeling(input_path, "unused")
        tm.load()
        threats = tm.analyze_stride()

        model_name = tm.inputdata.get("model", {}).get("name", "Unknown")

        # Convert threat dicts to StrideCategory objects with CVSS
        def convert_threat(t):
            cvss_score = t.get("cvss")
            severity = None
            if cvss_score is not None:
                if cvss_score >= 9.0:
                    severity = "Critical"
                elif cvss_score >= 7.0:
                    severity = "High"
                elif cvss_score >= 4.0:
                    severity = "Medium"
                elif cvss_score >= 0.1:
                    severity = "Low"
                else:
                    severity = "None"
            return StrideCategory(
                element=t.get("element", ""),
                threat=t.get("threat", ""),
                mitigation=t.get("mitigation", ""),
                cvss=cvss_score,
                severity=severity,
            )

        return StrideReport(
            model_name=model_name,
            spoofing=[convert_threat(t) for t in threats.get("Spoofing", [])],
            tampering=[convert_threat(t) for t in threats.get("Tampering", [])],
            repudiation=[convert_threat(t) for t in threats.get("Repudiation", [])],
            information_disclosure=[convert_threat(t) for t in threats.get("Information Disclosure", [])],
            denial_of_service=[convert_threat(t) for t in threats.get("Denial of Service", [])],
            elevation_of_privilege=[convert_threat(t) for t in threats.get("Elevation of Privilege", [])],
        )
