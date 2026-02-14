#
# VULNEX -Universal Security Visualization Library-
#
# File: routers/threat_models.py
# Description: Threat Modeling API endpoints
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
#

import os
import logging

from fastapi import APIRouter, File, UploadFile, Query, BackgroundTasks, Request, HTTPException
from fastapi.responses import FileResponse

from usecvislib import ThreatModeling
from usecvislib.utils import FileError, ConfigError, ReadConfigFile

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
    OutputFormat, ThreatModelStyle, ThreatModelEngine,
    ModelStats, TemplateMetadata, StrideReport, StrideCategory,
)

logger = logging.getLogger("usecvislib.api")

router = APIRouter(tags=["Threat Modeling"])


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
            "description": "Generated visualization image"
        }
    }
)
@limiter.limit(RATE_LIMIT_VISUALIZE)
async def visualize_threat_model(
    request: Request,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(..., description="TOML file containing threat model definition"),
    format: OutputFormat = Query(default=OutputFormat.PNG, description="Output format"),
    style: ThreatModelStyle = Query(default=ThreatModelStyle.DEFAULT, description="Style preset"),
    engine: ThreatModelEngine = Query(default=ThreatModelEngine.USECVISLIB, description="Threat modeling engine (usecvislib or pytm)"),
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
    input_path = None
    output_path = None
    modified_input_path = None

    try:
        validate_config_file_extension(file.filename)
        input_path = save_upload_file(file)
        output_base = os.path.join(TEMP_DIR, f"output_{os.urandom(8).hex()}")

        # Read and parse config to resolve image_id references
        try:
            config_data = ReadConfigFile(input_path)
            config_data = resolve_image_references(config_data)

            # Keep a valid extension for the resolved file
            base, ext = os.path.splitext(input_path)
            modified_input_path = f"{base}_resolved{ext}"
            write_config_file(modified_input_path, config_data, ext)
            input_for_viz = modified_input_path
        except Exception as e:
            logger.debug(f"Image resolution skipped: {e}")
            input_for_viz = input_path

        tm = ThreatModeling(
            input_for_viz,
            output_base,
            format=format.value,
            styleid=style.value,
            engine=engine.value
        )
        # SECURITY: Timeout protection for complex threat models
        await run_sync_with_timeout(
            tm.BuildThreatModel,
            REQUEST_TIMEOUT_VISUALIZE,
            "threat model visualization"
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
            filename=f"threat_model.{format.value}",
        )

    except (FileError, ConfigError) as e:
        cleanup_files(input_path, modified_input_path, output_path)
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        cleanup_files(input_path, modified_input_path, output_path)
        logger.error(f"Internal error: {str(e)}", exc_info=ENABLE_TRACEBACK_LOGGING)
        raise HTTPException(status_code=500, detail="An internal error occurred")


@router.post(
    "/analyze/threat-model",
    response_model=ModelStats,
    summary="Analyze threat model structure"
)
@limiter.limit(RATE_LIMIT_ANALYZE)
async def analyze_threat_model(
    request: Request,
    file: UploadFile = File(..., description="TOML file containing threat model definition"),
):
    """
    Analyze a threat model and return statistics without generating visualization.
    """
    input_path = None

    try:
        validate_config_file_extension(file.filename)
        input_path = save_upload_file(file)
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

    except Exception as e:
        logger.error(f"Internal error: {str(e)}", exc_info=ENABLE_TRACEBACK_LOGGING)
        raise HTTPException(status_code=500, detail="An internal error occurred")
    finally:
        cleanup_files(input_path)


@router.post(
    "/analyze/stride",
    response_model=StrideReport,
    summary="Perform STRIDE threat analysis"
)
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
    input_path = None

    try:
        validate_config_file_extension(file.filename)
        input_path = save_upload_file(file)
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
                severity=severity
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

    except Exception as e:
        logger.error(f"Internal error: {str(e)}", exc_info=ENABLE_TRACEBACK_LOGGING)
        raise HTTPException(status_code=500, detail="An internal error occurred")
    finally:
        cleanup_files(input_path)
