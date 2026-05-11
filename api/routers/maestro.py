#
# VULNEX -Universal Security Visualization Library-
#
# File: routers/maestro.py
# Description: MAESTRO Agentic Threat Model API endpoints
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
#

import logging
import os

from fastapi import APIRouter, BackgroundTasks, File, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse

from usecvislib import MaestroThreatModel
from usecvislib.maestro import MaestroError, MaestroLayer
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
    MaestroCatalogResponse,
    MaestroLayerThreatsResponse,
    MaestroStats,
    MaestroStyle,
    MaestroValidationResponse,
    OutputFormat,
    TemplateMetadata,
)

logger = logging.getLogger("usecvislib.api")

router = APIRouter(tags=["MAESTRO Agentic Threat Model"])


# =============================================================================
# Visualize
# =============================================================================

@router.post(
    "/visualize/maestro",
    summary="Generate MAESTRO agentic threat model visualization",
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
async def visualize_maestro(
    request: Request,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(..., description="MAESTRO configuration file (TOML/JSON/YAML)"),
    format: OutputFormat = Query(default=OutputFormat.PNG, description="Output format"),
    style: MaestroStyle = Query(default=MaestroStyle.DEFAULT, description="Style preset"),
):
    """
    Generate a MAESTRO threat model visualization from an uploaded configuration file.

    The configuration file should contain `meta`, `agents[]`, optional `assets[]`,
    `architecture.patterns[]`, and optional `threats[]`, `cross_layer_threats[]`,
    and `mitigations[]` sections.

    Catalog threats are auto-attached based on the layers each agent touches
    and the declared architecture patterns.
    """
    input_path = None
    output_path = None

    try:
        validate_config_file_extension(file.filename)
        input_path = save_upload_file(file)
        output_base = os.path.join(TEMP_DIR, f"output_{os.urandom(8).hex()}")

        mm = MaestroThreatModel(input_path, output_base, format=format.value, styleid=style.value)
        await run_sync_with_timeout(
            mm.build,
            REQUEST_TIMEOUT_VISUALIZE,
            "MAESTRO threat model visualization",
        )

        output_path = f"{output_base}.{format.value}"

        if not os.path.exists(output_path):
            cleanup_files(input_path)
            raise HTTPException(status_code=500, detail="Failed to generate visualization")

        background_tasks.add_task(cleanup_files, input_path, output_path)

        return FileResponse(
            path=output_path,
            media_type=get_content_type(format),
            filename=f"maestro_threat_model.{format.value}",
        )

    except HTTPException:
        cleanup_files(input_path, output_path)
        raise
    except MaestroError as e:
        cleanup_files(input_path, output_path)
        raise HTTPException(status_code=400, detail=str(e)) from e
    except (FileError, ConfigError) as e:
        cleanup_files(input_path, output_path)
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        cleanup_files(input_path, output_path)
        logger.error(f"Internal error: {e!s}", exc_info=ENABLE_TRACEBACK_LOGGING)
        raise HTTPException(status_code=500, detail="An internal error occurred") from e


# =============================================================================
# Analyze
# =============================================================================

@router.post(
    "/analyze/maestro",
    response_model=MaestroStats,
    summary="Analyze MAESTRO threat model",
)
@limiter.limit(RATE_LIMIT_ANALYZE)
async def analyze_maestro(
    request: Request,
    file: UploadFile = File(..., description="MAESTRO configuration file"),
):
    """
    Analyze a MAESTRO threat model and return statistics without rendering.

    Returns agent / asset / threat counts, severity and status breakdowns,
    declared patterns, and any validation warnings surfaced during load.
    """
    input_path = None

    try:
        validate_config_file_extension(file.filename)
        input_path = save_upload_file(file)
        mm = MaestroThreatModel(input_path, "unused")
        stats = mm.get_stats()

        metadata_obj = mm.get_metadata()
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

        return MaestroStats(**stats)

    except HTTPException:
        raise
    except MaestroError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        logger.error(f"Internal error: {e!s}", exc_info=ENABLE_TRACEBACK_LOGGING)
        raise HTTPException(status_code=500, detail="An internal error occurred") from e
    finally:
        cleanup_files(input_path)


# =============================================================================
# Validate
# =============================================================================

@router.post(
    "/validate/maestro",
    response_model=MaestroValidationResponse,
    summary="Validate MAESTRO threat model configuration",
)
@limiter.limit(RATE_LIMIT_ANALYZE)
async def validate_maestro(
    request: Request,
    file: UploadFile = File(..., description="MAESTRO configuration file"),
):
    """
    Validate a MAESTRO config and surface validation errors plus
    auto-populate warnings (including pattern x layer mismatches).
    """
    input_path = None

    try:
        validate_config_file_extension(file.filename)
        input_path = save_upload_file(file)
        mm = MaestroThreatModel(input_path, "unused")
        errors = mm.validate()
        return MaestroValidationResponse(
            valid=len(errors) == 0,
            errors=errors,
            warnings=list(mm.warnings),
        )

    except HTTPException:
        raise
    except MaestroError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        logger.error(f"Internal error: {e!s}", exc_info=ENABLE_TRACEBACK_LOGGING)
        raise HTTPException(status_code=500, detail="An internal error occurred") from e
    finally:
        cleanup_files(input_path)


# =============================================================================
# Catalog
# =============================================================================

@router.get(
    "/maestro/catalog",
    response_model=MaestroCatalogResponse,
    summary="Get the full MAESTRO threat catalog",
)
@limiter.limit(RATE_LIMIT_ANALYZE)
async def get_maestro_catalog(request: Request):
    """Return the built-in MAESTRO threat catalog (versioned, immutable IDs)."""
    try:
        mm = MaestroThreatModel("unused.toml", "unused", validate_paths=False)
        catalog = mm.get_catalog()
        return MaestroCatalogResponse(**catalog)
    except Exception as e:
        logger.error(f"Failed to load catalog: {e!s}", exc_info=ENABLE_TRACEBACK_LOGGING)
        raise HTTPException(status_code=500, detail="Failed to load catalog") from e


@router.get(
    "/maestro/catalog/{layer}",
    response_model=MaestroLayerThreatsResponse,
    summary="Get catalog threats for a single MAESTRO layer",
)
@limiter.limit(RATE_LIMIT_ANALYZE)
async def get_maestro_catalog_for_layer(request: Request, layer: str):
    """Return catalog threats scoped to one of the seven MAESTRO layers."""
    valid_layers = {ml.value for ml in MaestroLayer}
    if layer not in valid_layers:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown layer '{layer}'. Valid: {sorted(valid_layers)}",
        )

    try:
        mm = MaestroThreatModel("unused.toml", "unused", validate_paths=False)
        catalog = mm.get_catalog()
        layer_meta = catalog.get("layers", {}).get(layer, {})
        layer_name = layer_meta.get("name", layer)
        threats = [t for t in catalog.get("threats", []) if t["layer"] == layer]
        return MaestroLayerThreatsResponse(
            layer=layer,
            layer_name=layer_name,
            threats=threats,
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to load catalog layer: {e!s}", exc_info=ENABLE_TRACEBACK_LOGGING)
        raise HTTPException(status_code=500, detail="Failed to load catalog layer") from e
