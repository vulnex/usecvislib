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
from typing import Optional

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
    MaestroExportFormat,
    MaestroExportResponse,
    MaestroLayerThreatsResponse,
    MaestroStats,
    MaestroStyle,
    MaestroThreatDetail,
    MaestroThreatsResponse,
    MaestroValidationResponse,
    MaestroView,
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
    view: MaestroView = Query(default=MaestroView.LAYERED, description="Render view: layered, graph, or heatmap"),
):
    """
    Generate a MAESTRO threat model visualization from an uploaded configuration file.

    The configuration file should contain `meta`, `agents[]`, optional `assets[]`,
    `architecture.patterns[]`, and optional `threats[]`, `cross_layer_threats[]`,
    and `mitigations[]` sections.

    Catalog threats are auto-attached based on the layers each agent touches
    and the declared architecture patterns. The ``view`` query parameter
    selects between the layered architecture diagram (default), the agent-centric
    graph (clusters by primary layer with attack chains as directed edges),
    and the severity heatmap (agents x layers).
    """
    input_path = None
    output_path = None

    try:
        validate_config_file_extension(file.filename)
        input_path = save_upload_file(file)
        output_base = os.path.join(TEMP_DIR, f"output_{os.urandom(8).hex()}")

        mm = MaestroThreatModel(
            input_path,
            output_base,
            format=format.value,
            styleid=style.value,
            view=view.value,
        )
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
# Threats (filterable detail)
# =============================================================================

@router.post(
    "/analyze/maestro/threats",
    response_model=MaestroThreatsResponse,
    summary="List MAESTRO threats with optional filtering",
)
@limiter.limit(RATE_LIMIT_ANALYZE)
async def list_maestro_threats(
    request: Request,
    file: UploadFile = File(..., description="MAESTRO configuration file"),
    layer: Optional[str] = Query(default=None, description="Filter by MAESTRO layer key"),
    severity: Optional[str] = Query(default=None, description="Filter by severity (low/medium/high/critical)"),
    status: Optional[str] = Query(default=None, description="Filter by status (identified/in-progress/mitigated/accepted/not-applicable)"),
):
    """
    Return per-threat detail after auto-population and overrides are applied,
    with optional filters on layer, severity, and status. Powers the Threat
    List tab in the Vue panel.
    """
    input_path = None

    try:
        validate_config_file_extension(file.filename)
        input_path = save_upload_file(file)
        mm = MaestroThreatModel(input_path, "unused")
        mm.load()

        all_layers: set[str] = set()
        all_severities: set[str] = set()
        all_statuses: set[str] = set()

        threats: list[MaestroThreatDetail] = []
        for t in mm.threats.values():
            all_layers.add(t.layer)
            all_severities.add(t.severity)
            all_statuses.add(t.status)
            if layer and t.layer != layer:
                continue
            if severity and t.severity != severity:
                continue
            if status and t.status != status:
                continue
            threats.append(MaestroThreatDetail(
                id=t.id,
                layer=t.layer,
                name=t.name,
                description=t.description,
                target_id=t.target_id,
                severity=t.severity,
                likelihood=t.likelihood,
                status=t.status,
                mitigations=list(t.mitigations),
                stride_category=t.stride_category,
                stride_mapping=t.stride_mapping,
                mitre_attack=t.mitre_attack,
                owasp_asi=t.owasp_asi,
                nist_ai_rmf=t.nist_ai_rmf,
                from_catalog=t.from_catalog,
            ))

        return MaestroThreatsResponse(
            total=len(threats),
            threats=threats,
            layers=sorted(all_layers),
            severities=sorted(all_severities),
            statuses=sorted(all_statuses),
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


# =============================================================================
# Cross-Reference Exports (Phase 3)
# =============================================================================

@router.post(
    "/maestro/export/{target}",
    response_model=MaestroExportResponse,
    summary="Export MAESTRO model to a sibling framework",
)
@limiter.limit(RATE_LIMIT_ANALYZE)
async def export_maestro(
    request: Request,
    target: MaestroExportFormat,
    file: UploadFile = File(..., description="MAESTRO configuration file"),
):
    """
    Export a MAESTRO model to a sibling framework consumable by other USecVisLib modules:

    - ``stride``: STRIDE / threat-modeling shape (model / processes / datastores /
      threats), with explicit per-entry ``mapping`` label (``exact``/``partial``/
      ``informational``) and a ``_meta`` block summarising mapping coverage.
    - ``attack-graph``: AttackGraph shape (hosts / vulnerabilities / edges),
      materialising cross-layer attack chains.
    - ``privilege-gradient``: PrivilegeGradient shape with trust zones derived
      from agent autonomy levels.
    """
    input_path = None

    try:
        validate_config_file_extension(file.filename)
        input_path = save_upload_file(file)
        mm = MaestroThreatModel(input_path, "unused")
        mm.load()

        catalog = mm.get_catalog()
        catalog_version = catalog.get("catalog_version", "unknown")

        if target == MaestroExportFormat.STRIDE:
            payload = mm.to_stride()
        elif target == MaestroExportFormat.ATTACK_GRAPH:
            payload = mm.to_attack_graph()
        elif target == MaestroExportFormat.PRIVILEGE_GRADIENT:
            payload = mm.to_privilege_gradient()
        else:
            raise HTTPException(status_code=400, detail=f"Unsupported target: {target}")

        return MaestroExportResponse(
            target_framework=target.value,
            catalog_version=catalog_version,
            payload=payload,
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
