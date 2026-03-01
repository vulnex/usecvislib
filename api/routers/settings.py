#
# VULNEX -Universal Security Visualization Library-
#
# File: routers/settings.py
# Description: Display Settings API endpoints
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
#

import logging

from fastapi import APIRouter, Request, HTTPException

from usecvislib.settings import get_settings, get_cvss_display_settings, set_cvss_display_settings

from ..config import (
    limiter, RATE_LIMIT_DEFAULT, ENABLE_TRACEBACK_LOGGING,
)
from ..schemas import (
    DisplaySettingsResponse, CVSSDisplaySettings, DisplaySettingsRequest,
)

logger = logging.getLogger("usecvislib.api")

router = APIRouter(tags=["Settings"])


@router.get(
    "/settings",
    response_model=DisplaySettingsResponse,
    summary="Get current display settings"
)
@limiter.limit(RATE_LIMIT_DEFAULT)
async def get_display_settings(request: Request):
    """
    Get current display settings including CVSS visibility toggles.

    Returns the current state of all display settings that control
    how visualizations are rendered.
    """
    try:
        cvss_settings = get_cvss_display_settings()
        return DisplaySettingsResponse(
            cvss_display=CVSSDisplaySettings(**cvss_settings)
        )
    except Exception as e:
        logger.error(f"Error getting display settings: {str(e)}", exc_info=ENABLE_TRACEBACK_LOGGING)
        raise HTTPException(status_code=500, detail="An internal error occurred while retrieving settings")


@router.put(
    "/settings",
    response_model=DisplaySettingsResponse,
    summary="Update display settings"
)
@limiter.limit(RATE_LIMIT_DEFAULT)
async def update_display_settings(
    request: Request,
    settings: DisplaySettingsRequest
):
    """
    Update display settings for visualizations.

    Allows toggling CVSS display on/off globally or for specific
    visualization types (attack trees, attack graphs, threat models).

    **CVSS Display Options:**
    - `enabled`: Global toggle - if False, CVSS is hidden everywhere
    - `attack_tree`: Toggle CVSS in attack tree visualizations
    - `attack_graph`: Toggle CVSS in attack graph visualizations
    - `threat_model`: Toggle CVSS in threat model reports

    Settings persist for the lifetime of the API server.
    """
    try:
        if settings.cvss_display:
            set_cvss_display_settings(settings.cvss_display.model_dump())
            logger.info(f"Updated CVSS display settings: {settings.cvss_display.model_dump()}")

        # Return updated settings
        cvss_settings = get_cvss_display_settings()
        return DisplaySettingsResponse(
            cvss_display=CVSSDisplaySettings(**cvss_settings)
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid settings value: {str(e)}")
    except Exception as e:
        logger.error(f"Error updating display settings: {str(e)}", exc_info=ENABLE_TRACEBACK_LOGGING)
        raise HTTPException(status_code=500, detail="An internal error occurred while updating settings")


@router.post(
    "/settings/cvss/enable-all",
    response_model=DisplaySettingsResponse,
    summary="Enable CVSS display for all visualization types"
)
@limiter.limit(RATE_LIMIT_DEFAULT)
async def enable_cvss_all(request: Request):
    """
    Enable CVSS display for all visualization types.

    Sets all CVSS display toggles to True.
    """
    try:
        settings = get_settings()
        settings.enable_cvss_all()
        logger.info("Enabled CVSS display for all visualization types")

        cvss_settings = get_cvss_display_settings()
        return DisplaySettingsResponse(
            cvss_display=CVSSDisplaySettings(**cvss_settings)
        )
    except Exception as e:
        logger.error(f"Error enabling CVSS display: {str(e)}", exc_info=ENABLE_TRACEBACK_LOGGING)
        raise HTTPException(status_code=500, detail="An internal error occurred while updating settings")


@router.post(
    "/settings/cvss/disable-all",
    response_model=DisplaySettingsResponse,
    summary="Disable CVSS display for all visualization types"
)
@limiter.limit(RATE_LIMIT_DEFAULT)
async def disable_cvss_all(request: Request):
    """
    Disable CVSS display for all visualization types.

    Sets all CVSS display toggles to False.
    """
    try:
        settings = get_settings()
        settings.disable_cvss_all()
        logger.info("Disabled CVSS display for all visualization types")

        cvss_settings = get_cvss_display_settings()
        return DisplaySettingsResponse(
            cvss_display=CVSSDisplaySettings(**cvss_settings)
        )
    except Exception as e:
        logger.error(f"Error disabling CVSS display: {str(e)}", exc_info=ENABLE_TRACEBACK_LOGGING)
        raise HTTPException(status_code=500, detail="An internal error occurred while updating settings")


@router.post(
    "/settings/reset",
    response_model=DisplaySettingsResponse,
    summary="Reset all display settings to defaults"
)
@limiter.limit(RATE_LIMIT_DEFAULT)
async def reset_display_settings(request: Request):
    """
    Reset all display settings to their default values.

    Restores CVSS display to enabled for all visualization types.
    """
    try:
        settings = get_settings()
        settings.reset()
        logger.info("Reset display settings to defaults")

        cvss_settings = get_cvss_display_settings()
        return DisplaySettingsResponse(
            cvss_display=CVSSDisplaySettings(**cvss_settings)
        )
    except Exception as e:
        logger.error(f"Error resetting display settings: {str(e)}", exc_info=ENABLE_TRACEBACK_LOGGING)
        raise HTTPException(status_code=500, detail="An internal error occurred while resetting settings")
