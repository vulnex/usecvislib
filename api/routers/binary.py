#
# VULNEX -Universal Security Visualization Library-
#
# File: routers/binary.py
# Description: Binary Visualization API endpoints
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
#

import os
import json
import logging
from typing import Optional

from fastapi import APIRouter, File, UploadFile, Query, Form, BackgroundTasks, Request, HTTPException
from fastapi.responses import FileResponse

from usecvislib import BinVis
from usecvislib.utils import FileError, ConfigError, RenderError

from ..config import (
    limiter, RATE_LIMIT_VISUALIZE, RATE_LIMIT_ANALYZE,
    ENABLE_TRACEBACK_LOGGING, TEMP_DIR,
    REQUEST_TIMEOUT_VISUALIZE, MAX_BINARY_FILE_SIZE,
)
from ..helpers import (
    save_upload_file, cleanup_files, get_content_type,
    run_sync_with_timeout,
)
from ..schemas import (
    OutputFormat, BinVisStyle, BinVisType, BinVisConfig, FileStats,
)

logger = logging.getLogger("usecvislib.api")

router = APIRouter(tags=["Binary Visualization"])


def apply_binvis_config(bv: BinVis, config: BinVisConfig) -> None:
    """Apply API config schema to BinVis instance.

    Args:
        bv: BinVis instance to configure
        config: BinVisConfig schema with user settings
    """
    if config.entropy_analysis:
        entropy_dict = config.entropy_analysis.model_dump(exclude_none=True)
        # Convert thresholds to list of dicts
        if "thresholds" in entropy_dict:
            entropy_dict["thresholds"] = [t.model_dump() for t in config.entropy_analysis.thresholds]
        bv.config["entropy_analysis"].update(entropy_dict)

    if config.byte_distribution:
        dist_dict = config.byte_distribution.model_dump(exclude_none=True)
        if "regions" in dist_dict:
            dist_dict["regions"] = [r.model_dump() for r in config.byte_distribution.regions]
        bv.config["byte_distribution"].update(dist_dict)

    if config.wind_rose:
        bv.config["wind_rose"].update(config.wind_rose.model_dump(exclude_none=True))

    if config.heatmap:
        bv.config["heatmap"].update(config.heatmap.model_dump(exclude_none=True))


@router.post(
    "/visualize/binary",
    summary="Generate binary file visualization",
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
async def visualize_binary(
    request: Request,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(..., description="Binary file to analyze"),
    format: OutputFormat = Query(default=OutputFormat.PNG, description="Output format"),
    style: BinVisStyle = Query(default=BinVisStyle.DEFAULT, description="Style preset"),
    visualization_type: BinVisType = Query(default=BinVisType.ENTROPY, description="Visualization type"),
    config_json: Optional[str] = Form(default=None, description="JSON string with visualization configuration"),
):
    """
    Generate a visualization from an uploaded binary file.

    Visualization types:
    - **entropy**: Sliding window entropy analysis
    - **distribution**: Byte frequency histogram
    - **windrose**: Byte pair pattern visualization
    - **heatmap**: 2D file structure visualization
    - **all**: Generate all visualization types (returns entropy only via API)

    Configuration options (pass as JSON in config_json):
    - **entropy_analysis**: window_size, step, thresholds, fill_alpha, show_grid
    - **byte_distribution**: bar_width, bar_alpha, regions, show_regions
    - **wind_rose**: bar_alpha, rticks, rlabel_position
    - **heatmap**: block_size, interpolation, aspect, show_colorbar
    """
    input_path = None
    output_path = None

    try:
        # Save uploaded binary file (with larger size limit)
        input_path = save_upload_file(file, ".bin", max_size=MAX_BINARY_FILE_SIZE)
        output_base = os.path.join(TEMP_DIR, f"output_{os.urandom(8).hex()}")

        bv = BinVis(input_path, output_base, format=format.value, styleid=style.value)

        # Apply config from JSON if provided
        if config_json:
            try:
                config_dict = json.loads(config_json)
                config = BinVisConfig(**config_dict)
                apply_binvis_config(bv, config)
                logger.debug(f"Applied custom config: {list(config_dict.keys())}")
            except (json.JSONDecodeError, ValueError) as e:
                logger.warning(f"Invalid config JSON: {str(e)}")
                raise HTTPException(status_code=400, detail="Invalid configuration format")

        # Generate visualization with timeout protection
        # SECURITY: Prevents resource exhaustion from large binary files
        vis_type = visualization_type.value
        if vis_type == "all":
            await run_sync_with_timeout(
                lambda: bv.BuildBinVis("all"),
                REQUEST_TIMEOUT_VISUALIZE,
                "binary visualization (all)"
            )
            output_path = f"{output_base}_entropy.{format.value}"
        else:
            await run_sync_with_timeout(
                lambda: bv.BuildBinVis(vis_type),
                REQUEST_TIMEOUT_VISUALIZE,
                f"binary visualization ({vis_type})"
            )
            output_path = f"{output_base}_{vis_type}.{format.value}"

        if not os.path.exists(output_path):
            cleanup_files(input_path)
            raise HTTPException(status_code=500, detail="Failed to generate visualization")

        # Schedule cleanup after response is sent
        background_tasks.add_task(cleanup_files, input_path, output_path)

        return FileResponse(
            path=output_path,
            media_type=get_content_type(format),
            filename=f"binary_{vis_type}.{format.value}",
        )

    except (FileNotFoundError, FileError, ConfigError) as e:
        cleanup_files(input_path, output_path)
        raise HTTPException(status_code=400, detail=str(e))
    except ValueError as e:
        cleanup_files(input_path, output_path)
        raise HTTPException(status_code=400, detail=str(e))
    except RenderError as e:
        cleanup_files(input_path, output_path)
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        cleanup_files(input_path, output_path)
        logger.error(f"Internal error: {str(e)}", exc_info=ENABLE_TRACEBACK_LOGGING)
        raise HTTPException(status_code=500, detail="An internal error occurred")


@router.post(
    "/analyze/binary",
    response_model=FileStats,
    summary="Analyze binary file statistics"
)
@limiter.limit(RATE_LIMIT_ANALYZE)
async def analyze_binary(
    request: Request,
    file: UploadFile = File(..., description="Binary file to analyze"),
):
    """
    Analyze a binary file and return statistics without generating visualization.

    Returns:
    - File size
    - Overall entropy
    - Unique byte count
    - Percentage of null bytes
    - Percentage of printable ASCII
    - Percentage of high bytes (128-255)
    """
    input_path = None

    try:
        input_path = save_upload_file(file, ".bin", max_size=MAX_BINARY_FILE_SIZE)
        bv = BinVis(input_path, "unused")
        stats = bv.get_file_stats()

        # Remove most_common as it's not serializable easily
        stats.pop("most_common", None)

        return FileStats(**stats)

    except (FileNotFoundError, FileError, ConfigError) as e:
        raise HTTPException(status_code=400, detail=str(e))
    except RenderError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Internal error: {str(e)}", exc_info=ENABLE_TRACEBACK_LOGGING)
        raise HTTPException(status_code=500, detail="An internal error occurred")
    finally:
        cleanup_files(input_path)
