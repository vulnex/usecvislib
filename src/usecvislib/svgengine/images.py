#
# VULNEX -Universal Security Visualization Library-
#
# File: images.py
# Author: Simon Roses Femerling
# Created: 2026-08-08
# Last Modified: 2026-08-08
# Version: 0.4.1
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Image embedding for the SVG engine.

The Graphviz engine references node images by local file path (HTML-table
labels), which breaks the moment the SVG leaves the machine or is inlined
in a browser. The SVG engine instead embeds the image bytes as a base64
data URI in an ``<image>`` element, so output stays self-contained.

Resolution goes through the same validated pipeline as the Graphviz path
(``utils.resolve_image_reference``: ``bundled:`` / ``uploaded:`` / local
path). Files over ``utils.IMAGE_MAX_SIZE`` are refused; large rasters are
downscaled in memory via PIL (when available) so a 48px icon does not drag
megabytes of pixels into the document.
"""

import base64
import io
import logging
from pathlib import Path
from typing import Optional

from .. import utils

logger = logging.getLogger(__name__)

MIME_TYPES = {
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".bmp": "image/bmp",
    ".svg": "image/svg+xml",
}

# Downscale target: 2x the on-canvas icon box, for crisp raster on zoom.
THUMBNAIL_PX = 96


def _downscale(path: Path) -> Optional[bytes]:
    """Downscale a large raster image to PNG bytes in memory.

    Returns None when PIL is unavailable, the image is already small,
    or decoding fails (caller embeds the original bytes instead).
    """
    if not utils.PIL_AVAILABLE:
        return None
    try:
        from PIL import Image

        with Image.open(path) as img:
            if img.width <= THUMBNAIL_PX and img.height <= THUMBNAIL_PX:
                return None
            img.thumbnail((THUMBNAIL_PX, THUMBNAIL_PX), Image.Resampling.LANCZOS)
            buffer = io.BytesIO()
            img.save(buffer, format="PNG")
            return buffer.getvalue()
    except Exception as e:
        logger.debug(f"Could not downscale image {path}: {e}")
        return None


def resolve_data_uri(image_ref: str, node_id: str) -> Optional[str]:
    """Resolve an image reference and embed it as a base64 data URI.

    Args:
        image_ref: ``bundled:``/``uploaded:``/local-path reference.
        node_id: Node identifier for log messages.

    Returns:
        A ``data:<mime>;base64,...`` string, or None (with a logged
        warning) when the reference cannot be resolved or embedded.
    """
    path = utils.resolve_image_reference(str(image_ref))
    if path is None:
        logger.warning(f"Could not resolve image for node '{node_id}': {image_ref}")
        return None

    mime = MIME_TYPES.get(path.suffix.lower())
    if mime is None:
        logger.warning(f"Node '{node_id}': image type '{path.suffix}' not supported by SVG engine")
        return None

    try:
        if path.stat().st_size > utils.IMAGE_MAX_SIZE:
            logger.warning(f"Node '{node_id}': image exceeds {utils.IMAGE_MAX_SIZE} bytes, skipped: {path}")
            return None
        data = path.read_bytes()
    except OSError as e:
        logger.warning(f"Node '{node_id}': could not read image {path}: {e}")
        return None

    if mime != "image/svg+xml":
        scaled = _downscale(path)
        if scaled is not None:
            data, mime = scaled, "image/png"

    return f"data:{mime};base64,{base64.b64encode(data).decode('ascii')}"
