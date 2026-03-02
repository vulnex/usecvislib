#
# VULNEX -Universal Security Visualization Library-
#
# File: routers/images.py
# Description: Image Upload API endpoints
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
#

import logging
import os
import uuid
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse

from ..auth import verify_api_key
from ..config import (
    IMAGE_ALLOWED_TYPES,
    IMAGE_MAX_SIZE,
    RATE_LIMIT_DEFAULT,
    limiter,
)
from ..helpers import (
    get_image_content_type,
    get_user_image_dir,
    get_user_namespace,
    is_valid_image,
    resolve_image_id,
    sanitize_filename_for_log,
)
from ..schemas import (
    ImageDeleteResponse,
    ImageInfoResponse,
    ImageListResponse,
    ImageUploadResponse,
)

logger = logging.getLogger("usecvislib.api")

# SECURITY: Reduced from 30/minute to 10/minute to prevent disk exhaustion attacks
# With 5MB max per image and 1 hour cleanup, 10/min = max 3GB/hour worst case
RATE_LIMIT_IMAGE_UPLOAD = os.getenv("RATE_LIMIT_IMAGE_UPLOAD", "10/minute")

router = APIRouter(tags=["Images"])


@router.post(
    "/images/upload",
    response_model=ImageUploadResponse,
    summary="Upload an image for use in visualizations"
)
@limiter.limit(RATE_LIMIT_IMAGE_UPLOAD)
async def upload_image(
    request: Request,
    file: UploadFile = File(..., description="Image file to upload (PNG, JPEG, GIF, SVG, BMP)"),
    api_key: Optional[str] = Depends(verify_api_key)
):
    """
    Upload an image for use in node visualizations.

    The returned `image_id` can be used in configuration files:

    ```toml
    [nodes.server]
    label = "Web Server"
    image_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    ```

    **Supported formats:** PNG, JPEG, GIF, SVG, BMP
    **Maximum size:** 5 MB
    **Retention:** Images are automatically deleted after 1 hour

    Returns the unique image_id to reference in visualizations.
    """
    # Validate content type
    if file.content_type not in IMAGE_ALLOWED_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported image type: {file.content_type}. Allowed: {list(IMAGE_ALLOWED_TYPES.keys())}"
        )

    # Read and validate size
    contents = await file.read()
    if len(contents) > IMAGE_MAX_SIZE:
        raise HTTPException(
            status_code=400,
            detail=f"Image too large. Maximum size: {IMAGE_MAX_SIZE // (1024*1024)} MB"
        )

    # Validate it's actually an image (magic bytes check)
    if not is_valid_image(contents, file.content_type):
        raise HTTPException(
            status_code=400,
            detail="Invalid image file. Content does not match expected format."
        )

    # Generate unique ID and save to user-specific directory
    # SECURITY: Per-user isolation prevents cross-user image access
    image_id = str(uuid.uuid4())
    ext = IMAGE_ALLOWED_TYPES[file.content_type]
    filename = f"{image_id}{ext}"
    user_image_dir = get_user_image_dir(api_key)
    filepath = os.path.join(user_image_dir, filename)

    os.makedirs(user_image_dir, exist_ok=True)

    with open(filepath, 'wb') as f:
        f.write(contents)

    user_ns = get_user_namespace(api_key)
    logger.info(f"Image uploaded: {image_id} ({sanitize_filename_for_log(file.filename)}, {len(contents)} bytes, ns={user_ns})")

    return ImageUploadResponse(
        image_id=image_id,
        filename=file.filename or "unknown",
        size=len(contents),
        content_type=file.content_type
    )


@router.get(
    "/images/{image_id}",
    response_model=ImageInfoResponse,
    summary="Get information about an uploaded image"
)
@limiter.limit(RATE_LIMIT_DEFAULT)
async def get_image_info(
    request: Request,
    image_id: str,
    api_key: Optional[str] = Depends(verify_api_key)
):
    """
    Get information about an uploaded image by its ID.

    Returns image metadata including size, content type, and creation time.
    Images are isolated per-user based on API key.
    """
    # SECURITY: Use secure image resolution with UUID validation and user isolation
    try:
        filepath = resolve_image_id(image_id, api_key)
    except ValueError:
        raise HTTPException(status_code=404, detail="Image not found") from None

    stat = os.stat(filepath)

    return ImageInfoResponse(
        image_id=image_id,
        exists=True,
        size=stat.st_size,
        content_type=get_image_content_type(filepath),
        created_at=datetime.fromtimestamp(stat.st_mtime).isoformat() + "Z"
    )


@router.get(
    "/images/{image_id}/download",
    summary="Download an uploaded image"
)
@limiter.limit(RATE_LIMIT_DEFAULT)
async def download_image(
    request: Request,
    image_id: str,
    api_key: Optional[str] = Depends(verify_api_key)
):
    """
    Download an uploaded image by its ID.

    Returns the image file.
    Images are isolated per-user based on API key.
    """
    # SECURITY: Use secure image resolution with UUID validation and user isolation
    try:
        filepath = resolve_image_id(image_id, api_key)
    except ValueError:
        raise HTTPException(status_code=404, detail="Image not found") from None

    content_type = get_image_content_type(filepath)

    return FileResponse(
        filepath,
        media_type=content_type,
        filename=os.path.basename(filepath)
    )


@router.delete(
    "/images/{image_id}",
    response_model=ImageDeleteResponse,
    summary="Delete an uploaded image"
)
@limiter.limit(RATE_LIMIT_DEFAULT)
async def delete_image(
    request: Request,
    image_id: str,
    api_key: Optional[str] = Depends(verify_api_key)
):
    """
    Delete an uploaded image by its ID.

    This permanently removes the image from the server.
    Images are isolated per-user based on API key.
    """
    # SECURITY: Use secure image resolution with UUID validation and user isolation
    try:
        filepath = resolve_image_id(image_id, api_key)
    except ValueError:
        raise HTTPException(status_code=404, detail="Image not found") from None

    os.unlink(filepath)

    user_ns = get_user_namespace(api_key)
    logger.info(f"Image deleted: {image_id} (ns={user_ns})")

    return ImageDeleteResponse(
        deleted=True,
        image_id=image_id
    )


@router.get(
    "/images",
    response_model=ImageListResponse,
    summary="List all uploaded images"
)
@limiter.limit(RATE_LIMIT_DEFAULT)
async def list_images(
    request: Request,
    api_key: Optional[str] = Depends(verify_api_key)
):
    """
    List your uploaded images.

    Returns a list of image information including IDs, sizes, and types.
    Images are isolated per-user based on API key.
    Note: Images are automatically cleaned up after the retention period.
    """
    images = []

    # SECURITY: Only list images in user's namespace
    user_image_dir = get_user_image_dir(api_key)

    if os.path.exists(user_image_dir):
        for filename in os.listdir(user_image_dir):
            filepath = os.path.join(user_image_dir, filename)
            if os.path.isfile(filepath):
                # Extract image_id from filename (remove extension)
                image_id = os.path.splitext(filename)[0]
                stat = os.stat(filepath)

                images.append(ImageInfoResponse(
                    image_id=image_id,
                    exists=True,
                    size=stat.st_size,
                    content_type=get_image_content_type(filepath),
                    created_at=datetime.fromtimestamp(stat.st_mtime).isoformat() + "Z"
                ))

    return ImageListResponse(
        images=images,
        total=len(images)
    )
