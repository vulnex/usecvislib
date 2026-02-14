#
# VULNEX -Universal Security Visualization Library-
#
# File: routers/icons.py
# Description: Bundled Icons API endpoints
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
#

import os
import logging
from typing import Optional, List
from pathlib import Path

from fastapi import APIRouter, Query, Request, HTTPException
from fastapi.responses import FileResponse

from ..config import (
    limiter, RATE_LIMIT_DEFAULT,
    BUNDLED_ICONS_DIR, BUNDLED_ICON_CATEGORIES, BUNDLED_ICON_EXTENSIONS,
)
from ..schemas import (
    BundledIconInfo, BundledIconsListResponse, BundledIconsCategoriesResponse,
)

logger = logging.getLogger("usecvislib.api")

router = APIRouter(tags=["Icons"])


def _scan_bundled_icons(category: Optional[str] = None) -> List[dict]:
    """Scan the bundled icons directory recursively and return icon information."""
    icons = []

    if not os.path.isdir(BUNDLED_ICONS_DIR):
        logger.warning(f"Bundled icons directory not found: {BUNDLED_ICONS_DIR}")
        return icons

    categories_to_scan = [category] if category else BUNDLED_ICON_CATEGORIES

    for cat in categories_to_scan:
        cat_dir = os.path.join(BUNDLED_ICONS_DIR, cat)
        if not os.path.isdir(cat_dir):
            continue

        # Walk through all subdirectories recursively
        for root, dirs, files in os.walk(cat_dir):
            for filename in files:
                ext = os.path.splitext(filename)[1].lower()
                if ext not in BUNDLED_ICON_EXTENSIONS:
                    continue

                filepath = os.path.join(root, filename)
                name = os.path.splitext(filename)[0]

                # Calculate relative path from category directory for the ID
                rel_path = os.path.relpath(filepath, cat_dir)
                rel_dir = os.path.dirname(rel_path)

                # Create a clean icon ID: category/subdir/name or category/name
                if rel_dir and rel_dir != ".":
                    icon_id = f"{cat}/{rel_dir}/{name}"
                    subcategory = rel_dir.replace(os.sep, "/")
                else:
                    icon_id = f"{cat}/{name}"
                    subcategory = None

                try:
                    size = os.path.getsize(filepath)
                except OSError:
                    size = 0

                icons.append({
                    "id": icon_id,
                    "name": name,
                    "category": cat,
                    "subcategory": subcategory,
                    "filename": filename,
                    "format": ext[1:],  # Remove the leading dot
                    "size": size
                })

    return icons


@router.get(
    "/icons",
    response_model=BundledIconsListResponse,
    summary="List bundled icons"
)
@limiter.limit(RATE_LIMIT_DEFAULT)
async def list_bundled_icons(
    request: Request,
    category: Optional[str] = Query(None, description="Filter by category (azure, aws, bootstrap)"),
    subcategory: Optional[str] = Query(None, description="Filter by subcategory (e.g., Compute, Database)"),
    search: Optional[str] = Query(None, description="Search icons by name (case-insensitive)"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=10, le=200, description="Icons per page (10-200)")
):
    """
    List bundled icons with pagination, filtering, and search.

    Icons are organized by category:
    - **azure**: Microsoft Azure service icons (705 icons)
    - **aws**: Amazon Web Services icons (311 icons)
    - **bootstrap**: Bootstrap UI icons (2079 icons)

    Use the icon `id` (e.g., "aws/Compute/EC2") in your configuration
    with the `icon` attribute.
    """
    if category and category not in BUNDLED_ICON_CATEGORIES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid category. Available categories: {', '.join(BUNDLED_ICON_CATEGORIES)}"
        )

    # Get all icons for the category (or all categories)
    all_icons = _scan_bundled_icons(category)

    # Filter by subcategory if specified
    if subcategory:
        all_icons = [icon for icon in all_icons if icon.get("subcategory") == subcategory]

    # Filter by search query if specified
    if search:
        search_lower = search.lower()
        all_icons = [
            icon for icon in all_icons
            if search_lower in icon["name"].lower() or
               search_lower in icon.get("subcategory", "").lower() or
               search_lower in icon["id"].lower()
        ]

    # Get unique subcategories for the filtered results
    subcategories = sorted(set(
        icon.get("subcategory") for icon in _scan_bundled_icons(category)
        if icon.get("subcategory")
    ))

    # Calculate pagination
    total = len(all_icons)
    total_pages = max(1, (total + page_size - 1) // page_size)
    start_idx = (page - 1) * page_size
    end_idx = start_idx + page_size
    paginated_icons = all_icons[start_idx:end_idx]

    return BundledIconsListResponse(
        icons=[BundledIconInfo(**icon) for icon in paginated_icons],
        categories=BUNDLED_ICON_CATEGORIES,
        subcategories=subcategories,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
        has_more=page < total_pages
    )


@router.get(
    "/icons/categories",
    response_model=BundledIconsCategoriesResponse,
    summary="List icon categories"
)
@limiter.limit(RATE_LIMIT_DEFAULT)
async def list_icon_categories(request: Request):
    """
    List all available icon categories with their icon counts.
    """
    counts = {}
    for cat in BUNDLED_ICON_CATEGORIES:
        icons = _scan_bundled_icons(cat)
        counts[cat] = len(icons)

    return BundledIconsCategoriesResponse(
        categories=BUNDLED_ICON_CATEGORIES,
        counts=counts
    )


@router.get(
    "/icons/{icon_path:path}",
    summary="Get a bundled icon"
)
@limiter.limit(RATE_LIMIT_DEFAULT)
async def get_bundled_icon(
    request: Request,
    icon_path: str
):
    """
    Download a bundled icon by its path.

    The path format is: `category/[subcategory/]name`
    The name should not include the file extension - the API will find the
    appropriate file automatically.

    Examples:
    - `/icons/aws/Compute/EC2`
    - `/icons/bootstrap/icons/alarm`
    - `/icons/azure/Azure_Public_Service_Icons/Icons/compute/00195-icon-service-Maintenance-Configuration`
    """
    # SECURITY: Comprehensive path traversal prevention
    # Check for various bypass attempts including URL-encoded sequences
    dangerous_patterns = ['..', '%2e', '%2f', '%5c', '\x00', '\\']
    icon_path_lower = icon_path.lower()
    for pattern in dangerous_patterns:
        if pattern in icon_path_lower:
            logger.warning(f"Path traversal attempt blocked in icon path: {icon_path}")
            raise HTTPException(status_code=400, detail="Invalid icon path")

    # Split into parts
    parts = icon_path.split("/")
    if len(parts) < 2:
        raise HTTPException(status_code=400, detail="Invalid icon path. Format: category/[subcategory/]name")

    category = parts[0]

    # Validate category
    if category not in BUNDLED_ICON_CATEGORIES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid category. Available categories: {', '.join(BUNDLED_ICON_CATEGORIES)}"
        )

    # SECURITY: Validate each path component
    for part in parts:
        if not part or part.startswith('.'):
            raise HTTPException(status_code=400, detail="Invalid icon path")

    # Reconstruct the relative path (everything after category)
    relative_path = "/".join(parts[1:])

    base_dir = Path(BUNDLED_ICONS_DIR).resolve()
    cat_dir = Path(BUNDLED_ICONS_DIR) / category

    if not cat_dir.is_dir():
        raise HTTPException(status_code=404, detail="Category directory not found")

    # Find the icon file (try all supported extensions)
    icon_file_path = None
    for ext in BUNDLED_ICON_EXTENSIONS:
        candidate = cat_dir / f"{relative_path}{ext}"
        try:
            resolved = candidate.resolve()
            # SECURITY: Verify path stays within icons directory
            if not resolved.is_relative_to(base_dir):
                logger.warning(f"Path traversal blocked: {icon_path}")
                raise HTTPException(status_code=400, detail="Invalid icon path")
            # SECURITY: Reject symlinks
            if resolved.is_symlink():
                logger.warning(f"Symlink rejected: {icon_path}")
                raise HTTPException(status_code=400, detail="Invalid icon path")
            if resolved.is_file():
                icon_file_path = str(resolved)
                break
        except (ValueError, RuntimeError):
            continue

    if not icon_file_path:
        raise HTTPException(status_code=404, detail=f"Icon not found: {icon_path}")

    # Determine content type
    ext = os.path.splitext(icon_file_path)[1].lower()
    content_types = {
        ".png": "image/png",
        ".svg": "image/svg+xml",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".gif": "image/gif"
    }
    content_type = content_types.get(ext, "application/octet-stream")

    return FileResponse(
        path=icon_file_path,
        media_type=content_type,
        filename=os.path.basename(icon_file_path)
    )
