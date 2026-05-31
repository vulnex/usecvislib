#
# VULNEX -Universal Security Visualization Library-
#
# File: helpers.py
# Description: Shared utility functions for API endpoints
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
#

import asyncio
import json
import logging
import os
import time
from collections.abc import Callable, Coroutine
from functools import wraps
from pathlib import Path
from typing import Any, Optional, TypeVar

from fastapi import HTTPException, UploadFile

from .config import (
    IMAGE_ALLOWED_TYPES,
    IMAGE_CLEANUP_AGE,
    IMAGE_MAGIC_BYTES,
    IMAGE_UPLOAD_DIR,
    MAX_CONFIG_FILE_SIZE,
    PROGRESS_ENTRY_TTL,
    PROGRESS_MAX_ENTRIES,
    SUPPORTED_CONFIG_EXTENSIONS,
    TEMP_DIR,
    UUID_PATTERN,
)
from .schemas import OutputFormat

logger = logging.getLogger("usecvislib.api")

T = TypeVar("T")


# =============================================================================
# Timeout Helpers
# =============================================================================


async def run_with_timeout(coro: Coroutine[Any, Any, T], timeout_seconds: int, operation_name: str = "operation") -> T:
    """Run a coroutine with a timeout.

    SECURITY: Prevents resource exhaustion from slow/complex operations.

    Args:
        coro: The coroutine to run
        timeout_seconds: Maximum time in seconds
        operation_name: Name for error messages

    Returns:
        The result of the coroutine

    Raises:
        HTTPException: 504 Gateway Timeout if operation exceeds timeout
    """
    try:
        return await asyncio.wait_for(coro, timeout=timeout_seconds)
    except asyncio.TimeoutError:
        logger.warning(f"Request timeout: {operation_name} exceeded {timeout_seconds}s")
        raise HTTPException(
            status_code=504, detail=f"Request timeout: {operation_name} took too long (max {timeout_seconds}s)"
        ) from None


async def run_sync_with_timeout(
    func: Callable[..., T], timeout_seconds: int, operation_name: str = "operation", *args, **kwargs
) -> T:
    """Run a synchronous function in a thread pool with timeout.

    SECURITY: Prevents resource exhaustion from slow/complex synchronous operations.

    Args:
        func: The synchronous function to run
        timeout_seconds: Maximum time in seconds
        operation_name: Name for error messages
        *args: Positional arguments for func
        **kwargs: Keyword arguments for func

    Returns:
        The result of the function

    Raises:
        HTTPException: 504 Gateway Timeout if operation exceeds timeout
    """
    try:
        return await asyncio.wait_for(asyncio.to_thread(func, *args, **kwargs), timeout=timeout_seconds)
    except asyncio.TimeoutError:
        logger.warning(f"Request timeout: {operation_name} exceeded {timeout_seconds}s")
        raise HTTPException(
            status_code=504, detail=f"Request timeout: {operation_name} took too long (max {timeout_seconds}s)"
        ) from None


def with_timeout(timeout_seconds: int, operation_name: str = "operation"):
    """Decorator to add timeout to async endpoint functions.

    SECURITY: Prevents resource exhaustion from slow/complex operations.

    Args:
        timeout_seconds: Maximum time in seconds
        operation_name: Name for error messages

    Returns:
        Decorated function with timeout enforcement
    """

    def decorator(func: Callable[..., Coroutine[Any, Any, T]]) -> Callable[..., Coroutine[Any, Any, T]]:
        @wraps(func)
        async def wrapper(*args, **kwargs) -> T:
            try:
                return await asyncio.wait_for(func(*args, **kwargs), timeout=timeout_seconds)
            except asyncio.TimeoutError:
                logger.warning(f"Request timeout: {operation_name} exceeded {timeout_seconds}s")
                raise HTTPException(
                    status_code=504, detail=f"Request timeout: {operation_name} took too long (max {timeout_seconds}s)"
                ) from None

        return wrapper

    return decorator


# =============================================================================
# Validation Helpers
# =============================================================================


def validate_uuid_format(value: str) -> bool:
    """Validate that a string is a valid UUID format.

    Args:
        value: String to validate

    Returns:
        True if valid UUID format, False otherwise
    """
    return bool(UUID_PATTERN.match(value))


def validate_path_component(component: str) -> bool:
    """Validate a path component is safe (no traversal attempts).

    Args:
        component: Single path component to validate

    Returns:
        True if safe, False if contains traversal or dangerous chars
    """
    if not component:
        return False
    # Check for path traversal attempts
    if ".." in component:
        return False
    # Check for absolute path indicators
    if component.startswith("/") or component.startswith("\\"):
        return False
    # Check for URL-encoded traversal
    if "%2e" in component.lower() or "%2f" in component.lower():
        return False
    # Check for null bytes
    return "\x00" not in component


def validate_path_within_directory(path: Path, base_dir: Path) -> bool:
    """Validate that a resolved path stays within the base directory.

    SECURITY: Prevents path traversal attacks (CWE-22) by ensuring resolved
    paths cannot escape the intended base directory via '../' sequences,
    symlinks, or other path manipulation techniques.

    Args:
        path: Resolved absolute path to check
        base_dir: Base directory that should contain the path

    Returns:
        True if path is within base_dir, False otherwise
    """
    try:
        path = path.resolve()
        base_dir = base_dir.resolve()
        return path.is_relative_to(base_dir)
    except (ValueError, RuntimeError):
        return False


def is_safe_symlink(path: Path) -> bool:
    """Check if a path is a symlink (which we reject for security).

    SECURITY: Prevents symlink attacks (CWE-59) where an attacker could
    create a symlink pointing to sensitive files outside allowed directories.
    Always call this after validate_path_within_directory for defense-in-depth.

    Args:
        path: Path to check

    Returns:
        True if NOT a symlink (safe), False if symlink (reject)
    """
    return not path.is_symlink()


def sanitize_filename_for_log(filename: str) -> str:
    """Sanitize a filename for safe logging.

    Prevents log injection and removes potentially dangerous characters
    while preserving enough of the filename to be useful for debugging.

    Args:
        filename: Raw filename from user input

    Returns:
        Sanitized filename safe for logging
    """
    if not filename:
        return "<empty>"
    # Limit length to prevent log flooding
    if len(filename) > 100:
        filename = filename[:97] + "..."
    # Remove control characters and newlines (log injection prevention)
    sanitized = "".join(c if c.isprintable() and c not in "\r\n\t" else "_" for c in filename)
    # Escape any remaining special log format characters
    sanitized = sanitized.replace("%", "%%")
    return sanitized


# =============================================================================
# Image Helper Functions
# =============================================================================


def is_valid_image(content: bytes, claimed_type: str) -> bool:
    """Validate image content by checking magic bytes.

    SECURITY: Prevents file type spoofing attacks by validating actual
    content bytes rather than trusting client-provided MIME types or
    file extensions. Mitigates risks from malicious files disguised as images.

    Args:
        content: Raw file content
        claimed_type: MIME type claimed by the upload

    Returns:
        True if content matches a valid image format
    """
    # Check magic bytes FIRST (defense-in-depth: verify actual content before trusting claimed type)
    magic_match = False
    for magic, _detected_type in IMAGE_MAGIC_BYTES.items():
        if content.startswith(magic):
            magic_match = True
            break

    # For SVG, check for XML/SVG content with XXE prevention
    if claimed_type == "image/svg+xml":
        try:
            text = content.decode("utf-8", errors="ignore")
            text_lower = text.lower()
            # SECURITY: Scan entire content for DTD/entity declarations (XXE vectors)
            if "<!doctype" in text_lower or "<!entity" in text_lower:
                return False
            # Check header for valid SVG/XML markers
            header_lower = text_lower[:4000]
            return "<svg" in header_lower or "<?xml" in header_lower
        except Exception:
            return False

    return magic_match


def get_image_content_type(filepath: str) -> str:
    """Get content type from file extension."""
    ext = os.path.splitext(filepath)[1].lower()
    for content_type, file_ext in IMAGE_ALLOWED_TYPES.items():
        if file_ext == ext:
            return content_type
    return "application/octet-stream"


def get_user_namespace(api_key: Optional[str]) -> str:
    """Generate a user namespace from the API key.

    SECURITY: Creates a per-user directory namespace to isolate uploaded images.
    Uses first 12 chars of SHA-256 hash to create a short, safe directory name.

    Args:
        api_key: The authenticated API key (or None if auth disabled)

    Returns:
        A short hash string to use as directory name, or 'shared' if no key
    """
    if not api_key:
        return "shared"
    import hashlib

    key_hash = hashlib.sha256(api_key.encode("utf-8")).hexdigest()
    return key_hash[:12]


def get_user_image_dir(api_key: Optional[str]) -> str:
    """Get the image upload directory for a specific user.

    SECURITY: Isolates user uploads into separate directories.

    Args:
        api_key: The authenticated API key

    Returns:
        Path to user-specific image directory
    """
    namespace = get_user_namespace(api_key)
    return os.path.join(IMAGE_UPLOAD_DIR, namespace)


def resolve_image_id(image_id: str, api_key: Optional[str] = None) -> str:
    """Resolve an image_id to its actual file path.

    SECURITY: Images are isolated per-user based on API key hash.

    Args:
        image_id: UUID of the uploaded image
        api_key: API key for user namespace isolation

    Returns:
        Absolute file path to the image

    Raises:
        ValueError: If image not found or invalid format
    """
    # SECURITY: Validate UUID format to prevent path traversal
    if not validate_uuid_format(image_id):
        raise ValueError(f"Invalid image ID format: {image_id}")

    # SECURITY: Use user-specific directory for isolation
    user_image_dir = get_user_image_dir(api_key)

    if not os.path.exists(user_image_dir):
        raise ValueError(f"Image not found: {image_id}")

    # SECURITY: Use exact prefix match with dot separator to prevent partial UUID matching
    matches = [f for f in os.listdir(user_image_dir) if f.startswith(f"{image_id}.")]
    if not matches:
        raise ValueError(f"Image not found: {image_id}")

    # SECURITY: Verify exactly one match to avoid ambiguity
    if len(matches) != 1:
        raise ValueError(f"Ambiguous image ID: {image_id}")

    filepath = os.path.join(user_image_dir, matches[0])

    # SECURITY: Verify path is within upload directory and not a symlink
    resolved_path = Path(filepath).resolve()
    if not validate_path_within_directory(resolved_path, Path(IMAGE_UPLOAD_DIR)):
        raise ValueError(f"Invalid image path: {image_id}")
    if not is_safe_symlink(resolved_path):
        raise ValueError(f"Invalid image: {image_id}")

    return str(resolved_path)


def resolve_image_references(data: dict) -> dict:
    """Replace image_id references with actual file paths in configuration data.

    Processes nodes in various configuration formats:
    - Attack Trees: nodes dict with image_id attributes
    - Attack Graphs: hosts, vulnerabilities, privileges, services lists
    - Threat Models: processes, datastores, externals dicts
    - Custom Diagrams: nodes list with image_id attributes

    Args:
        data: Configuration dictionary (modified in place)

    Returns:
        Modified configuration dictionary
    """

    def process_node_attrs(attrs: dict) -> None:
        """Process node attributes, resolving image_id if present."""
        if not isinstance(attrs, dict):
            return

        if "image_id" in attrs:
            image_id = attrs.pop("image_id")
            try:
                attrs["image"] = resolve_image_id(str(image_id))
                logger.debug(f"Resolved image_id {image_id}")
            except ValueError as e:
                logger.warning(f"Could not resolve image_id: {e}")

    # Attack Trees - nodes dict
    if "nodes" in data and isinstance(data["nodes"], dict):
        for _node_id, attrs in data["nodes"].items():
            process_node_attrs(attrs)

    # Attack Graphs - hosts, vulnerabilities, privileges, services (can be dict or list)
    for section in ["hosts", "vulnerabilities", "privileges", "services"]:
        if section in data:
            section_data = data[section]
            if isinstance(section_data, dict):
                for _item_id, attrs in section_data.items():
                    process_node_attrs(attrs)
            elif isinstance(section_data, list):
                for item in section_data:
                    process_node_attrs(item)

    # Threat Models - processes, datastores, externals dicts
    for section in ["processes", "datastores", "externals"]:
        if section in data and isinstance(data[section], dict):
            for _item_id, attrs in data[section].items():
                process_node_attrs(attrs)

    # Custom Diagrams - nodes list
    if "nodes" in data and isinstance(data["nodes"], list):
        for node in data["nodes"]:
            process_node_attrs(node)

    return data


# =============================================================================
# File Helper Functions
# =============================================================================


def get_content_type(format: OutputFormat) -> str:
    """Get MIME content type for output format."""
    content_types = {
        OutputFormat.PNG: "image/png",
        OutputFormat.PDF: "application/pdf",
        OutputFormat.SVG: "image/svg+xml",
    }
    return content_types.get(format, "application/octet-stream")


def get_file_extension(filename: str) -> str:
    """Get lowercase file extension from filename.

    Args:
        filename: The filename to extract extension from

    Returns:
        Lowercase file extension including the dot (e.g., '.json')
    """
    if not filename:
        return ".tml"
    _, ext = os.path.splitext(filename.lower())
    return ext if ext else ".tml"


def validate_config_file_extension(filename: str) -> None:
    """Validate that file has a supported config extension.

    Args:
        filename: The filename to validate

    Raises:
        HTTPException: If extension is not supported
    """
    ext = get_file_extension(filename)
    if ext not in SUPPORTED_CONFIG_EXTENSIONS:
        logger.warning(f"File rejected: unsupported extension={ext}, name={sanitize_filename_for_log(filename)}")
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file format. Supported formats: {', '.join(sorted(SUPPORTED_CONFIG_EXTENSIONS))}",
        )


def write_config_file(filepath: str, data: dict, ext: str) -> None:
    """Write config data to file in the format matching the extension.

    Args:
        filepath: Path to write the file
        data: Config data dictionary
        ext: File extension (determines format: .json, .yaml, .yml, .toml, .tml)
    """
    import toml
    import yaml

    ext_lower = ext.lower()
    with open(filepath, "w") as f:
        if ext_lower == ".json":
            json.dump(data, f, indent=2)
        elif ext_lower in (".yaml", ".yml"):
            # SECURITY: Use SafeDumper to prevent serialization of arbitrary Python objects
            yaml.dump(data, f, default_flow_style=False, Dumper=yaml.SafeDumper)
        else:  # .toml, .tml or default
            toml.dump(data, f)


def save_upload_file(upload_file: UploadFile, suffix: str | None = None, max_size: int = MAX_CONFIG_FILE_SIZE) -> str:
    """Save uploaded file to temp directory and return path.

    Args:
        upload_file: The uploaded file
        suffix: File extension to use. If None, preserves original extension.
        max_size: Maximum allowed file size in bytes

    Raises:
        HTTPException: If file exceeds size limit
    """
    # Preserve original extension if no suffix specified
    if suffix is None:
        suffix = get_file_extension(upload_file.filename)

    temp_path = os.path.join(TEMP_DIR, f"upload_{os.urandom(8).hex()}{suffix}")

    # Read content with size limit check
    content = upload_file.file.read()
    file_size = len(content)

    if file_size > max_size:
        logger.warning(
            f"File rejected: size={file_size} bytes, max={max_size} bytes, name={sanitize_filename_for_log(upload_file.filename)}"
        )
        raise HTTPException(
            status_code=413, detail=f"File too large. Maximum size is {max_size // 1024 // 1024}MB for this file type."
        )

    with open(temp_path, "wb") as f:
        f.write(content)
    upload_file.file.seek(0)  # Reset file pointer

    logger.debug(f"Saved upload: {sanitize_filename_for_log(upload_file.filename)} ({file_size} bytes) -> {temp_path}")
    return temp_path


def cleanup_files(*paths: str) -> None:
    """Remove temporary files."""
    for path in paths:
        if path and os.path.exists(path):
            try:
                os.unlink(path)
                logger.debug(f"Cleaned up temp file: {path}")
            except OSError as e:
                logger.warning(f"Failed to cleanup temp file {path}: {e}")


# =============================================================================
# Progress Tracking
# =============================================================================

# In-memory progress storage (for demo; use Redis in production)
_progress_store: dict = {}


def _cleanup_old_progress_entries() -> int:
    """Remove expired progress entries to prevent memory exhaustion.

    SECURITY: This prevents DoS attacks through progress store flooding.

    Returns:
        Number of entries removed.
    """
    now = time.time()
    expired_keys = [
        job_id for job_id, data in _progress_store.items() if now - data.get("timestamp", 0) > PROGRESS_ENTRY_TTL
    ]
    for job_id in expired_keys:
        _progress_store.pop(job_id, None)
    return len(expired_keys)


PROGRESS_MAX_STEP_LENGTH = 500
PROGRESS_MAX_STATUS_LENGTH = 100
PROGRESS_MAX_JOB_ID_LENGTH = 128


def update_progress(job_id: str, step: str, progress: int, total: int = 100, status: str = "running"):
    """Update progress for a job.

    SECURITY: Enforces maximum entries limit and per-field size limits
    to prevent memory exhaustion.
    """
    # Truncate user-controlled string fields to prevent memory abuse
    job_id = str(job_id)[:PROGRESS_MAX_JOB_ID_LENGTH]
    step = str(step)[:PROGRESS_MAX_STEP_LENGTH]
    status = str(status)[:PROGRESS_MAX_STATUS_LENGTH]

    # SECURITY: Cleanup expired entries periodically
    if len(_progress_store) >= PROGRESS_MAX_ENTRIES:
        removed = _cleanup_old_progress_entries()
        logger.debug(f"Progress store cleanup: removed {removed} expired entries")

        # If still at limit after cleanup, reject new entries
        if len(_progress_store) >= PROGRESS_MAX_ENTRIES:
            logger.warning(f"Progress store at capacity ({PROGRESS_MAX_ENTRIES}), rejecting new job: {job_id}")
            return

    _progress_store[job_id] = {
        "job_id": job_id,
        "step": step,
        "progress": progress,
        "total": total,
        "percentage": round((progress / total) * 100, 1) if total > 0 else 0,
        "status": status,
        "timestamp": time.time(),
    }


def get_progress(job_id: str) -> Optional[dict]:
    """Get progress for a job."""
    return _progress_store.get(job_id)


def clear_progress(job_id: str):
    """Clear progress for a completed job."""
    _progress_store.pop(job_id, None)


# =============================================================================
# Template Helpers
# =============================================================================


def get_template_format(filename: str) -> str:
    """Get the format type for a template file."""
    ext = os.path.splitext(filename.lower())[1]
    if ext in (".tml", ".toml"):
        return "toml"
    elif ext == ".json":
        return "json"
    elif ext in (".yaml", ".yml"):
        return "yaml"
    return "toml"


# =============================================================================
# Background Cleanup Tasks
# =============================================================================


async def cleanup_old_images():
    """Background task to clean up old uploaded images.

    SECURITY: This task has safeguards against infinite loops and resource exhaustion:
    - Handles CancelledError for graceful shutdown
    - Implements exponential backoff on repeated errors
    - Also cleans up old progress entries periodically
    """
    from datetime import datetime, timedelta

    consecutive_errors = 0
    max_consecutive_errors = 10
    base_sleep = 300  # 5 minutes

    try:
        while True:
            # Calculate sleep time with exponential backoff on errors
            sleep_time = base_sleep * (2 ** min(consecutive_errors, 5))
            await asyncio.sleep(sleep_time)

            try:
                # SECURITY: Periodically cleanup progress store entries
                removed = _cleanup_old_progress_entries()
                if removed > 0:
                    logger.info(f"Cleaned up {removed} expired progress entries")

                if not os.path.exists(IMAGE_UPLOAD_DIR):
                    consecutive_errors = 0
                    continue

                cutoff = datetime.now() - timedelta(seconds=IMAGE_CLEANUP_AGE)
                cleaned = 0

                # Walk all files including user-namespaced subdirectories
                for dirpath, dirnames, filenames in os.walk(IMAGE_UPLOAD_DIR):
                    for filename in filenames:
                        filepath = os.path.join(dirpath, filename)
                        try:
                            mtime = datetime.fromtimestamp(os.path.getmtime(filepath))
                            if mtime < cutoff:
                                os.unlink(filepath)
                                cleaned += 1
                                logger.debug(f"Cleaned up old image: {filepath}")
                        except Exception as e:
                            logger.error(f"Failed to cleanup {filepath}: {e}")
                    # Remove empty subdirectories after file cleanup
                    for dirname in dirnames:
                        subdir = os.path.join(dirpath, dirname)
                        try:
                            if not os.listdir(subdir):
                                os.rmdir(subdir)
                                logger.debug(f"Removed empty directory: {subdir}")
                        except Exception:
                            pass

                if cleaned > 0:
                    logger.info(f"Cleaned up {cleaned} old images")

                # Reset error counter on success
                consecutive_errors = 0

            except Exception as e:
                consecutive_errors += 1
                logger.error(f"Image cleanup task error ({consecutive_errors}/{max_consecutive_errors}): {e}")

                # SECURITY: Stop task after too many consecutive errors
                if consecutive_errors >= max_consecutive_errors:
                    logger.error("Image cleanup task stopping due to repeated errors")
                    break

    except asyncio.CancelledError:
        logger.info("Image cleanup task cancelled (shutdown)")
        raise  # Re-raise for proper cancellation handling
