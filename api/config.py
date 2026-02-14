#
# VULNEX -Universal Security Visualization Library-
#
# File: config.py
# Description: Configuration constants, environment variables, and logging setup
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
#

import os
import re
import tempfile
import logging
from typing import List
from urllib.parse import urlparse

from slowapi import Limiter
from slowapi.util import get_remote_address

# =============================================================================
# Logging Configuration
# =============================================================================

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
LOG_FORMAT = os.getenv("LOG_FORMAT", "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s")

# SECURITY: Traceback logging must be explicitly enabled, separate from LOG_LEVEL.
# This prevents accidental exposure of internal details if LOG_LEVEL is set to DEBUG.
# Set ENABLE_TRACEBACK_LOGGING=true only in development/debugging environments.
ENABLE_TRACEBACK_LOGGING = os.getenv("ENABLE_TRACEBACK_LOGGING", "false").lower() == "true"

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format=LOG_FORMAT,
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("usecvislib.api")

# =============================================================================
# Security Constants
# =============================================================================

MAX_CONFIG_FILE_SIZE = 1024 * 1024  # 1 MB max for config files (TOML, JSON, YAML)
MAX_TOML_FILE_SIZE = MAX_CONFIG_FILE_SIZE  # Alias for backwards compatibility
MAX_BINARY_FILE_SIZE = 50 * 1024 * 1024  # 50 MB max for binary files

# SECURITY: Request timeout for long-running visualization operations
# Prevents resource exhaustion from slow/complex visualizations
REQUEST_TIMEOUT_VISUALIZE = int(os.getenv("REQUEST_TIMEOUT_VISUALIZE", "120"))  # 2 minutes
REQUEST_TIMEOUT_ANALYZE = int(os.getenv("REQUEST_TIMEOUT_ANALYZE", "60"))  # 1 minute
REQUEST_TIMEOUT_BATCH = int(os.getenv("REQUEST_TIMEOUT_BATCH", "300"))  # 5 minutes for batch

# Supported configuration file extensions
SUPPORTED_CONFIG_EXTENSIONS = {".toml", ".tml", ".json", ".yaml", ".yml"}

# =============================================================================
# CORS Configuration
# =============================================================================

# SECURITY: Validate CORS origins to prevent misconfiguration attacks
def _validate_cors_origin(origin: str) -> str:
    """Validate a CORS origin string.

    Args:
        origin: Origin URL to validate

    Returns:
        Validated origin string (stripped)

    Raises:
        ValueError: If origin is invalid or insecure
    """
    origin = origin.strip()
    if not origin:
        raise ValueError("Empty origin not allowed")
    # Reject wildcard origins (insecure with credentials)
    if origin == "*":
        raise ValueError("Wildcard '*' origin not allowed with credentials")
    # Must be a valid URL scheme
    if not origin.startswith(("http://", "https://")):
        raise ValueError(f"Origin must start with http:// or https://: {origin}")
    # Reject origins with wildcards in domain
    if "*" in origin:
        raise ValueError(f"Wildcards not allowed in origin: {origin}")
    # Basic URL structure validation
    try:
        parsed = urlparse(origin)
        if not parsed.netloc:
            raise ValueError(f"Invalid origin URL: {origin}")
    except Exception as e:
        raise ValueError(f"Cannot parse origin URL: {origin}: {e}")
    return origin


def _parse_allowed_origins() -> List[str]:
    """Parse and validate ALLOWED_ORIGINS environment variable.

    SECURITY: Validates each origin to prevent CORS misconfiguration attacks.
    Rejects wildcards and malformed URLs that could bypass security controls.
    """
    raw_origins = os.getenv(
        "ALLOWED_ORIGINS",
        "http://localhost:3001,http://localhost:3000,http://127.0.0.1:3001,http://127.0.0.1:3000"
    )
    origins = []
    for origin in raw_origins.split(","):
        try:
            validated = _validate_cors_origin(origin)
            origins.append(validated)
        except ValueError as e:
            # Log warning but skip invalid origins rather than failing startup
            logging.getLogger("usecvislib.api").warning(f"Skipping invalid CORS origin: {e}")
    if not origins:
        # Fallback to safe defaults if all origins invalid
        origins = ["http://localhost:3000", "http://localhost:3001"]
        logging.getLogger("usecvislib.api").warning("No valid CORS origins configured, using localhost defaults")
    return origins


ALLOWED_ORIGINS = _parse_allowed_origins()

# =============================================================================
# Image Upload Configuration
# =============================================================================

IMAGE_UPLOAD_DIR = os.getenv("IMAGE_UPLOAD_DIR", os.path.join(tempfile.gettempdir(), "usecvislib", "images"))
IMAGE_MAX_SIZE = 5 * 1024 * 1024  # 5 MB
IMAGE_CLEANUP_AGE = int(os.getenv("IMAGE_CLEANUP_AGE", "3600"))  # 1 hour default
IMAGE_ALLOWED_TYPES = {
    'image/png': '.png',
    'image/jpeg': '.jpg',
    'image/gif': '.gif',
    'image/svg+xml': '.svg',
    'image/bmp': '.bmp',
}
# Magic bytes for image format detection
IMAGE_MAGIC_BYTES = {
    b'\x89PNG\r\n\x1a\n': 'image/png',
    b'\xff\xd8\xff': 'image/jpeg',
    b'GIF87a': 'image/gif',
    b'GIF89a': 'image/gif',
    b'BM': 'image/bmp',
}

# =============================================================================
# Bundled Icons Configuration
# =============================================================================

# Resolve bundled icons directory (relative to project root or absolute path)
def _get_bundled_icons_dir():
    """Get the path to bundled icons directory."""
    # Check environment variable first
    env_path = os.getenv("BUNDLED_ICONS_DIR")
    if env_path and os.path.isdir(env_path):
        return env_path

    # Try relative to this file (api/config.py -> assets/icons)
    api_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(api_dir)
    assets_path = os.path.join(project_root, "assets", "icons")
    if os.path.isdir(assets_path):
        return assets_path

    # Try /app/assets/icons (Docker)
    docker_path = "/app/assets/icons"
    if os.path.isdir(docker_path):
        return docker_path

    # Return default even if doesn't exist
    return assets_path


BUNDLED_ICONS_DIR = _get_bundled_icons_dir()
BUNDLED_ICON_CATEGORIES = ["azure", "aws", "bootstrap"]
BUNDLED_ICON_EXTENSIONS = {".png", ".svg", ".jpg", ".jpeg", ".gif"}

# Rate limiting configuration
RATE_LIMIT_DEFAULT = os.getenv("RATE_LIMIT_DEFAULT", "30/minute")
RATE_LIMIT_VISUALIZE = os.getenv("RATE_LIMIT_VISUALIZE", "10/minute")
RATE_LIMIT_ANALYZE = os.getenv("RATE_LIMIT_ANALYZE", "20/minute")

# =============================================================================
# Rate Limiter Setup
# =============================================================================

limiter = Limiter(key_func=get_remote_address)

# Temporary directory for generated files
TEMP_DIR = tempfile.mkdtemp(prefix="usecvislib_api_")

# =============================================================================
# Progress Tracking Configuration
# =============================================================================

# SECURITY: Limits to prevent memory exhaustion
PROGRESS_MAX_ENTRIES = int(os.getenv("PROGRESS_MAX_ENTRIES", "1000"))
PROGRESS_ENTRY_TTL = int(os.getenv("PROGRESS_ENTRY_TTL", "3600"))  # 1 hour default

# =============================================================================
# Templates Configuration
# =============================================================================

# Templates directory path
TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), '..', 'templates')

# Supported template file extensions
TEMPLATE_EXTENSIONS = ('.tml', '.toml', '.json', '.yaml', '.yml')

# Custom Diagrams templates directory
CUSTOM_DIAGRAMS_TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), '..', 'templates', 'custom-diagrams')

# Extension mapping for output filenames
FORMAT_EXTENSIONS = {
    "toml": ".toml",
    "json": ".json",
    "yaml": ".yaml",
    "mermaid": ".mmd",
}

# Report extensions
REPORT_EXTENSIONS = {
    "markdown": ".md",
    "html": ".html",
}

# UUID validation pattern (RFC 4122)
UUID_PATTERN = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
    re.IGNORECASE
)
