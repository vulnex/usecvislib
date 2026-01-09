#
# VULNEX -Universal Security Visualization Library-
#
# File: main.py
# Author: Simon Roses Femerling
# Created: 2025-01-01
# Last Modified: 2025-12-31
# Version: 0.3.2
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""USecVisLib FastAPI Application.

REST API for generating security visualizations from uploaded files.
"""

import os
import sys
import tempfile
import shutil
import logging
import time
import uuid
import re
import html
from pathlib import Path
from typing import Optional, List
from contextlib import asynccontextmanager

from fastapi import FastAPI, File, UploadFile, Form, HTTPException, Query, BackgroundTasks, Request, Depends
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from starlette.middleware.base import BaseHTTPMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import asyncio
import json

# =============================================================================
# Logging Configuration
# =============================================================================

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
LOG_FORMAT = os.getenv("LOG_FORMAT", "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s")

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

# Supported configuration file extensions
SUPPORTED_CONFIG_EXTENSIONS = {".toml", ".tml", ".json", ".yaml", ".yml"}

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
    from urllib.parse import urlparse
    try:
        parsed = urlparse(origin)
        if not parsed.netloc:
            raise ValueError(f"Invalid origin URL: {origin}")
    except Exception as e:
        raise ValueError(f"Cannot parse origin URL: {origin}: {e}")
    return origin

def _parse_allowed_origins() -> list:
    """Parse and validate ALLOWED_ORIGINS environment variable."""
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

    # Try relative to this file (api/main.py -> assets/icons)
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


# =============================================================================
# Security Headers Middleware
# =============================================================================

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses."""

    # CSP for Swagger UI / ReDoc documentation pages
    DOCS_CSP = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "img-src 'self' data: https://fastapi.tiangolo.com; "
        "font-src 'self' https://cdn.jsdelivr.net; "
        "connect-src 'self' https://cdn.jsdelivr.net; "
        "frame-ancestors 'none'"
    )

    # Strict CSP for API endpoints
    API_CSP = "default-src 'none'; frame-ancestors 'none'"

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        # SECURITY: HTTP Strict Transport Security - enforce HTTPS
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        # Prevent MIME type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"
        # Prevent clickjacking
        response.headers["X-Frame-Options"] = "DENY"
        # XSS protection (legacy but still useful)
        response.headers["X-XSS-Protection"] = "1; mode=block"
        # Referrer policy
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        # Content Security Policy - relaxed for docs, strict for API
        path = request.url.path
        if path in ("/docs", "/redoc", "/openapi.json") or path.startswith("/docs/") or path.startswith("/redoc/"):
            response.headers["Content-Security-Policy"] = self.DOCS_CSP
        else:
            response.headers["Content-Security-Policy"] = self.API_CSP
        # Permissions policy
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        return response


# =============================================================================
# Request Logging Middleware
# =============================================================================

class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Log all incoming requests with timing."""

    async def dispatch(self, request: Request, call_next):
        request_id = str(uuid.uuid4())[:8]
        start_time = time.time()

        # Log incoming request
        logger.info(
            f"[{request_id}] --> {request.method} {request.url.path} "
            f"client={request.client.host if request.client else 'unknown'}"
        )

        try:
            response = await call_next(request)
            duration = (time.time() - start_time) * 1000

            # Log response
            logger.info(
                f"[{request_id}] <-- {response.status_code} "
                f"duration={duration:.2f}ms"
            )
            return response

        except Exception as e:
            duration = (time.time() - start_time) * 1000
            logger.error(
                f"[{request_id}] <-- ERROR {type(e).__name__}: {str(e)} "
                f"duration={duration:.2f}ms"
            )
            raise

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from usecvislib import AttackTrees, AttackGraphs, ThreatModeling, BinVis, CustomDiagrams, __version__ as lib_version
from usecvislib.attacktrees import AttackTreeError
from usecvislib.attackgraphs import AttackGraphError
from usecvislib.customdiagrams import CustomDiagramError
from usecvislib.shapes import ShapeRegistry
from usecvislib.threatmodeling import PyTMWrapper
from usecvislib.utils import FileError, ConfigError, detect_format, convert_format as utils_convert_format, ReadConfigFile
from usecvislib.batch import BatchProcessor, BatchResult
from usecvislib.exporters import Exporter
from usecvislib.diff import VisualizationDiff, ChangeType as LibChangeType

from .schemas import (
    OutputFormat,
    AttackTreeStyle,
    AttackGraphStyle,
    ThreatModelStyle,
    ThreatModelEngine,
    BinVisStyle,
    BinVisType,
    BinVisConfig,
    ConfigFormat,
    ReportFormat,
    TreeStats,
    GraphStats,
    CriticalNode,
    AttackPath,
    AttackPathsResponse,
    ModelStats,
    FileStats,
    StrideReport,
    StrideCategory,
    HealthResponse,
    ErrorResponse,
    ConvertResponse,
    ReportResponse,
    ThreatLibraryResponse,
    ThreatLibraryItem,
    # New schemas for Phase 5 features
    VisualizationMode,
    BatchItemResult,
    BatchResponse,
    ExportFormat,
    ExportResponse,
    ChangeType,
    ChangeItem,
    DiffSummary,
    DiffResponse,
    ValidationSeverity,
    ValidationIssue,
    ValidationResponse,
    TemplateMetadata,
    # Settings schemas
    CVSSDisplaySettings,
    DisplaySettingsRequest,
    DisplaySettingsResponse,
    # CustomDiagrams schemas
    CustomDiagramStyle,
    CustomDiagramLayout,
    CustomDiagramDirection,
    ShapeInfo,
    ShapeListResponse,
    TemplateInfo,
    TemplateListResponse,
    CustomDiagramRequest,
    CustomDiagramValidateRequest,
    CustomDiagramValidateResponse,
    CustomDiagramStatsResponse,
    CustomDiagramFromTemplateRequest,
    CustomDiagramImportRequest,
    # Image upload schemas
    ImageUploadResponse,
    ImageInfoResponse,
    ImageDeleteResponse,
    ImageListResponse,
    # Bundled icons schemas
    BundledIconInfo,
    BundledIconsListResponse,
    BundledIconsCategoriesResponse,
)

# Import settings module
from usecvislib.settings import get_settings, get_cvss_display_settings, set_cvss_display_settings

# Import authentication module
from .auth import validate_auth_config, verify_api_key, AUTH_ENABLED, API_KEY_HEADER_NAME


# Temporary directory for generated files
TEMP_DIR = tempfile.mkdtemp(prefix="usecvislib_api_")


# =============================================================================
# Security Helper Functions
# =============================================================================

# UUID validation pattern (RFC 4122)
UUID_PATTERN = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
    re.IGNORECASE
)


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
    if '..' in component:
        return False
    # Check for absolute path indicators
    if component.startswith('/') or component.startswith('\\'):
        return False
    # Check for URL-encoded traversal
    if '%2e' in component.lower() or '%2f' in component.lower():
        return False
    # Check for null bytes
    if '\x00' in component:
        return False
    return True


def validate_path_within_directory(path: Path, base_dir: Path) -> bool:
    """Validate that a resolved path stays within the base directory.

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
    sanitized = "".join(
        c if c.isprintable() and c not in '\r\n\t' else '_'
        for c in filename
    )
    # Escape any remaining special log format characters
    sanitized = sanitized.replace('%', '%%')
    return sanitized


# =============================================================================
# Image Helper Functions
# =============================================================================

def is_valid_image(content: bytes, claimed_type: str) -> bool:
    """Validate image content by checking magic bytes.

    Args:
        content: Raw file content
        claimed_type: MIME type claimed by the upload

    Returns:
        True if content matches a valid image format
    """
    # For SVG, check for XML/SVG content
    if claimed_type == 'image/svg+xml':
        try:
            text = content[:1000].decode('utf-8', errors='ignore').lower()
            return '<svg' in text or '<?xml' in text
        except Exception:
            return False

    # Check magic bytes for other formats
    for magic, detected_type in IMAGE_MAGIC_BYTES.items():
        if content.startswith(magic):
            return True

    return False


def get_image_content_type(filepath: str) -> str:
    """Get content type from file extension."""
    ext = os.path.splitext(filepath)[1].lower()
    for content_type, file_ext in IMAGE_ALLOWED_TYPES.items():
        if file_ext == ext:
            return content_type
    return 'application/octet-stream'


def resolve_image_id(image_id: str) -> str:
    """Resolve an image_id to its actual file path.

    Args:
        image_id: UUID of the uploaded image

    Returns:
        Absolute file path to the image

    Raises:
        ValueError: If image not found or invalid format
    """
    # SECURITY: Validate UUID format to prevent path traversal
    if not validate_uuid_format(image_id):
        raise ValueError(f"Invalid image ID format: {image_id}")

    if not os.path.exists(IMAGE_UPLOAD_DIR):
        raise ValueError(f"Image not found: {image_id}")

    # SECURITY: Use exact prefix match with dot separator to prevent partial UUID matching
    matches = [f for f in os.listdir(IMAGE_UPLOAD_DIR) if f.startswith(f"{image_id}.")]
    if not matches:
        raise ValueError(f"Image not found: {image_id}")

    # SECURITY: Verify exactly one match to avoid ambiguity
    if len(matches) != 1:
        raise ValueError(f"Ambiguous image ID: {image_id}")

    filepath = os.path.join(IMAGE_UPLOAD_DIR, matches[0])

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
        for node_id, attrs in data["nodes"].items():
            process_node_attrs(attrs)

    # Attack Graphs - hosts, vulnerabilities, privileges, services (can be dict or list)
    for section in ["hosts", "vulnerabilities", "privileges", "services"]:
        if section in data:
            section_data = data[section]
            if isinstance(section_data, dict):
                for item_id, attrs in section_data.items():
                    process_node_attrs(attrs)
            elif isinstance(section_data, list):
                for item in section_data:
                    process_node_attrs(item)

    # Threat Models - processes, datastores, externals dicts
    for section in ["processes", "datastores", "externals"]:
        if section in data and isinstance(data[section], dict):
            for item_id, attrs in data[section].items():
                process_node_attrs(attrs)

    # Custom Diagrams - nodes list
    if "nodes" in data and isinstance(data["nodes"], list):
        for node in data["nodes"]:
            process_node_attrs(node)

    return data


async def cleanup_old_images():
    """Background task to clean up old uploaded images."""
    from datetime import datetime, timedelta

    while True:
        await asyncio.sleep(300)  # Check every 5 minutes

        try:
            if not os.path.exists(IMAGE_UPLOAD_DIR):
                continue

            cutoff = datetime.now() - timedelta(seconds=IMAGE_CLEANUP_AGE)

            for filename in os.listdir(IMAGE_UPLOAD_DIR):
                filepath = os.path.join(IMAGE_UPLOAD_DIR, filename)
                if os.path.isfile(filepath):
                    mtime = datetime.fromtimestamp(os.path.getmtime(filepath))
                    if mtime < cutoff:
                        try:
                            os.unlink(filepath)
                            logger.info(f"Cleaned up old image: {filename}")
                        except Exception as e:
                            logger.error(f"Failed to cleanup {filepath}: {e}")
        except Exception as e:
            logger.error(f"Image cleanup task error: {e}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler for startup/shutdown."""
    # Validate authentication configuration (will exit if invalid)
    validate_auth_config()

    # Startup
    logger.info(f"Starting USecVisLib API v{lib_version}")
    logger.info(f"Temp directory: {TEMP_DIR}")
    logger.info(f"Image upload directory: {IMAGE_UPLOAD_DIR}")
    logger.info(f"Rate limits: default={RATE_LIMIT_DEFAULT}, visualize={RATE_LIMIT_VISUALIZE}, analyze={RATE_LIMIT_ANALYZE}")
    os.makedirs(TEMP_DIR, exist_ok=True)
    os.makedirs(IMAGE_UPLOAD_DIR, exist_ok=True)

    # Start image cleanup background task
    cleanup_task = asyncio.create_task(cleanup_old_images())
    logger.info(f"Image cleanup task started (cleanup age: {IMAGE_CLEANUP_AGE}s)")

    yield

    # Shutdown
    logger.info("Shutting down USecVisLib API")
    cleanup_task.cancel()
    try:
        await cleanup_task
    except asyncio.CancelledError:
        pass

    # Cleanup temp directory
    if os.path.exists(TEMP_DIR):
        shutil.rmtree(TEMP_DIR, ignore_errors=True)
        logger.info("Cleaned up temp directory")


import os
API_ROOT_PATH = os.environ.get("API_ROOT_PATH", "")

app = FastAPI(
    title="USecVisLib API",
    description="""
REST API for Universal Security Visualization Library.

Generate security visualizations from configuration files:
- **Attack Trees**: Hierarchical attack scenario diagrams
- **Attack Graphs**: Network attack path visualization and analysis
- **Threat Models**: Data Flow Diagrams with STRIDE analysis
- **Binary Analysis**: Entropy, distribution, and pattern visualizations

## Supported Formats

Configuration files can be in any of these formats:
- **TOML** (.toml, .tml)
- **JSON** (.json)
- **YAML** (.yaml, .yml)

## Usage

1. Upload a configuration file (TOML, JSON, or YAML) or binary file
2. Select visualization options (format, style)
3. Receive the generated visualization image

## Authentication

When authentication is enabled (`USECVISLIB_AUTH_ENABLED=true`), all API endpoints
require an API key. Include it in the request header:

```
X-API-Key: your-api-key-here
```

Configure your API key via environment variable:
```bash
export USECVISLIB_API_KEY=your-secure-key-here
```

To disable authentication for local development:
```bash
export USECVISLIB_AUTH_ENABLED=false
```
    """,
    version="0.3.2",
    lifespan=lifespan,
    root_path=API_ROOT_PATH,
    dependencies=[Depends(verify_api_key)],
    responses={
        400: {"model": ErrorResponse, "description": "Bad Request"},
        401: {"description": "Unauthorized - Missing or invalid API key"},
        422: {"model": ErrorResponse, "description": "Validation Error"},
        500: {"model": ErrorResponse, "description": "Internal Server Error"},
    }
)

# CORS middleware for cross-origin requests (restricted to allowed origins)
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "OPTIONS"],
    allow_headers=["Content-Type", "Accept", "X-API-Key"],
)

# Security headers middleware
app.add_middleware(SecurityHeadersMiddleware)

# Request logging middleware
app.add_middleware(RequestLoggingMiddleware)

# Rate limiting
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


# =============================================================================
# OpenAPI Security Scheme
# =============================================================================

def custom_openapi():
    """Generate custom OpenAPI schema with authentication security scheme."""
    if app.openapi_schema:
        return app.openapi_schema

    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )

    # Add security scheme when authentication is enabled
    if AUTH_ENABLED:
        if "components" not in openapi_schema:
            openapi_schema["components"] = {}
        openapi_schema["components"]["securitySchemes"] = {
            "ApiKeyAuth": {
                "type": "apiKey",
                "in": "header",
                "name": API_KEY_HEADER_NAME,
                "description": "API key for authentication. Set via USECVISLIB_API_KEY environment variable."
            }
        }
        # Apply security globally
        openapi_schema["security"] = [{"ApiKeyAuth": []}]

    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi


# =============================================================================
# Helper Functions
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
            detail=f"Unsupported file format. Supported formats: {', '.join(sorted(SUPPORTED_CONFIG_EXTENSIONS))}"
        )


def write_config_file(filepath: str, data: dict, ext: str) -> None:
    """Write config data to file in the format matching the extension.

    Args:
        filepath: Path to write the file
        data: Config data dictionary
        ext: File extension (determines format: .json, .yaml, .yml, .toml, .tml)
    """
    import toml
    import json
    import yaml

    ext_lower = ext.lower()
    with open(filepath, 'w') as f:
        if ext_lower == '.json':
            json.dump(data, f, indent=2)
        elif ext_lower in ('.yaml', '.yml'):
            # SECURITY: Use SafeDumper to prevent serialization of arbitrary Python objects
            yaml.dump(data, f, default_flow_style=False, Dumper=yaml.SafeDumper)
        else:  # .toml, .tml or default
            toml.dump(data, f)


def save_upload_file(upload_file: UploadFile, suffix: str = None, max_size: int = MAX_CONFIG_FILE_SIZE) -> str:
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
        logger.warning(f"File rejected: size={file_size} bytes, max={max_size} bytes, name={sanitize_filename_for_log(upload_file.filename)}")
        raise HTTPException(
            status_code=413,
            detail=f"File too large. Maximum size is {max_size // 1024 // 1024}MB for this file type."
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
# Health Check
# =============================================================================

@app.get(
    "/health",
    response_model=HealthResponse,
    tags=["System"],
    summary="Health check endpoint"
)
@limiter.limit(RATE_LIMIT_DEFAULT)
async def health_check(request: Request):
    """Check API health and module availability."""
    return HealthResponse(
        status="healthy",
        version=lib_version,
        modules={
            "attack_trees": True,
            "attack_graphs": True,
            "threat_modeling": True,
            "binary_visualization": True,
            "custom_diagrams": True,
        }
    )


# =============================================================================
# Attack Trees Endpoints
# =============================================================================

@app.post(
    "/visualize/attack-tree",
    tags=["Attack Trees"],
    summary="Generate attack tree visualization",
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
async def visualize_attack_tree(
    request: Request,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(..., description="TOML file containing attack tree definition"),
    format: OutputFormat = Query(default=OutputFormat.PNG, description="Output format"),
    style: AttackTreeStyle = Query(default=AttackTreeStyle.DEFAULT, description="Style preset"),
):
    """
    Generate an attack tree visualization from an uploaded TOML file.

    The TOML file should contain:
    - `[tree]` section with name and root node
    - `[nodes]` section with node definitions
    - `[edges]` section with connections

    Example TOML structure:
    ```toml
    [tree]
    name = "Attack Tree"
    root = "Goal"

    [nodes]
    "Goal" = {style="filled", fillcolor="red"}
    "Attack" = {}

    [edges]
    "Goal" = [{to = "Attack"}]
    ```
    """
    input_path = None
    output_path = None
    modified_input_path = None

    try:
        # Save uploaded file
        validate_config_file_extension(file.filename)
        input_path = save_upload_file(file)
        output_base = os.path.join(TEMP_DIR, f"output_{os.urandom(8).hex()}")

        # Read and parse config to resolve image_id references
        try:
            config_data = ReadConfigFile(input_path)
            config_data = resolve_image_references(config_data)

            # Write modified config to a temp file in the same format
            base, ext = os.path.splitext(input_path)
            modified_input_path = f"{base}_resolved{ext}"
            write_config_file(modified_input_path, config_data, ext)
            input_for_viz = modified_input_path
        except Exception as e:
            logger.debug(f"Image resolution skipped: {e}")
            input_for_viz = input_path

        # Generate visualization
        at = AttackTrees(input_for_viz, output_base, format=format.value, styleid=style.value)
        at.BuildAttackTree()

        output_path = f"{output_base}.{format.value}"

        if not os.path.exists(output_path):
            cleanup_files(input_path, modified_input_path)
            raise HTTPException(status_code=500, detail="Failed to generate visualization")

        # Schedule cleanup after response is sent
        background_tasks.add_task(cleanup_files, input_path, modified_input_path, output_path)

        return FileResponse(
            path=output_path,
            media_type=get_content_type(format),
            filename=f"attack_tree.{format.value}",
        )

    except AttackTreeError as e:
        cleanup_files(input_path, output_path)
        raise HTTPException(status_code=400, detail=str(e))
    except (FileError, ConfigError) as e:
        cleanup_files(input_path, output_path)
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        cleanup_files(input_path, output_path)
        logger.error(f"Internal error: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="An internal error occurred")


@app.post(
    "/analyze/attack-tree",
    response_model=TreeStats,
    tags=["Attack Trees"],
    summary="Analyze attack tree structure"
)
@limiter.limit(RATE_LIMIT_ANALYZE)
async def analyze_attack_tree(
    request: Request,
    file: UploadFile = File(..., description="TOML file containing attack tree definition"),
):
    """
    Analyze an attack tree and return statistics without generating visualization.

    Returns node counts, edge counts, and structural information.
    """
    input_path = None

    try:
        validate_config_file_extension(file.filename)
        input_path = save_upload_file(file)
        at = AttackTrees(input_path, "unused")
        stats = at.get_tree_stats()

        # Get metadata
        metadata_obj = at.get_metadata()
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

        return TreeStats(**stats)

    except AttackTreeError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Internal error: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="An internal error occurred")
    finally:
        cleanup_files(input_path)


@app.post(
    "/validate/attack-tree",
    tags=["Attack Trees"],
    summary="Validate attack tree structure"
)
@limiter.limit(RATE_LIMIT_ANALYZE)
async def validate_attack_tree(
    request: Request,
    file: UploadFile = File(..., description="TOML file containing attack tree definition"),
):
    """
    Validate an attack tree structure and return any errors found.

    Checks for:
    - Missing required sections
    - Orphan nodes
    - Undefined edge targets
    - Invalid root node
    """
    input_path = None

    try:
        validate_config_file_extension(file.filename)
        input_path = save_upload_file(file)
        at = AttackTrees(input_path, "unused")
        errors = at.validate()

        return {
            "valid": len(errors) == 0,
            "errors": errors
        }

    except AttackTreeError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Internal error: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="An internal error occurred")
    finally:
        cleanup_files(input_path)


# =============================================================================
# Attack Graphs Endpoints
# =============================================================================

@app.post(
    "/visualize/attack-graph",
    tags=["Attack Graphs"],
    summary="Generate attack graph visualization",
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
async def visualize_attack_graph(
    request: Request,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(..., description="Configuration file containing attack graph definition"),
    format: OutputFormat = Query(default=OutputFormat.PNG, description="Output format"),
    style: AttackGraphStyle = Query(default=AttackGraphStyle.DEFAULT, description="Style preset"),
):
    """
    Generate an attack graph visualization from an uploaded configuration file.

    The configuration file should contain:
    - `[graph]` section with name and description
    - `[hosts]` section with network hosts
    - `[vulnerabilities]` section with CVEs/weaknesses
    - `[privileges]` section with access levels
    - `[services]` section with running services (optional)
    - `[exploits]` section with preconditions/postconditions
    - `[network]` section with connectivity

    Example TOML structure:
    ```toml
    [graph]
    name = "Network Attack Graph"

    [hosts.webserver]
    label = "Web Server"
    ip = "192.168.1.10"

    [vulnerabilities.cve_2024_1234]
    label = "CVE-2024-1234"
    host = "webserver"
    cvss = 9.8

    [privileges.web_root]
    label = "Root Access"
    host = "webserver"
    level = "root"

    [exploits.exploit_web]
    label = "Exploit CVE"
    preconditions = ["cve_2024_1234"]
    postconditions = ["web_root"]

    [network]
    internet = ["webserver"]
    ```
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

        ag = AttackGraphs(input_for_viz, output_base, format=format.value, styleid=style.value)
        ag.BuildAttackGraph()

        output_path = f"{output_base}.{format.value}"

        if not os.path.exists(output_path):
            cleanup_files(input_path, modified_input_path)
            raise HTTPException(status_code=500, detail="Failed to generate visualization")

        background_tasks.add_task(cleanup_files, input_path, modified_input_path, output_path)

        return FileResponse(
            path=output_path,
            media_type=get_content_type(format),
            filename=f"attack_graph.{format.value}",
        )

    except AttackGraphError as e:
        cleanup_files(input_path, modified_input_path, output_path)
        raise HTTPException(status_code=400, detail=str(e))
    except (FileError, ConfigError) as e:
        cleanup_files(input_path, modified_input_path, output_path)
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        cleanup_files(input_path, modified_input_path, output_path)
        logger.error(f"Internal error: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="An internal error occurred")


@app.post(
    "/analyze/attack-graph",
    response_model=GraphStats,
    tags=["Attack Graphs"],
    summary="Analyze attack graph structure"
)
@limiter.limit(RATE_LIMIT_ANALYZE)
async def analyze_attack_graph(
    request: Request,
    file: UploadFile = File(..., description="Configuration file containing attack graph definition"),
):
    """
    Analyze an attack graph and return statistics without generating visualization.

    Returns host counts, vulnerability counts, CVSS averages, and structural information.
    """
    input_path = None

    try:
        validate_config_file_extension(file.filename)
        input_path = save_upload_file(file)
        ag = AttackGraphs(input_path, "unused")
        stats = ag.get_graph_stats()

        # Get metadata
        metadata_obj = ag.get_metadata()
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

        return GraphStats(**stats)

    except AttackGraphError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Internal error: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="An internal error occurred")
    finally:
        cleanup_files(input_path)


@app.post(
    "/analyze/attack-paths",
    response_model=AttackPathsResponse,
    tags=["Attack Graphs"],
    summary="Find attack paths in graph"
)
@limiter.limit(RATE_LIMIT_ANALYZE)
async def analyze_attack_paths(
    request: Request,
    file: UploadFile = File(..., description="Configuration file containing attack graph definition"),
    source: str = Query(..., description="Source node ID (e.g., 'internet' or a host)"),
    target: str = Query(..., description="Target node ID (e.g., a privilege node)"),
    max_paths: int = Query(10, ge=1, le=100, description="Maximum number of paths to return"),
):
    """
    Find all attack paths from source to target in the attack graph.

    Uses depth-first search to find paths. Also returns the shortest path.

    Example: Find paths from 'internet' to 'db_root' privilege.
    """
    input_path = None

    try:
        validate_config_file_extension(file.filename)
        input_path = save_upload_file(file)
        ag = AttackGraphs(input_path, "unused")
        ag.load()

        # Find all paths
        paths = ag.find_attack_paths(source, target, max_paths=max_paths)

        # Find shortest path
        shortest = ag.shortest_path(source, target)

        # Format response
        attack_paths = [
            AttackPath(path=p, length=len(p))
            for p in paths
        ]

        return AttackPathsResponse(
            source=source,
            target=target,
            paths=attack_paths,
            total_paths=len(paths),
            shortest_path_length=len(shortest) if shortest else None
        )

    except AttackGraphError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Internal error: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="An internal error occurred")
    finally:
        cleanup_files(input_path)


@app.post(
    "/analyze/critical-nodes",
    tags=["Attack Graphs"],
    summary="Identify critical nodes in attack graph"
)
@limiter.limit(RATE_LIMIT_ANALYZE)
async def analyze_critical_nodes(
    request: Request,
    file: UploadFile = File(..., description="Configuration file containing attack graph definition"),
    limit: int = Query(10, ge=1, le=50, description="Number of top critical nodes to return"),
):
    """
    Identify the most critical nodes in the attack graph based on connectivity.

    Critical nodes are those with high in-degree and out-degree, making them
    important chokepoints or targets in the network.

    Returns nodes sorted by criticality score (total degree).
    """
    input_path = None

    try:
        validate_config_file_extension(file.filename)
        input_path = save_upload_file(file)
        ag = AttackGraphs(input_path, "unused")
        ag.load()

        critical = ag.analyze_critical_nodes()[:limit]

        return {
            "critical_nodes": [CriticalNode(**node) for node in critical],
            "total_nodes": len(ag._adjacency)
        }

    except AttackGraphError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Internal error: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="An internal error occurred")
    finally:
        cleanup_files(input_path)


# =============================================================================
# NetworkX-powered Attack Graph Analysis Endpoints
# =============================================================================

@app.post(
    "/analyze/centrality",
    tags=["Attack Graphs"],
    summary="Calculate centrality metrics for attack graph nodes"
)
@limiter.limit(RATE_LIMIT_ANALYZE)
async def analyze_centrality(
    request: Request,
    file: UploadFile = File(..., description="Configuration file containing attack graph definition"),
    algorithm: str = Query("all", description="Centrality algorithm: betweenness, closeness, pagerank, or all"),
    limit: int = Query(10, ge=1, le=100, description="Number of top nodes to return"),
):
    """
    Calculate centrality metrics for nodes in the attack graph.

    Centrality measures help identify important nodes:
    - **Betweenness**: Nodes that lie on many shortest paths (chokepoints)
    - **Closeness**: Nodes that can quickly reach other nodes
    - **PageRank**: Nodes with many important incoming connections

    Use 'all' to calculate all three metrics at once.
    """
    input_path = None

    try:
        validate_config_file_extension(file.filename)
        input_path = save_upload_file(file)
        ag = AttackGraphs(input_path, "unused")
        ag.load()

        nodes = []
        if algorithm in ("betweenness", "all"):
            betweenness = ag.betweenness_centrality(top_n=limit)
            for node in betweenness:
                nodes.append({
                    "id": node["id"],
                    "label": node["label"],
                    "type": node["type"],
                    "betweenness_centrality": node.get("betweenness_centrality")
                })

        if algorithm in ("closeness", "all"):
            closeness = ag.closeness_centrality(top_n=limit)
            if algorithm == "closeness":
                for node in closeness:
                    nodes.append({
                        "id": node["id"],
                        "label": node["label"],
                        "type": node["type"],
                        "closeness_centrality": node.get("closeness_centrality")
                    })
            else:
                # Merge with existing nodes
                closeness_map = {n["id"]: n.get("closeness_centrality") for n in closeness}
                for node in nodes:
                    node["closeness_centrality"] = closeness_map.get(node["id"])

        if algorithm in ("pagerank", "all"):
            pr = ag.pagerank(top_n=limit)
            if algorithm == "pagerank":
                for node in pr:
                    nodes.append({
                        "id": node["id"],
                        "label": node["label"],
                        "type": node["type"],
                        "pagerank": node.get("pagerank")
                    })
            else:
                # Merge with existing nodes
                pr_map = {n["id"]: n.get("pagerank") for n in pr}
                for node in nodes:
                    node["pagerank"] = pr_map.get(node["id"])

        return {
            "nodes": nodes[:limit],
            "algorithm": algorithm,
            "total_nodes": len(ag._adjacency)
        }

    except AttackGraphError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Internal error: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="An internal error occurred")
    finally:
        cleanup_files(input_path)


@app.post(
    "/analyze/graph-metrics",
    tags=["Attack Graphs"],
    summary="Get comprehensive graph metrics"
)
@limiter.limit(RATE_LIMIT_ANALYZE)
async def analyze_graph_metrics(
    request: Request,
    file: UploadFile = File(..., description="Configuration file containing attack graph definition"),
):
    """
    Get comprehensive metrics about the attack graph structure.

    Returns:
    - Node and edge counts
    - Graph density
    - Diameter (longest shortest path)
    - Strongly connected components
    - Cycle detection
    - Node type distribution
    """
    input_path = None

    try:
        validate_config_file_extension(file.filename)
        input_path = save_upload_file(file)
        ag = AttackGraphs(input_path, "unused")
        ag.load()

        metrics = ag.get_graph_metrics()
        return metrics

    except AttackGraphError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Internal error: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="An internal error occurred")
    finally:
        cleanup_files(input_path)


@app.post(
    "/analyze/chokepoints",
    tags=["Attack Graphs"],
    summary="Identify network chokepoints"
)
@limiter.limit(RATE_LIMIT_ANALYZE)
async def analyze_chokepoints(
    request: Request,
    file: UploadFile = File(..., description="Configuration file containing attack graph definition"),
    limit: int = Query(10, ge=1, le=50, description="Number of top chokepoints to return"),
):
    """
    Identify network chokepoints based on betweenness centrality.

    Chokepoints are nodes that many attack paths must traverse.
    Securing these nodes can disrupt multiple attack vectors.

    Returns nodes sorted by betweenness score with criticality assessment.
    """
    input_path = None

    try:
        validate_config_file_extension(file.filename)
        input_path = save_upload_file(file)
        ag = AttackGraphs(input_path, "unused")
        ag.load()

        chokepoints = ag.find_chokepoints(top_n=limit)

        return {
            "chokepoints": chokepoints,
            "total_analyzed": len(ag._adjacency)
        }

    except AttackGraphError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Internal error: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="An internal error occurred")
    finally:
        cleanup_files(input_path)


@app.post(
    "/analyze/attack-surface",
    tags=["Attack Graphs"],
    summary="Identify attack surface entry points"
)
@limiter.limit(RATE_LIMIT_ANALYZE)
async def analyze_attack_surface(
    request: Request,
    file: UploadFile = File(..., description="Configuration file containing attack graph definition"),
):
    """
    Identify attack surface entry points in the network.

    Entry points are nodes with no incoming edges (sources) or
    nodes explicitly marked as external/internet-facing.

    Returns entry points sorted by reachable nodes (attack surface size).
    """
    input_path = None

    try:
        validate_config_file_extension(file.filename)
        input_path = save_upload_file(file)
        ag = AttackGraphs(input_path, "unused")
        ag.load()

        entry_points = ag.find_attack_surfaces()

        return {
            "entry_points": entry_points,
            "total_attack_surface": len(entry_points)
        }

    except AttackGraphError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Internal error: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="An internal error occurred")
    finally:
        cleanup_files(input_path)


@app.post(
    "/analyze/vulnerability-impact",
    tags=["Attack Graphs"],
    summary="Calculate vulnerability impact score"
)
@limiter.limit(RATE_LIMIT_ANALYZE)
async def analyze_vulnerability_impact(
    request: Request,
    file: UploadFile = File(..., description="Configuration file containing attack graph definition"),
    vulnerability_id: str = Query(..., description="Vulnerability node ID to analyze"),
):
    """
    Calculate impact score for a specific vulnerability.

    Combines CVSS score with graph position to estimate real impact.
    Vulnerabilities that lead to more critical assets score higher.

    Returns impact metrics including reachable nodes and privilege targets.
    """
    input_path = None

    try:
        validate_config_file_extension(file.filename)
        input_path = save_upload_file(file)
        ag = AttackGraphs(input_path, "unused")
        ag.load()

        impact = ag.vulnerability_impact_score(vulnerability_id)

        if "error" in impact:
            raise HTTPException(status_code=404, detail=impact["error"])

        return impact

    except AttackGraphError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Internal error: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="An internal error occurred")
    finally:
        cleanup_files(input_path)


@app.post(
    "/validate/attack-graph",
    tags=["Attack Graphs"],
    summary="Validate attack graph structure"
)
@limiter.limit(RATE_LIMIT_ANALYZE)
async def validate_attack_graph(
    request: Request,
    file: UploadFile = File(..., description="Configuration file containing attack graph definition"),
):
    """
    Validate an attack graph structure and return any errors found.

    Checks for:
    - Missing required sections
    - Undefined host references
    - Invalid exploit preconditions/postconditions
    - Network connectivity issues
    """
    input_path = None

    try:
        validate_config_file_extension(file.filename)
        input_path = save_upload_file(file)
        ag = AttackGraphs(input_path, "unused")
        errors = ag.validate()

        return {
            "valid": len(errors) == 0,
            "errors": errors
        }

    except AttackGraphError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Internal error: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="An internal error occurred")
    finally:
        cleanup_files(input_path)


# =============================================================================
# Threat Modeling Endpoints
# =============================================================================

@app.post(
    "/visualize/threat-model",
    tags=["Threat Modeling"],
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
        tm.BuildThreatModel()

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
        logger.error(f"Internal error: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="An internal error occurred")


@app.post(
    "/analyze/threat-model",
    response_model=ModelStats,
    tags=["Threat Modeling"],
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
        logger.error(f"Internal error: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="An internal error occurred")
    finally:
        cleanup_files(input_path)


@app.post(
    "/analyze/stride",
    response_model=StrideReport,
    tags=["Threat Modeling"],
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
        logger.error(f"Internal error: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="An internal error occurred")
    finally:
        cleanup_files(input_path)


# =============================================================================
# Binary Visualization Endpoints
# =============================================================================

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


@app.post(
    "/visualize/binary",
    tags=["Binary Visualization"],
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

        # Generate visualization
        vis_type = visualization_type.value
        if vis_type == "all":
            bv.BuildBinVis("all")
            output_path = f"{output_base}_entropy.{format.value}"
        else:
            bv.BuildBinVis(vis_type)
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

    except FileNotFoundError as e:
        cleanup_files(input_path, output_path)
        raise HTTPException(status_code=400, detail=str(e))
    except ValueError as e:
        cleanup_files(input_path, output_path)
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        cleanup_files(input_path, output_path)
        logger.error(f"Internal error: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="An internal error occurred")


@app.post(
    "/analyze/binary",
    response_model=FileStats,
    tags=["Binary Visualization"],
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

    except FileNotFoundError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Internal error: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="An internal error occurred")
    finally:
        cleanup_files(input_path)


# =============================================================================
# Styles Endpoints
# =============================================================================

@app.get(
    "/styles",
    tags=["Configuration"],
    summary="Get available styles"
)
async def get_available_styles():
    """Get all available style presets for each visualization type."""
    return {
        "attack_tree": [s.value for s in AttackTreeStyle],
        "attack_graph": [s.value for s in AttackGraphStyle],
        "threat_model": [s.value for s in ThreatModelStyle],
        "custom_diagram": [s.value for s in CustomDiagramStyle],
        "binary_visualization": [s.value for s in BinVisStyle],
    }


@app.get(
    "/formats",
    tags=["Configuration"],
    summary="Get supported output formats"
)
async def get_supported_formats():
    """Get all supported output formats."""
    return {
        "formats": [f.value for f in OutputFormat],
        "default": OutputFormat.PNG.value,
    }


@app.get(
    "/engines",
    tags=["Configuration"],
    summary="Get available threat modeling engines"
)
async def get_available_engines():
    """Get all available threat modeling engines and their status."""
    pytm_available = ThreatModeling.is_pytm_available()
    return {
        "engines": [e.value for e in ThreatModelEngine],
        "default": ThreatModelEngine.USECVISLIB.value,
        "pytm_available": pytm_available,
        "descriptions": {
            "usecvislib": "Native USecVisLib engine with custom styling support",
            "pytm": "OWASP PyTM framework for comprehensive threat analysis" + (" (not installed)" if not pytm_available else "")
        }
    }


# =============================================================================
# Progress Tracking (SSE)
# =============================================================================

# In-memory progress storage (for demo; use Redis in production)
_progress_store: dict = {}


def update_progress(job_id: str, step: str, progress: int, total: int = 100, status: str = "running"):
    """Update progress for a job."""
    _progress_store[job_id] = {
        "job_id": job_id,
        "step": step,
        "progress": progress,
        "total": total,
        "percentage": round((progress / total) * 100, 1) if total > 0 else 0,
        "status": status,
        "timestamp": time.time()
    }


def get_progress(job_id: str) -> Optional[dict]:
    """Get progress for a job."""
    return _progress_store.get(job_id)


def clear_progress(job_id: str):
    """Clear progress for a completed job."""
    _progress_store.pop(job_id, None)


async def progress_event_generator(job_id: str, timeout: int = 300):
    """Generate SSE events for job progress."""
    start_time = time.time()
    last_data = None

    while True:
        # Check timeout
        if time.time() - start_time > timeout:
            yield f"data: {json.dumps({'status': 'timeout', 'message': 'Progress tracking timed out'})}\n\n"
            break

        progress = get_progress(job_id)

        if progress:
            # Only send if data changed
            if progress != last_data:
                yield f"data: {json.dumps(progress)}\n\n"
                last_data = progress.copy()

            # If completed or failed, stop streaming
            if progress.get("status") in ("completed", "failed"):
                break

        await asyncio.sleep(0.5)


@app.get(
    "/progress/{job_id}",
    tags=["System"],
    summary="Stream job progress via SSE"
)
async def stream_progress(job_id: str):
    """
    Stream progress updates for a long-running job using Server-Sent Events (SSE).

    Connect to this endpoint with an EventSource to receive real-time progress updates.

    Example JavaScript:
    ```javascript
    const eventSource = new EventSource('/progress/job-123');
    eventSource.onmessage = (event) => {
        const progress = JSON.parse(event.data);
        console.log(`${progress.step}: ${progress.percentage}%`);
    };
    ```
    """
    logger.info(f"SSE connection opened for job: {job_id}")
    return StreamingResponse(
        progress_event_generator(job_id),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )


@app.post(
    "/jobs/start-demo",
    tags=["System"],
    summary="Start a demo job for testing progress"
)
async def start_demo_job(background_tasks: BackgroundTasks):
    """
    Start a demo job that simulates a long-running operation.
    Returns a job_id that can be used to track progress via /progress/{job_id}.
    """
    job_id = f"demo-{uuid.uuid4().hex[:8]}"

    async def demo_job():
        steps = ["Initializing", "Processing", "Analyzing", "Generating", "Finalizing"]
        for i, step in enumerate(steps):
            update_progress(job_id, step, (i + 1) * 20, 100, "running")
            await asyncio.sleep(1)
        update_progress(job_id, "Complete", 100, 100, "completed")
        await asyncio.sleep(5)  # Keep result for 5 seconds
        clear_progress(job_id)

    # Run in background
    asyncio.create_task(demo_job())

    logger.info(f"Started demo job: {job_id}")
    return {"job_id": job_id, "progress_url": f"/progress/{job_id}"}


# =============================================================================
# Templates Endpoints
# =============================================================================

# Templates directory path
TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), '..', 'templates')

# Supported template file extensions
TEMPLATE_EXTENSIONS = ('.tml', '.toml', '.json', '.yaml', '.yml')


def get_template_format(filename: str) -> str:
    """Get the format type for a template file."""
    ext = os.path.splitext(filename.lower())[1]
    if ext in ('.tml', '.toml'):
        return 'toml'
    elif ext == '.json':
        return 'json'
    elif ext in ('.yaml', '.yml'):
        return 'yaml'
    return 'toml'


@app.get(
    "/templates",
    tags=["Templates"],
    summary="List available templates"
)
async def list_templates():
    """List all available templates for attack trees and threat models."""
    templates = {
        "attack_trees": [],
        "threat_models": []
    }

    # Scan attack tree templates
    at_dir = os.path.join(TEMPLATES_DIR, "attack-trees")
    if os.path.exists(at_dir):
        for f in os.listdir(at_dir):
            if f.endswith(TEMPLATE_EXTENSIONS):
                # Extract base name without extension
                base_name = os.path.splitext(f)[0]
                name = base_name.replace('_', ' ').title()
                templates["attack_trees"].append({
                    "id": base_name,
                    "name": name,
                    "filename": f,
                    "format": get_template_format(f)
                })

    # Scan threat model templates
    tm_dir = os.path.join(TEMPLATES_DIR, "threat-models")
    if os.path.exists(tm_dir):
        for f in os.listdir(tm_dir):
            if f.endswith(TEMPLATE_EXTENSIONS):
                base_name = os.path.splitext(f)[0]
                name = base_name.replace('_', ' ').title()
                templates["threat_models"].append({
                    "id": base_name,
                    "name": name,
                    "filename": f,
                    "format": get_template_format(f)
                })

    logger.info(f"Listed templates: {len(templates['attack_trees'])} attack trees, {len(templates['threat_models'])} threat models")
    return templates


def find_template_file(template_dir: str, template_id: str) -> Optional[str]:
    """Find a template file by ID, checking all supported extensions.

    SECURITY: Validates template_id to prevent path traversal attacks.
    """
    # SECURITY: Validate template_id has no path traversal attempts
    if not validate_path_component(template_id):
        logger.warning(f"Invalid template_id rejected: {template_id}")
        return None

    base_dir = Path(template_dir).resolve()

    for ext in TEMPLATE_EXTENSIONS:
        path = Path(template_dir) / f"{template_id}{ext}"

        # SECURITY: Verify the resolved path stays within template directory
        try:
            resolved = path.resolve()
            if not resolved.is_relative_to(base_dir):
                logger.warning(f"Path traversal attempt blocked: {template_id}")
                return None
            # SECURITY: Reject symlinks
            if resolved.is_symlink():
                logger.warning(f"Symlink rejected: {template_id}")
                return None
            if resolved.exists() and resolved.is_file():
                return str(resolved)
        except (ValueError, RuntimeError):
            continue

    return None


@app.get(
    "/templates/attack-tree/{template_id}",
    tags=["Templates"],
    summary="Get attack tree template"
)
async def get_attack_tree_template(template_id: str):
    """Get a specific attack tree template by ID."""
    template_dir = os.path.join(TEMPLATES_DIR, "attack-trees")
    template_path = find_template_file(template_dir, template_id)

    if not template_path:
        logger.warning(f"Template not found: {template_id}")
        raise HTTPException(status_code=404, detail=f"Template '{template_id}' not found")

    with open(template_path, 'r') as f:
        content = f.read()

    filename = os.path.basename(template_path)
    logger.info(f"Served attack tree template: {template_id} ({filename})")
    return {
        "id": template_id,
        "type": "attack_tree",
        "format": get_template_format(filename),
        "content": content
    }


@app.get(
    "/templates/threat-model/{template_id}",
    tags=["Templates"],
    summary="Get threat model template"
)
async def get_threat_model_template(template_id: str):
    """Get a specific threat model template by ID."""
    template_dir = os.path.join(TEMPLATES_DIR, "threat-models")
    template_path = find_template_file(template_dir, template_id)

    if not template_path:
        logger.warning(f"Template not found: {template_id}")
        raise HTTPException(status_code=404, detail=f"Template '{template_id}' not found")

    with open(template_path, 'r') as f:
        content = f.read()

    filename = os.path.basename(template_path)
    logger.info(f"Served threat model template: {template_id} ({filename})")
    return {
        "id": template_id,
        "type": "threat_model",
        "format": get_template_format(filename),
        "content": content
    }


# =============================================================================
# Format Conversion Endpoint
# =============================================================================

# Extension mapping for output filenames
FORMAT_EXTENSIONS = {
    "toml": ".toml",
    "json": ".json",
    "yaml": ".yaml",
    "mermaid": ".mmd",
}


@app.post(
    "/convert",
    response_model=ConvertResponse,
    tags=["Conversion"],
    summary="Convert configuration file between formats"
)
@limiter.limit(RATE_LIMIT_ANALYZE)
async def convert_config_format(
    request: Request,
    file: UploadFile = File(..., description="Configuration file to convert (TOML, JSON, or YAML)"),
    target_format: ConfigFormat = Query(..., description="Target format to convert to"),
):
    """
    Convert a configuration file from one format to another.

    Supports conversion between:
    - **TOML** (.toml, .tml)
    - **JSON** (.json)
    - **YAML** (.yaml, .yml)
    - **Mermaid** (.mmd) - output only, for diagram generation

    The source format is auto-detected from the file extension.

    Example use cases:
    - Convert YAML threat models to TOML for CLI usage
    - Convert TOML attack trees to JSON for programmatic processing
    - Standardize team configurations to a single format
    - **Export to Mermaid** for browser-based diagrams or documentation

    Note: Mermaid is an output-only format. The diagram type is auto-detected
    from the configuration structure (attack tree, threat model, etc.).
    """
    input_path = None

    try:
        # Validate file extension
        validate_config_file_extension(file.filename)
        input_path = save_upload_file(file)

        # Detect source format from extension
        source_format = detect_format(file.filename)

        # Read file content
        with open(input_path, 'r', encoding='utf-8') as f:
            content = f.read()

        # Convert format
        converted_content = utils_convert_format(content, source_format, target_format.value)

        # Generate suggested filename
        base_name = os.path.splitext(file.filename)[0]
        suggested_filename = f"{base_name}{FORMAT_EXTENSIONS[target_format.value]}"

        logger.info(f"Converted {sanitize_filename_for_log(file.filename)} from {source_format} to {target_format.value}")

        return ConvertResponse(
            content=converted_content,
            source_format=source_format,
            target_format=target_format.value,
            filename=suggested_filename
        )

    except (FileError, ConfigError) as e:
        logger.warning(f"Conversion failed: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Conversion error: {e}")
        logger.error(f"Conversion failed: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Conversion failed")
    finally:
        cleanup_files(input_path)


# =============================================================================
# Report Generation Endpoints
# =============================================================================

REPORT_EXTENSIONS = {
    "markdown": ".md",
    "html": ".html",
}


@app.post(
    "/report/threat-model",
    response_model=ReportResponse,
    tags=["Reports"],
    summary="Generate threat model report"
)
@limiter.limit(RATE_LIMIT_ANALYZE)
async def generate_threat_model_report(
    request: Request,
    file: UploadFile = File(..., description="Threat model configuration file (TOML, JSON, or YAML)"),
    format: ReportFormat = Query(ReportFormat.MARKDOWN, description="Report output format"),
):
    """
    Generate a comprehensive threat model report.

    Includes:
    - Executive summary with element counts
    - System components documentation
    - STRIDE threat analysis with mitigations
    - Security property audit

    Supports Markdown and HTML output formats.
    """
    input_path = None

    try:
        validate_config_file_extension(file.filename)
        input_path = save_upload_file(file)

        # Read and parse the configuration
        inputdata = ReadConfigFile(input_path)

        # Create PyTM wrapper and generate report
        wrapper = PyTMWrapper(inputdata, os.path.join(TEMP_DIR, "pytm_output"), "png")

        if format == ReportFormat.MARKDOWN:
            content = wrapper.generate_markdown_report()
            ext = ".md"
        else:
            content = wrapper.generate_html_report()
            ext = ".html"

        base_name = os.path.splitext(file.filename)[0]
        suggested_filename = f"{base_name}_report{ext}"

        logger.info(f"Generated {format.value} report for {sanitize_filename_for_log(file.filename)}")

        return ReportResponse(
            content=content,
            format=format.value,
            filename=suggested_filename
        )

    except (FileError, ConfigError) as e:
        logger.warning(f"Report generation failed: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Report generation error: {e}")
        logger.error(f"Report generation failed: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Report generation failed")
    finally:
        cleanup_files(input_path)


# =============================================================================
# Threat Library Endpoints
# =============================================================================

@app.get(
    "/threats/library",
    response_model=ThreatLibraryResponse,
    tags=["Threats"],
    summary="Get PyTM threat library"
)
@limiter.limit(RATE_LIMIT_DEFAULT)
async def get_threat_library(
    request: Request,
    element_type: Optional[str] = Query(None, description="Filter by element type (Process, Server, Datastore, Dataflow, etc.)"),
    limit: int = Query(100, ge=1, le=500, description="Maximum number of threats to return"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
):
    """
    Access PyTM's threat library database.

    The threat library contains hundreds of security threats with:
    - Threat descriptions and severity levels
    - Target element types
    - Prerequisites and conditions
    - Recommended mitigations
    - References

    Use `element_type` to filter threats applicable to specific element types.
    """
    try:
        # Create a minimal wrapper to access threat library
        wrapper = PyTMWrapper({}, os.path.join(TEMP_DIR, "pytm_output"), "png")

        if element_type:
            all_threats = wrapper.get_threats_by_element_type(element_type)
        else:
            all_threats = wrapper.get_threat_library()

        # Apply pagination
        total = len(all_threats)
        paginated = all_threats[offset:offset + limit]

        # Convert to schema objects
        threat_items = []
        for t in paginated:
            target = t.get("target", [])
            if isinstance(target, str):
                target = [target]
            refs = t.get("references", [])
            if isinstance(refs, str):
                refs = [refs] if refs else []

            threat_items.append(ThreatLibraryItem(
                id=str(t.get("id", "")),
                description=str(t.get("description", "")),
                severity=str(t.get("severity", "Unknown")),
                target=target,
                condition=str(t.get("condition", "")),
                prerequisites=str(t.get("prerequisites", "")),
                mitigations=str(t.get("mitigations", "")),
                references=refs
            ))

        return ThreatLibraryResponse(
            total=total,
            threats=threat_items,
            pytm_available=wrapper._pytm_available
        )

    except Exception as e:
        logger.error(f"Threat library error: {e}")
        logger.error(f"Failed to access threat library: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to access threat library")


@app.get(
    "/threats/element-types",
    tags=["Threats"],
    summary="Get available element types for threat filtering"
)
@limiter.limit(RATE_LIMIT_DEFAULT)
async def get_threat_element_types(request: Request):
    """
    Get list of element types that can be used to filter the threat library.
    """
    return {
        "element_types": [
            "Process",
            "Server",
            "Lambda",
            "Datastore",
            "Dataflow",
            "Actor",
            "ExternalEntity",
            "Boundary"
        ]
    }


# =============================================================================
# Batch Processing Endpoints
# =============================================================================

@app.post(
    "/batch/visualize",
    response_model=BatchResponse,
    tags=["Batch Processing"],
    summary="Process multiple files in batch"
)
@limiter.limit(RATE_LIMIT_VISUALIZE)
async def batch_visualize(
    request: Request,
    background_tasks: BackgroundTasks,
    files: List[UploadFile] = File(..., description="Multiple configuration files to process"),
    mode: VisualizationMode = Query(..., description="Visualization mode"),
    format: OutputFormat = Query(default=OutputFormat.PNG, description="Output format"),
    style: Optional[str] = Query(default=None, description="Style preset"),
    collect_stats: bool = Query(default=True, description="Collect statistics for each file"),
):
    """
    Process multiple configuration files in batch.

    Upload multiple TOML/JSON/YAML files and process them all at once.
    Returns success/failure status for each file along with aggregate statistics.

    Supported modes:
    - **attack_tree**: Process attack tree configurations
    - **attack_graph**: Process attack graph configurations
    - **threat_model**: Process threat model configurations
    - **custom_diagram**: Process custom diagram configurations
    """
    if len(files) > 20:
        raise HTTPException(status_code=400, detail="Maximum 20 files allowed per batch")

    input_paths = []
    results = []

    try:
        # Save all uploaded files
        for file in files:
            try:
                validate_config_file_extension(file.filename)
                path = save_upload_file(file)
                input_paths.append((file.filename, path))
            except HTTPException as e:
                results.append(BatchItemResult(
                    filename=file.filename,
                    success=False,
                    error=str(e.detail)
                ))

        # Determine module type from mode
        module_map = {
            VisualizationMode.ATTACK_TREE: "attack_tree",
            VisualizationMode.ATTACK_GRAPH: "attack_graph",
            VisualizationMode.THREAT_MODEL: "threat_model",
            VisualizationMode.CUSTOM_DIAGRAM: "custom_diagram",
        }
        module_type = module_map.get(mode)
        if not module_type:
            raise HTTPException(status_code=400, detail=f"Batch processing not supported for mode: {mode.value}")

        # Create output directory for batch
        batch_output_dir = os.path.join(TEMP_DIR, f"batch_{os.urandom(8).hex()}")
        os.makedirs(batch_output_dir, exist_ok=True)

        # Process each file
        for filename, input_path in input_paths:
            try:
                output_base = os.path.join(batch_output_dir, os.path.splitext(filename)[0])

                if mode == VisualizationMode.ATTACK_TREE:
                    viz = AttackTrees(input_path, output_base, format=format.value, styleid=style or "at_default")
                    viz.BuildAttackTree()
                    stats = viz.get_tree_stats() if collect_stats else None
                elif mode == VisualizationMode.ATTACK_GRAPH:
                    viz = AttackGraphs(input_path, output_base, format=format.value, styleid=style or "ag_default")
                    viz.BuildAttackGraph()
                    stats = viz.get_graph_stats() if collect_stats else None
                elif mode == VisualizationMode.THREAT_MODEL:
                    viz = ThreatModeling(input_path, output_base, format=format.value, styleid=style or "tm_default")
                    viz.BuildThreatModel()
                    stats = viz.get_model_stats() if collect_stats else None
                elif mode == VisualizationMode.CUSTOM_DIAGRAM:
                    cd = CustomDiagrams()
                    cd.load(input_path)
                    # Override style if specified
                    if style and cd.settings:
                        cd.settings.style = style
                    result = cd.BuildCustomDiagram(
                        output=output_base,
                        output_format=format.value
                    )
                    stats = cd.get_stats() if collect_stats else None
                else:
                    stats = None

                output_file = f"{os.path.splitext(filename)[0]}.{format.value}"
                output_path = f"{output_base}.{format.value}"

                # Read the generated file and encode as base64 for download
                image_data = None
                if os.path.exists(output_path):
                    with open(output_path, "rb") as f:
                        import base64
                        image_data = base64.b64encode(f.read()).decode("utf-8")

                results.append(BatchItemResult(
                    filename=filename,
                    success=True,
                    output_file=output_file,
                    stats=stats,
                    image_data=image_data
                ))

            except Exception as e:
                results.append(BatchItemResult(
                    filename=filename,
                    success=False,
                    error=str(e)
                ))

        # Calculate aggregate stats
        success_count = sum(1 for r in results if r.success)
        failure_count = len(results) - success_count
        success_rate = success_count / len(results) if results else 0.0

        # Aggregate stats from successful results
        aggregate_stats = None
        if collect_stats:
            stats_list = [r.stats for r in results if r.success and r.stats]
            if stats_list:
                aggregate_stats = {"file_count": len(stats_list)}
                # Sum up common numeric stats
                for key in ["total_nodes", "total_edges", "total_hosts", "total_vulnerabilities"]:
                    values = [s.get(key, 0) for s in stats_list if key in s]
                    if values:
                        aggregate_stats[key] = sum(values)

        # Schedule cleanup
        background_tasks.add_task(cleanup_files, *[p for _, p in input_paths])
        background_tasks.add_task(shutil.rmtree, batch_output_dir, True)

        return BatchResponse(
            total=len(results),
            success_count=success_count,
            failure_count=failure_count,
            success_rate=success_rate,
            results=results,
            aggregate_stats=aggregate_stats
        )

    except Exception as e:
        # Cleanup on error
        for _, path in input_paths:
            cleanup_files(path)
        logger.error(f"Batch processing failed: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Batch processing failed")


# =============================================================================
# Export Endpoints
# =============================================================================

@app.post(
    "/export/data",
    response_model=ExportResponse,
    tags=["Export"],
    summary="Export visualization data to various formats"
)
@limiter.limit(RATE_LIMIT_ANALYZE)
async def export_data(
    request: Request,
    file: UploadFile = File(..., description="Configuration file to export data from"),
    mode: Optional[VisualizationMode] = Query(default=None, description="Visualization mode (auto-detected if not specified)"),
    format: ExportFormat = Query(default=ExportFormat.JSON, description="Export format"),
    section: Optional[str] = Query(default=None, description="Specific section to export (e.g., 'hosts', 'vulnerabilities')"),
    include_stats: bool = Query(default=True, description="Include statistics in export"),
):
    """
    Export visualization data to JSON, CSV, YAML, Markdown, or Mermaid format.

    Mode is auto-detected from the file content if not specified.

    For attack graphs, available sections include:
    - hosts, vulnerabilities, privileges, services, exploits

    For threat models:
    - processes, datastores, externals, dataflows, boundaries

    For attack trees:
    - nodes, edges
    """
    input_path = None

    try:
        validate_config_file_extension(file.filename)
        input_path = save_upload_file(file)

        # Auto-detect mode if not specified
        if mode is None:
            raw_data = ReadConfigFile(input_path)
            # Detect based on data structure
            if "graph" in raw_data or "hosts" in raw_data or "vulnerabilities" in raw_data:
                mode = VisualizationMode.ATTACK_GRAPH
            elif "model" in raw_data or "dataflows" in raw_data or "processes" in raw_data:
                mode = VisualizationMode.THREAT_MODEL
            elif "tree" in raw_data or ("nodes" in raw_data and "edges" in raw_data):
                mode = VisualizationMode.ATTACK_TREE
            else:
                # Default to attack tree for generic node/edge structures
                mode = VisualizationMode.ATTACK_TREE

        # Load the data based on mode
        if mode == VisualizationMode.ATTACK_TREE:
            viz = AttackTrees(input_path, "unused")
            viz.load()
            data = viz.inputdata
            stats = viz.get_tree_stats() if include_stats else None
        elif mode == VisualizationMode.ATTACK_GRAPH:
            viz = AttackGraphs(input_path, "unused")
            viz.load()
            data = viz.inputdata
            stats = viz.get_graph_stats() if include_stats else None
        elif mode == VisualizationMode.THREAT_MODEL:
            viz = ThreatModeling(input_path, "unused")
            viz.load()
            data = viz.inputdata
            stats = viz.get_model_stats() if include_stats else None
        else:
            raise HTTPException(status_code=400, detail=f"Export not supported for mode: {mode.value}")

        # Extract section if specified
        if section:
            if section not in data:
                available = [k for k in data.keys() if isinstance(data[k], (list, dict))]
                raise HTTPException(
                    status_code=400,
                    detail=f"Section '{section}' not found. Available: {available}"
                )
            export_data = data[section]
        else:
            export_data = {"data": data}
            if stats:
                export_data["stats"] = stats

        # Generate filename
        base_name = os.path.splitext(file.filename)[0]
        section_suffix = f"_{section}" if section else ""

        # Export based on format
        rows = None
        if format == ExportFormat.JSON:
            content = Exporter.to_json(export_data, pretty=True)
            filename = f"{base_name}{section_suffix}.json"
        elif format == ExportFormat.CSV:
            # CSV only works for list data
            if isinstance(export_data, list):
                csv_data = export_data
            elif isinstance(export_data, dict) and section:
                csv_data = export_data if isinstance(export_data, list) else [export_data]
            else:
                raise HTTPException(
                    status_code=400,
                    detail="CSV export requires a section with list data (e.g., 'hosts', 'nodes')"
                )
            # Write to temp file and read back
            temp_csv = os.path.join(TEMP_DIR, f"export_{os.urandom(4).hex()}.csv")
            rows = Exporter.to_csv(csv_data, temp_csv)
            with open(temp_csv, 'r') as f:
                content = f.read()
            cleanup_files(temp_csv)
            filename = f"{base_name}{section_suffix}.csv"
        elif format == ExportFormat.YAML:
            content = Exporter.to_yaml(export_data)
            filename = f"{base_name}{section_suffix}.yaml"
        elif format == ExportFormat.MARKDOWN:
            if isinstance(export_data, list):
                content = Exporter.to_markdown_table(export_data)
            else:
                # Convert dict to simple markdown
                lines = [f"# {base_name} Export\n"]
                if stats:
                    lines.append("## Statistics\n")
                    for k, v in stats.items():
                        lines.append(f"- **{k}**: {v}")
                    lines.append("\n## Data\n")
                lines.append(f"```yaml\n{Exporter.to_yaml(export_data)}```")
                content = "\n".join(lines)
            filename = f"{base_name}{section_suffix}.md"
        elif format == ExportFormat.MERMAID:
            # Mermaid export - convert data to Mermaid diagram syntax
            from usecvislib.mermaid import serialize_to_mermaid, detect_visualization_type
            vis_type = detect_visualization_type(data)
            content = serialize_to_mermaid(data, diagram_type=vis_type)
            filename = f"{base_name}{section_suffix}.mmd"
        else:
            raise HTTPException(status_code=400, detail=f"Unknown format: {format.value}")

        logger.info(f"Exported {sanitize_filename_for_log(file.filename)} to {format.value}")

        return ExportResponse(
            content=content,
            format=format.value,
            filename=filename,
            rows=rows
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Export error: {e}")
        logger.error(f"Export failed: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Export failed")
    finally:
        cleanup_files(input_path)


@app.get(
    "/export/sections",
    tags=["Export"],
    summary="Get available export sections for a visualization mode"
)
async def get_export_sections(
    mode: VisualizationMode = Query(..., description="Visualization mode")
):
    """
    Get the available sections that can be exported for each visualization mode.
    """
    sections = {
        VisualizationMode.ATTACK_TREE: ["tree", "nodes", "edges"],
        VisualizationMode.ATTACK_GRAPH: ["graph", "hosts", "vulnerabilities", "privileges", "services", "exploits", "network_edges"],
        VisualizationMode.THREAT_MODEL: ["model", "processes", "datastores", "externals", "dataflows", "boundaries"],
        VisualizationMode.BINARY: [],
    }
    return {
        "mode": mode.value,
        "sections": sections.get(mode, []),
        "note": "Use section=null to export all data"
    }


# =============================================================================
# Diff/Comparison Endpoints
# =============================================================================

@app.post(
    "/diff/compare",
    response_model=DiffResponse,
    tags=["Comparison"],
    summary="Compare two configuration files"
)
@limiter.limit(RATE_LIMIT_ANALYZE)
async def compare_configs(
    request: Request,
    old_file: UploadFile = File(..., description="Old/baseline configuration file"),
    new_file: UploadFile = File(..., description="New/updated configuration file"),
    mode: VisualizationMode = Query(..., description="Visualization mode"),
    include_report: bool = Query(default=False, description="Include markdown report in response"),
    ignore_paths: Optional[str] = Query(default=None, description="Comma-separated paths to ignore (e.g., 'metadata,timestamps')"),
):
    """
    Compare two configuration files and identify changes.

    Returns a detailed diff showing:
    - Added elements (new in the updated file)
    - Removed elements (deleted from the old file)
    - Modified elements (changed between versions)

    Useful for:
    - Tracking threat model evolution
    - Auditing security configuration changes
    - Version control for attack scenarios
    """
    old_path = None
    new_path = None

    try:
        # Validate and save both files
        validate_config_file_extension(old_file.filename)
        validate_config_file_extension(new_file.filename)

        old_path = save_upload_file(old_file)
        new_path = save_upload_file(new_file)

        # Create visualization instances based on mode
        if mode == VisualizationMode.ATTACK_TREE:
            old_viz = AttackTrees(old_path, "old_output", validate_paths=False)
            new_viz = AttackTrees(new_path, "new_output", validate_paths=False)
        elif mode == VisualizationMode.ATTACK_GRAPH:
            old_viz = AttackGraphs(old_path, "old_output", validate_paths=False)
            new_viz = AttackGraphs(new_path, "new_output", validate_paths=False)
        elif mode == VisualizationMode.THREAT_MODEL:
            old_viz = ThreatModeling(old_path, "old_output", validate_paths=False)
            new_viz = ThreatModeling(new_path, "new_output", validate_paths=False)
        else:
            raise HTTPException(status_code=400, detail=f"Comparison not supported for mode: {mode.value}")

        # Parse ignore paths
        ignore_list = None
        if ignore_paths:
            ignore_list = [p.strip() for p in ignore_paths.split(",")]

        # Perform comparison
        diff = VisualizationDiff(old_viz, new_viz)
        result = diff.compare(ignore_paths=ignore_list)

        # Build response
        changes = []
        for change in result.changes:
            changes.append(ChangeItem(
                change_type=ChangeType(change.change_type.value),
                path=change.path,
                old_value=change.old_value,
                new_value=change.new_value,
                description=change.description
            ))

        summary = DiffSummary(
            added=result.summary["added"],
            removed=result.summary["removed"],
            modified=result.summary["modified"],
            total=result.summary["total"]
        )

        report = None
        if include_report:
            report = diff.summary_report(include_details=True)

        logger.info(f"Compared {sanitize_filename_for_log(old_file.filename)} vs {sanitize_filename_for_log(new_file.filename)}: {summary.total} changes")

        return DiffResponse(
            has_changes=result.has_changes,
            summary=summary,
            old_source=old_file.filename,
            new_source=new_file.filename,
            changes=changes,
            report=report
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Comparison error: {e}")
        logger.error(f"Comparison failed: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Comparison failed")
    finally:
        cleanup_files(old_path, new_path)


# =============================================================================
# Display Settings Endpoints
# =============================================================================

@app.get(
    "/settings",
    response_model=DisplaySettingsResponse,
    tags=["Settings"],
    summary="Get current display settings"
)
@limiter.limit(RATE_LIMIT_DEFAULT)
async def get_display_settings(request: Request):
    """
    Get current display settings including CVSS visibility toggles.

    Returns the current state of all display settings that control
    how visualizations are rendered.
    """
    cvss_settings = get_cvss_display_settings()
    return DisplaySettingsResponse(
        cvss_display=CVSSDisplaySettings(**cvss_settings)
    )


@app.put(
    "/settings",
    response_model=DisplaySettingsResponse,
    tags=["Settings"],
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
    if settings.cvss_display:
        set_cvss_display_settings(settings.cvss_display.model_dump())
        logger.info(f"Updated CVSS display settings: {settings.cvss_display.model_dump()}")

    # Return updated settings
    cvss_settings = get_cvss_display_settings()
    return DisplaySettingsResponse(
        cvss_display=CVSSDisplaySettings(**cvss_settings)
    )


@app.post(
    "/settings/cvss/enable-all",
    response_model=DisplaySettingsResponse,
    tags=["Settings"],
    summary="Enable CVSS display for all visualization types"
)
@limiter.limit(RATE_LIMIT_DEFAULT)
async def enable_cvss_all(request: Request):
    """
    Enable CVSS display for all visualization types.

    Sets all CVSS display toggles to True.
    """
    settings = get_settings()
    settings.enable_cvss_all()
    logger.info("Enabled CVSS display for all visualization types")

    cvss_settings = get_cvss_display_settings()
    return DisplaySettingsResponse(
        cvss_display=CVSSDisplaySettings(**cvss_settings)
    )


@app.post(
    "/settings/cvss/disable-all",
    response_model=DisplaySettingsResponse,
    tags=["Settings"],
    summary="Disable CVSS display for all visualization types"
)
@limiter.limit(RATE_LIMIT_DEFAULT)
async def disable_cvss_all(request: Request):
    """
    Disable CVSS display for all visualization types.

    Sets all CVSS display toggles to False.
    """
    settings = get_settings()
    settings.disable_cvss_all()
    logger.info("Disabled CVSS display for all visualization types")

    cvss_settings = get_cvss_display_settings()
    return DisplaySettingsResponse(
        cvss_display=CVSSDisplaySettings(**cvss_settings)
    )


@app.post(
    "/settings/reset",
    response_model=DisplaySettingsResponse,
    tags=["Settings"],
    summary="Reset all display settings to defaults"
)
@limiter.limit(RATE_LIMIT_DEFAULT)
async def reset_display_settings(request: Request):
    """
    Reset all display settings to their default values.

    Restores CVSS display to enabled for all visualization types.
    """
    settings = get_settings()
    settings.reset()
    logger.info("Reset display settings to defaults")

    cvss_settings = get_cvss_display_settings()
    return DisplaySettingsResponse(
        cvss_display=CVSSDisplaySettings(**cvss_settings)
    )


# =============================================================================
# Custom Diagrams Endpoints
# =============================================================================

# Custom Diagrams templates directory
CUSTOM_DIAGRAMS_TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), '..', 'templates', 'custom-diagrams')


@app.get(
    "/custom-diagrams/shapes",
    response_model=ShapeListResponse,
    tags=["Custom Diagrams"],
    summary="List available shapes"
)
@limiter.limit(RATE_LIMIT_DEFAULT)
async def list_shapes(
    request: Request,
    category: Optional[str] = Query(default=None, description="Filter by category (basic, flowchart, network, uml, icons, custom)"),
):
    """
    List all available shapes for custom diagrams.

    Shapes are organized into categories:
    - **basic**: Rectangle, ellipse, diamond, etc.
    - **flowchart**: Start, end, decision, process shapes
    - **network**: Router, server, firewall, cloud icons
    - **uml**: Class, interface, actor shapes
    - **icons**: Various icon shapes
    - **custom**: User-defined shapes

    Each shape has properties like fill color, border style, and label positioning.
    """
    registry = ShapeRegistry.get_instance()
    all_shapes = registry.list_shapes()

    shapes = []
    for shape in all_shapes:
        shape_category = shape.category.value if hasattr(shape.category, 'value') else str(shape.category)
        if category and shape_category != category:
            continue

        # Get attributes from graphviz and default_style dictionaries
        graphviz_attrs = shape.graphviz if shape.graphviz else {}
        style_attrs = shape.default_style if shape.default_style else {}

        shapes.append(ShapeInfo(
            id=shape.id,
            name=shape.name,
            category=shape_category,
            description=shape.description or "",
            shape=graphviz_attrs.get("shape", "box"),
            fillcolor=style_attrs.get("fillcolor"),
            bordercolor=style_attrs.get("color") or style_attrs.get("bordercolor"),
            fontcolor=style_attrs.get("fontcolor"),
            style=graphviz_attrs.get("style"),
        ))

    # Get available categories
    categories = list(set(s.category for s in shapes))

    logger.info(f"Listed {len(shapes)} shapes" + (f" in category '{category}'" if category else ""))

    return ShapeListResponse(
        shapes=shapes,
        total=len(shapes),
        categories=sorted(categories)
    )


@app.get(
    "/custom-diagrams/shapes/{shape_id}",
    response_model=ShapeInfo,
    tags=["Custom Diagrams"],
    summary="Get shape details"
)
@limiter.limit(RATE_LIMIT_DEFAULT)
async def get_shape(
    request: Request,
    shape_id: str,
):
    """Get detailed information about a specific shape."""
    registry = ShapeRegistry.get_instance()
    shape = registry.get_shape(shape_id)

    if not shape:
        raise HTTPException(status_code=404, detail=f"Shape '{shape_id}' not found")

    shape_category = shape.category.value if hasattr(shape.category, 'value') else str(shape.category)

    # Get attributes from graphviz and default_style dictionaries
    graphviz_attrs = shape.graphviz if shape.graphviz else {}
    style_attrs = shape.default_style if shape.default_style else {}

    return ShapeInfo(
        id=shape.id,
        name=shape.name,
        category=shape_category,
        description=shape.description or "",
        shape=graphviz_attrs.get("shape", "box"),
        fillcolor=style_attrs.get("fillcolor"),
        bordercolor=style_attrs.get("color") or style_attrs.get("bordercolor"),
        fontcolor=style_attrs.get("fontcolor"),
        style=graphviz_attrs.get("style"),
    )


@app.get(
    "/custom-diagrams/templates",
    response_model=TemplateListResponse,
    tags=["Custom Diagrams"],
    summary="List custom diagram templates"
)
@limiter.limit(RATE_LIMIT_DEFAULT)
async def list_custom_diagram_templates(
    request: Request,
    category: Optional[str] = Query(default=None, description="Filter by category (general, software, network, security, business)"),
):
    """
    List all available custom diagram templates.

    Templates provide pre-configured schemas and example nodes/edges for common diagram types:

    - **general**: Flowchart, mindmap, hierarchy, timeline
    - **software**: Architecture, class diagram, sequence diagram, component diagram
    - **network**: Network topology, data flow, infrastructure
    - **security**: Risk matrix, incident flow, access control
    - **business**: Process flow, swimlane, org chart

    Each template includes a schema definition, styling, and example elements.
    """
    templates = []

    if not os.path.exists(CUSTOM_DIAGRAMS_TEMPLATES_DIR):
        return TemplateListResponse(templates=[], total=0, categories=[])

    categories_found = set()

    for category_dir in os.listdir(CUSTOM_DIAGRAMS_TEMPLATES_DIR):
        category_path = os.path.join(CUSTOM_DIAGRAMS_TEMPLATES_DIR, category_dir)
        if not os.path.isdir(category_path) or category_dir.startswith('.') or category_dir == '__pycache__':
            continue

        if category and category_dir != category:
            continue

        categories_found.add(category_dir)

        for template_file in os.listdir(category_path):
            if not template_file.endswith('.toml'):
                continue

            template_path = os.path.join(category_path, template_file)
            template_id = os.path.splitext(template_file)[0]

            # Load template to get metadata
            try:
                cd = CustomDiagrams()
                cd.load(template_path)

                templates.append(TemplateInfo(
                    id=f"{category_dir}/{template_id}",
                    name=cd.settings.title if cd.settings else template_id.replace('-', ' ').title(),
                    category=category_dir,
                    description=getattr(cd.settings, 'description', '') if cd.settings else '',
                    filename=template_file,
                    node_count=len(cd.nodes),
                    edge_count=len(cd.edges),
                ))
            except Exception as e:
                logger.warning(f"Failed to load template {template_path}: {e}")
                # Add basic info even if loading fails
                templates.append(TemplateInfo(
                    id=f"{category_dir}/{template_id}",
                    name=template_id.replace('-', ' ').title(),
                    category=category_dir,
                    description='',
                    filename=template_file,
                    node_count=0,
                    edge_count=0,
                ))

    logger.info(f"Listed {len(templates)} custom diagram templates" + (f" in category '{category}'" if category else ""))

    return TemplateListResponse(
        templates=templates,
        total=len(templates),
        categories=sorted(categories_found)
    )


@app.get(
    "/custom-diagrams/templates/{template_id:path}",
    tags=["Custom Diagrams"],
    summary="Get custom diagram template content"
)
@limiter.limit(RATE_LIMIT_DEFAULT)
async def get_custom_diagram_template(
    request: Request,
    template_id: str,
):
    """
    Get a specific custom diagram template by ID.

    Template ID format: `category/template_name` (e.g., `software/architecture`)
    """
    # Parse template ID
    parts = template_id.split('/')
    if len(parts) != 2:
        raise HTTPException(status_code=400, detail="Invalid template ID format. Use 'category/template_name'")

    category, template_name = parts

    # SECURITY: Validate each path component to prevent path traversal
    if not validate_path_component(category) or not validate_path_component(template_name):
        logger.warning(f"Path traversal attempt blocked in custom diagram template: {template_id}")
        raise HTTPException(status_code=400, detail="Invalid template ID")

    base_dir = Path(CUSTOM_DIAGRAMS_TEMPLATES_DIR).resolve()
    template_path = Path(CUSTOM_DIAGRAMS_TEMPLATES_DIR) / category / f"{template_name}.toml"

    # SECURITY: Verify path stays within templates directory
    try:
        resolved_path = template_path.resolve()
        if not resolved_path.is_relative_to(base_dir):
            logger.warning(f"Path traversal attempt blocked: {template_id}")
            raise HTTPException(status_code=400, detail="Invalid template ID")
        # SECURITY: Reject symlinks
        if resolved_path.is_symlink():
            logger.warning(f"Symlink rejected: {template_id}")
            raise HTTPException(status_code=400, detail="Invalid template")
    except (ValueError, RuntimeError):
        raise HTTPException(status_code=400, detail="Invalid template ID")

    if not resolved_path.exists():
        raise HTTPException(status_code=404, detail=f"Template '{template_id}' not found")

    with open(resolved_path, 'r') as f:
        content = f.read()

    logger.info(f"Served custom diagram template: {template_id}")

    return {
        "id": template_id,
        "category": category,
        "name": template_name,
        "format": "toml",
        "content": content
    }


@app.post(
    "/custom-diagrams/visualize",
    tags=["Custom Diagrams"],
    summary="Generate custom diagram visualization",
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
async def visualize_custom_diagram(
    request: Request,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(..., description="TOML/JSON/YAML file containing custom diagram definition"),
    format: OutputFormat = Query(default=OutputFormat.PNG, description="Output format"),
    style: CustomDiagramStyle = Query(default=CustomDiagramStyle.DEFAULT, description="Style preset"),
):
    """
    Generate a custom diagram visualization from an uploaded configuration file.

    The configuration file should contain:
    - `[diagram]` section with title, layout, and direction settings
    - `[schema]` section defining node types and edge types
    - `[[nodes]]` array with node instances
    - `[[edges]]` array with edge connections
    - `[[clusters]]` array (optional) for grouping nodes

    Example TOML structure:
    ```toml
    [diagram]
    title = "My Custom Diagram"
    layout = "hierarchical"
    direction = "TB"

    [schema.nodes.process]
    shape = "box"
    fillcolor = "#E3F2FD"

    [[nodes]]
    id = "node1"
    type = "process"
    label = "Process A"

    [[edges]]
    from = "node1"
    to = "node2"
    label = "connects"
    ```
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

        # Create CustomDiagrams instance and build visualization
        cd = CustomDiagrams()
        cd.load(input_for_viz)

        # Build the diagram
        result = cd.BuildCustomDiagram(
            output=output_base,
            output_format=format.value,
            validate=True
        )
        output_path = result.output_path

        if not output_path or not os.path.exists(output_path):
            cleanup_files(input_path, modified_input_path)
            raise HTTPException(status_code=500, detail="Failed to generate visualization")

        background_tasks.add_task(cleanup_files, input_path, modified_input_path, output_path)

        return FileResponse(
            path=output_path,
            media_type=get_content_type(format),
            filename=f"custom_diagram.{format.value}",
        )

    except CustomDiagramError as e:
        cleanup_files(input_path, modified_input_path, output_path)
        raise HTTPException(status_code=400, detail=str(e))
    except (FileError, ConfigError) as e:
        cleanup_files(input_path, modified_input_path, output_path)
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        cleanup_files(input_path, modified_input_path, output_path)
        logger.error(f"Custom diagram visualization error: {e}")
        logger.error(f"Internal error: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="An internal error occurred")


@app.post(
    "/custom-diagrams/validate",
    response_model=CustomDiagramValidateResponse,
    tags=["Custom Diagrams"],
    summary="Validate custom diagram configuration"
)
@limiter.limit(RATE_LIMIT_ANALYZE)
async def validate_custom_diagram(
    request: Request,
    file: UploadFile = File(..., description="TOML/JSON/YAML file containing custom diagram definition"),
):
    """
    Validate a custom diagram configuration without generating visualization.

    Checks for:
    - Valid schema structure (node types, edge types)
    - Node references in edges
    - Required fields
    - Type consistency

    Returns validation result with any errors or warnings found.
    """
    input_path = None

    try:
        validate_config_file_extension(file.filename)
        input_path = save_upload_file(file)

        cd = CustomDiagrams()
        cd.load(input_path)
        result = cd.validate(raise_on_error=False)

        return CustomDiagramValidateResponse(
            valid=result.get("valid", False),
            errors=result.get("errors", []),
            warnings=result.get("warnings", []),
            node_count=len(cd.nodes),
            edge_count=len(cd.edges),
            cluster_count=len(cd.clusters) if cd.clusters else 0,
        )

    except CustomDiagramError as e:
        return CustomDiagramValidateResponse(
            valid=False,
            errors=[str(e)],
            warnings=[],
            node_count=0,
            edge_count=0,
            cluster_count=0,
        )
    except (FileError, ConfigError) as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Custom diagram validation error: {e}")
        logger.error(f"Internal error: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="An internal error occurred")
    finally:
        cleanup_files(input_path)


@app.post(
    "/custom-diagrams/stats",
    response_model=CustomDiagramStatsResponse,
    tags=["Custom Diagrams"],
    summary="Get custom diagram statistics"
)
@limiter.limit(RATE_LIMIT_ANALYZE)
async def get_custom_diagram_stats(
    request: Request,
    file: UploadFile = File(..., description="TOML/JSON/YAML file containing custom diagram definition"),
):
    """
    Analyze a custom diagram and return statistics.

    Returns:
    - Node and edge counts
    - Node type distribution
    - Edge type distribution
    - Cluster information
    - Connectivity metrics
    """
    input_path = None

    try:
        validate_config_file_extension(file.filename)
        input_path = save_upload_file(file)

        cd = CustomDiagrams()
        cd.load(input_path)
        cd.validate(raise_on_error=False)
        stats = cd.get_stats()

        return CustomDiagramStatsResponse(
            total_nodes=stats.get("total_nodes", 0),
            total_edges=stats.get("total_edges", 0),
            total_clusters=stats.get("total_clusters", 0),
            node_types=stats.get("node_types", {}),
            edge_types=stats.get("edge_types", {}),
            title=stats.get("title", "Custom Diagram"),
            layout=stats.get("layout", "hierarchical"),
            direction=stats.get("direction", "TB"),
        )

    except CustomDiagramError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except (FileError, ConfigError) as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Custom diagram stats error: {e}")
        logger.error(f"Internal error: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="An internal error occurred")
    finally:
        cleanup_files(input_path)


@app.post(
    "/custom-diagrams/from-template",
    tags=["Custom Diagrams"],
    summary="Create custom diagram from template",
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
async def custom_diagram_from_template(
    request: Request,
    background_tasks: BackgroundTasks,
    template_id: str = Query(..., description="Template ID (e.g., 'software/architecture')"),
    format: OutputFormat = Query(default=OutputFormat.PNG, description="Output format"),
    style: CustomDiagramStyle = Query(default=CustomDiagramStyle.DEFAULT, description="Style preset"),
):
    """
    Generate a custom diagram from a built-in template.

    Use this endpoint to quickly generate example diagrams using pre-defined templates.

    Available templates can be listed using GET /custom-diagrams/templates
    """
    output_path = None

    try:
        # Parse template ID
        parts = template_id.split('/')
        if len(parts) != 2:
            raise HTTPException(status_code=400, detail="Invalid template ID format. Use 'category/template_name'")

        category, template_name = parts
        template_path = os.path.join(CUSTOM_DIAGRAMS_TEMPLATES_DIR, category, f"{template_name}.toml")

        if not os.path.exists(template_path):
            raise HTTPException(status_code=404, detail=f"Template '{template_id}' not found")

        output_base = os.path.join(TEMP_DIR, f"output_{os.urandom(8).hex()}")

        # Create CustomDiagrams instance and build visualization
        cd = CustomDiagrams()
        cd.load(template_path)

        # Build the diagram
        result = cd.BuildCustomDiagram(
            output=output_base,
            output_format=format.value,
            validate=True
        )
        output_path = result.output_path

        if not output_path or not os.path.exists(output_path):
            raise HTTPException(status_code=500, detail="Failed to generate visualization")

        background_tasks.add_task(cleanup_files, output_path)

        return FileResponse(
            path=output_path,
            media_type=get_content_type(format),
            filename=f"{template_name}.{format.value}",
        )

    except CustomDiagramError as e:
        cleanup_files(output_path)
        raise HTTPException(status_code=400, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        cleanup_files(output_path)
        logger.error(f"Custom diagram from template error: {e}")
        logger.error(f"Internal error: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="An internal error occurred")


@app.post(
    "/custom-diagrams/import",
    tags=["Custom Diagrams"],
    summary="Import from another visualization type",
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
async def import_to_custom_diagram(
    request: Request,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(..., description="Configuration file to import"),
    source_type: VisualizationMode = Query(..., description="Source visualization type"),
    format: OutputFormat = Query(default=OutputFormat.PNG, description="Output format"),
    style: CustomDiagramStyle = Query(default=CustomDiagramStyle.DEFAULT, description="Style preset"),
):
    """
    Import data from another visualization type and render as custom diagram.

    Converts existing visualizations to custom diagram format:
    - **attack_tree**: Converts attack tree nodes and edges
    - **attack_graph**: Converts hosts, vulnerabilities, exploits to nodes
    - **threat_model**: Converts DFD elements (processes, datastores, externals)

    This allows applying custom styling and schema to existing security models.
    """
    input_path = None
    output_path = None

    try:
        validate_config_file_extension(file.filename)
        input_path = save_upload_file(file)
        output_base = os.path.join(TEMP_DIR, f"output_{os.urandom(8).hex()}")

        # Create CustomDiagrams from source type
        cd = CustomDiagrams()

        if source_type == VisualizationMode.ATTACK_TREE:
            at = AttackTrees(input_path, "unused")
            cd.from_attack_tree(at)
        elif source_type == VisualizationMode.ATTACK_GRAPH:
            ag = AttackGraphs(input_path, "unused")
            ag.load()
            cd.from_attack_graph(ag)
        elif source_type == VisualizationMode.THREAT_MODEL:
            tm = ThreatModeling(input_path, "unused")
            tm.load()
            cd.from_threat_model(tm)
        else:
            raise HTTPException(status_code=400, detail=f"Import from '{source_type.value}' is not supported")

        # Build the diagram
        result = cd.BuildCustomDiagram(
            output=output_base,
            output_format=format.value,
            validate=True
        )
        output_path = result.output_path

        if not output_path or not os.path.exists(output_path):
            cleanup_files(input_path)
            raise HTTPException(status_code=500, detail="Failed to generate visualization")

        background_tasks.add_task(cleanup_files, input_path, output_path)

        return FileResponse(
            path=output_path,
            media_type=get_content_type(format),
            filename=f"imported_diagram.{format.value}",
        )

    except CustomDiagramError as e:
        cleanup_files(input_path, output_path)
        raise HTTPException(status_code=400, detail=str(e))
    except (AttackTreeError, AttackGraphError) as e:
        cleanup_files(input_path, output_path)
        raise HTTPException(status_code=400, detail=str(e))
    except (FileError, ConfigError) as e:
        cleanup_files(input_path, output_path)
        raise HTTPException(status_code=400, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        cleanup_files(input_path, output_path)
        logger.error(f"Custom diagram import error: {e}")
        logger.error(f"Internal error: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="An internal error occurred")


@app.get(
    "/custom-diagrams/styles",
    tags=["Custom Diagrams"],
    summary="Get available custom diagram styles"
)
async def get_custom_diagram_styles():
    """Get all available style presets for custom diagrams."""
    return {
        "styles": [s.value for s in CustomDiagramStyle],
        "default": CustomDiagramStyle.DEFAULT.value,
        "descriptions": {
            CustomDiagramStyle.DEFAULT.value: "Default clean style with blue tones",
            CustomDiagramStyle.DARK.value: "Dark mode with light text on dark backgrounds",
            CustomDiagramStyle.BLUEPRINT.value: "Technical blueprint style with grid background",
            CustomDiagramStyle.MINIMAL.value: "Minimal black and white style",
            CustomDiagramStyle.NEON.value: "Vibrant neon style with glowing effects",
            CustomDiagramStyle.CORPORATE.value: "Professional corporate styling",
        }
    }


@app.get(
    "/custom-diagrams/layouts",
    tags=["Custom Diagrams"],
    summary="Get available layout algorithms"
)
async def get_custom_diagram_layouts():
    """Get all available layout algorithms for custom diagrams."""
    return {
        "layouts": [l.value for l in CustomDiagramLayout],
        "default": CustomDiagramLayout.HIERARCHICAL.value,
        "descriptions": {
            CustomDiagramLayout.HIERARCHICAL.value: "Top-down or left-right tree layout (dot)",
            CustomDiagramLayout.CIRCULAR.value: "Circular arrangement of nodes (circo)",
            CustomDiagramLayout.FORCE.value: "Force-directed graph layout (neato)",
            CustomDiagramLayout.RADIAL.value: "Radial layout from center (twopi)",
            CustomDiagramLayout.GRID.value: "Grid-based layout (osage)",
        }
    }


# =============================================================================
# Image Upload Endpoints
# =============================================================================

RATE_LIMIT_IMAGE_UPLOAD = os.getenv("RATE_LIMIT_IMAGE_UPLOAD", "30/minute")


@app.post(
    "/images/upload",
    response_model=ImageUploadResponse,
    tags=["Images"],
    summary="Upload an image for use in visualizations"
)
@limiter.limit(RATE_LIMIT_IMAGE_UPLOAD)
async def upload_image(
    request: Request,
    file: UploadFile = File(..., description="Image file to upload (PNG, JPEG, GIF, SVG, BMP)")
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
    from datetime import datetime

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

    # Generate unique ID and save
    image_id = str(uuid.uuid4())
    ext = IMAGE_ALLOWED_TYPES[file.content_type]
    filename = f"{image_id}{ext}"
    filepath = os.path.join(IMAGE_UPLOAD_DIR, filename)

    os.makedirs(IMAGE_UPLOAD_DIR, exist_ok=True)

    with open(filepath, 'wb') as f:
        f.write(contents)

    logger.info(f"Image uploaded: {image_id} ({sanitize_filename_for_log(file.filename)}, {len(contents)} bytes)")

    return ImageUploadResponse(
        image_id=image_id,
        filename=file.filename or "unknown",
        size=len(contents),
        content_type=file.content_type
    )


@app.get(
    "/images/{image_id}",
    response_model=ImageInfoResponse,
    tags=["Images"],
    summary="Get information about an uploaded image"
)
@limiter.limit(RATE_LIMIT_DEFAULT)
async def get_image_info(request: Request, image_id: str):
    """
    Get information about an uploaded image by its ID.

    Returns image metadata including size, content type, and creation time.
    """
    from datetime import datetime

    # SECURITY: Use secure image resolution with UUID validation
    try:
        filepath = resolve_image_id(image_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Image not found")

    stat = os.stat(filepath)

    return ImageInfoResponse(
        image_id=image_id,
        exists=True,
        size=stat.st_size,
        content_type=get_image_content_type(filepath),
        created_at=datetime.fromtimestamp(stat.st_mtime).isoformat() + "Z"
    )


@app.get(
    "/images/{image_id}/download",
    tags=["Images"],
    summary="Download an uploaded image"
)
@limiter.limit(RATE_LIMIT_DEFAULT)
async def download_image(request: Request, image_id: str):
    """
    Download an uploaded image by its ID.

    Returns the image file.
    """
    # SECURITY: Use secure image resolution with UUID validation
    try:
        filepath = resolve_image_id(image_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Image not found")

    content_type = get_image_content_type(filepath)

    return FileResponse(
        filepath,
        media_type=content_type,
        filename=os.path.basename(filepath)
    )


@app.delete(
    "/images/{image_id}",
    response_model=ImageDeleteResponse,
    tags=["Images"],
    summary="Delete an uploaded image"
)
@limiter.limit(RATE_LIMIT_DEFAULT)
async def delete_image(request: Request, image_id: str):
    """
    Delete an uploaded image by its ID.

    This permanently removes the image from the server.
    """
    # SECURITY: Use secure image resolution with UUID validation
    try:
        filepath = resolve_image_id(image_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Image not found")

    os.unlink(filepath)

    logger.info(f"Image deleted: {image_id}")

    return ImageDeleteResponse(
        deleted=True,
        image_id=image_id
    )


@app.get(
    "/images",
    response_model=ImageListResponse,
    tags=["Images"],
    summary="List all uploaded images"
)
@limiter.limit(RATE_LIMIT_DEFAULT)
async def list_images(request: Request):
    """
    List all currently uploaded images.

    Returns a list of image information including IDs, sizes, and types.
    Note: Images are automatically cleaned up after the retention period.
    """
    from datetime import datetime

    images = []

    if os.path.exists(IMAGE_UPLOAD_DIR):
        for filename in os.listdir(IMAGE_UPLOAD_DIR):
            filepath = os.path.join(IMAGE_UPLOAD_DIR, filename)
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


# =============================================================================
# Bundled Icons Endpoints
# =============================================================================

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


@app.get(
    "/icons",
    response_model=BundledIconsListResponse,
    tags=["Icons"],
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


@app.get(
    "/icons/categories",
    response_model=BundledIconsCategoriesResponse,
    tags=["Icons"],
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


@app.get(
    "/icons/{icon_path:path}",
    tags=["Icons"],
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


# =============================================================================
# Main Entry Point
# =============================================================================

if __name__ == "__main__":
    import uvicorn

    # SECURITY: Configure uvicorn with appropriate limits and timeouts
    # These can be overridden via environment variables for production
    uvicorn.run(
        app,
        host=os.getenv("API_HOST", "0.0.0.0"),
        port=int(os.getenv("API_PORT", "8000")),
        # Timeout for keep-alive connections (seconds)
        timeout_keep_alive=int(os.getenv("TIMEOUT_KEEP_ALIVE", "5")),
        # Limit max concurrent connections to prevent resource exhaustion
        limit_concurrency=int(os.getenv("LIMIT_CONCURRENCY", "100")),
        # Limit max requests per worker before recycling (prevents memory leaks)
        limit_max_requests=int(os.getenv("LIMIT_MAX_REQUESTS", "10000")),
    )
