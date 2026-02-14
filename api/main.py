#
# VULNEX -Universal Security Visualization Library-
#
# File: main.py
# Description: FastAPI application entry point with router includes
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
#

"""USecVisLib FastAPI Application.

REST API for generating security visualizations from uploaded files.
"""

import os
import sys
import shutil
import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from usecvislib import __version__ as lib_version

from .config import (
    LOG_LEVEL,
    ALLOWED_ORIGINS,
    IMAGE_UPLOAD_DIR,
    IMAGE_CLEANUP_AGE,
    RATE_LIMIT_DEFAULT,
    RATE_LIMIT_VISUALIZE,
    RATE_LIMIT_ANALYZE,
    TEMP_DIR,
    limiter,
)
from .middleware import SecurityHeadersMiddleware, RequestLoggingMiddleware
from .helpers import cleanup_old_images
from .auth import validate_auth_config, verify_api_key, AUTH_ENABLED, API_KEY_HEADER_NAME
from .schemas import ErrorResponse

from .routers import (
    attack_trees,
    attack_graphs,
    threat_models,
    binary,
    custom_diagrams,
    mermaid,
    cloud,
    images,
    icons,
    settings,
    utilities,
    privilege_gradient,
    architecture,
)

logger = logging.getLogger("usecvislib.api")


# =============================================================================
# Application Lifespan
# =============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler for startup/shutdown."""
    # Validate authentication configuration (will exit if invalid)
    validate_auth_config()

    # Startup - version info only in DEBUG to reduce information disclosure
    if LOG_LEVEL == "DEBUG":
        logger.debug(f"Starting USecVisLib API v{lib_version}")
        logger.debug(f"Temp directory: {TEMP_DIR}")
        logger.debug(f"Image upload directory: {IMAGE_UPLOAD_DIR}")
    else:
        logger.info("Starting USecVisLib API")
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


# =============================================================================
# FastAPI Application
# =============================================================================

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
    version="0.3.4",
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

# =============================================================================
# Middleware
# =============================================================================

# CORS middleware for cross-origin requests (restricted to allowed origins)
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "OPTIONS"],
    # SECURITY: Use API_KEY_HEADER_NAME to support custom header names
    allow_headers=["Content-Type", "Accept", API_KEY_HEADER_NAME],
    # SECURITY: Cache preflight requests for 1 hour to reduce OPTIONS requests
    max_age=3600,
)

# Security headers middleware
app.add_middleware(SecurityHeadersMiddleware)

# Request logging middleware
app.add_middleware(RequestLoggingMiddleware)

# Rate limiting
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# =============================================================================
# Router Includes
# =============================================================================

app.include_router(utilities.router)
app.include_router(attack_trees.router)
app.include_router(attack_graphs.router)
app.include_router(threat_models.router)
app.include_router(binary.router)
app.include_router(custom_diagrams.router)
app.include_router(mermaid.router)
app.include_router(cloud.router)
app.include_router(images.router)
app.include_router(icons.router)
app.include_router(settings.router)
app.include_router(privilege_gradient.router)
app.include_router(architecture.router)


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
