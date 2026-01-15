#
# VULNEX -Universal Security Visualization Library-
#
# File: auth.py
# Author: Simon Roses Femerling
# Created: 2025-12-30
# Last Modified: 2025-12-31
# Version: 0.3.3
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""API Authentication module for USecVisLib.

Provides API key-based authentication with support for:
- Single or multiple API keys
- Auth toggle for local development
- Fail-fast validation on startup
"""

import os
import secrets
import logging
import hashlib
from typing import Optional, List, Dict

from fastapi import HTTPException, Security, Request
from fastapi.security import APIKeyHeader

logger = logging.getLogger("usecvislib.api.auth")

# =============================================================================
# Configuration
# =============================================================================

def is_auth_enabled() -> bool:
    """Check if authentication is enabled (runtime check for testing flexibility)."""
    return os.getenv("USECVISLIB_AUTH_ENABLED", "true").lower() == "true"

# Legacy constant for backwards compatibility (use is_auth_enabled() for dynamic check)
AUTH_ENABLED = is_auth_enabled()
API_KEY_HEADER_NAME = os.getenv("USECVISLIB_API_KEY_HEADER", "X-API-Key")

# Paths that don't require authentication (docs only - health now requires auth for security)
AUTH_EXCLUDED_PATHS = {
    "/docs",
    "/docs/oauth2-redirect",
    "/redoc",
    "/openapi.json",
    "/icons",             # Icon list endpoint (needed for gallery)
    "/icons/categories",  # Icon categories endpoint (needed for gallery)
    # NOTE: /health removed - should require auth to prevent information disclosure
}

# Path prefixes that don't require authentication (for wildcard routes)
# NOTE: /icons/ must be excluded because <img> tags cannot pass auth headers
AUTH_EXCLUDED_PREFIXES = (
    "/icons/",  # Icon file serving - required for <img> tags in gallery
)

# Multiple keys support: comma-separated list
# Example: USECVISLIB_API_KEYS="key1,key2,key3"
API_KEYS_ENV = os.getenv("USECVISLIB_API_KEYS", "")

# Single key fallback for backwards compatibility
API_KEY_ENV = os.getenv("USECVISLIB_API_KEY", "")


# =============================================================================
# Key Management
# =============================================================================

def get_configured_keys() -> List[str]:
    """Get list of configured API keys.

    Reads from both USECVISLIB_API_KEYS (comma-separated) and
    USECVISLIB_API_KEY (single key) for flexibility.

    Returns:
        List of configured API keys (may be empty).
    """
    keys = []

    # Add keys from USECVISLIB_API_KEYS (comma-separated)
    if API_KEYS_ENV:
        keys.extend([k.strip() for k in API_KEYS_ENV.split(",") if k.strip()])

    # Add single key from USECVISLIB_API_KEY (backwards compatibility)
    if API_KEY_ENV and API_KEY_ENV not in keys:
        keys.append(API_KEY_ENV)

    return keys


def generate_example_key() -> str:
    """Generate a secure example API key.

    Returns:
        A cryptographically secure random key with 'usecvis_' prefix.
    """
    return f"usecvis_{secrets.token_urlsafe(32)}"


def _hash_key(key: str) -> str:
    """Hash an API key using SHA-256 for constant-time comparison.

    SECURITY: This normalizes key lengths to prevent timing attacks.
    secrets.compare_digest() returns early on length mismatch, so we hash
    keys to ensure all comparisons operate on 64-character hex strings.

    Args:
        key: The API key to hash.

    Returns:
        SHA-256 hash of the key as a hex string (always 64 characters).
    """
    return hashlib.sha256(key.encode('utf-8')).hexdigest()


# Cache of hashed keys for efficient lookup (populated on first use)
_hashed_keys_cache: Dict[str, int] = {}  # hash -> key index
_cache_initialized: bool = False


def _get_hashed_keys() -> Dict[str, int]:
    """Get dictionary mapping hashed keys to their indices.

    Lazily initializes the cache on first call.

    Returns:
        Dictionary mapping SHA-256 hashes to key indices.
    """
    global _hashed_keys_cache, _cache_initialized

    if not _cache_initialized:
        keys = get_configured_keys()
        _hashed_keys_cache = {_hash_key(k): idx for idx, k in enumerate(keys)}
        _cache_initialized = True

    return _hashed_keys_cache


def refresh_key_cache() -> None:
    """Refresh the hashed keys cache.

    Call this if API keys are modified at runtime.
    """
    global _cache_initialized
    _cache_initialized = False
    _get_hashed_keys()  # Re-initialize


# =============================================================================
# Startup Validation
# =============================================================================

def validate_auth_config() -> None:
    """Validate authentication configuration on startup.

    When authentication is enabled, ensures at least one API key is configured.
    If no keys are found, logs helpful instructions and exits.

    Raises:
        SystemExit: If auth is enabled but no keys are configured.
    """
    if not AUTH_ENABLED:
        logger.info("Authentication DISABLED (USECVISLIB_AUTH_ENABLED=false)")
        return

    keys = get_configured_keys()

    if not keys:
        example_key = generate_example_key()
        logger.error("=" * 70)
        logger.error("AUTHENTICATION ERROR: No API keys configured!")
        logger.error("")
        logger.error("Authentication is enabled but no keys are set.")
        logger.error("Please set one of the following environment variables:")
        logger.error("")
        logger.error(f"  USECVISLIB_API_KEY={example_key}")
        logger.error("")
        logger.error("Or for multiple keys:")
        logger.error("")
        logger.error(f"  USECVISLIB_API_KEYS={example_key},another_key_here")
        logger.error("")
        logger.error("To disable authentication for local development:")
        logger.error("")
        logger.error("  USECVISLIB_AUTH_ENABLED=false")
        logger.error("=" * 70)
        raise SystemExit(1)

    logger.info(f"Authentication ENABLED with {len(keys)} API key(s) configured")


# =============================================================================
# FastAPI Security
# =============================================================================

# Security scheme for OpenAPI docs
api_key_header = APIKeyHeader(name=API_KEY_HEADER_NAME, auto_error=False)


async def verify_api_key(
    request: Request,
    api_key: Optional[str] = Security(api_key_header)
) -> Optional[str]:
    """Verify API key from request header.

    This is a FastAPI dependency that validates the API key on each request.
    When authentication is disabled, it passes through without checking.
    Documentation paths are always excluded from authentication.

    Args:
        request: FastAPI request object (for logging context).
        api_key: API key extracted from header by FastAPI.

    Returns:
        The validated API key if authentication passes, None if auth disabled.

    Raises:
        HTTPException: 401 Unauthorized if auth enabled and key is missing/invalid.
    """
    path = request.url.path

    # Skip auth for excluded paths (docs, etc.)
    if path in AUTH_EXCLUDED_PATHS:
        return None

    # Skip auth for excluded prefixes (icons, etc.)
    if path.startswith(AUTH_EXCLUDED_PREFIXES):
        return None

    # Skip auth if disabled globally (use dynamic check for testing flexibility)
    if not is_auth_enabled():
        return None

    client_ip = request.client.host if request.client else "unknown"

    # Check if key is provided
    if not api_key:
        logger.warning(f"Auth failed: missing API key | path={path} | client={client_ip}")
        raise HTTPException(
            status_code=401,
            detail="Missing API key. Include header: X-API-Key: <your-key>",
            headers={"WWW-Authenticate": "ApiKey"}
        )

    # SECURITY: Validate key using constant-time comparison with hashed keys
    # We hash the incoming key to normalize length (SHA-256 = 64 chars always)
    # This prevents timing attacks that could leak key length information
    # because secrets.compare_digest() returns early on length mismatch.
    incoming_hash = _hash_key(api_key)
    hashed_keys = _get_hashed_keys()

    # Use constant-time comparison on fixed-length hashes
    key_valid = False
    matched_key_index = -1

    # Iterate ALL hashed keys to ensure constant time (no early exit)
    for key_hash, idx in hashed_keys.items():
        if secrets.compare_digest(incoming_hash, key_hash):
            key_valid = True
            matched_key_index = idx
        # Continue checking all keys even after match to ensure constant time

    if not key_valid:
        logger.warning(f"Auth failed: invalid API key | path={path} | client={client_ip}")
        raise HTTPException(
            status_code=401,
            detail="Invalid API key",
            headers={"WWW-Authenticate": "ApiKey"}
        )

    # Log successful auth with key identifier (index only, not the key itself)
    key_id = f"key_{matched_key_index}" if matched_key_index >= 0 else "unknown"
    logger.debug(f"Auth successful | path={path} | client={client_ip} | key_id={key_id}")
    logger.info(f"API access | path={path} | client={client_ip} | key_id={key_id}")
    return api_key


# Dependency for protected routes - use this in endpoint definitions
require_auth = Security(verify_api_key)
