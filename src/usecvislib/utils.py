#
# VULNEX -Universal Security Visualization Library-
#
# File: utils.py
# Author: Simon Roses Femerling
# Created: 2025-01-01
# Last Modified: 2025-12-31
# Version: 0.3.3
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Utility functions for USecVisLib.

This module provides common utility functions for file handling,
configuration management, dictionary operations, and security utilities.

Supports multiple configuration formats: TOML, JSON, and YAML.
"""

import os
import re
import sys
import json
import logging
import functools
import hashlib
from pathlib import Path
from typing import Dict, Any, Optional, List, TypeVar, Literal, Union, Callable

try:
    import tomllib  # Python 3.11+ standard library
except ImportError:
    tomllib = None
import toml  # Fallback for older parsing
import yaml
import tempfile

# Optional PIL for image resizing
try:
    from PIL import Image
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False


# Configure module logger
logger = logging.getLogger(__name__)


# Supported configuration formats
ConfigFormat = Literal["toml", "json", "yaml", "mermaid"]
SUPPORTED_EXTENSIONS = {
    ".toml": "toml",
    ".tml": "toml",
    ".json": "json",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".mmd": "mermaid",
}


T = TypeVar('T')


# =============================================================================
# Custom Exception Hierarchy
# =============================================================================

class USecVisLibError(Exception):
    """Base exception for all USecVisLib errors.

    Provides consistent error formatting with optional context.

    Attributes:
        message: The error message.
        context: Optional dictionary of additional context information.
    """

    def __init__(self, message: str, **context):
        self.message = message
        self.context = context
        super().__init__(self._format_message())

    def _format_message(self) -> str:
        """Format error message with context."""
        msg = self.message
        if self.context:
            details = ", ".join(f"{k}={v}" for k, v in self.context.items())
            msg += f" ({details})"
        return msg


class ConfigError(USecVisLibError):
    """Exception raised for configuration parsing errors."""
    pass


class FileError(USecVisLibError):
    """Exception raised for file operation errors."""
    pass


class SecurityError(USecVisLibError):
    """Exception raised when a security violation is detected.

    This includes path traversal attempts, injection attempts,
    and other security-related issues.
    """
    pass


class ValidationError(USecVisLibError):
    """Exception raised when input validation fails."""
    pass


class RenderError(USecVisLibError):
    """Exception raised when visualization rendering fails."""
    pass


class AnalysisError(USecVisLibError):
    """Exception raised when analysis operations fail."""
    pass


# =============================================================================
# Path Validation Utilities
# =============================================================================

# Sensitive system paths that should not be written to
# SECURITY: Comprehensive list of paths that should never be written to
# NOTE: /var/tmp, /tmp, and /private/var/folders are excluded as they are temp dirs
SENSITIVE_PATHS = [
    # Core system directories
    '/etc', '/usr', '/bin', '/sbin', '/root', '/boot', '/lib',
    # Linux kernel/process filesystems
    '/proc', '/sys', '/dev',
    # Library directories
    '/lib64', '/lib32',
    # Optional/third-party software
    '/opt',
    # macOS-specific system paths (but not /private/var/folders which is temp)
    '/private/etc', '/System', '/Library',
    # Snap/Flatpak paths
    '/snap',
    # Specific /var subdirectories (not /var itself to allow /var/tmp)
    '/var/log', '/var/run', '/var/lib', '/var/spool', '/var/cache',
    # Specific /private/var subdirectories (not /private/var/folders which is temp)
    '/private/var/log', '/private/var/run', '/private/var/db', '/private/var/root',
]

# Default allowed configuration file extensions
CONFIG_EXTENSIONS = ['.toml', '.tml', '.json', '.yaml', '.yml']


def validate_input_path(
    path: str,
    allowed_extensions: Optional[List[str]] = None,
    max_size_bytes: Optional[int] = None
) -> Path:
    """Validate an input file path for security.

    Performs the following checks:
    - Path is not empty
    - No null bytes in path (path injection)
    - File exists and is a regular file
    - Extension is in allowed list (if specified)
    - File size is within limit (if specified)

    Args:
        path: The file path to validate.
        allowed_extensions: List of allowed file extensions (e.g., ['.toml', '.json']).
            If None, all extensions are allowed.
        max_size_bytes: Maximum allowed file size in bytes. If None, no limit.

    Returns:
        Resolved Path object.

    Raises:
        SecurityError: If path validation fails due to security concerns.
        FileNotFoundError: If file doesn't exist.
        FileError: If path is not a file.
    """
    if not path:
        raise SecurityError("Empty path provided")

    # Check for null bytes (path injection)
    if '\x00' in path:
        logger.warning(f"Null byte detected in path: {repr(path)}")
        raise SecurityError("Null byte detected in path")

    # Resolve to absolute path
    try:
        resolved = Path(path).resolve()
    except (OSError, ValueError) as e:
        raise SecurityError(f"Invalid path: {e}", path=path)

    # Check for null bytes in resolved path
    if '\x00' in str(resolved):
        raise SecurityError("Null byte detected in resolved path")

    # Check path exists
    if not resolved.exists():
        raise FileNotFoundError(f"Input file not found: {path}")

    if not resolved.is_file():
        raise FileError(f"Path is not a file: {path}")

    # Check extension
    if allowed_extensions:
        if resolved.suffix.lower() not in [ext.lower() for ext in allowed_extensions]:
            raise SecurityError(
                f"File extension '{resolved.suffix}' not allowed",
                allowed=allowed_extensions
            )

    # Check file size
    if max_size_bytes is not None:
        try:
            size = resolved.stat().st_size
            if size > max_size_bytes:
                raise SecurityError(
                    f"File size ({size} bytes) exceeds maximum ({max_size_bytes} bytes)",
                    file_size=size,
                    max_size=max_size_bytes
                )
        except OSError as e:
            raise FileError(f"Cannot check file size: {e}", path=path)

    logger.debug(f"Validated input path: {resolved}")
    return resolved


def validate_output_path(
    path: str,
    allowed_directory: Optional[Union[str, Path]] = None,
    create_parents: bool = True
) -> Path:
    """Validate an output file path for security.

    Performs the following checks:
    - Path is not empty
    - No null bytes in path
    - Not writing to sensitive system directories
    - Within allowed directory (if specified)
    - Parent directory can be created

    Args:
        path: The output file path to validate.
        allowed_directory: If set, output must be within this directory.
        create_parents: Whether to create parent directories if they don't exist.

    Returns:
        Resolved Path object.

    Raises:
        SecurityError: If path validation fails due to security concerns.
    """
    if not path:
        raise SecurityError("Empty output path provided")

    # Check for null bytes
    if '\x00' in path:
        logger.warning(f"Null byte detected in output path: {repr(path)}")
        raise SecurityError("Null byte detected in path")

    # Resolve to absolute path
    try:
        resolved = Path(path).resolve()
    except (OSError, ValueError) as e:
        raise SecurityError(f"Invalid path: {e}", path=path)

    # Check for null bytes in resolved path
    if '\x00' in str(resolved):
        raise SecurityError("Null byte detected in resolved path")

    # Check within allowed directory
    if allowed_directory:
        allowed = Path(allowed_directory).resolve()
        try:
            resolved.relative_to(allowed)
        except ValueError:
            raise SecurityError(
                f"Output path must be within {allowed_directory}",
                output_path=str(resolved),
                allowed_directory=str(allowed)
            )

    # Prevent writing to sensitive system locations
    resolved_str = str(resolved)
    for sensitive in SENSITIVE_PATHS:
        if resolved_str.startswith(sensitive + '/') or resolved_str == sensitive:
            raise SecurityError(
                f"Cannot write to sensitive location: {sensitive}",
                path=resolved_str
            )

    # Create parent directories if needed
    if create_parents:
        try:
            resolved.parent.mkdir(parents=True, exist_ok=True)
        except (OSError, PermissionError) as e:
            raise FileError(f"Cannot create output directory: {e}", path=str(resolved.parent))

    logger.debug(f"Validated output path: {resolved}")
    return resolved


# =============================================================================
# Image Path Validation and Resolution
# =============================================================================

# Supported image extensions for Graphviz
IMAGE_EXTENSIONS = ['.png', '.jpg', '.jpeg', '.gif', '.bmp', '.svg']

# Default max image size (5 MB)
IMAGE_MAX_SIZE = 5 * 1024 * 1024

# Image reference prefixes
IMAGE_PREFIX_BUNDLED = "bundled:"
IMAGE_PREFIX_UPLOADED = "uploaded:"


def _get_bundled_icons_dir() -> Optional[Path]:
    """Get the path to bundled icons directory.

    Searches in order:
    1. BUNDLED_ICONS_DIR environment variable
    2. assets/icons relative to src/usecvislib/
    3. /app/assets/icons (Docker)

    Returns:
        Path to bundled icons directory, or None if not found.
    """
    import os

    # Check environment variable first
    env_path = os.getenv("BUNDLED_ICONS_DIR")
    if env_path and os.path.isdir(env_path):
        return Path(env_path)

    # Try relative to this file (src/usecvislib/utils.py -> assets/icons)
    utils_dir = Path(__file__).parent
    project_root = utils_dir.parent.parent  # src/usecvislib -> src -> project_root
    assets_path = project_root / "assets" / "icons"
    if assets_path.is_dir():
        return assets_path

    # Try /app/assets/icons (Docker)
    docker_path = Path("/app/assets/icons")
    if docker_path.is_dir():
        return docker_path

    return None


def _get_uploaded_images_dir() -> Optional[Path]:
    """Get the path to uploaded images directory.

    Searches in order:
    1. IMAGE_UPLOAD_DIR environment variable
    2. Default temp directory location

    Returns:
        Path to uploaded images directory, or None if not found.
    """
    import os
    import tempfile

    # Check environment variable first
    env_path = os.getenv("IMAGE_UPLOAD_DIR")
    if env_path and os.path.isdir(env_path):
        return Path(env_path)

    # Default temp directory location
    default_path = Path(tempfile.gettempdir()) / "usecvislib" / "images"
    if default_path.is_dir():
        return default_path

    return None


def _validate_path_within_directory(path: Path, base_dir: Path) -> bool:
    """Securely validate that a path is within a base directory.

    SECURITY: This function prevents symlink escapes and path traversal attacks.

    Args:
        path: The path to validate (may be a symlink).
        base_dir: The directory the path must be within.

    Returns:
        True if path is safely within base_dir, False otherwise.
    """
    try:
        # Reject symlinks entirely to prevent symlink attacks
        if path.is_symlink():
            logger.warning(f"Security: Rejected symlink: {path}")
            return False

        # Resolve both paths to absolute
        resolved_path = path.resolve()
        resolved_base = base_dir.resolve()

        # Use relative_to() which raises ValueError if path is outside base
        try:
            resolved_path.relative_to(resolved_base)
            return True
        except ValueError:
            logger.warning(f"Security: Path escapes base directory: {path} not in {base_dir}")
            return False

    except (OSError, ValueError) as e:
        logger.warning(f"Security: Path validation failed for {path}: {e}")
        return False


def _convert_svg_to_png(svg_path: Path, size: int = 48) -> Optional[Path]:
    """Convert SVG to PNG for Graphviz compatibility.

    Graphviz has limited SVG support, so we convert to PNG.
    Converted files are cached in a temp directory.

    Args:
        svg_path: Path to the SVG file.
        size: Output size in pixels (square).

    Returns:
        Path to the converted PNG file, or None on failure.
    """
    try:
        import cairosvg
        import tempfile
        import hashlib
        import stat

        # Create a cache directory for converted icons
        cache_dir = Path(tempfile.gettempdir()) / "usecvislib_icon_cache"

        # SECURITY: TOCTOU-resistant directory creation
        # Use os.lstat() which doesn't follow symlinks, then check mode
        try:
            # Try to create the directory first (atomic operation)
            cache_dir.mkdir(exist_ok=False)
        except FileExistsError:
            # Directory already exists - verify it's safe using lstat
            pass

        # SECURITY: Use lstat to check the path without following symlinks
        try:
            dir_stat = os.lstat(cache_dir)
            # Verify it's a directory (not a symlink or file)
            if not stat.S_ISDIR(dir_stat.st_mode):
                logger.error(f"Security: Cache path is not a directory: {cache_dir}")
                return None
            # Check if it's a symlink (S_ISLNK check on lstat result)
            if stat.S_ISLNK(dir_stat.st_mode):
                logger.error(f"Security: Cache directory is a symlink: {cache_dir}")
                return None
        except OSError as e:
            logger.error(f"Security: Cannot stat cache directory: {cache_dir}: {e}")
            return None

        # Generate cache filename based on SVG path hash
        path_hash = hashlib.md5(str(svg_path).encode()).hexdigest()[:12]
        png_path = cache_dir / f"{path_hash}_{size}.png"

        # Return cached version if exists
        if png_path.exists():
            return png_path

        # Convert SVG to PNG
        cairosvg.svg2png(
            url=str(svg_path),
            write_to=str(png_path),
            output_width=size,
            output_height=size
        )
        logger.debug(f"Converted SVG to PNG: {svg_path} -> {png_path}")
        return png_path

    except ImportError:
        logger.warning("cairosvg not available, SVG icons will not render in Graphviz")
        return None
    except Exception as e:
        logger.warning(f"Failed to convert SVG to PNG: {svg_path} - {e}")
        return None


def resolve_bundled_icon(icon_id: str) -> Optional[Path]:
    """Resolve a bundled icon ID to its file path.

    Icon IDs can be in formats:
    - "category/name" (e.g., "azure/virtual-machine")
    - "category/subcategory/name" (e.g., "azure/Compute/virtual-machine")

    SVG icons are automatically converted to PNG for Graphviz compatibility.

    Args:
        icon_id: The bundled icon identifier.

    Returns:
        Path to the icon file (PNG preferred), or None if not found.

    Example:
        >>> path = resolve_bundled_icon("azure/Compute/10021-icon-service-Virtual-Machine")
        >>> # Returns path to the PNG file
    """
    icons_dir = _get_bundled_icons_dir()
    if not icons_dir:
        logger.warning("Bundled icons directory not found")
        return None

    # Security: Validate icon_id has no path traversal
    if ".." in icon_id or icon_id.startswith("/") or icon_id.startswith("\\"):
        logger.warning(f"Invalid bundled icon ID (path traversal attempt): {icon_id}")
        return None

    # Security: Reject URL-encoded path traversal attempts
    if "%2e" in icon_id.lower() or "%2f" in icon_id.lower() or "%5c" in icon_id.lower():
        logger.warning(f"Invalid bundled icon ID (encoded path traversal attempt): {icon_id}")
        return None

    # Priority order: PNG first (native Graphviz support), then SVG (needs conversion)
    png_extensions = ['.png', '.PNG']
    svg_extensions = ['.svg', '.SVG']
    other_extensions = [ext for ext in IMAGE_EXTENSIONS if ext.lower() not in ['.png', '.svg']]

    # Try PNG first (best Graphviz support)
    for ext in png_extensions:
        icon_path = icons_dir / f"{icon_id}{ext}"
        if icon_path.exists() and _validate_path_within_directory(icon_path, icons_dir):
            return icon_path.resolve()

    # Try SVG and convert to PNG
    for ext in svg_extensions:
        icon_path = icons_dir / f"{icon_id}{ext}"
        if icon_path.exists() and _validate_path_within_directory(icon_path, icons_dir):
            resolved = icon_path.resolve()
            # Convert SVG to PNG for Graphviz
            png_path = _convert_svg_to_png(resolved)
            if png_path:
                return png_path
            # Fall back to SVG if conversion fails
            return resolved

    # Try other formats
    for ext in other_extensions:
        icon_path = icons_dir / f"{icon_id}{ext}"
        if icon_path.exists() and _validate_path_within_directory(icon_path, icons_dir):
            return icon_path.resolve()

    # Also try without extension if icon_id already has one
    for ext in IMAGE_EXTENSIONS:
        if icon_id.lower().endswith(ext):
            icon_path = icons_dir / icon_id
            if icon_path.exists() and _validate_path_within_directory(icon_path, icons_dir):
                resolved = icon_path.resolve()
                # Convert SVG if needed
                if ext.lower() == '.svg':
                    png_path = _convert_svg_to_png(resolved)
                    if png_path:
                        return png_path
                return resolved
            break

    logger.warning(f"Bundled icon not found: {icon_id}")
    return None


def resolve_uploaded_image(image_id: str) -> Optional[Path]:
    """Resolve an uploaded image UUID to its file path.

    Args:
        image_id: The uploaded image UUID.

    Returns:
        Path to the image file, or None if not found.

    Example:
        >>> path = resolve_uploaded_image("abc12345-6789-def0-1234-567890abcdef")
        >>> # Returns path to the uploaded image file
    """
    images_dir = _get_uploaded_images_dir()
    if not images_dir:
        logger.warning("Uploaded images directory not found")
        return None

    # Validate UUID format (basic check)
    import re
    uuid_pattern = r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$'
    if not re.match(uuid_pattern, image_id.lower()):
        logger.warning(f"Invalid uploaded image ID format: {image_id}")
        return None

    # Find the image file (stored as uuid.ext)
    for ext in IMAGE_EXTENSIONS:
        image_path = images_dir / f"{image_id}{ext}"
        # SECURITY: Use secure path validation (prevents symlink attacks)
        if image_path.exists() and _validate_path_within_directory(image_path, images_dir):
            return image_path.resolve()

    logger.warning(f"Uploaded image not found: {image_id}")
    return None


def resolve_image_reference(image_ref: str) -> Optional[Path]:
    """Resolve an image reference to its file path.

    Supports three reference formats:
    1. "bundled:category/name" - Bundled icon from assets/icons
    2. "uploaded:uuid" - Uploaded image from temp storage
    3. "path/to/image.png" - Local file path (existing behavior)

    Args:
        image_ref: Image reference string.

    Returns:
        Resolved Path to the image file, or None if not found/invalid.

    Example:
        >>> resolve_image_reference("bundled:azure/Compute/virtual-machine")
        >>> resolve_image_reference("uploaded:abc12345-...")
        >>> resolve_image_reference("icons/custom.png")
    """
    if not image_ref:
        return None

    image_ref = str(image_ref).strip()

    # Handle bundled icon reference
    if image_ref.startswith(IMAGE_PREFIX_BUNDLED):
        icon_id = image_ref[len(IMAGE_PREFIX_BUNDLED):]
        return resolve_bundled_icon(icon_id)

    # Handle uploaded image reference
    if image_ref.startswith(IMAGE_PREFIX_UPLOADED):
        image_id = image_ref[len(IMAGE_PREFIX_UPLOADED):]
        return resolve_uploaded_image(image_id)

    # Handle local file path (existing behavior)
    try:
        return validate_image_path(image_ref)
    except (SecurityError, FileNotFoundError, Exception):
        return None


def validate_image_path(
    image_path: str,
    allowed_extensions: Optional[List[str]] = None,
    max_size_bytes: Optional[int] = None
) -> Path:
    """Validate an image path for security and existence.

    Performs the following checks:
    - Path is not empty
    - No null bytes in path (path injection)
    - File exists and is a regular file
    - Extension is in allowed list (image formats by default)
    - File size is within limit (5 MB default)

    This function is used to validate image paths in node attributes
    before passing them to Graphviz for rendering.

    Args:
        image_path: Path to the image file.
        allowed_extensions: List of allowed file extensions.
            Defaults to IMAGE_EXTENSIONS (.png, .jpg, .jpeg, .gif, .bmp, .svg).
        max_size_bytes: Maximum allowed file size in bytes.
            Defaults to IMAGE_MAX_SIZE (5 MB).

    Returns:
        Resolved Path object to the validated image.

    Raises:
        SecurityError: If path validation fails due to security concerns.
        FileNotFoundError: If image file doesn't exist.

    Example:
        >>> path = validate_image_path("icons/server.png")
        >>> node_attrs["image"] = str(path)
    """
    if allowed_extensions is None:
        allowed_extensions = IMAGE_EXTENSIONS

    if max_size_bytes is None:
        max_size_bytes = IMAGE_MAX_SIZE

    # Use existing validation infrastructure
    return validate_input_path(
        image_path,
        allowed_extensions=allowed_extensions,
        max_size_bytes=max_size_bytes
    )


def _escape_html(text: str) -> str:
    """Escape special HTML characters in text for Graphviz HTML labels.

    Args:
        text: The text to escape.

    Returns:
        HTML-escaped text safe for use in Graphviz HTML labels.
    """
    if not text:
        return ""
    # Escape HTML special characters
    text = str(text)
    text = text.replace("&", "&amp;")
    text = text.replace("<", "&lt;")
    text = text.replace(">", "&gt;")
    text = text.replace('"', "&quot;")
    # Convert newlines to HTML line breaks
    text = text.replace("\\n", "<BR/>")
    text = text.replace("\n", "<BR/>")
    return text


def process_node_image(
    node_attrs: Dict[str, Any],
    node_id: str,
    logger_instance: Optional[logging.Logger] = None,
    preserve_shape: bool = False
) -> Dict[str, Any]:
    """Process and validate image attribute in node attributes.

    If the node has an 'image' attribute, resolves and validates the path.
    Also sets proper Graphviz attributes for clean icon rendering:
    - shape="none" - No box/rectangle around icon (unless preserve_shape=True)
    - label="" - Empty internal label
    - xlabel - External label below the icon

    Supports three image reference formats:
    - "bundled:category/name" - Use bundled icon from assets/icons
    - "uploaded:uuid" - Use uploaded image from temp storage
    - "path/to/image.png" - Local file path

    Invalid images are removed with a warning.

    Args:
        node_attrs: Dictionary of node attributes (modified in place).
        node_id: Node identifier for logging purposes.
        logger_instance: Logger to use for warnings. Defaults to module logger.
        preserve_shape: If True, keep existing shape/style/fillcolor attributes.
            Use this when user explicitly set a shape in their config file.

    Returns:
        The node_attrs dictionary (same reference, potentially modified).

    Example:
        >>> attrs = {"label": "Server", "image": "bundled:azure/Compute/virtual-machine"}
        >>> process_node_image(attrs, "server_node")
        >>> # attrs now has xlabel="Server", label="", shape="none"

        >>> attrs = {"label": "Server", "image": "bundled:aws/ec2", "shape": "box"}
        >>> process_node_image(attrs, "server_node", preserve_shape=True)
        >>> # attrs keeps shape="box" with icon inside
    """
    log = logger_instance or logger

    if 'image' not in node_attrs:
        return node_attrs

    image_ref = node_attrs.get('image')

    # Skip if image is empty or None
    if not image_ref:
        del node_attrs['image']
        return node_attrs

    # Use the unified image resolution function
    resolved_path = resolve_image_reference(str(image_ref))

    if resolved_path:
        log.debug(f"Resolved image for node '{node_id}': {image_ref} -> {resolved_path}")

        # Get the label text (existing label or node_id)
        label_text = node_attrs.get('label', '') or node_id

        # Set Graphviz attributes for icon rendering
        # SECURITY: Escape the path to prevent DOT injection via special characters
        escaped_path = _escape_html(str(resolved_path))

        # Always render icons cleanly without background boxes
        # Clear ALL existing attributes to ensure clean rendering
        node_attrs.clear()

        # Escape label text for HTML
        safe_label = _escape_html(str(label_text))

        # Resize large images to thumbnails for better display
        display_path = str(resolved_path)
        if PIL_AVAILABLE:
            try:
                with Image.open(resolved_path) as img:
                    # Only resize if image is larger than 64 pixels
                    if img.width > 64 or img.height > 64:
                        # Create thumbnail maintaining aspect ratio
                        img.thumbnail((48, 48), Image.Resampling.LANCZOS)
                        # Save to temp file
                        suffix = Path(resolved_path).suffix or '.png'
                        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
                            img.save(tmp.name)
                            display_path = tmp.name
                            log.debug(f"Created thumbnail for large icon: {resolved_path} -> {tmp.name}")
            except Exception as e:
                log.debug(f"Could not resize image {resolved_path}: {e}")

        # Use HTML TABLE for consistent icon + text layout
        # Image on top, text below - this ensures consistent positioning
        escaped_display = _escape_html(display_path)
        html_label = f'''<<TABLE BORDER="0" CELLBORDER="0" CELLSPACING="0" CELLPADDING="2">
<TR><TD><IMG SRC="{escaped_display}"/></TD></TR>
<TR><TD>{safe_label}</TD></TR>
</TABLE>>'''

        node_attrs['label'] = html_label
        node_attrs['shape'] = 'none'        # No shape = no background
        node_attrs['style'] = ''            # No style

    else:
        log.warning(f"Could not resolve image for node '{node_id}': {image_ref}")
        del node_attrs['image']

    return node_attrs


# =============================================================================
# DOT Injection Prevention
# =============================================================================

def escape_dot_label(value: Any, max_length: int = 1000) -> str:
    """Escape a value for safe use in Graphviz DOT labels.

    Prevents DOT injection by escaping special characters and
    enforcing length limits.

    Args:
        value: The value to escape (will be converted to string).
        max_length: Maximum allowed length (truncated if exceeded).

    Returns:
        Escaped string safe for DOT labels.
    """
    if value is None:
        return ""

    s = str(value)

    # Truncate if too long
    if len(s) > max_length:
        s = s[:max_length - 3] + "..."
        logger.debug(f"Truncated DOT label to {max_length} characters")

    # Remove null bytes and other control characters
    s = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', s)

    # Escape backslashes first
    s = s.replace('\\', '\\\\')

    # Escape quotes
    s = s.replace('"', '\\"')

    # Escape newlines and tabs
    s = s.replace('\n', '\\n')
    s = s.replace('\r', '\\r')
    s = s.replace('\t', '\\t')

    # Escape HTML-like characters for label safety
    s = s.replace('<', '\\<')
    s = s.replace('>', '\\>')
    s = s.replace('{', '\\{')
    s = s.replace('}', '\\}')
    s = s.replace('|', '\\|')

    return s


def sanitize_node_id(node_id: Any) -> str:
    """Sanitize a node ID for safe use in DOT graphs.

    Only allows alphanumeric characters, underscores, and hyphens.
    Ensures the ID is valid for Graphviz DOT format.

    Args:
        node_id: The node ID to sanitize.

    Returns:
        Sanitized node ID safe for DOT graphs.
    """
    if node_id is None:
        return "unnamed"

    s = str(node_id)

    # Only allow safe characters: alphanumeric, underscore, hyphen
    sanitized = re.sub(r'[^a-zA-Z0-9_-]', '_', s)

    # Ensure doesn't start with a number (DOT requirement)
    if sanitized and sanitized[0].isdigit():
        sanitized = 'n_' + sanitized

    # Ensure not empty
    if not sanitized:
        return 'unnamed'

    return sanitized


# =============================================================================
# Logging Configuration
# =============================================================================

def configure_logging(
    level: int = logging.INFO,
    format_string: Optional[str] = None,
    log_file: Optional[str] = None
) -> None:
    """Configure logging for USecVisLib.

    Args:
        level: Logging level (e.g., logging.DEBUG, logging.INFO).
        format_string: Custom format string for log messages.
        log_file: Optional file path to write logs to.
    """
    if format_string is None:
        format_string = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

    handlers: List[logging.Handler] = [logging.StreamHandler()]

    if log_file:
        try:
            file_handler = logging.FileHandler(log_file)
            handlers.append(file_handler)
        except (OSError, PermissionError) as e:
            logger.warning(f"Cannot create log file {log_file}: {e}")

    logging.basicConfig(
        level=level,
        format=format_string,
        handlers=handlers
    )


def get_logger(name: str) -> logging.Logger:
    """Get a logger for a specific module.

    Args:
        name: The name of the module (typically __name__).

    Returns:
        Configured logger instance.
    """
    return logging.getLogger(name)


def ReadTomlFile(ifile: str) -> Dict[str, Any]:
    """Read and parse a TOML file.

    Args:
        ifile: Path to the TOML file.

    Returns:
        Parsed TOML data as a dictionary.

    Raises:
        FileError: If the file does not exist or cannot be read.
        ConfigError: If the file is not valid TOML.

    Note:
        This function is kept for backwards compatibility.
        Consider using ReadConfigFile() for multi-format support.
    """
    if not os.path.isfile(ifile):
        raise FileError(f"Input file not found: {ifile}")

    try:
        return toml.load(ifile)
    except toml.TomlDecodeError as e:
        raise ConfigError(f"Invalid TOML file {ifile}: {e}")


def detect_format(filepath: str) -> ConfigFormat:
    """Detect configuration file format from extension.

    Args:
        filepath: Path to the configuration file.

    Returns:
        Detected format: 'toml', 'json', or 'yaml'.

    Raises:
        ConfigError: If the file extension is not supported.
    """
    _, ext = os.path.splitext(filepath.lower())

    if ext in SUPPORTED_EXTENSIONS:
        return SUPPORTED_EXTENSIONS[ext]

    raise ConfigError(
        f"Unsupported file extension: {ext}. "
        f"Supported extensions: {', '.join(SUPPORTED_EXTENSIONS.keys())}"
    )


def detect_format_from_content(content: str) -> ConfigFormat:
    """Detect configuration format from content.

    Attempts to parse content as JSON, then YAML, then TOML.

    Args:
        content: Configuration file content as string.

    Returns:
        Detected format: 'toml', 'json', or 'yaml'.

    Raises:
        ConfigError: If the content format cannot be detected.
    """
    # Try JSON first (strict syntax)
    try:
        json.loads(content)
        return "json"
    except json.JSONDecodeError:
        pass

    # Try TOML (has distinct syntax with [sections])
    try:
        toml.loads(content)
        # Check if it looks like TOML (has sections or key = value)
        if '[' in content or '=' in content:
            return "toml"
    except toml.TomlDecodeError:
        pass

    # Try YAML (most permissive)
    try:
        yaml.safe_load(content)
        return "yaml"
    except yaml.YAMLError:
        pass

    raise ConfigError("Unable to detect configuration format from content")


def parse_toml(content: str) -> Dict[str, Any]:
    """Parse TOML content string.

    Uses tomllib (Python 3.11+ standard library) as primary parser,
    with fallback to toml library for compatibility.

    Args:
        content: TOML content as string.

    Returns:
        Parsed data as dictionary.

    Raises:
        ConfigError: If content is not valid TOML.
    """
    # Try tomllib first (Python 3.11+) - more compliant parser
    if tomllib is not None:
        try:
            return tomllib.loads(content)
        except tomllib.TOMLDecodeError as e:
            raise ConfigError(f"Invalid TOML content: {e}")

    # Fallback to toml library
    try:
        return toml.loads(content)
    except toml.TomlDecodeError as e:
        raise ConfigError(f"Invalid TOML content: {e}")


def parse_json(content: str) -> Dict[str, Any]:
    """Parse JSON content string.

    Args:
        content: JSON content as string.

    Returns:
        Parsed data as dictionary.

    Raises:
        ConfigError: If content is not valid JSON.
    """
    try:
        return json.loads(content)
    except json.JSONDecodeError as e:
        raise ConfigError(f"Invalid JSON content: {e}")


def parse_yaml(content: str) -> Dict[str, Any]:
    """Parse YAML content string.

    Args:
        content: YAML content as string.

    Returns:
        Parsed data as dictionary.

    Raises:
        ConfigError: If content is not valid YAML.
    """
    try:
        result = yaml.safe_load(content)
        if result is None:
            return {}
        if not isinstance(result, dict):
            raise ConfigError("YAML content must be a mapping/dictionary at the root level")
        return result
    except yaml.YAMLError as e:
        raise ConfigError(f"Invalid YAML content: {e}")


def parse_content(content: str, format: ConfigFormat) -> Dict[str, Any]:
    """Parse configuration content in the specified format.

    Args:
        content: Configuration content as string.
        format: Format to parse as ('toml', 'json', or 'yaml').

    Returns:
        Parsed data as dictionary.

    Raises:
        ConfigError: If content is invalid or format is unsupported.
    """
    parsers = {
        "toml": parse_toml,
        "json": parse_json,
        "yaml": parse_yaml,
    }

    if format not in parsers:
        raise ConfigError(f"Unsupported format: {format}")

    return parsers[format](content)


def ReadConfigFile(filepath: str, format: Optional[ConfigFormat] = None) -> Dict[str, Any]:
    """Read and parse a configuration file (TOML, JSON, or YAML).

    Args:
        filepath: Path to the configuration file.
        format: Optional format override. If not provided, detected from extension.

    Returns:
        Parsed configuration data as dictionary.

    Raises:
        FileError: If the file does not exist or cannot be read.
        ConfigError: If the file format is unsupported or content is invalid.
    """
    if not os.path.isfile(filepath):
        raise FileError(f"Configuration file not found: {filepath}")

    # Detect format from extension if not provided
    if format is None:
        format = detect_format(filepath)

    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
    except IOError as e:
        raise FileError(f"Failed to read file {filepath}: {e}")

    return parse_content(content, format)


def serialize_to_toml(data: Dict[str, Any]) -> str:
    """Serialize dictionary to TOML string.

    Args:
        data: Dictionary to serialize.

    Returns:
        TOML formatted string.
    """
    return toml.dumps(data)


def serialize_to_json(data: Dict[str, Any], pretty: bool = True) -> str:
    """Serialize dictionary to JSON string.

    Args:
        data: Dictionary to serialize.
        pretty: If True, format with indentation.

    Returns:
        JSON formatted string.
    """
    if pretty:
        return json.dumps(data, indent=2, default=str)
    return json.dumps(data, default=str)


def serialize_to_yaml(data: Dict[str, Any]) -> str:
    """Serialize dictionary to YAML string.

    Args:
        data: Dictionary to serialize.

    Returns:
        YAML formatted string.
    """
    # SECURITY: Use SafeDumper to prevent serialization of arbitrary Python objects
    return yaml.dump(data, default_flow_style=False, allow_unicode=True, sort_keys=False, Dumper=yaml.SafeDumper)


def serialize_to_mermaid(data: Dict[str, Any]) -> str:
    """Serialize dictionary to Mermaid diagram syntax.

    Auto-detects the visualization type from the data structure
    and generates appropriate Mermaid diagram syntax.

    Args:
        data: Dictionary to serialize (configuration data).

    Returns:
        Mermaid diagram syntax string.

    Note:
        This is a one-way conversion. Mermaid syntax cannot be
        converted back to TOML/JSON/YAML.
    """
    from .mermaid import serialize_to_mermaid as mermaid_serialize
    return mermaid_serialize(data)


def serialize_content(data: Dict[str, Any], format: ConfigFormat) -> str:
    """Serialize dictionary to the specified format.

    Args:
        data: Dictionary to serialize.
        format: Target format ('toml', 'json', 'yaml', or 'mermaid').

    Returns:
        Formatted string in the specified format.

    Raises:
        ConfigError: If format is unsupported.
    """
    serializers = {
        "toml": serialize_to_toml,
        "json": serialize_to_json,
        "yaml": serialize_to_yaml,
        "mermaid": serialize_to_mermaid,
    }

    if format not in serializers:
        raise ConfigError(f"Unsupported format: {format}")

    return serializers[format](data)


def convert_format(content: str, from_format: ConfigFormat, to_format: ConfigFormat) -> str:
    """Convert configuration content from one format to another.

    Args:
        content: Configuration content as string.
        from_format: Source format ('toml', 'json', or 'yaml').
        to_format: Target format ('toml', 'json', 'yaml', or 'mermaid').

    Returns:
        Content converted to the target format.

    Raises:
        ConfigError: If parsing or serialization fails.

    Note:
        Converting to 'mermaid' is one-way. Mermaid syntax cannot be
        parsed back into structured data.
    """
    # Mermaid cannot be a source format
    if from_format == "mermaid":
        raise ConfigError("Cannot convert from Mermaid format. Mermaid is output-only.")

    data = parse_content(content, from_format)
    return serialize_content(data, to_format)


def GetCurrentDirectory() -> str:
    """Get the current working directory.

    Returns:
        Absolute path to the current working directory.
    """
    return os.getcwd()


def GetPackageDirectory() -> str:
    """Get the package installation directory.

    Returns:
        Absolute path to the package directory.
    """
    return os.path.dirname(os.path.abspath(__file__))


def _validate_path_component(component: str) -> None:
    """Validate a path component for security.

    SECURITY: Prevents path traversal and absolute path injection attacks.

    Args:
        component: Path component to validate.

    Raises:
        SecurityError: If the component contains dangerous patterns.
    """
    if not component:
        return

    # Check for path traversal
    if '..' in component:
        raise SecurityError(f"Path traversal detected in path component: {component}")

    # Check for absolute paths (would reset os.path.join)
    if component.startswith('/') or component.startswith('\\'):
        raise SecurityError(f"Absolute path not allowed in path component: {component}")

    # Check for Windows drive letters
    if len(component) >= 2 and component[1] == ':':
        raise SecurityError(f"Drive letter not allowed in path component: {component}")

    # Check for null bytes
    if '\x00' in component:
        raise SecurityError(f"Null byte detected in path component")


def JoinDirFile(directory: str, filename: str) -> str:
    """Join a directory and filename into a path.

    SECURITY: Validates filename to prevent path traversal attacks.

    Args:
        directory: Directory path.
        filename: Filename to append.

    Returns:
        Combined path.

    Raises:
        SecurityError: If filename contains path traversal patterns.
    """
    _validate_path_component(filename)
    return os.path.join(directory, filename)


def JoinDirFileList(directory: str, *args: str) -> str:
    """Join a directory with multiple path components.

    SECURITY: Validates all components to prevent path traversal attacks.

    Args:
        directory: Base directory path.
        *args: Additional path components.

    Returns:
        Combined path.

    Raises:
        SecurityError: If any component contains path traversal patterns.
    """
    for component in args:
        _validate_path_component(component)
    return os.path.join(directory, *args)


def merge_dicts(dict1: Dict[str, Any], dict2: Dict[str, Any]) -> Dict[str, Any]:
    """Merge two dictionaries, with dict2 values taking precedence.

    Args:
        dict1: Base dictionary.
        dict2: Dictionary with override values.

    Returns:
        New dictionary with merged values.
    """
    merged = dict1.copy()
    merged.update(dict2)
    return merged


def deep_merge_dicts(dict1: Dict[str, Any], dict2: Dict[str, Any]) -> Dict[str, Any]:
    """Deep merge two dictionaries recursively.

    Args:
        dict1: Base dictionary.
        dict2: Dictionary with override values.

    Returns:
        New dictionary with recursively merged values.
    """
    result = dict1.copy()

    for key, value in dict2.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge_dicts(result[key], value)
        else:
            result[key] = value

    return result


def stringify_dict(d: Dict[str, Any]) -> Dict[str, str]:
    """Convert all dictionary values to strings.

    Args:
        d: Dictionary with any value types.

    Returns:
        New dictionary with all values converted to strings.
    """
    return {k: str(v) for k, v in d.items()}


def convert_dict_to_string(d: Any) -> Any:
    """Recursively convert all values in a nested structure to strings.

    Args:
        d: Dictionary, list, or value to convert.

    Returns:
        Structure with all leaf values converted to strings.
    """
    if isinstance(d, dict):
        return {k: convert_dict_to_string(v) for k, v in d.items()}
    elif isinstance(d, list):
        return [convert_dict_to_string(v) for v in d]
    else:
        return str(d)


class ConfigModel:
    """Configuration file manager.

    Handles reading, writing, and accessing TOML configuration files.

    Attributes:
        config_file: Path to the configuration file.
        config: Parsed configuration data.
    """

    def __init__(self, config_file: str) -> None:
        """Initialize ConfigModel with a configuration file.

        Args:
            config_file: Path to the TOML configuration file.
                Can be relative to the models directory or absolute.

        Raises:
            FileError: If the configuration file cannot be found.
            ConfigError: If the file is not valid TOML.
        """
        self.config_file = config_file

        # Try multiple locations for the config file
        # If config_file is absolute, only check that path (don't join with other dirs)
        if os.path.isabs(config_file):
            possible_paths = [config_file]
        else:
            possible_paths = [
                config_file,  # Relative to cwd
                JoinDirFileList(GetCurrentDirectory(), "models", config_file),
                JoinDirFileList(GetPackageDirectory(), "models", config_file),
            ]

        config_path = None
        for path in possible_paths:
            if os.path.isfile(path):
                config_path = path
                break

        if config_path is None:
            raise FileError(
                f"Configuration file not found: {config_file}. "
                f"Searched in: {', '.join(possible_paths)}"
            )

        try:
            self.config = toml.load(config_path)
        except toml.TomlDecodeError as e:
            raise ConfigError(f"Invalid TOML in {config_path}: {e}")

    def get(self, key: str, default: Optional[T] = None) -> Any:
        """Get a configuration value by key.

        Args:
            key: Configuration key to retrieve.
            default: Default value if key is not found.

        Returns:
            Configuration value or default.

        Raises:
            KeyError: If key is not found and no default provided.
        """
        if default is not None:
            return self.config.get(key, default)
        return self.config[key]

    def set(self, key: str, value: Any) -> None:
        """Set a configuration value.

        Args:
            key: Configuration key to set.
            value: Value to assign.
        """
        self.config[key] = value

    def getallvalues(self, key: str) -> List[Any]:
        """Get all values from a configuration section.

        Args:
            key: Configuration section key.

        Returns:
            List of all values in the section.

        Raises:
            KeyError: If the section does not exist.
        """
        return list(self.config[key].values())

    def has(self, key: str) -> bool:
        """Check if a configuration key exists.

        Args:
            key: Configuration key to check.

        Returns:
            True if the key exists, False otherwise.
        """
        return key in self.config

    def keys(self) -> List[str]:
        """Get all top-level configuration keys.

        Returns:
            List of configuration keys.
        """
        return list(self.config.keys())

    def save(self, filepath: Optional[str] = None) -> None:
        """Save the configuration to a file.

        Args:
            filepath: Path to save to. Uses original file if not specified.
        """
        save_path = filepath or self.config_file
        with open(save_path, 'w') as f:
            toml.dump(self.config, f)


# =============================================================================
# Caching Utilities
# =============================================================================

def cached_result(key_func: Optional[Callable] = None):
    """Decorator for caching method results.

    Caches the result of a method call based on its arguments.
    Results are stored per-instance in a cache attribute.

    Args:
        key_func: Optional function to generate cache key from arguments.
                  If None, uses a tuple of (args, kwargs) as the key.

    Returns:
        Decorated method with caching.

    Example:
        >>> class MyClass:
        ...     @cached_result()
        ...     def expensive_computation(self, x, y):
        ...         return x ** y
        ...
        >>> obj = MyClass()
        >>> obj.expensive_computation(2, 10)  # Computed
        >>> obj.expensive_computation(2, 10)  # Cached
        >>> obj.expensive_computation.clear_cache(obj)  # Clear cache
    """
    def decorator(method: Callable) -> Callable:
        cache_attr = f'_cache_{method.__name__}'

        @functools.wraps(method)
        def wrapper(self, *args, **kwargs):
            # Get or create cache
            if not hasattr(self, cache_attr):
                setattr(self, cache_attr, {})
            cache = getattr(self, cache_attr)

            # Generate cache key
            if key_func:
                key = key_func(*args, **kwargs)
            else:
                # Create hashable key from args and kwargs
                try:
                    key = (args, tuple(sorted(kwargs.items())))
                except TypeError:
                    # If args contain unhashable types, use string representation
                    key = (str(args), str(sorted(kwargs.items())))

            # Check cache
            if key not in cache:
                cache[key] = method(self, *args, **kwargs)
                logger.debug(f"Cache miss for {method.__name__}, computed result")
            else:
                logger.debug(f"Cache hit for {method.__name__}")

            return cache[key]

        # Add cache clear method
        def clear_cache(self) -> None:
            """Clear the cache for this method."""
            if hasattr(self, cache_attr):
                getattr(self, cache_attr).clear()
                logger.debug(f"Cleared cache for {method.__name__}")

        wrapper.clear_cache = clear_cache
        return wrapper

    return decorator


def content_hash(content: Union[str, bytes], algorithm: str = 'md5') -> str:
    """Generate hash of content for cache keys.

    Useful for creating cache keys based on file or data content.

    Args:
        content: String or bytes content to hash.
        algorithm: Hash algorithm to use ('md5', 'sha1', 'sha256').

    Returns:
        Hexadecimal hash string.

    Example:
        >>> content_hash("Hello, World!")
        '65a8e27d8879283831b664bd8b7f0ad4'
    """
    if isinstance(content, str):
        content = content.encode('utf-8')

    if algorithm == 'md5':
        return hashlib.md5(content).hexdigest()
    elif algorithm == 'sha1':
        return hashlib.sha1(content).hexdigest()
    elif algorithm == 'sha256':
        return hashlib.sha256(content).hexdigest()
    else:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")


def file_hash(filepath: str, algorithm: str = 'md5', chunk_size: int = 8192) -> str:
    """Generate hash of a file's contents.

    Processes the file in chunks for memory efficiency with large files.

    Args:
        filepath: Path to the file to hash.
        algorithm: Hash algorithm to use ('md5', 'sha1', 'sha256').
        chunk_size: Size of chunks to read.

    Returns:
        Hexadecimal hash string.

    Example:
        >>> file_hash("myfile.txt")
        '65a8e27d8879283831b664bd8b7f0ad4'
    """
    if algorithm == 'md5':
        hasher = hashlib.md5()
    elif algorithm == 'sha1':
        hasher = hashlib.sha1()
    elif algorithm == 'sha256':
        hasher = hashlib.sha256()
    else:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")

    with open(filepath, 'rb') as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            hasher.update(chunk)

    return hasher.hexdigest()


class StyleManager:
    """Manages style loading and caching.

    Provides centralized style management with caching to avoid
    repeated file I/O for commonly used styles.

    Example:
        >>> style = StyleManager.load("config_attacktrees.tml", "at_default")
        >>> StyleManager.clear_cache()  # Clear when styles are updated
    """

    _cache: Dict[str, Dict[str, Any]] = {}

    @classmethod
    def load(cls, style_file: str, style_id: str) -> Dict[str, Any]:
        """Load style configuration with caching.

        Args:
            style_file: Path to the style configuration file.
            style_id: Style identifier within the file.

        Returns:
            Style configuration dictionary.

        Raises:
            KeyError: If style_id is not found in the file.
            FileError: If the style file cannot be read.
        """
        cache_key = f"{style_file}:{style_id}"

        if cache_key not in cls._cache:
            config = ConfigModel(style_file)
            cls._cache[cache_key] = config.get(style_id)
            logger.debug(f"Loaded and cached style: {cache_key}")

        # Return a copy to prevent modification of cached values
        return cls._cache[cache_key].copy()

    @classmethod
    def clear_cache(cls) -> None:
        """Clear the style cache.

        Call this if style files have been modified and need reloading.
        """
        cls._cache.clear()
        logger.debug("Cleared style cache")

    @classmethod
    def get_cached_styles(cls) -> List[str]:
        """Get list of currently cached style keys.

        Returns:
            List of "style_file:style_id" keys currently in cache.
        """
        return list(cls._cache.keys())
