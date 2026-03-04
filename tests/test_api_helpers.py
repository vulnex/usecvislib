#
# VULNEX -Universal Security Visualization Library-
#
# File: test_api_helpers.py
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
#

"""Tests for API helper functions: path validation, sanitization, timeouts.

Covers security-critical helpers in api/helpers.py:
- Path component validation (traversal prevention)
- Path containment checks (CWE-22)
- Symlink rejection (CWE-59)
- UUID format validation
- Filename sanitization (log injection prevention)
- Timeout enforcement (504 responses)
- File upload helpers
- Progress tracking
- CORS validation (api/config.py)
"""

import asyncio
import os
import sys
import tempfile
from io import BytesIO
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# Add the api directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'api'))

os.environ["USECVISLIB_AUTH_ENABLED"] = "false"

from fastapi import HTTPException

from api.helpers import (
    _cleanup_old_progress_entries,
    _progress_store,
    clear_progress,
    cleanup_files,
    get_content_type,
    get_file_extension,
    get_image_content_type,
    get_progress,
    get_template_format,
    get_user_image_dir,
    get_user_namespace,
    is_safe_symlink,
    is_valid_image,
    run_with_timeout,
    run_sync_with_timeout,
    sanitize_filename_for_log,
    update_progress,
    validate_config_file_extension,
    validate_path_component,
    validate_path_within_directory,
    validate_uuid_format,
    with_timeout,
    write_config_file,
)
from api.config import _validate_cors_origin, _parse_allowed_origins
from api.schemas import OutputFormat


# =============================================================================
# validate_path_component
# =============================================================================

class TestValidatePathComponent:
    """Test path component validation for traversal prevention."""

    def test_valid_simple_name(self):
        assert validate_path_component("myfile.txt") is True

    def test_valid_uuid(self):
        assert validate_path_component("550e8400-e29b-41d4-a716-446655440000") is True

    def test_empty_string(self):
        assert validate_path_component("") is False

    def test_dot_dot_traversal(self):
        assert validate_path_component("..") is False

    def test_dot_dot_in_path(self):
        assert validate_path_component("foo/../bar") is False

    def test_leading_slash(self):
        assert validate_path_component("/etc/passwd") is False

    def test_leading_backslash(self):
        assert validate_path_component("\\windows\\system32") is False

    def test_url_encoded_dot(self):
        assert validate_path_component("%2e%2e") is False

    def test_url_encoded_slash(self):
        assert validate_path_component("foo%2fbar") is False

    def test_null_byte(self):
        assert validate_path_component("file\x00.txt") is False

    def test_url_encoded_dot_mixed_case(self):
        assert validate_path_component("%2E%2E") is False


# =============================================================================
# validate_path_within_directory
# =============================================================================

class TestValidatePathWithinDirectory:
    """Test path containment checks (CWE-22)."""

    def test_path_inside_base(self):
        base = Path(tempfile.gettempdir())
        child = base / "subdir" / "file.txt"
        assert validate_path_within_directory(child, base) is True

    def test_path_is_base_itself(self):
        base = Path(tempfile.gettempdir())
        assert validate_path_within_directory(base, base) is True

    def test_path_outside_base(self):
        base = Path(tempfile.gettempdir()) / "sandbox"
        outside = Path("/etc/passwd")
        assert validate_path_within_directory(outside, base) is False

    def test_traversal_attempt(self):
        base = Path(tempfile.gettempdir()) / "sandbox"
        traversal = base / ".." / ".." / "etc" / "passwd"
        assert validate_path_within_directory(traversal, base) is False


# =============================================================================
# is_safe_symlink
# =============================================================================

class TestIsSafeSymlink:
    """Test symlink rejection (CWE-59)."""

    def test_regular_file_is_safe(self):
        with tempfile.NamedTemporaryFile() as f:
            assert is_safe_symlink(Path(f.name)) is True

    def test_symlink_is_not_safe(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "target.txt"
            target.write_text("data")
            link = Path(d) / "link.txt"
            link.symlink_to(target)
            assert is_safe_symlink(link) is False

    def test_nonexistent_path_is_safe(self):
        """Non-existent paths are not symlinks."""
        assert is_safe_symlink(Path("/nonexistent/path")) is True


# =============================================================================
# validate_uuid_format
# =============================================================================

class TestValidateUUIDFormat:
    """Test UUID format validation."""

    def test_valid_uuid(self):
        assert validate_uuid_format("550e8400-e29b-41d4-a716-446655440000") is True

    def test_valid_uuid_uppercase(self):
        assert validate_uuid_format("550E8400-E29B-41D4-A716-446655440000") is True

    def test_invalid_too_short(self):
        assert validate_uuid_format("550e8400") is False

    def test_invalid_no_dashes(self):
        assert validate_uuid_format("550e8400e29b41d4a716446655440000") is False

    def test_path_traversal_attempt(self):
        assert validate_uuid_format("../../etc/passwd") is False

    def test_empty_string(self):
        assert validate_uuid_format("") is False

    def test_null_bytes(self):
        assert validate_uuid_format("550e8400-e29b-41d4-a716-4466554400\x00") is False


# =============================================================================
# sanitize_filename_for_log
# =============================================================================

class TestSanitizeFilenameForLog:
    """Test filename sanitization for log injection prevention."""

    def test_normal_filename(self):
        assert sanitize_filename_for_log("config.toml") == "config.toml"

    def test_empty_filename(self):
        assert sanitize_filename_for_log("") == "<empty>"

    def test_none_like_empty(self):
        assert sanitize_filename_for_log("") == "<empty>"

    def test_truncates_long_names(self):
        long_name = "a" * 200
        result = sanitize_filename_for_log(long_name)
        assert len(result) <= 100
        assert result.endswith("...")

    def test_strips_newlines(self):
        """Newlines in filenames could inject fake log entries."""
        result = sanitize_filename_for_log("file\nINFO: fake log entry")
        assert "\n" not in result

    def test_strips_carriage_returns(self):
        result = sanitize_filename_for_log("file\r\nfake")
        assert "\r" not in result
        assert "\n" not in result

    def test_strips_tabs(self):
        result = sanitize_filename_for_log("file\tfake")
        assert "\t" not in result

    def test_escapes_percent(self):
        """Percent signs could interfere with log format strings."""
        result = sanitize_filename_for_log("file%s.txt")
        assert "%%" in result

    def test_strips_control_characters(self):
        result = sanitize_filename_for_log("file\x01\x02\x03.txt")
        assert "\x01" not in result


# =============================================================================
# Timeout Helpers
# =============================================================================

class TestRunWithTimeout:
    """Test async timeout enforcement."""

    @pytest.mark.asyncio
    async def test_completes_within_timeout(self):
        async def quick():
            return 42
        result = await run_with_timeout(quick(), timeout_seconds=5, operation_name="test")
        assert result == 42

    @pytest.mark.asyncio
    async def test_raises_504_on_timeout(self):
        async def slow():
            await asyncio.sleep(10)
        with pytest.raises(HTTPException) as exc_info:
            await run_with_timeout(slow(), timeout_seconds=0.1, operation_name="slow op")
        assert exc_info.value.status_code == 504
        assert "slow op" in exc_info.value.detail


class TestRunSyncWithTimeout:
    """Test sync-in-thread timeout enforcement."""

    @pytest.mark.asyncio
    async def test_completes_within_timeout(self):
        def quick():
            return 99
        result = await run_sync_with_timeout(quick, timeout_seconds=5, operation_name="test")
        assert result == 99

    @pytest.mark.asyncio
    async def test_raises_504_on_timeout(self):
        import time
        def slow():
            time.sleep(10)
        with pytest.raises(HTTPException) as exc_info:
            await run_sync_with_timeout(slow, timeout_seconds=0.1, operation_name="slow sync")
        assert exc_info.value.status_code == 504


class TestWithTimeoutDecorator:
    """Test the @with_timeout decorator."""

    @pytest.mark.asyncio
    async def test_decorator_passes_through(self):
        @with_timeout(5, "decorated")
        async def task():
            return "ok"
        assert await task() == "ok"

    @pytest.mark.asyncio
    async def test_decorator_raises_504(self):
        @with_timeout(0.1, "slow decorated")
        async def task():
            await asyncio.sleep(10)
        with pytest.raises(HTTPException) as exc_info:
            await task()
        assert exc_info.value.status_code == 504


# =============================================================================
# File Helpers
# =============================================================================

class TestGetFileExtension:
    """Test file extension extraction."""

    def test_toml_extension(self):
        assert get_file_extension("config.toml") == ".toml"

    def test_json_extension(self):
        assert get_file_extension("config.json") == ".json"

    def test_empty_returns_default(self):
        assert get_file_extension("") == ".tml"

    def test_none_like_empty(self):
        assert get_file_extension("") == ".tml"

    def test_no_extension(self):
        assert get_file_extension("Makefile") == ".tml"

    def test_uppercase_normalized(self):
        assert get_file_extension("CONFIG.JSON") == ".json"


class TestValidateConfigFileExtension:
    """Test config file extension validation."""

    def test_valid_toml(self):
        validate_config_file_extension("config.toml")  # Should not raise

    def test_valid_json(self):
        validate_config_file_extension("config.json")

    def test_valid_yaml(self):
        validate_config_file_extension("config.yaml")

    def test_valid_yml(self):
        validate_config_file_extension("config.yml")

    def test_valid_tml(self):
        validate_config_file_extension("config.tml")

    def test_invalid_extension_raises(self):
        with pytest.raises(HTTPException) as exc_info:
            validate_config_file_extension("config.exe")
        assert exc_info.value.status_code == 400

    def test_invalid_txt_raises(self):
        with pytest.raises(HTTPException):
            validate_config_file_extension("readme.txt")


class TestWriteConfigFile:
    """Test config file writing in different formats."""

    def test_write_json(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            write_config_file(path, {"key": "value"}, ".json")
            import json
            with open(path) as fh:
                data = json.load(fh)
            assert data["key"] == "value"
        finally:
            os.unlink(path)

    def test_write_yaml(self):
        with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as f:
            path = f.name
        try:
            write_config_file(path, {"key": "value"}, ".yaml")
            import yaml
            with open(path) as fh:
                data = yaml.safe_load(fh)
            assert data["key"] == "value"
        finally:
            os.unlink(path)

    def test_write_toml(self):
        with tempfile.NamedTemporaryFile(suffix=".toml", delete=False) as f:
            path = f.name
        try:
            write_config_file(path, {"key": "value"}, ".toml")
            import toml
            with open(path) as fh:
                data = toml.load(fh)
            assert data["key"] == "value"
        finally:
            os.unlink(path)


class TestGetContentType:
    """Test output format to MIME type mapping."""

    def test_png(self):
        assert get_content_type(OutputFormat.PNG) == "image/png"

    def test_pdf(self):
        assert get_content_type(OutputFormat.PDF) == "application/pdf"

    def test_svg(self):
        assert get_content_type(OutputFormat.SVG) == "image/svg+xml"


class TestCleanupFiles:
    """Test temporary file cleanup."""

    def test_removes_existing_file(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            path = f.name
        cleanup_files(path)
        assert not os.path.exists(path)

    def test_handles_nonexistent_file(self):
        cleanup_files("/nonexistent/file.tmp")  # Should not raise

    def test_handles_none(self):
        cleanup_files(None)  # Should not raise


# =============================================================================
# Progress Tracking
# =============================================================================

class TestProgressTracking:
    """Test in-memory progress tracking."""

    def setup_method(self):
        _progress_store.clear()

    def test_update_and_get(self):
        update_progress("job-1", "Processing", 50, 100)
        p = get_progress("job-1")
        assert p is not None
        assert p["progress"] == 50
        assert p["percentage"] == 50.0
        assert p["status"] == "running"

    def test_get_nonexistent(self):
        assert get_progress("nonexistent") is None

    def test_clear_progress(self):
        update_progress("job-2", "Done", 100, 100, "completed")
        clear_progress("job-2")
        assert get_progress("job-2") is None

    def test_percentage_calculation(self):
        update_progress("job-3", "Step", 25, 200)
        p = get_progress("job-3")
        assert p["percentage"] == 12.5

    def test_zero_total_no_divide_by_zero(self):
        update_progress("job-4", "Step", 0, 0)
        p = get_progress("job-4")
        assert p["percentage"] == 0

    def test_field_truncation(self):
        """Long strings are truncated to prevent memory abuse."""
        long_step = "x" * 1000
        update_progress("job-5", long_step, 50)
        p = get_progress("job-5")
        assert len(p["step"]) <= 500

    def test_cleanup_old_entries(self):
        """Expired entries are removed during cleanup."""
        import time
        _progress_store["old-job"] = {
            "job_id": "old-job",
            "step": "old",
            "progress": 0,
            "total": 100,
            "percentage": 0,
            "status": "running",
            "timestamp": time.time() - 99999  # Very old
        }
        removed = _cleanup_old_progress_entries()
        assert removed == 1
        assert get_progress("old-job") is None


# =============================================================================
# User Namespace / Image Isolation
# =============================================================================

class TestUserNamespace:
    """Test per-user image directory isolation."""

    def test_no_key_returns_shared(self):
        assert get_user_namespace(None) == "shared"

    def test_empty_key_returns_shared(self):
        assert get_user_namespace("") == "shared"

    def test_key_returns_hash(self):
        ns = get_user_namespace("my-api-key")
        assert len(ns) == 12
        assert ns.isalnum()

    def test_different_keys_different_namespaces(self):
        ns1 = get_user_namespace("key-1")
        ns2 = get_user_namespace("key-2")
        assert ns1 != ns2

    def test_same_key_same_namespace(self):
        ns1 = get_user_namespace("consistent-key")
        ns2 = get_user_namespace("consistent-key")
        assert ns1 == ns2


class TestGetUserImageDir:
    """Test user-specific image directory path generation."""

    def test_shared_user(self):
        path = get_user_image_dir(None)
        assert path.endswith(os.sep + "shared") or path.endswith("/shared")

    def test_authenticated_user(self):
        path = get_user_image_dir("my-key")
        ns = get_user_namespace("my-key")
        assert ns in path


# =============================================================================
# Image Validation
# =============================================================================

class TestIsValidImage:
    """Test image content validation via magic bytes."""

    def test_valid_png(self):
        png_header = b'\x89PNG\r\n\x1a\n' + b'\x00' * 100
        assert is_valid_image(png_header, "image/png") is True

    def test_valid_jpeg(self):
        jpeg_header = b'\xff\xd8\xff' + b'\x00' * 100
        assert is_valid_image(jpeg_header, "image/jpeg") is True

    def test_valid_gif87(self):
        gif_header = b'GIF87a' + b'\x00' * 100
        assert is_valid_image(gif_header, "image/gif") is True

    def test_valid_gif89(self):
        gif_header = b'GIF89a' + b'\x00' * 100
        assert is_valid_image(gif_header, "image/gif") is True

    def test_valid_bmp(self):
        bmp_header = b'BM' + b'\x00' * 100
        assert is_valid_image(bmp_header, "image/bmp") is True

    def test_invalid_random_bytes(self):
        assert is_valid_image(b'\x00\x01\x02\x03', "image/png") is False

    def test_svg_valid(self):
        svg = b'<svg xmlns="http://www.w3.org/2000/svg"><rect/></svg>'
        assert is_valid_image(svg, "image/svg+xml") is True

    def test_svg_with_xml_declaration(self):
        svg = b'<?xml version="1.0"?><svg><rect/></svg>'
        assert is_valid_image(svg, "image/svg+xml") is True

    def test_svg_rejects_xxe_doctype(self):
        """SVGs with DOCTYPE are rejected to prevent XXE."""
        svg = b'<!DOCTYPE svg SYSTEM "evil.dtd"><svg></svg>'
        assert is_valid_image(svg, "image/svg+xml") is False

    def test_svg_rejects_entity_declaration(self):
        """SVGs with ENTITY declarations are rejected to prevent XXE."""
        svg = b'<?xml version="1.0"?><!ENTITY xxe SYSTEM "file:///etc/passwd"><svg></svg>'
        assert is_valid_image(svg, "image/svg+xml") is False


# =============================================================================
# Template Format Detection
# =============================================================================

class TestGetTemplateFormat:
    """Test template format detection from filename."""

    def test_toml(self):
        assert get_template_format("config.toml") == "toml"

    def test_tml(self):
        assert get_template_format("config.tml") == "toml"

    def test_json(self):
        assert get_template_format("config.json") == "json"

    def test_yaml(self):
        assert get_template_format("config.yaml") == "yaml"

    def test_yml(self):
        assert get_template_format("config.yml") == "yaml"

    def test_unknown_defaults_to_toml(self):
        assert get_template_format("config.xyz") == "toml"


# =============================================================================
# CORS Validation (api/config.py)
# =============================================================================

class TestValidateCorsOrigin:
    """Test CORS origin validation."""

    def test_valid_http_origin(self):
        assert _validate_cors_origin("http://localhost:3000") == "http://localhost:3000"

    def test_valid_https_origin(self):
        assert _validate_cors_origin("https://example.com") == "https://example.com"

    def test_strips_whitespace(self):
        assert _validate_cors_origin("  http://localhost:3000  ") == "http://localhost:3000"

    def test_rejects_wildcard(self):
        with pytest.raises(ValueError, match="Wildcard"):
            _validate_cors_origin("*")

    def test_rejects_domain_wildcard(self):
        with pytest.raises(ValueError, match="Wildcards"):
            _validate_cors_origin("http://*.example.com")

    def test_rejects_no_scheme(self):
        with pytest.raises(ValueError, match="http"):
            _validate_cors_origin("localhost:3000")

    def test_rejects_ftp_scheme(self):
        with pytest.raises(ValueError, match="http"):
            _validate_cors_origin("ftp://example.com")

    def test_rejects_empty(self):
        with pytest.raises(ValueError, match="Empty"):
            _validate_cors_origin("")

    def test_rejects_whitespace_only(self):
        with pytest.raises(ValueError, match="Empty"):
            _validate_cors_origin("   ")


class TestParseAllowedOrigins:
    """Test CORS origin list parsing from environment."""

    def test_default_origins(self):
        """Without env var, defaults include localhost origins."""
        from unittest.mock import patch
        with patch.dict(os.environ, {}, clear=False):
            # Remove ALLOWED_ORIGINS if set
            os.environ.pop("ALLOWED_ORIGINS", None)
            origins = _parse_allowed_origins()
            assert any("localhost" in o for o in origins)

    def test_custom_origins(self):
        from unittest.mock import patch
        with patch.dict(os.environ, {"ALLOWED_ORIGINS": "https://app.example.com,https://admin.example.com"}):
            origins = _parse_allowed_origins()
            assert "https://app.example.com" in origins
            assert "https://admin.example.com" in origins

    def test_invalid_origins_skipped(self):
        """Invalid origins are silently skipped."""
        from unittest.mock import patch
        with patch.dict(os.environ, {"ALLOWED_ORIGINS": "https://valid.com,not-a-url,https://also-valid.com"}):
            origins = _parse_allowed_origins()
            assert "https://valid.com" in origins
            assert "https://also-valid.com" in origins
            assert "not-a-url" not in origins

    def test_all_invalid_falls_back(self):
        """If all origins are invalid, falls back to safe defaults."""
        from unittest.mock import patch
        with patch.dict(os.environ, {"ALLOWED_ORIGINS": "ftp://bad,*,no-scheme"}):
            origins = _parse_allowed_origins()
            assert len(origins) > 0
            assert any("localhost" in o for o in origins)
