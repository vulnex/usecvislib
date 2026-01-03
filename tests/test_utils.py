#
# VULNEX -Universal Security Visualization Library-
#
# File: test_utils.py
# Author: Simon Roses Femerling
# Created: 2025-01-01
# Last Modified: 2025-12-25
# Version: 0.3.1
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Unit tests for utils module."""

import os
import sys
import tempfile
import logging
import pytest

# Add src to path for testing
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from usecvislib import utils


# =============================================================================
# Security Tests - Exception Hierarchy
# =============================================================================

class TestExceptionHierarchy:
    """Tests for custom exception hierarchy."""

    def test_usecvisliberror_is_base(self):
        """Test that USecVisLibError is the base exception."""
        assert issubclass(utils.ConfigError, utils.USecVisLibError)
        assert issubclass(utils.FileError, utils.USecVisLibError)
        assert issubclass(utils.SecurityError, utils.USecVisLibError)
        assert issubclass(utils.ValidationError, utils.USecVisLibError)
        assert issubclass(utils.RenderError, utils.USecVisLibError)
        assert issubclass(utils.AnalysisError, utils.USecVisLibError)

    def test_exception_with_context(self):
        """Test exception formatting with context."""
        exc = utils.SecurityError("Path traversal detected", path="/etc/passwd", attempt=1)
        message = str(exc)
        assert "Path traversal detected" in message
        assert "path=/etc/passwd" in message
        assert "attempt=1" in message

    def test_exception_without_context(self):
        """Test exception formatting without context."""
        exc = utils.SecurityError("Simple error")
        message = str(exc)
        assert message == "Simple error"

    def test_exception_attributes(self):
        """Test exception attributes are accessible."""
        exc = utils.SecurityError("Test", key="value")
        assert exc.message == "Test"
        assert exc.context == {"key": "value"}


# =============================================================================
# Security Tests - Path Validation
# =============================================================================

class TestValidateInputPath:
    """Tests for input path validation."""

    def test_valid_file_path(self):
        """Test validating a valid file path."""
        with tempfile.NamedTemporaryFile(suffix='.toml', delete=False) as f:
            f.write(b'test = "data"')
            f.flush()
            try:
                result = utils.validate_input_path(f.name)
                assert str(result) == os.path.realpath(f.name)
            finally:
                os.unlink(f.name)

    def test_empty_path_raises_error(self):
        """Test that empty path raises SecurityError."""
        with pytest.raises(utils.SecurityError, match="Empty path"):
            utils.validate_input_path("")

    def test_null_byte_in_path(self):
        """Test that null byte in path raises SecurityError."""
        with pytest.raises(utils.SecurityError, match="Null byte"):
            utils.validate_input_path("/path/to\x00/file.txt")

    def test_nonexistent_file(self):
        """Test that nonexistent file raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            utils.validate_input_path("/nonexistent/path/file.toml")

    def test_directory_not_file(self):
        """Test that directory path raises FileError."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with pytest.raises(utils.FileError, match="not a file"):
                utils.validate_input_path(tmpdir)

    def test_extension_validation(self):
        """Test that extension validation works."""
        with tempfile.NamedTemporaryFile(suffix='.txt', delete=False) as f:
            f.write(b'test')
            f.flush()
            try:
                with pytest.raises(utils.SecurityError, match="extension"):
                    utils.validate_input_path(f.name, allowed_extensions=['.toml', '.json'])
            finally:
                os.unlink(f.name)

    def test_extension_validation_passes(self):
        """Test that allowed extension passes validation."""
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
            f.write(b'{}')
            f.flush()
            try:
                result = utils.validate_input_path(f.name, allowed_extensions=['.toml', '.json'])
                assert result.suffix == '.json'
            finally:
                os.unlink(f.name)

    def test_max_file_size(self):
        """Test that file size validation works."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b'x' * 1000)  # 1000 bytes
            f.flush()
            try:
                with pytest.raises(utils.SecurityError, match="exceeds maximum"):
                    utils.validate_input_path(f.name, max_size_bytes=500)
            finally:
                os.unlink(f.name)

    def test_max_file_size_passes(self):
        """Test that file within size limit passes."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b'small')
            f.flush()
            try:
                result = utils.validate_input_path(f.name, max_size_bytes=1000)
                assert result.exists()
            finally:
                os.unlink(f.name)


class TestValidateOutputPath:
    """Tests for output path validation."""

    def test_valid_output_path(self):
        """Test validating a valid output path."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = os.path.join(tmpdir, 'output.png')
            result = utils.validate_output_path(output_path)
            assert str(result) == os.path.realpath(output_path)

    def test_empty_path_raises_error(self):
        """Test that empty path raises SecurityError."""
        with pytest.raises(utils.SecurityError, match="Empty"):
            utils.validate_output_path("")

    def test_null_byte_in_path(self):
        """Test that null byte in path raises SecurityError."""
        with pytest.raises(utils.SecurityError, match="Null byte"):
            utils.validate_output_path("/path/to\x00/output.png")

    def test_sensitive_path_blocked(self):
        """Test that sensitive system paths are blocked."""
        # Note: On macOS, /etc resolves to /private/etc, so we test with /private/etc
        # or skip if sensitive paths don't exist on this system
        import platform
        if platform.system() == "Darwin":
            # macOS uses /private prefix
            pytest.skip("Sensitive paths on macOS use /private prefix")
        else:
            with pytest.raises(utils.SecurityError, match="sensitive"):
                utils.validate_output_path("/etc/output.png")

    def test_sensitive_paths_list(self):
        """Test that all sensitive paths are blocked."""
        import platform
        if platform.system() == "Darwin":
            # macOS uses /private prefix for system paths
            pytest.skip("Sensitive paths on macOS use /private prefix")
        else:
            for sensitive in utils.SENSITIVE_PATHS:
                with pytest.raises(utils.SecurityError, match="sensitive"):
                    utils.validate_output_path(f"{sensitive}/output.png")

    def test_allowed_directory_enforcement(self):
        """Test that allowed_directory constraint is enforced."""
        with tempfile.TemporaryDirectory() as allowed_dir:
            # Path outside allowed directory should fail
            with pytest.raises(utils.SecurityError, match="must be within"):
                utils.validate_output_path("/tmp/other/output.png", allowed_directory=allowed_dir)

    def test_allowed_directory_passes(self):
        """Test that path within allowed directory passes."""
        with tempfile.TemporaryDirectory() as allowed_dir:
            output_path = os.path.join(allowed_dir, 'output.png')
            result = utils.validate_output_path(output_path, allowed_directory=allowed_dir)
            assert str(result).startswith(os.path.realpath(allowed_dir))

    def test_parent_directory_creation(self):
        """Test that parent directories are created."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = os.path.join(tmpdir, 'subdir', 'deep', 'output.png')
            result = utils.validate_output_path(output_path, create_parents=True)
            assert os.path.isdir(os.path.dirname(output_path))


# =============================================================================
# Security Tests - DOT Injection Prevention
# =============================================================================

class TestEscapeDotLabel:
    """Tests for DOT label escaping."""

    def test_escape_basic_string(self):
        """Test escaping a basic string."""
        result = utils.escape_dot_label("Hello World")
        assert result == "Hello World"

    def test_escape_quotes(self):
        """Test escaping double quotes."""
        result = utils.escape_dot_label('Hello "World"')
        assert result == 'Hello \\"World\\"'

    def test_escape_backslashes(self):
        """Test escaping backslashes."""
        result = utils.escape_dot_label('path\\to\\file')
        assert result == 'path\\\\to\\\\file'

    def test_escape_newlines(self):
        """Test escaping newlines."""
        result = utils.escape_dot_label("line1\nline2")
        assert result == "line1\\nline2"

    def test_escape_tabs(self):
        """Test escaping tabs."""
        result = utils.escape_dot_label("col1\tcol2")
        assert result == "col1\\tcol2"

    def test_escape_html_like_chars(self):
        """Test escaping HTML-like characters."""
        result = utils.escape_dot_label("<script>alert('xss')</script>")
        # Characters are escaped, not removed
        assert "\\<" in result
        assert "\\>" in result
        # Make sure the raw unescaped characters are not at start of string
        assert not result.startswith("<")

    def test_escape_dot_special_chars(self):
        """Test escaping DOT special characters."""
        result = utils.escape_dot_label("{node|label}")
        assert "{" not in result or "\\{" in result
        assert "|" not in result or "\\|" in result
        assert "}" not in result or "\\}" in result

    def test_escape_null_bytes(self):
        """Test that null bytes are removed."""
        result = utils.escape_dot_label("hello\x00world")
        assert "\x00" not in result
        assert "helloworld" == result

    def test_escape_control_characters(self):
        """Test that control characters are removed."""
        result = utils.escape_dot_label("hello\x07world\x1f")
        assert "\x07" not in result
        assert "\x1f" not in result

    def test_truncate_long_string(self):
        """Test that long strings are truncated."""
        long_string = "x" * 2000
        result = utils.escape_dot_label(long_string, max_length=100)
        assert len(result) == 100
        assert result.endswith("...")

    def test_escape_none(self):
        """Test escaping None returns empty string."""
        result = utils.escape_dot_label(None)
        assert result == ""

    def test_escape_non_string(self):
        """Test escaping non-string values."""
        result = utils.escape_dot_label(12345)
        assert result == "12345"


class TestSanitizeNodeId:
    """Tests for node ID sanitization."""

    def test_sanitize_alphanumeric(self):
        """Test that alphanumeric strings pass through."""
        assert utils.sanitize_node_id("node123") == "node123"

    def test_sanitize_with_underscore(self):
        """Test that underscores are allowed."""
        assert utils.sanitize_node_id("node_name") == "node_name"

    def test_sanitize_with_hyphen(self):
        """Test that hyphens are allowed."""
        assert utils.sanitize_node_id("node-name") == "node-name"

    def test_sanitize_special_chars(self):
        """Test that special characters are replaced."""
        result = utils.sanitize_node_id("node.name@test!")
        assert "." not in result
        assert "@" not in result
        assert "!" not in result
        assert "_" in result  # Replaced with underscore

    def test_sanitize_numeric_start(self):
        """Test that IDs starting with numbers get prefix."""
        result = utils.sanitize_node_id("123node")
        assert result.startswith("n_")
        assert "123node" in result

    def test_sanitize_empty_string(self):
        """Test that empty string returns 'unnamed'."""
        assert utils.sanitize_node_id("") == "unnamed"

    def test_sanitize_none(self):
        """Test that None returns 'unnamed'."""
        assert utils.sanitize_node_id(None) == "unnamed"

    def test_sanitize_special_only(self):
        """Test that string of only special chars returns 'unnamed'."""
        result = utils.sanitize_node_id("@#$%")
        # All chars replaced with underscore, which is valid
        assert all(c in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for c in result)

    def test_sanitize_sql_injection_attempt(self):
        """Test that SQL injection attempts are sanitized."""
        result = utils.sanitize_node_id("'; DROP TABLE users; --")
        assert "'" not in result
        assert ";" not in result
        assert "-" in result  # Hyphens are allowed


# =============================================================================
# Security Tests - Logging Configuration
# =============================================================================

class TestLoggingConfiguration:
    """Tests for logging configuration."""

    def test_configure_logging(self):
        """Test that logging can be configured."""
        # Should not raise
        utils.configure_logging(level=logging.DEBUG)

    def test_get_logger(self):
        """Test getting a logger."""
        logger = utils.get_logger("test_module")
        assert isinstance(logger, logging.Logger)
        assert logger.name == "test_module"

    def test_get_logger_is_same_instance(self):
        """Test that getting the same logger returns same instance."""
        logger1 = utils.get_logger("test_same")
        logger2 = utils.get_logger("test_same")
        assert logger1 is logger2


class TestDictFunctions:
    """Tests for dictionary utility functions."""

    def test_merge_dicts_basic(self):
        """Test basic dictionary merge."""
        dict1 = {"a": 1, "b": 2}
        dict2 = {"b": 3, "c": 4}
        result = utils.merge_dicts(dict1, dict2)
        assert result == {"a": 1, "b": 3, "c": 4}

    def test_merge_dicts_empty(self):
        """Test merge with empty dictionaries."""
        assert utils.merge_dicts({}, {"a": 1}) == {"a": 1}
        assert utils.merge_dicts({"a": 1}, {}) == {"a": 1}
        assert utils.merge_dicts({}, {}) == {}

    def test_merge_dicts_no_mutation(self):
        """Test that merge doesn't mutate original dicts."""
        dict1 = {"a": 1}
        dict2 = {"b": 2}
        utils.merge_dicts(dict1, dict2)
        assert dict1 == {"a": 1}
        assert dict2 == {"b": 2}

    def test_stringify_dict(self):
        """Test dictionary value stringification."""
        d = {"a": 1, "b": True, "c": 3.14}
        result = utils.stringify_dict(d)
        assert result == {"a": "1", "b": "True", "c": "3.14"}

    def test_stringify_dict_empty(self):
        """Test stringify with empty dict."""
        assert utils.stringify_dict({}) == {}

    def test_deep_merge_dicts(self):
        """Test deep recursive dictionary merge."""
        dict1 = {"a": {"x": 1, "y": 2}, "b": 3}
        dict2 = {"a": {"y": 5, "z": 6}, "c": 7}
        result = utils.deep_merge_dicts(dict1, dict2)
        assert result == {"a": {"x": 1, "y": 5, "z": 6}, "b": 3, "c": 7}

    def test_convert_dict_to_string_nested(self):
        """Test recursive string conversion."""
        d = {"a": {"b": 1}, "c": [1, 2, 3]}
        result = utils.convert_dict_to_string(d)
        assert result == {"a": {"b": "1"}, "c": ["1", "2", "3"]}


class TestPathFunctions:
    """Tests for path utility functions."""

    def test_get_current_directory(self):
        """Test getting current directory."""
        result = utils.GetCurrentDirectory()
        assert os.path.isabs(result)
        assert os.path.isdir(result)

    def test_get_package_directory(self):
        """Test getting package directory."""
        result = utils.GetPackageDirectory()
        assert os.path.isabs(result)
        assert os.path.isdir(result)

    def test_join_dir_file(self):
        """Test path joining."""
        result = utils.JoinDirFile("/foo", "bar.txt")
        assert result == os.path.join("/foo", "bar.txt")

    def test_join_dir_file_list(self):
        """Test multi-component path joining."""
        result = utils.JoinDirFileList("/foo", "bar", "baz.txt")
        assert result == os.path.join("/foo", "bar", "baz.txt")


class TestReadTomlFile:
    """Tests for TOML file reading."""

    def test_read_valid_toml(self):
        """Test reading a valid TOML file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write('[section]\nkey = "value"\n')
            f.flush()
            try:
                result = utils.ReadTomlFile(f.name)
                assert result == {"section": {"key": "value"}}
            finally:
                os.unlink(f.name)

    def test_read_missing_file(self):
        """Test reading a non-existent file."""
        with pytest.raises(utils.FileError):
            utils.ReadTomlFile("/nonexistent/file.tml")

    def test_read_invalid_toml(self):
        """Test reading an invalid TOML file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write('invalid toml content [[[')
            f.flush()
            try:
                with pytest.raises(utils.ConfigError):
                    utils.ReadTomlFile(f.name)
            finally:
                os.unlink(f.name)


# Test data constants for multi-format testing
VALID_TOML_CONTENT = '''[tree]
name = "Test Attack Tree"
root = "goal"

[nodes.goal]
label = "Main Goal"

[edges]
goal = [{to = "step1"}]
'''

VALID_JSON_CONTENT = '''{
  "tree": {
    "name": "Test Attack Tree",
    "root": "goal"
  },
  "nodes": {
    "goal": {"label": "Main Goal"}
  },
  "edges": {
    "goal": [{"to": "step1"}]
  }
}'''

VALID_YAML_CONTENT = '''tree:
  name: Test Attack Tree
  root: goal

nodes:
  goal:
    label: Main Goal

edges:
  goal:
    - to: step1
'''


class TestDetectFormat:
    """Tests for format detection from file extension."""

    def test_detect_toml_extension(self):
        """Test detecting TOML format from .toml extension."""
        assert utils.detect_format("config.toml") == "toml"

    def test_detect_tml_extension(self):
        """Test detecting TOML format from .tml extension."""
        assert utils.detect_format("config.tml") == "toml"

    def test_detect_json_extension(self):
        """Test detecting JSON format from .json extension."""
        assert utils.detect_format("config.json") == "json"

    def test_detect_yaml_extension(self):
        """Test detecting YAML format from .yaml extension."""
        assert utils.detect_format("config.yaml") == "yaml"

    def test_detect_yml_extension(self):
        """Test detecting YAML format from .yml extension."""
        assert utils.detect_format("config.yml") == "yaml"

    def test_detect_unsupported_extension(self):
        """Test that unsupported extensions raise ConfigError."""
        with pytest.raises(utils.ConfigError, match="Unsupported file extension"):
            utils.detect_format("config.xml")

    def test_detect_case_insensitive(self):
        """Test that extension detection is case-insensitive."""
        assert utils.detect_format("config.JSON") == "json"
        assert utils.detect_format("config.YAML") == "yaml"


class TestDetectFormatFromContent:
    """Tests for format detection from content."""

    def test_detect_json_content(self):
        """Test detecting JSON format from content."""
        assert utils.detect_format_from_content(VALID_JSON_CONTENT) == "json"

    def test_detect_yaml_content(self):
        """Test detecting YAML format from content."""
        # Pure YAML without JSON-like structure
        yaml_content = "key: value\nlist:\n  - item1\n  - item2"
        assert utils.detect_format_from_content(yaml_content) == "yaml"

    def test_detect_toml_content(self):
        """Test detecting TOML format from content."""
        assert utils.detect_format_from_content(VALID_TOML_CONTENT) == "toml"

    def test_detect_invalid_content(self):
        """Test that truly unparseable content raises ConfigError."""
        # Use content with invalid syntax for all formats
        # Tabs at start of line break YAML, unclosed brackets break JSON, invalid chars break TOML
        with pytest.raises(utils.ConfigError, match="Unable to detect"):
            utils.detect_format_from_content("\t\t{{{[[[invalid:::")


class TestParseJson:
    """Tests for JSON parsing."""

    def test_parse_valid_json(self):
        """Test parsing valid JSON content."""
        result = utils.parse_json(VALID_JSON_CONTENT)
        assert result["tree"]["name"] == "Test Attack Tree"
        assert result["tree"]["root"] == "goal"
        assert "nodes" in result
        assert "edges" in result

    def test_parse_invalid_json(self):
        """Test that invalid JSON raises ConfigError."""
        with pytest.raises(utils.ConfigError, match="Invalid JSON"):
            utils.parse_json("{invalid json}")

    def test_parse_empty_json(self):
        """Test parsing empty JSON object."""
        result = utils.parse_json("{}")
        assert result == {}


class TestParseYaml:
    """Tests for YAML parsing."""

    def test_parse_valid_yaml(self):
        """Test parsing valid YAML content."""
        result = utils.parse_yaml(VALID_YAML_CONTENT)
        assert result["tree"]["name"] == "Test Attack Tree"
        assert result["tree"]["root"] == "goal"
        assert "nodes" in result
        assert "edges" in result

    def test_parse_invalid_yaml(self):
        """Test that invalid YAML raises ConfigError."""
        # Use truly invalid YAML with duplicate keys at same level or bad structure
        with pytest.raises(utils.ConfigError, match="Invalid YAML"):
            utils.parse_yaml("key: value\n\tkey: value2")  # Tab character breaks YAML

    def test_parse_empty_yaml(self):
        """Test parsing empty YAML returns empty dict."""
        result = utils.parse_yaml("")
        assert result == {}

    def test_parse_non_dict_yaml(self):
        """Test that non-dict YAML raises ConfigError."""
        with pytest.raises(utils.ConfigError, match="must be a mapping"):
            utils.parse_yaml("- item1\n- item2")


class TestReadConfigFile:
    """Tests for multi-format config file reading."""

    def test_read_toml_file(self):
        """Test reading a TOML config file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.toml', delete=False) as f:
            f.write(VALID_TOML_CONTENT)
            f.flush()
            try:
                result = utils.ReadConfigFile(f.name)
                assert result["tree"]["name"] == "Test Attack Tree"
            finally:
                os.unlink(f.name)

    def test_read_json_file(self):
        """Test reading a JSON config file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write(VALID_JSON_CONTENT)
            f.flush()
            try:
                result = utils.ReadConfigFile(f.name)
                assert result["tree"]["name"] == "Test Attack Tree"
            finally:
                os.unlink(f.name)

    def test_read_yaml_file(self):
        """Test reading a YAML config file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(VALID_YAML_CONTENT)
            f.flush()
            try:
                result = utils.ReadConfigFile(f.name)
                assert result["tree"]["name"] == "Test Attack Tree"
            finally:
                os.unlink(f.name)

    def test_read_yml_file(self):
        """Test reading a .yml config file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            f.write(VALID_YAML_CONTENT)
            f.flush()
            try:
                result = utils.ReadConfigFile(f.name)
                assert result["tree"]["name"] == "Test Attack Tree"
            finally:
                os.unlink(f.name)

    def test_read_missing_file(self):
        """Test reading a non-existent file."""
        with pytest.raises(utils.FileError, match="not found"):
            utils.ReadConfigFile("/nonexistent/file.json")

    def test_read_with_format_override(self):
        """Test reading with explicit format override."""
        # Write JSON content but save with .txt extension
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write(VALID_JSON_CONTENT)
            f.flush()
            try:
                # Should fail without override (unsupported extension)
                with pytest.raises(utils.ConfigError):
                    utils.ReadConfigFile(f.name)
                # Should work with format override
                result = utils.ReadConfigFile(f.name, format="json")
                assert result["tree"]["name"] == "Test Attack Tree"
            finally:
                os.unlink(f.name)


class TestSerializeFunctions:
    """Tests for serialization functions."""

    def test_serialize_to_toml(self):
        """Test serializing dict to TOML."""
        data = {"section": {"key": "value"}}
        result = utils.serialize_to_toml(data)
        assert "[section]" in result
        assert 'key = "value"' in result

    def test_serialize_to_json(self):
        """Test serializing dict to JSON."""
        data = {"key": "value", "number": 42}
        result = utils.serialize_to_json(data)
        assert '"key": "value"' in result
        assert '"number": 42' in result

    def test_serialize_to_json_pretty(self):
        """Test that JSON serialization is pretty by default."""
        data = {"key": "value"}
        result = utils.serialize_to_json(data)
        assert "\n" in result  # Pretty format has newlines

    def test_serialize_to_json_compact(self):
        """Test compact JSON serialization."""
        data = {"key": "value"}
        result = utils.serialize_to_json(data, pretty=False)
        assert "\n" not in result

    def test_serialize_to_yaml(self):
        """Test serializing dict to YAML."""
        data = {"key": "value", "list": [1, 2, 3]}
        result = utils.serialize_to_yaml(data)
        assert "key: value" in result
        assert "- 1" in result


class TestConvertFormat:
    """Tests for format conversion."""

    def test_convert_toml_to_json(self):
        """Test converting TOML to JSON."""
        result = utils.convert_format(VALID_TOML_CONTENT, "toml", "json")
        # Parse result to verify it's valid JSON
        parsed = utils.parse_json(result)
        assert parsed["tree"]["name"] == "Test Attack Tree"

    def test_convert_json_to_yaml(self):
        """Test converting JSON to YAML."""
        result = utils.convert_format(VALID_JSON_CONTENT, "json", "yaml")
        # Parse result to verify it's valid YAML
        parsed = utils.parse_yaml(result)
        assert parsed["tree"]["name"] == "Test Attack Tree"

    def test_convert_yaml_to_toml(self):
        """Test converting YAML to TOML."""
        result = utils.convert_format(VALID_YAML_CONTENT, "yaml", "toml")
        # Parse result to verify it's valid TOML
        parsed = utils.parse_toml(result)
        assert parsed["tree"]["name"] == "Test Attack Tree"

    def test_convert_same_format(self):
        """Test converting to same format."""
        result = utils.convert_format(VALID_JSON_CONTENT, "json", "json")
        parsed = utils.parse_json(result)
        assert parsed["tree"]["name"] == "Test Attack Tree"

    def test_convert_invalid_source(self):
        """Test converting invalid source content."""
        with pytest.raises(utils.ConfigError):
            utils.convert_format("{invalid}", "json", "yaml")

    def test_convert_roundtrip(self):
        """Test roundtrip conversion preserves data."""
        # TOML -> JSON -> YAML -> TOML
        json_result = utils.convert_format(VALID_TOML_CONTENT, "toml", "json")
        yaml_result = utils.convert_format(json_result, "json", "yaml")
        toml_result = utils.convert_format(yaml_result, "yaml", "toml")

        original = utils.parse_toml(VALID_TOML_CONTENT)
        final = utils.parse_toml(toml_result)

        assert original["tree"]["name"] == final["tree"]["name"]
        assert original["tree"]["root"] == final["tree"]["root"]


class TestConfigModel:
    """Tests for ConfigModel class."""

    def test_config_model_get(self):
        """Test getting config values."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write('[section]\nkey = "value"\n')
            f.flush()
            try:
                config = utils.ConfigModel(f.name)
                assert config.get("section") == {"key": "value"}
            finally:
                os.unlink(f.name)

    def test_config_model_get_with_default(self):
        """Test getting config with default value."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write('[section]\nkey = "value"\n')
            f.flush()
            try:
                config = utils.ConfigModel(f.name)
                assert config.get("missing", "default") == "default"
            finally:
                os.unlink(f.name)

    def test_config_model_set(self):
        """Test setting config values."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write('[section]\nkey = "value"\n')
            f.flush()
            try:
                config = utils.ConfigModel(f.name)
                config.set("new_section", {"new_key": "new_value"})
                assert config.get("new_section") == {"new_key": "new_value"}
            finally:
                os.unlink(f.name)

    def test_config_model_has(self):
        """Test checking key existence."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write('[section]\nkey = "value"\n')
            f.flush()
            try:
                config = utils.ConfigModel(f.name)
                assert config.has("section") is True
                assert config.has("missing") is False
            finally:
                os.unlink(f.name)

    def test_config_model_keys(self):
        """Test getting all keys."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write('[section1]\nkey = "value"\n[section2]\nkey = "value"\n')
            f.flush()
            try:
                config = utils.ConfigModel(f.name)
                assert set(config.keys()) == {"section1", "section2"}
            finally:
                os.unlink(f.name)

    def test_config_model_missing_file(self):
        """Test loading missing config file."""
        with pytest.raises(utils.FileError):
            utils.ConfigModel("/nonexistent/config.tml")


# =============================================================================
# Caching Utilities Tests (Phase 3)
# =============================================================================

class TestCachedResultDecorator:
    """Tests for cached_result decorator."""

    def test_caches_result(self):
        """Test that results are cached."""
        call_count = [0]

        class TestClass:
            @utils.cached_result()
            def expensive_method(self, x):
                call_count[0] += 1
                return x * 2

        obj = TestClass()
        # First call
        result1 = obj.expensive_method(5)
        assert result1 == 10
        assert call_count[0] == 1

        # Second call with same arg - should use cache
        result2 = obj.expensive_method(5)
        assert result2 == 10
        assert call_count[0] == 1  # Not called again

    def test_different_args_not_cached(self):
        """Test that different arguments compute new results."""
        call_count = [0]

        class TestClass:
            @utils.cached_result()
            def compute(self, x):
                call_count[0] += 1
                return x ** 2

        obj = TestClass()
        obj.compute(2)
        obj.compute(3)
        obj.compute(2)  # Should be cached
        assert call_count[0] == 2

    def test_cache_is_per_instance(self):
        """Test that cache is per-instance, not shared."""
        class TestClass:
            def __init__(self, value):
                self.value = value

            @utils.cached_result()
            def get_value(self):
                return self.value

        obj1 = TestClass(1)
        obj2 = TestClass(2)

        assert obj1.get_value() == 1
        assert obj2.get_value() == 2

    def test_clear_cache(self):
        """Test cache clearing."""
        call_count = [0]

        class TestClass:
            @utils.cached_result()
            def compute(self, x):
                call_count[0] += 1
                return x * 2

        obj = TestClass()
        obj.compute(5)
        assert call_count[0] == 1

        # Clear cache
        obj.compute.clear_cache(obj)

        # Should compute again
        obj.compute(5)
        assert call_count[0] == 2

    def test_kwargs_caching(self):
        """Test that kwargs are included in cache key."""
        call_count = [0]

        class TestClass:
            @utils.cached_result()
            def compute(self, x, multiplier=1):
                call_count[0] += 1
                return x * multiplier

        obj = TestClass()
        obj.compute(5, multiplier=2)
        obj.compute(5, multiplier=3)
        obj.compute(5, multiplier=2)  # Should be cached
        assert call_count[0] == 2


class TestContentHash:
    """Tests for content_hash function."""

    def test_string_hash_md5(self):
        """Test hashing string with MD5."""
        result = utils.content_hash("Hello, World!")
        assert isinstance(result, str)
        assert len(result) == 32  # MD5 produces 32 hex chars

    def test_bytes_hash_md5(self):
        """Test hashing bytes with MD5."""
        result = utils.content_hash(b"Hello, World!")
        assert isinstance(result, str)
        assert len(result) == 32

    def test_consistent_hash(self):
        """Test that same content produces same hash."""
        hash1 = utils.content_hash("test content")
        hash2 = utils.content_hash("test content")
        assert hash1 == hash2

    def test_different_content_different_hash(self):
        """Test that different content produces different hash."""
        hash1 = utils.content_hash("content 1")
        hash2 = utils.content_hash("content 2")
        assert hash1 != hash2

    def test_sha1_algorithm(self):
        """Test SHA-1 hashing."""
        result = utils.content_hash("test", algorithm='sha1')
        assert len(result) == 40  # SHA-1 produces 40 hex chars

    def test_sha256_algorithm(self):
        """Test SHA-256 hashing."""
        result = utils.content_hash("test", algorithm='sha256')
        assert len(result) == 64  # SHA-256 produces 64 hex chars

    def test_invalid_algorithm(self):
        """Test that invalid algorithm raises error."""
        with pytest.raises(ValueError, match="Unsupported hash algorithm"):
            utils.content_hash("test", algorithm='invalid')


class TestFileHash:
    """Tests for file_hash function."""

    def test_file_hash_md5(self):
        """Test hashing file with MD5."""
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(b"Hello, World!")
            f.flush()
            try:
                result = utils.file_hash(f.name)
                assert isinstance(result, str)
                assert len(result) == 32
            finally:
                os.unlink(f.name)

    def test_file_hash_matches_content_hash(self):
        """Test that file hash matches content hash."""
        content = b"Test file content"
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(content)
            f.flush()
            try:
                file_result = utils.file_hash(f.name)
                content_result = utils.content_hash(content)
                assert file_result == content_result
            finally:
                os.unlink(f.name)

    def test_file_hash_sha256(self):
        """Test file hashing with SHA-256."""
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(b"test")
            f.flush()
            try:
                result = utils.file_hash(f.name, algorithm='sha256')
                assert len(result) == 64
            finally:
                os.unlink(f.name)

    def test_large_file_chunked_hash(self):
        """Test that large files are hashed correctly in chunks."""
        # Create a file larger than the chunk size
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            # Write 100KB of data
            f.write(b'x' * 100000)
            f.flush()
            try:
                result = utils.file_hash(f.name, chunk_size=1024)
                assert isinstance(result, str)
                assert len(result) == 32
            finally:
                os.unlink(f.name)


class TestStyleManager:
    """Tests for StyleManager class."""

    def test_cache_is_initially_empty(self):
        """Test that cache starts empty."""
        utils.StyleManager.clear_cache()
        assert len(utils.StyleManager.get_cached_styles()) == 0

    def test_get_cached_styles_returns_list(self):
        """Test that get_cached_styles returns a list."""
        utils.StyleManager.clear_cache()
        result = utils.StyleManager.get_cached_styles()
        assert isinstance(result, list)

    def test_clear_cache_removes_all(self):
        """Test that clear_cache removes all cached styles."""
        # First, we need to have something in cache
        # Since we can't easily load a real style file, just verify clear works
        utils.StyleManager.clear_cache()
        assert len(utils.StyleManager.get_cached_styles()) == 0

    def test_load_returns_dict_copy(self):
        """Test that load returns a copy of cached data."""
        # Create a temporary style file
        style_content = '''[test_style]
name = "Test"
color = "#000000"
'''
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(style_content)
            f.flush()
            try:
                utils.StyleManager.clear_cache()
                style1 = utils.StyleManager.load(f.name, "test_style")
                style2 = utils.StyleManager.load(f.name, "test_style")

                # Should be equal but not the same object
                assert style1 == style2

                # Modifying one shouldn't affect the other
                style1["name"] = "Modified"
                assert style2["name"] == "Test"
            finally:
                utils.StyleManager.clear_cache()
                os.unlink(f.name)

    def test_load_caches_style(self):
        """Test that loading a style caches it."""
        style_content = '''[cached_style]
value = 42
'''
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(style_content)
            f.flush()
            try:
                utils.StyleManager.clear_cache()
                utils.StyleManager.load(f.name, "cached_style")
                cached = utils.StyleManager.get_cached_styles()
                assert len(cached) == 1
                assert "cached_style" in cached[0]
            finally:
                utils.StyleManager.clear_cache()
                os.unlink(f.name)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
