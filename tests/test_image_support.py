#
# VULNEX -Universal Security Visualization Library-
#
# File: test_image_support.py
# Author: Claude Code
# Created: 2025-12-30
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
#

"""Tests for Image Support functionality.

This module tests the image validation and processing features:
- validate_image_path() function
- process_node_image() function
- Integration with visualization modules
"""

import os
import pytest
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from usecvislib.utils import (
    validate_image_path,
    process_node_image,
    SecurityError,
    IMAGE_EXTENSIONS,
    IMAGE_MAX_SIZE,
)


# =============================================================================
# Test Fixtures
# =============================================================================

@pytest.fixture
def temp_image_file():
    """Create a temporary image file for testing."""
    with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as f:
        # Write minimal PNG header
        f.write(b'\x89PNG\r\n\x1a\n')
        f.write(b'\x00' * 100)  # Add some content
        temp_path = f.name
    yield temp_path
    # Cleanup
    if os.path.exists(temp_path):
        os.unlink(temp_path)


@pytest.fixture
def temp_large_image():
    """Create a large temporary file exceeding size limit."""
    with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as f:
        # Write content larger than IMAGE_MAX_SIZE
        f.write(b'\x89PNG\r\n\x1a\n')
        f.write(b'\x00' * (IMAGE_MAX_SIZE + 1000))
        temp_path = f.name
    yield temp_path
    if os.path.exists(temp_path):
        os.unlink(temp_path)


@pytest.fixture
def temp_invalid_extension():
    """Create a file with invalid extension."""
    with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as f:
        f.write(b'MZ' + b'\x00' * 100)
        temp_path = f.name
    yield temp_path
    if os.path.exists(temp_path):
        os.unlink(temp_path)


# =============================================================================
# validate_image_path() Tests
# =============================================================================

class TestValidateImagePath:
    """Tests for validate_image_path() function."""

    def test_valid_png_image(self, temp_image_file):
        """Test validation of a valid PNG image."""
        result = validate_image_path(temp_image_file)
        assert result.exists()
        assert result.suffix == '.png'

    def test_valid_extensions(self, temp_image_file):
        """Test that all expected extensions are in IMAGE_EXTENSIONS."""
        assert '.png' in IMAGE_EXTENSIONS
        assert '.jpg' in IMAGE_EXTENSIONS
        assert '.jpeg' in IMAGE_EXTENSIONS
        assert '.gif' in IMAGE_EXTENSIONS
        assert '.svg' in IMAGE_EXTENSIONS
        assert '.bmp' in IMAGE_EXTENSIONS

    def test_nonexistent_file_raises_error(self):
        """Test that nonexistent file raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            validate_image_path('/nonexistent/path/to/image.png')

    def test_invalid_extension_raises_error(self, temp_invalid_extension):
        """Test that invalid extension raises SecurityError."""
        with pytest.raises(SecurityError) as exc_info:
            validate_image_path(temp_invalid_extension)
        assert "extension" in str(exc_info.value).lower()

    def test_file_too_large_raises_error(self, temp_large_image):
        """Test that oversized file raises SecurityError."""
        with pytest.raises(SecurityError) as exc_info:
            validate_image_path(temp_large_image)
        assert "size" in str(exc_info.value).lower() or "large" in str(exc_info.value).lower()

    def test_null_byte_in_path_raises_error(self, temp_image_file):
        """Test that null byte in path raises SecurityError."""
        malicious_path = temp_image_file + '\x00.evil'
        with pytest.raises(SecurityError):
            validate_image_path(malicious_path)

    def test_empty_path_raises_error(self):
        """Test that empty path raises SecurityError."""
        with pytest.raises(SecurityError):
            validate_image_path('')

    def test_custom_allowed_extensions(self, temp_image_file):
        """Test custom allowed_extensions parameter."""
        # Should work with PNG in allowed list
        result = validate_image_path(temp_image_file, allowed_extensions=['.png'])
        assert result.exists()

        # Should fail with PNG not in allowed list
        with pytest.raises(SecurityError):
            validate_image_path(temp_image_file, allowed_extensions=['.jpg'])

    def test_custom_max_size(self, temp_image_file):
        """Test custom max_size_bytes parameter."""
        # Should work with reasonable size
        result = validate_image_path(temp_image_file, max_size_bytes=1024 * 1024)
        assert result.exists()

        # Should fail with tiny size limit
        with pytest.raises(SecurityError):
            validate_image_path(temp_image_file, max_size_bytes=10)


# =============================================================================
# process_node_image() Tests
# =============================================================================

class TestProcessNodeImage:
    """Tests for process_node_image() function."""

    def test_node_without_image_unchanged(self):
        """Test that nodes without image attribute are unchanged."""
        node_attrs = {'label': 'Test Node', 'shape': 'box'}
        result = process_node_image(node_attrs, 'test_node')
        assert result == node_attrs
        assert 'image' not in result

    def test_node_with_empty_image_removed(self):
        """Test that empty image attribute is removed."""
        node_attrs = {'label': 'Test Node', 'image': ''}
        result = process_node_image(node_attrs, 'test_node')
        assert 'image' not in result
        assert 'label' in result

    def test_node_with_none_image_removed(self):
        """Test that None image attribute is removed."""
        node_attrs = {'label': 'Test Node', 'image': None}
        result = process_node_image(node_attrs, 'test_node')
        assert 'image' not in result

    def test_node_with_valid_image(self, temp_image_file):
        """Test that valid image path sets up clean icon rendering."""
        node_attrs = {'label': 'Server', 'image': temp_image_file}
        result = process_node_image(node_attrs, 'server_node')
        # HTML TABLE with image and text
        assert 'label' in result
        assert result['shape'] == 'none'       # No shape for clean rendering
        assert '<TABLE' in result['label']     # HTML table label
        assert 'IMG SRC=' in result['label']   # Contains image
        assert 'Server' in result['label']     # Contains text

    def test_node_with_invalid_image_removed(self):
        """Test that invalid image path is removed with warning."""
        node_attrs = {'label': 'Server', 'image': '/nonexistent/image.png'}
        result = process_node_image(node_attrs, 'server_node')
        assert 'image' not in result
        assert 'label' in result  # Other attributes preserved

    def test_node_with_security_error_image_removed(self, temp_invalid_extension):
        """Test that security-violating image is removed."""
        node_attrs = {'label': 'Server', 'image': temp_invalid_extension}
        result = process_node_image(node_attrs, 'server_node')
        assert 'image' not in result

    def test_returns_same_dict_reference(self):
        """Test that the same dictionary reference is returned."""
        node_attrs = {'label': 'Test'}
        result = process_node_image(node_attrs, 'test')
        assert result is node_attrs

    def test_custom_logger_used(self, temp_image_file):
        """Test that custom logger is used for warnings."""
        mock_logger = MagicMock()
        node_attrs = {'label': 'Server', 'image': '/invalid/path.png'}
        process_node_image(node_attrs, 'server_node', mock_logger)
        # Logger should have been called for warning
        assert mock_logger.warning.called or mock_logger.debug.called


# =============================================================================
# Integration Tests
# =============================================================================

class TestImageIntegration:
    """Integration tests for image support in visualization modules."""

    def test_image_constants(self):
        """Test that image constants are properly defined."""
        assert isinstance(IMAGE_EXTENSIONS, list)
        assert len(IMAGE_EXTENSIONS) > 0
        assert isinstance(IMAGE_MAX_SIZE, int)
        assert IMAGE_MAX_SIZE > 0

    def test_attacktrees_imports_image_functions(self):
        """Test that AttackTrees module uses image processing."""
        from usecvislib import attacktrees
        # Verify the module imports utils which has process_node_image
        assert hasattr(attacktrees, 'utils')

    def test_attackgraphs_imports_image_functions(self):
        """Test that AttackGraphs module uses image processing."""
        from usecvislib import attackgraphs
        assert hasattr(attackgraphs, 'utils')

    def test_threatmodeling_imports_image_functions(self):
        """Test that ThreatModeling module uses image processing."""
        from usecvislib import threatmodeling
        assert hasattr(threatmodeling, 'utils')

    def test_customdiagrams_imports_image_function(self):
        """Test that CustomDiagrams module imports image processing."""
        from usecvislib.customdiagrams import process_node_image as cd_process
        assert cd_process is not None

    def test_exports_from_package(self):
        """Test that image functions are exported from package."""
        from usecvislib import validate_image_path, process_node_image
        assert callable(validate_image_path)
        assert callable(process_node_image)


# =============================================================================
# Edge Case Tests
# =============================================================================

class TestImageEdgeCases:
    """Edge case tests for image handling."""

    def test_relative_path_resolution(self, temp_image_file):
        """Test that relative paths are resolved correctly."""
        # Get the directory containing the temp file
        temp_dir = os.path.dirname(temp_image_file)
        temp_name = os.path.basename(temp_image_file)

        # Change to temp directory
        original_cwd = os.getcwd()
        try:
            os.chdir(temp_dir)
            result = validate_image_path(temp_name)
            assert result.is_absolute()
        finally:
            os.chdir(original_cwd)

    def test_symlink_handling(self, temp_image_file):
        """Test handling of symlinked images."""
        import tempfile

        # Create a symlink to the temp image
        with tempfile.TemporaryDirectory() as tmpdir:
            link_path = os.path.join(tmpdir, 'link.png')
            try:
                os.symlink(temp_image_file, link_path)
                result = validate_image_path(link_path)
                assert result.exists()
            except OSError:
                # Skip if symlinks not supported
                pytest.skip("Symlinks not supported on this platform")

    def test_unicode_path(self, temp_image_file):
        """Test handling of unicode characters in path."""
        import tempfile
        import shutil

        with tempfile.TemporaryDirectory() as tmpdir:
            unicode_name = os.path.join(tmpdir, 'imagen_círculo.png')
            try:
                shutil.copy(temp_image_file, unicode_name)
                result = validate_image_path(unicode_name)
                assert result.exists()
            except (OSError, UnicodeError):
                pytest.skip("Unicode paths not supported")

    def test_spaces_in_path(self, temp_image_file):
        """Test handling of spaces in path."""
        import tempfile
        import shutil

        with tempfile.TemporaryDirectory() as tmpdir:
            spaced_name = os.path.join(tmpdir, 'image with spaces.png')
            shutil.copy(temp_image_file, spaced_name)
            result = validate_image_path(spaced_name)
            assert result.exists()

    def test_dot_in_filename(self, temp_image_file):
        """Test handling of multiple dots in filename."""
        import tempfile
        import shutil

        with tempfile.TemporaryDirectory() as tmpdir:
            dotted_name = os.path.join(tmpdir, 'image.v2.final.png')
            shutil.copy(temp_image_file, dotted_name)
            result = validate_image_path(dotted_name)
            assert result.exists()


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
