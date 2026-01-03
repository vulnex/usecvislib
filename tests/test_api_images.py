#
# VULNEX -Universal Security Visualization Library-
#
# File: test_api_images.py
# Author: Claude Code
# Created: 2025-12-30
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
#

"""Tests for Image API endpoints.

This module tests the image upload, info, delete, and list endpoints:
- Upload validation (type, size, content)
- Image info retrieval
- Image download
- Image deletion
- Image listing
- Image reference resolution
"""

import os
import pytest
import io
import sys
from unittest.mock import patch

# Add the api directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'api'))


# =============================================================================
# Test Fixtures
# =============================================================================

@pytest.fixture
def test_client():
    """Create a test client with auth disabled."""
    with patch.dict(os.environ, {
        "USECVISLIB_AUTH_ENABLED": "false",
        "USECVISLIB_API_KEY": "",
        "USECVISLIB_API_KEYS": ""
    }, clear=False):
        import importlib
        import api.auth
        import api.main
        importlib.reload(api.auth)
        importlib.reload(api.main)

        from fastapi.testclient import TestClient
        from api.main import app
        return TestClient(app)


@pytest.fixture
def sample_png_content():
    """Create minimal valid PNG content."""
    # Minimal PNG header
    return b'\x89PNG\r\n\x1a\n' + b'\x00' * 100


@pytest.fixture
def sample_jpeg_content():
    """Create minimal valid JPEG content."""
    # JPEG magic bytes
    return b'\xff\xd8\xff\xe0' + b'\x00' * 100


@pytest.fixture
def sample_gif_content():
    """Create minimal valid GIF content."""
    return b'GIF89a' + b'\x00' * 100


@pytest.fixture
def sample_svg_content():
    """Create minimal valid SVG content."""
    return b'<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"></svg>'


# =============================================================================
# Image Upload Tests
# =============================================================================

class TestImageUpload:
    """Tests for image upload endpoint."""

    def test_upload_png_image(self, test_client, sample_png_content):
        """Test uploading a PNG image."""
        response = test_client.post(
            "/images/upload",
            files={"file": ("test.png", io.BytesIO(sample_png_content), "image/png")}
        )
        assert response.status_code == 200
        data = response.json()
        assert "image_id" in data
        assert data["filename"] == "test.png"
        assert data["content_type"] == "image/png"
        assert data["size"] == len(sample_png_content)

    def test_upload_jpeg_image(self, test_client, sample_jpeg_content):
        """Test uploading a JPEG image."""
        response = test_client.post(
            "/images/upload",
            files={"file": ("test.jpg", io.BytesIO(sample_jpeg_content), "image/jpeg")}
        )
        assert response.status_code == 200
        data = response.json()
        assert "image_id" in data
        assert data["content_type"] == "image/jpeg"

    def test_upload_gif_image(self, test_client, sample_gif_content):
        """Test uploading a GIF image."""
        response = test_client.post(
            "/images/upload",
            files={"file": ("test.gif", io.BytesIO(sample_gif_content), "image/gif")}
        )
        assert response.status_code == 200
        data = response.json()
        assert "image_id" in data
        assert data["content_type"] == "image/gif"

    def test_upload_svg_image(self, test_client, sample_svg_content):
        """Test uploading an SVG image."""
        response = test_client.post(
            "/images/upload",
            files={"file": ("test.svg", io.BytesIO(sample_svg_content), "image/svg+xml")}
        )
        assert response.status_code == 200
        data = response.json()
        assert "image_id" in data
        assert data["content_type"] == "image/svg+xml"

    def test_upload_invalid_content_type(self, test_client):
        """Test uploading with unsupported content type."""
        response = test_client.post(
            "/images/upload",
            files={"file": ("test.txt", io.BytesIO(b"hello world"), "text/plain")}
        )
        assert response.status_code == 400
        assert "Unsupported image type" in response.json()["detail"]

    def test_upload_invalid_content(self, test_client):
        """Test uploading invalid image content."""
        response = test_client.post(
            "/images/upload",
            files={"file": ("test.png", io.BytesIO(b"not a real png"), "image/png")}
        )
        assert response.status_code == 400
        assert "Invalid image file" in response.json()["detail"]

    def test_upload_too_large(self, test_client):
        """Test uploading an image that exceeds size limit."""
        # Create content larger than 5 MB
        large_content = b'\x89PNG\r\n\x1a\n' + b'\x00' * (6 * 1024 * 1024)
        response = test_client.post(
            "/images/upload",
            files={"file": ("large.png", io.BytesIO(large_content), "image/png")}
        )
        assert response.status_code == 400
        assert "too large" in response.json()["detail"].lower()


# =============================================================================
# Image Info Tests
# =============================================================================

class TestImageInfo:
    """Tests for image info endpoint."""

    def test_get_image_info(self, test_client, sample_png_content):
        """Test getting info about an uploaded image."""
        # First upload an image
        upload_response = test_client.post(
            "/images/upload",
            files={"file": ("test.png", io.BytesIO(sample_png_content), "image/png")}
        )
        image_id = upload_response.json()["image_id"]

        # Get info
        response = test_client.get(f"/images/{image_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["image_id"] == image_id
        assert data["exists"] is True
        assert data["size"] == len(sample_png_content)
        assert data["content_type"] == "image/png"
        assert "created_at" in data

    def test_get_nonexistent_image_info(self, test_client):
        """Test getting info for non-existent image."""
        response = test_client.get("/images/nonexistent-image-id")
        assert response.status_code == 404


# =============================================================================
# Image Download Tests
# =============================================================================

class TestImageDownload:
    """Tests for image download endpoint."""

    def test_download_image(self, test_client, sample_png_content):
        """Test downloading an uploaded image."""
        # First upload an image
        upload_response = test_client.post(
            "/images/upload",
            files={"file": ("test.png", io.BytesIO(sample_png_content), "image/png")}
        )
        image_id = upload_response.json()["image_id"]

        # Download
        response = test_client.get(f"/images/{image_id}/download")
        assert response.status_code == 200
        assert response.content == sample_png_content

    def test_download_nonexistent_image(self, test_client):
        """Test downloading non-existent image."""
        response = test_client.get("/images/nonexistent-image-id/download")
        assert response.status_code == 404


# =============================================================================
# Image Delete Tests
# =============================================================================

class TestImageDelete:
    """Tests for image delete endpoint."""

    def test_delete_image(self, test_client, sample_png_content):
        """Test deleting an uploaded image."""
        # First upload an image
        upload_response = test_client.post(
            "/images/upload",
            files={"file": ("test.png", io.BytesIO(sample_png_content), "image/png")}
        )
        image_id = upload_response.json()["image_id"]

        # Delete
        response = test_client.delete(f"/images/{image_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["deleted"] is True
        assert data["image_id"] == image_id

        # Verify it's gone
        info_response = test_client.get(f"/images/{image_id}")
        assert info_response.status_code == 404

    def test_delete_nonexistent_image(self, test_client):
        """Test deleting non-existent image."""
        response = test_client.delete("/images/nonexistent-image-id")
        assert response.status_code == 404


# =============================================================================
# Image List Tests
# =============================================================================

class TestImageList:
    """Tests for image list endpoint."""

    def test_list_images_empty(self, test_client):
        """Test listing images when none uploaded."""
        response = test_client.get("/images")
        assert response.status_code == 200
        data = response.json()
        assert "images" in data
        assert "total" in data
        assert isinstance(data["images"], list)

    def test_list_images_after_upload(self, test_client, sample_png_content):
        """Test listing images after uploading."""
        # Upload an image
        upload_response = test_client.post(
            "/images/upload",
            files={"file": ("test.png", io.BytesIO(sample_png_content), "image/png")}
        )
        image_id = upload_response.json()["image_id"]

        # List images
        response = test_client.get("/images")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] >= 1

        # Find our uploaded image
        image_ids = [img["image_id"] for img in data["images"]]
        assert image_id in image_ids


# =============================================================================
# Image Reference Resolution Tests
# =============================================================================

class TestImageReferenceResolution:
    """Tests for image reference resolution functionality."""

    def test_resolve_image_references_attack_tree(self):
        """Test resolving image references in attack tree config."""
        from api.main import resolve_image_references

        # Mock config with image_id
        config = {
            "tree": {"name": "Test", "root": "Goal"},
            "nodes": {
                "Goal": {"label": "Root", "image_id": "test-uuid"},
                "Attack": {"label": "Attack"}
            }
        }

        # Resolve (will log warning for missing image)
        result = resolve_image_references(config)

        # image_id should be removed (since image doesn't exist)
        assert "image_id" not in result["nodes"]["Goal"]
        # Other node unchanged
        assert result["nodes"]["Attack"]["label"] == "Attack"

    def test_resolve_image_references_attack_graph(self):
        """Test resolving image references in attack graph config."""
        from api.main import resolve_image_references

        config = {
            "hosts": [
                {"id": "server", "label": "Server", "image_id": "test-uuid"}
            ],
            "vulnerabilities": {}
        }

        result = resolve_image_references(config)
        # image_id should be removed (since image doesn't exist)
        assert "image_id" not in result["hosts"][0]

    def test_resolve_image_references_custom_diagram(self):
        """Test resolving image references in custom diagram config."""
        from api.main import resolve_image_references

        config = {
            "nodes": [
                {"id": "node1", "type": "server", "image_id": "test-uuid"}
            ]
        }

        result = resolve_image_references(config)
        # image_id should be removed (since image doesn't exist)
        assert "image_id" not in result["nodes"][0]


# =============================================================================
# Image Helper Function Tests
# =============================================================================

class TestImageHelpers:
    """Tests for image helper functions."""

    def test_is_valid_image_png(self, sample_png_content):
        """Test PNG validation."""
        from api.main import is_valid_image
        assert is_valid_image(sample_png_content, "image/png") is True

    def test_is_valid_image_jpeg(self, sample_jpeg_content):
        """Test JPEG validation."""
        from api.main import is_valid_image
        assert is_valid_image(sample_jpeg_content, "image/jpeg") is True

    def test_is_valid_image_gif(self, sample_gif_content):
        """Test GIF validation."""
        from api.main import is_valid_image
        assert is_valid_image(sample_gif_content, "image/gif") is True

    def test_is_valid_image_svg(self, sample_svg_content):
        """Test SVG validation."""
        from api.main import is_valid_image
        assert is_valid_image(sample_svg_content, "image/svg+xml") is True

    def test_is_valid_image_invalid(self):
        """Test invalid image content."""
        from api.main import is_valid_image
        assert is_valid_image(b"not an image", "image/png") is False

    def test_get_image_content_type(self):
        """Test content type detection from filepath."""
        from api.main import get_image_content_type

        assert get_image_content_type("/path/to/image.png") == "image/png"
        assert get_image_content_type("/path/to/image.jpg") == "image/jpeg"
        assert get_image_content_type("/path/to/image.gif") == "image/gif"
        assert get_image_content_type("/path/to/image.svg") == "image/svg+xml"


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
