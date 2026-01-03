#
# VULNEX -Universal Security Visualization Library-
#
# File: test_async.py
# Author: Simon Roses Femerling
# Created: 2025-12-25
# Last Modified: 2025-12-25
# Version: 0.3.1
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Unit tests for async_support module."""

import os
import sys
import asyncio
import tempfile
import pytest

# Add src to path for testing
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from usecvislib.async_support import (
    AsyncVisualization,
    async_wrap,
    AsyncBatchProcessor,
    process_files_async,
    AsyncContextManager,
)

# Configure pytest-asyncio
pytestmark = pytest.mark.asyncio(loop_scope="function")


class MockVisualization:
    """Mock visualization class for testing."""

    def __init__(self):
        self.loaded = False
        self.rendered = False
        self.drawn = False
        self.inputdata = {"test": "data"}

    def load(self):
        self.loaded = True

    def Render(self):
        self.rendered = True

    def draw(self):
        self.drawn = True

    def validate(self):
        return []

    def get_graph_stats(self):
        return {"nodes": 5, "edges": 3}

    def export_json(self, output=None):
        return '{"test": "json"}'


class TestAsyncVisualization:
    """Tests for AsyncVisualization class."""

    async def test_init(self):
        """Test initialization."""
        mock = MockVisualization()
        async_viz = AsyncVisualization(mock)
        assert async_viz.sync is mock
        await async_viz.close()

    async def test_async_load(self):
        """Test async loading."""
        mock = MockVisualization()
        async_viz = AsyncVisualization(mock)
        result = await async_viz.load()
        assert mock.loaded is True
        assert result is mock
        await async_viz.close()

    async def test_async_render(self):
        """Test async rendering."""
        mock = MockVisualization()
        async_viz = AsyncVisualization(mock)
        result = await async_viz.render()
        assert mock.rendered is True
        assert result is mock
        await async_viz.close()

    async def test_async_draw(self):
        """Test async drawing."""
        mock = MockVisualization()
        async_viz = AsyncVisualization(mock)
        result = await async_viz.draw()
        assert mock.drawn is True
        assert result is mock
        await async_viz.close()

    async def test_async_build(self):
        """Test async complete build."""
        mock = MockVisualization()
        async_viz = AsyncVisualization(mock)
        result = await async_viz.build()
        assert mock.loaded is True
        assert mock.rendered is True
        assert mock.drawn is True
        assert result is mock
        await async_viz.close()

    async def test_async_validate(self):
        """Test async validation."""
        mock = MockVisualization()
        async_viz = AsyncVisualization(mock)
        result = await async_viz.validate()
        assert isinstance(result, list)
        await async_viz.close()

    async def test_async_get_stats(self):
        """Test async stats collection."""
        mock = MockVisualization()
        async_viz = AsyncVisualization(mock)
        result = await async_viz.get_stats()
        assert result["nodes"] == 5
        assert result["edges"] == 3
        await async_viz.close()

    async def test_async_export_json(self):
        """Test async JSON export."""
        mock = MockVisualization()
        async_viz = AsyncVisualization(mock)
        result = await async_viz.export_json()
        assert "test" in result
        await async_viz.close()

    async def test_context_manager(self):
        """Test async context manager."""
        mock = MockVisualization()
        async with AsyncVisualization(mock) as async_viz:
            assert async_viz.sync is mock
        # Context manager should close without error

    async def test_close(self):
        """Test executor shutdown."""
        mock = MockVisualization()
        async_viz = AsyncVisualization(mock)
        await async_viz.close()
        # Should not raise


class TestAsyncWrap:
    """Tests for async_wrap function."""

    async def test_wrap_creates_async_visualization(self):
        """Test that wrap creates AsyncVisualization."""
        mock = MockVisualization()
        async_viz = async_wrap(mock)
        assert isinstance(async_viz, AsyncVisualization)
        assert async_viz.sync is mock
        await async_viz.close()

    async def test_wrap_usable(self):
        """Test wrapped instance is usable."""
        mock = MockVisualization()
        async_viz = async_wrap(mock)
        await async_viz.load()
        assert mock.loaded is True
        await async_viz.close()


class TestAsyncBatchProcessor:
    """Tests for AsyncBatchProcessor class."""

    async def test_init(self):
        """Test initialization."""
        with tempfile.TemporaryDirectory() as tmpdir:
            processor = AsyncBatchProcessor("attack_graph", tmpdir)
            assert processor._semaphore is not None
            await processor.close()

    async def test_process_empty_list(self):
        """Test processing empty file list."""
        with tempfile.TemporaryDirectory() as tmpdir:
            processor = AsyncBatchProcessor("attack_graph", tmpdir)
            result = await processor.process_files([])
            assert result.total == 0
            await processor.close()

    async def test_process_nonexistent_file(self):
        """Test processing nonexistent file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            processor = AsyncBatchProcessor("attack_graph", tmpdir)
            result = await processor.process_files(["/nonexistent/file.toml"])
            assert result.failure_count == 1
            await processor.close()

    async def test_process_with_progress_callback(self):
        """Test processing with progress callback."""
        progress_calls = []

        def on_progress(filename, success, error):
            progress_calls.append((filename, success, error))

        with tempfile.TemporaryDirectory() as tmpdir:
            processor = AsyncBatchProcessor("attack_graph", tmpdir)
            await processor.process_files(
                ["/nonexistent/file.toml"],
                on_progress=on_progress
            )
            assert len(progress_calls) == 1
            await processor.close()


class TestProcessFilesAsync:
    """Tests for process_files_async function."""

    async def test_process_empty(self):
        """Test processing empty list."""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = await process_files_async(
                "attack_graph",
                [],
                tmpdir
            )
            assert result.total == 0

    async def test_process_with_options(self):
        """Test processing with options."""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = await process_files_async(
                "attack_graph",
                [],
                tmpdir,
                format="svg",
                max_concurrent=2
            )
            assert result.total == 0


class TestAsyncContextManager:
    """Tests for AsyncContextManager class."""

    async def test_context_manager_entry_exit(self):
        """Test context manager entry and exit."""
        cm = AsyncContextManager(MockVisualization)
        async with cm as async_viz:
            assert isinstance(async_viz, AsyncVisualization)
        # Should not raise on exit


class TestConcurrentOperations:
    """Tests for concurrent async operations."""

    async def test_multiple_concurrent_loads(self):
        """Test multiple concurrent load operations."""
        mocks = [MockVisualization() for _ in range(3)]
        async_vizs = [AsyncVisualization(m) for m in mocks]

        # Run all loads concurrently
        await asyncio.gather(*[av.load() for av in async_vizs])

        for mock in mocks:
            assert mock.loaded is True

        # Cleanup
        for av in async_vizs:
            await av.close()

    async def test_sequential_operations(self):
        """Test sequential async operations."""
        mock = MockVisualization()
        async_viz = AsyncVisualization(mock)

        await async_viz.load()
        assert mock.loaded is True
        assert mock.rendered is False

        await async_viz.render()
        assert mock.rendered is True
        assert mock.drawn is False

        await async_viz.draw()
        assert mock.drawn is True

        await async_viz.close()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
