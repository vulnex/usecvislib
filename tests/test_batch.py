#
# VULNEX -Universal Security Visualization Library-
#
# File: test_batch.py
# Author: Simon Roses Femerling
# Created: 2025-12-25
# Last Modified: 2025-12-25
# Version: 0.3.1
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Unit tests for batch module."""

import os
import sys
import tempfile
import pytest

# Add src to path for testing
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from usecvislib.batch import BatchProcessor, BatchResult, process_batch


# Sample valid attack graph TOML content
VALID_ATTACK_GRAPH = '''
[graph]
name = "Test Attack Graph"

[[hosts]]
id = "attacker"
label = "Attacker"
zone = "external"

[[hosts]]
id = "target"
label = "Target"
zone = "internal"

[[network_edges]]
from = "attacker"
to = "target"
'''


class TestBatchResult:
    """Tests for BatchResult dataclass."""

    def test_empty_result(self):
        """Test empty batch result."""
        result = BatchResult()
        assert result.total == 0
        assert result.success_count == 0
        assert result.failure_count == 0
        assert result.success_rate == 0.0

    def test_with_successes(self):
        """Test result with successes."""
        result = BatchResult()
        result.successes["file1.toml"] = {"stats": {"nodes": 10}}
        result.successes["file2.toml"] = {"stats": {"nodes": 20}}
        assert result.total == 2
        assert result.success_count == 2
        assert result.success_rate == 1.0
        assert result.success_percentage == 100.0

    def test_with_failures(self):
        """Test result with failures."""
        result = BatchResult()
        result.failures["file1.toml"] = "File not found"
        result.failures["file2.toml"] = "Invalid format"
        assert result.total == 2
        assert result.failure_count == 2
        assert result.success_rate == 0.0

    def test_mixed_results(self):
        """Test result with mixed successes and failures."""
        result = BatchResult()
        result.successes["file1.toml"] = {}
        result.successes["file2.toml"] = {}
        result.failures["file3.toml"] = "Error"
        assert result.total == 3
        assert result.success_count == 2
        assert result.failure_count == 1
        assert result.success_rate == pytest.approx(2/3)

    def test_summary(self):
        """Test summary generation."""
        result = BatchResult()
        result.successes["good.toml"] = {}
        result.failures["bad.toml"] = "Error"

        summary = result.summary()
        assert summary["total"] == 2
        assert summary["successes"] == 1
        assert summary["failures"] == 1
        assert "bad.toml" in summary["failed_files"]

    def test_get_stats(self):
        """Test getting stats for specific file."""
        result = BatchResult()
        result.successes["file.toml"] = {"stats": {"nodes": 10}}

        stats = result.get_stats("file.toml")
        assert stats["nodes"] == 10

        assert result.get_stats("nonexistent.toml") is None

    def test_get_error(self):
        """Test getting error for specific file."""
        result = BatchResult()
        result.failures["file.toml"] = "Test error"

        assert result.get_error("file.toml") == "Test error"
        assert result.get_error("nonexistent.toml") is None

    def test_to_dict(self):
        """Test dictionary conversion."""
        result = BatchResult()
        result.successes["file.toml"] = {"data": 1}

        d = result.to_dict()
        assert "summary" in d
        assert "successes" in d
        assert "failures" in d


class TestBatchProcessor:
    """Tests for BatchProcessor class."""

    def test_init_valid_module(self):
        """Test initialization with valid module type."""
        with tempfile.TemporaryDirectory() as tmpdir:
            processor = BatchProcessor("attack_graph", tmpdir)
            assert processor.module_type == "attack_graph"
            assert processor.format == "png"

    def test_init_invalid_module(self):
        """Test initialization with invalid module type."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with pytest.raises(ValueError, match="Unknown module type"):
                BatchProcessor("invalid_type", tmpdir)

    def test_init_creates_output_dir(self):
        """Test that init creates output directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = os.path.join(tmpdir, "new_subdir")
            BatchProcessor("attack_graph", output_dir)
            assert os.path.isdir(output_dir)

    def test_process_empty_list(self):
        """Test processing empty file list."""
        with tempfile.TemporaryDirectory() as tmpdir:
            processor = BatchProcessor("attack_graph", tmpdir)
            result = processor.process_files([])
            assert result.total == 0

    def test_process_nonexistent_file(self):
        """Test processing nonexistent file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            processor = BatchProcessor("attack_graph", tmpdir)
            result = processor.process_files(["/nonexistent/file.toml"])
            assert result.failure_count == 1
            assert "file.toml" in list(result.failures.keys())[0]

    def test_process_directory_nonexistent(self):
        """Test processing nonexistent directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            processor = BatchProcessor("attack_graph", tmpdir)
            with pytest.raises(ValueError, match="does not exist"):
                processor.process_directory("/nonexistent/dir")

    def test_process_with_progress_callback(self):
        """Test processing with progress callback."""
        progress_calls = []

        def on_progress(filename, success, error):
            progress_calls.append((filename, success, error))

        with tempfile.TemporaryDirectory() as tmpdir:
            processor = BatchProcessor("attack_graph", tmpdir)
            processor.process_files(
                ["/nonexistent/file.toml"],
                on_progress=on_progress
            )

            assert len(progress_calls) == 1
            assert progress_calls[0][1] is False  # Failed

    def test_aggregate_stats_empty(self):
        """Test aggregating stats from empty result."""
        with tempfile.TemporaryDirectory() as tmpdir:
            processor = BatchProcessor("attack_graph", tmpdir)
            result = BatchResult()
            stats = processor.aggregate_stats(result)
            assert stats == {"file_count": 0}

    def test_aggregate_stats_with_data(self):
        """Test aggregating stats from results."""
        with tempfile.TemporaryDirectory() as tmpdir:
            processor = BatchProcessor("attack_graph", tmpdir)
            result = BatchResult()
            result.successes["file1.toml"] = {
                "stats": {"total_hosts": 5, "network_edges": 3}
            }
            result.successes["file2.toml"] = {
                "stats": {"total_hosts": 3, "network_edges": 2}
            }

            stats = processor.aggregate_stats(result)
            assert stats["file_count"] == 2
            assert stats["total_nodes"] == 8  # 5 + 3
            assert stats["total_edges"] == 5  # 3 + 2


class TestProcessBatchFunction:
    """Tests for process_batch convenience function."""

    def test_process_batch_creates_processor(self):
        """Test that process_batch creates a processor and runs."""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = process_batch(
                "attack_graph",
                [],
                tmpdir
            )
            assert isinstance(result, BatchResult)
            assert result.total == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
