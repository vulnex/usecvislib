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
from pathlib import Path
from unittest.mock import patch
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

    def test_aggregate_stats_attack_graph_totals_not_double_counted(self):
        """Attack-graph totals already include hosts and network edges."""
        with tempfile.TemporaryDirectory() as tmpdir:
            processor = BatchProcessor("attack_graph", tmpdir)
            result = BatchResult()
            result.successes["a.toml"] = {"stats": {
                "total_hosts": 2, "network_edges": 1, "total_nodes": 6, "total_edges": 4,
                "total_vulnerabilities": 3, "average_cvss": 8.0,
            }}
            result.successes["b.toml"] = {"stats": {
                "total_hosts": 1, "network_edges": 0, "total_nodes": 1, "total_edges": 0,
                "total_vulnerabilities": 0, "average_cvss": 0,
            }}

            stats = processor.aggregate_stats(result)
            assert stats["total_nodes"] == 7
            assert stats["total_edges"] == 4
            # A file without vulnerabilities does not pull the average down
            assert stats["avg_cvss"] == 8.0


class TestBatchOutputs:
    """Output naming and engine forwarding."""

    def test_same_stem_inputs_get_distinct_outputs(self):
        names = BatchProcessor.output_names(["a/net.toml", "b/net.toml", "c/net.json", "x/other.toml"])
        assert names == {
            "a/net.toml": "net",
            "b/net.toml": "net-2",
            "c/net.json": "net-3",
            "x/other.toml": "other",
        }

    def test_recursive_directory_outputs_do_not_overwrite(self):
        template = Path(__file__).parent.parent / "templates" / "attack-trees" / "network_infrastructure.toml"
        with tempfile.TemporaryDirectory() as tmpdir:
            src = Path(tmpdir) / "in"
            for sub in ("a", "b"):
                (src / sub).mkdir(parents=True)
                (src / sub / "tree.toml").write_bytes(template.read_bytes())
            out = Path(tmpdir) / "out"
            processor = BatchProcessor("attack_tree", str(out), format="svg", render_engine="svg", max_workers=2)
            result = processor.process_directory(str(src), recursive=True)
            assert result.failure_count == 0
            outputs = sorted(d["output"] for d in result.successes.values())
            assert [Path(o).name for o in outputs] == ["tree-2.svg", "tree.svg"]
            assert all(Path(o).exists() for o in outputs)

    def test_binary_ignores_render_engine(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            data = Path(tmpdir) / "blob.bin"
            data.write_bytes(bytes(range(256)) * 16)
            result = process_batch(
                "binary", [str(data)], str(Path(tmpdir) / "out"), format="png",
                render_engine="svg", validate=False,
            )
            assert result.failure_count == 0, result.failures

    def test_process_batch_forwards_render_engine(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.object(BatchProcessor, "process_files", return_value=BatchResult()):
                with patch.object(BatchProcessor, "__init__", return_value=None) as init:
                    process_batch("attack_tree", [], tmpdir, render_engine="svg")
            assert init.call_args.kwargs["render_engine"] == "svg"


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


TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "..", "templates")


@pytest.mark.skipif(not __import__("shutil").which("dot"), reason="graphviz 'dot' binary not installed")
@pytest.mark.parametrize(
    "module_type,template",
    [
        ("privilege_gradient", "privilege-gradient/corporate_network.tml"),
        ("component_diagram", "architecture/component-diagram-example.json"),
        ("dependency_graph", "architecture/dependency-graph-example.json"),
        ("kill_chain", "kill-chains/apt_intrusion.tml"),
        ("incident_timeline", "timelines/phishing_compromise.tml"),
        ("vuln_tree", "vuln-trees/java_log4shell.tml"),
        ("maestro", "maestro/single-agent-rag.toml"),
    ],
)
def test_batch_supports_every_file_based_module(tmp_path, module_type, template):
    # Only attack trees/graphs, threat models and binaries were accepted;
    # other module types raised "Unknown module type".
    result = process_batch(module_type, [os.path.join(TEMPLATES_DIR, template)], str(tmp_path))
    assert result.failure_count == 0, result.failures
    assert list(tmp_path.glob("*.png"))
