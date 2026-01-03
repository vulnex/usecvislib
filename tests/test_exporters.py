#
# VULNEX -Universal Security Visualization Library-
#
# File: test_exporters.py
# Author: Simon Roses Femerling
# Created: 2025-12-25
# Last Modified: 2025-12-25
# Version: 0.3.1
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Unit tests for exporters module."""

import os
import sys
import json
import tempfile
import pytest

# Add src to path for testing
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from usecvislib.exporters import ExportMixin, Exporter, ReportGenerator


class TestExporter:
    """Tests for Exporter utility class."""

    def test_to_json_simple(self):
        """Test JSON export of simple data."""
        data = {"key": "value", "number": 42}
        result = Exporter.to_json(data)
        parsed = json.loads(result)
        assert parsed["key"] == "value"
        assert parsed["number"] == 42

    def test_to_json_pretty(self):
        """Test pretty-printed JSON."""
        data = {"a": 1}
        result = Exporter.to_json(data, pretty=True)
        assert "\n" in result  # Pretty print has newlines

    def test_to_json_compact(self):
        """Test compact JSON."""
        data = {"a": 1, "b": 2}
        result = Exporter.to_json(data, pretty=False)
        assert "\n" not in result

    def test_to_json_with_file(self):
        """Test JSON export to file."""
        data = {"test": "data"}
        with tempfile.TemporaryDirectory() as tmpdir:
            output = os.path.join(tmpdir, "test.json")
            Exporter.to_json(data, output)
            assert os.path.exists(output)
            with open(output) as f:
                loaded = json.load(f)
            assert loaded["test"] == "data"

    def test_to_csv_list_of_dicts(self):
        """Test CSV export from list of dicts."""
        data = [
            {"name": "Alice", "age": 30},
            {"name": "Bob", "age": 25},
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            output = os.path.join(tmpdir, "test.csv")
            count = Exporter.to_csv(data, output)
            assert count == 2
            assert os.path.exists(output)
            with open(output) as f:
                content = f.read()
            assert "name" in content
            assert "Alice" in content

    def test_to_csv_with_file(self):
        """Test CSV export to file."""
        data = [{"x": 1}, {"x": 2}]
        with tempfile.TemporaryDirectory() as tmpdir:
            output = os.path.join(tmpdir, "test.csv")
            Exporter.to_csv(data, output)
            assert os.path.exists(output)

    def test_to_csv_custom_delimiter(self):
        """Test CSV with custom delimiter."""
        data = [{"a": 1, "b": 2}]
        with tempfile.TemporaryDirectory() as tmpdir:
            output = os.path.join(tmpdir, "test.csv")
            Exporter.to_csv(data, output, delimiter=";")
            with open(output) as f:
                content = f.read()
            assert ";" in content

    def test_to_csv_empty(self):
        """Test CSV with empty data."""
        data = []
        with tempfile.TemporaryDirectory() as tmpdir:
            output = os.path.join(tmpdir, "test.csv")
            count = Exporter.to_csv(data, output)
            assert count == 0

    def test_to_yaml_simple(self):
        """Test YAML export."""
        data = {"key": "value"}
        result = Exporter.to_yaml(data)
        assert "key:" in result
        assert "value" in result

    def test_to_yaml_with_file(self):
        """Test YAML export to file."""
        data = {"test": "yaml"}
        with tempfile.TemporaryDirectory() as tmpdir:
            output = os.path.join(tmpdir, "test.yaml")
            Exporter.to_yaml(data, output)
            assert os.path.exists(output)

    def test_to_markdown_table(self):
        """Test Markdown table export."""
        data = [
            {"name": "Alice", "age": 30},
            {"name": "Bob", "age": 25},
        ]
        result = Exporter.to_markdown_table(data)
        assert "| name |" in result or "| age |" in result
        assert "Alice" in result
        assert "Bob" in result

    def test_to_markdown_table_empty(self):
        """Test Markdown table with empty data."""
        data = []
        result = Exporter.to_markdown_table(data)
        assert result == ""

    def test_to_markdown_table_with_columns(self):
        """Test Markdown table with specific columns."""
        data = [{"a": 1, "b": 2, "c": 3}]
        result = Exporter.to_markdown_table(data, columns=["a", "b"])
        assert "| a |" in result
        assert "| b |" in result

    def test_to_markdown_table_with_file(self):
        """Test Markdown table export to file."""
        data = [{"key": "value"}]
        with tempfile.TemporaryDirectory() as tmpdir:
            output = os.path.join(tmpdir, "test.md")
            Exporter.to_markdown_table(data, output)
            assert os.path.exists(output)


class TestExportMixin:
    """Tests for ExportMixin class."""

    def test_mixin_has_export_methods(self):
        """Test that mixin provides export methods."""
        # Create a mock class with the mixin
        class MockViz(ExportMixin):
            def __init__(self):
                self.inputdata = {"test": "data"}
                self.inputfile = "test.toml"
                self._loaded = True

            def load(self):
                pass

            def get_graph_stats(self):
                return {"nodes": 5}

        viz = MockViz()
        assert hasattr(viz, 'export_json')
        assert hasattr(viz, 'export_csv')
        assert hasattr(viz, 'get_exportable_sections')

    def test_mixin_export_json(self):
        """Test mixin JSON export."""
        class MockViz(ExportMixin):
            def __init__(self):
                self.inputdata = {"key": "value"}
                self.inputfile = "test.toml"
                self._loaded = True

            def load(self):
                pass

        viz = MockViz()
        result = viz.export_json()
        parsed = json.loads(result)
        assert "data" in parsed
        assert parsed["data"]["key"] == "value"

    def test_mixin_export_json_with_stats(self):
        """Test mixin JSON export includes stats."""
        class MockViz(ExportMixin):
            def __init__(self):
                self.inputdata = {}
                self.inputfile = "test.toml"
                self._loaded = True

            def load(self):
                pass

            def get_graph_stats(self):
                return {"count": 10}

        viz = MockViz()
        result = viz.export_json(include_stats=True)
        parsed = json.loads(result)
        assert "stats" in parsed
        assert parsed["stats"]["count"] == 10

    def test_mixin_export_json_to_file(self):
        """Test mixin JSON export to file."""
        class MockViz(ExportMixin):
            def __init__(self):
                self.inputdata = {"data": "test"}
                self.inputfile = "test.toml"
                self._loaded = True

            def load(self):
                pass

        viz = MockViz()
        with tempfile.TemporaryDirectory() as tmpdir:
            output = os.path.join(tmpdir, "export.json")
            viz.export_json(output)
            assert os.path.exists(output)

    def test_mixin_export_csv(self):
        """Test mixin CSV export."""
        class MockViz(ExportMixin):
            def __init__(self):
                self.inputdata = {
                    "nodes": [
                        {"id": "a", "label": "A"},
                        {"id": "b", "label": "B"},
                    ]
                }
                self.inputfile = "test.toml"
                self._loaded = True

            def load(self):
                pass

        viz = MockViz()
        with tempfile.TemporaryDirectory() as tmpdir:
            output = os.path.join(tmpdir, "nodes.csv")
            count = viz.export_csv(output, section="nodes")
            assert count == 2
            assert os.path.exists(output)

    def test_mixin_export_csv_no_data(self):
        """Test mixin CSV export with missing section."""
        class MockViz(ExportMixin):
            def __init__(self):
                self.inputdata = {}
                self.inputfile = "test.toml"
                self._loaded = True

            def load(self):
                pass

        viz = MockViz()
        with tempfile.TemporaryDirectory() as tmpdir:
            output = os.path.join(tmpdir, "nodes.csv")
            with pytest.raises(ValueError):
                viz.export_csv(output, section="nonexistent")

    def test_mixin_get_exportable_sections(self):
        """Test mixin get_exportable_sections."""
        class MockViz(ExportMixin):
            def __init__(self):
                self.inputdata = {
                    "hosts": [{"id": "a"}],
                    "edges": [{"from": "a", "to": "b"}],
                    "config": {"key": "value"},
                }
                self.inputfile = "test.toml"
                self._loaded = True

            def load(self):
                pass

        viz = MockViz()
        sections = viz.get_exportable_sections()
        assert "hosts" in sections
        assert "edges" in sections
        assert "config" in sections


class TestReportGenerator:
    """Tests for ReportGenerator class."""

    def test_init(self):
        """Test initialization."""
        class MockViz:
            def __init__(self):
                self.inputdata = {"test": "data"}
                self.inputfile = "test.toml"
                self._loaded = True

            def load(self):
                pass

        mock = MockViz()
        gen = ReportGenerator(mock)
        assert gen.viz is mock

    def test_init_loads_data(self):
        """Test that init loads data if not loaded."""
        class MockViz:
            def __init__(self):
                self.inputdata = {"test": "data"}
                self.inputfile = "test.toml"
                self._loaded = False
                self.load_called = False

            def load(self):
                self.load_called = True
                self._loaded = True

        mock = MockViz()
        gen = ReportGenerator(mock)
        assert mock.load_called is True

    def test_generate_report(self):
        """Test report generation."""
        class MockViz(ExportMixin):
            def __init__(self):
                self.inputdata = {
                    "hosts": [{"id": "a"}],
                }
                self.inputfile = "test.toml"
                self._loaded = True

            def load(self):
                pass

            def get_graph_stats(self):
                return {"nodes": 5}

        mock = MockViz()
        gen = ReportGenerator(mock)
        with tempfile.TemporaryDirectory() as tmpdir:
            outputs = gen.generate_report(tmpdir)
            assert "json" in outputs
            assert os.path.exists(outputs["json"])

    def test_generate_report_formats(self):
        """Test report generation with specific formats."""
        class MockViz(ExportMixin):
            def __init__(self):
                self.inputdata = {"data": [1, 2, 3]}
                self.inputfile = "test.toml"
                self._loaded = True

            def load(self):
                pass

        mock = MockViz()
        gen = ReportGenerator(mock)
        with tempfile.TemporaryDirectory() as tmpdir:
            outputs = gen.generate_report(tmpdir, formats=["json", "yaml"])
            assert "json" in outputs
            assert "yaml" in outputs
            assert "md" not in outputs

    def test_generate_markdown_report(self):
        """Test Markdown report generation."""
        class MockViz:
            def __init__(self):
                self.inputdata = {
                    "hosts": [{"id": "a"}],
                    "edges": {"x": {"y": 1}},
                }
                self.inputfile = "test.toml"
                self._loaded = True

            def load(self):
                pass

            def get_graph_stats(self):
                return {"nodes": 5, "edges": 3}

        mock = MockViz()
        gen = ReportGenerator(mock)
        with tempfile.TemporaryDirectory() as tmpdir:
            outputs = gen.generate_report(tmpdir, formats=["md"])
            assert "md" in outputs
            with open(outputs["md"]) as f:
                content = f.read()
            assert "Report" in content
            assert "Statistics" in content


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
