#
# VULNEX -Universal Security Visualization Library-
#
# File: test_diff.py
# Author: Simon Roses Femerling
# Created: 2025-12-25
# Last Modified: 2025-12-25
# Version: 0.3.1
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Unit tests for diff module."""

import os
import sys
import tempfile
import pytest

# Add src to path for testing
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from usecvislib.diff import (
    ChangeType,
    Change,
    DiffResult,
    VisualizationDiff,
    compare_files,
)


class TestChangeType:
    """Tests for ChangeType enum."""

    def test_enum_values(self):
        """Test enum values."""
        assert ChangeType.ADDED.value == "added"
        assert ChangeType.REMOVED.value == "removed"
        assert ChangeType.MODIFIED.value == "modified"
        assert ChangeType.UNCHANGED.value == "unchanged"


class TestChange:
    """Tests for Change dataclass."""

    def test_added_change(self):
        """Test added change."""
        change = Change(
            ChangeType.ADDED,
            "hosts.new_host",
            new_value={"label": "New Host"}
        )
        assert "+" in str(change)
        assert "hosts.new_host" in str(change)

    def test_removed_change(self):
        """Test removed change."""
        change = Change(
            ChangeType.REMOVED,
            "hosts.old_host",
            old_value={"label": "Old Host"}
        )
        assert "-" in str(change)
        assert "hosts.old_host" in str(change)

    def test_modified_change(self):
        """Test modified change."""
        change = Change(
            ChangeType.MODIFIED,
            "hosts.host.label",
            old_value="Old Label",
            new_value="New Label"
        )
        assert "~" in str(change)
        assert "->" in str(change)

    def test_to_dict(self):
        """Test dictionary conversion."""
        change = Change(
            ChangeType.ADDED,
            "path.to.item",
            new_value="value"
        )
        d = change.to_dict()
        assert d["type"] == "added"
        assert d["path"] == "path.to.item"
        assert d["new_value"] == "value"


class TestDiffResult:
    """Tests for DiffResult dataclass."""

    def test_empty_result(self):
        """Test empty diff result."""
        result = DiffResult()
        assert result.has_changes is False
        assert result.summary["total"] == 0

    def test_with_changes(self):
        """Test result with changes."""
        result = DiffResult(changes=[
            Change(ChangeType.ADDED, "a", new_value=1),
            Change(ChangeType.REMOVED, "b", old_value=2),
            Change(ChangeType.MODIFIED, "c", old_value=3, new_value=4),
        ])
        assert result.has_changes is True
        assert result.summary["added"] == 1
        assert result.summary["removed"] == 1
        assert result.summary["modified"] == 1
        assert result.summary["total"] == 3

    def test_filter_methods(self):
        """Test filter methods."""
        result = DiffResult(changes=[
            Change(ChangeType.ADDED, "a", new_value=1),
            Change(ChangeType.ADDED, "b", new_value=2),
            Change(ChangeType.REMOVED, "c", old_value=3),
        ])
        assert len(result.added()) == 2
        assert len(result.removed()) == 1
        assert len(result.modified()) == 0

    def test_by_path_prefix(self):
        """Test filtering by path prefix."""
        result = DiffResult(changes=[
            Change(ChangeType.ADDED, "hosts.a", new_value=1),
            Change(ChangeType.ADDED, "hosts.b", new_value=2),
            Change(ChangeType.ADDED, "vulns.c", new_value=3),
        ])
        hosts = result.by_path_prefix("hosts")
        assert len(hosts) == 2

    def test_to_dict(self):
        """Test dictionary conversion."""
        result = DiffResult(
            changes=[Change(ChangeType.ADDED, "x", new_value=1)],
            old_source="old.toml",
            new_source="new.toml"
        )
        d = result.to_dict()
        assert d["has_changes"] is True
        assert d["old_source"] == "old.toml"
        assert len(d["changes"]) == 1


class TestVisualizationDiff:
    """Tests for VisualizationDiff class."""

    def test_compare_identical(self):
        """Test comparing identical visualizations."""
        # Create mock visualization objects
        class MockViz:
            _loaded = True
            inputdata = {"key": "value"}
            inputfile = "test.toml"

            def load(self):
                pass

        old = MockViz()
        new = MockViz()

        diff = VisualizationDiff(old, new)
        result = diff.compare()

        assert result.has_changes is False
        assert len(result.changes) == 0

    def test_compare_added(self):
        """Test detecting additions."""
        class OldViz:
            _loaded = True
            inputdata = {"a": 1}
            inputfile = "old.toml"
            def load(self): pass

        class NewViz:
            _loaded = True
            inputdata = {"a": 1, "b": 2}
            inputfile = "new.toml"
            def load(self): pass

        diff = VisualizationDiff(OldViz(), NewViz())
        result = diff.compare()

        assert result.has_changes is True
        assert len(result.added()) == 1
        assert result.added()[0].path == "b"

    def test_compare_removed(self):
        """Test detecting removals."""
        class OldViz:
            _loaded = True
            inputdata = {"a": 1, "b": 2}
            inputfile = "old.toml"
            def load(self): pass

        class NewViz:
            _loaded = True
            inputdata = {"a": 1}
            inputfile = "new.toml"
            def load(self): pass

        diff = VisualizationDiff(OldViz(), NewViz())
        result = diff.compare()

        assert result.has_changes is True
        assert len(result.removed()) == 1
        assert result.removed()[0].path == "b"

    def test_compare_modified(self):
        """Test detecting modifications."""
        class OldViz:
            _loaded = True
            inputdata = {"a": 1}
            inputfile = "old.toml"
            def load(self): pass

        class NewViz:
            _loaded = True
            inputdata = {"a": 2}
            inputfile = "new.toml"
            def load(self): pass

        diff = VisualizationDiff(OldViz(), NewViz())
        result = diff.compare()

        assert result.has_changes is True
        assert len(result.modified()) == 1
        assert result.modified()[0].old_value == 1
        assert result.modified()[0].new_value == 2

    def test_compare_nested(self):
        """Test comparing nested structures."""
        class OldViz:
            _loaded = True
            inputdata = {"graph": {"name": "Old", "version": 1}}
            inputfile = "old.toml"
            def load(self): pass

        class NewViz:
            _loaded = True
            inputdata = {"graph": {"name": "New", "version": 1}}
            inputfile = "new.toml"
            def load(self): pass

        diff = VisualizationDiff(OldViz(), NewViz())
        result = diff.compare()

        assert result.has_changes is True
        modified = result.modified()
        assert len(modified) == 1
        assert modified[0].path == "graph.name"

    def test_compare_lists_with_ids(self):
        """Test comparing lists with id fields."""
        class OldViz:
            _loaded = True
            inputdata = {
                "hosts": [
                    {"id": "a", "label": "Host A"},
                    {"id": "b", "label": "Host B"},
                ]
            }
            inputfile = "old.toml"
            def load(self): pass

        class NewViz:
            _loaded = True
            inputdata = {
                "hosts": [
                    {"id": "a", "label": "Host A Modified"},
                    {"id": "c", "label": "Host C"},
                ]
            }
            inputfile = "new.toml"
            def load(self): pass

        diff = VisualizationDiff(OldViz(), NewViz())
        result = diff.compare()

        assert result.has_changes is True
        # Should detect: b removed, c added, a.label modified
        assert len(result.added()) >= 1
        assert len(result.removed()) >= 1

    def test_summary_report(self):
        """Test summary report generation."""
        class OldViz:
            _loaded = True
            inputdata = {"a": 1}
            inputfile = "old.toml"
            def load(self): pass

        class NewViz:
            _loaded = True
            inputdata = {"b": 2}
            inputfile = "new.toml"
            def load(self): pass

        diff = VisualizationDiff(OldViz(), NewViz())
        report = diff.summary_report()

        assert "# Visualization Diff Report" in report
        assert "Added" in report
        assert "Removed" in report

    def test_summary_report_no_changes(self):
        """Test summary report with no changes."""
        class MockViz:
            _loaded = True
            inputdata = {"a": 1}
            inputfile = "test.toml"
            def load(self): pass

        diff = VisualizationDiff(MockViz(), MockViz())
        report = diff.summary_report()

        assert "No changes detected" in report

    def test_ignore_paths(self):
        """Test ignoring specific paths."""
        class OldViz:
            _loaded = True
            inputdata = {"meta": {"version": 1}, "data": {"x": 1}}
            inputfile = "old.toml"
            def load(self): pass

        class NewViz:
            _loaded = True
            inputdata = {"meta": {"version": 2}, "data": {"x": 2}}
            inputfile = "new.toml"
            def load(self): pass

        diff = VisualizationDiff(OldViz(), NewViz())
        result = diff.compare(ignore_paths=["meta"])

        # Should only see data changes, not meta changes
        paths = [c.path for c in result.changes]
        assert all(not p.startswith("meta") for p in paths)

    def test_save_report_md(self):
        """Test saving report as Markdown."""
        class MockViz:
            _loaded = True
            inputdata = {"a": 1}
            inputfile = "test.toml"
            def load(self): pass

        with tempfile.TemporaryDirectory() as tmpdir:
            diff = VisualizationDiff(MockViz(), MockViz())
            output = os.path.join(tmpdir, "report.md")
            diff.save_report(output, format="md")
            assert os.path.exists(output)

    def test_save_report_json(self):
        """Test saving report as JSON."""
        class MockViz:
            _loaded = True
            inputdata = {"a": 1}
            inputfile = "test.toml"
            def load(self): pass

        with tempfile.TemporaryDirectory() as tmpdir:
            diff = VisualizationDiff(MockViz(), MockViz())
            output = os.path.join(tmpdir, "report.json")
            diff.save_report(output, format="json")
            assert os.path.exists(output)

            import json
            with open(output) as f:
                data = json.load(f)
            assert "summary" in data


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
