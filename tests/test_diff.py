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


@pytest.mark.parametrize(
    "viz_type,template",
    [
        ("kill_chain", "kill-chains/apt_intrusion.tml"),
        ("vuln_tree", "vuln-trees/java_log4shell.tml"),
        ("maestro", "maestro/single-agent-rag.toml"),
        ("component_diagram", "architecture/component-diagram-example.json"),
    ],
)
def test_compare_files_supports_newer_modules(tmp_path, viz_type, template):
    # compare_files() only knew attack trees, attack graphs and threat models.
    import shutil

    from usecvislib.diff import compare_files

    src = os.path.join(os.path.dirname(__file__), "..", "templates", template)
    old = tmp_path / f"old{os.path.splitext(template)[1]}"
    new = tmp_path / f"new{os.path.splitext(template)[1]}"
    shutil.copy(src, old)
    shutil.copy(src, new)
    assert not compare_files(str(old), str(new), viz_type).has_changes

    # Rename the first named element: the diff must report the change
    text = new.read_text(encoding="utf-8")
    first_name = text.split('name = "', 1)[1].split('"', 1)[0] if 'name = "' in text else None
    if first_name is None:
        first_name = text.split('"name": "', 1)[1].split('"', 1)[0]
    new.write_text(text.replace(first_name, first_name + " v2"), encoding="utf-8")
    changes = compare_files(str(old), str(new), viz_type).changes
    assert changes


# =============================================================================
# compare_series
# =============================================================================


def _snapshot(path, hosts, vulns):
    """Write a minimal attack-graph snapshot: host ids and {vuln_id: (host, cvss)}."""
    lines = ['[graph]\nname = "Engagement"\n']
    for host in hosts:
        lines.append(f'[hosts.{host}]\nlabel = "{host}"\n')
    for vuln, (host, cvss) in vulns.items():
        lines.append(f'[vulnerabilities.{vuln}]\nlabel = "{vuln}"\nhost = "{host}"\ncvss = {cvss}\n')
    path.write_text("\n".join(lines), encoding="utf-8")
    return str(path)


class TestCompareSeries:
    @pytest.fixture
    def series_files(self, tmp_path):
        # day 1: two hosts; day 2: a third host and a vuln; day 3: web01 gone, vuln re-scored
        return [
            _snapshot(tmp_path / "day1.toml", ["web01", "db01"], {}),
            _snapshot(tmp_path / "day2.toml", ["web01", "db01", "app01"], {"cve1": ("app01", 7.5)}),
            _snapshot(tmp_path / "day3.toml", ["db01", "app01"], {"cve1": ("app01", 9.8)}),
        ]

    def test_one_step_per_consecutive_pair(self, series_files):
        from usecvislib.diff import compare_series

        series = compare_series(series_files, "attack_graph")
        assert len(series.steps) == 2
        assert [c.path for c in series.steps[0].added()] == ["hosts.app01", "vulnerabilities.cve1"]
        step2 = {c.path: c.change_type for c in series.steps[1].changes}
        assert step2 == {"hosts.web01": ChangeType.REMOVED, "vulnerabilities.cve1.cvss": ChangeType.MODIFIED}
        assert series.steps[1].old_source == series_files[1]

    def test_overall_is_net_first_to_last(self, series_files):
        from usecvislib.diff import compare_series

        overall = compare_series(series_files, "attack_graph").overall
        changes = {c.path: c.change_type for c in overall.changes}
        assert changes == {
            "hosts.app01": ChangeType.ADDED,
            "hosts.web01": ChangeType.REMOVED,
            "vulnerabilities.cve1": ChangeType.ADDED,
        }
        # The day 2 -> day 3 re-score is folded into the net addition, not a separate change
        assert overall.old_source == series_files[0] and overall.new_source == series_files[-1]

    def test_summary_and_to_dict(self, series_files):
        import json

        from usecvislib.diff import compare_series

        series = compare_series(series_files, "attack_graph")
        assert series.has_changes
        assert series.summary["versions"] == 3
        assert [s["total"] for s in series.summary["steps"]] == [2, 2]
        data = json.loads(json.dumps(series.to_dict()))
        assert data["sources"] == series_files
        assert len(data["steps"]) == 2 and data["overall"]["summary"]["total"] == 3

    def test_unchanged_series(self, series_files):
        from usecvislib.diff import compare_series

        series = compare_series([series_files[0], series_files[0]], "attack_graph")
        assert not series.has_changes and not series.overall.has_changes

    def test_ignore_paths_apply_to_every_step(self, series_files):
        from usecvislib.diff import compare_series

        series = compare_series(series_files, "attack_graph", ignore_paths=["vulnerabilities"])
        assert all(not c.path.startswith("vulnerabilities") for step in series.steps for c in step.changes)

    def test_needs_two_files(self, series_files):
        from usecvislib.diff import compare_series

        with pytest.raises(ValueError, match="at least two"):
            compare_series(series_files[:1], "attack_graph")

    def test_unknown_type(self, series_files):
        from usecvislib.diff import compare_series

        with pytest.raises(ValueError, match="Unknown type"):
            compare_series(series_files, "binary")
