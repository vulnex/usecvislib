#
# VULNEX -Universal Security Visualization Library-
#
# File: test_attacktrees.py
# Author: Simon Roses Femerling
# Created: 2025-01-01
# Last Modified: 2025-12-23
# Version: 0.3.1
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Unit tests for attacktrees module."""

import os
import shutil
import sys
import tempfile
import pytest

# Add src to path for testing
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from usecvislib.attacktrees import AttackTrees, AttackTreeError

# Check if graphviz is installed
GRAPHVIZ_INSTALLED = shutil.which('dot') is not None


# Sample valid attack tree TOML content
VALID_ATTACK_TREE = '''
[tree]
name = "Test Attack Tree"
root = "Root"
params = { rankdir = "TB" }

[nodes]
"Root" = {style="filled", fillcolor="red"}
"Child1" = {style="filled", fillcolor="blue"}
"Child2" = {style="filled", fillcolor="green"}
"Leaf" = {style="filled", fillcolor="yellow"}

[edges]
"Root" = [{to = "Child1"}, {to = "Child2"}]
"Child1" = [{to = "Leaf"}]
'''

MINIMAL_ATTACK_TREE = '''
[tree]
name = "Minimal Tree"
root = "Root"

[nodes]
"Root" = {}

[edges]
'''


class TestAttackTreesInit:
    """Tests for AttackTrees initialization."""

    def test_init_defaults(self):
        """Test default initialization values."""
        at = AttackTrees("input.tml", "output", validate_paths=False)
        assert at.format == "png"
        assert at.styleid == "at_default"
        assert at.inputfile == "input.tml"
        assert at.outputfile == "output"

    def test_init_custom_format(self):
        """Test custom format initialization."""
        at = AttackTrees("input.tml", "output", format="svg", validate_paths=False)
        assert at.format == "svg"

    def test_init_custom_style(self):
        """Test custom style initialization."""
        at = AttackTrees("input.tml", "output", styleid="custom", validate_paths=False)
        assert at.styleid == "custom"


class TestAttackTreesLoad:
    """Tests for attack tree data loading."""

    def test_load_valid_file(self):
        """Test loading a valid attack tree file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(VALID_ATTACK_TREE)
            f.flush()
            try:
                at = AttackTrees(f.name, "output", validate_paths=False)
                at.load()
                data = at.inputdata
                assert "tree" in data
                assert "nodes" in data
                assert "edges" in data
                assert data["tree"]["name"] == "Test Attack Tree"
            finally:
                os.unlink(f.name)

    def test_load_missing_file(self):
        """Test loading a non-existent file."""
        at = AttackTrees("/nonexistent/file.tml", "output", validate_paths=False)
        with pytest.raises(AttackTreeError):
            at.load()


class TestAttackTreesRender:
    """Tests for attack tree rendering."""

    def test_render_valid_tree(self):
        """Test rendering a valid attack tree."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(VALID_ATTACK_TREE)
            f.flush()
            try:
                at = AttackTrees(f.name, "output", validate_paths=False)
                at.load()
                at.Render()
                assert at.dot is not None
            finally:
                os.unlink(f.name)

    def test_render_without_load(self):
        """Test rendering without loading data first."""
        at = AttackTrees("/nonexistent/input.tml", "output", validate_paths=False)
        with pytest.raises(AttackTreeError):
            at.Render()

    def test_render_missing_tree_section(self):
        """Test rendering with missing tree section."""
        invalid_tree = '''
[nodes]
"Root" = {}
[edges]
'''
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(invalid_tree)
            f.flush()
            try:
                at = AttackTrees(f.name, "output", validate_paths=False)
                at.load()
                with pytest.raises(AttackTreeError, match="Missing 'tree' section"):
                    at.Render()
            finally:
                os.unlink(f.name)

    def test_render_missing_root(self):
        """Test rendering with missing root node."""
        invalid_tree = '''
[tree]
name = "No Root Tree"

[nodes]
"Node1" = {}

[edges]
'''
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(invalid_tree)
            f.flush()
            try:
                at = AttackTrees(f.name, "output", validate_paths=False)
                at.load()
                with pytest.raises(AttackTreeError, match="Missing 'root'"):
                    at.Render()
            finally:
                os.unlink(f.name)


class TestAttackTreesDraw:
    """Tests for attack tree output generation."""

    def test_draw_without_render(self):
        """Test drawing without rendering first."""
        at = AttackTrees("/nonexistent/input.tml", "output", validate_paths=False)
        with pytest.raises(AttackTreeError):
            at.draw()

    @pytest.mark.skipif(not GRAPHVIZ_INSTALLED, reason="Graphviz not installed")
    def test_full_build(self):
        """Test complete build process."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(VALID_ATTACK_TREE)
            f.flush()
            try:
                with tempfile.TemporaryDirectory() as tmpdir:
                    output = os.path.join(tmpdir, "output")
                    at = AttackTrees(f.name, output, format="dot")
                    at.BuildAttackTree()
                    # Check that output file was created
                    assert os.path.exists(f"{output}.dot")
            finally:
                os.unlink(f.name)


class TestAttackTreesStats:
    """Tests for attack tree statistics."""

    def test_get_tree_stats(self):
        """Test getting tree statistics."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(VALID_ATTACK_TREE)
            f.flush()
            try:
                at = AttackTrees(f.name, "output", validate_paths=False)
                stats = at.get_tree_stats()
                assert stats["name"] == "Test Attack Tree"
                assert stats["root"] == "Root"
                assert stats["total_nodes"] == 4
                assert stats["total_edges"] == 3
            finally:
                os.unlink(f.name)


class TestAttackTreesValidation:
    """Tests for attack tree validation."""

    def test_validate_valid_tree(self):
        """Test validation of a valid tree."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(VALID_ATTACK_TREE)
            f.flush()
            try:
                at = AttackTrees(f.name, "output", validate_paths=False)
                errors = at.validate()
                assert len(errors) == 0
            finally:
                os.unlink(f.name)

    def test_validate_orphan_nodes(self):
        """Test detection of orphan nodes."""
        tree_with_orphan = '''
[tree]
name = "Tree with Orphan"
root = "Root"

[nodes]
"Root" = {}
"Child" = {}
"Orphan" = {}

[edges]
"Root" = [{to = "Child"}]
'''
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(tree_with_orphan)
            f.flush()
            try:
                at = AttackTrees(f.name, "output", validate_paths=False)
                errors = at.validate()
                assert any("Orphan" in error for error in errors)
            finally:
                os.unlink(f.name)

    def test_validate_undefined_edge_target(self):
        """Test detection of undefined edge targets."""
        tree_with_undefined = '''
[tree]
name = "Tree with Undefined Target"
root = "Root"

[nodes]
"Root" = {}

[edges]
"Root" = [{to = "Undefined"}]
'''
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(tree_with_undefined)
            f.flush()
            try:
                at = AttackTrees(f.name, "output", validate_paths=False)
                errors = at.validate()
                assert any("Undefined" in error for error in errors)
            finally:
                os.unlink(f.name)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
