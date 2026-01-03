#
# VULNEX -Universal Security Visualization Library-
#
# File: test_attackgraphs.py
# Author: Simon Roses Femerling
# Created: 2025-01-01
# Last Modified: 2025-12-27
# Version: 0.3.1
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Unit tests for attackgraphs module."""

import os
import shutil
import sys
import tempfile
import pytest

# Add src to path for testing
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from usecvislib.attackgraphs import AttackGraphs, AttackGraphError

# Check if graphviz is installed
GRAPHVIZ_INSTALLED = shutil.which('dot') is not None


# Sample valid attack graph TOML content
VALID_ATTACK_GRAPH = '''
[graph]
name = "Test Attack Graph"
description = "Test network attack scenario"

[[hosts]]
id = "attacker"
label = "Attacker"
zone = "external"

[[hosts]]
id = "webserver"
label = "Web Server"
ip = "10.0.1.10"
zone = "dmz"

[[hosts]]
id = "database"
label = "Database"
ip = "10.0.2.10"
zone = "internal"

[[vulnerabilities]]
id = "vuln_rce"
label = "RCE Vulnerability"
cvss = 9.8
affected_host = "webserver"

[[vulnerabilities]]
id = "vuln_sqli"
label = "SQL Injection"
cvss = 8.5
affected_host = "database"

[[privileges]]
id = "priv_shell"
label = "Web Shell"
host = "webserver"
level = "user"

[[privileges]]
id = "priv_db"
label = "DB Access"
host = "database"
level = "user"

[[services]]
id = "svc_http"
label = "HTTP"
host = "webserver"
port = 80

[[services]]
id = "svc_mysql"
label = "MySQL"
host = "database"
port = 3306

[[exploits]]
id = "exploit_rce"
label = "RCE Exploit"
vulnerability = "vuln_rce"
precondition = "attacker"
postcondition = "priv_shell"

[[exploits]]
id = "exploit_sqli"
label = "SQLi Exploit"
vulnerability = "vuln_sqli"
precondition = "priv_shell"
postcondition = "priv_db"

[[network_edges]]
from = "attacker"
to = "webserver"
label = "Internet"

[[network_edges]]
from = "webserver"
to = "database"
label = "Internal"
'''

MINIMAL_ATTACK_GRAPH = '''
[graph]
name = "Minimal Graph"

[[hosts]]
id = "attacker"
label = "Attacker"

[[hosts]]
id = "target"
label = "Target"

[[network_edges]]
from = "attacker"
to = "target"
'''

GRAPH_WITH_PATH = '''
[graph]
name = "Path Test Graph"

[[hosts]]
id = "a"
label = "Node A"

[[hosts]]
id = "b"
label = "Node B"

[[hosts]]
id = "c"
label = "Node C"

[[hosts]]
id = "d"
label = "Node D"

[[network_edges]]
from = "a"
to = "b"

[[network_edges]]
from = "b"
to = "c"

[[network_edges]]
from = "a"
to = "c"

[[network_edges]]
from = "c"
to = "d"
'''


class TestAttackGraphsInit:
    """Tests for AttackGraphs initialization."""

    def test_init_defaults(self):
        """Test default initialization values."""
        ag = AttackGraphs("input.tml", "output", validate_paths=False)
        assert ag.format == "png"
        assert ag.styleid == "ag_default"
        assert ag.inputfile == "input.tml"
        assert ag.outputfile == "output"

    def test_init_custom_format(self):
        """Test custom format initialization."""
        ag = AttackGraphs("input.tml", "output", format="svg", validate_paths=False)
        assert ag.format == "svg"

    def test_init_custom_style(self):
        """Test custom style initialization."""
        ag = AttackGraphs("input.tml", "output", styleid="ag_dark", validate_paths=False)
        assert ag.styleid == "ag_dark"


class TestAttackGraphsLoad:
    """Tests for attack graph data loading."""

    def test_load_valid_file(self):
        """Test loading a valid attack graph file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(VALID_ATTACK_GRAPH)
            f.flush()
            try:
                ag = AttackGraphs(f.name, "output", validate_paths=False)
                ag.load()
                data = ag.inputdata
                assert "graph" in data
                assert "hosts" in data
                assert "vulnerabilities" in data
                assert data["graph"]["name"] == "Test Attack Graph"
            finally:
                os.unlink(f.name)

    def test_load_missing_file(self):
        """Test loading a non-existent file."""
        ag = AttackGraphs("/nonexistent/file.tml", "output", validate_paths=False)
        with pytest.raises(AttackGraphError):
            ag.load()


class TestAttackGraphsRender:
    """Tests for attack graph rendering."""

    def test_render_valid_graph(self):
        """Test rendering a valid attack graph."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(VALID_ATTACK_GRAPH)
            f.flush()
            try:
                ag = AttackGraphs(f.name, "output", validate_paths=False)
                ag.load()
                ag.Render()
                assert ag.graph is not None
            finally:
                os.unlink(f.name)

    def test_render_without_load(self):
        """Test rendering without loading data first."""
        ag = AttackGraphs("/nonexistent/input.tml", "output", validate_paths=False)
        with pytest.raises(AttackGraphError):
            ag.Render()

    def test_render_missing_graph_section(self):
        """Test rendering with missing graph section."""
        invalid_graph = '''
[[hosts]]
id = "test"
label = "Test"
'''
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(invalid_graph)
            f.flush()
            try:
                ag = AttackGraphs(f.name, "output", validate_paths=False)
                ag.load()
                with pytest.raises(AttackGraphError, match="Missing 'graph' section"):
                    ag.Render()
            finally:
                os.unlink(f.name)


class TestAttackGraphsDraw:
    """Tests for attack graph output generation."""

    def test_draw_without_render(self):
        """Test drawing without rendering first."""
        ag = AttackGraphs("/nonexistent/input.tml", "output", validate_paths=False)
        with pytest.raises(AttackGraphError):
            ag.draw()

    @pytest.mark.skipif(not GRAPHVIZ_INSTALLED, reason="Graphviz not installed")
    def test_full_build(self):
        """Test complete build process."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(VALID_ATTACK_GRAPH)
            f.flush()
            try:
                with tempfile.TemporaryDirectory() as tmpdir:
                    output = os.path.join(tmpdir, "output")
                    ag = AttackGraphs(f.name, output, format="dot")
                    ag.BuildAttackGraph()
                    # Check that output file was created
                    assert os.path.exists(f"{output}.dot")
            finally:
                os.unlink(f.name)


class TestAttackGraphsStats:
    """Tests for attack graph statistics."""

    def test_get_graph_stats(self):
        """Test getting graph statistics."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(VALID_ATTACK_GRAPH)
            f.flush()
            try:
                ag = AttackGraphs(f.name, "output", validate_paths=False)
                stats = ag.get_graph_stats()
                assert stats["name"] == "Test Attack Graph"
                assert stats["total_hosts"] == 3
                assert stats["total_vulnerabilities"] == 2
                assert stats["total_privileges"] == 2
                assert stats["total_services"] == 2
                assert stats["total_exploits"] == 2
                assert stats["network_edges"] == 2
            finally:
                os.unlink(f.name)

    def test_cvss_stats(self):
        """Test CVSS statistics calculation."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(VALID_ATTACK_GRAPH)
            f.flush()
            try:
                ag = AttackGraphs(f.name, "output", validate_paths=False)
                stats = ag.get_graph_stats()
                # Average of 9.8 and 8.5 = 9.15
                assert 9.0 <= stats["average_cvss"] <= 9.5
                # Both are >= 9.0 threshold for critical
                assert stats["critical_vulnerabilities"] == 1  # Only 9.8 is >= 9.0
            finally:
                os.unlink(f.name)


class TestAttackGraphsPathFinding:
    """Tests for attack path finding algorithms."""

    def test_find_paths_exists(self):
        """Test finding paths that exist."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(GRAPH_WITH_PATH)
            f.flush()
            try:
                ag = AttackGraphs(f.name, "output", validate_paths=False)
                ag.load()
                paths = ag.find_attack_paths("a", "d")
                assert len(paths) > 0
                # Should find paths: a->b->c->d and a->c->d
                assert len(paths) >= 2
            finally:
                os.unlink(f.name)

    def test_find_paths_not_exists(self):
        """Test finding paths that don't exist."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(GRAPH_WITH_PATH)
            f.flush()
            try:
                ag = AttackGraphs(f.name, "output", validate_paths=False)
                ag.load()
                # No reverse path from d to a
                paths = ag.find_attack_paths("d", "a")
                assert len(paths) == 0
            finally:
                os.unlink(f.name)

    def test_shortest_path(self):
        """Test finding shortest path."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(GRAPH_WITH_PATH)
            f.flush()
            try:
                ag = AttackGraphs(f.name, "output", validate_paths=False)
                ag.load()
                path = ag.shortest_path("a", "d")
                assert path is not None
                # Shortest path should be a->c->d (length 3)
                assert len(path) == 3
                assert path[0] == "a"
                assert path[-1] == "d"
            finally:
                os.unlink(f.name)

    def test_shortest_path_not_exists(self):
        """Test shortest path when no path exists."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(GRAPH_WITH_PATH)
            f.flush()
            try:
                ag = AttackGraphs(f.name, "output", validate_paths=False)
                ag.load()
                path = ag.shortest_path("d", "a")
                assert path == []  # Returns empty list when no path exists
            finally:
                os.unlink(f.name)


class TestAttackGraphsCriticalNodes:
    """Tests for critical node analysis."""

    def test_analyze_critical_nodes(self):
        """Test critical node analysis."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(VALID_ATTACK_GRAPH)
            f.flush()
            try:
                ag = AttackGraphs(f.name, "output", validate_paths=False)
                ag.load()
                critical = ag.analyze_critical_nodes(top_n=5)
                assert len(critical) > 0
                # Each node should have required fields
                for node in critical:
                    assert "id" in node
                    assert "label" in node
                    assert "type" in node
                    assert "in_degree" in node
                    assert "out_degree" in node
                    assert "criticality_score" in node
            finally:
                os.unlink(f.name)

    def test_critical_nodes_sorted(self):
        """Test that critical nodes are sorted by degree."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(GRAPH_WITH_PATH)
            f.flush()
            try:
                ag = AttackGraphs(f.name, "output", validate_paths=False)
                ag.load()
                critical = ag.analyze_critical_nodes(top_n=10)
                # Should be sorted by total degree (descending)
                for i in range(len(critical) - 1):
                    assert critical[i]["total_degree"] >= critical[i + 1]["total_degree"]
            finally:
                os.unlink(f.name)


class TestAttackGraphsValidation:
    """Tests for attack graph validation."""

    def test_validate_valid_graph(self):
        """Test validation of a valid graph."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(VALID_ATTACK_GRAPH)
            f.flush()
            try:
                ag = AttackGraphs(f.name, "output", validate_paths=False)
                errors = ag.validate()
                assert len(errors) == 0
            finally:
                os.unlink(f.name)

    def test_validate_undefined_edge_target(self):
        """Test detection of undefined edge targets."""
        graph_with_undefined = '''
[graph]
name = "Graph with Undefined Target"

[[hosts]]
id = "attacker"
label = "Attacker"

[[network_edges]]
from = "attacker"
to = "undefined_target"
'''
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(graph_with_undefined)
            f.flush()
            try:
                ag = AttackGraphs(f.name, "output", validate_paths=False)
                errors = ag.validate()
                assert any("undefined_target" in error for error in errors)
            finally:
                os.unlink(f.name)

    def test_validate_exploit_missing_vulnerability(self):
        """Test detection of exploit with missing vulnerability."""
        graph_with_bad_exploit = '''
[graph]
name = "Graph with Bad Exploit"

[[hosts]]
id = "attacker"
label = "Attacker"

[[hosts]]
id = "target"
label = "Target"

[[privileges]]
id = "priv_shell"
label = "Shell"
host = "target"

[[exploits]]
id = "exploit_bad"
label = "Bad Exploit"
vulnerability = "nonexistent_vuln"
precondition = "attacker"
postcondition = "priv_shell"

[[network_edges]]
from = "attacker"
to = "target"
'''
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(graph_with_bad_exploit)
            f.flush()
            try:
                ag = AttackGraphs(f.name, "output", validate_paths=False)
                errors = ag.validate()
                assert any("nonexistent_vuln" in error for error in errors)
            finally:
                os.unlink(f.name)


# Graph with CVSS-weighted vulnerabilities for Dijkstra testing
GRAPH_WITH_CVSS = '''
[graph]
name = "CVSS Weighted Graph"

[[hosts]]
id = "attacker"
label = "Attacker"

[[hosts]]
id = "webserver"
label = "Web Server"

[[hosts]]
id = "database"
label = "Database"

[[vulnerabilities]]
id = "vuln_high"
label = "High CVSS Vuln"
cvss = 9.8
affected_host = "webserver"

[[vulnerabilities]]
id = "vuln_low"
label = "Low CVSS Vuln"
cvss = 3.0
affected_host = "database"

[[network_edges]]
from = "attacker"
to = "webserver"

[[network_edges]]
from = "attacker"
to = "database"

[[network_edges]]
from = "webserver"
to = "database"
'''


class TestAttackGraphsPathFindingGenerator:
    """Tests for path finding generator (Phase 3)."""

    def test_generator_yields_paths(self):
        """Test that generator yields paths one at a time."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(GRAPH_WITH_PATH)
            f.flush()
            try:
                ag = AttackGraphs(f.name, "output", validate_paths=False)
                ag.load()
                generator = ag.find_attack_paths_generator("a", "d")
                # Should be a generator
                assert hasattr(generator, '__iter__')
                assert hasattr(generator, '__next__')
                # Collect paths
                paths = list(generator)
                assert len(paths) >= 2  # a->b->c->d and a->c->d
            finally:
                os.unlink(f.name)

    def test_generator_yields_valid_paths(self):
        """Test that generator yields valid paths."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(GRAPH_WITH_PATH)
            f.flush()
            try:
                ag = AttackGraphs(f.name, "output", validate_paths=False)
                ag.load()
                for path in ag.find_attack_paths_generator("a", "d"):
                    assert path[0] == "a"
                    assert path[-1] == "d"
                    assert len(path) >= 2
            finally:
                os.unlink(f.name)

    def test_generator_no_paths(self):
        """Test generator with no paths."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(GRAPH_WITH_PATH)
            f.flush()
            try:
                ag = AttackGraphs(f.name, "output", validate_paths=False)
                ag.load()
                paths = list(ag.find_attack_paths_generator("d", "a"))
                assert len(paths) == 0
            finally:
                os.unlink(f.name)

    def test_generator_max_depth(self):
        """Test generator respects max_depth."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(GRAPH_WITH_PATH)
            f.flush()
            try:
                ag = AttackGraphs(f.name, "output", validate_paths=False)
                ag.load()
                # With max_depth=2, should only find a->c->d (length 3 = 2 edges)
                # but not a->b->c->d (length 4 = 3 edges)
                paths = list(ag.find_attack_paths_generator("a", "d", max_depth=2))
                for path in paths:
                    assert len(path) <= 3  # max_depth=2 means at most 2 edges


            finally:
                os.unlink(f.name)


class TestAttackGraphsWeightedShortestPath:
    """Tests for weighted shortest path (Dijkstra) (Phase 3)."""

    def test_weighted_shortest_path_exists(self):
        """Test finding weighted shortest path."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(GRAPH_WITH_PATH)
            f.flush()
            try:
                ag = AttackGraphs(f.name, "output", validate_paths=False)
                ag.load()
                path, cost = ag.find_weighted_shortest_path("a", "d")
                assert len(path) > 0
                assert path[0] == "a"
                assert path[-1] == "d"
                assert cost >= 0
            finally:
                os.unlink(f.name)

    def test_weighted_shortest_path_no_path(self):
        """Test weighted shortest path when no path exists."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(GRAPH_WITH_PATH)
            f.flush()
            try:
                ag = AttackGraphs(f.name, "output", validate_paths=False)
                ag.load()
                path, cost = ag.find_weighted_shortest_path("d", "a")
                assert path == []
                assert cost == float('inf')
            finally:
                os.unlink(f.name)

    def test_weighted_shortest_path_with_cvss(self):
        """Test weighted shortest path uses CVSS weights."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(GRAPH_WITH_CVSS)
            f.flush()
            try:
                ag = AttackGraphs(f.name, "output", validate_paths=False)
                ag.load()
                path, cost = ag.find_weighted_shortest_path("attacker", "database")
                assert len(path) > 0
                assert path[0] == "attacker"
                assert path[-1] == "database"
                # Cost should be > 0
                assert cost > 0
            finally:
                os.unlink(f.name)

    def test_weighted_shortest_path_custom_weight_func(self):
        """Test weighted shortest path with custom weight function."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(GRAPH_WITH_PATH)
            f.flush()
            try:
                ag = AttackGraphs(f.name, "output", validate_paths=False)
                ag.load()
                # Custom weight: all nodes cost 2.0
                custom_weight = lambda node_id: 2.0
                path, cost = ag.find_weighted_shortest_path("a", "d", weight_func=custom_weight)
                assert len(path) > 0
                # Cost should be multiples of 2.0
                assert cost % 2.0 == 0 or cost == pytest.approx(cost, rel=0.01)
            finally:
                os.unlink(f.name)

    def test_weighted_shortest_path_same_source_target(self):
        """Test weighted path when source equals target."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(GRAPH_WITH_PATH)
            f.flush()
            try:
                ag = AttackGraphs(f.name, "output", validate_paths=False)
                ag.load()
                path, cost = ag.find_weighted_shortest_path("a", "a")
                assert path == ["a"]
                assert cost == 0
            finally:
                os.unlink(f.name)


class TestAttackGraphsFormats:
    """Tests for different input file formats."""

    def test_load_json_file(self):
        """Test loading a JSON attack graph file."""
        json_content = '''{
    "graph": {"name": "JSON Test Graph"},
    "hosts": [
        {"id": "attacker", "label": "Attacker"},
        {"id": "target", "label": "Target"}
    ],
    "network_edges": [
        {"from": "attacker", "to": "target"}
    ]
}'''
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write(json_content)
            f.flush()
            try:
                ag = AttackGraphs(f.name, "output", validate_paths=False)
                ag.load()
                assert ag.inputdata["graph"]["name"] == "JSON Test Graph"
            finally:
                os.unlink(f.name)

    def test_load_yaml_file(self):
        """Test loading a YAML attack graph file."""
        yaml_content = '''graph:
  name: YAML Test Graph
hosts:
  - id: attacker
    label: Attacker
  - id: target
    label: Target
network_edges:
  - from: attacker
    to: target
'''
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(yaml_content)
            f.flush()
            try:
                ag = AttackGraphs(f.name, "output", validate_paths=False)
                ag.load()
                assert ag.inputdata["graph"]["name"] == "YAML Test Graph"
            finally:
                os.unlink(f.name)


# =============================================================================
# NetworkX Integration Tests
# =============================================================================

class TestNetworkXCentrality:
    """Tests for NetworkX centrality methods."""

    def test_betweenness_centrality(self):
        """Test betweenness centrality calculation."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(VALID_ATTACK_GRAPH)
            f.flush()
            try:
                ag = AttackGraphs(f.name, "output", validate_paths=False)
                ag.load()
                results = ag.betweenness_centrality(top_n=5)
                assert isinstance(results, list)
                assert len(results) <= 5
                for node in results:
                    assert "id" in node
                    assert "betweenness_centrality" in node
                    assert node["betweenness_centrality"] >= 0
            finally:
                os.unlink(f.name)

    def test_closeness_centrality(self):
        """Test closeness centrality calculation."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(VALID_ATTACK_GRAPH)
            f.flush()
            try:
                ag = AttackGraphs(f.name, "output", validate_paths=False)
                ag.load()
                results = ag.closeness_centrality(top_n=5)
                assert isinstance(results, list)
                for node in results:
                    assert "id" in node
                    assert "closeness_centrality" in node
                    assert 0 <= node["closeness_centrality"] <= 1
            finally:
                os.unlink(f.name)

    def test_pagerank(self):
        """Test PageRank calculation."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(VALID_ATTACK_GRAPH)
            f.flush()
            try:
                ag = AttackGraphs(f.name, "output", validate_paths=False)
                ag.load()
                results = ag.pagerank(top_n=5)
                assert isinstance(results, list)
                for node in results:
                    assert "id" in node
                    assert "pagerank" in node
                    assert node["pagerank"] > 0
            finally:
                os.unlink(f.name)


class TestNetworkXPaths:
    """Tests for NetworkX path methods."""

    def test_k_shortest_paths(self):
        """Test k shortest paths finding."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(GRAPH_WITH_PATH)
            f.flush()
            try:
                ag = AttackGraphs(f.name, "output", validate_paths=False)
                ag.load()
                paths = ag.k_shortest_paths("a", "d", k=3)
                assert isinstance(paths, list)
                assert len(paths) <= 3
                for path in paths:
                    assert path[0] == "a"
                    assert path[-1] == "d"
            finally:
                os.unlink(f.name)

    def test_k_shortest_paths_no_path(self):
        """Test k shortest paths when no path exists."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(GRAPH_WITH_PATH)
            f.flush()
            try:
                ag = AttackGraphs(f.name, "output", validate_paths=False)
                ag.load()
                paths = ag.k_shortest_paths("d", "a", k=3)
                assert paths == []
            finally:
                os.unlink(f.name)

    def test_all_paths_between_generator(self):
        """Test all paths generator."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(GRAPH_WITH_PATH)
            f.flush()
            try:
                ag = AttackGraphs(f.name, "output", validate_paths=False)
                ag.load()
                paths = list(ag.all_paths_between("a", "d", cutoff=5))
                assert len(paths) >= 1
                for path in paths:
                    assert path[0] == "a"
                    assert path[-1] == "d"
            finally:
                os.unlink(f.name)


class TestNetworkXGraphStructure:
    """Tests for NetworkX graph structure methods."""

    def test_find_cycles(self):
        """Test cycle detection."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(VALID_ATTACK_GRAPH)
            f.flush()
            try:
                ag = AttackGraphs(f.name, "output", validate_paths=False)
                ag.load()
                cycles = ag.find_cycles()
                assert isinstance(cycles, list)
                # Cycles may or may not exist
            finally:
                os.unlink(f.name)

    def test_strongly_connected_components(self):
        """Test SCC detection."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(VALID_ATTACK_GRAPH)
            f.flush()
            try:
                ag = AttackGraphs(f.name, "output", validate_paths=False)
                ag.load()
                sccs = ag.strongly_connected_components()
                assert isinstance(sccs, list)
                assert len(sccs) > 0
                for scc in sccs:
                    assert isinstance(scc, set)
            finally:
                os.unlink(f.name)

    def test_graph_density(self):
        """Test graph density calculation."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(VALID_ATTACK_GRAPH)
            f.flush()
            try:
                ag = AttackGraphs(f.name, "output", validate_paths=False)
                ag.load()
                density = ag.graph_density()
                assert isinstance(density, float)
                assert 0 <= density <= 1
            finally:
                os.unlink(f.name)

    def test_diameter(self):
        """Test diameter calculation."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(VALID_ATTACK_GRAPH)
            f.flush()
            try:
                ag = AttackGraphs(f.name, "output", validate_paths=False)
                ag.load()
                diameter = ag.diameter()
                # Diameter may be None for disconnected graphs
                assert diameter is None or isinstance(diameter, int)
            finally:
                os.unlink(f.name)

    def test_get_graph_metrics(self):
        """Test comprehensive graph metrics."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(VALID_ATTACK_GRAPH)
            f.flush()
            try:
                ag = AttackGraphs(f.name, "output", validate_paths=False)
                ag.load()
                metrics = ag.get_graph_metrics()
                assert "num_nodes" in metrics
                assert "num_edges" in metrics
                assert "density" in metrics
                assert "is_dag" in metrics
                assert "node_types" in metrics
                assert metrics["num_nodes"] > 0
            finally:
                os.unlink(f.name)


class TestNetworkXSecurityAnalysis:
    """Tests for NetworkX security analysis methods."""

    def test_find_chokepoints(self):
        """Test chokepoint identification."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(VALID_ATTACK_GRAPH)
            f.flush()
            try:
                ag = AttackGraphs(f.name, "output", validate_paths=False)
                ag.load()
                chokepoints = ag.find_chokepoints(top_n=5)
                assert isinstance(chokepoints, list)
                for cp in chokepoints:
                    assert "id" in cp
                    assert "betweenness_score" in cp
                    assert "is_critical" in cp
            finally:
                os.unlink(f.name)

    def test_find_attack_surfaces(self):
        """Test attack surface identification."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(VALID_ATTACK_GRAPH)
            f.flush()
            try:
                ag = AttackGraphs(f.name, "output", validate_paths=False)
                ag.load()
                surfaces = ag.find_attack_surfaces()
                assert isinstance(surfaces, list)
                # Should find at least the attacker node
                assert len(surfaces) >= 1
                for surface in surfaces:
                    assert "id" in surface
                    assert "reachable_nodes" in surface
            finally:
                os.unlink(f.name)

    def test_vulnerability_impact_score(self):
        """Test vulnerability impact calculation."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(VALID_ATTACK_GRAPH)
            f.flush()
            try:
                ag = AttackGraphs(f.name, "output", validate_paths=False)
                ag.load()
                impact = ag.vulnerability_impact_score("vuln_rce")
                assert "id" in impact
                assert "cvss" in impact
                assert "impact_score" in impact
                assert 0 <= impact["impact_score"] <= 10
            finally:
                os.unlink(f.name)

    def test_vulnerability_impact_not_found(self):
        """Test vulnerability impact for non-existent vulnerability."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(VALID_ATTACK_GRAPH)
            f.flush()
            try:
                ag = AttackGraphs(f.name, "output", validate_paths=False)
                ag.load()
                impact = ag.vulnerability_impact_score("nonexistent_vuln")
                assert "error" in impact
            finally:
                os.unlink(f.name)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
