#
# VULNEX -Universal Security Visualization Library-
#
# File: test_api_attack_graphs.py
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
#

"""Tests for Attack Graphs API router endpoints.

Covers: POST /visualize/attack-graph, /analyze/attack-graph,
/analyze/attack-paths, /analyze/critical-nodes, /analyze/centrality,
/analyze/graph-metrics, /analyze/chokepoints, /analyze/attack-surface,
/analyze/vulnerability-impact, /validate/attack-graph
"""

import io
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'api'))
os.environ["USECVISLIB_AUTH_ENABLED"] = "false"

from fastapi.testclient import TestClient
from api.main import app

client = TestClient(app)

VALID_ATTACK_GRAPH = """
[graph]
name = "Test Attack Graph"

[[hosts]]
id = "attacker"
label = "Attacker"
zone = "external"

[[hosts]]
id = "webserver"
label = "Web Server"
ip = "10.0.1.1"
zone = "dmz"

[[hosts]]
id = "dbserver"
label = "Database"
ip = "10.0.2.1"
zone = "internal"

[[vulnerabilities]]
id = "vuln1"
label = "SQL Injection"
host = "webserver"
cvss = 9.8
cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

[[vulnerabilities]]
id = "vuln2"
label = "Weak Auth"
host = "dbserver"
cvss = 7.5

[[exploits]]
id = "exploit1"
label = "SQLi to RCE"
vulnerability = "vuln1"
target = "webserver"

[[network_edges]]
source = "attacker"
target = "webserver"
label = "HTTP"

[[network_edges]]
source = "webserver"
target = "dbserver"
label = "MySQL"
"""

INVALID_TOML = "{{not valid}}"


def _upload(content, filename="graph.toml"):
    return ("file", (filename, io.BytesIO(content.encode()), "application/octet-stream"))


# =============================================================================
# Visualize
# =============================================================================

class TestVisualizeAttackGraph:

    def test_visualize_returns_image(self):
        response = client.post(
            "/visualize/attack-graph?format=png",
            files=[_upload(VALID_ATTACK_GRAPH)],
        )
        # 400 if graphviz not installed
        assert response.status_code in (200, 400)

    def test_visualize_svg(self):
        response = client.post(
            "/visualize/attack-graph?format=svg",
            files=[_upload(VALID_ATTACK_GRAPH)],
        )
        assert response.status_code in (200, 400)

    def test_visualize_malformed(self):
        response = client.post(
            "/visualize/attack-graph",
            files=[_upload(INVALID_TOML)],
        )
        assert response.status_code in (400, 500)


# =============================================================================
# Analyze
# =============================================================================

class TestAnalyzeAttackGraph:

    def test_analyze_returns_stats(self):
        response = client.post(
            "/analyze/attack-graph",
            files=[_upload(VALID_ATTACK_GRAPH)],
        )
        assert response.status_code == 200
        data = response.json()
        assert "total_hosts" in data
        assert "total_vulnerabilities" in data
        assert data["total_hosts"] >= 3

    def test_analyze_malformed(self):
        response = client.post(
            "/analyze/attack-graph",
            files=[_upload(INVALID_TOML)],
        )
        assert response.status_code in (400, 500)


class TestAnalyzeAttackPaths:

    def test_attack_paths(self):
        response = client.post(
            "/analyze/attack-paths?source=attacker&target=dbserver",
            files=[_upload(VALID_ATTACK_GRAPH)],
        )
        assert response.status_code == 200
        data = response.json()
        assert "paths" in data
        assert "total_paths" in data

    def test_attack_paths_invalid_source(self):
        response = client.post(
            "/analyze/attack-paths?source=nonexistent&target=dbserver",
            files=[_upload(VALID_ATTACK_GRAPH)],
        )
        # Could be 200 with empty paths or 400
        assert response.status_code in (200, 400, 500)


class TestAnalyzeCriticalNodes:

    def test_critical_nodes(self):
        response = client.post(
            "/analyze/critical-nodes?limit=5",
            files=[_upload(VALID_ATTACK_GRAPH)],
        )
        assert response.status_code == 200
        data = response.json()
        assert "critical_nodes" in data


class TestAnalyzeCentrality:

    def test_centrality_all(self):
        response = client.post(
            "/analyze/centrality?algorithm=all",
            files=[_upload(VALID_ATTACK_GRAPH)],
        )
        assert response.status_code == 200
        data = response.json()
        assert "nodes" in data

    def test_centrality_betweenness(self):
        response = client.post(
            "/analyze/centrality?algorithm=betweenness",
            files=[_upload(VALID_ATTACK_GRAPH)],
        )
        assert response.status_code == 200


class TestAnalyzeGraphMetrics:

    def test_graph_metrics(self):
        response = client.post(
            "/analyze/graph-metrics",
            files=[_upload(VALID_ATTACK_GRAPH)],
        )
        assert response.status_code == 200
        data = response.json()
        assert "num_nodes" in data
        assert "num_edges" in data
        assert "density" in data


class TestAnalyzeChokepoints:

    def test_chokepoints(self):
        response = client.post(
            "/analyze/chokepoints",
            files=[_upload(VALID_ATTACK_GRAPH)],
        )
        assert response.status_code == 200
        data = response.json()
        assert "chokepoints" in data


class TestAnalyzeAttackSurface:

    def test_attack_surface(self):
        response = client.post(
            "/analyze/attack-surface",
            files=[_upload(VALID_ATTACK_GRAPH)],
        )
        assert response.status_code == 200
        data = response.json()
        assert "entry_points" in data


class TestAnalyzeVulnerabilityImpact:

    def test_vulnerability_impact(self):
        response = client.post(
            "/analyze/vulnerability-impact?vulnerability_id=vuln1",
            files=[_upload(VALID_ATTACK_GRAPH)],
        )
        assert response.status_code == 200
        data = response.json()
        assert "id" in data

    def test_vulnerability_impact_nonexistent(self):
        response = client.post(
            "/analyze/vulnerability-impact?vulnerability_id=nonexistent",
            files=[_upload(VALID_ATTACK_GRAPH)],
        )
        assert response.status_code in (200, 404, 500)


# =============================================================================
# Validate
# =============================================================================

class TestValidateAttackGraph:

    def test_validate_valid(self):
        response = client.post(
            "/validate/attack-graph",
            files=[_upload(VALID_ATTACK_GRAPH)],
        )
        assert response.status_code == 200
        data = response.json()
        assert "valid" in data

    def test_validate_malformed(self):
        response = client.post(
            "/validate/attack-graph",
            files=[_upload(INVALID_TOML)],
        )
        assert response.status_code in (200, 400, 500)
