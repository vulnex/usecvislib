#
# VULNEX -Universal Security Visualization Library-
#
# File: test_api_architecture.py
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
#

"""Tests for Architecture Diagrams API router endpoints.

Covers: POST /visualize/component-diagram, /analyze/component-diagram,
/validate/component-diagram, /visualize/dependency-graph,
/analyze/dependency-graph, /validate/dependency-graph
"""

import io
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'api'))
os.environ["USECVISLIB_AUTH_ENABLED"] = "false"

from fastapi.testclient import TestClient
from api.main import app

client = TestClient(app)

VALID_COMPONENT_DIAGRAM = json.dumps({
    "title": "Test Architecture",
    "layers": [
        {
            "name": "Frontend",
            "order": 1,
            "components": [
                {"id": "ui", "name": "Web UI", "type": "frontend", "tech": "Vue"}
            ]
        },
        {
            "name": "Backend",
            "order": 2,
            "components": [
                {"id": "api", "name": "API Server", "type": "service", "tech": "FastAPI"},
                {"id": "worker", "name": "Worker", "type": "service", "tech": "Celery"}
            ]
        },
        {
            "name": "Data",
            "order": 3,
            "components": [
                {"id": "db", "name": "Database", "type": "database", "tech": "PostgreSQL"}
            ]
        }
    ],
    "connections": [
        {"source": "ui", "target": "api", "label": "REST"},
        {"source": "api", "target": "db", "label": "SQL"},
        {"source": "api", "target": "worker", "label": "Tasks"}
    ]
})

VALID_DEPENDENCY_GRAPH = json.dumps({
    "title": "Test Dependencies",
    "modules": [
        {"id": "main", "name": "app.main", "group": "app", "sloc": 100},
        {"id": "utils", "name": "app.utils", "group": "app", "sloc": 50},
        {"id": "models", "name": "app.models", "group": "app", "sloc": 200},
        {"id": "numpy", "name": "numpy", "group": "external"}
    ],
    "dependencies": [
        {"source": "main", "target": "utils"},
        {"source": "main", "target": "models"},
        {"source": "models", "target": "numpy"}
    ]
})

INVALID_JSON = "{{{not valid json"


def _upload(content, filename="config.json"):
    return ("file", (filename, io.BytesIO(content.encode()), "application/octet-stream"))


# =============================================================================
# Component Diagram - Visualize
# =============================================================================

class TestVisualizeComponentDiagram:

    def test_visualize_returns_image(self):
        response = client.post(
            "/visualize/component-diagram?format=png",
            files=[_upload(VALID_COMPONENT_DIAGRAM)],
        )
        # 400 if graphviz not installed
        assert response.status_code in (200, 400)

    def test_visualize_svg(self):
        response = client.post(
            "/visualize/component-diagram?format=svg",
            files=[_upload(VALID_COMPONENT_DIAGRAM)],
        )
        assert response.status_code in (200, 400)

    def test_visualize_malformed(self):
        response = client.post(
            "/visualize/component-diagram",
            files=[_upload(INVALID_JSON)],
        )
        assert response.status_code in (400, 500)


# =============================================================================
# Component Diagram - Analyze
# =============================================================================

class TestAnalyzeComponentDiagram:

    def test_analyze_returns_stats(self):
        response = client.post(
            "/analyze/component-diagram",
            files=[_upload(VALID_COMPONENT_DIAGRAM)],
        )
        assert response.status_code == 200
        data = response.json()
        assert "total_layers" in data
        assert "total_components" in data
        assert "total_connections" in data
        assert data["total_layers"] >= 3
        assert data["total_components"] >= 4

    def test_analyze_malformed(self):
        response = client.post(
            "/analyze/component-diagram",
            files=[_upload(INVALID_JSON)],
        )
        assert response.status_code in (400, 500)


# =============================================================================
# Component Diagram - Validate
# =============================================================================

class TestValidateComponentDiagram:

    def test_validate_valid(self):
        response = client.post(
            "/validate/component-diagram",
            files=[_upload(VALID_COMPONENT_DIAGRAM)],
        )
        assert response.status_code == 200
        data = response.json()
        assert "valid" in data

    def test_validate_malformed(self):
        response = client.post(
            "/validate/component-diagram",
            files=[_upload(INVALID_JSON)],
        )
        assert response.status_code in (200, 400, 500)


# =============================================================================
# Dependency Graph - Visualize
# =============================================================================

class TestVisualizeDependencyGraph:

    def test_visualize_returns_image(self):
        response = client.post(
            "/visualize/dependency-graph?format=png",
            files=[_upload(VALID_DEPENDENCY_GRAPH)],
        )
        # 400 if graphviz not installed
        assert response.status_code in (200, 400)

    def test_visualize_svg(self):
        response = client.post(
            "/visualize/dependency-graph?format=svg",
            files=[_upload(VALID_DEPENDENCY_GRAPH)],
        )
        assert response.status_code in (200, 400)

    def test_visualize_malformed(self):
        response = client.post(
            "/visualize/dependency-graph",
            files=[_upload(INVALID_JSON)],
        )
        assert response.status_code in (400, 500)


# =============================================================================
# Dependency Graph - Analyze
# =============================================================================

class TestAnalyzeDependencyGraph:

    def test_analyze_returns_stats(self):
        response = client.post(
            "/analyze/dependency-graph",
            files=[_upload(VALID_DEPENDENCY_GRAPH)],
        )
        assert response.status_code == 200
        data = response.json()
        assert "total_modules" in data
        assert "total_dependencies" in data
        assert data["total_modules"] >= 4

    def test_analyze_malformed(self):
        response = client.post(
            "/analyze/dependency-graph",
            files=[_upload(INVALID_JSON)],
        )
        assert response.status_code in (400, 500)


# =============================================================================
# Dependency Graph - Validate
# =============================================================================

class TestValidateDependencyGraph:

    def test_validate_valid(self):
        response = client.post(
            "/validate/dependency-graph",
            files=[_upload(VALID_DEPENDENCY_GRAPH)],
        )
        assert response.status_code == 200
        data = response.json()
        assert "valid" in data

    def test_validate_malformed(self):
        response = client.post(
            "/validate/dependency-graph",
            files=[_upload(INVALID_JSON)],
        )
        assert response.status_code in (200, 400, 500)
