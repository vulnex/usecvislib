#
# VULNEX -Universal Security Visualization Library-
#
# File: tests/test_import_export.py
# Author: Simon Roses Femerling
# Created: 2025-12-29
# Last Modified: 2025-12-29
# Version: 0.3.1
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Tests for import/export functionality in CustomDiagrams.

Tests cover:
- Importing from AttackTrees
- Importing from AttackGraphs
- Importing from ThreatModels
- Exporting schema templates
"""

import pytest
import tempfile
from pathlib import Path

from usecvislib import CustomDiagrams


# =============================================================================
# Sample Data
# =============================================================================

SAMPLE_ATTACK_TREE = '''
[tree]
name = "Test Attack Tree"
description = "Test tree for import"

[nodes.root]
label = "Compromise System"
is_root = true
gate = "OR"

[nodes.attack1]
label = "Exploit Vulnerability"
parent = "root"

[nodes.attack2]
label = "Social Engineering"
parent = "root"

[nodes.sub1]
label = "SQL Injection"
parent = "attack1"

[nodes.sub2]
label = "Phishing"
parent = "attack2"
'''

SAMPLE_ATTACK_GRAPH = '''
[graph]
name = "Test Attack Graph"
description = "Test graph for import"

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
label = "Database Server"
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

[[services]]
id = "svc_http"
label = "HTTP Service"
host = "webserver"
port = 80

[[exploits]]
id = "exploit_rce"
label = "RCE Exploit"
vulnerability = "vuln_rce"

[[network_edges]]
from = "attacker"
to = "webserver"
label = "Internet"
'''

SAMPLE_THREAT_MODEL = '''
[model]
name = "Test Threat Model"
description = "Test DFD for import"

[processes.webapp]
label = "Web Application"
description = "Main web app"

[processes.api]
label = "API Server"
description = "Backend API"

[datastores.userdb]
label = "User Database"
type = "PostgreSQL"

[datastores.cache]
label = "Session Cache"
type = "Redis"

[externals.user]
label = "End User"
type = "person"

[externals.admin]
label = "Administrator"
type = "person"

[dataflows.login]
source = "user"
destination = "webapp"
label = "Login Request"

[dataflows.api_call]
source = "webapp"
destination = "api"
label = "API Calls"

[dataflows.db_query]
source = "api"
destination = "userdb"
label = "SQL Queries"

[dataflows.cache_access]
source = "api"
destination = "cache"
label = "Session Data"
bidirectional = true

[boundaries.internal]
label = "Internal Network"
elements = ["api", "userdb", "cache"]

[boundaries.dmz]
label = "DMZ"
elements = ["webapp"]
'''


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def attack_tree_file(tmp_path):
    """Create a temporary attack tree file."""
    config = tmp_path / "attack_tree.toml"
    config.write_text(SAMPLE_ATTACK_TREE)
    return config


@pytest.fixture
def attack_graph_file(tmp_path):
    """Create a temporary attack graph file."""
    config = tmp_path / "attack_graph.toml"
    config.write_text(SAMPLE_ATTACK_GRAPH)
    return config


@pytest.fixture
def threat_model_file(tmp_path):
    """Create a temporary threat model file."""
    config = tmp_path / "threat_model.toml"
    config.write_text(SAMPLE_THREAT_MODEL)
    return config


# =============================================================================
# Attack Tree Import Tests
# =============================================================================

class TestFromAttackTree:
    """Tests for importing from AttackTrees."""

    def test_import_basic_tree(self, attack_tree_file):
        """Test importing a basic attack tree."""
        cd = CustomDiagrams.from_attack_tree(str(attack_tree_file))

        assert cd._config_loaded is True
        assert cd.settings.title == "Test Attack Tree"

    def test_import_creates_schema(self, attack_tree_file):
        """Test that import creates appropriate schema."""
        cd = CustomDiagrams.from_attack_tree(str(attack_tree_file))

        # Should have node types for attack tree elements
        assert "root" in cd.schema["nodes"]
        assert "and_gate" in cd.schema["nodes"]
        assert "or_gate" in cd.schema["nodes"]
        assert "leaf" in cd.schema["nodes"]

        # Should have edge type for parent-child relationships
        assert "parent_child" in cd.schema["edges"]

    def test_import_converts_nodes(self, attack_tree_file):
        """Test that nodes are converted correctly."""
        cd = CustomDiagrams.from_attack_tree(str(attack_tree_file))

        # Should have all nodes from the tree
        node_ids = [n["id"] for n in cd.nodes]
        assert "root" in node_ids
        assert "attack1" in node_ids
        assert "attack2" in node_ids
        assert "sub1" in node_ids
        assert "sub2" in node_ids

    def test_import_converts_edges(self, attack_tree_file):
        """Test that edges are converted correctly."""
        cd = CustomDiagrams.from_attack_tree(str(attack_tree_file))

        # Should have parent-child edges
        edges = [(e["from"], e["to"]) for e in cd.edges]
        assert ("root", "attack1") in edges
        assert ("root", "attack2") in edges

    def test_import_can_validate(self, attack_tree_file):
        """Test that imported diagram can be validated."""
        cd = CustomDiagrams.from_attack_tree(str(attack_tree_file))
        report = cd.validate(raise_on_error=False)
        assert report["valid"] is True

    def test_import_can_generate_dot(self, attack_tree_file):
        """Test that imported diagram can generate DOT output."""
        cd = CustomDiagrams.from_attack_tree(str(attack_tree_file))
        cd.validate()
        dot = cd.get_dot_source()

        assert "digraph" in dot
        assert "Test_Attack_Tree" in dot or "Test Attack Tree" in dot


# =============================================================================
# Attack Graph Import Tests
# =============================================================================

class TestFromAttackGraph:
    """Tests for importing from AttackGraphs."""

    def test_import_basic_graph(self, attack_graph_file):
        """Test importing a basic attack graph."""
        cd = CustomDiagrams.from_attack_graph(str(attack_graph_file))

        assert cd._config_loaded is True
        assert cd.settings.title == "Test Attack Graph"

    def test_import_creates_schema(self, attack_graph_file):
        """Test that import creates appropriate schema."""
        cd = CustomDiagrams.from_attack_graph(str(attack_graph_file))

        # Should have node types for attack graph elements
        assert "host" in cd.schema["nodes"]
        assert "vulnerability" in cd.schema["nodes"]
        assert "privilege" in cd.schema["nodes"]
        assert "service" in cd.schema["nodes"]
        assert "exploit" in cd.schema["nodes"]

        # Should have edge types
        assert "network" in cd.schema["edges"]
        assert "affects" in cd.schema["edges"]
        assert "exploits" in cd.schema["edges"]

    def test_import_converts_hosts(self, attack_graph_file):
        """Test that hosts are converted correctly."""
        cd = CustomDiagrams.from_attack_graph(str(attack_graph_file))

        host_nodes = [n for n in cd.nodes if n["type"] == "host"]
        assert len(host_nodes) == 3

        host_ids = [n["id"] for n in host_nodes]
        assert "attacker" in host_ids
        assert "webserver" in host_ids
        assert "database" in host_ids

    def test_import_converts_vulnerabilities(self, attack_graph_file):
        """Test that vulnerabilities are converted correctly."""
        cd = CustomDiagrams.from_attack_graph(str(attack_graph_file))

        vuln_nodes = [n for n in cd.nodes if n["type"] == "vulnerability"]
        assert len(vuln_nodes) == 2

        # Check vulnerability has CVSS
        rce_vuln = next(n for n in vuln_nodes if n["id"] == "vuln_rce")
        assert rce_vuln["cvss"] == "9.8"

    def test_import_converts_services(self, attack_graph_file):
        """Test that services are converted correctly."""
        cd = CustomDiagrams.from_attack_graph(str(attack_graph_file))

        svc_nodes = [n for n in cd.nodes if n["type"] == "service"]
        assert len(svc_nodes) == 1

        http_svc = svc_nodes[0]
        assert http_svc["name"] == "HTTP Service"
        assert http_svc["port"] == "80"

    def test_import_creates_edges(self, attack_graph_file):
        """Test that edges are created correctly."""
        cd = CustomDiagrams.from_attack_graph(str(attack_graph_file))

        # Should have network edges
        network_edges = [e for e in cd.edges if e["type"] == "network"]
        assert len(network_edges) >= 1

        # Should have affects edges (vuln -> host)
        affects_edges = [e for e in cd.edges if e["type"] == "affects"]
        assert len(affects_edges) == 2

    def test_import_can_validate(self, attack_graph_file):
        """Test that imported diagram can be validated."""
        cd = CustomDiagrams.from_attack_graph(str(attack_graph_file))
        report = cd.validate(raise_on_error=False)
        assert report["valid"] is True

    def test_import_can_generate_dot(self, attack_graph_file):
        """Test that imported diagram can generate DOT output."""
        cd = CustomDiagrams.from_attack_graph(str(attack_graph_file))
        cd.validate()
        dot = cd.get_dot_source()

        assert "digraph" in dot
        # Should contain host nodes
        assert "attacker" in dot or "Attacker" in dot


# =============================================================================
# Threat Model Import Tests
# =============================================================================

class TestFromThreatModel:
    """Tests for importing from ThreatModels."""

    def test_import_basic_model(self, threat_model_file):
        """Test importing a basic threat model."""
        cd = CustomDiagrams.from_threat_model(str(threat_model_file))

        assert cd._config_loaded is True
        assert cd.settings.title == "Test Threat Model"

    def test_import_creates_schema(self, threat_model_file):
        """Test that import creates appropriate schema."""
        cd = CustomDiagrams.from_threat_model(str(threat_model_file))

        # Should have node types for DFD elements
        assert "process" in cd.schema["nodes"]
        assert "datastore" in cd.schema["nodes"]
        assert "external" in cd.schema["nodes"]

        # Should have edge types
        assert "dataflow" in cd.schema["edges"]
        assert "bidirectional" in cd.schema["edges"]

    def test_import_converts_processes(self, threat_model_file):
        """Test that processes are converted correctly."""
        cd = CustomDiagrams.from_threat_model(str(threat_model_file))

        proc_nodes = [n for n in cd.nodes if n["type"] == "process"]
        assert len(proc_nodes) == 2

        proc_ids = [n["id"] for n in proc_nodes]
        assert "webapp" in proc_ids
        assert "api" in proc_ids

    def test_import_converts_datastores(self, threat_model_file):
        """Test that datastores are converted correctly."""
        cd = CustomDiagrams.from_threat_model(str(threat_model_file))

        ds_nodes = [n for n in cd.nodes if n["type"] == "datastore"]
        assert len(ds_nodes) == 2

        ds_ids = [n["id"] for n in ds_nodes]
        assert "userdb" in ds_ids
        assert "cache" in ds_ids

    def test_import_converts_externals(self, threat_model_file):
        """Test that external entities are converted correctly."""
        cd = CustomDiagrams.from_threat_model(str(threat_model_file))

        ext_nodes = [n for n in cd.nodes if n["type"] == "external"]
        assert len(ext_nodes) == 2

        ext_ids = [n["id"] for n in ext_nodes]
        assert "user" in ext_ids
        assert "admin" in ext_ids

    def test_import_converts_dataflows(self, threat_model_file):
        """Test that dataflows are converted correctly."""
        cd = CustomDiagrams.from_threat_model(str(threat_model_file))

        dataflow_edges = [e for e in cd.edges if e["type"] == "dataflow"]
        bidir_edges = [e for e in cd.edges if e["type"] == "bidirectional"]

        # Should have 3 regular dataflows and 1 bidirectional
        assert len(dataflow_edges) == 3
        assert len(bidir_edges) == 1

    def test_import_converts_boundaries(self, threat_model_file):
        """Test that trust boundaries are converted to clusters."""
        cd = CustomDiagrams.from_threat_model(str(threat_model_file))

        # Should have 2 clusters (boundaries)
        assert len(cd.clusters) == 2

        cluster_ids = [c["id"] for c in cd.clusters]
        assert "internal" in cluster_ids
        assert "dmz" in cluster_ids

        # Check cluster contains correct elements
        internal = next(c for c in cd.clusters if c["id"] == "internal")
        assert "api" in internal["nodes"]
        assert "userdb" in internal["nodes"]
        assert "cache" in internal["nodes"]

    def test_import_can_validate(self, threat_model_file):
        """Test that imported diagram can be validated."""
        cd = CustomDiagrams.from_threat_model(str(threat_model_file))
        report = cd.validate(raise_on_error=False)
        assert report["valid"] is True

    def test_import_can_generate_dot(self, threat_model_file):
        """Test that imported diagram can generate DOT output."""
        cd = CustomDiagrams.from_threat_model(str(threat_model_file))
        cd.validate()
        dot = cd.get_dot_source()

        assert "digraph" in dot
        # Should contain clusters for boundaries
        assert "subgraph" in dot


# =============================================================================
# Export Schema Template Tests
# =============================================================================

class TestExportSchemaTemplate:
    """Tests for exporting schema templates."""

    def test_export_from_loaded_config(self, tmp_path):
        """Test exporting schema from loaded configuration."""
        config = tmp_path / "diagram.toml"
        config.write_text('''
[diagram]
title = "Test Diagram"

[schema.nodes.server]
shape = "server"
required_fields = ["name"]

[schema.nodes.database]
shape = "database"
required_fields = ["name"]

[schema.edges.connection]
style = "solid"
color = "#333333"

[[nodes]]
id = "s1"
type = "server"
name = "Server 1"
''')

        cd = CustomDiagrams()
        cd.load(config)

        template = cd.export_schema_template()

        assert "[diagram]" in template
        assert "[schema.nodes.server]" in template or "server" in template
        assert "[schema.nodes.database]" in template or "database" in template

    def test_export_creates_example_nodes(self, tmp_path):
        """Test that export creates example nodes for each type."""
        config = tmp_path / "diagram.toml"
        config.write_text('''
[diagram]
title = "Test Diagram"

[schema.nodes.typeA]
shape = "rectangle"
required_fields = ["name"]

[schema.nodes.typeB]
shape = "ellipse"
required_fields = ["name"]

[[nodes]]
id = "n1"
type = "typeA"
name = "Node 1"
''')

        cd = CustomDiagrams()
        cd.load(config)

        template = cd.export_schema_template()

        # Should have example nodes for each type
        assert "example_typeA" in template
        assert "example_typeB" in template

    def test_export_from_imported_tree(self, attack_tree_file):
        """Test exporting template from imported attack tree."""
        cd = CustomDiagrams.from_attack_tree(str(attack_tree_file))
        template = cd.export_schema_template()

        assert "[diagram]" in template
        assert "title" in template

    def test_export_from_imported_graph(self, attack_graph_file):
        """Test exporting template from imported attack graph."""
        cd = CustomDiagrams.from_attack_graph(str(attack_graph_file))
        template = cd.export_schema_template()

        assert "[diagram]" in template
        # Should have node types from attack graph schema
        assert "host" in template or "vulnerability" in template

    def test_export_returns_valid_toml(self, attack_tree_file):
        """Test that exported template is valid TOML."""
        import toml

        cd = CustomDiagrams.from_attack_tree(str(attack_tree_file))
        template = cd.export_schema_template()

        # Should parse without errors
        parsed = toml.loads(template)
        assert "diagram" in parsed
        assert "schema" in parsed


# =============================================================================
# Integration Tests
# =============================================================================

class TestImportExportIntegration:
    """Integration tests for import/export workflow."""

    def test_import_export_roundtrip(self, attack_tree_file, tmp_path):
        """Test importing and exporting creates usable template."""
        # Import from attack tree
        cd1 = CustomDiagrams.from_attack_tree(str(attack_tree_file))

        # Export template
        template = cd1.export_schema_template()

        # Save and reload
        template_file = tmp_path / "template.toml"
        template_file.write_text(template)

        # Load the template
        cd2 = CustomDiagrams()
        cd2.load(template_file)

        # Should be loadable and validatable
        assert cd2._config_loaded is True
        report = cd2.validate(raise_on_error=False)
        assert report["valid"] is True

    def test_all_imports_produce_valid_diagrams(
        self, attack_tree_file, attack_graph_file, threat_model_file
    ):
        """Test all import methods produce valid, renderable diagrams."""
        sources = [
            ("attack_tree", CustomDiagrams.from_attack_tree, attack_tree_file),
            ("attack_graph", CustomDiagrams.from_attack_graph, attack_graph_file),
            ("threat_model", CustomDiagrams.from_threat_model, threat_model_file),
        ]

        for name, import_func, config_file in sources:
            cd = import_func(str(config_file))

            # Should be loaded
            assert cd._config_loaded, f"{name}: not loaded"

            # Should validate
            report = cd.validate(raise_on_error=False)
            assert report["valid"], f"{name}: validation failed - {report.get('errors', [])}"

            # Should generate DOT
            dot = cd.get_dot_source()
            assert "digraph" in dot, f"{name}: no digraph in DOT output"

    def test_imported_diagram_has_stats(self, attack_graph_file):
        """Test that imported diagram has correct statistics."""
        cd = CustomDiagrams.from_attack_graph(str(attack_graph_file))

        stats = cd.get_stats()

        assert stats["total_nodes"] > 0
        assert stats["total_edges"] > 0
        assert "schema_node_types" in stats
        assert "schema_edge_types" in stats
