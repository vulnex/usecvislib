#
# VULNEX -Universal Security Visualization Library-
#
# File: test_builders.py
# Author: Simon Roses Femerling
# Created: 2025-12-25
# Last Modified: 2025-12-25
# Version: 0.3.1
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Unit tests for builders module."""

import os
import sys
import json
import pytest

# Add src to path for testing
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from usecvislib.builders import (
    AttackTreeBuilder,
    AttackGraphBuilder,
    ThreatModelBuilder,
)


class TestAttackTreeBuilder:
    """Tests for AttackTreeBuilder class."""

    def test_basic_initialization(self):
        """Test basic builder initialization."""
        builder = AttackTreeBuilder("Test Tree", "root_node")
        data = builder.build()
        assert data["tree"]["name"] == "Test Tree"
        assert data["tree"]["root"] == "root_node"

    def test_add_node(self):
        """Test adding nodes."""
        builder = AttackTreeBuilder("Test", "root")
        builder.add_node("node1", "Node 1")
        builder.add_node("node2", "Node 2", fillcolor="#ff0000")

        data = builder.build()
        assert "node1" in data["nodes"]
        assert "node2" in data["nodes"]
        assert data["nodes"]["node1"]["label"] == "Node 1"
        assert data["nodes"]["node2"]["fillcolor"] == "#ff0000"

    def test_add_and_node(self):
        """Test adding AND nodes."""
        builder = AttackTreeBuilder("Test", "root")
        builder.add_and_node("and_node", "AND Gate")

        data = builder.build()
        assert data["nodes"]["and_node"]["shape"] == "trapezium"

    def test_add_or_node(self):
        """Test adding OR nodes."""
        builder = AttackTreeBuilder("Test", "root")
        builder.add_or_node("or_node", "OR Gate")

        data = builder.build()
        assert data["nodes"]["or_node"]["shape"] == "invtrapezium"

    def test_add_leaf_node(self):
        """Test adding leaf nodes."""
        builder = AttackTreeBuilder("Test", "root")
        builder.add_leaf_node("leaf", "Leaf Node")

        data = builder.build()
        assert data["nodes"]["leaf"]["shape"] == "ellipse"

    def test_add_edge(self):
        """Test adding edges."""
        builder = AttackTreeBuilder("Test", "root")
        builder.add_node("root", "Root")
        builder.add_node("child", "Child")
        builder.add_edge("root", "child", "OR")

        data = builder.build()
        assert "root" in data["edges"]
        assert len(data["edges"]["root"]) == 1
        assert data["edges"]["root"][0]["to"] == "child"
        assert data["edges"]["root"][0]["label"] == "OR"

    def test_add_and_edge(self):
        """Test adding AND edges."""
        builder = AttackTreeBuilder("Test", "root")
        builder.add_node("root", "Root")
        builder.add_node("child", "Child")
        builder.add_and_edge("root", "child")

        data = builder.build()
        assert data["edges"]["root"][0]["label"] == "AND"
        assert data["edges"]["root"][0]["style"] == "solid"

    def test_add_or_edge(self):
        """Test adding OR edges."""
        builder = AttackTreeBuilder("Test", "root")
        builder.add_node("root", "Root")
        builder.add_node("child", "Child")
        builder.add_or_edge("root", "child")

        data = builder.build()
        assert data["edges"]["root"][0]["label"] == "OR"
        assert data["edges"]["root"][0]["style"] == "dashed"

    def test_fluent_interface(self):
        """Test fluent interface (method chaining)."""
        builder = (
            AttackTreeBuilder("Web Attack", "compromise")
            .add_node("compromise", "Compromise Server")
            .add_node("sqli", "SQL Injection")
            .add_node("xss", "XSS Attack")
            .add_edge("compromise", "sqli")
            .add_edge("compromise", "xss")
        )

        data = builder.build()
        assert len(data["nodes"]) == 3
        assert len(data["edges"]["compromise"]) == 2

    def test_to_json(self):
        """Test JSON export."""
        builder = AttackTreeBuilder("Test", "root")
        builder.add_node("root", "Root Node")

        json_str = builder.to_json()
        parsed = json.loads(json_str)
        assert parsed["tree"]["name"] == "Test"

    def test_to_json_compact(self):
        """Test compact JSON export."""
        builder = AttackTreeBuilder("Test", "root")
        json_pretty = builder.to_json(pretty=True)
        json_compact = builder.to_json(pretty=False)
        assert len(json_compact) < len(json_pretty)

    def test_set_tree_attribute(self):
        """Test setting tree attributes."""
        builder = AttackTreeBuilder("Test", "root")
        builder.set_tree_attribute("author", "Test Author")

        data = builder.build()
        assert data["tree"]["author"] == "Test Author"


class TestAttackGraphBuilder:
    """Tests for AttackGraphBuilder class."""

    def test_basic_initialization(self):
        """Test basic builder initialization."""
        builder = AttackGraphBuilder("Network Attack")
        data = builder.build()
        assert data["graph"]["name"] == "Network Attack"

    def test_add_host(self):
        """Test adding hosts."""
        builder = AttackGraphBuilder("Test")
        builder.add_host("attacker", "Attacker", zone="external")
        builder.add_host("web", "Web Server", ip="10.0.1.10", zone="dmz")

        data = builder.build()
        assert len(data["hosts"]) == 2
        assert data["hosts"][0]["zone"] == "external"
        assert data["hosts"][1]["ip"] == "10.0.1.10"

    def test_add_vulnerability(self):
        """Test adding vulnerabilities."""
        builder = AttackGraphBuilder("Test")
        builder.add_host("web", "Web Server")
        builder.add_vulnerability(
            "rce", "RCE Vulnerability",
            cvss=9.8,
            affected_host="web",
            cve="CVE-2024-1234"
        )

        data = builder.build()
        assert len(data["vulnerabilities"]) == 1
        assert data["vulnerabilities"][0]["cvss"] == 9.8
        assert data["vulnerabilities"][0]["cve"] == "CVE-2024-1234"

    def test_add_privilege(self):
        """Test adding privileges."""
        builder = AttackGraphBuilder("Test")
        builder.add_host("web", "Web Server")
        builder.add_privilege("shell", "Web Shell", host="web", level="user")

        data = builder.build()
        assert len(data["privileges"]) == 1
        assert data["privileges"][0]["level"] == "user"

    def test_add_service(self):
        """Test adding services."""
        builder = AttackGraphBuilder("Test")
        builder.add_host("web", "Web Server")
        builder.add_service("http", "HTTP", host="web", port=80)
        builder.add_service("https", "HTTPS", host="web", port=443, protocol="tcp")

        data = builder.build()
        assert len(data["services"]) == 2
        assert data["services"][0]["port"] == 80

    def test_add_exploit(self):
        """Test adding exploits."""
        builder = AttackGraphBuilder("Test")
        builder.add_host("web", "Web Server")
        builder.add_vulnerability("vuln", "Vuln", cvss=9.0, affected_host="web")
        builder.add_privilege("shell", "Shell", host="web")
        builder.add_exploit(
            "exp",
            "RCE Exploit",
            vulnerability="vuln",
            precondition="attacker",
            postcondition="shell"
        )

        data = builder.build()
        assert len(data["exploits"]) == 1
        assert data["exploits"][0]["vulnerability"] == "vuln"

    def test_add_network_edge(self):
        """Test adding network edges."""
        builder = AttackGraphBuilder("Test")
        builder.add_host("attacker", "Attacker")
        builder.add_host("web", "Web Server")
        builder.add_network_edge("attacker", "web", label="Internet")

        data = builder.build()
        assert len(data["network_edges"]) == 1
        assert data["network_edges"][0]["from"] == "attacker"
        assert data["network_edges"][0]["to"] == "web"

    def test_fluent_interface(self):
        """Test fluent interface."""
        builder = (
            AttackGraphBuilder("Network Attack")
            .add_host("attacker", "Attacker", zone="external")
            .add_host("web", "Web Server", ip="10.0.1.10")
            .add_vulnerability("rce", "RCE", cvss=9.8, affected_host="web")
            .add_network_edge("attacker", "web")
        )

        data = builder.build()
        assert len(data["hosts"]) == 2
        assert len(data["vulnerabilities"]) == 1
        assert len(data["network_edges"]) == 1

    def test_to_json(self):
        """Test JSON export."""
        builder = AttackGraphBuilder("Test")
        builder.add_host("host", "Host")

        json_str = builder.to_json()
        parsed = json.loads(json_str)
        assert parsed["graph"]["name"] == "Test"

    def test_set_graph_attribute(self):
        """Test setting graph attributes."""
        builder = AttackGraphBuilder("Test")
        builder.set_graph_attribute("version", "1.0")

        data = builder.build()
        assert data["graph"]["version"] == "1.0"


class TestThreatModelBuilder:
    """Tests for ThreatModelBuilder class."""

    def test_basic_initialization(self):
        """Test basic builder initialization."""
        builder = ThreatModelBuilder("Web App", "webapp")
        data = builder.build()
        assert data["dfd"]["name"] == "Web App"
        assert data["dfd"]["id"] == "webapp"

    def test_add_process(self):
        """Test adding processes."""
        builder = ThreatModelBuilder("Test", "test")
        builder.add_process("web", "Web Server", trust_level="internal")

        data = builder.build()
        assert len(data["processes"]) == 1
        assert data["processes"][0]["trust_level"] == "internal"

    def test_add_datastore(self):
        """Test adding data stores."""
        builder = ThreatModelBuilder("Test", "test")
        builder.add_datastore("db", "Database", store_type="database", encrypted=True)

        data = builder.build()
        assert len(data["datastores"]) == 1
        assert data["datastores"][0]["encrypted"] is True
        assert data["datastores"][0]["type"] == "database"

    def test_add_external_entity(self):
        """Test adding external entities."""
        builder = ThreatModelBuilder("Test", "test")
        builder.add_external_entity("user", "End User", entity_type="user")

        data = builder.build()
        assert len(data["external_entities"]) == 1
        assert data["external_entities"][0]["type"] == "user"

    def test_add_data_flow(self):
        """Test adding data flows."""
        builder = ThreatModelBuilder("Test", "test")
        builder.add_process("web", "Web Server")
        builder.add_datastore("db", "Database")
        builder.add_data_flow(
            "web", "db",
            label="SQL Query",
            protocol="TCP",
            encrypted=True,
            authenticated=True
        )

        data = builder.build()
        assert len(data["data_flows"]) == 1
        assert data["data_flows"][0]["encrypted"] is True
        assert data["data_flows"][0]["authenticated"] is True
        assert data["data_flows"][0]["protocol"] == "TCP"

    def test_add_trust_boundary(self):
        """Test adding trust boundaries."""
        builder = ThreatModelBuilder("Test", "test")
        builder.add_process("web", "Web Server")
        builder.add_process("api", "API Server")
        builder.add_trust_boundary("dmz", "DMZ", elements=["web", "api"])

        data = builder.build()
        assert len(data["trust_boundaries"]) == 1
        assert "web" in data["trust_boundaries"][0]["elements"]
        assert "api" in data["trust_boundaries"][0]["elements"]

    def test_fluent_interface(self):
        """Test fluent interface."""
        builder = (
            ThreatModelBuilder("Web Application", "webapp")
            .add_external_entity("user", "User")
            .add_process("web", "Web Server")
            .add_datastore("db", "Database")
            .add_data_flow("user", "web", "HTTP Request")
            .add_data_flow("web", "db", "SQL Query")
            .add_trust_boundary("internal", "Internal", elements=["web", "db"])
        )

        data = builder.build()
        assert len(data["external_entities"]) == 1
        assert len(data["processes"]) == 1
        assert len(data["datastores"]) == 1
        assert len(data["data_flows"]) == 2
        assert len(data["trust_boundaries"]) == 1

    def test_to_json(self):
        """Test JSON export."""
        builder = ThreatModelBuilder("Test", "test")
        builder.add_process("proc", "Process")

        json_str = builder.to_json()
        parsed = json.loads(json_str)
        assert parsed["dfd"]["name"] == "Test"

    def test_set_dfd_attribute(self):
        """Test setting DFD attributes."""
        builder = ThreatModelBuilder("Test", "test")
        builder.set_dfd_attribute("author", "Security Team")

        data = builder.build()
        assert data["dfd"]["author"] == "Security Team"


class TestBuilderIntegration:
    """Integration tests for builders with visualization classes."""

    def test_attack_tree_builder_creates_valid_structure(self):
        """Test that builder creates valid attack tree structure."""
        builder = (
            AttackTreeBuilder("Test Attack", "goal")
            .add_node("goal", "Compromise System")
            .add_node("step1", "Step 1")
            .add_node("step2", "Step 2")
            .add_edge("goal", "step1")
            .add_edge("goal", "step2")
        )

        data = builder.build()

        # Verify structure
        assert "tree" in data
        assert "nodes" in data
        assert "edges" in data
        assert data["tree"]["root"] == "goal"
        assert len(data["nodes"]) == 3
        assert "goal" in data["edges"]

    def test_attack_graph_builder_creates_valid_structure(self):
        """Test that builder creates valid attack graph structure."""
        builder = (
            AttackGraphBuilder("Network Attack")
            .add_host("attacker", "Attacker", zone="external")
            .add_host("target", "Target Server", ip="192.168.1.1")
            .add_vulnerability("vuln", "Critical Vuln", cvss=9.5, affected_host="target")
            .add_network_edge("attacker", "target")
        )

        data = builder.build()

        # Verify structure
        assert "graph" in data
        assert "hosts" in data
        assert "vulnerabilities" in data
        assert "network_edges" in data
        assert len(data["hosts"]) == 2
        assert len(data["vulnerabilities"]) == 1

    def test_threat_model_builder_creates_valid_structure(self):
        """Test that builder creates valid threat model structure."""
        builder = (
            ThreatModelBuilder("Application", "app")
            .add_external_entity("user", "User")
            .add_process("api", "API Gateway")
            .add_datastore("db", "Database")
            .add_data_flow("user", "api", "Request")
            .add_data_flow("api", "db", "Query")
        )

        data = builder.build()

        # Verify structure
        assert "dfd" in data
        assert "processes" in data
        assert "external_entities" in data
        assert "datastores" in data
        assert "data_flows" in data
        assert len(data["data_flows"]) == 2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
