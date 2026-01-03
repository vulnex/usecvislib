#
# VULNEX -Universal Security Visualization Library-
#
# File: builders.py
# Author: Simon Roses Femerling
# Created: 2025-12-25
# Last Modified: 2025-12-25
# Version: 0.3.1
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""
Builder classes for programmatically creating security visualizations.

This module provides fluent builder interfaces for creating attack trees,
attack graphs, and threat models without needing to write configuration files.

Example:
    >>> tree = (
    ...     AttackTreeBuilder("Web Attack", "Compromise Server")
    ...     .add_node("Compromise Server", fillcolor="red")
    ...     .add_node("SQL Injection")
    ...     .add_node("XSS Attack")
    ...     .add_edge("Compromise Server", "SQL Injection", "OR")
    ...     .add_edge("Compromise Server", "XSS Attack", "OR")
    ...     .to_attack_tree("output")
    ...     .Render()
    ...     .draw()
    ... )
"""

from typing import Dict, Any, List, Optional
import tempfile
import json
import os


class AttackTreeBuilder:
    """Builder for programmatically creating attack trees.

    Provides a fluent interface for constructing attack tree structures
    without needing external configuration files.

    Example:
        >>> builder = AttackTreeBuilder("Web Attack", "compromise_server")
        >>> builder.add_node("compromise_server", "Compromise Server", fillcolor="red")
        >>> builder.add_node("sqli", "SQL Injection")
        >>> builder.add_edge("compromise_server", "sqli", "OR")
        >>> attack_tree = builder.to_attack_tree("output")
    """

    def __init__(self, name: str, root: str, description: str = ""):
        """Initialize AttackTreeBuilder.

        Args:
            name: Name of the attack tree.
            root: Root node ID.
            description: Optional description.
        """
        self._data: Dict[str, Any] = {
            "tree": {
                "name": name,
                "root": root,
                "description": description
            },
            "nodes": {},
            "edges": {}
        }

    def add_node(
        self,
        node_id: str,
        label: Optional[str] = None,
        style: str = "filled",
        fillcolor: str = "#3498db",
        shape: str = "box",
        fontcolor: str = "white",
        **attrs
    ) -> 'AttackTreeBuilder':
        """Add a node to the tree.

        Args:
            node_id: Unique identifier for the node.
            label: Display label (defaults to node_id).
            style: Graphviz style attribute.
            fillcolor: Node fill color.
            shape: Node shape.
            fontcolor: Font color for the label.
            **attrs: Additional Graphviz attributes.

        Returns:
            Self for method chaining.
        """
        self._data["nodes"][node_id] = {
            "label": label or node_id,
            "style": style,
            "fillcolor": fillcolor,
            "shape": shape,
            "fontcolor": fontcolor,
            **attrs
        }
        return self

    def add_and_node(
        self,
        node_id: str,
        label: Optional[str] = None,
        fillcolor: str = "#e74c3c",
        **attrs
    ) -> 'AttackTreeBuilder':
        """Add an AND node (all children must be completed).

        Args:
            node_id: Unique identifier for the node.
            label: Display label (defaults to node_id).
            fillcolor: Node fill color.
            **attrs: Additional attributes.

        Returns:
            Self for method chaining.
        """
        return self.add_node(
            node_id,
            label=label,
            fillcolor=fillcolor,
            shape="trapezium",
            **attrs
        )

    def add_or_node(
        self,
        node_id: str,
        label: Optional[str] = None,
        fillcolor: str = "#2ecc71",
        **attrs
    ) -> 'AttackTreeBuilder':
        """Add an OR node (any child can complete it).

        Args:
            node_id: Unique identifier for the node.
            label: Display label (defaults to node_id).
            fillcolor: Node fill color.
            **attrs: Additional attributes.

        Returns:
            Self for method chaining.
        """
        return self.add_node(
            node_id,
            label=label,
            fillcolor=fillcolor,
            shape="invtrapezium",
            **attrs
        )

    def add_leaf_node(
        self,
        node_id: str,
        label: Optional[str] = None,
        fillcolor: str = "#9b59b6",
        **attrs
    ) -> 'AttackTreeBuilder':
        """Add a leaf node (basic attack step).

        Args:
            node_id: Unique identifier for the node.
            label: Display label (defaults to node_id).
            fillcolor: Node fill color.
            **attrs: Additional attributes.

        Returns:
            Self for method chaining.
        """
        return self.add_node(
            node_id,
            label=label,
            fillcolor=fillcolor,
            shape="ellipse",
            **attrs
        )

    def add_edge(
        self,
        from_node: str,
        to_node: str,
        label: str = "",
        style: str = "solid",
        color: str = "black",
        **attrs
    ) -> 'AttackTreeBuilder':
        """Add an edge between nodes.

        Args:
            from_node: Source node ID.
            to_node: Target node ID.
            label: Edge label.
            style: Edge style (solid, dashed, dotted).
            color: Edge color.
            **attrs: Additional Graphviz attributes.

        Returns:
            Self for method chaining.
        """
        if from_node not in self._data["edges"]:
            self._data["edges"][from_node] = []

        self._data["edges"][from_node].append({
            "to": to_node,
            "label": label,
            "style": style,
            "color": color,
            **attrs
        })
        return self

    def add_and_edge(
        self,
        from_node: str,
        to_node: str,
        **attrs
    ) -> 'AttackTreeBuilder':
        """Add an AND edge (required path).

        Args:
            from_node: Source node ID.
            to_node: Target node ID.
            **attrs: Additional attributes.

        Returns:
            Self for method chaining.
        """
        return self.add_edge(from_node, to_node, label="AND", style="solid", **attrs)

    def add_or_edge(
        self,
        from_node: str,
        to_node: str,
        **attrs
    ) -> 'AttackTreeBuilder':
        """Add an OR edge (alternative path).

        Args:
            from_node: Source node ID.
            to_node: Target node ID.
            **attrs: Additional attributes.

        Returns:
            Self for method chaining.
        """
        return self.add_edge(from_node, to_node, label="OR", style="dashed", **attrs)

    def set_tree_attribute(self, key: str, value: Any) -> 'AttackTreeBuilder':
        """Set a tree-level attribute.

        Args:
            key: Attribute name.
            value: Attribute value.

        Returns:
            Self for method chaining.
        """
        self._data["tree"][key] = value
        return self

    def build(self) -> Dict[str, Any]:
        """Build and return the tree data as a dictionary.

        Returns:
            Dictionary representation of the attack tree.
        """
        return self._data.copy()

    def to_json(self, pretty: bool = True) -> str:
        """Convert to JSON string.

        Args:
            pretty: Whether to use pretty formatting.

        Returns:
            JSON string representation.
        """
        if pretty:
            return json.dumps(self._data, indent=2)
        return json.dumps(self._data)

    def to_attack_tree(
        self,
        outputfile: str,
        format: str = "png",
        styleid: str = "at_default"
    ) -> 'AttackTrees':
        """Create AttackTrees instance from builder data.

        Args:
            outputfile: Output file path (without extension).
            format: Output format (png, svg, pdf, dot).
            styleid: Style identifier to use.

        Returns:
            Configured AttackTrees instance ready for rendering.
        """
        from .attacktrees import AttackTrees

        # Create a temporary file with the data
        with tempfile.NamedTemporaryFile(
            mode='w',
            suffix='.json',
            delete=False
        ) as f:
            json.dump(self._data, f)
            temp_path = f.name

        at = AttackTrees(temp_path, outputfile, format=format, styleid=styleid)
        at._temp_input = temp_path  # Mark for cleanup
        return at


class AttackGraphBuilder:
    """Builder for programmatically creating attack graphs.

    Provides a fluent interface for constructing network attack graphs
    with hosts, vulnerabilities, services, privileges, and exploits.

    Example:
        >>> builder = AttackGraphBuilder("Network Attack")
        >>> builder.add_host("attacker", "Attacker", zone="external")
        >>> builder.add_host("webserver", "Web Server", ip="10.0.1.10")
        >>> builder.add_vulnerability("rce", "RCE Vuln", cvss=9.8, affected_host="webserver")
        >>> builder.add_network_edge("attacker", "webserver")
        >>> attack_graph = builder.to_attack_graph("output")
    """

    def __init__(self, name: str, description: str = ""):
        """Initialize AttackGraphBuilder.

        Args:
            name: Name of the attack graph.
            description: Optional description.
        """
        self._data: Dict[str, Any] = {
            "graph": {
                "name": name,
                "description": description
            },
            "hosts": [],
            "vulnerabilities": [],
            "privileges": [],
            "services": [],
            "exploits": [],
            "network_edges": []
        }

    def add_host(
        self,
        host_id: str,
        label: str,
        ip: Optional[str] = None,
        zone: str = "internal",
        **attrs
    ) -> 'AttackGraphBuilder':
        """Add a host to the graph.

        Args:
            host_id: Unique identifier for the host.
            label: Display label.
            ip: IP address.
            zone: Network zone (internal, dmz, external).
            **attrs: Additional attributes.

        Returns:
            Self for method chaining.
        """
        host = {
            "id": host_id,
            "label": label,
            "zone": zone,
            **attrs
        }
        if ip:
            host["ip"] = ip
        self._data["hosts"].append(host)
        return self

    def add_vulnerability(
        self,
        vuln_id: str,
        label: str,
        cvss: float,
        affected_host: str,
        cve: Optional[str] = None,
        **attrs
    ) -> 'AttackGraphBuilder':
        """Add a vulnerability to the graph.

        Args:
            vuln_id: Unique identifier for the vulnerability.
            label: Display label.
            cvss: CVSS score (0-10).
            affected_host: Host ID that is affected.
            cve: Optional CVE identifier.
            **attrs: Additional attributes.

        Returns:
            Self for method chaining.
        """
        vuln = {
            "id": vuln_id,
            "label": label,
            "cvss": cvss,
            "affected_host": affected_host,
            **attrs
        }
        if cve:
            vuln["cve"] = cve
        self._data["vulnerabilities"].append(vuln)
        return self

    def add_privilege(
        self,
        priv_id: str,
        label: str,
        host: str,
        level: str = "user",
        **attrs
    ) -> 'AttackGraphBuilder':
        """Add a privilege level to the graph.

        Args:
            priv_id: Unique identifier for the privilege.
            label: Display label.
            host: Host ID where privilege applies.
            level: Privilege level (user, admin, root, system).
            **attrs: Additional attributes.

        Returns:
            Self for method chaining.
        """
        self._data["privileges"].append({
            "id": priv_id,
            "label": label,
            "host": host,
            "level": level,
            **attrs
        })
        return self

    def add_service(
        self,
        service_id: str,
        label: str,
        host: str,
        port: int,
        protocol: str = "tcp",
        **attrs
    ) -> 'AttackGraphBuilder':
        """Add a service to the graph.

        Args:
            service_id: Unique identifier for the service.
            label: Display label.
            host: Host ID where service runs.
            port: Port number.
            protocol: Protocol (tcp, udp).
            **attrs: Additional attributes.

        Returns:
            Self for method chaining.
        """
        self._data["services"].append({
            "id": service_id,
            "label": label,
            "host": host,
            "port": port,
            "protocol": protocol,
            **attrs
        })
        return self

    def add_exploit(
        self,
        exploit_id: str,
        label: str,
        vulnerability: str,
        precondition: str,
        postcondition: str,
        **attrs
    ) -> 'AttackGraphBuilder':
        """Add an exploit to the graph.

        Args:
            exploit_id: Unique identifier for the exploit.
            label: Display label.
            vulnerability: Vulnerability ID that is exploited.
            precondition: Required state/privilege before exploit.
            postcondition: Resulting state/privilege after exploit.
            **attrs: Additional attributes.

        Returns:
            Self for method chaining.
        """
        self._data["exploits"].append({
            "id": exploit_id,
            "label": label,
            "vulnerability": vulnerability,
            "precondition": precondition,
            "postcondition": postcondition,
            **attrs
        })
        return self

    def add_network_edge(
        self,
        from_host: str,
        to_host: str,
        label: str = "",
        **attrs
    ) -> 'AttackGraphBuilder':
        """Add a network connection between hosts.

        Args:
            from_host: Source host ID.
            to_host: Destination host ID.
            label: Edge label.
            **attrs: Additional attributes.

        Returns:
            Self for method chaining.
        """
        edge = {
            "from": from_host,
            "to": to_host,
            **attrs
        }
        if label:
            edge["label"] = label
        self._data["network_edges"].append(edge)
        return self

    def set_graph_attribute(self, key: str, value: Any) -> 'AttackGraphBuilder':
        """Set a graph-level attribute.

        Args:
            key: Attribute name.
            value: Attribute value.

        Returns:
            Self for method chaining.
        """
        self._data["graph"][key] = value
        return self

    def build(self) -> Dict[str, Any]:
        """Build and return the graph data as a dictionary.

        Returns:
            Dictionary representation of the attack graph.
        """
        return self._data.copy()

    def to_json(self, pretty: bool = True) -> str:
        """Convert to JSON string.

        Args:
            pretty: Whether to use pretty formatting.

        Returns:
            JSON string representation.
        """
        if pretty:
            return json.dumps(self._data, indent=2)
        return json.dumps(self._data)

    def to_attack_graph(
        self,
        outputfile: str,
        format: str = "png",
        styleid: str = "ag_default"
    ) -> 'AttackGraphs':
        """Create AttackGraphs instance from builder data.

        Args:
            outputfile: Output file path (without extension).
            format: Output format (png, svg, pdf, dot).
            styleid: Style identifier to use.

        Returns:
            Configured AttackGraphs instance ready for rendering.
        """
        from .attackgraphs import AttackGraphs

        # Create a temporary file with the data
        with tempfile.NamedTemporaryFile(
            mode='w',
            suffix='.json',
            delete=False
        ) as f:
            json.dump(self._data, f)
            temp_path = f.name

        ag = AttackGraphs(temp_path, outputfile, format=format, styleid=styleid)
        ag._temp_input = temp_path  # Mark for cleanup
        return ag


class ThreatModelBuilder:
    """Builder for programmatically creating threat models.

    Provides a fluent interface for constructing data flow diagrams
    with processes, data stores, external entities, and data flows.

    Example:
        >>> builder = ThreatModelBuilder("Web Application", "webapp")
        >>> builder.add_process("webserver", "Web Server")
        >>> builder.add_datastore("db", "Database")
        >>> builder.add_external_entity("user", "User")
        >>> builder.add_data_flow("user", "webserver", "HTTP Request")
        >>> builder.add_data_flow("webserver", "db", "SQL Query")
        >>> threat_model = builder.to_threat_model("output")
    """

    def __init__(self, name: str, system_id: str, description: str = ""):
        """Initialize ThreatModelBuilder.

        Args:
            name: Name of the threat model.
            system_id: System identifier.
            description: Optional description.
        """
        self._data: Dict[str, Any] = {
            "dfd": {
                "name": name,
                "id": system_id,
                "description": description
            },
            "processes": [],
            "datastores": [],
            "external_entities": [],
            "data_flows": [],
            "trust_boundaries": []
        }

    def add_process(
        self,
        process_id: str,
        label: str,
        trust_level: str = "internal",
        **attrs
    ) -> 'ThreatModelBuilder':
        """Add a process to the diagram.

        Args:
            process_id: Unique identifier for the process.
            label: Display label.
            trust_level: Trust level (internal, external, trusted).
            **attrs: Additional attributes.

        Returns:
            Self for method chaining.
        """
        self._data["processes"].append({
            "id": process_id,
            "label": label,
            "trust_level": trust_level,
            **attrs
        })
        return self

    def add_datastore(
        self,
        store_id: str,
        label: str,
        store_type: str = "database",
        encrypted: bool = False,
        **attrs
    ) -> 'ThreatModelBuilder':
        """Add a data store to the diagram.

        Args:
            store_id: Unique identifier for the data store.
            label: Display label.
            store_type: Type of store (database, file, cache).
            encrypted: Whether the data is encrypted.
            **attrs: Additional attributes.

        Returns:
            Self for method chaining.
        """
        self._data["datastores"].append({
            "id": store_id,
            "label": label,
            "type": store_type,
            "encrypted": encrypted,
            **attrs
        })
        return self

    def add_external_entity(
        self,
        entity_id: str,
        label: str,
        entity_type: str = "user",
        **attrs
    ) -> 'ThreatModelBuilder':
        """Add an external entity to the diagram.

        Args:
            entity_id: Unique identifier for the entity.
            label: Display label.
            entity_type: Type of entity (user, system, service).
            **attrs: Additional attributes.

        Returns:
            Self for method chaining.
        """
        self._data["external_entities"].append({
            "id": entity_id,
            "label": label,
            "type": entity_type,
            **attrs
        })
        return self

    def add_data_flow(
        self,
        from_element: str,
        to_element: str,
        label: str = "",
        protocol: Optional[str] = None,
        encrypted: bool = False,
        authenticated: bool = False,
        **attrs
    ) -> 'ThreatModelBuilder':
        """Add a data flow between elements.

        Args:
            from_element: Source element ID.
            to_element: Destination element ID.
            label: Flow label/description.
            protocol: Communication protocol.
            encrypted: Whether the flow is encrypted.
            authenticated: Whether the flow requires authentication.
            **attrs: Additional attributes.

        Returns:
            Self for method chaining.
        """
        flow = {
            "from": from_element,
            "to": to_element,
            "encrypted": encrypted,
            "authenticated": authenticated,
            **attrs
        }
        if label:
            flow["label"] = label
        if protocol:
            flow["protocol"] = protocol
        self._data["data_flows"].append(flow)
        return self

    def add_trust_boundary(
        self,
        boundary_id: str,
        label: str,
        elements: List[str],
        **attrs
    ) -> 'ThreatModelBuilder':
        """Add a trust boundary containing elements.

        Args:
            boundary_id: Unique identifier for the boundary.
            label: Display label.
            elements: List of element IDs within this boundary.
            **attrs: Additional attributes.

        Returns:
            Self for method chaining.
        """
        self._data["trust_boundaries"].append({
            "id": boundary_id,
            "label": label,
            "elements": elements,
            **attrs
        })
        return self

    def set_dfd_attribute(self, key: str, value: Any) -> 'ThreatModelBuilder':
        """Set a DFD-level attribute.

        Args:
            key: Attribute name.
            value: Attribute value.

        Returns:
            Self for method chaining.
        """
        self._data["dfd"][key] = value
        return self

    def build(self) -> Dict[str, Any]:
        """Build and return the threat model data as a dictionary.

        Returns:
            Dictionary representation of the threat model.
        """
        return self._data.copy()

    def to_json(self, pretty: bool = True) -> str:
        """Convert to JSON string.

        Args:
            pretty: Whether to use pretty formatting.

        Returns:
            JSON string representation.
        """
        if pretty:
            return json.dumps(self._data, indent=2)
        return json.dumps(self._data)

    def to_threat_model(
        self,
        outputfile: str,
        format: str = "png",
        styleid: str = "tm_default"
    ) -> 'ThreatModeling':
        """Create ThreatModeling instance from builder data.

        Args:
            outputfile: Output file path (without extension).
            format: Output format (png, svg, pdf, dot).
            styleid: Style identifier to use.

        Returns:
            Configured ThreatModeling instance ready for rendering.
        """
        from .threatmodeling import ThreatModeling

        # Create a temporary file with the data
        with tempfile.NamedTemporaryFile(
            mode='w',
            suffix='.json',
            delete=False
        ) as f:
            json.dump(self._data, f)
            temp_path = f.name

        tm = ThreatModeling(temp_path, outputfile, format=format, styleid=styleid)
        tm._temp_input = temp_path  # Mark for cleanup
        return tm
