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
attack graphs, threat models, privilege gradient graphs, component diagrams,
and dependency graphs without needing to write configuration files.

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

from __future__ import annotations

import json
import tempfile
from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:
    from .attackgraphs import AttackGraphs
    from .attacktrees import AttackTrees
    from .componentdiagram import ComponentDiagram
    from .dependencygraph import DependencyGraph
    from .killchain import KillChain
    from .privilegegradient import PrivilegeGradient
    from .threatmodeling import ThreatModeling
    from .timeline import IncidentTimeline
    from .vulntree import VulnDependencyTree


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
        self._data: dict[str, Any] = {
            "tree": {"name": name, "root": root, "description": description},
            "nodes": {},
            "edges": {},
        }

    def add_node(
        self,
        node_id: str,
        label: Optional[str] = None,
        style: str = "filled",
        fillcolor: str = "#3498db",
        shape: str = "box",
        fontcolor: str = "white",
        **attrs,
    ) -> AttackTreeBuilder:
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
            **attrs,
        }
        return self

    def add_and_node(
        self, node_id: str, label: Optional[str] = None, fillcolor: str = "#e74c3c", **attrs
    ) -> AttackTreeBuilder:
        """Add an AND node (all children must be completed).

        Args:
            node_id: Unique identifier for the node.
            label: Display label (defaults to node_id).
            fillcolor: Node fill color.
            **attrs: Additional attributes.

        Returns:
            Self for method chaining.
        """
        return self.add_node(node_id, label=label, fillcolor=fillcolor, shape="trapezium", **attrs)

    def add_or_node(
        self, node_id: str, label: Optional[str] = None, fillcolor: str = "#2ecc71", **attrs
    ) -> AttackTreeBuilder:
        """Add an OR node (any child can complete it).

        Args:
            node_id: Unique identifier for the node.
            label: Display label (defaults to node_id).
            fillcolor: Node fill color.
            **attrs: Additional attributes.

        Returns:
            Self for method chaining.
        """
        return self.add_node(node_id, label=label, fillcolor=fillcolor, shape="invtrapezium", **attrs)

    def add_leaf_node(
        self, node_id: str, label: Optional[str] = None, fillcolor: str = "#9b59b6", **attrs
    ) -> AttackTreeBuilder:
        """Add a leaf node (basic attack step).

        Args:
            node_id: Unique identifier for the node.
            label: Display label (defaults to node_id).
            fillcolor: Node fill color.
            **attrs: Additional attributes.

        Returns:
            Self for method chaining.
        """
        return self.add_node(node_id, label=label, fillcolor=fillcolor, shape="ellipse", **attrs)

    def add_edge(
        self, from_node: str, to_node: str, label: str = "", style: str = "solid", color: str = "black", **attrs
    ) -> AttackTreeBuilder:
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

        self._data["edges"][from_node].append({"to": to_node, "label": label, "style": style, "color": color, **attrs})
        return self

    def add_and_edge(self, from_node: str, to_node: str, **attrs) -> AttackTreeBuilder:
        """Add an AND edge (required path).

        Args:
            from_node: Source node ID.
            to_node: Target node ID.
            **attrs: Additional attributes.

        Returns:
            Self for method chaining.
        """
        return self.add_edge(from_node, to_node, label="AND", style="solid", **attrs)

    def add_or_edge(self, from_node: str, to_node: str, **attrs) -> AttackTreeBuilder:
        """Add an OR edge (alternative path).

        Args:
            from_node: Source node ID.
            to_node: Target node ID.
            **attrs: Additional attributes.

        Returns:
            Self for method chaining.
        """
        return self.add_edge(from_node, to_node, label="OR", style="dashed", **attrs)

    def set_tree_attribute(self, key: str, value: Any) -> AttackTreeBuilder:
        """Set a tree-level attribute.

        Args:
            key: Attribute name.
            value: Attribute value.

        Returns:
            Self for method chaining.
        """
        self._data["tree"][key] = value
        return self

    def build(self) -> dict[str, Any]:
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
        self, outputfile: str, format: str = "png", styleid: str = "", render_engine: str = "graphviz"
    ) -> AttackTrees:
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
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(self._data, f)
            temp_path = f.name

        at = AttackTrees(temp_path, outputfile, format=format, styleid=styleid, render_engine=render_engine)
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
        self._data: dict[str, Any] = {
            "graph": {"name": name, "description": description},
            "hosts": [],
            "vulnerabilities": [],
            "privileges": [],
            "services": [],
            "exploits": [],
            "network_edges": [],
        }

    def add_host(
        self, host_id: str, label: str, ip: Optional[str] = None, zone: str = "internal", **attrs
    ) -> AttackGraphBuilder:
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
        host = {"id": host_id, "label": label, "zone": zone, **attrs}
        if ip:
            host["ip"] = ip
        self._data["hosts"].append(host)
        return self

    def add_vulnerability(
        self, vuln_id: str, label: str, cvss: float, affected_host: str, cve: Optional[str] = None, **attrs
    ) -> AttackGraphBuilder:
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
        vuln = {"id": vuln_id, "label": label, "cvss": cvss, "affected_host": affected_host, **attrs}
        if cve:
            vuln["cve"] = cve
        self._data["vulnerabilities"].append(vuln)
        return self

    def add_privilege(self, priv_id: str, label: str, host: str, level: str = "user", **attrs) -> AttackGraphBuilder:
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
        self._data["privileges"].append({"id": priv_id, "label": label, "host": host, "level": level, **attrs})
        return self

    def add_service(
        self, service_id: str, label: str, host: str, port: int, protocol: str = "tcp", **attrs
    ) -> AttackGraphBuilder:
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
        self._data["services"].append(
            {"id": service_id, "label": label, "host": host, "port": port, "protocol": protocol, **attrs}
        )
        return self

    def add_exploit(
        self, exploit_id: str, label: str, vulnerability: str, precondition: str, postcondition: str, **attrs
    ) -> AttackGraphBuilder:
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
        self._data["exploits"].append(
            {
                "id": exploit_id,
                "label": label,
                "vulnerability": vulnerability,
                "precondition": precondition,
                "postcondition": postcondition,
                **attrs,
            }
        )
        return self

    def add_network_edge(self, from_host: str, to_host: str, label: str = "", **attrs) -> AttackGraphBuilder:
        """Add a network connection between hosts.

        Args:
            from_host: Source host ID.
            to_host: Destination host ID.
            label: Edge label.
            **attrs: Additional attributes.

        Returns:
            Self for method chaining.
        """
        edge = {"from": from_host, "to": to_host, **attrs}
        if label:
            edge["label"] = label
        self._data["network_edges"].append(edge)
        return self

    def set_graph_attribute(self, key: str, value: Any) -> AttackGraphBuilder:
        """Set a graph-level attribute.

        Args:
            key: Attribute name.
            value: Attribute value.

        Returns:
            Self for method chaining.
        """
        self._data["graph"][key] = value
        return self

    def build(self) -> dict[str, Any]:
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
        self, outputfile: str, format: str = "png", styleid: str = "", render_engine: str = "graphviz"
    ) -> AttackGraphs:
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
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(self._data, f)
            temp_path = f.name

        ag = AttackGraphs(temp_path, outputfile, format=format, styleid=styleid, render_engine=render_engine)
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
        self._data: dict[str, Any] = {
            "dfd": {"name": name, "id": system_id, "description": description},
            "processes": [],
            "datastores": [],
            "external_entities": [],
            "data_flows": [],
            "trust_boundaries": [],
        }

    def add_process(self, process_id: str, label: str, trust_level: str = "internal", **attrs) -> ThreatModelBuilder:
        """Add a process to the diagram.

        Args:
            process_id: Unique identifier for the process.
            label: Display label.
            trust_level: Trust level (internal, external, trusted).
            **attrs: Additional attributes.

        Returns:
            Self for method chaining.
        """
        self._data["processes"].append({"id": process_id, "label": label, "trust_level": trust_level, **attrs})
        return self

    def add_datastore(
        self, store_id: str, label: str, store_type: str = "database", encrypted: bool = False, **attrs
    ) -> ThreatModelBuilder:
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
        self._data["datastores"].append(
            {"id": store_id, "label": label, "type": store_type, "encrypted": encrypted, **attrs}
        )
        return self

    def add_external_entity(self, entity_id: str, label: str, entity_type: str = "user", **attrs) -> ThreatModelBuilder:
        """Add an external entity to the diagram.

        Args:
            entity_id: Unique identifier for the entity.
            label: Display label.
            entity_type: Type of entity (user, system, service).
            **attrs: Additional attributes.

        Returns:
            Self for method chaining.
        """
        self._data["external_entities"].append({"id": entity_id, "label": label, "type": entity_type, **attrs})
        return self

    def add_data_flow(
        self,
        from_element: str,
        to_element: str,
        label: str = "",
        protocol: Optional[str] = None,
        encrypted: bool = False,
        authenticated: bool = False,
        **attrs,
    ) -> ThreatModelBuilder:
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
        flow = {"from": from_element, "to": to_element, "encrypted": encrypted, "authenticated": authenticated, **attrs}
        if label:
            flow["label"] = label
        if protocol:
            flow["protocol"] = protocol
        self._data["data_flows"].append(flow)
        return self

    def add_trust_boundary(self, boundary_id: str, label: str, elements: list[str], **attrs) -> ThreatModelBuilder:
        """Add a trust boundary containing elements.

        Args:
            boundary_id: Unique identifier for the boundary.
            label: Display label.
            elements: List of element IDs within this boundary.
            **attrs: Additional attributes.

        Returns:
            Self for method chaining.
        """
        self._data["trust_boundaries"].append({"id": boundary_id, "label": label, "elements": elements, **attrs})
        return self

    def set_dfd_attribute(self, key: str, value: Any) -> ThreatModelBuilder:
        """Set a DFD-level attribute.

        Args:
            key: Attribute name.
            value: Attribute value.

        Returns:
            Self for method chaining.
        """
        self._data["dfd"][key] = value
        return self

    def build(self) -> dict[str, Any]:
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
        self, outputfile: str, format: str = "png", styleid: str = "", render_engine: str = "graphviz"
    ) -> ThreatModeling:
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
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(self._data, f)
            temp_path = f.name

        tm = ThreatModeling(temp_path, outputfile, format=format, styleid=styleid, render_engine=render_engine)
        tm._temp_input = temp_path  # Mark for cleanup
        return tm


class PrivilegeGradientBuilder:
    """Builder for programmatically creating privilege gradient graphs.

    Provides a fluent interface for constructing privilege gradient graphs
    with trust zones, components, influence types, and influences.

    Example:
        >>> builder = PrivilegeGradientBuilder("Auth Architecture")
        >>> builder.add_component("browser", "Browser", "Z0")
        >>> builder.add_component("api_gw", "API Gateway", "Z1")
        >>> builder.add_data_influence("browser", "api_gw", "HTTP Request")
        >>> pg = builder.to_privilege_gradient("output")
    """

    DEFAULT_ZONES = [
        {
            "id": "Z0",
            "label": "Untrusted / External",
            "trust_level": 0,
            "color": "#ffcccc",
            "border_color": "#cc0000",
            "font_color": "#660000",
        },
        {
            "id": "Z1",
            "label": "Edge / DMZ",
            "trust_level": 1,
            "color": "#ffe0b2",
            "border_color": "#e65100",
            "font_color": "#663300",
        },
        {
            "id": "Z2",
            "label": "Application Tier",
            "trust_level": 2,
            "color": "#fff9c4",
            "border_color": "#f9a825",
            "font_color": "#665500",
        },
        {
            "id": "Z3",
            "label": "Control Plane",
            "trust_level": 3,
            "color": "#c8e6c9",
            "border_color": "#2e7d32",
            "font_color": "#1b5e20",
        },
        {
            "id": "Z4",
            "label": "Root of Trust",
            "trust_level": 4,
            "color": "#bbdefb",
            "border_color": "#1565c0",
            "font_color": "#0d47a1",
        },
    ]

    DEFAULT_INFLUENCE_TYPES = [
        {
            "id": "data",
            "label": "Data Flow",
            "color": "#3498db",
            "style": "solid",
            "arrowhead": "vee",
            "penwidth": "1.5",
        },
        {
            "id": "feedback",
            "label": "Feedback",
            "color": "#e67e22",
            "style": "dashed",
            "arrowhead": "vee",
            "penwidth": "1.5",
        },
        {
            "id": "resource",
            "label": "Resource",
            "color": "#27ae60",
            "style": "dotted",
            "arrowhead": "diamond",
            "penwidth": "2",
        },
        {"id": "control", "label": "Control", "color": "#8e44ad", "style": "bold", "arrowhead": "dot", "penwidth": "2"},
    ]

    def __init__(
        self, name: str, description: str = "", use_default_zones: bool = True, use_default_influence_types: bool = True
    ):
        """Initialize PrivilegeGradientBuilder.

        Args:
            name: Name of the privilege gradient graph.
            description: Optional description.
            use_default_zones: Whether to include default trust zones.
            use_default_influence_types: Whether to include default influence types.
        """
        self._data: dict[str, Any] = {
            "gradient": {
                "name": name,
                "description": description,
            },
            "zones": [],
            "components": [],
            "influence_types": [],
            "influences": [],
        }

        if use_default_zones:
            for z in self.DEFAULT_ZONES:
                self._data["zones"].append(z.copy())

        if use_default_influence_types:
            for it in self.DEFAULT_INFLUENCE_TYPES:
                self._data["influence_types"].append(it.copy())

        self._influence_counter = 0

    def add_zone(
        self,
        zone_id: str,
        label: str,
        trust_level: int,
        color: str = "#f0f0f0",
        border_color: str = "#999999",
        font_color: str = "#333333",
        **attrs,
    ) -> PrivilegeGradientBuilder:
        """Add a trust zone.

        Args:
            zone_id: Unique identifier for the zone.
            label: Display label.
            trust_level: Trust level (0 = lowest).
            color: Zone background fill color.
            border_color: Zone border color.
            font_color: Zone label font color.
            **attrs: Additional attributes.

        Returns:
            Self for method chaining.
        """
        self._data["zones"].append(
            {
                "id": zone_id,
                "label": label,
                "trust_level": trust_level,
                "color": color,
                "border_color": border_color,
                "font_color": font_color,
                **attrs,
            }
        )
        return self

    def add_component(self, comp_id: str, label: str, zone: str, **attrs) -> PrivilegeGradientBuilder:
        """Add a component to a zone.

        Args:
            comp_id: Unique identifier for the component.
            label: Display label.
            zone: Zone ID this component belongs to.
            **attrs: Additional attributes.

        Returns:
            Self for method chaining.
        """
        self._data["components"].append({"id": comp_id, "label": label, "zone": zone, **attrs})
        return self

    def add_influence_type(
        self,
        type_id: str,
        label: str,
        color: str = "#333333",
        style: str = "solid",
        arrowhead: str = "vee",
        penwidth: str = "1.5",
        **attrs,
    ) -> PrivilegeGradientBuilder:
        """Add an influence type definition.

        Args:
            type_id: Unique identifier for the influence type.
            label: Display label.
            color: Edge color.
            style: Edge style (solid, dashed, dotted, bold).
            arrowhead: Arrow head style.
            penwidth: Edge pen width.
            **attrs: Additional attributes.

        Returns:
            Self for method chaining.
        """
        self._data["influence_types"].append(
            {
                "id": type_id,
                "label": label,
                "color": color,
                "style": style,
                "arrowhead": arrowhead,
                "penwidth": penwidth,
                **attrs,
            }
        )
        return self

    def add_influence(
        self,
        from_comp: str,
        to_comp: str,
        influence_type: str = "data",
        label: str = "",
        influence_id: Optional[str] = None,
        **attrs,
    ) -> PrivilegeGradientBuilder:
        """Add an influence edge between components.

        Args:
            from_comp: Source component ID.
            to_comp: Target component ID.
            influence_type: Influence type ID.
            label: Edge label.
            influence_id: Optional unique ID for the influence.
            **attrs: Additional attributes.

        Returns:
            Self for method chaining.
        """
        if influence_id is None:
            self._influence_counter += 1
            influence_id = f"inf_{self._influence_counter}"

        influence = {"id": influence_id, "from": from_comp, "to": to_comp, "type": influence_type, **attrs}
        if label:
            influence["label"] = label
        self._data["influences"].append(influence)
        return self

    def add_data_influence(self, from_comp: str, to_comp: str, label: str = "", **attrs) -> PrivilegeGradientBuilder:
        """Add a data flow influence."""
        return self.add_influence(from_comp, to_comp, "data", label, **attrs)

    def add_feedback_influence(
        self, from_comp: str, to_comp: str, label: str = "", **attrs
    ) -> PrivilegeGradientBuilder:
        """Add a feedback influence."""
        return self.add_influence(from_comp, to_comp, "feedback", label, **attrs)

    def add_resource_influence(
        self, from_comp: str, to_comp: str, label: str = "", **attrs
    ) -> PrivilegeGradientBuilder:
        """Add a resource dependency influence."""
        return self.add_influence(from_comp, to_comp, "resource", label, **attrs)

    def add_control_influence(self, from_comp: str, to_comp: str, label: str = "", **attrs) -> PrivilegeGradientBuilder:
        """Add a control flow influence."""
        return self.add_influence(from_comp, to_comp, "control", label, **attrs)

    def set_gradient_attribute(self, key: str, value: Any) -> PrivilegeGradientBuilder:
        """Set a gradient-level attribute.

        Args:
            key: Attribute name.
            value: Attribute value.

        Returns:
            Self for method chaining.
        """
        self._data["gradient"][key] = value
        return self

    def build(self) -> dict[str, Any]:
        """Build and return the data as a dictionary.

        Returns:
            Dictionary representation of the privilege gradient graph.
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

    def to_privilege_gradient(
        self, outputfile: str, format: str = "png", styleid: str = "", render_engine: str = "graphviz"
    ) -> PrivilegeGradient:
        """Create PrivilegeGradient instance from builder data.

        Args:
            outputfile: Output file path (without extension).
            format: Output format (png, svg, pdf, dot).
            styleid: Style identifier to use.

        Returns:
            Configured PrivilegeGradient instance ready for rendering.
        """
        from .privilegegradient import PrivilegeGradient

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(self._data, f)
            temp_path = f.name

        pg = PrivilegeGradient(temp_path, outputfile, format=format, styleid=styleid, render_engine=render_engine)
        pg._temp_input = temp_path
        return pg


class ComponentDiagramBuilder:
    """Builder for programmatically creating component diagrams.

    Provides a fluent interface for constructing layered architecture
    diagrams with components and connections.

    Example:
        >>> builder = ComponentDiagramBuilder("Platform Architecture")
        >>> builder.add_layer("Client", "top")
        >>> builder.add_component("browser", "Vue.js SPA", "Client", tech="Vue 3")
        >>> builder.add_connection("browser", "api", "HTTPS", style="sync")
        >>> cd = builder.to_component_diagram("output")
    """

    def __init__(self, title: str, description: str = ""):
        self._data: dict[str, Any] = {
            "title": title,
            "description": description,
            "layers": [],
            "connections": [],
        }
        self._layer_map: dict[str, dict] = {}

    def add_layer(
        self,
        name: str,
        position: str = "middle",
    ) -> ComponentDiagramBuilder:
        """Add a layer to the diagram.

        Args:
            name: Layer name.
            position: Position hint (top, middle, bottom).

        Returns:
            Self for method chaining.
        """
        layer = {
            "name": name,
            "position": position,
            "components": [],
        }
        self._data["layers"].append(layer)
        self._layer_map[name] = layer
        return self

    def add_component(
        self, comp_id: str, name: str, layer: str, comp_type: str = "service", tech: str = "", **attrs
    ) -> ComponentDiagramBuilder:
        """Add a component to a layer.

        Args:
            comp_id: Unique component identifier.
            name: Display name.
            layer: Layer name to add the component to.
            comp_type: Component type (frontend, service, database, etc.).
            tech: Technology label.
            **attrs: Additional attributes.

        Returns:
            Self for method chaining.
        """
        if layer not in self._layer_map:
            self.add_layer(layer)

        comp = {
            "id": comp_id,
            "name": name,
            "type": comp_type,
            **attrs,
        }
        if tech:
            comp["tech"] = tech

        self._layer_map[layer]["components"].append(comp)
        return self

    def add_connection(
        self, from_comp: str, to_comp: str, label: str = "", style: str = "sync", **attrs
    ) -> ComponentDiagramBuilder:
        """Add a connection between components.

        Args:
            from_comp: Source component ID.
            to_comp: Target component ID.
            label: Connection label.
            style: Connection style (sync, async, bidirectional, event).
            **attrs: Additional attributes.

        Returns:
            Self for method chaining.
        """
        conn = {
            "from": from_comp,
            "to": to_comp,
            "style": style,
            **attrs,
        }
        if label:
            conn["label"] = label
        self._data["connections"].append(conn)
        return self

    def build(self) -> dict[str, Any]:
        return self._data.copy()

    def to_json(self, pretty: bool = True) -> str:
        if pretty:
            return json.dumps(self._data, indent=2)
        return json.dumps(self._data)

    def to_component_diagram(
        self, outputfile: str, format: str = "png", styleid: str = "", render_engine: str = "graphviz"
    ) -> ComponentDiagram:
        """Create ComponentDiagram instance from builder data."""
        from .componentdiagram import ComponentDiagram

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(self._data, f)
            temp_path = f.name

        cd = ComponentDiagram(temp_path, outputfile, format=format, styleid=styleid, render_engine=render_engine)
        cd._temp_input = temp_path
        return cd


class DependencyGraphBuilder:
    """Builder for programmatically creating dependency graphs.

    Provides a fluent interface for constructing module dependency graphs
    with SLOC sizing and circular dependency detection.

    Example:
        >>> builder = DependencyGraphBuilder("Module Dependencies")
        >>> builder.add_module("accounts", "Accounts", sloc=1500, group="core")
        >>> builder.add_dependency("scanning", "accounts", weight="heavy")
        >>> builder.mark_circular(["scanning", "accounts"])
        >>> dg = builder.to_dependency_graph("output")
    """

    def __init__(self, title: str, description: str = ""):
        self._data: dict[str, Any] = {
            "title": title,
            "description": description,
            "modules": [],
            "dependencies": [],
            "circular": [],
        }

    def add_module(
        self,
        mod_id: str,
        name: str,
        mod_type: str = "internal",
        sloc: int = 0,
        language: str = "",
        group: str = "",
        version: str = "",
        **attrs,
    ) -> DependencyGraphBuilder:
        """Add a module to the graph.

        Args:
            mod_id: Unique module identifier.
            name: Display name.
            mod_type: Module type (internal, external).
            sloc: Source lines of code.
            language: Programming language.
            group: Module group for clustering.
            version: Version string (for external modules).
            **attrs: Additional attributes.

        Returns:
            Self for method chaining.
        """
        mod = {
            "id": mod_id,
            "name": name,
            "type": mod_type,
            **attrs,
        }
        if sloc:
            mod["sloc"] = sloc
        if language:
            mod["language"] = language
        if group:
            mod["group"] = group
        if version:
            mod["version"] = version
        self._data["modules"].append(mod)
        return self

    def add_dependency(
        self, from_mod: str, to_mod: str, dep_type: str = "import", weight: str = "medium", **attrs
    ) -> DependencyGraphBuilder:
        """Add a dependency between modules.

        Args:
            from_mod: Source module ID.
            to_mod: Target module ID.
            dep_type: Dependency type (import, framework, runtime).
            weight: Dependency weight (light, medium, heavy).
            **attrs: Additional attributes.

        Returns:
            Self for method chaining.
        """
        self._data["dependencies"].append(
            {
                "from": from_mod,
                "to": to_mod,
                "type": dep_type,
                "weight": weight,
                **attrs,
            }
        )
        return self

    def mark_circular(self, cycle: list[str]) -> DependencyGraphBuilder:
        """Mark a circular dependency.

        Args:
            cycle: List of module IDs forming a cycle.

        Returns:
            Self for method chaining.
        """
        self._data["circular"].append(cycle)
        return self

    def build(self) -> dict[str, Any]:
        return self._data.copy()

    def to_json(self, pretty: bool = True) -> str:
        if pretty:
            return json.dumps(self._data, indent=2)
        return json.dumps(self._data)

    def to_dependency_graph(
        self, outputfile: str, format: str = "png", styleid: str = "", render_engine: str = "graphviz"
    ) -> DependencyGraph:
        """Create DependencyGraph instance from builder data."""
        from .dependencygraph import DependencyGraph

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(self._data, f)
            temp_path = f.name

        dg = DependencyGraph(temp_path, outputfile, format=format, styleid=styleid, render_engine=render_engine)
        dg._temp_input = temp_path
        return dg


class KillChainBuilder:
    """Builder for programmatically creating kill chain / ATT&CK models.

    Example:
        >>> builder = KillChainBuilder("APT Intrusion", framework="kill_chain")
        >>> builder.add_technique("T1566", "Spearphishing", "Delivery", detected=True)
        >>> builder.add_incident("INC-1", ["T1566"], name="Campaign")
        >>> kc = builder.to_kill_chain("output", render_engine="svg")
    """

    def __init__(self, name: str, framework: str = "kill_chain", phases: Optional[list[str]] = None):
        """Initialize the builder.

        Args:
            name: Kill chain name.
            framework: "kill_chain", "attack", "atlas" (MITRE ATLAS), or "custom".
            phases: Ordered phase list (required for the custom framework).
        """
        killchain: dict[str, Any] = {"name": name, "framework": framework}
        if phases is not None:
            killchain["phases"] = list(phases)
        self._data: dict[str, Any] = {"killchain": killchain, "techniques": {}, "incidents": []}

    def add_technique(
        self,
        tech_id: str,
        name: str,
        phase: str,
        severity: str = "medium",
        detected: bool = False,
        mitigated: bool = False,
        **attrs: Any,
    ) -> KillChainBuilder:
        """Add a technique mapped to a phase.

        Args:
            tech_id: Technique identifier (e.g. "T1566").
            name: Human-readable technique name.
            phase: Phase/tactic this technique belongs to.
            severity: critical | high | medium | low | none | info.
            detected: Whether detection coverage exists.
            mitigated: Whether mitigation coverage exists.
            **attrs: Extra fields (description, detection, mitigation).

        Returns:
            Self for method chaining.
        """
        self._data["techniques"][tech_id] = {
            "name": name,
            "phase": phase,
            "severity": severity,
            "detected": detected,
            "mitigated": mitigated,
            **attrs,
        }
        return self

    def add_incident(
        self,
        incident_id: str,
        techniques: list[str],
        name: Optional[str] = None,
        threat_actor: Optional[str] = None,
        campaign: Optional[str] = None,
    ) -> KillChainBuilder:
        """Add an ordered technique path (one incident).

        Returns:
            Self for method chaining.
        """
        incident: dict[str, Any] = {"id": incident_id, "name": name or incident_id, "techniques": list(techniques)}
        if threat_actor:
            incident["threat_actor"] = threat_actor
        if campaign:
            incident["campaign"] = campaign
        self._data["incidents"].append(incident)
        return self

    def build(self) -> dict[str, Any]:
        """Return the kill chain data as a dictionary."""
        return self._data.copy()

    def to_json(self, pretty: bool = True) -> str:
        """Convert to a JSON string."""
        return json.dumps(self._data, indent=2) if pretty else json.dumps(self._data)

    def to_kill_chain(
        self, outputfile: str, format: str = "png", styleid: str = "", render_engine: str = "graphviz"
    ) -> KillChain:
        """Create a KillChain instance from the builder data."""
        from .killchain import KillChain

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(self._data, f)
            temp_path = f.name

        kc = KillChain(temp_path, outputfile, format=format, styleid=styleid, render_engine=render_engine)
        kc._temp_input = temp_path
        return kc


class TimelineBuilder:
    """Builder for programmatically creating incident timelines.

    Example:
        >>> builder = TimelineBuilder("Ransomware Incident", incident_id="INC-1")
        >>> builder.add_phase("Detection", "2026-01-15T08:00:00Z", "2026-01-15T10:00:00Z")
        >>> builder.add_event("EVT-1", "2026-01-15T08:32:00Z", "Phishing opened", severity="high")
        >>> tl = builder.to_timeline("output", mode="swimlane")
    """

    def __init__(self, name: str, incident_id: Optional[str] = None, analyst: Optional[str] = None):
        """Initialize the builder.

        Args:
            name: Incident/timeline name.
            incident_id: Optional incident identifier.
            analyst: Optional analyst/team name.
        """
        incident: dict[str, Any] = {"name": name}
        if incident_id is not None:
            incident["id"] = incident_id
        if analyst is not None:
            incident["analyst"] = analyst
        self._data: dict[str, Any] = {"incident": incident, "phases": [], "events": []}

    def add_event(
        self,
        event_id: str,
        timestamp: str,
        title: str,
        severity: str = "info",
        lane: str = "Events",
        duration: Optional[str] = None,
        technique: Optional[str] = None,
        **attrs: Any,
    ) -> TimelineBuilder:
        """Add an event to the timeline.

        Args:
            event_id: Event identifier (e.g. "EVT-001").
            timestamp: ISO-8601 timestamp.
            title: Human-readable event title.
            severity: critical | high | medium | low | info.
            lane: Swimlane grouping (asset/actor).
            duration: Optional compact duration (e.g. "2m", "1h30m").
            technique: Optional ATT&CK technique id.
            **attrs: Extra fields (description, source, indicators).

        Returns:
            Self for method chaining.
        """
        event: dict[str, Any] = {
            "id": event_id,
            "timestamp": timestamp,
            "title": title,
            "severity": severity,
            "lane": lane,
        }
        if duration is not None:
            event["duration"] = duration
        if technique is not None:
            event["technique"] = technique
        event.update(attrs)
        self._data["events"].append(event)
        return self

    def add_phase(
        self,
        name: str,
        start: str,
        end: str,
        color: Optional[str] = None,
        description: Optional[str] = None,
    ) -> TimelineBuilder:
        """Add a response phase band.

        Returns:
            Self for method chaining.
        """
        phase: dict[str, Any] = {"name": name, "start": start, "end": end}
        if color is not None:
            phase["color"] = color
        if description is not None:
            phase["description"] = description
        self._data["phases"].append(phase)
        return self

    def build(self) -> dict[str, Any]:
        """Return the timeline data as a dictionary."""
        return self._data.copy()

    def to_json(self, pretty: bool = True) -> str:
        """Convert to a JSON string."""
        return json.dumps(self._data, indent=2) if pretty else json.dumps(self._data)

    def to_timeline(
        self, outputfile: str, format: str = "png", styleid: str = "", mode: str = "swimlane"
    ) -> IncidentTimeline:
        """Create an IncidentTimeline instance from the builder data."""
        from .timeline import IncidentTimeline

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(self._data, f)
            temp_path = f.name

        tl = IncidentTimeline(temp_path, outputfile, format=format, styleid=styleid, mode=mode)
        tl._temp_input = temp_path
        return tl


class VulnTreeBuilder:
    """Builder for programmatically creating vulnerability dependency trees.

    Example:
        >>> builder = VulnTreeBuilder("my-app", root_packages=["app"])
        >>> builder.add_dependency("app", "app", "1.0.0", dependencies=["lodash"])
        >>> builder.add_dependency("lodash", "lodash", "4.17.20", direct=False)
        >>> builder.add_vulnerability("lodash", "CVE-2021-23337", "high", cvss=7.2, fixed_version="4.17.21")
        >>> vt = builder.to_vuln_tree("output", mode="vulnerable_only")
    """

    def __init__(self, name: str, root_packages: Optional[list[str]] = None):
        """Initialize the builder.

        Args:
            name: Tree/project name.
            root_packages: Optional explicit list of root dependency ids.
        """
        vulntree: dict[str, Any] = {"name": name}
        if root_packages is not None:
            vulntree["root_packages"] = list(root_packages)
        self._data: dict[str, Any] = {"vulntree": vulntree, "dependencies": {}}

    def add_dependency(
        self,
        dep_id: str,
        name: str,
        version: str = "",
        direct: bool = True,
        dependencies: Optional[list[str]] = None,
        license: str = "",
    ) -> VulnTreeBuilder:
        """Add a dependency (package) node.

        Returns:
            Self for method chaining.
        """
        self._data["dependencies"][dep_id] = {
            "name": name,
            "version": version,
            "direct": direct,
            "dependencies": list(dependencies) if dependencies else [],
            "license": license,
            "vulnerabilities": [],
        }
        return self

    def add_vulnerability(
        self,
        dep_id: str,
        cve_id: str,
        severity: str = "none",
        cvss: float = 0.0,
        fixed_version: Optional[str] = None,
        exploited: bool = False,
        **attrs: Any,
    ) -> VulnTreeBuilder:
        """Attach a vulnerability (CVE) to an existing dependency.

        Args:
            dep_id: Id of a dependency added via ``add_dependency``.
            cve_id: CVE identifier.
            severity: critical | high | medium | low | none.
            cvss: CVSS base score.
            fixed_version: Version that remediates the CVE, if any.
            exploited: Whether the CVE is known-exploited.
            **attrs: Extra fields (description, cwe).

        Returns:
            Self for method chaining.

        Raises:
            KeyError: If ``dep_id`` has not been added yet.
        """
        vuln: dict[str, Any] = {"id": cve_id, "severity": severity, "cvss": cvss, "exploited": exploited}
        if fixed_version is not None:
            vuln["fixed_version"] = fixed_version
        vuln.update(attrs)
        self._data["dependencies"][dep_id]["vulnerabilities"].append(vuln)
        return self

    def build(self) -> dict[str, Any]:
        """Return the vulnerability tree data as a dictionary."""
        return self._data.copy()

    def to_json(self, pretty: bool = True) -> str:
        """Convert to a JSON string."""
        return json.dumps(self._data, indent=2) if pretty else json.dumps(self._data)

    def to_vuln_tree(
        self, outputfile: str, format: str = "png", styleid: str = "", mode: str = "tree"
    ) -> VulnDependencyTree:
        """Create a VulnDependencyTree instance from the builder data."""
        from .vulntree import VulnDependencyTree

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(self._data, f)
            temp_path = f.name

        vt = VulnDependencyTree(temp_path, outputfile, format=format, styleid=styleid, mode=mode)
        vt._temp_input = temp_path
        return vt
