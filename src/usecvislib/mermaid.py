#
# VULNEX -Universal Security Visualization Library-
#
# File: mermaid.py
# Author: Simon Roses Femerling / Claude Code
# Created: 2025-12-28
# Last Modified: 2025-12-29
# Version: 0.3.1
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""
Mermaid diagram syntax generator for USecVisLib.

Converts visualization configuration data (attack trees, threat models,
attack graphs, kill chains) into Mermaid diagram syntax.

Mermaid is a JavaScript-based diagramming tool that renders markdown-like
text definitions into diagrams. This module generates the text syntax
that can be rendered by Mermaid in browsers, documentation tools
(GitHub, GitLab, VS Code), or exported as .mmd files.

Supported diagram types:
- Flowchart (for attack trees, threat models, attack graphs)
- Sequence diagrams (for threat model data flows)
- Gantt charts (for timelines)

Usage:
    from usecvislib.mermaid import serialize_to_mermaid, detect_visualization_type

    # Convert configuration to Mermaid
    config = ReadConfigFile("attack_tree.toml")
    mermaid_syntax = serialize_to_mermaid(config)

    # Auto-detect visualization type
    vis_type = detect_visualization_type(config)
"""

import re
from enum import Enum
from typing import Any, Optional


class MermaidDiagramType(str, Enum):
    """Supported Mermaid diagram types."""

    FLOWCHART = "flowchart"
    SEQUENCE = "sequenceDiagram"
    GANTT = "gantt"


class MermaidDirection(str, Enum):
    """Flowchart direction options."""

    TOP_DOWN = "TD"
    BOTTOM_UP = "BT"
    LEFT_RIGHT = "LR"
    RIGHT_LEFT = "RL"


# =============================================================================
# Helper Functions
# =============================================================================


_MERMAID_RESERVED_IDS = frozenset(
    {
        "end",
        "graph",
        "subgraph",
        "flowchart",
        "class",
        "classdef",
        "style",
        "click",
        "linkstyle",
        "default",
        "direction",
    }
)


def sanitize_node_id(node_id: str) -> str:
    """
    Sanitize a node ID for Mermaid compatibility.

    Mermaid has restrictions on node IDs:
    - No spaces (use underscores)
    - No special characters except underscore
    - Cannot start with number in some contexts

    Args:
        node_id: Original node identifier

    Returns:
        Sanitized identifier safe for Mermaid
    """
    if not node_id:
        return "node"

    # Replace spaces and hyphens with underscores
    sanitized = re.sub(r"[\s\-]+", "_", str(node_id))

    # Remove other special characters
    sanitized = re.sub(r"[^a-zA-Z0-9_]", "", sanitized)

    # Ensure doesn't start with number
    if sanitized and sanitized[0].isdigit():
        sanitized = "n_" + sanitized

    # Mermaid keywords cannot be node ids ("end" closes a subgraph)
    if sanitized.lower() in _MERMAID_RESERVED_IDS:
        sanitized += "_node"

    # Ensure not empty
    return sanitized or "node"


def escape_label(text: str, max_length: int = 100) -> str:
    """
    Escape text for use in Mermaid labels.

    Args:
        text: Original label text
        max_length: Maximum length before truncation

    Returns:
        Escaped text safe for Mermaid labels
    """
    if not text:
        return ""

    text = str(text)

    # Truncate if too long
    if len(text) > max_length:
        text = text[: max_length - 3] + "..."

    # Escape quotes
    text = text.replace('"', "'")

    # Handle special Mermaid characters
    text = text.replace("[", "(")
    text = text.replace("]", ")")
    text = text.replace("{", "(")
    text = text.replace("}", ")")
    text = text.replace("|", "/")
    text = text.replace("#", "")
    # Mermaid entity codes (plain "lt"/"gt" turned <<device>> into "ltltdevicegtgt")
    text = text.replace("<", "#lt;")
    text = text.replace(">", "#gt;")

    # Remove newlines
    text = text.replace("\n", " ").replace("\r", "")

    return text


# =============================================================================
# Visualization Type Detection
# =============================================================================


def detect_visualization_type(data: dict[str, Any]) -> str:
    """
    Detect the visualization type from configuration data.

    Args:
        data: Configuration dictionary

    Returns:
        Visualization type string: 'attack_tree', 'threat_model',
        'attack_graph', 'killchain', 'timeline', 'access_graph', 'vuln_tree',
        'component_diagram', 'dependency_graph', 'privilege_gradient',
        'maestro', 'node_graph', 'mermaid_source', or 'unknown'
    """
    # Mermaid templates already carry Mermaid source
    if isinstance(data.get("mermaid"), dict) and data["mermaid"].get("source"):
        return "mermaid_source"

    # Attack Trees: have 'tree' section with 'root'
    if "tree" in data and "root" in data.get("tree", {}):
        return "attack_tree"

    # Attack Graphs: have 'graph' section and 'hosts' or 'vulnerabilities'
    if "graph" in data and ("hosts" in data or "vulnerabilities" in data):
        return "attack_graph"

    # Threat Models: have 'model' section and (elements or dataflows/processes)
    if "model" in data:
        if "elements" in data:
            return "threat_model"
        # Alternative threat model structure with separate sections
        if any(k in data for k in ["dataflows", "processes", "externals", "datastores"]):
            return "threat_model"

    # Kill Chain: have 'killchain' section and 'techniques'
    if "killchain" in data and "techniques" in data:
        return "killchain"

    # Timeline/Incident: have 'incident' section and 'events'
    if "incident" in data and "events" in data:
        return "timeline"

    # Access Graph: have 'principals' and 'relations'
    if "principals" in data and "relations" in data:
        return "access_graph"

    # Vulnerability Tree: have 'dependencies' with 'vulnerabilities'
    if "dependencies" in data:
        deps = data.get("dependencies", {})
        if isinstance(deps, dict) and any("vulnerabilities" in v for v in deps.values() if isinstance(v, dict)):
            return "vuln_tree"

    # Component Diagram: layered components plus connections
    if isinstance(data.get("layers"), list) and "connections" in data:
        return "component_diagram"

    # Dependency Graph: modules plus dependencies
    if isinstance(data.get("modules"), list | dict) and "dependencies" in data:
        return "dependency_graph"

    # Privilege Gradient: trust zones, components, influences
    if "zones" in data and "components" in data and ("influences" in data or "gradient" in data):
        return "privilege_gradient"

    # MAESTRO: agents (with layers) and cross-layer threats
    if "agents" in data and ("cross_layer_threats" in data or "meta" in data):
        return "maestro"

    # Custom / cloud diagrams: plain node and edge lists
    if isinstance(data.get("nodes"), list) and isinstance(data.get("edges"), list):
        return "node_graph"

    return "unknown"


# =============================================================================
# Attack Tree Converter
# =============================================================================


def _convert_attack_tree(data: dict[str, Any], direction: MermaidDirection = MermaidDirection.TOP_DOWN) -> str:
    """
    Convert attack tree configuration to Mermaid flowchart.

    Args:
        data: Attack tree configuration
        direction: Flowchart direction

    Returns:
        Mermaid flowchart syntax
    """
    lines = [f"flowchart {direction.value}"]

    tree_info = data.get("tree", {})
    nodes = data.get("nodes", {})
    edges = data.get("edges", {})
    root_id = tree_info.get("root", "")

    # Add title as comment
    tree_name = tree_info.get("name", "Attack Tree")
    lines.append(f"    %% {escape_label(tree_name)}")
    lines.append("")

    # Generate node definitions
    for node_id, node_data in nodes.items():
        safe_id = sanitize_node_id(node_id)

        if isinstance(node_data, str):
            label = node_data
            node_type = ""
        else:
            label = node_data.get("label", node_id)
            node_type = node_data.get("type", "")

        safe_label = escape_label(label)

        # Determine node shape based on type
        if node_id == root_id:
            # Root node: stadium shape
            lines.append(f'    {safe_id}(["{safe_label}"])')
        elif node_type == "and":
            # AND node: hexagon
            lines.append(f'    {safe_id}{{{{"{safe_label}"}}}}')
        elif node_type == "or":
            # OR node: diamond
            lines.append(f'    {safe_id}{{"{safe_label}"}}')
        else:
            # Regular node: rectangle
            lines.append(f'    {safe_id}["{safe_label}"]')

    lines.append("")

    # Generate edges
    for source, targets in edges.items():
        safe_source = sanitize_node_id(source)

        if isinstance(targets, list):
            for target in targets:
                if isinstance(target, str):
                    safe_target = sanitize_node_id(target)
                    lines.append(f"    {safe_source} --> {safe_target}")
                elif isinstance(target, dict):
                    safe_target = sanitize_node_id(target.get("to", ""))
                    edge_label = target.get("label", "")
                    if edge_label:
                        lines.append(f'    {safe_source} -->|"{escape_label(edge_label)}"| {safe_target}')
                    else:
                        lines.append(f"    {safe_source} --> {safe_target}")
        elif isinstance(targets, dict):
            # Handle dict format {target_id: attrs}
            for target_id, attrs in targets.items():
                safe_target = sanitize_node_id(target_id)
                if isinstance(attrs, dict):
                    edge_label = attrs.get("label", "")
                    if edge_label:
                        lines.append(f'    {safe_source} -->|"{escape_label(edge_label)}"| {safe_target}')
                    else:
                        lines.append(f"    {safe_source} --> {safe_target}")
                else:
                    lines.append(f"    {safe_source} --> {safe_target}")

    # Add styling for root node
    if root_id:
        safe_root = sanitize_node_id(root_id)
        lines.append("")
        lines.append(f"    style {safe_root} fill:#e74c3c,color:#fff,stroke:#c0392b")

    return "\n".join(lines)


# =============================================================================
# Threat Model Converter
# =============================================================================


def _convert_threat_model(data: dict[str, Any], diagram_type: str = "flowchart") -> str:
    """
    Convert threat model configuration to Mermaid diagram.

    Args:
        data: Threat model configuration
        diagram_type: 'flowchart' for DFD or 'sequence' for data flow sequence

    Returns:
        Mermaid diagram syntax
    """
    if diagram_type == "sequence":
        return _convert_threat_model_sequence(data)
    return _convert_threat_model_flowchart(data)


def _convert_threat_model_flowchart(data: dict[str, Any]) -> str:
    """Convert threat model to DFD-style flowchart."""
    lines = ["flowchart LR"]

    model = data.get("model", {})
    boundaries = data.get("boundaries", {})

    # Support both unified 'elements' format and separate sections format
    if "elements" in data:
        elements = data.get("elements", {})
        flows = data.get("flows", {})
    else:
        # Build elements from separate sections (externals, processes, datastores)
        elements = {}
        for ext_id, ext_data in data.get("externals", {}).items():
            # Template uses 'label' instead of 'name'
            elem_name = ext_data.get("label", ext_data.get("name", ext_id))
            elements[ext_id] = {"name": elem_name, "type": "external", **ext_data}
        for proc_id, proc_data in data.get("processes", {}).items():
            elem_name = proc_data.get("label", proc_data.get("name", proc_id))
            elements[proc_id] = {"name": elem_name, "type": "process", **proc_data}
        for ds_id, ds_data in data.get("datastores", {}).items():
            elem_name = ds_data.get("label", ds_data.get("name", ds_id))
            elements[ds_id] = {"name": elem_name, "type": "datastore", **ds_data}
        # Use dataflows section with normalized field names
        flows = {}
        for flow_id, flow_data in data.get("dataflows", {}).items():
            flows[flow_id] = {
                "source": flow_data.get("from", flow_data.get("source", "")),
                "target": flow_data.get("to", flow_data.get("target", "")),
                "name": flow_data.get("label", flow_data.get("name", "")),
                **flow_data,
            }

    # Add title as comment
    model_name = model.get("name", "Threat Model")
    lines.append(f"    %% {escape_label(model_name)}")
    lines.append("")

    # Element type to shape mapping
    shape_map = {
        "process": ("((", "))"),  # Circle
        "datastore": ("[(", ")]"),  # Cylinder
        "external": ("[", "]"),  # Rectangle
        "actor": ("[", "]"),  # Rectangle
    }

    # Generate elements
    for elem_id, elem_data in elements.items():
        safe_id = sanitize_node_id(elem_id)
        label = elem_data.get("name", elem_id)
        elem_type = elem_data.get("type", "process")
        safe_label = escape_label(label)

        left, right = shape_map.get(elem_type, ("[", "]"))
        lines.append(f'    {safe_id}{left}"{safe_label}"{right}')

    lines.append("")

    # Generate flows (dataflows)
    for _flow_id, flow_data in flows.items():
        source = flow_data.get("source", "")
        target = flow_data.get("target", "")
        # The flow's label first ("data" is its classification list)
        flow_label = flow_data.get("label") or flow_data.get("name") or flow_data.get("data", "")
        if isinstance(flow_label, list):
            flow_label = ", ".join(str(v) for v in flow_label)

        if source and target:
            safe_source = sanitize_node_id(source)
            safe_target = sanitize_node_id(target)

            if flow_label:
                lines.append(f'    {safe_source} -->|"{escape_label(flow_label)}"| {safe_target}')
            else:
                lines.append(f"    {safe_source} --> {safe_target}")

    # Add subgraphs for boundaries
    if boundaries:
        lines.append("")
        for boundary_id, boundary_data in boundaries.items():
            boundary_name = boundary_data.get("label") or boundary_data.get("name", boundary_id)
            boundary_elements = boundary_data.get("elements", [])

            if boundary_elements:
                safe_boundary = sanitize_node_id(boundary_id)
                lines.append(f'    subgraph {safe_boundary}["{escape_label(boundary_name)}"]')
                for elem in boundary_elements:
                    lines.append(f"        {sanitize_node_id(elem)}")
                lines.append("    end")

    return "\n".join(lines)


def _convert_threat_model_sequence(data: dict[str, Any]) -> str:
    """Convert threat model flows to sequence diagram."""
    lines = ["sequenceDiagram"]

    elements = data.get("elements", {})
    flows = data.get("flows", {})

    # Add participants
    for elem_id, elem_data in elements.items():
        safe_id = sanitize_node_id(elem_id)
        label = elem_data.get("name", elem_id)
        elem_type = elem_data.get("type", "process")

        if elem_type in ("external", "actor"):
            lines.append(f"    actor {safe_id} as {escape_label(label)}")
        else:
            lines.append(f"    participant {safe_id} as {escape_label(label)}")

    lines.append("")

    # Add messages from flows
    for flow_id, flow_data in flows.items():
        source = flow_data.get("source", "")
        target = flow_data.get("target", "")
        flow_label = flow_data.get("data", flow_data.get("name", flow_id))

        if source and target:
            safe_source = sanitize_node_id(source)
            safe_target = sanitize_node_id(target)
            lines.append(f"    {safe_source}->>>{safe_target}: {escape_label(flow_label)}")

    return "\n".join(lines)


# =============================================================================
# Attack Graph Converter
# =============================================================================


def _list_to_dict(items: Any, id_key: str = "id") -> dict[str, Any]:
    """Convert list of items to dict keyed by id_key."""
    if isinstance(items, dict):
        return items
    if isinstance(items, list):
        return {item.get(id_key, f"item_{i}"): item for i, item in enumerate(items)}
    return {}


def _convert_attack_graph(data: dict[str, Any], max_nodes: int = 100) -> str:
    """
    Convert attack graph configuration to Mermaid flowchart.

    Args:
        data: Attack graph configuration
        max_nodes: Maximum nodes to include (for performance)

    Returns:
        Mermaid flowchart syntax
    """
    lines = ["flowchart LR"]

    graph_info = data.get("graph", {})
    # Handle both dict and list formats for collections
    hosts = _list_to_dict(data.get("hosts", {}))
    vulnerabilities = _list_to_dict(data.get("vulnerabilities", {}))
    privileges = _list_to_dict(data.get("privileges", {}))
    services = _list_to_dict(data.get("services", {}))
    exploits = _list_to_dict(data.get("exploits", {}))
    network = data.get("network", {})

    # Add title as comment
    graph_name = graph_info.get("name", "Attack Graph")
    lines.append(f"    %% {escape_label(graph_name)}")
    lines.append("")

    # Check total nodes
    total_nodes = len(hosts) + len(vulnerabilities) + len(privileges) + len(services)
    if total_nodes > max_nodes:
        lines.append(f"    %% Warning: Graph truncated ({total_nodes} nodes > {max_nodes} max)")
        lines.append("")

    node_count = 0

    # Generate host nodes (box shape)
    for host_id, host_data in hosts.items():
        if node_count >= max_nodes:
            break
        safe_id = sanitize_node_id(host_id)
        label = host_data.get("label", host_data.get("name", host_id))
        lines.append(f'    {safe_id}["{escape_label(label)}"]')
        node_count += 1

    # Generate vulnerability nodes (diamond shape, red)
    for vuln_id, vuln_data in vulnerabilities.items():
        if node_count >= max_nodes:
            break
        safe_id = sanitize_node_id(vuln_id)
        label = vuln_data.get("label", vuln_data.get("name", vuln_id))
        cvss = vuln_data.get("cvss", "")
        if cvss:
            label = f"{label} ({cvss})"
        lines.append(f'    {safe_id}{{"{escape_label(label)}"}}')
        node_count += 1

    # Generate privilege nodes (hexagon shape)
    for priv_id, priv_data in privileges.items():
        if node_count >= max_nodes:
            break
        safe_id = sanitize_node_id(priv_id)
        label = priv_data.get("label", priv_data.get("name", priv_id))
        lines.append(f'    {safe_id}{{{{"{escape_label(label)}"}}}}')
        node_count += 1

    # Generate service nodes (rounded rectangle)
    for svc_id, svc_data in services.items():
        if node_count >= max_nodes:
            break
        safe_id = sanitize_node_id(svc_id)
        label = svc_data.get("label", svc_data.get("name", svc_id))
        lines.append(f'    {safe_id}("{escape_label(label)}")')
        node_count += 1

    lines.append("")

    # Generate network edges: [[network_edges]] from/to (the schema the
    # module reads) plus the legacy {source: [targets]} "network" table
    known = set(hosts) | set(vulnerabilities) | set(privileges) | set(services)
    for edge in _items_of(data.get("network_edges", [])):
        src, dst = edge.get("from"), edge.get("to")
        if src and dst:
            for end in (src, dst):
                if end not in known:  # e.g. the external "attacker"
                    known.add(end)
                    lines.append(f'    {sanitize_node_id(end)}(["{escape_label(end)}"])')
            lines.append(_edge_line(sanitize_node_id(src), sanitize_node_id(dst), edge.get("label", ""), "-.->"))
    for source, targets in network.items() if isinstance(network, dict) else ():
        safe_source = sanitize_node_id(source)
        if isinstance(targets, list):
            for target in targets:
                safe_target = sanitize_node_id(target)
                lines.append(f"    {safe_source} -.-> {safe_target}")

    # Generate exploit edges (singular precondition/postcondition is the
    # module schema; plural lists are accepted too)
    def _as_list(value: Any) -> list[str]:
        if not value:
            return []
        return [str(v) for v in value] if isinstance(value, list) else [str(value)]

    for exploit_id, exploit_data in exploits.items():
        preconditions = _as_list(exploit_data.get("preconditions") or exploit_data.get("precondition"))
        postconditions = _as_list(exploit_data.get("postconditions") or exploit_data.get("postcondition"))

        for pre in preconditions:
            for post in postconditions:
                safe_pre = sanitize_node_id(pre)
                safe_post = sanitize_node_id(post)
                exploit_label = exploit_data.get("label", exploit_id)
                lines.append(f'    {safe_pre} ==>|"{escape_label(exploit_label)}"| {safe_post}')

    # Vulnerability to host connections
    for vuln_id, vuln_data in vulnerabilities.items():
        host = vuln_data.get("affected_host") or vuln_data.get("host", "")
        if host:
            safe_vuln = sanitize_node_id(vuln_id)
            safe_host = sanitize_node_id(host)
            lines.append(f"    {safe_vuln} --> {safe_host}")

    # Add styling
    lines.append("")
    lines.append("    %% Styling")
    for vuln_id in vulnerabilities:
        safe_id = sanitize_node_id(vuln_id)
        lines.append(f"    style {safe_id} fill:#e74c3c,color:#fff")
    for priv_id in privileges:
        safe_id = sanitize_node_id(priv_id)
        lines.append(f"    style {safe_id} fill:#f39c12,color:#fff")

    return "\n".join(lines)


# =============================================================================
# Kill Chain Converter
# =============================================================================


def _convert_killchain(data: dict[str, Any], diagram_type: str = "flowchart") -> str:
    """
    Convert kill chain configuration to Mermaid diagram.

    Args:
        data: Kill chain configuration
        diagram_type: 'flowchart' or 'timeline'

    Returns:
        Mermaid diagram syntax
    """
    if diagram_type == "timeline":
        return _convert_killchain_timeline(data)
    return _convert_killchain_flowchart(data)


def _convert_killchain_flowchart(data: dict[str, Any]) -> str:
    """Convert kill chain to horizontal flowchart."""
    lines = ["flowchart LR"]

    killchain_info = data.get("killchain", {})
    techniques = data.get("techniques", {})
    incidents = data.get("incidents", [])

    # Add title as comment
    kc_name = killchain_info.get("name", "Kill Chain")
    lines.append(f"    %% {escape_label(kc_name)}")
    lines.append("")

    # Generate technique nodes
    for tech_id, tech_data in techniques.items():
        safe_id = sanitize_node_id(tech_id)
        label = tech_data.get("name", tech_id)
        detected = tech_data.get("detected", False)
        mitigated = tech_data.get("mitigated", False)

        # Add status indicators
        status = ""
        if detected:
            status += " [D]"
        if mitigated:
            status += " [M]"

        safe_label = escape_label(label + status)
        lines.append(f'    {safe_id}["{safe_label}"]')

    lines.append("")

    # Generate edges from incidents
    edges_seen = set()
    for incident in incidents:
        tech_list = incident.get("techniques", [])
        for i in range(len(tech_list) - 1):
            source = tech_list[i]
            target = tech_list[i + 1]
            edge_key = (source, target)

            if edge_key not in edges_seen:
                safe_source = sanitize_node_id(source)
                safe_target = sanitize_node_id(target)
                lines.append(f"    {safe_source} --> {safe_target}")
                edges_seen.add(edge_key)

    # Add styling based on detection status
    lines.append("")
    lines.append("    %% Styling based on detection/mitigation")
    for tech_id, tech_data in techniques.items():
        safe_id = sanitize_node_id(tech_id)
        detected = tech_data.get("detected", False)
        mitigated = tech_data.get("mitigated", False)

        if detected and mitigated:
            lines.append(f"    style {safe_id} fill:#27ae60,color:#fff")
        elif detected or mitigated:
            lines.append(f"    style {safe_id} fill:#f39c12,color:#fff")
        else:
            lines.append(f"    style {safe_id} fill:#e74c3c,color:#fff")

    return "\n".join(lines)


def _convert_killchain_timeline(data: dict[str, Any]) -> str:
    """Convert kill chain to Mermaid timeline."""
    lines = ["timeline"]

    killchain_info = data.get("killchain", {})
    techniques = data.get("techniques", {})

    kc_name = killchain_info.get("name", "Kill Chain")
    lines.append(f"    title {escape_label(kc_name)}")
    lines.append("")

    # Group techniques by tactic
    tactics: dict[str, list[str]] = {}
    for tech_id, tech_data in techniques.items():
        tactic = tech_data.get("tactic", "Unknown")
        if tactic not in tactics:
            tactics[tactic] = []
        tactics[tactic].append(tech_data.get("name", tech_id))

    # Generate timeline sections
    for tactic, tech_names in tactics.items():
        lines.append(f"    section {escape_label(tactic)}")
        for tech_name in tech_names:
            lines.append(f"        {escape_label(tech_name)}")

    return "\n".join(lines)


# =============================================================================
# Timeline/Incident Converter
# =============================================================================


def _convert_timeline(data: dict[str, Any]) -> str:
    """
    Convert incident timeline to Mermaid Gantt chart.

    Args:
        data: Timeline configuration

    Returns:
        Mermaid Gantt chart syntax
    """
    lines = ["gantt"]

    incident = data.get("incident", {})
    events = data.get("events", [])
    phases = data.get("phases", [])

    incident_name = incident.get("name", "Incident Timeline")
    lines.append(f"    title {escape_label(incident_name)}")
    # Must match the "YYYY-MM-DD HH:MM:SS" form _add_gantt_event writes
    # (a "T" here left every date unparsable and crashed mermaid-cli)
    lines.append("    dateFormat YYYY-MM-DD HH:mm:ss")
    lines.append("    axisFormat %H:%M")
    lines.append("")

    # Group events by lane or phase
    if phases:
        # Use phases as sections. Each event goes to the first phase that
        # contains it (boundary events were listed twice) and events outside
        # every phase get their own section (they were dropped).
        def norm(ts: Any) -> str:
            return re.sub(r"(Z|[+-]\d{2}:?\d{2})$", "", str(ts or "")).replace("T", " ")

        placed: set[int] = set()
        for phase in phases:
            phase_name = phase.get("name", "Phase")
            phase_start, phase_end = norm(phase.get("start")), norm(phase.get("end"))
            members = [
                i
                for i, event in enumerate(events)
                if i not in placed and phase_start <= norm(event.get("timestamp")) <= phase_end
            ]
            if not members:
                continue
            lines.append(f"    section {escape_label(phase_name)}")
            for i in members:
                placed.add(i)
                _add_gantt_event(lines, events[i])
        rest = [event for i, event in enumerate(events) if i not in placed]
        if rest:
            lines.append("    section Other events")
            for event in rest:
                _add_gantt_event(lines, event)
    else:
        # Group by lane
        lanes: dict[str, list] = {}
        for event in events:
            lane = event.get("lane", "Events")
            if lane not in lanes:
                lanes[lane] = []
            lanes[lane].append(event)

        for lane_name, lane_events in lanes.items():
            lines.append(f"    section {escape_label(lane_name)}")
            for event in lane_events:
                _add_gantt_event(lines, event)

    return "\n".join(lines)


def _add_gantt_event(lines: list[str], event: dict[str, Any]) -> None:
    """Add a single event to Gantt chart lines."""
    title = event.get("title", "Event")
    event_id = event.get("id", "")
    severity = event.get("severity", "info")

    # Map severity to Gantt status
    status = ""
    if severity in ("critical", "high"):
        status = "crit,"
    elif severity == "medium":
        status = "active,"

    # Format timestamp for Gantt
    timestamp = event.get("timestamp", "")
    if timestamp:
        # Drop the timezone (Z or +hh:mm) for Mermaid; space-separated time
        timestamp = re.sub(r"(Z|[+-]\d{2}:?\d{2})$", "", str(timestamp)).replace("T", " ")

    duration = event.get("duration", "5m")

    # ":" separates a gantt task's title from its data
    safe_title = escape_label(title).replace(":", " -")
    safe_id = sanitize_node_id(event_id) if event_id else ""

    if safe_id:
        lines.append(f"        {safe_title} :{status} {safe_id}, {timestamp}, {duration}")
    else:
        lines.append(f"        {safe_title} :{status} {timestamp}, {duration}")


# =============================================================================
# Access Graph Converter
# =============================================================================


def _convert_access_graph(data: dict[str, Any], max_nodes: int = 50) -> str:
    """
    Convert access graph configuration to Mermaid flowchart.

    Args:
        data: Access graph configuration
        max_nodes: Maximum nodes to include

    Returns:
        Mermaid flowchart syntax
    """
    lines = ["flowchart LR"]

    graph_info = data.get("graph", {})
    principals = data.get("principals", {})
    resources = data.get("resources", {})
    relations = data.get("relations", [])

    graph_name = graph_info.get("name", "Access Graph")
    lines.append(f"    %% {escape_label(graph_name)}")
    lines.append("")

    # Principal type to shape mapping
    principal_shapes = {
        "user": ("((", "))"),  # Circle
        "group": ("{{", "}}"),  # Hexagon
        "role": ("{", "}"),  # Diamond
        "service_account": ("[", "]"),  # Rectangle
        "machine": ("[/", "/]"),  # Parallelogram
    }

    node_count = 0

    # Generate principal nodes
    for p_id, p_data in principals.items():
        if node_count >= max_nodes:
            break
        safe_id = sanitize_node_id(p_id)
        label = p_data.get("name", p_id)
        p_type = p_data.get("type", "user")
        privileged = p_data.get("privileged", False)

        if privileged:
            label += " [PRIV]"

        left, right = principal_shapes.get(p_type, ("(", ")"))
        lines.append(f'    {safe_id}{left}"{escape_label(label)}"{right}')
        node_count += 1

    # Generate resource nodes
    for r_id, r_data in resources.items():
        if node_count >= max_nodes:
            break
        safe_id = sanitize_node_id(r_id)
        label = r_data.get("name", r_id)
        lines.append(f'    {safe_id}[("{escape_label(label)}")]')
        node_count += 1

    lines.append("")

    # Generate relations
    valid_nodes = {sanitize_node_id(p) for p in principals}
    valid_nodes.update(sanitize_node_id(r) for r in resources)

    for rel in relations:
        source = rel.get("source", "")
        target = rel.get("target", "")
        rel_type = rel.get("type", "")

        safe_source = sanitize_node_id(source)
        safe_target = sanitize_node_id(target)

        # Only include if both nodes are in the graph
        if safe_source in valid_nodes and safe_target in valid_nodes:
            if rel_type:
                lines.append(f'    {safe_source} -->|"{escape_label(rel_type)}"| {safe_target}')
            else:
                lines.append(f"    {safe_source} --> {safe_target}")

    # Styling for privileged principals
    lines.append("")
    for p_id, p_data in principals.items():
        if p_data.get("privileged"):
            safe_id = sanitize_node_id(p_id)
            lines.append(f"    style {safe_id} fill:#f39c12,color:#fff,stroke:#d35400")

    return "\n".join(lines)


# =============================================================================
# Vulnerability Tree Converter
# =============================================================================


def _convert_vuln_tree(data: dict[str, Any]) -> str:
    """
    Convert vulnerability dependency tree to Mermaid flowchart.

    Args:
        data: Vulnerability tree configuration

    Returns:
        Mermaid flowchart syntax
    """
    lines = ["flowchart TD"]

    dependencies = data.get("dependencies", {})
    root_packages = data.get("root_packages", list(dependencies.keys())[:5])

    lines.append("    %% Vulnerability Dependency Tree")
    lines.append("")

    # Severity colors
    severity_styles = {
        "critical": "fill:#7b1fa2,color:#fff",
        "high": "fill:#c62828,color:#fff",
        "medium": "fill:#ef6c00,color:#fff",
        "low": "fill:#fbc02d,color:#000",
        "none": "fill:#4caf50,color:#fff",
    }

    processed = set()

    def process_dep(dep_id: str, depth: int = 0) -> None:
        if dep_id in processed or depth > 5:
            return
        processed.add(dep_id)

        dep_data = dependencies.get(dep_id, {})
        safe_id = sanitize_node_id(dep_id)
        name = dep_data.get("name", dep_id)
        version = dep_data.get("version", "")
        vulns = dep_data.get("vulnerabilities", [])

        # Build label
        label = f"{name}@{version}" if version else name
        if vulns:
            label += f" ({len(vulns)} CVE)"

        lines.append(f'    {safe_id}["{escape_label(label)}"]')

        # Process sub-dependencies
        sub_deps = dep_data.get("dependencies", [])
        for sub_dep in sub_deps:
            if sub_dep in dependencies:
                safe_sub = sanitize_node_id(sub_dep)
                lines.append(f"    {safe_id} --> {safe_sub}")
                process_dep(sub_dep, depth + 1)

    # Process root packages
    for root in root_packages:
        if root in dependencies:
            process_dep(root)

    # Add styling based on severity
    lines.append("")
    for dep_id, dep_data in dependencies.items():
        if dep_id not in processed:
            continue
        vulns = dep_data.get("vulnerabilities", [])
        if vulns:
            # Get highest severity
            severities = [v.get("severity", "none") for v in vulns]
            severity_order = ["critical", "high", "medium", "low", "none"]
            highest = "none"
            for sev in severity_order:
                if sev in severities:
                    highest = sev
                    break

            safe_id = sanitize_node_id(dep_id)
            style = severity_styles.get(highest, "")
            if style:
                lines.append(f"    style {safe_id} {style}")

    return "\n".join(lines)


# =============================================================================
# Generic/Unknown Format Converter
# =============================================================================


def _items_of(section: Any, id_key: str = "id") -> list[dict[str, Any]]:
    """Normalize a list-of-dicts or id-keyed dict section to a list of dicts with ids."""
    if isinstance(section, dict):
        return [{id_key: k, **v} for k, v in section.items() if isinstance(v, dict)]
    if isinstance(section, list):
        return [item for item in section if isinstance(item, dict)]
    return []


def _edge_line(src: str, dst: str, label: Any = "", arrow: str = "-->") -> str:
    """One flowchart edge; labels are quoted so punctuation is safe."""
    s, d = sanitize_node_id(str(src)), sanitize_node_id(str(dst))
    if label:
        return f'    {s} {arrow}|"{escape_label(label)}"| {d}'
    return f"    {s} {arrow} {d}"


def _convert_component_diagram(data: dict[str, Any]) -> str:
    """Component diagram: one subgraph per layer (in order), typed connections."""
    lines = ["flowchart TB", f"    %% {escape_label(data.get('title', 'Component Diagram'))}", ""]
    layers = sorted(_items_of(data.get("layers")), key=lambda layer: layer.get("order", 0))
    for i, layer in enumerate(layers):
        lines.append(f'    subgraph layer_{i}["{escape_label(layer.get("name", f"Layer {i}"))}"]')
        for comp in _items_of(layer.get("components")):
            label = comp.get("name", comp.get("id", ""))
            if comp.get("tech"):
                label = f"{label} - {comp['tech']}"
            lines.append(f'        {sanitize_node_id(str(comp.get("id", label)))}["{escape_label(label)}"]')
        lines.append("    end")
    for conn in _items_of(data.get("connections")):
        arrow = "-.->" if conn.get("style") in ("async", "event") else "-->"
        lines.append(_edge_line(conn.get("from", ""), conn.get("to", ""), conn.get("label", ""), arrow))
    return "\n".join(lines)


def _convert_dependency_graph(data: dict[str, Any]) -> str:
    """Dependency graph: modules grouped into subgraphs; circular edges labelled."""
    lines = ["flowchart LR", f"    %% {escape_label(data.get('title', 'Dependency Graph'))}", ""]
    modules = _items_of(data.get("modules"))
    circular = set()
    for cycle in data.get("circular", []) or []:
        members = cycle.get("cycle") if isinstance(cycle, dict) else cycle
        if isinstance(members, list) and len(members) >= 2:
            for i, src in enumerate(members):
                circular.add((src, members[(i + 1) % len(members)]))
    groups: dict[str, list[dict[str, Any]]] = {}
    for mod in modules:
        groups.setdefault(mod.get("group", ""), []).append(mod)
    for group, members in groups.items():
        if group:
            lines.append(f'    subgraph grp_{sanitize_node_id(group)}["{escape_label(group)}"]')
        for mod in members:
            mid = sanitize_node_id(str(mod.get("id", mod.get("name", ""))))
            label = escape_label(mod.get("name", mid))
            external = mod.get("type") == "external" or mod.get("external")
            lines.append(f'        {mid}(["{label}"])' if external else f'        {mid}["{label}"]')
        if group:
            lines.append("    end")
    for dep in _items_of(data.get("dependencies")):
        src, dst = dep.get("from", ""), dep.get("to", "")
        if (src, dst) in circular:
            lines.append(_edge_line(src, dst, "circular", "==>"))
        else:
            lines.append(_edge_line(src, dst, "", "-.->" if dep.get("type") in ("runtime", "framework") else "-->"))
    return "\n".join(lines)


def _convert_privilege_gradient(data: dict[str, Any]) -> str:
    """Privilege gradient: trust zones (low to high) as subgraphs, influence edges."""
    meta = data.get("gradient", {}) if isinstance(data.get("gradient"), dict) else {}
    lines = ["flowchart LR", f"    %% {escape_label(meta.get('name', 'Privilege Gradient'))}", ""]
    zones = sorted(_items_of(data.get("zones")), key=lambda z: z.get("trust_level", 0))
    components = _items_of(data.get("components"))
    for zone in zones:
        zid = zone.get("id", "")
        title = f"{zone.get('label', zid)} (Trust {zone.get('trust_level', 0)})"
        lines.append(f'    subgraph zone_{sanitize_node_id(str(zid))}["{escape_label(title)}"]')
        for comp in components:
            if comp.get("zone") == zid:
                cid = sanitize_node_id(str(comp.get("id", "")))
                lines.append(f'        {cid}["{escape_label(comp.get("label", comp.get("id", "")))}"]')
        lines.append("    end")
    for inf in _items_of(data.get("influences")):
        lines.append(_edge_line(inf.get("from", ""), inf.get("to", ""), inf.get("label", "")))
    return "\n".join(lines)


def _convert_maestro(data: dict[str, Any]) -> str:
    """MAESTRO: agents grouped by primary layer; cross-layer chains as edges."""
    meta = data.get("meta", {}) if isinstance(data.get("meta"), dict) else {}
    lines = ["flowchart LR", f"    %% {escape_label(meta.get('name', 'MAESTRO Threat Model'))}", ""]
    agents = _items_of(data.get("agents"))
    by_layer: dict[str, list[dict[str, Any]]] = {}
    for agent in agents:
        layers = agent.get("layers") or ["unassigned"]
        by_layer.setdefault(layers[0], []).append(agent)
    for layer, members in by_layer.items():
        lines.append(f'    subgraph layer_{sanitize_node_id(layer)}["{escape_label(layer)}"]')
        for agent in members:
            aid = sanitize_node_id(f"agent_{agent.get('id', '')}")
            label = f"{agent.get('name', agent.get('id', ''))} - {agent.get('type', '')}"
            lines.append(f'        {aid}["{escape_label(label)}"]')
        lines.append("    end")
    for clt in _items_of(data.get("cross_layer_threats")):
        path = []
        for layer in clt.get("layers", []) or []:
            agent = next((a for a in agents if layer in (a.get("layers") or [])), None)
            if agent is not None:
                aid = f"agent_{agent.get('id', '')}"
                if not path or path[-1] != aid:
                    path.append(aid)
        for i in range(len(path) - 1):
            lines.append(_edge_line(path[i], path[i + 1], clt.get("id", "") if i == 0 else "", "-.->"))
    return "\n".join(lines)


# Graphviz shape name -> Mermaid flowchart node brackets
_MERMAID_SHAPES = {
    "ellipse": ("([", "])"),
    "oval": ("([", "])"),
    "circle": ("((", "))"),
    "doublecircle": ("(((", ")))"),
    "diamond": ("{", "}"),
    "hexagon": ("{{", "}}"),
    "octagon": ("{{", "}}"),
    "database": ("[(", ")]"),
    "cylinder": ("[(", ")]"),
    "parallelogram": ("[/", "/]"),
    "trapezium": ("[/", "\\]"),
    "note": (">", "]"),
    "box3d": ("[[", "]]"),
    "component": ("[[", "]]"),
    "package": ("[[", "]]"),
}


def _convert_node_graph(data: dict[str, Any]) -> str:
    """Custom / cloud diagrams: node and edge lists, clusters as subgraphs."""
    diagram = data.get("diagram", {}) if isinstance(data.get("diagram"), dict) else {}
    direction = str(diagram.get("direction", "TB")).upper()
    direction = direction if direction in ("TB", "TD", "BT", "LR", "RL") else "TB"
    lines = [f"flowchart {direction}", f"    %% {escape_label(diagram.get('title', 'Diagram'))}", ""]
    nodes = {str(n.get("id", "")): n for n in _items_of(data.get("nodes"))}
    # Custom diagrams describe shapes, labels and edge-label fields per type
    # in [schema]; without it every node was a box and labels were lost
    schema = data.get("schema", {}) if isinstance(data.get("schema"), dict) else {}
    node_types = schema.get("nodes", {}) if isinstance(schema.get("nodes"), dict) else {}
    edge_types = schema.get("edges", {}) if isinstance(schema.get("edges"), dict) else {}

    def node_label(node: dict[str, Any], nid: str) -> str:
        if node.get("label"):
            return str(node["label"])
        template = (node_types.get(node.get("type"), {}) or {}).get("label_template")
        if template:
            fields = {k: v for k, v in node.items() if isinstance(v, str | int | float)}
            text = re.sub(r"\{(\w+)\}", lambda m: str(fields.get(m.group(1), "")), str(template))
            text = text.replace("\\n", " ").replace("\n", " ").strip()
            if text:
                return text
        return str(node.get("name", nid))

    def node_line(nid: str, indent: str) -> str:
        node = nodes[nid]
        shape = str((node_types.get(node.get("type"), {}) or {}).get("shape", node.get("shape", "")))
        left, right = _MERMAID_SHAPES.get(shape, ("[", "]"))
        return f'{indent}{sanitize_node_id(nid)}{left}"{escape_label(node_label(node, nid))}"{right}'

    def edge_label(edge: dict[str, Any]) -> str:
        field = (edge_types.get(edge.get("type"), {}) or {}).get("label_field")
        value = edge.get(field) if field else None
        return str(value if value not in (None, "") else edge.get("label", ""))

    placed: set[str] = set()
    clusters = _items_of(data.get("clusters"))
    cluster_ids = {str(c.get("id", "")) for c in clusters}
    kids: dict[str, list[dict[str, Any]]] = {}
    for cluster in clusters:
        kids.setdefault(str(cluster.get("parent") or ""), []).append(cluster)
    done: set[str] = set()

    def emit(cluster: dict[str, Any], depth: int) -> None:
        cid = str(cluster.get("id", ""))
        if cid in done:
            return
        done.add(cid)
        pad = "    " * depth
        lines.append(
            f'{pad}subgraph cl_{sanitize_node_id(cid)}["{escape_label(cluster.get("label", cluster.get("id", "")))}"]'
        )
        for member in cluster.get("nodes", []) or []:
            mid = str(member.get("id", "")) if isinstance(member, dict) else str(member)
            if isinstance(member, dict) and mid not in nodes:
                nodes[mid] = member
            if mid in nodes and mid not in placed:
                lines.append(node_line(mid, pad + "    "))
                placed.add(mid)
        for child in kids.get(cid, []):  # nested clusters ("parent" key)
            emit(child, depth + 1)
        lines.append(f"{pad}end")

    for cluster in clusters:
        if str(cluster.get("parent") or "") not in cluster_ids:
            emit(cluster, 1)
    for cluster in clusters:
        emit(cluster, 1)
    for nid in nodes:
        if nid not in placed:
            lines.append(node_line(nid, "    "))
    for edge in _items_of(data.get("edges")):
        targets = edge.get("to", "")
        for dst in targets if isinstance(targets, list) else [targets]:
            src_list = edge.get("from", "")
            for src in src_list if isinstance(src_list, list) else [src_list]:
                lines.append(_edge_line(src, dst, edge_label(edge)))
    return "\n".join(lines)


def _convert_generic(data: dict[str, Any]) -> str:
    """
    Convert generic/unknown configuration to basic Mermaid flowchart.

    Creates a simple representation of the data structure.

    Args:
        data: Configuration dictionary

    Returns:
        Mermaid flowchart syntax
    """
    lines = ["flowchart TD"]
    lines.append("    %% Generic configuration visualization")
    lines.append("")

    # Create nodes for top-level keys
    for key in data:
        if isinstance(data[key], dict | list):
            safe_key = sanitize_node_id(key)
            count = len(data[key])
            lines.append(f'    {safe_key}["{escape_label(key)} ({count} items)"]')

    return "\n".join(lines)


# =============================================================================
# Main Serialization Function
# =============================================================================


def serialize_to_mermaid(
    data: dict[str, Any],
    diagram_type: Optional[str] = None,
    direction: MermaidDirection = MermaidDirection.TOP_DOWN,
    max_nodes: int = 100,
) -> str:
    """
    Serialize configuration data to Mermaid diagram syntax.

    Auto-detects the visualization type from the configuration structure
    and generates appropriate Mermaid syntax.

    Args:
        data: Configuration dictionary (from TOML/JSON/YAML)
        diagram_type: Optional override for diagram type.
            For threat_model: 'flowchart' or 'sequence'
            For killchain: 'flowchart' or 'timeline'
        direction: Flowchart direction (for flowcharts)
        max_nodes: Maximum nodes to include in complex graphs

    Returns:
        Mermaid diagram syntax as string

    Raises:
        ValueError: If configuration cannot be converted

    Example:
        >>> config = {"tree": {"name": "Test", "root": "goal"},
        ...           "nodes": {"goal": {"label": "Main Goal"}},
        ...           "edges": {}}
        >>> mermaid = serialize_to_mermaid(config)
        >>> print(mermaid)
        flowchart TD
            %% Test
            goal(["Main Goal"])
            style goal fill:#e74c3c,color:#fff,stroke:#c0392b
    """
    if not isinstance(data, dict):
        raise ValueError("Data must be a dictionary")

    if not data:
        raise ValueError("Data is empty")

    vis_type = detect_visualization_type(data)

    converters = {
        "attack_tree": lambda: _convert_attack_tree(data, direction),
        "threat_model": lambda: _convert_threat_model(data, diagram_type or "flowchart"),
        "attack_graph": lambda: _convert_attack_graph(data, max_nodes),
        "killchain": lambda: _convert_killchain(data, diagram_type or "flowchart"),
        "timeline": lambda: _convert_timeline(data),
        "access_graph": lambda: _convert_access_graph(data, max_nodes),
        "vuln_tree": lambda: _convert_vuln_tree(data),
        "mermaid_source": lambda: str(data["mermaid"]["source"]).strip(),
        "component_diagram": lambda: _convert_component_diagram(data),
        "dependency_graph": lambda: _convert_dependency_graph(data),
        "privilege_gradient": lambda: _convert_privilege_gradient(data),
        "maestro": lambda: _convert_maestro(data),
        "node_graph": lambda: _convert_node_graph(data),
        "unknown": lambda: _convert_generic(data),
    }

    converter = converters.get(vis_type, converters["unknown"])
    return converter()


# =============================================================================
# File Extension
# =============================================================================

MERMAID_FILE_EXTENSION = ".mmd"


def get_mermaid_filename(base_name: str) -> str:
    """
    Get the appropriate filename for Mermaid output.

    Args:
        base_name: Base filename without extension

    Returns:
        Filename with .mmd extension
    """
    return f"{base_name}{MERMAID_FILE_EXTENSION}"
