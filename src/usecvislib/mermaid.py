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
from typing import Dict, List, Any, Optional, Tuple
from enum import Enum


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
    sanitized = re.sub(r'[\s\-]+', '_', str(node_id))

    # Remove other special characters
    sanitized = re.sub(r'[^a-zA-Z0-9_]', '', sanitized)

    # Ensure doesn't start with number
    if sanitized and sanitized[0].isdigit():
        sanitized = 'n_' + sanitized

    # Ensure not empty
    return sanitized or 'node'


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
        text = text[:max_length - 3] + "..."

    # Escape quotes
    text = text.replace('"', "'")

    # Handle special Mermaid characters
    text = text.replace('[', '(')
    text = text.replace(']', ')')
    text = text.replace('{', '(')
    text = text.replace('}', ')')
    text = text.replace('|', '/')
    text = text.replace('<', 'lt')
    text = text.replace('>', 'gt')
    text = text.replace('#', '')

    # Remove newlines
    text = text.replace('\n', ' ').replace('\r', '')

    return text


# =============================================================================
# Visualization Type Detection
# =============================================================================

def detect_visualization_type(data: Dict[str, Any]) -> str:
    """
    Detect the visualization type from configuration data.

    Args:
        data: Configuration dictionary

    Returns:
        Visualization type string: 'attack_tree', 'threat_model',
        'attack_graph', 'killchain', 'timeline', or 'unknown'
    """
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
        if isinstance(deps, dict) and any(
            "vulnerabilities" in v for v in deps.values() if isinstance(v, dict)
        ):
            return "vuln_tree"

    return "unknown"


# =============================================================================
# Attack Tree Converter
# =============================================================================

def _convert_attack_tree(
    data: Dict[str, Any],
    direction: MermaidDirection = MermaidDirection.TOP_DOWN
) -> str:
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
            lines.append(f'    {safe_id}{{{{{safe_label}}}}}')
        elif node_type == "or":
            # OR node: diamond
            lines.append(f'    {safe_id}{{{safe_label}}}')
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
                        lines.append(f"    {safe_source} -->|{escape_label(edge_label)}| {safe_target}")
                    else:
                        lines.append(f"    {safe_source} --> {safe_target}")
        elif isinstance(targets, dict):
            # Handle dict format {target_id: attrs}
            for target_id, attrs in targets.items():
                safe_target = sanitize_node_id(target_id)
                if isinstance(attrs, dict):
                    edge_label = attrs.get("label", "")
                    if edge_label:
                        lines.append(f"    {safe_source} -->|{escape_label(edge_label)}| {safe_target}")
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

def _convert_threat_model(
    data: Dict[str, Any],
    diagram_type: str = "flowchart"
) -> str:
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


def _convert_threat_model_flowchart(data: Dict[str, Any]) -> str:
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
                **flow_data
            }

    # Add title as comment
    model_name = model.get("name", "Threat Model")
    lines.append(f"    %% {escape_label(model_name)}")
    lines.append("")

    # Element type to shape mapping
    shape_map = {
        "process": ('((', '))'),      # Circle
        "datastore": ('[(', ')]'),    # Cylinder
        "external": ('[', ']'),       # Rectangle
        "actor": ('[', ']'),          # Rectangle
    }

    # Generate elements
    for elem_id, elem_data in elements.items():
        safe_id = sanitize_node_id(elem_id)
        label = elem_data.get("name", elem_id)
        elem_type = elem_data.get("type", "process")
        safe_label = escape_label(label)

        left, right = shape_map.get(elem_type, ('[', ']'))
        lines.append(f'    {safe_id}{left}"{safe_label}"{right}')

    lines.append("")

    # Generate flows (dataflows)
    for flow_id, flow_data in flows.items():
        source = flow_data.get("source", "")
        target = flow_data.get("target", "")
        flow_label = flow_data.get("data", flow_data.get("name", ""))

        if source and target:
            safe_source = sanitize_node_id(source)
            safe_target = sanitize_node_id(target)

            if flow_label:
                lines.append(f"    {safe_source} -->|{escape_label(flow_label)}| {safe_target}")
            else:
                lines.append(f"    {safe_source} --> {safe_target}")

    # Add subgraphs for boundaries
    if boundaries:
        lines.append("")
        for boundary_id, boundary_data in boundaries.items():
            boundary_name = boundary_data.get("name", boundary_id)
            boundary_elements = boundary_data.get("elements", [])

            if boundary_elements:
                safe_boundary = sanitize_node_id(boundary_id)
                lines.append(f"    subgraph {safe_boundary}[{escape_label(boundary_name)}]")
                for elem in boundary_elements:
                    lines.append(f"        {sanitize_node_id(elem)}")
                lines.append("    end")

    return "\n".join(lines)


def _convert_threat_model_sequence(data: Dict[str, Any]) -> str:
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

def _list_to_dict(items: Any, id_key: str = "id") -> Dict[str, Any]:
    """Convert list of items to dict keyed by id_key."""
    if isinstance(items, dict):
        return items
    if isinstance(items, list):
        return {item.get(id_key, f"item_{i}"): item for i, item in enumerate(items)}
    return {}


def _convert_attack_graph(
    data: Dict[str, Any],
    max_nodes: int = 100
) -> str:
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
        lines.append(f'    {safe_id}{{{escape_label(label)}}}')
        node_count += 1

    # Generate privilege nodes (hexagon shape)
    for priv_id, priv_data in privileges.items():
        if node_count >= max_nodes:
            break
        safe_id = sanitize_node_id(priv_id)
        label = priv_data.get("label", priv_data.get("name", priv_id))
        lines.append(f'    {safe_id}{{{{{escape_label(label)}}}}}')
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

    # Generate network edges
    for source, targets in network.items():
        safe_source = sanitize_node_id(source)
        if isinstance(targets, list):
            for target in targets:
                safe_target = sanitize_node_id(target)
                lines.append(f"    {safe_source} -.-> {safe_target}")

    # Generate exploit edges
    for exploit_id, exploit_data in exploits.items():
        preconditions = exploit_data.get("preconditions", [])
        postconditions = exploit_data.get("postconditions", [])

        for pre in preconditions:
            for post in postconditions:
                safe_pre = sanitize_node_id(pre)
                safe_post = sanitize_node_id(post)
                exploit_label = exploit_data.get("label", exploit_id)
                lines.append(f"    {safe_pre} ==>|{escape_label(exploit_label)}| {safe_post}")

    # Vulnerability to host connections
    for vuln_id, vuln_data in vulnerabilities.items():
        host = vuln_data.get("host", "")
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

def _convert_killchain(
    data: Dict[str, Any],
    diagram_type: str = "flowchart"
) -> str:
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


def _convert_killchain_flowchart(data: Dict[str, Any]) -> str:
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


def _convert_killchain_timeline(data: Dict[str, Any]) -> str:
    """Convert kill chain to Mermaid timeline."""
    lines = ["timeline"]

    killchain_info = data.get("killchain", {})
    techniques = data.get("techniques", {})

    kc_name = killchain_info.get("name", "Kill Chain")
    lines.append(f"    title {escape_label(kc_name)}")
    lines.append("")

    # Group techniques by tactic
    tactics: Dict[str, List[str]] = {}
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

def _convert_timeline(data: Dict[str, Any]) -> str:
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
    lines.append("    dateFormat YYYY-MM-DDTHH:mm:ss")
    lines.append("    axisFormat %H:%M")
    lines.append("")

    # Group events by lane or phase
    if phases:
        # Use phases as sections
        for phase in phases:
            phase_name = phase.get("name", "Phase")
            lines.append(f"    section {escape_label(phase_name)}")

            # Find events in this phase's time range
            phase_start = phase.get("start", "")
            phase_end = phase.get("end", "")

            for event in events:
                event_time = event.get("timestamp", "")
                if phase_start <= event_time <= phase_end:
                    _add_gantt_event(lines, event)
    else:
        # Group by lane
        lanes: Dict[str, List] = {}
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


def _add_gantt_event(lines: List[str], event: Dict[str, Any]) -> None:
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
        # Remove timezone indicator for Mermaid compatibility
        timestamp = timestamp.replace("Z", "").replace("T", " ")

    duration = event.get("duration", "5m")

    safe_title = escape_label(title)
    safe_id = sanitize_node_id(event_id) if event_id else ""

    if safe_id:
        lines.append(f"        {safe_title} :{status} {safe_id}, {timestamp}, {duration}")
    else:
        lines.append(f"        {safe_title} :{status} {timestamp}, {duration}")


# =============================================================================
# Access Graph Converter
# =============================================================================

def _convert_access_graph(
    data: Dict[str, Any],
    max_nodes: int = 50
) -> str:
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
        "user": ('((', '))'),           # Circle
        "group": ('{{', '}}'),          # Hexagon
        "role": ('{', '}'),             # Diamond
        "service_account": ('[', ']'),  # Rectangle
        "machine": ('[/', '/]'),        # Parallelogram
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

        left, right = principal_shapes.get(p_type, ('(', ')'))
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
    valid_nodes = set(sanitize_node_id(p) for p in principals.keys())
    valid_nodes.update(sanitize_node_id(r) for r in resources.keys())

    for rel in relations:
        source = rel.get("source", "")
        target = rel.get("target", "")
        rel_type = rel.get("type", "")

        safe_source = sanitize_node_id(source)
        safe_target = sanitize_node_id(target)

        # Only include if both nodes are in the graph
        if safe_source in valid_nodes and safe_target in valid_nodes:
            if rel_type:
                lines.append(f"    {safe_source} -->|{escape_label(rel_type)}| {safe_target}")
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

def _convert_vuln_tree(data: Dict[str, Any]) -> str:
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

def _convert_generic(data: Dict[str, Any]) -> str:
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
    node_id = 0
    for key in data.keys():
        if isinstance(data[key], dict):
            safe_key = sanitize_node_id(key)
            count = len(data[key])
            lines.append(f'    {safe_key}["{escape_label(key)} ({count} items)"]')
        elif isinstance(data[key], list):
            safe_key = sanitize_node_id(key)
            count = len(data[key])
            lines.append(f'    {safe_key}["{escape_label(key)} ({count} items)"]')

    return "\n".join(lines)


# =============================================================================
# Main Serialization Function
# =============================================================================

def serialize_to_mermaid(
    data: Dict[str, Any],
    diagram_type: Optional[str] = None,
    direction: MermaidDirection = MermaidDirection.TOP_DOWN,
    max_nodes: int = 100
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
