#
# VULNEX -Universal Security Visualization Library-
#
# File: attackgraphs.py
# Author: Simon Roses Femerling
# Created: 2025-01-01
# Last Modified: 2025-12-31
# Version: 0.3.2
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Attack Graphs Visualization Module.

This module provides visualization and analysis tools for attack graphs.
Unlike attack trees (hierarchical DAGs), attack graphs model all possible
attack paths through a network, including cycles.

Attack graphs represent:
- Hosts: Network machines/servers
- Vulnerabilities: CVEs or weaknesses on hosts
- Privileges: Access levels (user, root, admin)
- Services: Running services/ports
- Network connectivity: How hosts can reach each other
- Exploits: How vulnerabilities lead to privileges

Supports TOML, JSON, and YAML input formats.
"""

from collections import deque
from typing import Dict, Any, Optional, List, Set, Iterator, Tuple
import heapq

from graphviz import Digraph
import networkx as nx

from . import utils
from .base import VisualizationBase
from .constants import cvss_to_color, cvss_to_severity_label, validate_cvss_score
from .cvss import get_cvss_score, validate_cvss_vector
from .settings import is_cvss_enabled


class AttackGraphError(utils.RenderError):
    """Exception raised for attack graph generation errors."""
    pass


class AttackGraphs(VisualizationBase):
    """Attack graph visualization and analysis class.

    Creates visual representations of network attack scenarios using
    Graphviz directed graphs. Supports path finding and critical node
    analysis.

    Supports TOML, JSON, and YAML input formats.

    Attributes:
        inputfile: Path to the configuration file (TOML, JSON, or YAML).
        outputfile: Path for the output visualization.
        format: Output format (png, pdf, svg, dot).
        styleid: Style identifier for visualization theming.
        inputdata: Parsed attack graph data.
        style: Style configuration dictionary.
        graph: Graphviz Digraph object.
    """

    # Configuration for base class
    STYLE_FILE = "config_attackgraphs.tml"
    DEFAULT_STYLE_ID = "ag_default"
    ALLOWED_EXTENSIONS = ['.toml', '.tml', '.json', '.yaml', '.yml']
    MAX_INPUT_SIZE = 10 * 1024 * 1024  # 10 MB

    # Node type prefixes for internal identification
    NODE_TYPES = {
        'host': 'H',
        'vulnerability': 'V',
        'privilege': 'P',
        'service': 'S'
    }

    def __init__(
        self,
        inputfile: str,
        outputfile: str,
        format: str = "",
        styleid: str = "",
        validate_paths: bool = True
    ) -> None:
        """Initialize AttackGraphs with input/output paths and styling options.

        Args:
            inputfile: Path to the attack graph file (TOML, JSON, or YAML).
            outputfile: Path for the output visualization.
            format: Output format (png, pdf, svg, dot). Defaults to png.
            styleid: Style identifier from config. Defaults to ag_default.
            validate_paths: Whether to validate paths on initialization.
                Set to False for deferred validation (e.g., API usage).

        Raises:
            SecurityError: If path validation fails (when validate_paths=True).
            FileNotFoundError: If input file doesn't exist (when validate_paths=True).
        """
        # Handle empty strings for backward compatibility
        if format == "":
            format = "png"
        if styleid == "":
            styleid = None  # Will use DEFAULT_STYLE_ID

        # Initialize base class
        super().__init__(
            inputfile=inputfile,
            outputfile=outputfile,
            format=format,
            styleid=styleid,
            validate_paths=validate_paths
        )

        # Attack graph specific state
        self.graph: Optional[Digraph] = None

        # Internal graph representation for analysis
        self._adjacency: Dict[str, Set[str]] = {}
        self._reverse_adjacency: Dict[str, Set[str]] = {}
        self._node_types: Dict[str, str] = {}

        # NetworkX graph for advanced analysis
        self._nx_graph: Optional[nx.DiGraph] = None

        # Backward compatibility: expose stylefile attribute
        self.stylefile = self.STYLE_FILE

        # SECURITY: Track temp input file for cleanup (used by builder)
        self._temp_input: Optional[str] = None

    def __del__(self):
        """SECURITY: Cleanup temporary input files on object destruction.

        This ensures temp files created by AttackGraphBuilder are properly
        cleaned up even if an exception occurs during processing.
        """
        if hasattr(self, '_temp_input') and self._temp_input:
            try:
                import os
                if os.path.exists(self._temp_input):
                    os.remove(self._temp_input)
            except Exception:
                pass  # Best effort cleanup

    def _default_style(self) -> Dict[str, Any]:
        """Return default style configuration for attack graphs.

        Returns:
            Dictionary with default graph, node type, and edge styles.
        """
        return {
            "graph": {
                "rankdir": "LR",
                "bgcolor": "white",
                "fontname": "Arial",
                "splines": "ortho"
            },
            "host": {
                "shape": "box3d",
                "style": "filled",
                "fillcolor": "#4a90d9",
                "fontcolor": "white",
                "fontname": "Arial"
            },
            "vulnerability": {
                "shape": "diamond",
                "style": "filled",
                "fillcolor": "#e74c3c",
                "fontcolor": "white",
                "fontname": "Arial"
            },
            "privilege": {
                "shape": "ellipse",
                "style": "filled",
                "fillcolor": "#f39c12",
                "fontcolor": "white",
                "fontname": "Arial"
            },
            "service": {
                "shape": "component",
                "style": "filled",
                "fillcolor": "#27ae60",
                "fontcolor": "white",
                "fontname": "Arial"
            },
            "edge": {
                "color": "#34495e",
                "fontname": "Arial",
                "fontsize": "10"
            },
            "network_edge": {
                "color": "#3498db",
                "style": "dashed",
                "fontname": "Arial"
            },
            "exploit_edge": {
                "color": "#e74c3c",
                "style": "bold",
                "fontname": "Arial"
            }
        }

    def _get_metadata_root_key(self) -> str:
        """Get the root key for metadata extraction.

        Returns:
            'graph' as the root key for attack graphs.
        """
        return "graph"

    def _load_impl(self) -> Dict[str, Any]:
        """Load attack graph data from configuration file.

        Returns:
            Parsed attack graph data dictionary.

        Raises:
            AttackGraphError: If the file cannot be read or parsed.
        """
        try:
            data = utils.ReadConfigFile(self.inputfile)
        except (utils.FileError, utils.ConfigError) as e:
            self.logger.error(f"Failed to load attack graph from {self.inputfile}: {e}")
            raise AttackGraphError(f"Failed to load attack graph: {e}")
        except FileNotFoundError as e:
            self.logger.error(f"Input file not found: {self.inputfile}")
            raise AttackGraphError(f"Input file not found: {e}")

        # Store data and build internal graph representation
        self.inputdata = data
        self._build_adjacency()
        self.logger.debug(f"Built adjacency graph with {len(self._adjacency)} nodes")

        return data

    def _normalize_data(self) -> None:
        """Normalize data from array format to dict format.

        TOML [[section]] creates lists, but we need dicts keyed by 'id'.
        """
        for section in ['hosts', 'vulnerabilities', 'privileges', 'services', 'exploits', 'network_edges']:
            data = self.inputdata.get(section, [])
            if isinstance(data, list):
                # Convert list of dicts to dict keyed by 'id'
                normalized = {}
                for item in data:
                    if isinstance(item, dict):
                        item_id = item.get('id', f'item_{len(normalized)}')
                        normalized[item_id] = item
                self.inputdata[section] = normalized

    def _build_adjacency(self) -> None:
        """Build adjacency lists from loaded data for path analysis."""
        self._adjacency = {}
        self._reverse_adjacency = {}
        self._node_types = {}

        # Normalize data first (convert arrays to dicts)
        self._normalize_data()

        # Add all nodes
        for node_type in ['hosts', 'vulnerabilities', 'privileges', 'services']:
            nodes = self.inputdata.get(node_type, {})
            type_key = node_type.rstrip('s')  # 'hosts' -> 'host'
            if type_key == 'vulnerabilitie':
                type_key = 'vulnerability'
            for node_id in nodes:
                self._adjacency[node_id] = set()
                self._reverse_adjacency[node_id] = set()
                self._node_types[node_id] = type_key

        # Add network edges from network_edges array format
        network_edges = self.inputdata.get("network_edges", {})
        for edge_id, edge_data in network_edges.items():
            source = edge_data.get("from")
            target = edge_data.get("to")
            if source and target:
                if source not in self._adjacency:
                    self._adjacency[source] = set()
                    self._reverse_adjacency[source] = set()
                if target not in self._adjacency:
                    self._adjacency[target] = set()
                    self._reverse_adjacency[target] = set()
                self._adjacency[source].add(target)
                self._reverse_adjacency[target].add(source)

        # Also support old dict-style network format
        network = self.inputdata.get("network", {})
        if isinstance(network, dict):
            for source, targets in network.items():
                if isinstance(targets, list):
                    if source not in self._adjacency:
                        self._adjacency[source] = set()
                        self._reverse_adjacency[source] = set()
                    for target in targets:
                        if target not in self._adjacency:
                            self._adjacency[target] = set()
                            self._reverse_adjacency[target] = set()
                        self._adjacency[source].add(target)
                        self._reverse_adjacency[target].add(source)

        # Add exploit edges (precondition -> exploit -> postcondition)
        exploits = self.inputdata.get("exploits", {})
        for exploit_id, exploit_data in exploits.items():
            preconditions = exploit_data.get("preconditions", [])
            postconditions = exploit_data.get("postconditions", [])

            if not preconditions and exploit_data.get("precondition"):
                preconditions = [exploit_data.get("precondition")]
            if not postconditions and exploit_data.get("postcondition"):
                postconditions = [exploit_data.get("postcondition")]

            if exploit_id not in self._adjacency:
                self._adjacency[exploit_id] = set()
                self._reverse_adjacency[exploit_id] = set()
                self._node_types[exploit_id] = "exploit"

            for pre in preconditions:
                if pre not in self._adjacency:
                    self._adjacency[pre] = set()
                    self._reverse_adjacency[pre] = set()
                self._adjacency[pre].add(exploit_id)
                self._reverse_adjacency[exploit_id].add(pre)

            for post in postconditions:
                if post not in self._adjacency:
                    self._adjacency[post] = set()
                    self._reverse_adjacency[post] = set()
                self._adjacency[exploit_id].add(post)
                self._reverse_adjacency[post].add(exploit_id)

        # Link vulnerabilities to their hosts
        vulnerabilities = self.inputdata.get("vulnerabilities", {})
        for vuln_id, vuln_data in vulnerabilities.items():
            host = vuln_data.get("host") or vuln_data.get("affected_host")
            if host and host in self._adjacency:
                self._adjacency[host].add(vuln_id)
                self._reverse_adjacency[vuln_id].add(host)

        # Link services to their hosts
        services = self.inputdata.get("services", {})
        for svc_id, svc_data in services.items():
            host = svc_data.get("host")
            if host and host in self._adjacency:
                self._adjacency[host].add(svc_id)
                self._reverse_adjacency[svc_id].add(host)

        # Link privileges to their hosts
        privileges = self.inputdata.get("privileges", {})
        for priv_id, priv_data in privileges.items():
            host = priv_data.get("host")
            if host and host in self._adjacency:
                self._adjacency[priv_id].add(host)
                self._reverse_adjacency[host].add(priv_id)

        # Build NetworkX graph from adjacency data
        self._build_nx_graph()

    def _build_nx_graph(self) -> None:
        """Build NetworkX DiGraph from adjacency data for advanced analysis."""
        self._nx_graph = nx.DiGraph()

        # Add nodes with attributes
        for node_id, node_type in self._node_types.items():
            self._nx_graph.add_node(node_id, node_type=node_type)

        # Add edges from adjacency
        for source, targets in self._adjacency.items():
            for target in targets:
                self._nx_graph.add_edge(source, target)

        # Add CVSS scores as node attributes for vulnerabilities
        vulnerabilities = self.inputdata.get("vulnerabilities", {})
        for vuln_id, vuln_data in vulnerabilities.items():
            if vuln_id in self._nx_graph:
                score, _ = get_cvss_score(
                    vuln_data.get("cvss"),
                    vuln_data.get("cvss_vector")
                )
                self._nx_graph.nodes[vuln_id]["cvss"] = score if score is not None else 5.0

        # Add host metadata
        hosts = self.inputdata.get("hosts", {})
        for host_id, host_data in hosts.items():
            if host_id in self._nx_graph:
                self._nx_graph.nodes[host_id]["label"] = host_data.get("label", host_id)
                if host_data.get("ip"):
                    self._nx_graph.nodes[host_id]["ip"] = host_data["ip"]

    def _ensure_nx_graph(self) -> None:
        """Ensure NetworkX graph is built, loading data if necessary."""
        if self._nx_graph is None:
            if not self.inputdata:
                self.load()
            else:
                self._build_nx_graph()

    def _render_impl(self) -> None:
        """Build the attack graph from loaded data.

        Raises:
            AttackGraphError: If required data sections are missing.
        """
        # Ensure data is normalized
        self._normalize_data()

        # Check for required sections
        if "graph" not in self.inputdata:
            raise AttackGraphError("Missing 'graph' section in attack graph configuration")

        # Get graph metadata
        graph_meta = self.inputdata.get("graph", {})

        # Get styles
        graph_style = self.style.get("graph", self._default_style()["graph"])
        host_style = self.style.get("host", self._default_style()["host"])
        vuln_style = self.style.get("vulnerability", self._default_style()["vulnerability"])
        priv_style = self.style.get("privilege", self._default_style()["privilege"])
        svc_style = self.style.get("service", self._default_style()["service"])
        network_edge_style = self.style.get("network_edge", self._default_style()["network_edge"])
        exploit_edge_style = self.style.get("exploit_edge", self._default_style()["exploit_edge"])

        # Create the graph
        self.graph = Digraph(
            name=graph_meta.get("name", "Attack Graph"),
            format=self.format
        )

        # Apply graph attributes
        graph_attrs = utils.stringify_dict(graph_style)
        self.graph.attr(**graph_attrs)

        # Add title
        if graph_meta.get("name"):
            self.graph.attr(label=graph_meta["name"], labelloc="t")

        # Add hosts
        hosts = self.inputdata.get("hosts", {})
        for host_id, host_data in hosts.items():
            node_attrs = host_data.copy() if isinstance(host_data, dict) else {}
            # Check if node has an image and if user wants a styled background
            has_image = 'image' in node_attrs and node_attrs['image']
            host_user_shape = host_data.get('shape', '') if isinstance(host_data, dict) else ''
            host_user_style = host_data.get('style', '') if isinstance(host_data, dict) else ''
            host_user_fillcolor = host_data.get('fillcolor', '') if isinstance(host_data, dict) else ''
            host_wants_no_bg = host_user_shape in ('none', 'plaintext', 'point')
            host_wants_bg = ('filled' in str(host_user_style).lower()) or bool(host_user_fillcolor)
            host_has_visible_shape = bool(host_user_shape) and not host_wants_no_bg
            user_set_shape = (host_has_visible_shape or host_wants_bg) and not host_wants_no_bg
            # Merge default style first, then process image (so image can override shape)
            node_attrs = utils.merge_dicts(node_attrs, host_style)
            # Process and validate image attribute if present (after merge to override style)
            utils.process_node_image(node_attrs, host_id, self.logger, preserve_shape=user_set_shape)
            # For nodes with icons, set fontcolor to black for readability
            if has_image and "fontcolor" not in host_data:
                node_attrs["fontcolor"] = "black"
            node_attrs = utils.stringify_dict(node_attrs)
            label = node_attrs.pop("label", host_id)
            node_attrs.pop("ip", None)
            node_attrs.pop("os", None)
            node_attrs.pop("description", None)
            self.graph.node(host_id, label, **node_attrs)

        # Add vulnerabilities with CVSS-based color coding
        vulnerabilities = self.inputdata.get("vulnerabilities", {})
        for vuln_id, vuln_data in vulnerabilities.items():
            node_attrs = vuln_data.copy() if isinstance(vuln_data, dict) else {}
            # Check if node has an image and if user wants a styled background
            has_image = 'image' in node_attrs and node_attrs['image']
            vuln_user_shape = vuln_data.get('shape', '') if isinstance(vuln_data, dict) else ''
            vuln_user_style = vuln_data.get('style', '') if isinstance(vuln_data, dict) else ''
            vuln_user_fillcolor = vuln_data.get('fillcolor', '') if isinstance(vuln_data, dict) else ''
            vuln_wants_no_bg = vuln_user_shape in ('none', 'plaintext', 'point')
            vuln_wants_bg = ('filled' in str(vuln_user_style).lower()) or bool(vuln_user_fillcolor)
            vuln_has_visible_shape = bool(vuln_user_shape) and not vuln_wants_no_bg
            user_set_shape = (vuln_has_visible_shape or vuln_wants_bg) and not vuln_wants_no_bg
            # Merge default style first, then process image (so image can override shape)
            node_attrs = utils.merge_dicts(node_attrs, vuln_style)
            # Process and validate image attribute if present (after merge to override style)
            utils.process_node_image(node_attrs, vuln_id, self.logger, preserve_shape=user_set_shape)
            node_attrs = utils.stringify_dict(node_attrs)
            label = node_attrs.pop("label", vuln_id)

            # Get CVSS score from either numeric value or vector string
            cvss_value = vuln_data.get("cvss")
            cvss_vector = vuln_data.get("cvss_vector")
            resolved_score, _ = get_cvss_score(cvss_value, cvss_vector)

            # Apply CVSS styling only if CVSS display is enabled for attack graphs
            if resolved_score is not None and is_cvss_enabled("attack_graph"):
                severity = cvss_to_severity_label(resolved_score)
                # Show vector indicator if score was calculated from vector
                if cvss_vector and cvss_value is None:
                    label = f"{label}\\n(CVSS: {resolved_score} - {severity})*"
                else:
                    label = f"{label}\\n(CVSS: {resolved_score} - {severity})"
                # Apply CVSS-based color only when using default style
                # Non-default styles should have their colors take full precedence
                use_cvss_colors = self.styleid == self.DEFAULT_STYLE_ID
                if not has_image and use_cvss_colors:
                    node_attrs["fillcolor"] = cvss_to_color(resolved_score)
                    # Set fontcolor to white for readability on CVSS-colored backgrounds
                    # (only if user hasn't explicitly set fontcolor)
                    if "fontcolor" not in vuln_data:
                        node_attrs["fontcolor"] = "white"

            # For nodes with icons, set fontcolor to black for readability
            if has_image and "fontcolor" not in vuln_data:
                node_attrs["fontcolor"] = "black"

            node_attrs.pop("host", None)
            node_attrs.pop("cvss", None)
            node_attrs.pop("cvss_vector", None)
            node_attrs.pop("description", None)
            node_attrs.pop("cwe", None)
            node_attrs.pop("affected_host", None)
            self.graph.node(vuln_id, label, **node_attrs)

        # Add privileges
        privileges = self.inputdata.get("privileges", {})
        for priv_id, priv_data in privileges.items():
            node_attrs = priv_data.copy() if isinstance(priv_data, dict) else {}
            # Check if node has an image and if user wants a styled background
            has_image = 'image' in node_attrs and node_attrs['image']
            priv_user_shape = priv_data.get('shape', '') if isinstance(priv_data, dict) else ''
            priv_user_style = priv_data.get('style', '') if isinstance(priv_data, dict) else ''
            priv_user_fillcolor = priv_data.get('fillcolor', '') if isinstance(priv_data, dict) else ''
            priv_wants_no_bg = priv_user_shape in ('none', 'plaintext', 'point')
            priv_wants_bg = ('filled' in str(priv_user_style).lower()) or bool(priv_user_fillcolor)
            priv_has_visible_shape = bool(priv_user_shape) and not priv_wants_no_bg
            user_set_shape = (priv_has_visible_shape or priv_wants_bg) and not priv_wants_no_bg
            # Merge default style first, then process image (so image can override shape)
            node_attrs = utils.merge_dicts(node_attrs, priv_style)
            # Process and validate image attribute if present (after merge to override style)
            utils.process_node_image(node_attrs, priv_id, self.logger, preserve_shape=user_set_shape)
            # For nodes with icons, set fontcolor to black for readability
            if has_image and "fontcolor" not in priv_data:
                node_attrs["fontcolor"] = "black"
            node_attrs = utils.stringify_dict(node_attrs)
            label = node_attrs.pop("label", priv_id)
            level = priv_data.get("level")
            if level:
                label = f"{label}\\n[{level}]"
            node_attrs.pop("host", None)
            node_attrs.pop("level", None)
            self.graph.node(priv_id, label, **node_attrs)

        # Add services
        services = self.inputdata.get("services", {})
        for svc_id, svc_data in services.items():
            node_attrs = svc_data.copy() if isinstance(svc_data, dict) else {}
            # Check if node has an image and if user wants a styled background
            has_image = 'image' in node_attrs and node_attrs['image']
            svc_user_shape = svc_data.get('shape', '') if isinstance(svc_data, dict) else ''
            svc_user_style = svc_data.get('style', '') if isinstance(svc_data, dict) else ''
            svc_user_fillcolor = svc_data.get('fillcolor', '') if isinstance(svc_data, dict) else ''
            svc_wants_no_bg = svc_user_shape in ('none', 'plaintext', 'point')
            svc_wants_bg = ('filled' in str(svc_user_style).lower()) or bool(svc_user_fillcolor)
            svc_has_visible_shape = bool(svc_user_shape) and not svc_wants_no_bg
            user_set_shape = (svc_has_visible_shape or svc_wants_bg) and not svc_wants_no_bg
            # Merge default style first, then process image (so image can override shape)
            node_attrs = utils.merge_dicts(node_attrs, svc_style)
            # Process and validate image attribute if present (after merge to override style)
            utils.process_node_image(node_attrs, svc_id, self.logger, preserve_shape=user_set_shape)
            # For nodes with icons, set fontcolor to black for readability
            if has_image and "fontcolor" not in svc_data:
                node_attrs["fontcolor"] = "black"
            node_attrs = utils.stringify_dict(node_attrs)
            label = node_attrs.pop("label", svc_id)
            port = svc_data.get("port")
            if port:
                label = f"{label}\\n:{port}"
            node_attrs.pop("host", None)
            node_attrs.pop("port", None)
            node_attrs.pop("protocol", None)
            self.graph.node(svc_id, label, **node_attrs)

        # Add network edges
        network_edges = self.inputdata.get("network_edges", {})
        for edge_id, edge_data in network_edges.items():
            source = edge_data.get("from")
            target = edge_data.get("to")
            if source and target:
                edge_attrs = utils.stringify_dict(network_edge_style.copy())
                edge_label = edge_data.get("label", "")
                if edge_label:
                    edge_attrs["label"] = edge_label
                self.graph.edge(source, target, **edge_attrs)

        # Also support old dict-style network format
        network = self.inputdata.get("network", {})
        if isinstance(network, dict):
            for source, targets in network.items():
                if isinstance(targets, list):
                    for target in targets:
                        edge_attrs = utils.stringify_dict(network_edge_style.copy())
                        self.graph.edge(source, target, **edge_attrs)

        # Add exploit edges
        exploits = self.inputdata.get("exploits", {})
        for exploit_id, exploit_data in exploits.items():
            exploit_label = exploit_data.get("label", exploit_id)
            self.graph.node(
                exploit_id,
                exploit_label,
                shape="hexagon",
                style="filled",
                fillcolor="#9b59b6",
                fontcolor="white"
            )

            preconditions = exploit_data.get("preconditions", [])
            postconditions = exploit_data.get("postconditions", [])
            if not preconditions and exploit_data.get("precondition"):
                preconditions = [exploit_data.get("precondition")]
            if not postconditions and exploit_data.get("postcondition"):
                postconditions = [exploit_data.get("postcondition")]

            for pre in preconditions:
                edge_attrs = utils.stringify_dict(exploit_edge_style.copy())
                self.graph.edge(pre, exploit_id, **edge_attrs)

            for post in postconditions:
                edge_attrs = utils.stringify_dict(exploit_edge_style.copy())
                self.graph.edge(exploit_id, post, **edge_attrs)

        # Link vulnerabilities to hosts
        for vuln_id, vuln_data in vulnerabilities.items():
            host = vuln_data.get("host") or vuln_data.get("affected_host")
            if host:
                self.graph.edge(host, vuln_id, style="dotted", color="#95a5a6")

        # Link services to hosts
        for svc_id, svc_data in services.items():
            host = svc_data.get("host")
            if host:
                self.graph.edge(host, svc_id, style="dotted", color="#95a5a6")

        self.logger.debug(f"Rendered attack graph with {len(hosts)} hosts")

    def _draw_impl(self, outputfile: str) -> None:
        """Save the attack graph visualization to file.

        Args:
            outputfile: Path for output file.

        Raises:
            AttackGraphError: If rendering fails.
        """
        if self.graph is None:
            raise AttackGraphError("Graph not rendered. Call render() first.")

        try:
            self.graph.render(outputfile, cleanup=True)
            self.logger.debug("Successfully wrote attack graph visualization")
        except Exception as e:
            self.logger.error(f"Failed to render graph to {outputfile}: {e}")
            raise AttackGraphError(f"Failed to render graph: {e}")

    def _validate_impl(self) -> List[str]:
        """Validate the attack graph structure.

        Returns:
            List of validation error messages. Empty if valid.
        """
        errors = []

        # Ensure data is normalized
        self._normalize_data()

        # Check for graph section
        if "graph" not in self.inputdata:
            errors.append("Missing 'graph' section in attack graph")

        # Check for at least one host
        hosts = self.inputdata.get("hosts", {})
        if not hosts:
            errors.append("No hosts defined in attack graph")

        # Validate vulnerability references and CVSS scores
        vulnerabilities = self.inputdata.get("vulnerabilities", {})
        for vuln_id, vuln_data in vulnerabilities.items():
            host = vuln_data.get("host") or vuln_data.get("affected_host")
            if host and host not in hosts:
                errors.append(f"Vulnerability '{vuln_id}' references undefined host '{host}'")

            # Validate CVSS score and/or vector if provided
            cvss_value = vuln_data.get("cvss")
            cvss_vector = vuln_data.get("cvss_vector")

            if cvss_value is not None:
                is_valid, _, error_msg = validate_cvss_score(cvss_value)
                if not is_valid:
                    errors.append(f"Vulnerability '{vuln_id}': {error_msg}")

            if cvss_vector is not None:
                is_valid, error_msg = validate_cvss_vector(cvss_vector)
                if not is_valid:
                    errors.append(f"Vulnerability '{vuln_id}': {error_msg}")

        # Validate service references
        services = self.inputdata.get("services", {})
        for svc_id, svc_data in services.items():
            host = svc_data.get("host")
            if host and host not in hosts:
                errors.append(f"Service '{svc_id}' references undefined host '{host}'")

        # Validate privilege references
        privileges = self.inputdata.get("privileges", {})
        for priv_id, priv_data in privileges.items():
            host = priv_data.get("host")
            if host and host not in hosts:
                errors.append(f"Privilege '{priv_id}' references undefined host '{host}'")

        # Validate exploit references
        exploits = self.inputdata.get("exploits", {})
        all_nodes = set(hosts.keys()) | set(vulnerabilities.keys()) | set(privileges.keys()) | set(services.keys())

        for exploit_id, exploit_data in exploits.items():
            vuln_ref = exploit_data.get("vulnerability")
            if vuln_ref and vuln_ref not in vulnerabilities:
                errors.append(f"Exploit '{exploit_id}' references undefined vulnerability '{vuln_ref}'")

            preconditions = exploit_data.get("preconditions", [])
            postconditions = exploit_data.get("postconditions", [])
            if not preconditions and exploit_data.get("precondition"):
                preconditions = [exploit_data.get("precondition")]
            if not postconditions and exploit_data.get("postcondition"):
                postconditions = [exploit_data.get("postcondition")]

            for pre in preconditions:
                if pre not in all_nodes:
                    errors.append(f"Exploit '{exploit_id}' precondition '{pre}' not defined")
            for post in postconditions:
                if post not in all_nodes:
                    errors.append(f"Exploit '{exploit_id}' postcondition '{post}' not defined")

        # Validate network_edges references
        network_edges = self.inputdata.get("network_edges", {})
        for edge_id, edge_data in network_edges.items():
            source = edge_data.get("from")
            target = edge_data.get("to")
            if source and source not in all_nodes and source != "internet" and source != "attacker":
                errors.append(f"Network edge source '{source}' not defined")
            if target and target not in all_nodes:
                errors.append(f"Network edge target '{target}' not defined")

        # Also validate old network format
        network = self.inputdata.get("network", {})
        if isinstance(network, dict):
            for source, targets in network.items():
                if isinstance(targets, list):
                    if source not in all_nodes and source != "internet":
                        errors.append(f"Network source '{source}' not defined")
                    for target in targets:
                        if target not in all_nodes:
                            errors.append(f"Network target '{target}' not defined")

        return errors

    def _get_stats_impl(self) -> Dict[str, Any]:
        """Get statistical summary of the attack graph.

        Returns:
            Dictionary containing graph statistics.
        """
        # Ensure data is normalized
        self._normalize_data()

        graph_meta = self.inputdata.get("graph", {})
        hosts = self.inputdata.get("hosts", {})
        vulnerabilities = self.inputdata.get("vulnerabilities", {})
        privileges = self.inputdata.get("privileges", {})
        services = self.inputdata.get("services", {})
        exploits = self.inputdata.get("exploits", {})

        # Count network edges
        network_edges_data = self.inputdata.get("network_edges", {})
        network_edge_count = len(network_edges_data)

        network = self.inputdata.get("network", {})
        if isinstance(network, dict):
            for targets in network.values():
                if isinstance(targets, list):
                    network_edge_count += len(targets)

        # Count exploit edges
        exploit_edge_count = 0
        for e in exploits.values():
            pre = e.get("preconditions", [])
            post = e.get("postconditions", [])
            if not pre and e.get("precondition"):
                pre = [e.get("precondition")]
            if not post and e.get("postcondition"):
                post = [e.get("postcondition")]
            exploit_edge_count += len(pre) + len(post)

        # Calculate average CVSS (supporting both numeric and vector)
        cvss_scores = []
        for v in vulnerabilities.values():
            score, _ = get_cvss_score(v.get("cvss"), v.get("cvss_vector"))
            if score is not None:
                cvss_scores.append(score)

        avg_cvss = sum(cvss_scores) / len(cvss_scores) if cvss_scores else 0
        critical_vulns = len([c for c in cvss_scores if c >= 9.0])

        return {
            "name": graph_meta.get("name", "Unknown"),
            "total_hosts": len(hosts),
            "total_vulnerabilities": len(vulnerabilities),
            "total_privileges": len(privileges),
            "total_services": len(services),
            "total_exploits": len(exploits),
            "network_edges": network_edge_count,
            "exploit_edges": exploit_edge_count,
            "total_nodes": len(hosts) + len(vulnerabilities) + len(privileges) + len(services) + len(exploits),
            "total_edges": network_edge_count + exploit_edge_count,
            "average_cvss": round(avg_cvss, 2),
            "critical_vulnerabilities": critical_vulns
        }

    # Attack graph specific analysis methods

    def find_attack_paths(
        self,
        source: str,
        target: str,
        max_paths: int = 10,
        max_depth: int = 20
    ) -> List[List[str]]:
        """Find all attack paths from source to target using optimized iterative DFS.

        Uses an iterative approach with explicit stack for better performance
        on deep graphs (avoids Python recursion limit and stack overflow).

        Args:
            source: Starting node ID (e.g., "internet" or a host).
            target: Target node ID (e.g., a privilege node).
            max_paths: Maximum number of paths to return.
            max_depth: Maximum path length to search.

        Returns:
            List of paths, where each path is a list of node IDs.

        Raises:
            ValueError: If source node is not found in the graph.
        """
        if not self._adjacency:
            if not self.inputdata:
                self.load()
            self._build_adjacency()

        if source not in self._adjacency and source not in self._node_types:
            raise ValueError(f"Source node '{source}' not found in graph")

        paths: List[List[str]] = []

        # Use iterative approach with explicit stack
        # Stack entries: (current_node, path_so_far, visited_set)
        stack: List[Tuple[str, List[str], Set[str]]] = [(source, [source], {source})]

        while stack and len(paths) < max_paths:
            current, path, visited = stack.pop()

            # Check depth limit
            if len(path) > max_depth:
                continue

            # Found target
            if current == target:
                paths.append(path.copy())
                continue

            # Explore neighbors in reverse order (so first neighbor is processed first)
            neighbors = list(self._adjacency.get(current, set()))
            for neighbor in reversed(neighbors):
                if neighbor not in visited:
                    new_visited = visited | {neighbor}
                    new_path = path + [neighbor]
                    stack.append((neighbor, new_path, new_visited))

        return paths

    def find_attack_paths_generator(
        self,
        source: str,
        target: str,
        max_depth: int = 20
    ) -> Iterator[List[str]]:
        """Generator version for memory-efficient path enumeration.

        Yields paths one at a time without storing all in memory.
        Useful for very large graphs where storing all paths is impractical.

        Args:
            source: Starting node ID.
            target: Target node ID.
            max_depth: Maximum path depth to search.

        Yields:
            Paths from source to target, one at a time.

        Example:
            >>> for path in ag.find_attack_paths_generator("attacker", "target"):
            ...     print(f"Found path: {' -> '.join(path)}")
            ...     if some_condition:
            ...         break  # Can stop early without computing all paths
        """
        if not self._adjacency:
            if not self.inputdata:
                self.load()
            self._build_adjacency()

        if source not in self._adjacency and source not in self._node_types:
            return

        stack: List[Tuple[str, List[str], Set[str]]] = [(source, [source], {source})]

        while stack:
            current, path, visited = stack.pop()

            if len(path) > max_depth:
                continue

            if current == target:
                yield path
                continue

            for neighbor in self._adjacency.get(current, set()):
                if neighbor not in visited:
                    stack.append((
                        neighbor,
                        path + [neighbor],
                        visited | {neighbor}
                    ))

    def shortest_path(self, source: str, target: str) -> List[str]:
        """Find shortest attack path using optimized BFS with parent pointers.

        Uses parent pointer reconstruction instead of storing full paths
        in the queue, which is more memory efficient for large graphs.

        Args:
            source: Starting node ID.
            target: Target node ID.

        Returns:
            Shortest path as a list of node IDs, or empty list if no path exists.
        """
        if not self._adjacency:
            if not self.inputdata:
                self.load()
            self._build_adjacency()

        if source not in self._adjacency and source not in self._node_types:
            return []

        if source == target:
            return [source]

        # BFS with parent pointers (more memory efficient)
        visited: Set[str] = {source}
        parent: Dict[str, Optional[str]] = {source: None}
        queue: deque = deque([source])

        while queue:
            current = queue.popleft()

            for neighbor in self._adjacency.get(current, set()):
                if neighbor not in visited:
                    visited.add(neighbor)
                    parent[neighbor] = current

                    if neighbor == target:
                        # Reconstruct path from parent pointers
                        path: List[str] = []
                        node: Optional[str] = target
                        while node is not None:
                            path.append(node)
                            node = parent[node]
                        return list(reversed(path))

                    queue.append(neighbor)

        return []  # No path found

    def find_weighted_shortest_path(
        self,
        source: str,
        target: str,
        weight_func: Optional[callable] = None
    ) -> Tuple[List[str], float]:
        """Find shortest path with weights using Dijkstra's algorithm.

        Can use CVSS scores as weights for risk-based path finding.
        By default, uses inverted CVSS (10 - cvss) so higher-risk paths
        are preferred (lower total weight).

        Args:
            source: Starting node ID.
            target: Target node ID.
            weight_func: Optional function(node_id) -> weight.
                         Defaults to CVSS-based weights for vulnerabilities.

        Returns:
            Tuple of (path, total_weight). Returns ([], inf) if no path exists.

        Example:
            >>> path, weight = ag.find_weighted_shortest_path("attacker", "target")
            >>> print(f"Riskiest path: {' -> '.join(path)} (weight: {weight})")
        """
        if weight_func is None:
            weight_func = self._get_node_weight

        if not self._adjacency:
            if not self.inputdata:
                self.load()
            self._build_adjacency()

        if source not in self._adjacency and source not in self._node_types:
            return [], float('inf')

        # Dijkstra's algorithm with heapq
        distances: Dict[str, float] = {source: 0}
        parent: Dict[str, Optional[str]] = {source: None}
        heap: List[Tuple[float, str]] = [(0, source)]
        visited: Set[str] = set()

        while heap:
            dist, current = heapq.heappop(heap)

            if current in visited:
                continue
            visited.add(current)

            if current == target:
                # Reconstruct path
                path: List[str] = []
                node: Optional[str] = target
                while node is not None:
                    path.append(node)
                    node = parent[node]
                return list(reversed(path)), dist

            for neighbor in self._adjacency.get(current, set()):
                if neighbor not in visited:
                    weight = weight_func(neighbor)
                    new_dist = dist + weight

                    if neighbor not in distances or new_dist < distances[neighbor]:
                        distances[neighbor] = new_dist
                        parent[neighbor] = current
                        heapq.heappush(heap, (new_dist, neighbor))

        return [], float('inf')

    def _get_node_weight(self, node_id: str) -> float:
        """Get weight for a node based on CVSS score for vulnerabilities.

        For vulnerabilities, returns (10 - CVSS) so higher CVSS = lower weight,
        meaning the algorithm prefers high-risk paths.
        For other node types, returns a default weight of 1.0.

        Args:
            node_id: The node ID to get weight for.

        Returns:
            Weight value for the node.
        """
        node_type = self._node_types.get(node_id, "")

        if node_type == "vulnerability":
            vulns = self.inputdata.get("vulnerabilities", {})
            if node_id in vulns:
                vuln_data = vulns[node_id]
                # Support both numeric CVSS and vector strings
                score, _ = get_cvss_score(vuln_data.get("cvss"), vuln_data.get("cvss_vector"))
                cvss = score if score is not None else 5.0
                # Invert so higher CVSS = lower weight (prefer high-risk paths)
                return max(0.1, 10.0 - cvss)

        return 1.0  # Default weight for non-vulnerability nodes

    def analyze_critical_nodes(self, top_n: int = 10) -> List[Dict[str, Any]]:
        """Identify critical nodes based on connectivity.

        Calculates degree centrality (in-degree + out-degree) to find
        nodes that are most connected and thus most critical.

        Args:
            top_n: Number of top critical nodes to return.

        Returns:
            List of node dictionaries sorted by criticality score.
        """
        if not self._adjacency:
            if not self.inputdata:
                self.load()
            self._build_adjacency()

        node_scores: List[Dict[str, Any]] = []

        for node_id in self._adjacency:
            out_degree = len(self._adjacency.get(node_id, set()))
            in_degree = len(self._reverse_adjacency.get(node_id, set()))
            total_degree = in_degree + out_degree

            node_type = self._node_types.get(node_id, "unknown")

            label = node_id
            for section in ['hosts', 'vulnerabilities', 'privileges', 'services', 'exploits']:
                if node_id in self.inputdata.get(section, {}):
                    label = self.inputdata[section][node_id].get("label", node_id)
                    break

            node_scores.append({
                "id": node_id,
                "label": label,
                "type": node_type,
                "in_degree": in_degree,
                "out_degree": out_degree,
                "total_degree": total_degree,
                "criticality_score": total_degree
            })

        node_scores.sort(key=lambda x: x["criticality_score"], reverse=True)

        return node_scores[:top_n]

    # Backward compatibility methods

    def get_graph_stats(self) -> Dict[str, Any]:
        """Get statistical summary of the attack graph.

        Deprecated: Use get_stats() instead.

        Returns:
            Dictionary containing graph statistics.
        """
        return self.get_stats()

    def BuildAttackGraph(self) -> None:
        """Main entry point for attack graph visualization.

        Deprecated: Use build() instead.

        Loads data, renders the graph, and saves to file.

        Raises:
            AttackGraphError: If any step fails.
        """
        self.build()

    # NetworkX-powered analysis methods

    def _get_node_label(self, node_id: str) -> str:
        """Get display label for a node."""
        for section in ['hosts', 'vulnerabilities', 'privileges', 'services', 'exploits']:
            if node_id in self.inputdata.get(section, {}):
                return self.inputdata[section][node_id].get("label", node_id)
        return node_id

    def betweenness_centrality(self, top_n: int = 10) -> List[Dict[str, Any]]:
        """Calculate betweenness centrality for all nodes.

        Betweenness centrality measures how often a node lies on the shortest
        path between other nodes. High betweenness nodes are critical chokepoints.

        Args:
            top_n: Number of top nodes to return.

        Returns:
            List of node dictionaries sorted by betweenness centrality.
        """
        self._ensure_nx_graph()

        centrality = nx.betweenness_centrality(self._nx_graph)
        results = []

        for node_id, score in centrality.items():
            results.append({
                "id": node_id,
                "label": self._get_node_label(node_id),
                "type": self._node_types.get(node_id, "unknown"),
                "betweenness_centrality": round(score, 6)
            })

        results.sort(key=lambda x: x["betweenness_centrality"], reverse=True)
        return results[:top_n]

    def closeness_centrality(self, top_n: int = 10) -> List[Dict[str, Any]]:
        """Calculate closeness centrality for all nodes.

        Closeness centrality measures how close a node is to all other nodes.
        High closeness nodes can quickly reach other parts of the network.

        Args:
            top_n: Number of top nodes to return.

        Returns:
            List of node dictionaries sorted by closeness centrality.
        """
        self._ensure_nx_graph()

        centrality = nx.closeness_centrality(self._nx_graph)
        results = []

        for node_id, score in centrality.items():
            results.append({
                "id": node_id,
                "label": self._get_node_label(node_id),
                "type": self._node_types.get(node_id, "unknown"),
                "closeness_centrality": round(score, 6)
            })

        results.sort(key=lambda x: x["closeness_centrality"], reverse=True)
        return results[:top_n]

    def pagerank(self, top_n: int = 10, alpha: float = 0.85) -> List[Dict[str, Any]]:
        """Calculate PageRank for all nodes.

        PageRank measures node importance based on incoming links from
        important nodes. Useful for identifying high-value targets.

        Args:
            top_n: Number of top nodes to return.
            alpha: Damping factor (default 0.85).

        Returns:
            List of node dictionaries sorted by PageRank score.
        """
        self._ensure_nx_graph()

        try:
            pr = nx.pagerank(self._nx_graph, alpha=alpha)
        except nx.PowerIterationFailedConvergence:
            # Fall back to simpler calculation if convergence fails
            pr = nx.pagerank(self._nx_graph, alpha=alpha, max_iter=200)

        results = []
        for node_id, score in pr.items():
            results.append({
                "id": node_id,
                "label": self._get_node_label(node_id),
                "type": self._node_types.get(node_id, "unknown"),
                "pagerank": round(score, 6)
            })

        results.sort(key=lambda x: x["pagerank"], reverse=True)
        return results[:top_n]

    def k_shortest_paths(
        self,
        source: str,
        target: str,
        k: int = 5
    ) -> List[List[str]]:
        """Find k shortest simple paths between source and target.

        Uses NetworkX's shortest_simple_paths for efficient enumeration.

        Args:
            source: Starting node ID.
            target: Target node ID.
            k: Number of shortest paths to return.

        Returns:
            List of paths, each path is a list of node IDs.
        """
        self._ensure_nx_graph()

        if source not in self._nx_graph or target not in self._nx_graph:
            return []

        try:
            paths = list(nx.shortest_simple_paths(self._nx_graph, source, target))
            return paths[:k]
        except nx.NetworkXNoPath:
            return []

    def all_paths_between(
        self,
        source: str,
        target: str,
        cutoff: int = 10
    ) -> Iterator[List[str]]:
        """Generator for all simple paths between source and target.

        Memory-efficient iteration over all paths up to a cutoff depth.

        Args:
            source: Starting node ID.
            target: Target node ID.
            cutoff: Maximum path length.

        Yields:
            Paths from source to target.
        """
        self._ensure_nx_graph()

        if source not in self._nx_graph or target not in self._nx_graph:
            return

        yield from nx.all_simple_paths(self._nx_graph, source, target, cutoff=cutoff)

    def find_cycles(self) -> List[List[str]]:
        """Find all simple cycles in the attack graph.

        Cycles may indicate feedback loops or circular dependencies
        in attack paths.

        Returns:
            List of cycles, each cycle is a list of node IDs.
        """
        self._ensure_nx_graph()

        try:
            cycles = list(nx.simple_cycles(self._nx_graph))
            return cycles
        except Exception:
            return []

    def strongly_connected_components(self) -> List[Set[str]]:
        """Find strongly connected components in the graph.

        Nodes in the same SCC can all reach each other. Useful for
        identifying tightly coupled network segments.

        Returns:
            List of sets, each set contains node IDs in a component.
        """
        self._ensure_nx_graph()

        sccs = list(nx.strongly_connected_components(self._nx_graph))
        # Sort by size, largest first
        sccs.sort(key=len, reverse=True)
        return sccs

    def graph_density(self) -> float:
        """Calculate the density of the attack graph.

        Density is the ratio of actual edges to possible edges.
        Higher density means more interconnected attack surface.

        Returns:
            Density value between 0 and 1.
        """
        self._ensure_nx_graph()
        return nx.density(self._nx_graph)

    def diameter(self) -> Optional[int]:
        """Calculate the diameter of the attack graph.

        Diameter is the longest shortest path. Returns None if graph
        is not strongly connected.

        Returns:
            Diameter as integer, or None if not computable.
        """
        self._ensure_nx_graph()

        try:
            # For directed graphs, use the strongly connected component
            if nx.is_strongly_connected(self._nx_graph):
                return nx.diameter(self._nx_graph)
            else:
                # Find diameter of largest strongly connected component
                largest_scc = max(
                    nx.strongly_connected_components(self._nx_graph),
                    key=len
                )
                if len(largest_scc) > 1:
                    subgraph = self._nx_graph.subgraph(largest_scc)
                    return nx.diameter(subgraph)
                return None
        except Exception:
            return None

    def find_chokepoints(self, top_n: int = 10) -> List[Dict[str, Any]]:
        """Identify network chokepoints based on betweenness centrality.

        Chokepoints are nodes that many attack paths must traverse.
        Securing these nodes can disrupt multiple attack vectors.

        Args:
            top_n: Number of top chokepoints to return.

        Returns:
            List of chokepoint dictionaries with scores.
        """
        self._ensure_nx_graph()

        betweenness = nx.betweenness_centrality(self._nx_graph)
        results = []

        for node_id, score in betweenness.items():
            if score > 0:  # Only include nodes that are on paths
                in_deg = self._nx_graph.in_degree(node_id)
                out_deg = self._nx_graph.out_degree(node_id)

                results.append({
                    "id": node_id,
                    "label": self._get_node_label(node_id),
                    "type": self._node_types.get(node_id, "unknown"),
                    "betweenness_score": round(score, 6),
                    "in_degree": in_deg,
                    "out_degree": out_deg,
                    "is_critical": score > 0.1  # Threshold for critical chokepoint
                })

        results.sort(key=lambda x: x["betweenness_score"], reverse=True)
        return results[:top_n]

    def find_attack_surfaces(self) -> List[Dict[str, Any]]:
        """Identify attack surface entry points.

        Entry points are nodes with no incoming edges (sources) or
        nodes explicitly marked as external/internet-facing.

        Returns:
            List of attack surface nodes with metadata.
        """
        self._ensure_nx_graph()

        entry_points = []

        for node_id in self._nx_graph.nodes():
            in_degree = self._nx_graph.in_degree(node_id)
            out_degree = self._nx_graph.out_degree(node_id)
            node_type = self._node_types.get(node_id, "unknown")

            # Entry points: no incoming edges and has outgoing edges
            # or nodes named 'internet', 'attacker', 'external'
            is_entry = (in_degree == 0 and out_degree > 0) or \
                       node_id.lower() in ('internet', 'attacker', 'external')

            if is_entry:
                entry_points.append({
                    "id": node_id,
                    "label": self._get_node_label(node_id),
                    "type": node_type,
                    "out_degree": out_degree,
                    "reachable_nodes": len(nx.descendants(self._nx_graph, node_id))
                })

        # Sort by number of reachable nodes (attack surface size)
        entry_points.sort(key=lambda x: x["reachable_nodes"], reverse=True)
        return entry_points

    def vulnerability_impact_score(self, vuln_id: str) -> Dict[str, Any]:
        """Calculate impact score for a vulnerability based on reachability.

        Combines CVSS score with graph position to estimate real impact.
        Vulnerabilities that lead to more critical assets score higher.

        Args:
            vuln_id: Vulnerability node ID.

        Returns:
            Dictionary with impact metrics.
        """
        self._ensure_nx_graph()

        if vuln_id not in self._nx_graph:
            return {
                "id": vuln_id,
                "error": "Vulnerability not found in graph"
            }

        # Get base CVSS score
        cvss = self._nx_graph.nodes[vuln_id].get("cvss", 5.0)

        # Calculate reachability metrics
        descendants = nx.descendants(self._nx_graph, vuln_id)
        ancestors = nx.ancestors(self._nx_graph, vuln_id)

        # Count high-value targets reachable from this vulnerability
        privilege_targets = sum(
            1 for n in descendants
            if self._node_types.get(n) == "privilege"
        )

        # Calculate normalized impact score
        # Base: CVSS (0-10), adjusted by reachability
        reachability_factor = min(len(descendants) / 10, 2.0)  # Cap at 2x
        impact_score = cvss * (1 + reachability_factor * 0.2)

        return {
            "id": vuln_id,
            "label": self._get_node_label(vuln_id),
            "cvss": cvss,
            "reachable_nodes": len(descendants),
            "privilege_targets": privilege_targets,
            "attack_paths_through": len(ancestors),
            "impact_score": round(min(impact_score, 10.0), 2)
        }

    def get_graph_metrics(self) -> Dict[str, Any]:
        """Get comprehensive graph metrics using NetworkX.

        Returns:
            Dictionary with various graph metrics.
        """
        self._ensure_nx_graph()

        num_nodes = self._nx_graph.number_of_nodes()
        num_edges = self._nx_graph.number_of_edges()

        # Count nodes by type
        type_counts = {}
        for node_type in self._node_types.values():
            type_counts[node_type] = type_counts.get(node_type, 0) + 1

        # Get SCCs
        sccs = list(nx.strongly_connected_components(self._nx_graph))

        # Get cycles (limit for performance)
        try:
            cycles = list(nx.simple_cycles(self._nx_graph))
            num_cycles = len(cycles)
        except Exception:
            num_cycles = 0

        return {
            "num_nodes": num_nodes,
            "num_edges": num_edges,
            "density": round(nx.density(self._nx_graph), 6),
            "diameter": self.diameter(),
            "num_strongly_connected_components": len(sccs),
            "largest_scc_size": len(max(sccs, key=len)) if sccs else 0,
            "num_cycles": num_cycles,
            "is_dag": nx.is_directed_acyclic_graph(self._nx_graph),
            "node_types": type_counts
        }

    # =========================================================================
    # Export/Conversion Methods
    # =========================================================================

    def to_mermaid_diagram(self) -> "MermaidDiagrams":
        """Convert to MermaidDiagrams format.

        Returns:
            MermaidDiagrams instance ready to render.

        Example:
            >>> ag = AttackGraphs("graph.toml", "output")
            >>> md = ag.to_mermaid_diagram()
            >>> md.render("output", format="svg")
        """
        from .mermaiddiagrams import MermaidDiagrams
        return MermaidDiagrams.from_attack_graph(self.inputfile)

    def to_cloud_diagram(self) -> "CloudDiagrams":
        """Convert to CloudDiagrams format.

        Returns:
            CloudDiagrams instance ready to render.

        Example:
            >>> ag = AttackGraphs("graph.toml", "output")
            >>> cd = ag.to_cloud_diagram()
            >>> cd.render("output", format="png")
        """
        from .clouddiagrams import CloudDiagrams
        return CloudDiagrams.from_attack_graph(self.inputfile)

    def export_mermaid(self, output: str) -> str:
        """Export as Mermaid syntax file.

        Args:
            output: Output file path (with or without .mmd extension)

        Returns:
            Path to saved file.
        """
        md = self.to_mermaid_diagram()
        return md.save_mmd(output)

    def export_python_diagrams(self, output: str) -> str:
        """Export as Python Diagrams code file.

        Args:
            output: Output file path (with or without .py extension)

        Returns:
            Path to saved file.
        """
        cd = self.to_cloud_diagram()
        return cd.save_python(output)
