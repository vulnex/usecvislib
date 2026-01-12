#
# VULNEX -Universal Security Visualization Library-
#
# File: attacktrees.py
# Author: Simon Roses Femerling
# Created: 2025-01-01
# Last Modified: 2025-12-31
# Version: 0.3.2
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Attack Trees Visualization Module.

This module provides visualization tools for attack tree diagrams using
directed acyclic graphs (DAGs). Attack trees represent security threats
as hierarchical structures showing how an attacker might achieve goals.
"""

from typing import Dict, Any, Optional, List

from graphviz import Digraph

from . import utils
from .base import VisualizationBase
from .constants import cvss_to_color, cvss_to_severity_label, validate_cvss_score
from .cvss import get_cvss_score, validate_cvss_vector
from .settings import is_cvss_enabled


class AttackTreeError(utils.RenderError):
    """Exception raised for attack tree generation errors."""
    pass


class AttackTrees(VisualizationBase):
    """Attack tree visualization class.

    Creates visual representations of attack scenarios using Graphviz
    directed graphs with customizable styling.

    Supports TOML, JSON, and YAML input formats.

    Attributes:
        inputfile: Path to the configuration file (TOML, JSON, or YAML).
        outputfile: Path for the output visualization.
        format: Output format (png, pdf, svg, dot).
        styleid: Style identifier for visualization theming.
        inputdata: Parsed attack tree data.
        style: Style configuration dictionary.
        dot: Graphviz Digraph object.
    """

    # Configuration for base class
    STYLE_FILE = "config_attacktrees.tml"
    DEFAULT_STYLE_ID = "at_default"
    ALLOWED_EXTENSIONS = ['.toml', '.tml', '.json', '.yaml', '.yml']
    MAX_INPUT_SIZE = 10 * 1024 * 1024  # 10 MB

    # Style-related attributes that should be overridden by selected style
    # When a non-default style is selected, these attributes from template nodes
    # are stripped so the style's values take precedence
    STYLE_OVERRIDE_ATTRS = {
        'fillcolor', 'fontcolor', 'color', 'style', 'shape',
        'fontname', 'fontsize', 'penwidth', 'margin'
    }

    def __init__(
        self,
        inputfile: str,
        outputfile: str,
        format: str = "",
        styleid: str = "",
        validate_paths: bool = True
    ) -> None:
        """Initialize AttackTrees with input/output paths and styling options.

        Args:
            inputfile: Path to the attack tree file (TOML, JSON, or YAML).
            outputfile: Path for the output visualization.
            format: Output format (png, pdf, svg, dot). Defaults to png.
            styleid: Style identifier from config. Defaults to at_default.
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

        # Attack tree specific state
        self.dot: Optional[Digraph] = None

        # Backward compatibility: expose stylefile attribute
        self.stylefile = self.STYLE_FILE

        # SECURITY: Track temp input file for cleanup (used by builder)
        self._temp_input: Optional[str] = None

    def __del__(self):
        """SECURITY: Cleanup temporary input files on object destruction.

        This ensures temp files created by AttackTreeBuilder are properly
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
        """Return default style configuration for attack trees.

        Returns:
            Dictionary with default root, node, and edge styles.
        """
        return {
            "root": {
                "style": "filled",
                "fillcolor": "#e74c3c",
                "fontcolor": "white",
                "fontname": "Arial",
                "shape": "box"
            },
            "node": {
                "style": "filled",
                "fillcolor": "#3498db",
                "fontcolor": "white",
                "fontname": "Arial",
                "shape": "box"
            },
            "edge": {
                "color": "#34495e",
                "fontname": "Arial"
            }
        }

    def _strip_style_attrs(self, attrs: Dict[str, Any]) -> Dict[str, Any]:
        """Strip style-related attributes from node data when a style is selected.

        When a non-default style is explicitly selected, template-defined colors
        and styling should be overridden by the style's values. This method
        removes style-related attributes so the selected style takes precedence.

        Args:
            attrs: Node attributes dictionary.

        Returns:
            New dictionary with style attributes removed.
        """
        if self.styleid == self.DEFAULT_STYLE_ID:
            # Default style: preserve template colors
            return attrs
        # Non-default style selected: strip style attrs so style takes precedence
        return {k: v for k, v in attrs.items() if k not in self.STYLE_OVERRIDE_ATTRS}

    def _get_metadata_root_key(self) -> str:
        """Get the root key for metadata extraction.

        Returns:
            'tree' as the root key for attack trees.
        """
        return "tree"

    def _load_impl(self) -> Dict[str, Any]:
        """Load attack tree data from configuration file.

        Returns:
            Parsed attack tree data dictionary.

        Raises:
            AttackTreeError: If the file cannot be read or parsed.
        """
        try:
            data = utils.ReadConfigFile(self.inputfile)
            self.logger.debug(f"Loaded attack tree with {len(data.get('nodes', {}))} nodes")
            return data
        except (utils.FileError, utils.ConfigError) as e:
            self.logger.error(f"Failed to load attack tree from {self.inputfile}: {e}")
            raise AttackTreeError(f"Failed to load attack tree: {e}")
        except FileNotFoundError as e:
            self.logger.error(f"Input file not found: {self.inputfile}")
            raise AttackTreeError(f"Input file not found: {e}")

    def _render_impl(self) -> None:
        """Build the attack tree graph from loaded data.

        Raises:
            AttackTreeError: If required data sections are missing.
        """
        # Validate required sections
        if "tree" not in self.inputdata:
            raise AttackTreeError("Missing 'tree' section in input file")
        if "nodes" not in self.inputdata:
            raise AttackTreeError("Missing 'nodes' section in input file")
        if "edges" not in self.inputdata:
            raise AttackTreeError("Missing 'edges' section in input file")

        tree = self.inputdata["tree"]
        nodes = self.inputdata["nodes"]
        edges = self.inputdata["edges"]

        # Get style defaults
        root_defaults = self.style.get("root", {})
        node_defaults = self.style.get("node", {})
        edge_defaults = self.style.get("edge", {})

        # Create the graph
        self.dot = Digraph(
            format=self.format,
            name=tree.get("name", "Attack Tree")
        )

        # Apply graph-level parameters
        diagraph_params = tree.get("params", {})
        diagraph_params = utils.stringify_dict(diagraph_params)
        self.dot.attr(**diagraph_params)

        # Get root node
        root_node = tree.get("root")
        if not root_node:
            raise AttackTreeError("Missing 'root' in tree section")

        # Add root node with styling (root nodes don't get CVSS coloring)
        root_node_attributes = nodes.get(root_node, {}).copy()
        # Check if user wants a styled background for root node
        # Preserve shape/style if:
        # 1. User set a visible shape (not none/plaintext/point), OR
        # 2. User set style containing "filled", OR
        # 3. User set a fillcolor
        root_user_data = nodes.get(root_node, {})
        root_user_shape = root_user_data.get('shape', '') if isinstance(root_user_data, dict) else ''
        root_user_style = root_user_data.get('style', '') if isinstance(root_user_data, dict) else ''
        root_user_fillcolor = root_user_data.get('fillcolor', '') if isinstance(root_user_data, dict) else ''

        root_wants_no_background = root_user_shape in ('none', 'plaintext', 'point')
        root_wants_background = ('filled' in str(root_user_style).lower()) or bool(root_user_fillcolor)
        root_has_visible_shape = bool(root_user_shape) and not root_wants_no_background

        user_set_shape = (root_has_visible_shape or root_wants_background) and not root_wants_no_background
        # Remove CVSS fields from attributes before passing to graphviz
        root_node_attributes.pop("cvss", None)
        root_node_attributes.pop("cvss_vector", None)
        # Strip style attributes when a non-default style is selected
        # This allows the selected style to override template colors
        root_node_attributes = self._strip_style_attrs(root_node_attributes)
        # Merge with defaults first (style values take precedence when style selected)
        root_node_kwargs = utils.merge_dicts(root_defaults, root_node_attributes)
        # Process image AFTER merge so icon settings take priority
        utils.process_node_image(root_node_kwargs, root_node, self.logger, preserve_shape=user_set_shape)
        root_node_kwargs = utils.stringify_dict(root_node_kwargs)
        self.dot.node(root_node, **root_node_kwargs)

        # Add remaining nodes with styling and CVSS support
        for node, attributes in nodes.items():
            if node == root_node:
                continue

            # Copy attributes to avoid modifying original
            node_attrs = attributes.copy() if isinstance(attributes, dict) else {}

            # Check if node has an image and if user wants a styled background
            # Preserve shape/style if:
            # 1. User set a visible shape (not none/plaintext/point), OR
            # 2. User set style containing "filled", OR
            # 3. User set a fillcolor
            has_image = 'image' in node_attrs and node_attrs['image']
            user_shape = attributes.get('shape', '') if isinstance(attributes, dict) else ''
            user_style = attributes.get('style', '') if isinstance(attributes, dict) else ''
            user_fillcolor = attributes.get('fillcolor', '') if isinstance(attributes, dict) else ''

            # User explicitly wants NO background if they set shape="none"
            user_wants_no_background = user_shape in ('none', 'plaintext', 'point')
            # User wants a styled background if they set style="filled" or a fillcolor
            user_wants_background = ('filled' in str(user_style).lower()) or bool(user_fillcolor)
            # Also preserve if user set a visible shape (box, ellipse, etc.)
            user_has_visible_shape = bool(user_shape) and not user_wants_no_background

            user_set_shape = (user_has_visible_shape or user_wants_background) and not user_wants_no_background

            # Extract and process CVSS
            cvss_value = node_attrs.pop("cvss", None)
            cvss_vector = node_attrs.pop("cvss_vector", None)
            resolved_score, _ = get_cvss_score(cvss_value, cvss_vector)

            # Strip style attributes when a non-default style is selected
            # This allows the selected style to override template colors
            node_attrs = self._strip_style_attrs(node_attrs)

            # Apply CVSS-based styling if score is present and CVSS display is enabled
            # Skip fillcolor for nodes with images (they use shape=none)
            # Only apply CVSS colors when using default style - otherwise let style take precedence
            if resolved_score is not None and is_cvss_enabled("attack_tree"):
                severity = cvss_to_severity_label(resolved_score)
                # Only apply CVSS fillcolor when using default style
                # Non-default styles should have their colors take full precedence
                use_cvss_colors = self.styleid == self.DEFAULT_STYLE_ID
                if not has_image and use_cvss_colors:
                    node_attrs["fillcolor"] = cvss_to_color(resolved_score)
                    # Set fontcolor to white for readability on CVSS-colored backgrounds
                    # (only if user hasn't explicitly set fontcolor)
                    if "fontcolor" not in attributes:
                        node_attrs["fontcolor"] = "white"
                # Add CVSS to label if not already customized
                current_label = node_attrs.get("label", node)
                if "CVSS" not in str(current_label):
                    if cvss_vector and cvss_value is None:
                        node_attrs["label"] = f"{node}\\n(CVSS: {resolved_score} - {severity})*"
                    else:
                        node_attrs["label"] = f"{node}\\n(CVSS: {resolved_score} - {severity})"

            # For nodes with icons, set fontcolor to black for readability
            # (icons appear on white/light background, not colored fill)
            if has_image and "fontcolor" not in attributes:
                node_attrs["fontcolor"] = "black"

            # Merge with defaults (style values take precedence when style selected)
            node_kwargs = utils.merge_dicts(node_defaults, node_attrs)
            # Process image AFTER merge so icon settings take priority
            utils.process_node_image(node_kwargs, node, self.logger, preserve_shape=user_set_shape)
            node_kwargs = utils.stringify_dict(node_kwargs)
            self.dot.node(node, **node_kwargs)

        # Add edges
        for parent, children in edges.items():
            if not isinstance(children, list):
                raise AttackTreeError(
                    f"Edges for '{parent}' must be a list, got {type(children).__name__}"
                )
            for child in children:
                if not isinstance(child, dict):
                    raise AttackTreeError(
                        f"Edge entry must be a dict with 'to' key, got {type(child).__name__}"
                    )
                if 'to' not in child:
                    raise AttackTreeError(f"Edge entry missing 'to' key: {child}")

                edge_attrs = {k: v for k, v in child.items() if k != 'to'}
                edge_kwargs = utils.merge_dicts(edge_attrs, edge_defaults)
                edge_kwargs = utils.stringify_dict(edge_kwargs)
                self.dot.edge(parent, child['to'], **edge_kwargs)

        self.logger.debug(f"Rendered attack tree with {len(nodes)} nodes")

    def _draw_impl(self, outputfile: str) -> None:
        """Save the attack tree visualization to file.

        Args:
            outputfile: Path for output file.

        Raises:
            AttackTreeError: If rendering fails.
        """
        if self.dot is None:
            raise AttackTreeError("Graph not rendered. Call render() first.")

        try:
            self.dot.render(outputfile, cleanup=True)
            self.logger.debug("Successfully wrote attack tree visualization")
        except Exception as e:
            self.logger.error(f"Failed to render graph to {outputfile}: {e}")
            raise AttackTreeError(f"Failed to render graph: {e}")

    def _validate_impl(self) -> List[str]:
        """Validate the attack tree structure.

        Returns:
            List of validation error messages. Empty if valid.
        """
        errors = []

        tree = self.inputdata.get("tree", {})
        nodes = self.inputdata.get("nodes", {})
        edges = self.inputdata.get("edges", {})

        # Check for required tree section
        if not tree:
            errors.append("Missing 'tree' section")
        else:
            if "root" not in tree:
                errors.append("Missing 'root' in tree section")
            elif tree["root"] not in nodes:
                errors.append(f"Root node '{tree['root']}' not defined in nodes")

        # Check for orphan nodes (not connected)
        all_connected = set()
        all_connected.add(tree.get("root", ""))

        for parent, children in edges.items():
            all_connected.add(parent)
            for child in children:
                if isinstance(child, dict) and 'to' in child:
                    all_connected.add(child['to'])

        orphans = set(nodes.keys()) - all_connected
        if orphans:
            errors.append(f"Orphan nodes (not connected): {', '.join(orphans)}")

        # Check for undefined nodes in edges
        defined_nodes = set(nodes.keys())
        for parent, children in edges.items():
            if parent not in defined_nodes:
                errors.append(f"Edge parent '{parent}' not defined in nodes")
            for child in children:
                if isinstance(child, dict) and 'to' in child:
                    if child['to'] not in defined_nodes:
                        errors.append(f"Edge target '{child['to']}' not defined in nodes")

        # Validate CVSS values in nodes
        for node_name, node_attrs in nodes.items():
            if isinstance(node_attrs, dict):
                cvss_value = node_attrs.get("cvss")
                cvss_vector = node_attrs.get("cvss_vector")

                if cvss_value is not None:
                    is_valid, _, error_msg = validate_cvss_score(cvss_value)
                    if not is_valid:
                        errors.append(f"Node '{node_name}': {error_msg}")

                if cvss_vector is not None:
                    is_valid, error_msg = validate_cvss_vector(cvss_vector)
                    if not is_valid:
                        errors.append(f"Node '{node_name}': {error_msg}")

        return errors

    def _get_stats_impl(self) -> Dict[str, Any]:
        """Get statistical summary of the attack tree.

        Returns:
            Dictionary containing tree statistics including CVSS analysis.
        """
        nodes = self.inputdata.get("nodes", {})
        edges = self.inputdata.get("edges", {})
        tree = self.inputdata.get("tree", {})

        # Count total edges
        total_edges = sum(len(children) for children in edges.values())

        # Find leaf nodes (nodes with no outgoing edges)
        parents = set(edges.keys())
        all_children = set()
        for children in edges.values():
            for child in children:
                if isinstance(child, dict) and 'to' in child:
                    all_children.add(child['to'])

        leaf_nodes = all_children - parents

        # Calculate CVSS statistics
        cvss_scores = []
        nodes_with_cvss = 0
        for node_name, node_attrs in nodes.items():
            if isinstance(node_attrs, dict):
                score, _ = get_cvss_score(node_attrs.get("cvss"), node_attrs.get("cvss_vector"))
                if score is not None:
                    cvss_scores.append(score)
                    nodes_with_cvss += 1

        avg_cvss = sum(cvss_scores) / len(cvss_scores) if cvss_scores else 0
        max_cvss = max(cvss_scores) if cvss_scores else 0
        critical_nodes = len([s for s in cvss_scores if s >= 9.0])
        high_risk_nodes = len([s for s in cvss_scores if s >= 7.0])

        return {
            "name": tree.get("name", "Unknown"),
            "root": tree.get("root", "Unknown"),
            "total_nodes": len(nodes),
            "total_edges": total_edges,
            "leaf_nodes": len(leaf_nodes),
            "internal_nodes": len(parents),
            "nodes_with_cvss": nodes_with_cvss,
            "average_cvss": round(avg_cvss, 2),
            "max_cvss": round(max_cvss, 1),
            "critical_nodes": critical_nodes,
            "high_risk_nodes": high_risk_nodes,
        }

    # Backward compatibility methods

    def get_tree_stats(self) -> Dict[str, Any]:
        """Get statistical summary of the attack tree.

        Deprecated: Use get_stats() instead.

        Returns:
            Dictionary containing tree statistics.
        """
        return self.get_stats()

    def BuildAttackTree(self) -> None:
        """Main entry point for attack tree visualization.

        Deprecated: Use build() instead.

        Loads data, renders the graph, and saves to file.

        Raises:
            AttackTreeError: If any step fails.
        """
        self.build()
