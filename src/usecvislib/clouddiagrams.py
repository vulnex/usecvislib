#
# VULNEX -Universal Security Visualization Library-
#
# File: clouddiagrams.py
# Author: Simon Roses Femerling
# Created: 2025-01-14
# Last Modified: 2025-01-14
# Version: 0.3.3
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""
Cloud architecture diagrams using Python Diagrams library.

Config-driven wrapper around the 'diagrams' library for creating
cloud architecture visualizations with provider-specific icons.

Requirements:
    - pip install diagrams
    - Graphviz installed (system dependency)

Example:
    >>> from usecvislib import CloudDiagrams
    >>> cd = CloudDiagrams()
    >>> cd.load("aws_architecture.toml")
    >>> cd.render("output", format="png")

    # Generate Python code for customization
    >>> print(cd.to_python_code())
"""

from typing import Dict, List, Any, Optional, Union, Set, Tuple
from pathlib import Path
from dataclasses import dataclass, field
import logging
import importlib
import pkgutil
import tempfile
import subprocess
import sys
import re

from .utils import (
    ReadConfigFile,
    parse_content,
    ValidationError,
    RenderError,
    validate_output_path,
    sanitize_node_id,
)


logger = logging.getLogger(__name__)


class CloudDiagramError(RenderError):
    """Cloud diagram specific error."""
    pass


class DiagramsNotInstalledError(CloudDiagramError):
    """Raised when diagrams library is not installed."""
    pass


class IconNotFoundError(CloudDiagramError):
    """Raised when a requested icon is not found."""
    pass


# =============================================================================
# Security: String Escaping for Code Generation
# =============================================================================

def _escape_python_string(value: str, max_length: int = 500) -> str:
    """Escape a string for safe use in generated Python code.

    SECURITY: Prevents code injection attacks by properly escaping all
    characters that could break out of a Python string literal. This is
    critical when generating Python code from user-provided input.

    The function:
    1. Removes/replaces control characters (newlines, tabs, etc.)
    2. Escapes backslashes first (to prevent interaction with other escapes)
    3. Escapes quotes
    4. Truncates overly long strings
    5. Removes null bytes

    Args:
        value: The string to escape
        max_length: Maximum allowed length (truncated if exceeded)

    Returns:
        Escaped string safe for use in Python string literals

    Example:
        >>> _escape_python_string('Hello "World"')
        'Hello \\"World\\"'
        >>> _escape_python_string('Line1\\nLine2')
        'Line1 Line2'
    """
    if not value:
        return ""

    # Remove null bytes (potential security issue)
    value = value.replace('\x00', '')

    # Truncate if too long
    if len(value) > max_length:
        value = value[:max_length - 3] + "..."
        logger.warning(f"Truncated string to {max_length} characters for code generation")

    # Remove/replace control characters that could break the string
    # Replace newlines and carriage returns with spaces
    value = value.replace('\r\n', ' ')
    value = value.replace('\n', ' ')
    value = value.replace('\r', ' ')
    # Replace tabs with spaces
    value = value.replace('\t', ' ')
    # Remove other control characters (ASCII 0-31 except those already handled)
    value = ''.join(c if ord(c) >= 32 or c in ' ' else '' for c in value)

    # Escape backslashes FIRST (before escaping quotes)
    # This prevents backslashes from interacting with quote escaping
    value = value.replace('\\', '\\\\')

    # Escape double quotes
    value = value.replace('"', '\\"')

    return value


@dataclass
class CloudDiagramConfig:
    """Cloud diagram configuration.

    Attributes:
        title: Diagram title
        direction: Graph direction (LR, RL, TB, BT)
        outformat: Default output format
        filename: Output filename (without extension)
        show: Whether to open result after rendering
        graph_attr: Graphviz graph attributes
        node_attr: Default node attributes
        edge_attr: Default edge attributes
    """
    title: str = "Cloud Architecture"
    direction: str = "LR"
    outformat: str = "png"
    filename: str = ""
    show: bool = False
    graph_attr: Dict[str, str] = field(default_factory=dict)
    node_attr: Dict[str, str] = field(default_factory=dict)
    edge_attr: Dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CloudDiagramConfig":
        """Create from dictionary.

        Supports both [diagram] section (templates) and [cloud] section (frontend).
        """
        # Check for diagram section first, then cloud section, then use root
        diagram_section = data.get("diagram") or data.get("cloud") or data
        return cls(
            title=diagram_section.get("title", "Cloud Architecture"),
            direction=diagram_section.get("direction", "LR"),
            outformat=diagram_section.get("outformat", "png"),
            filename=diagram_section.get("filename", ""),
            show=diagram_section.get("show", False),
            graph_attr=diagram_section.get("graph_attr", {}),
            node_attr=diagram_section.get("node_attr", {}),
            edge_attr=diagram_section.get("edge_attr", {}),
        )


@dataclass
class CloudNode:
    """A node in the cloud diagram.

    Attributes:
        id: Unique node identifier
        icon: Icon path (e.g., "aws.compute.EC2" or "aws:EC2")
        label: Display label
        cluster_id: Optional cluster this node belongs to
    """
    id: str
    icon: str
    label: str
    cluster_id: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any], cluster_id: str = None) -> "CloudNode":
        """Create from dictionary."""
        return cls(
            id=data.get("id", ""),
            icon=data.get("icon", data.get("type", "")),
            label=data.get("label", data.get("id", "")),
            cluster_id=cluster_id,
        )


@dataclass
class CloudEdge:
    """An edge in the cloud diagram.

    Attributes:
        from_id: Source node ID(s) - can be string or list
        to_id: Target node ID(s) - can be string or list
        label: Edge label
        color: Edge color
        style: Edge style (solid, dashed, dotted, bold)
    """
    from_id: Union[str, List[str]]
    to_id: Union[str, List[str]]
    label: str = ""
    color: str = ""
    style: str = ""

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CloudEdge":
        """Create from dictionary."""
        return cls(
            from_id=data.get("from", ""),
            to_id=data.get("to", ""),
            label=data.get("label", ""),
            color=data.get("color", ""),
            style=data.get("style", ""),
        )


@dataclass
class CloudCluster:
    """A cluster (group) in the cloud diagram.

    Attributes:
        id: Unique cluster identifier
        label: Display label
        nodes: List of nodes in this cluster
        style: Cluster style attributes
    """
    id: str
    label: str
    nodes: List[CloudNode] = field(default_factory=list)
    style: Dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CloudCluster":
        """Create from dictionary."""
        cluster_id = data.get("id", "")
        nodes = [
            CloudNode.from_dict(n, cluster_id)
            for n in data.get("nodes", [])
        ]
        return cls(
            id=cluster_id,
            label=data.get("label", cluster_id),
            nodes=nodes,
            style=data.get("style", {}),
        )


@dataclass
class CloudDiagramResult:
    """Result of a cloud diagram rendering operation.

    Attributes:
        output_path: Path to the generated output file
        format: Output format
        stats: Dictionary of diagram statistics
        success: Whether the operation was successful
    """
    output_path: str
    format: str
    stats: Dict[str, Any] = field(default_factory=dict)
    success: bool = True

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "output_path": self.output_path,
            "format": self.format,
            "stats": self.stats,
            "success": self.success,
        }


class CloudDiagrams:
    """Cloud architecture diagrams with provider icons.

    Provides a config-driven interface to the Python Diagrams library,
    allowing users to define cloud architecture in TOML/YAML/JSON.

    Features:
    - All major cloud providers (AWS, Azure, GCP, K8s, etc.)
    - Icon discovery and search
    - Python code generation for advanced customization
    - Conversion from other usecvislib formats

    Example:
        >>> cd = CloudDiagrams()
        >>> cd.load("architecture.toml")
        >>> result = cd.render("output", format="png")

        >>> # Generate Python code
        >>> code = cd.to_python_code()
        >>> print(code)

        >>> # Search for icons
        >>> icons = CloudDiagrams.search_icons("database")
    """

    # Supported cloud providers
    PROVIDERS = {
        "aws": "Amazon Web Services",
        "azure": "Microsoft Azure",
        "gcp": "Google Cloud Platform",
        "k8s": "Kubernetes",
        "onprem": "On-Premises",
        "saas": "SaaS Applications",
        "generic": "Generic Icons",
        "programming": "Programming Languages",
        "firebase": "Firebase",
        "digitalocean": "DigitalOcean",
        "alibabacloud": "Alibaba Cloud",
        "oci": "Oracle Cloud Infrastructure",
        "openstack": "OpenStack",
        "outscale": "Outscale",
        "ibm": "IBM Cloud",
        "elastic": "Elastic",
        "c4": "C4 Model",
        "custom": "Custom Icons",
    }

    # Supported output formats
    OUTPUT_FORMATS = {"png", "jpg", "svg", "pdf", "dot"}

    # Valid directions
    DIRECTIONS = {"LR", "RL", "TB", "BT"}

    # Allowed config file extensions
    ALLOWED_EXTENSIONS = [".toml", ".tml", ".json", ".yaml", ".yml"]

    # Icon cache for performance
    _icon_cache: Dict[str, List[Dict[str, str]]] = {}

    def __init__(self, validate_diagrams: bool = True):
        """Initialize CloudDiagrams.

        Args:
            validate_diagrams: Whether to validate diagrams library availability

        Raises:
            DiagramsNotInstalledError: If diagrams library is not installed
        """
        self.config = CloudDiagramConfig()
        self.nodes: List[CloudNode] = []
        self.edges: List[CloudEdge] = []
        self.clusters: List[CloudCluster] = []
        self._config_path: Optional[Path] = None
        self._loaded = False
        self._diagrams_available = False

        if validate_diagrams:
            self._validate_diagrams_available()

    def _validate_diagrams_available(self) -> None:
        """Check if diagrams library is installed.

        Raises:
            DiagramsNotInstalledError: If diagrams library is not found
        """
        try:
            import diagrams
            self._diagrams_available = True
            logger.debug("diagrams library available")
        except ImportError:
            raise DiagramsNotInstalledError(
                "diagrams library not found. Install with: pip install diagrams"
            )

    # =========================================================================
    # Input Methods
    # =========================================================================

    def load(self, filepath: str) -> "CloudDiagrams":
        """Load from TOML/YAML/JSON config file.

        Args:
            filepath: Path to configuration file

        Returns:
            Self for method chaining

        Raises:
            FileNotFoundError: If file doesn't exist
            ValidationError: If format is invalid
        """
        path = Path(filepath)

        if not path.exists():
            raise FileNotFoundError(f"File not found: {filepath}")

        suffix = path.suffix.lower()
        if suffix not in self.ALLOWED_EXTENSIONS:
            raise ValidationError(
                f"Unsupported file extension: {suffix}. "
                f"Supported: {self.ALLOWED_EXTENSIONS}"
            )

        self._config_path = path

        config_data = ReadConfigFile(str(path))
        self._load_from_dict(config_data)
        self._loaded = True

        logger.info(f"Loaded cloud diagram from {path}")
        return self

    def load_from_string(
        self,
        content: str,
        format: str = "toml"
    ) -> "CloudDiagrams":
        """Load from string content.

        Args:
            content: Configuration content
            format: Content format - "toml", "yaml", "json"

        Returns:
            Self for method chaining

        Raises:
            ValidationError: If content is empty or invalid
        """
        if not content.strip():
            raise ValidationError("Content is empty")

        if format not in ("toml", "yaml", "json"):
            raise ValidationError(
                f"Unsupported format: {format}. Supported: toml, yaml, json"
            )

        config_data = parse_content(content, format)
        self._load_from_dict(config_data)
        self._loaded = True

        logger.info(f"Loaded cloud diagram from string ({format})")
        return self

    def _load_from_dict(self, data: Dict[str, Any]) -> None:
        """Load configuration from dictionary.

        Supports two formats:
        1. Standard format: [diagram], [[nodes]], [[edges]], [[clusters]]
        2. Cloud format: [cloud], [[cloud.nodes]], [[cloud.edges]], [[cloud.clusters]]

        Args:
            data: Configuration dictionary
        """
        self.config = CloudDiagramConfig.from_dict(data)

        # Support both formats: check for 'cloud' section (frontend format) or root level (template format)
        cloud_section = data.get("cloud", {})

        # Load clusters (with embedded nodes) - check both locations
        clusters_data = data.get("clusters", []) or cloud_section.get("clusters", [])
        self.clusters = []
        for cluster_data in clusters_data:
            cluster = CloudCluster.from_dict(cluster_data)
            self.clusters.append(cluster)

        # Load standalone nodes - check both locations
        nodes_data = data.get("nodes", []) or cloud_section.get("nodes", [])
        standalone_nodes = [
            CloudNode.from_dict(n)
            for n in nodes_data
        ]

        # Combine all nodes (cluster nodes + standalone)
        self.nodes = standalone_nodes.copy()
        for cluster in self.clusters:
            self.nodes.extend(cluster.nodes)

        # Load edges - check both locations
        edges_data = data.get("edges", []) or cloud_section.get("edges", [])
        self.edges = [
            CloudEdge.from_dict(e)
            for e in edges_data
        ]

    # =========================================================================
    # Rendering
    # =========================================================================

    def render(
        self,
        output: str,
        format: str = None,
        show: bool = None,
    ) -> CloudDiagramResult:
        """Render diagram to image file.

        Args:
            output: Output file path (without extension)
            format: Output format (overrides config)
            show: Whether to open result (overrides config)

        Returns:
            CloudDiagramResult with output path and stats

        Raises:
            ValidationError: If not loaded or invalid format
            CloudDiagramError: If rendering fails
        """
        if not self._loaded:
            raise ValidationError("No configuration loaded. Call load() first.")

        self._validate_diagrams_available()

        fmt = format or self.config.outformat
        show_result = show if show is not None else self.config.show

        if fmt not in self.OUTPUT_FORMATS:
            raise ValidationError(
                f"Unsupported format: {fmt}. Supported: {self.OUTPUT_FORMATS}"
            )

        # Validate output path
        output_path_obj = validate_output_path(output)
        output_base = str(output_path_obj)

        # Generate and execute Python code
        code = self._generate_executable_code(output_base, fmt, show_result)

        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".py",
            delete=False,
            encoding="utf-8"
        ) as f:
            f.write(code)
            script_path = f.name

        try:
            # Run the generated script
            result = subprocess.run(
                [sys.executable, script_path],
                capture_output=True,
                text=True,
                timeout=120,
                cwd=str(Path(output_base).parent) if Path(output_base).parent.exists() else "."
            )

            if result.returncode != 0:
                error_msg = result.stderr or result.stdout or "Unknown error"
                raise CloudDiagramError(f"Diagram generation failed: {error_msg}")

            output_file = f"{output_base}.{fmt}"

            # Check if file was created
            if not Path(output_file).exists():
                # Try to find the file (diagrams may adjust filename)
                possible_files = list(Path(output_base).parent.glob(f"{Path(output_base).stem}*.{fmt}"))
                if possible_files:
                    output_file = str(possible_files[0])
                else:
                    raise CloudDiagramError(f"Output file was not created: {output_file}")

            logger.info(f"Rendered cloud diagram to {output_file}")

            return CloudDiagramResult(
                output_path=output_file,
                format=fmt,
                stats=self.get_stats(),
                success=True
            )

        except subprocess.TimeoutExpired:
            raise CloudDiagramError("Diagram rendering timed out (120s limit)")

        finally:
            try:
                Path(script_path).unlink(missing_ok=True)
            except Exception as e:
                logger.warning(f"Failed to cleanup temp script: {e}")

    def _generate_executable_code(
        self,
        output: str,
        format: str,
        show: bool
    ) -> str:
        """Generate executable Python code for rendering.

        Args:
            output: Output file path
            format: Output format
            show: Whether to show result

        Returns:
            Python code string
        """
        lines = []

        # Collect imports
        imports = self._collect_imports()

        # Add base imports
        lines.append("from diagrams import Diagram, Cluster, Edge")

        # Add provider imports
        for imp in sorted(imports):
            lines.append(imp)

        lines.append("")

        # Create diagram
        # SECURITY: Use _escape_python_string to prevent code injection
        title_escaped = _escape_python_string(self.config.title)
        direction_escaped = _escape_python_string(self.config.direction)
        lines.append(f'with Diagram(')
        lines.append(f'    "{title_escaped}",')
        lines.append(f'    filename="{output}",')
        lines.append(f'    outformat="{format}",')
        lines.append(f'    show={show},')
        lines.append(f'    direction="{direction_escaped}",')
        lines.append(f'):')

        # Track node variable names for edge references
        node_vars: Dict[str, str] = {}

        # Add standalone nodes (not in clusters)
        cluster_node_ids = {n.id for c in self.clusters for n in c.nodes}
        standalone_nodes = [n for n in self.nodes if n.id not in cluster_node_ids]

        for node in standalone_nodes:
            var_name = self._safe_var_name(node.id)
            icon_class = self._get_icon_class_name(node.icon)
            label_escaped = _escape_python_string(node.label)
            lines.append(f'    {var_name} = {icon_class}("{label_escaped}")')
            node_vars[node.id] = var_name

        # Add clusters with their nodes
        for cluster in self.clusters:
            cluster_label_escaped = _escape_python_string(cluster.label)
            lines.append(f'')
            lines.append(f'    with Cluster("{cluster_label_escaped}"):')

            for node in cluster.nodes:
                var_name = self._safe_var_name(node.id)
                icon_class = self._get_icon_class_name(node.icon)
                node_label_escaped = _escape_python_string(node.label)
                lines.append(f'        {var_name} = {icon_class}("{node_label_escaped}")')
                node_vars[node.id] = var_name

        lines.append("")

        # Add edges
        for edge in self.edges:
            edge_code = self._generate_edge_code(edge, node_vars)
            if edge_code:
                lines.append(f'    {edge_code}')

        return "\n".join(lines)

    def _collect_imports(self) -> Set[str]:
        """Collect all required imports based on icons used.

        Returns:
            Set of import statements
        """
        imports = set()

        for node in self.nodes:
            imp = self._get_import_statement(node.icon)
            if imp:
                imports.add(imp)

        return imports

    def _get_import_statement(self, icon: str) -> Optional[str]:
        """Get import statement for an icon.

        Args:
            icon: Icon path like "aws.compute.EC2" or shorthand "aws:EC2"

        Returns:
            Import statement string or None
        """
        # Normalize icon path
        normalized = self._normalize_icon_path(icon)
        if not normalized:
            return None

        parts = normalized.split(".")
        if len(parts) >= 3:
            provider = parts[0]
            category = parts[1]
            class_name = parts[2]
            return f"from diagrams.{provider}.{category} import {class_name}"

        return None

    def _normalize_icon_path(self, icon: str) -> Optional[str]:
        """Normalize icon path to full format.

        Converts shorthand like "aws:EC2" to "aws.compute.EC2".

        Args:
            icon: Icon path or shorthand

        Returns:
            Normalized icon path or None
        """
        if not icon:
            return None

        # Already in full format
        if icon.count(".") >= 2:
            return icon

        # Shorthand format: "provider:IconName"
        if ":" in icon:
            provider, icon_name = icon.split(":", 1)
            # Try to find the icon in provider's modules
            found = self._find_icon_in_provider(provider, icon_name)
            if found:
                return found

        # Try generic as fallback
        if "." not in icon and ":" not in icon:
            return f"generic.blank.Blank"

        return icon

    def _find_icon_in_provider(self, provider: str, icon_name: str) -> Optional[str]:
        """Find icon in provider's modules.

        Args:
            provider: Provider name
            icon_name: Icon class name

        Returns:
            Full icon path or None
        """
        try:
            provider_module = importlib.import_module(f"diagrams.{provider}")
            for importer, modname, ispkg in pkgutil.iter_modules(provider_module.__path__):
                try:
                    submodule = importlib.import_module(f"diagrams.{provider}.{modname}")
                    if hasattr(submodule, icon_name):
                        return f"{provider}.{modname}.{icon_name}"
                except ImportError:
                    continue
        except ImportError:
            pass
        return None

    def _get_icon_class_name(self, icon: str) -> str:
        """Extract class name from icon path.

        Args:
            icon: Icon path

        Returns:
            Class name for use in code
        """
        if ":" in icon:
            return icon.split(":")[1]
        if "." in icon:
            return icon.split(".")[-1]
        return icon

    def _safe_var_name(self, node_id: str) -> str:
        """Create a safe Python variable name from node ID.

        Args:
            node_id: Original node ID

        Returns:
            Safe variable name
        """
        # Replace non-alphanumeric with underscore
        safe = re.sub(r'[^a-zA-Z0-9]', '_', node_id)
        # Ensure doesn't start with number
        if safe and safe[0].isdigit():
            safe = 'n_' + safe
        # Ensure not empty
        return safe or 'node'

    def _generate_edge_code(
        self,
        edge: CloudEdge,
        node_vars: Dict[str, str]
    ) -> Optional[str]:
        """Generate Python code for an edge.

        Args:
            edge: Edge definition
            node_vars: Mapping of node IDs to variable names

        Returns:
            Python code string or None
        """
        # Handle single or multiple sources/targets
        from_ids = edge.from_id if isinstance(edge.from_id, list) else [edge.from_id]
        to_ids = edge.to_id if isinstance(edge.to_id, list) else [edge.to_id]

        # Map to variable names
        from_vars = [node_vars.get(f) for f in from_ids if f in node_vars]
        to_vars = [node_vars.get(t) for t in to_ids if t in node_vars]

        if not from_vars or not to_vars:
            logger.warning(f"Edge references unknown nodes: {edge.from_id} -> {edge.to_id}")
            return None

        # Format source
        if len(from_vars) == 1:
            source = from_vars[0]
        else:
            source = f"[{', '.join(from_vars)}]"

        # Format target
        if len(to_vars) == 1:
            target = to_vars[0]
        else:
            target = f"[{', '.join(to_vars)}]"

        # Build edge with optional label/style
        # SECURITY: Use _escape_python_string to prevent code injection
        if edge.label or edge.color or edge.style:
            edge_params = []
            if edge.label:
                label_escaped = _escape_python_string(edge.label)
                edge_params.append(f'label="{label_escaped}"')
            if edge.color:
                color_escaped = _escape_python_string(edge.color)
                edge_params.append(f'color="{color_escaped}"')
            if edge.style:
                style_escaped = _escape_python_string(edge.style)
                edge_params.append(f'style="{style_escaped}"')

            edge_str = f"Edge({', '.join(edge_params)})"
            return f"{source} >> {edge_str} >> {target}"
        else:
            return f"{source} >> {target}"

    # =========================================================================
    # Code Generation
    # =========================================================================

    def to_python_code(self) -> str:
        """Generate Python Diagrams code from configuration.

        Returns:
            Python code string that can be executed or saved

        Raises:
            ValidationError: If not loaded
        """
        if not self._loaded:
            raise ValidationError("No configuration loaded. Call load() first.")

        return self._generate_executable_code(
            output="diagram",
            format=self.config.outformat,
            show=self.config.show
        )

    def save_python(self, output: str) -> str:
        """Save generated Python code to file.

        Args:
            output: Output file path (with or without .py extension)

        Returns:
            Path to saved file

        Raises:
            ValidationError: If not loaded
        """
        if not self._loaded:
            raise ValidationError("No configuration loaded. Call load() first.")

        path = Path(output)
        if path.suffix != ".py":
            path = path.with_suffix(".py")

        code = self.to_python_code()
        path.write_text(code, encoding="utf-8")

        logger.info(f"Saved Python Diagrams code to {path}")
        return str(path)

    # =========================================================================
    # Icon Discovery
    # =========================================================================

    @classmethod
    def list_providers(cls) -> List[Dict[str, str]]:
        """List available cloud providers.

        Returns:
            List of provider dictionaries with id and name
        """
        return [
            {"id": pid, "name": pname}
            for pid, pname in cls.PROVIDERS.items()
        ]

    @classmethod
    def list_categories(cls, provider: str) -> List[str]:
        """List icon categories for a provider.

        Args:
            provider: Provider ID (aws, azure, gcp, etc.)

        Returns:
            List of category names
        """
        try:
            provider_module = importlib.import_module(f"diagrams.{provider}")
            categories = []
            for importer, modname, ispkg in pkgutil.iter_modules(provider_module.__path__):
                if not modname.startswith("_"):
                    categories.append(modname)
            return sorted(categories)
        except ImportError:
            logger.warning(f"Provider not found: {provider}")
            return []

    @classmethod
    def list_icons(
        cls,
        provider: str,
        category: str = None
    ) -> List[Dict[str, str]]:
        """List available icons.

        Args:
            provider: Provider ID
            category: Optional category filter

        Returns:
            List of icon dictionaries with id, path, name, category, provider
        """
        # Check cache
        cache_key = f"{provider}:{category or 'all'}"
        if cache_key in cls._icon_cache:
            return cls._icon_cache[cache_key]

        icons = []
        categories = [category] if category else cls.list_categories(provider)

        for cat in categories:
            try:
                module = importlib.import_module(f"diagrams.{provider}.{cat}")
                for name in dir(module):
                    if not name.startswith("_"):
                        obj = getattr(module, name)
                        # Check if it's a diagrams node class
                        if isinstance(obj, type) and name[0].isupper():
                            icons.append({
                                "id": name,
                                "path": f"{provider}.{cat}.{name}",
                                "name": name,
                                "category": cat,
                                "provider": provider,
                            })
            except ImportError:
                continue

        # Cache results
        cls._icon_cache[cache_key] = icons
        return icons

    @classmethod
    def search_icons(cls, query: str, limit: int = 50) -> List[Dict[str, str]]:
        """Search icons by name across all providers.

        Args:
            query: Search query (case-insensitive)
            limit: Maximum results to return

        Returns:
            List of matching icon dictionaries
        """
        query_lower = query.lower()
        results = []

        for provider in cls.PROVIDERS.keys():
            try:
                icons = cls.list_icons(provider)
                for icon in icons:
                    if query_lower in icon["name"].lower():
                        results.append(icon)
                        if len(results) >= limit:
                            return results
            except Exception:
                continue

        return results

    # =========================================================================
    # Validation
    # =========================================================================

    def validate(self) -> List[str]:
        """Validate configuration.

        Checks:
        - All icon paths are valid
        - All edge references exist
        - Direction is valid

        Returns:
            List of error messages (empty if valid)
        """
        errors = []

        if not self._loaded:
            return ["No configuration loaded"]

        # Check direction
        if self.config.direction not in self.DIRECTIONS:
            errors.append(
                f"Invalid direction: {self.config.direction}. "
                f"Must be one of: {self.DIRECTIONS}"
            )

        # Check icon paths
        for node in self.nodes:
            if not self._validate_icon(node.icon):
                errors.append(f"Invalid or unknown icon: {node.icon} (node: {node.id})")

        # Check edge references
        node_ids = {n.id for n in self.nodes}
        for i, edge in enumerate(self.edges):
            from_ids = edge.from_id if isinstance(edge.from_id, list) else [edge.from_id]
            to_ids = edge.to_id if isinstance(edge.to_id, list) else [edge.to_id]

            for fid in from_ids:
                if fid not in node_ids:
                    errors.append(f"Edge {i} references unknown source node: {fid}")
            for tid in to_ids:
                if tid not in node_ids:
                    errors.append(f"Edge {i} references unknown target node: {tid}")

        return errors

    def _validate_icon(self, icon: str) -> bool:
        """Validate that an icon exists.

        Args:
            icon: Icon path

        Returns:
            True if valid
        """
        normalized = self._normalize_icon_path(icon)
        if not normalized:
            return False

        parts = normalized.split(".")
        if len(parts) < 3:
            return False

        try:
            module = importlib.import_module(f"diagrams.{parts[0]}.{parts[1]}")
            return hasattr(module, parts[2])
        except ImportError:
            return False

    def get_stats(self) -> Dict[str, Any]:
        """Get diagram statistics.

        Returns:
            Dictionary with diagram statistics
        """
        providers_used = set()
        for node in self.nodes:
            normalized = self._normalize_icon_path(node.icon)
            if normalized:
                parts = normalized.split(".")
                if parts:
                    providers_used.add(parts[0])

        return {
            "title": self.config.title,
            "total_nodes": len(self.nodes),
            "total_edges": len(self.edges),
            "total_clusters": len(self.clusters),
            "providers_used": list(providers_used),
            "direction": self.config.direction,
        }

    # =========================================================================
    # Conversion FROM other formats
    # =========================================================================

    @classmethod
    def from_attack_tree(cls, config_path: str) -> "CloudDiagrams":
        """Convert attack tree to cloud diagram.

        Mapping:
        - Root node → onprem.security.Vault
        - AND/OR gates → generic.blank.Blank
        - Leaf nodes → generic.compute.Rack

        Args:
            config_path: Path to attack tree config

        Returns:
            CloudDiagrams instance
        """
        from .attacktrees import AttackTrees

        at = AttackTrees(config_path, "temp", validate_paths=False)
        at.load()

        cd = cls(validate_diagrams=False)
        cd.config.title = at.inputdata.get("tree", {}).get("name", "Attack Tree")
        cd.config.direction = "TB"

        # Convert nodes
        nodes_data = at.inputdata.get("nodes", {})
        root_id = at.inputdata.get("tree", {}).get("root", "")

        for node_id, node_data in nodes_data.items():
            if isinstance(node_data, str):
                label = node_data
                gate = ""
            else:
                label = node_data.get("label", node_id)
                gate = node_data.get("gate", "")

            # Determine icon based on node type
            if node_id == root_id:
                icon = "onprem.security.Vault"
            elif gate:
                icon = "generic.blank.Blank"
            else:
                icon = "generic.compute.Rack"

            cd.nodes.append(CloudNode(
                id=node_id,
                icon=icon,
                label=label
            ))

        # Convert edges
        edges_data = at.inputdata.get("edges", {})
        for source, targets in edges_data.items():
            if isinstance(targets, list):
                for target in targets:
                    if isinstance(target, str):
                        cd.edges.append(CloudEdge(from_id=source, to_id=target))
                    elif isinstance(target, dict):
                        cd.edges.append(CloudEdge(
                            from_id=source,
                            to_id=target.get("to", ""),
                            label=target.get("label", "")
                        ))

        cd._loaded = True
        return cd

    @classmethod
    def from_attack_graph(cls, config_path: str) -> "CloudDiagrams":
        """Convert attack graph to cloud diagram.

        Mapping:
        - Hosts → onprem.compute.Server
        - Vulnerabilities → generic.os.Suse (red-ish)
        - Services → generic.network.Switch
        - Privileges → generic.storage.Storage

        Args:
            config_path: Path to attack graph config

        Returns:
            CloudDiagrams instance
        """
        from .attackgraphs import AttackGraphs

        ag = AttackGraphs(config_path, "temp", validate_paths=False)
        ag.load()

        cd = cls(validate_diagrams=False)
        cd.config.title = ag.inputdata.get("graph", {}).get("name", "Attack Graph")
        cd.config.direction = "LR"

        # Convert hosts
        for host_id, host_data in ag.inputdata.get("hosts", {}).items():
            cd.nodes.append(CloudNode(
                id=host_id,
                icon="onprem.compute.Server",
                label=host_data.get("label", host_id)
            ))

        # Convert vulnerabilities
        for vuln_id, vuln_data in ag.inputdata.get("vulnerabilities", {}).items():
            label = vuln_data.get("label", vuln_id)
            cvss = vuln_data.get("cvss", "")
            if cvss:
                label = f"{label} ({cvss})"

            cd.nodes.append(CloudNode(
                id=vuln_id,
                icon="generic.os.Suse",
                label=label
            ))

            # Edge to affected host
            host = vuln_data.get("host")
            if host:
                cd.edges.append(CloudEdge(
                    from_id=vuln_id,
                    to_id=host,
                    label="affects"
                ))

        # Convert services
        for svc_id, svc_data in ag.inputdata.get("services", {}).items():
            cd.nodes.append(CloudNode(
                id=svc_id,
                icon="generic.network.Switch",
                label=svc_data.get("label", svc_id)
            ))

        # Convert privileges
        for priv_id, priv_data in ag.inputdata.get("privileges", {}).items():
            cd.nodes.append(CloudNode(
                id=priv_id,
                icon="generic.storage.Storage",
                label=priv_data.get("label", priv_id)
            ))

        # Convert network edges
        for source, targets in ag.inputdata.get("network", {}).items():
            if isinstance(targets, list):
                for target in targets:
                    cd.edges.append(CloudEdge(
                        from_id=source,
                        to_id=target,
                        style="dashed"
                    ))

        cd._loaded = True
        return cd

    @classmethod
    def from_threat_model(cls, config_path: str) -> "CloudDiagrams":
        """Convert threat model DFD to cloud diagram.

        Mapping:
        - Processes → generic.compute.Rack
        - Data stores → generic.storage.Storage
        - External entities → generic.device.Mobile
        - Trust boundaries → Clusters

        Args:
            config_path: Path to threat model config

        Returns:
            CloudDiagrams instance
        """
        from .threatmodeling import ThreatModeling

        tm = ThreatModeling(config_path, "temp", validate_paths=False)
        tm.load()

        cd = cls(validate_diagrams=False)
        cd.config.title = tm.inputdata.get("model", {}).get("name", "Threat Model")
        cd.config.direction = "LR"

        # Track node to boundary mapping
        node_to_boundary: Dict[str, str] = {}
        for boundary_id, boundary_data in tm.inputdata.get("boundaries", {}).items():
            for elem in boundary_data.get("elements", []):
                node_to_boundary[elem] = boundary_id

        # Convert processes
        for proc_id, proc_data in tm.inputdata.get("processes", {}).items():
            cd.nodes.append(CloudNode(
                id=proc_id,
                icon="generic.compute.Rack",
                label=proc_data.get("label", proc_id),
                cluster_id=node_to_boundary.get(proc_id)
            ))

        # Convert data stores
        for ds_id, ds_data in tm.inputdata.get("datastores", {}).items():
            cd.nodes.append(CloudNode(
                id=ds_id,
                icon="generic.storage.Storage",
                label=ds_data.get("label", ds_id),
                cluster_id=node_to_boundary.get(ds_id)
            ))

        # Convert external entities
        for ext_id, ext_data in tm.inputdata.get("externals", {}).items():
            cd.nodes.append(CloudNode(
                id=ext_id,
                icon="generic.device.Mobile",
                label=ext_data.get("label", ext_id),
                cluster_id=node_to_boundary.get(ext_id)
            ))

        # Create clusters from boundaries
        for boundary_id, boundary_data in tm.inputdata.get("boundaries", {}).items():
            cluster_nodes = [n for n in cd.nodes if n.cluster_id == boundary_id]
            if cluster_nodes:
                cd.clusters.append(CloudCluster(
                    id=boundary_id,
                    label=boundary_data.get("label", boundary_id),
                    nodes=cluster_nodes
                ))

        # Convert data flows
        for flow_id, flow_data in tm.inputdata.get("dataflows", {}).items():
            cd.edges.append(CloudEdge(
                from_id=flow_data.get("from", flow_data.get("source", "")),
                to_id=flow_data.get("to", flow_data.get("destination", "")),
                label=flow_data.get("label", flow_data.get("data", ""))
            ))

        cd._loaded = True
        return cd

    @classmethod
    def from_custom_diagram(cls, custom: "CustomDiagrams") -> "CloudDiagrams":
        """Convert CustomDiagrams to CloudDiagrams.

        Args:
            custom: CustomDiagrams instance

        Returns:
            CloudDiagrams instance
        """
        cd = cls(validate_diagrams=False)
        cd.config.title = custom.settings.title if custom.settings else "Custom Diagram"
        cd.config.direction = custom.settings.direction if custom.settings else "LR"

        # Map node types to icons
        type_to_icon = {
            "server": "onprem.compute.Server",
            "database": "generic.storage.Storage",
            "user": "generic.device.Mobile",
            "process": "generic.compute.Rack",
            "external": "generic.device.Tablet",
            "default": "generic.blank.Blank",
        }

        for node in custom.nodes:
            node_type = node.get("type", "default").lower()
            icon = type_to_icon.get(node_type, type_to_icon["default"])

            cd.nodes.append(CloudNode(
                id=node.get("id", ""),
                icon=icon,
                label=node.get("name", node.get("id", ""))
            ))

        for edge in custom.edges:
            cd.edges.append(CloudEdge(
                from_id=edge.get("from", ""),
                to_id=edge.get("to", ""),
                label=edge.get("label", "")
            ))

        # Convert clusters
        for cluster in custom.clusters:
            cluster_node_ids = cluster.get("nodes", [])
            cluster_nodes = [n for n in cd.nodes if n.id in cluster_node_ids]
            for n in cluster_nodes:
                n.cluster_id = cluster.get("id", "")

            cd.clusters.append(CloudCluster(
                id=cluster.get("id", ""),
                label=cluster.get("label", cluster.get("id", "")),
                nodes=cluster_nodes
            ))

        cd._loaded = True
        return cd

    # =========================================================================
    # Template Methods
    # =========================================================================

    @classmethod
    def get_templates_dir(cls) -> Path:
        """Get the path to the Cloud templates directory.

        Returns:
            Path to templates/cloud directory

        Raises:
            CloudDiagramError: If templates directory not found
        """
        # Try relative to this file first (development)
        module_dir = Path(__file__).parent.parent.parent.parent
        templates_dir = module_dir / "templates" / "cloud"
        if templates_dir.exists():
            return templates_dir

        # Try relative to working directory
        cwd_templates = Path.cwd() / "templates" / "cloud"
        if cwd_templates.exists():
            return cwd_templates

        raise CloudDiagramError(
            "Cloud templates directory not found. "
            "Expected at templates/cloud/"
        )

    @classmethod
    def list_templates(cls, category: Optional[str] = None) -> List[Dict[str, str]]:
        """List available cloud diagram templates.

        Args:
            category: Optional category filter (aws, azure, gcp, kubernetes, etc.)

        Returns:
            List of template info dictionaries
        """
        try:
            templates_dir = cls.get_templates_dir()
        except CloudDiagramError:
            return []

        templates = []

        if category:
            categories = [templates_dir / category]
        else:
            categories = [d for d in templates_dir.iterdir() if d.is_dir()]

        for category_dir in categories:
            if not category_dir.exists():
                continue

            for ext in (".toml", ".yaml", ".yml", ".json"):
                for template_file in category_dir.glob(f"*{ext}"):
                    templates.append({
                        "id": f"{category_dir.name}/{template_file.stem}",
                        "name": template_file.stem.replace("-", " ").title(),
                        "category": category_dir.name,
                        "path": str(template_file),
                    })

        return sorted(templates, key=lambda t: (t["category"], t["name"]))

    @classmethod
    def list_template_categories(cls) -> List[str]:
        """List available template categories.

        Returns:
            List of category names
        """
        try:
            templates_dir = cls.get_templates_dir()
        except CloudDiagramError:
            return []

        categories = []
        for item in templates_dir.iterdir():
            if item.is_dir() and not item.name.startswith("."):
                categories.append(item.name)

        return sorted(categories)

    @classmethod
    def from_template(cls, template_id: str) -> "CloudDiagrams":
        """Load from a built-in template.

        Args:
            template_id: Template identifier in format "category/name"

        Returns:
            CloudDiagrams instance

        Raises:
            CloudDiagramError: If template not found
        """
        templates_dir = cls.get_templates_dir()

        if "/" not in template_id:
            raise CloudDiagramError(
                f"Invalid template ID format: {template_id}. "
                "Expected format: category/name"
            )

        category, name = template_id.split("/", 1)

        # Try different extensions
        template_path = None
        for ext in (".toml", ".yaml", ".yml", ".json"):
            candidate = templates_dir / category / f"{name}{ext}"
            if candidate.exists():
                template_path = candidate
                break

        if not template_path:
            available = cls.list_templates(category)
            available_ids = [t["id"] for t in available]
            raise CloudDiagramError(
                f"Template not found: {template_id}. "
                f"Available in '{category}': {available_ids}"
            )

        instance = cls()
        instance.load(str(template_path))
        return instance

    # =========================================================================
    # Context Manager
    # =========================================================================

    def __enter__(self) -> "CloudDiagrams":
        """Enter context manager."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Exit context manager."""
        pass

    def __repr__(self) -> str:
        """Return string representation."""
        status = "loaded" if self._loaded else "empty"
        return (
            f"<CloudDiagrams({self.config.title!r}, {status}, "
            f"nodes={len(self.nodes)}, edges={len(self.edges)})>"
        )
