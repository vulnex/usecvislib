#
# VULNEX -Universal Security Visualization Library-
#
# File: mermaiddiagrams.py
# Author: Simon Roses Femerling
# Created: 2025-01-14
# Last Modified: 2025-01-14
# Version: 0.3.2
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""
Mermaid diagram rendering module.

Renders Mermaid syntax to images using mermaid-cli (mmdc).
Supports all Mermaid diagram types including flowcharts, sequence diagrams,
class diagrams, state diagrams, ER diagrams, Gantt charts, and more.

Requirements:
    - Node.js installed
    - mermaid-cli: npm install -g @mermaid-js/mermaid-cli

Example:
    >>> from usecvislib import MermaidDiagrams
    >>> md = MermaidDiagrams()
    >>> md.load_from_string('''
    ... flowchart TD
    ...     A[Start] --> B{Decision}
    ...     B -->|Yes| C[End]
    ... ''')
    >>> md.render("output", format="png")
"""

from typing import Dict, List, Any, Optional, Union
from pathlib import Path
from dataclasses import dataclass, field
import subprocess
import tempfile
import shutil
import logging
import re

from .utils import (
    ReadConfigFile,
    parse_content,
    ValidationError,
    RenderError,
    validate_output_path,
)


logger = logging.getLogger(__name__)


class MermaidError(RenderError):
    """Mermaid-specific error."""
    pass


class MermaidCLINotFoundError(MermaidError):
    """Raised when mermaid-cli is not installed."""
    pass


class MermaidSyntaxError(MermaidError):
    """Raised when Mermaid syntax is invalid."""
    pass


@dataclass
class MermaidConfig:
    """Mermaid diagram configuration.

    Attributes:
        title: Diagram title (for metadata)
        theme: Mermaid theme (default, dark, forest, neutral, base)
        background: Background color (white, transparent, or hex color)
        width: Output image width in pixels
        height: Output image height in pixels
        source: Raw Mermaid syntax
    """
    title: str = ""
    theme: str = "default"
    background: str = "white"
    width: int = 800
    height: int = 600
    source: str = ""

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "MermaidConfig":
        """Create MermaidConfig from dictionary.

        Args:
            data: Configuration dictionary with optional 'mermaid' key

        Returns:
            MermaidConfig instance
        """
        mermaid_section = data.get("mermaid", data)
        return cls(
            title=mermaid_section.get("title", ""),
            theme=mermaid_section.get("theme", "default"),
            background=mermaid_section.get("background", "white"),
            width=int(mermaid_section.get("width", 800)),
            height=int(mermaid_section.get("height", 600)),
            source=mermaid_section.get("source", ""),
        )


@dataclass
class MermaidResult:
    """Result of a Mermaid rendering operation.

    Attributes:
        output_path: Path to the generated output file
        format: Output format (png, svg, pdf)
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


class MermaidDiagrams:
    """Render Mermaid diagrams via mermaid-cli.

    Supports all Mermaid diagram types including flowcharts, sequence diagrams,
    class diagrams, state diagrams, ER diagrams, Gantt charts, and more.

    The class can load Mermaid content from:
    - Raw .mmd/.mermaid files
    - TOML/YAML/JSON configuration wrappers
    - String content directly

    Attributes:
        config: MermaidConfig with diagram settings
        source: Raw Mermaid syntax
        diagram_type: Detected diagram type

    Example:
        >>> md = MermaidDiagrams()
        >>> md.load("diagram.mmd")
        >>> result = md.render("output", format="png")

        >>> # Or from config file
        >>> md = MermaidDiagrams()
        >>> md.load("diagram.toml")
        >>> result = md.render("output", format="svg", theme="dark")

        >>> # Or from string
        >>> md = MermaidDiagrams()
        >>> md.load_from_string("flowchart TD\\n    A --> B")
        >>> result = md.render("output")
    """

    # All supported Mermaid diagram types
    SUPPORTED_TYPES = [
        # Flow diagrams
        "flowchart",
        "graph",
        # Sequence & interaction
        "sequenceDiagram",
        "zenuml",
        # Structure
        "classDiagram",
        "erDiagram",
        "stateDiagram",
        "stateDiagram-v2",
        # Project management
        "gantt",
        "timeline",
        "journey",
        # Charts
        "pie",
        "quadrantChart",
        "xychart-beta",
        "sankey-beta",
        # Other
        "requirementDiagram",
        "gitGraph",
        "mindmap",
        "block-beta",
        "packet-beta",
        "kanban",
        "architecture-beta",
        "c4Context",
        "c4Container",
        "c4Component",
        "c4Dynamic",
        "c4Deployment",
    ]

    # Supported output formats
    OUTPUT_FORMATS = {"png", "svg", "pdf"}

    # Available themes
    THEMES = ["default", "dark", "forest", "neutral", "base"]

    # Allowed input file extensions
    ALLOWED_EXTENSIONS = [".mmd", ".mermaid", ".toml", ".tml", ".json", ".yaml", ".yml"]

    def __init__(self, theme: str = "default", validate_cli: bool = True):
        """Initialize MermaidDiagrams.

        Args:
            theme: Default Mermaid theme (default, dark, forest, neutral, base)
            validate_cli: Whether to validate mermaid-cli availability on init

        Raises:
            MermaidCLINotFoundError: If mermaid-cli is not installed and validate_cli=True
        """
        self.config = MermaidConfig(theme=theme)
        self.source: str = ""
        self.diagram_type: str = ""
        self._config_path: Optional[Path] = None
        self._loaded = False
        self._cli_validated = False

        if validate_cli:
            self._validate_cli_available()

    def _validate_cli_available(self) -> None:
        """Check if mermaid-cli (mmdc) is installed.

        Raises:
            MermaidCLINotFoundError: If mmdc is not found or not working
        """
        if self._cli_validated:
            return

        # Check if mmdc is in PATH
        mmdc_path = shutil.which("mmdc")
        if not mmdc_path:
            raise MermaidCLINotFoundError(
                "mermaid-cli (mmdc) not found in PATH. "
                "Install with: npm install -g @mermaid-js/mermaid-cli"
            )

        try:
            result = subprocess.run(
                ["mmdc", "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode != 0:
                raise MermaidCLINotFoundError(
                    f"mermaid-cli check failed: {result.stderr or result.stdout}"
                )
            version = result.stdout.strip()
            logger.debug(f"mermaid-cli version: {version}")
            self._cli_validated = True
        except subprocess.TimeoutExpired:
            raise MermaidCLINotFoundError("mermaid-cli version check timed out")
        except FileNotFoundError:
            raise MermaidCLINotFoundError(
                "mermaid-cli (mmdc) not found. "
                "Install with: npm install -g @mermaid-js/mermaid-cli"
            )

    def _get_puppeteer_config(self) -> Optional[str]:
        """Get path to puppeteer config file if available.

        The config file is needed for Docker/sandbox environments where
        Chromium requires --no-sandbox flag.

        Returns:
            Path to puppeteer config file, or None if not found
        """
        # Check common locations for puppeteer-config.json
        search_paths = [
            # Docker container location
            Path("/app/puppeteer-config.json"),
            # Working directory
            Path.cwd() / "puppeteer-config.json",
            # Module parent directory (development)
            Path(__file__).parent.parent.parent.parent / "puppeteer-config.json",
        ]

        for config_path in search_paths:
            if config_path.exists():
                logger.debug(f"Using puppeteer config: {config_path}")
                return str(config_path)

        return None

    # =========================================================================
    # Input Methods
    # =========================================================================

    def load(self, filepath: str) -> "MermaidDiagrams":
        """Load Mermaid from file.

        Supports:
        - .mmd / .mermaid files (raw Mermaid syntax)
        - .toml / .yaml / .json files (config wrapper with 'mermaid' section)

        Args:
            filepath: Path to input file

        Returns:
            Self for method chaining

        Raises:
            FileNotFoundError: If file doesn't exist
            ValidationError: If file format is invalid
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

        if suffix in (".mmd", ".mermaid"):
            # Raw Mermaid file
            self.source = path.read_text(encoding="utf-8")
        else:
            # Config wrapper (TOML/YAML/JSON)
            config_data = ReadConfigFile(str(path))
            self.config = MermaidConfig.from_dict(config_data)
            self.source = self.config.source

        if not self.source.strip():
            raise ValidationError("Mermaid source is empty")

        self.diagram_type = self._detect_type()
        self._loaded = True

        logger.info(f"Loaded Mermaid diagram from {path} (type: {self.diagram_type})")
        return self

    def load_from_string(
        self,
        content: str,
        format: str = "mermaid"
    ) -> "MermaidDiagrams":
        """Load from string content.

        Args:
            content: Diagram content
            format: Content format - "mermaid", "toml", "yaml", "json"

        Returns:
            Self for method chaining

        Raises:
            ValidationError: If content is empty or invalid
        """
        if not content.strip():
            raise ValidationError("Content is empty")

        if format == "mermaid":
            self.source = content
        elif format in ("toml", "yaml", "json"):
            config_data = parse_content(content, format)
            self.config = MermaidConfig.from_dict(config_data)
            self.source = self.config.source
        else:
            raise ValidationError(
                f"Unsupported format: {format}. "
                "Supported: mermaid, toml, yaml, json"
            )

        if not self.source.strip():
            raise ValidationError("Mermaid source is empty")

        self.diagram_type = self._detect_type()
        self._loaded = True

        logger.info(f"Loaded Mermaid diagram from string (type: {self.diagram_type})")
        return self

    # =========================================================================
    # Rendering
    # =========================================================================

    def render(
        self,
        output: str,
        format: str = "png",
        width: Optional[int] = None,
        height: Optional[int] = None,
        theme: Optional[str] = None,
        background: Optional[str] = None,
    ) -> MermaidResult:
        """Render diagram to image file.

        Args:
            output: Output file path (without extension)
            format: Output format (png, svg, pdf)
            width: Image width in pixels (overrides config)
            height: Image height in pixels (overrides config)
            theme: Mermaid theme (overrides config)
            background: Background color (overrides config)

        Returns:
            MermaidResult with output path and stats

        Raises:
            ValidationError: If no source loaded or invalid format
            MermaidError: If rendering fails
            MermaidCLINotFoundError: If mmdc not found
        """
        # Ensure CLI is available
        self._validate_cli_available()

        if not self._loaded or not self.source:
            raise ValidationError("No Mermaid source loaded. Call load() first.")

        if format not in self.OUTPUT_FORMATS:
            raise ValidationError(
                f"Unsupported format: {format}. Supported: {self.OUTPUT_FORMATS}"
            )

        # Resolve parameters (explicit > config > defaults)
        w = width if width is not None else self.config.width
        h = height if height is not None else self.config.height
        t = theme if theme is not None else self.config.theme
        bg = background if background is not None else self.config.background

        # Validate theme
        if t not in self.THEMES:
            logger.warning(f"Unknown theme '{t}', using 'default'")
            t = "default"

        # Validate output path
        output_path_obj = validate_output_path(output)
        output_file = f"{output_path_obj}.{format}"

        # Create temp input file
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".mmd",
            delete=False,
            encoding="utf-8"
        ) as f:
            f.write(self.source)
            input_path = f.name

        try:
            # Build mmdc command
            cmd = [
                "mmdc",
                "-i", input_path,
                "-o", output_file,
                "-t", t,
                "-w", str(w),
                "-H", str(h),
                "-b", bg,
            ]

            # Add puppeteer config if available (for Docker/sandbox environments)
            puppeteer_config = self._get_puppeteer_config()
            if puppeteer_config:
                cmd.extend(["-p", puppeteer_config])

            logger.debug(f"Running: {' '.join(cmd)}")

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )

            if result.returncode != 0:
                error_msg = result.stderr or result.stdout or "Unknown error"
                # Check for common syntax errors
                if "Parse error" in error_msg or "Syntax error" in error_msg:
                    raise MermaidSyntaxError(f"Mermaid syntax error: {error_msg}")
                raise MermaidError(f"mermaid-cli failed: {error_msg}")

            # Verify output was created
            if not Path(output_file).exists():
                raise MermaidError(f"Output file was not created: {output_file}")

            logger.info(f"Rendered Mermaid diagram to {output_file}")

            return MermaidResult(
                output_path=output_file,
                format=format,
                stats=self.get_stats(),
                success=True
            )

        except subprocess.TimeoutExpired:
            raise MermaidError("mermaid-cli rendering timed out (120s limit)")

        finally:
            # Cleanup temp file
            try:
                Path(input_path).unlink(missing_ok=True)
            except Exception as e:
                logger.warning(f"Failed to cleanup temp file: {e}")

    def get_svg(self) -> str:
        """Get SVG string without saving to file.

        Useful for embedding diagrams directly in web pages.

        Returns:
            SVG content as string

        Raises:
            ValidationError: If no source loaded
            MermaidError: If rendering fails
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "diagram"
            self.render(str(output), format="svg")
            svg_path = output.with_suffix(".svg")
            return svg_path.read_text(encoding="utf-8")

    # =========================================================================
    # Validation & Info
    # =========================================================================

    def validate(self) -> List[str]:
        """Validate Mermaid syntax.

        Performs a dry-run render to check for syntax errors.

        Returns:
            List of error messages (empty if valid)
        """
        if not self.source:
            return ["No Mermaid source loaded"]

        errors = []

        # Ensure CLI is available
        try:
            self._validate_cli_available()
        except MermaidCLINotFoundError as e:
            return [str(e)]

        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = Path(tmpdir) / "test.mmd"
            output_path = Path(tmpdir) / "test.svg"

            input_path.write_text(self.source, encoding="utf-8")

            try:
                cmd = ["mmdc", "-i", str(input_path), "-o", str(output_path)]

                # Add puppeteer config if available (for Docker/sandbox environments)
                puppeteer_config = self._get_puppeteer_config()
                if puppeteer_config:
                    cmd.extend(["-p", puppeteer_config])

                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=30
                )

                if result.returncode != 0:
                    error_msg = result.stderr or result.stdout or "Unknown validation error"
                    errors.append(error_msg.strip())

            except subprocess.TimeoutExpired:
                errors.append("Validation timed out")
            except Exception as e:
                errors.append(f"Validation failed: {str(e)}")

        return errors

    def _detect_type(self) -> str:
        """Detect diagram type from source.

        Returns:
            Detected diagram type or "unknown"
        """
        if not self.source:
            return "unknown"

        # Get first non-empty, non-comment line
        for line in self.source.strip().split("\n"):
            line = line.strip()
            if line and not line.startswith("%%"):
                first_line = line.lower()
                break
        else:
            return "unknown"

        # Check for each supported type
        for dtype in self.SUPPORTED_TYPES:
            if first_line.startswith(dtype.lower()):
                return dtype

        # 'graph' is alias for flowchart
        if first_line.startswith("graph "):
            return "flowchart"

        return "unknown"

    def get_stats(self) -> Dict[str, Any]:
        """Get diagram statistics.

        Returns:
            Dictionary with diagram statistics
        """
        lines = self.source.split("\n") if self.source else []
        non_empty_lines = [l for l in lines if l.strip() and not l.strip().startswith("%%")]

        return {
            "title": self.config.title,
            "diagram_type": self.diagram_type,
            "theme": self.config.theme,
            "line_count": len(lines),
            "non_empty_lines": len(non_empty_lines),
            "char_count": len(self.source),
            "width": self.config.width,
            "height": self.config.height,
        }

    # =========================================================================
    # Export
    # =========================================================================

    def get_source(self) -> str:
        """Get raw Mermaid syntax.

        Returns:
            Mermaid source string
        """
        return self.source

    def save_mmd(self, output: str) -> str:
        """Save Mermaid source to .mmd file.

        Args:
            output: Output file path (with or without .mmd extension)

        Returns:
            Path to saved file

        Raises:
            ValidationError: If no source loaded
        """
        if not self.source:
            raise ValidationError("No Mermaid source to save")

        path = Path(output)
        if path.suffix.lower() not in (".mmd", ".mermaid"):
            path = path.with_suffix(".mmd")

        # Validate output path
        validated_path = validate_output_path(str(path.with_suffix("")))
        final_path = Path(str(validated_path) + path.suffix)

        final_path.write_text(self.source, encoding="utf-8")
        logger.info(f"Saved Mermaid source to {final_path}")
        return str(final_path)

    # =========================================================================
    # Conversion FROM other formats
    # =========================================================================

    @classmethod
    def from_attack_tree(cls, config_path: str, **kwargs) -> "MermaidDiagrams":
        """Create from attack tree configuration.

        Uses existing mermaid.py serialization to convert attack tree
        to Mermaid flowchart syntax.

        Args:
            config_path: Path to attack tree config file
            **kwargs: Additional arguments passed to __init__

        Returns:
            MermaidDiagrams instance with loaded content
        """
        from .mermaid import serialize_to_mermaid

        config = ReadConfigFile(config_path)
        mermaid_source = serialize_to_mermaid(config)

        instance = cls(**kwargs)
        instance.load_from_string(mermaid_source, format="mermaid")
        instance.config.title = config.get("tree", {}).get("name", "Attack Tree")
        return instance

    @classmethod
    def from_attack_graph(cls, config_path: str, **kwargs) -> "MermaidDiagrams":
        """Create from attack graph configuration.

        Args:
            config_path: Path to attack graph config file
            **kwargs: Additional arguments passed to __init__

        Returns:
            MermaidDiagrams instance with loaded content
        """
        from .mermaid import serialize_to_mermaid

        config = ReadConfigFile(config_path)
        mermaid_source = serialize_to_mermaid(config)

        instance = cls(**kwargs)
        instance.load_from_string(mermaid_source, format="mermaid")
        instance.config.title = config.get("graph", {}).get("name", "Attack Graph")
        return instance

    @classmethod
    def from_threat_model(cls, config_path: str, **kwargs) -> "MermaidDiagrams":
        """Create from threat model configuration.

        Args:
            config_path: Path to threat model config file
            **kwargs: Additional arguments passed to __init__

        Returns:
            MermaidDiagrams instance with loaded content
        """
        from .mermaid import serialize_to_mermaid

        config = ReadConfigFile(config_path)
        mermaid_source = serialize_to_mermaid(config)

        instance = cls(**kwargs)
        instance.load_from_string(mermaid_source, format="mermaid")
        instance.config.title = config.get("model", {}).get("name", "Threat Model")
        return instance

    @classmethod
    def from_custom_diagram(
        cls,
        custom_diagram: "CustomDiagrams",
        **kwargs
    ) -> "MermaidDiagrams":
        """Create from CustomDiagrams instance.

        Converts CustomDiagrams to Mermaid flowchart syntax.

        Args:
            custom_diagram: CustomDiagrams instance
            **kwargs: Additional arguments passed to __init__

        Returns:
            MermaidDiagrams instance with loaded content
        """
        # Import here to avoid circular imports
        from .customdiagrams import CustomDiagrams

        if not isinstance(custom_diagram, CustomDiagrams):
            raise ValidationError("Expected CustomDiagrams instance")

        # Build Mermaid flowchart from CustomDiagrams
        direction = custom_diagram.settings.direction if custom_diagram.settings else "TD"
        lines = [f"flowchart {direction}"]

        # Add title as comment
        if custom_diagram.settings and custom_diagram.settings.title:
            lines.append(f"    %% {custom_diagram.settings.title}")
            lines.append("")

        # Add nodes
        for node in custom_diagram.nodes:
            node_id = _sanitize_mermaid_id(node.get("id", ""))
            label = node.get("name", node.get("label", node_id))
            label = _escape_mermaid_label(label)

            node_type = node.get("type", "")

            # Determine shape based on type
            if "diamond" in node_type.lower() or "decision" in node_type.lower():
                lines.append(f'    {node_id}{{{label}}}')
            elif "circle" in node_type.lower() or "process" in node_type.lower():
                lines.append(f'    {node_id}(({label}))')
            elif "database" in node_type.lower() or "datastore" in node_type.lower():
                lines.append(f'    {node_id}[({label})]')
            else:
                lines.append(f'    {node_id}["{label}"]')

        lines.append("")

        # Add edges
        for edge in custom_diagram.edges:
            from_id = _sanitize_mermaid_id(edge.get("from", ""))
            to_id = _sanitize_mermaid_id(edge.get("to", ""))
            label = edge.get("label", "")

            if label:
                label = _escape_mermaid_label(label)
                lines.append(f"    {from_id} -->|{label}| {to_id}")
            else:
                lines.append(f"    {from_id} --> {to_id}")

        mermaid_source = "\n".join(lines)

        instance = cls(**kwargs)
        instance.load_from_string(mermaid_source, format="mermaid")
        if custom_diagram.settings:
            instance.config.title = custom_diagram.settings.title
        return instance

    # =========================================================================
    # Conversion TO other formats
    # =========================================================================

    def to_custom_diagram(self) -> "CustomDiagrams":
        """Convert to CustomDiagrams format.

        Note: Only works for flowchart/graph diagram types.
        Other types will raise an error.

        Returns:
            CustomDiagrams instance

        Raises:
            MermaidError: If diagram type cannot be converted
            ValidationError: If no source loaded
        """
        from .customdiagrams import CustomDiagrams, DiagramSettings

        if not self._loaded:
            raise ValidationError("No Mermaid source loaded")

        if self.diagram_type not in ("flowchart", "graph", "unknown"):
            raise MermaidError(
                f"Cannot convert {self.diagram_type} to CustomDiagrams. "
                "Only flowchart/graph types are supported."
            )

        cd = CustomDiagrams()

        # Parse direction from first line
        direction = "TD"
        first_line = self.source.strip().split("\n")[0]
        direction_match = re.search(r'(flowchart|graph)\s+(TD|TB|BT|LR|RL)', first_line, re.IGNORECASE)
        if direction_match:
            direction = direction_match.group(2).upper()

        cd.settings = DiagramSettings(
            title=self.config.title or "Converted Diagram",
            direction=direction,
        )

        # Simple parsing of nodes and edges
        # This is a basic implementation - full Mermaid parsing is complex
        nodes_found = {}
        edges = []

        for line in self.source.split("\n"):
            line = line.strip()
            if not line or line.startswith("%%") or line.startswith("flowchart") or line.startswith("graph"):
                continue

            # Match node definitions: id[label] or id["label"] or id{label} etc.
            node_match = re.match(
                r'^(\w+)\s*[\[\(\{<][\[\(\{"\']*([^\]\)\}>"\']+)[\]\)\}>"\']*[\]\)\}>]?\s*$',
                line
            )
            if node_match:
                node_id = node_match.group(1)
                label = node_match.group(2)
                nodes_found[node_id] = {"id": node_id, "name": label, "type": "default"}
                continue

            # Match edges: A --> B or A -->|label| B
            edge_match = re.match(
                r'^(\w+)\s*(-+>+|=+>+|\.+>+)\s*(?:\|([^|]+)\|)?\s*(\w+)\s*$',
                line
            )
            if edge_match:
                from_id = edge_match.group(1)
                label = edge_match.group(3) or ""
                to_id = edge_match.group(4)

                # Ensure nodes exist
                if from_id not in nodes_found:
                    nodes_found[from_id] = {"id": from_id, "name": from_id, "type": "default"}
                if to_id not in nodes_found:
                    nodes_found[to_id] = {"id": to_id, "name": to_id, "type": "default"}

                edges.append({"from": from_id, "to": to_id, "label": label})

        cd.nodes = list(nodes_found.values())
        cd.edges = edges
        cd._config_loaded = True

        return cd

    # =========================================================================
    # Template Methods
    # =========================================================================

    @classmethod
    def get_templates_dir(cls) -> Path:
        """Get the path to the Mermaid templates directory.

        Returns:
            Path to templates/mermaid directory

        Raises:
            MermaidError: If templates directory not found
        """
        # Try relative to this file first (development)
        module_dir = Path(__file__).parent.parent.parent.parent
        templates_dir = module_dir / "templates" / "mermaid"
        if templates_dir.exists():
            return templates_dir

        # Try relative to working directory
        cwd_templates = Path.cwd() / "templates" / "mermaid"
        if cwd_templates.exists():
            return cwd_templates

        raise MermaidError(
            "Mermaid templates directory not found. "
            "Expected at templates/mermaid/"
        )

    @classmethod
    def list_templates(cls, category: Optional[str] = None) -> List[Dict[str, str]]:
        """List available Mermaid templates.

        Args:
            category: Optional category filter (flowcharts, sequence, class, etc.)

        Returns:
            List of template info dictionaries with id, name, category, path
        """
        try:
            templates_dir = cls.get_templates_dir()
        except MermaidError:
            return []

        templates = []

        if category:
            categories = [templates_dir / category]
        else:
            categories = [d for d in templates_dir.iterdir() if d.is_dir()]

        for category_dir in categories:
            if not category_dir.exists():
                continue

            for template_file in category_dir.glob("*.toml"):
                templates.append({
                    "id": f"{category_dir.name}/{template_file.stem}",
                    "name": template_file.stem.replace("-", " ").title(),
                    "category": category_dir.name,
                    "path": str(template_file),
                })

            # Also check for .mmd files
            for template_file in category_dir.glob("*.mmd"):
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
        except MermaidError:
            return []

        categories = []
        for item in templates_dir.iterdir():
            if item.is_dir() and not item.name.startswith("."):
                categories.append(item.name)

        return sorted(categories)

    @classmethod
    def from_template(cls, template_id: str, **kwargs) -> "MermaidDiagrams":
        """Load from a built-in template.

        Args:
            template_id: Template identifier in format "category/name"
                        e.g., "flowcharts/basic-flow", "sequence/api-auth"
            **kwargs: Additional arguments passed to __init__

        Returns:
            MermaidDiagrams instance loaded with the template

        Raises:
            MermaidError: If template not found
        """
        templates_dir = cls.get_templates_dir()

        if "/" not in template_id:
            raise MermaidError(
                f"Invalid template ID format: {template_id}. "
                "Expected format: category/name (e.g., 'flowcharts/basic-flow')"
            )

        category, name = template_id.split("/", 1)

        # Try .toml first, then .mmd
        template_path = templates_dir / category / f"{name}.toml"
        if not template_path.exists():
            template_path = templates_dir / category / f"{name}.mmd"

        if not template_path.exists():
            available = cls.list_templates(category)
            available_ids = [t["id"] for t in available]
            raise MermaidError(
                f"Template not found: {template_id}. "
                f"Available templates in '{category}': {available_ids}"
            )

        instance = cls(**kwargs)
        instance.load(str(template_path))
        return instance

    # =========================================================================
    # Context Manager
    # =========================================================================

    def __enter__(self) -> "MermaidDiagrams":
        """Enter context manager."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Exit context manager."""
        pass

    def __repr__(self) -> str:
        """Return string representation."""
        status = "loaded" if self._loaded else "empty"
        return f"<MermaidDiagrams({self.diagram_type}, {status})>"


# =============================================================================
# Helper Functions
# =============================================================================

def _sanitize_mermaid_id(node_id: str) -> str:
    """Sanitize a node ID for Mermaid compatibility.

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


def _escape_mermaid_label(text: str, max_length: int = 100) -> str:
    """Escape text for use in Mermaid labels.

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
