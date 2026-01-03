#
# VULNEX -Universal Security Visualization Library-
#
# File: base.py
# Author: Simon Roses Femerling
# Created: 2025-12-25
# Last Modified: 2025-12-25
# Version: 0.3.1
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Base classes for USecVisLib visualization modules.

This module provides abstract base classes that define the common interface
and shared functionality for all visualization modules.
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, Any, List, Optional, TypeVar, Generic, TYPE_CHECKING
import logging

from . import utils

if TYPE_CHECKING:
    from .results import TemplateMetadata

T = TypeVar('T')


class VisualizationBase(ABC, Generic[T]):
    """Abstract base class for all visualization modules.

    Provides common functionality for:
    - File loading and validation
    - Style management
    - Output rendering
    - Statistics collection

    Subclasses must implement:
    - _load_impl(): Load and parse input data
    - _render_impl(): Build the visualization graph
    - _draw_impl(): Save visualization to file
    - _validate_impl(): Validate input structure
    - _get_stats_impl(): Collect statistics
    - _default_style(): Return default style configuration

    Attributes:
        inputfile: Path to the input configuration file.
        outputfile: Path for the output visualization.
        format: Output format (png, pdf, svg, dot).
        styleid: Style identifier for visualization theming.
        inputdata: Parsed input data dictionary.
        style: Style configuration dictionary.
    """

    # Override in subclasses
    STYLE_FILE: str = ""
    DEFAULT_STYLE_ID: str = ""
    ALLOWED_EXTENSIONS: List[str] = ['.toml', '.tml', '.json', '.yaml', '.yml']
    MAX_INPUT_SIZE: int = 10 * 1024 * 1024  # 10 MB

    def __init__(
        self,
        inputfile: str,
        outputfile: str,
        format: str = "png",
        styleid: Optional[str] = None,
        validate_paths: bool = True
    ) -> None:
        """Initialize visualization module.

        Args:
            inputfile: Path to input configuration file.
            outputfile: Path for output visualization (without extension).
            format: Output format (png, pdf, svg, dot).
            styleid: Style identifier. Use "0" to disable styling.
            validate_paths: Whether to validate paths on initialization.
                Set to False for deferred validation (e.g., API usage).

        Raises:
            SecurityError: If path validation fails (when validate_paths=True).
            FileNotFoundError: If input file doesn't exist (when validate_paths=True).
        """
        self.logger = logging.getLogger(self.__class__.__name__)

        # Validate and store paths
        if validate_paths:
            self._inputfile = utils.validate_input_path(
                inputfile,
                allowed_extensions=self.ALLOWED_EXTENSIONS,
                max_size_bytes=self.MAX_INPUT_SIZE
            )
            self._outputfile = utils.validate_output_path(outputfile)
            self.inputfile = str(self._inputfile)
            self.outputfile = str(self._outputfile)
        else:
            self._inputfile = None
            self._outputfile = None
            self.inputfile = inputfile
            self.outputfile = outputfile

        # Format and style
        self.format = format or "png"
        self.styleid = styleid or self.DEFAULT_STYLE_ID

        # State
        self.inputdata: Dict[str, Any] = {}
        self.style: Dict[str, Any] = {}
        self._loaded = False
        self._rendered = False

        self.logger.debug(f"Initialized {self.__class__.__name__} with input={inputfile}")

        # Load style if not disabled
        if self.styleid != "0":
            self._load_style()

    def _load_style(self) -> None:
        """Load style configuration from file."""
        if not self.STYLE_FILE:
            self.style = self._default_style()
            return

        try:
            config = utils.ConfigModel(self.STYLE_FILE)
            self.style = config.get(self.styleid)
            self.logger.debug(f"Loaded style: {self.styleid}")
        except (KeyError, utils.FileError) as e:
            self.logger.warning(f"Style '{self.styleid}' not found, using defaults: {e}")
            self.style = self._default_style()

    @abstractmethod
    def _default_style(self) -> Dict[str, Any]:
        """Return default style configuration.

        Returns:
            Dictionary containing default style settings.
        """
        pass

    @abstractmethod
    def _load_impl(self) -> Dict[str, Any]:
        """Implementation of data loading.

        Returns:
            Parsed input data dictionary.

        Raises:
            ConfigError: If parsing fails.
            FileError: If file cannot be read.
        """
        pass

    @abstractmethod
    def _render_impl(self) -> None:
        """Implementation of rendering.

        Raises:
            RenderError: If rendering fails.
        """
        pass

    @abstractmethod
    def _draw_impl(self, outputfile: str) -> None:
        """Implementation of drawing.

        Args:
            outputfile: Path for output file.

        Raises:
            RenderError: If drawing fails.
        """
        pass

    @abstractmethod
    def _validate_impl(self) -> List[str]:
        """Implementation of validation.

        Returns:
            List of validation error messages (empty if valid).
        """
        pass

    @abstractmethod
    def _get_stats_impl(self) -> Dict[str, Any]:
        """Implementation of statistics collection.

        Returns:
            Dictionary of statistics.
        """
        pass

    # Public API with fluent interface

    def load(self, inputfile: Optional[str] = None) -> 'VisualizationBase':
        """Load input data from configuration file.

        Args:
            inputfile: Optional override for input file path.

        Returns:
            Self for method chaining.

        Raises:
            SecurityError: If path validation fails.
            FileError: If file cannot be read.
            ConfigError: If parsing fails.
        """
        if inputfile:
            self._inputfile = utils.validate_input_path(
                inputfile,
                allowed_extensions=self.ALLOWED_EXTENSIONS,
                max_size_bytes=self.MAX_INPUT_SIZE
            )
            self.inputfile = str(self._inputfile)

        self.logger.info(f"Loading from {self.inputfile}")
        self.inputdata = self._load_impl()
        self._loaded = True
        self._rendered = False
        return self

    def render(self) -> 'VisualizationBase':
        """Build the visualization graph from loaded data.

        Returns:
            Self for method chaining.

        Raises:
            RuntimeError: If data not loaded.
            RenderError: If rendering fails.
        """
        if not self._loaded:
            self.load()

        self.logger.info("Rendering visualization")
        self._render_impl()
        self._rendered = True
        return self

    def draw(self, outputfile: Optional[str] = None) -> 'VisualizationBase':
        """Save visualization to file.

        Args:
            outputfile: Optional override for output file path.

        Returns:
            Self for method chaining.

        Raises:
            RuntimeError: If not rendered.
            SecurityError: If output path validation fails.
        """
        if not self._rendered:
            self.render()

        if outputfile:
            validated_path = utils.validate_output_path(outputfile)
            output = str(validated_path)
        else:
            output = self.outputfile

        self.logger.info(f"Drawing to {output}.{self.format}")
        self._draw_impl(output)
        return self

    def validate(self) -> List[str]:
        """Validate input data structure.

        Returns:
            List of validation error messages (empty if valid).
        """
        if not self._loaded:
            self.load()

        return self._validate_impl()

    def get_stats(self) -> Dict[str, Any]:
        """Get statistical summary.

        Returns:
            Dictionary of statistics.
        """
        if not self._loaded:
            self.load()

        return self._get_stats_impl()

    def get_metadata(self) -> 'TemplateMetadata':
        """Get template metadata.

        Extracts metadata fields from the loaded template data including
        version, author, dates, and type information.

        Returns:
            TemplateMetadata instance with extracted metadata.
        """
        # Import here to avoid circular imports
        from .results import TemplateMetadata

        if not self._loaded:
            self.load()

        # Determine root key based on class type
        root_key = self._get_metadata_root_key()
        return TemplateMetadata.from_dict(self.inputdata, root_key)

    def _get_metadata_root_key(self) -> str:
        """Get the root key for metadata extraction.

        Override in subclasses if needed.

        Returns:
            Root key name (tree, graph, model, etc.)
        """
        # Default behavior: auto-detect
        return ""

    def build(self) -> 'VisualizationBase':
        """Complete build workflow: load, render, draw.

        Returns:
            Self for method chaining.
        """
        return self.load().render().draw()

    # Context manager support

    def __enter__(self) -> 'VisualizationBase':
        """Enter context manager."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Exit context manager."""
        # Cleanup if needed
        pass

    # Properties

    @property
    def is_loaded(self) -> bool:
        """Check if data has been loaded."""
        return self._loaded

    @property
    def is_rendered(self) -> bool:
        """Check if visualization has been rendered."""
        return self._rendered

    # Backward compatibility aliases

    def Render(self) -> None:
        """Deprecated: Use render() instead."""
        self.render()

    def loadstyle(self) -> None:
        """Deprecated: Style is loaded automatically in __init__."""
        self._load_style()
