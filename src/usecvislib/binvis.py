#
# VULNEX -Universal Security Visualization Library-
#
# File: binvis.py
# Author: Simon Roses Femerling
# Created: 2025-01-01
# Last Modified: 2025-12-25
# Version: 0.3.1
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Binary Visualization Module.

This module provides visualization tools for binary file analysis including:
- Entropy analysis with sliding window
- Byte frequency distribution
- Wind rose diagrams for pattern analysis
- File structure visualization
"""

import os
import sys
import logging
import mmap
from pathlib import Path
from typing import Optional, Tuple, List, Dict, Any, Iterator

from . import utils

import numpy as np
import matplotlib.pyplot as plt
from matplotlib.patches import Wedge
from matplotlib.collections import PatchCollection
from scipy.stats import entropy
from collections import Counter

# Module logger
logger = logging.getLogger(__name__)


class BinVis:
    """Binary file visualization class.

    Provides methods to visualize binary file properties including entropy,
    byte distribution, and structural patterns.

    Attributes:
        inputfile: Path to the binary file to analyze.
        outputfile: Path for the output visualization.
        format: Output format (png, pdf, svg).
        styleid: Style identifier for visualization theming.
        data: Raw binary data from the input file.
        style: Style configuration dictionary.
    """

    # Maximum binary file size to analyze (100 MB)
    MAX_FILE_SIZE = 100 * 1024 * 1024

    # Default chunk size for streaming operations (10 MB)
    CHUNK_SIZE = 10 * 1024 * 1024

    def __init__(
        self,
        inputfile: str,
        outputfile: str,
        format: str = "",
        styleid: str = "",
        configfile: str = "",
        validate_paths: bool = True
    ) -> None:
        """Initialize BinVis with input/output paths and styling options.

        Args:
            inputfile: Path to the binary file to analyze.
            outputfile: Path for the output visualization.
            format: Output format (png, pdf, svg). Defaults to png.
            styleid: Style identifier from config. Defaults to bv_default.
            configfile: Path to user configuration TOML file for visualization
                parameters. If not provided, uses default parameters.
            validate_paths: Whether to validate paths on initialization.
                Set to False for deferred validation (e.g., API usage).

        Raises:
            SecurityError: If path validation fails (when validate_paths=True).
            FileNotFoundError: If input file doesn't exist (when validate_paths=True).
        """
        if format == "":
            format = "png"
        if styleid == "":
            styleid = "bv_default"

        self.stylefile = "config_binvis.tml"
        self.styleid = styleid
        self.configfile = configfile
        self.format = format
        self.data: Optional[bytes] = None
        self.style: Dict[str, Any] = {}
        self.config: Dict[str, Any] = {}
        self._loaded = False

        # Memory-mapped file support for streaming
        self._file: Optional[Any] = None
        self._mmap: Optional[mmap.mmap] = None

        # Validate and store paths
        # For binary files, we allow any extension but still validate for security
        if validate_paths:
            self._inputfile = utils.validate_input_path(
                inputfile,
                allowed_extensions=None,  # Binary files can have any extension
                max_size_bytes=self.MAX_FILE_SIZE
            )
            self._outputfile = utils.validate_output_path(outputfile)
            self.inputfile = str(self._inputfile)
            self.outputfile = str(self._outputfile)
        else:
            # Deferred validation - store raw paths
            self._inputfile = None
            self._outputfile = None
            self.inputfile = inputfile
            self.outputfile = outputfile

        logger.debug(f"Initialized BinVis with input={inputfile}")

        if self.styleid != "0":
            self.loadstyle()

        # Load user configuration (or defaults)
        self.loadconfig()

    def loadstyle(self) -> None:
        """Load style configuration from TOML file."""
        try:
            stp = utils.ConfigModel(self.stylefile)
            self.style = stp.get(self.styleid)
        except (KeyError, FileNotFoundError):
            self.style = self._default_style()

    def _default_style(self) -> Dict[str, Any]:
        """Return default style configuration."""
        return {
            "entropy": {
                "colormap": "viridis",
                "figsize": [12, 4],
                "linewidth": 1.0
            },
            "distribution": {
                "colormap": "Blues",
                "figsize": [12, 6],
                "bar_color": "#3498db"
            },
            "windrose": {
                "colormap": "plasma",
                "figsize": [8, 8]
            },
            "heatmap": {
                "colormap": "inferno",
                "figsize": [12, 12]
            }
        }

    def _default_config(self) -> Dict[str, Any]:
        """Return default visualization configuration parameters.

        Returns:
            Dictionary containing default parameters for all visualization types.
        """
        return {
            "byte_distribution": {
                "bar_width": 1.0,
                "bar_alpha": 0.7,
                "dpi": 150,
                "show_regions": True,
                "regions": [
                    {"start": 0, "end": 31, "color": "red", "alpha": 0.1, "label": "Control chars"},
                    {"start": 32, "end": 126, "color": "green", "alpha": 0.1, "label": "Printable ASCII"},
                    {"start": 127, "end": 255, "color": "blue", "alpha": 0.1, "label": "Extended"}
                ]
            },
            "entropy_analysis": {
                "window_size": 256,
                "step": 64,
                "dpi": 150,
                "show_thresholds": True,
                "thresholds": [
                    {"value": 7.5, "color": "r", "style": "--", "alpha": 0.5, "label": "High entropy (compressed/encrypted)"},
                    {"value": 4.0, "color": "g", "style": "--", "alpha": 0.5, "label": "Medium entropy (code)"},
                    {"value": 1.0, "color": "b", "style": "--", "alpha": 0.5, "label": "Low entropy (sparse data)"}
                ],
                "fill_alpha": 0.3,
                "show_grid": True,
                "grid_alpha": 0.3
            },
            "wind_rose": {
                "bar_alpha": 0.7,
                "dpi": 150,
                "rticks": [0.25, 0.5, 0.75, 1.0],
                "rlabel_position": 0
            },
            "heatmap": {
                "block_size": 256,
                "dpi": 150,
                "interpolation": "nearest",
                "aspect": "auto",
                "show_colorbar": True,
                "colorbar_label": "Byte Value"
            }
        }

    def loadconfig(self, configfile: Optional[str] = None) -> None:
        """Load user configuration from TOML file.

        Loads visualization parameters from a user-provided TOML file and
        merges them with default values. Missing parameters use defaults.

        Args:
            configfile: Path to the configuration TOML file.
                Uses self.configfile if not provided.

        Raises:
            ConfigError: If the configuration file is invalid TOML.
            SecurityError: If path validation fails.
        """
        config_path = configfile or self.configfile

        # Start with defaults
        self.config = self._default_config()

        if not config_path:
            logger.debug("No config file specified, using defaults")
            return

        # Validate and load user config
        try:
            import toml

            # Check if file exists
            if not os.path.isfile(config_path):
                logger.warning(f"Config file not found: {config_path}, using defaults")
                return

            user_config = toml.load(config_path)
            logger.info(f"Loaded user config from {config_path}")

            # Merge user config with defaults (user values override defaults)
            self._merge_config(user_config)

        except Exception as e:
            logger.warning(f"Failed to load config file {config_path}: {e}, using defaults")

    def _merge_config(self, user_config: Dict[str, Any]) -> None:
        """Merge user configuration with defaults.

        Args:
            user_config: User-provided configuration dictionary.
        """
        for section, values in user_config.items():
            if section in self.config:
                if isinstance(values, dict):
                    # Merge section values
                    for key, value in values.items():
                        self.config[section][key] = value
                else:
                    self.config[section] = values
            else:
                # Add new section from user config
                self.config[section] = values

        logger.debug(f"Merged config: {list(self.config.keys())}")

    def load(self, inputfile: Optional[str] = None) -> bytes:
        """Load binary data from input file.

        Args:
            inputfile: Path to input file. Uses self.inputfile if None.

        Returns:
            Raw bytes from the input file.

        Raises:
            FileNotFoundError: If input file does not exist.
            IOError: If file cannot be read.
            SecurityError: If path validation fails.
        """
        if inputfile:
            # Validate the new path
            validated_path = utils.validate_input_path(
                inputfile,
                allowed_extensions=None,  # Binary files can have any extension
                max_size_bytes=self.MAX_FILE_SIZE
            )
            self._inputfile = validated_path
            self.inputfile = str(validated_path)

        logger.info(f"Loading binary file from {self.inputfile}")

        if not os.path.isfile(self.inputfile):
            logger.error(f"Input file not found: {self.inputfile}")
            raise FileNotFoundError(f"Input file not found: {self.inputfile}")

        try:
            with open(self.inputfile, 'rb') as f:
                self.data = f.read()
            self._loaded = True
            logger.debug(f"Loaded {len(self.data)} bytes from binary file")
        except IOError as e:
            logger.error(f"Failed to read binary file {self.inputfile}: {e}")
            raise

        return self.data

    # Streaming methods for large file support

    def load_mmap(self) -> mmap.mmap:
        """Memory-map the file for efficient random access.

        Better for large files - the OS handles paging automatically.
        Useful when you need random access to different parts of a large file
        without loading it entirely into memory.

        Returns:
            Memory-mapped file object.

        Raises:
            FileNotFoundError: If input file does not exist.
            OSError: If memory mapping fails.

        Example:
            >>> bv = BinVis("large_file.bin", "output")
            >>> mm = bv.load_mmap()
            >>> chunk = mm[1000:2000]  # Read bytes 1000-2000
            >>> bv.close_mmap()  # Clean up when done
        """
        logger.info(f"Memory-mapping file: {self.inputfile}")

        if not os.path.isfile(self.inputfile):
            raise FileNotFoundError(f"Input file not found: {self.inputfile}")

        self._file = open(self.inputfile, 'rb')
        self._mmap = mmap.mmap(
            self._file.fileno(),
            0,
            access=mmap.ACCESS_READ
        )
        self.data = self._mmap
        self._loaded = True

        logger.debug(f"Memory-mapped {len(self._mmap)} bytes")
        return self._mmap

    def close_mmap(self) -> None:
        """Close the memory-mapped file and clean up resources.

        Should be called when done using load_mmap() to free resources.
        """
        if self._mmap:
            self._mmap.close()
            self._mmap = None
        if self._file:
            self._file.close()
            self._file = None
        logger.debug("Closed memory-mapped file")

    def load_chunked(self, chunk_size: Optional[int] = None) -> Iterator[bytes]:
        """Generator that yields file chunks.

        Memory efficient for sequential processing of large files.
        Each chunk is read and yielded one at a time, avoiding
        loading the entire file into memory.

        Args:
            chunk_size: Size of each chunk in bytes. Defaults to CHUNK_SIZE.

        Yields:
            Bytes chunks from the file.

        Example:
            >>> bv = BinVis("large_file.bin", "output")
            >>> for chunk in bv.load_chunked():
            ...     process_chunk(chunk)
        """
        chunk_size = chunk_size or self.CHUNK_SIZE

        logger.info(f"Reading file in {chunk_size} byte chunks: {self.inputfile}")

        with open(self.inputfile, 'rb') as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                yield chunk

    def calculate_entropy_streaming(
        self,
        chunk_size: Optional[int] = None
    ) -> float:
        """Calculate entropy without loading entire file into memory.

        Uses streaming byte counting to compute entropy for files
        that are too large to fit in memory.

        Args:
            chunk_size: Size of chunks to read. Defaults to CHUNK_SIZE.

        Returns:
            Entropy value (0-8 for byte data).

        Example:
            >>> bv = BinVis("very_large_file.bin", "output")
            >>> entropy = bv.calculate_entropy_streaming()
        """
        chunk_size = chunk_size or self.CHUNK_SIZE
        byte_counts = np.zeros(256, dtype=np.int64)
        total_bytes = 0

        logger.info("Calculating entropy using streaming method")

        for chunk in self.load_chunked(chunk_size):
            chunk_array = np.frombuffer(chunk, dtype=np.uint8)
            counts = np.bincount(chunk_array, minlength=256)
            byte_counts += counts
            total_bytes += len(chunk)

        if total_bytes == 0:
            return 0.0

        # Calculate entropy
        probabilities = byte_counts / total_bytes
        probabilities = probabilities[probabilities > 0]  # Remove zeros
        entropy_value = -np.sum(probabilities * np.log2(probabilities))

        logger.debug(f"Calculated streaming entropy: {entropy_value:.4f}")
        return float(entropy_value)

    def sliding_entropy_streaming(
        self,
        window_size: int = 256,
        step: int = 64,
        chunk_size: Optional[int] = None
    ) -> Iterator[Tuple[int, float]]:
        """Generator for sliding window entropy without loading entire file.

        Yields (position, entropy) tuples one at a time, enabling
        processing of files too large to fit in memory.

        Args:
            window_size: Size of the sliding window in bytes.
            step: Step size for sliding the window.
            chunk_size: Size of file chunks to read. Defaults to CHUNK_SIZE.

        Yields:
            Tuples of (position, entropy_value).

        Example:
            >>> bv = BinVis("large_file.bin", "output")
            >>> for pos, entropy in bv.sliding_entropy_streaming():
            ...     if entropy > 7.5:
            ...         print(f"High entropy at position {pos}")
        """
        chunk_size = chunk_size or self.CHUNK_SIZE

        # Maintain sliding window state across chunks
        window = bytearray()
        position = 0
        global_position = 0

        logger.info("Calculating sliding entropy using streaming method")

        for chunk in self.load_chunked(chunk_size):
            window.extend(chunk)

            while len(window) >= window_size:
                # Calculate entropy for current window
                window_bytes = bytes(window[:window_size])
                entropy_value = self.calculate_entropy(window_bytes)
                yield (global_position + position, entropy_value)

                # Slide window
                window = window[step:]
                position += step

            # Adjust for next chunk
            global_position += len(chunk)
            position = 0

    def get_file_stats_streaming(self) -> Dict[str, Any]:
        """Get file statistics without loading entire file into memory.

        Uses streaming processing to calculate statistics for files
        that are too large to fit in memory.

        Returns:
            Dictionary containing file statistics.

        Example:
            >>> bv = BinVis("very_large_file.bin", "output")
            >>> stats = bv.get_file_stats_streaming()
            >>> print(f"File size: {stats['file_size']} bytes")
            >>> print(f"Entropy: {stats['entropy']:.4f}")
        """
        byte_counts = np.zeros(256, dtype=np.int64)
        total_bytes = 0

        logger.info("Calculating file stats using streaming method")

        for chunk in self.load_chunked():
            chunk_array = np.frombuffer(chunk, dtype=np.uint8)
            counts = np.bincount(chunk_array, minlength=256)
            byte_counts += counts
            total_bytes += len(chunk)

        if total_bytes == 0:
            return {"file_size": 0, "error": "Empty file"}

        # Calculate statistics
        probabilities = byte_counts / total_bytes
        nonzero_probs = probabilities[probabilities > 0]
        entropy_value = -np.sum(nonzero_probs * np.log2(nonzero_probs))

        # Find most common bytes
        most_common_indices = np.argsort(byte_counts)[-10:][::-1]
        most_common = [
            (int(i), int(byte_counts[i]))
            for i in most_common_indices
            if byte_counts[i] > 0
        ]

        return {
            "file_size": total_bytes,
            "entropy": float(entropy_value),
            "unique_bytes": int(np.sum(byte_counts > 0)),
            "most_common": most_common,
            "null_percentage": float(byte_counts[0] / total_bytes * 100),
            "printable_percentage": float(
                np.sum(byte_counts[32:127]) / total_bytes * 100
            ),
            "high_byte_percentage": float(
                np.sum(byte_counts[128:256]) / total_bytes * 100
            ),
        }

    def __del__(self):
        """Cleanup memory-mapped file on object destruction."""
        self.close_mmap()

    def calculate_entropy(self, data: bytes, base: int = 2) -> float:
        """Calculate Shannon entropy of binary data.

        Args:
            data: Binary data to analyze.
            base: Logarithm base for entropy calculation. Defaults to 2.

        Returns:
            Entropy value (0-8 for byte data with base 2).
        """
        if not data:
            return 0.0

        byte_counts = Counter(data)
        total = len(data)
        probabilities = [count / total for count in byte_counts.values()]
        return entropy(probabilities, base=base)

    def sliding_entropy(self, window_size: int = 256, step: int = 64) -> Tuple[np.ndarray, np.ndarray]:
        """Calculate entropy using a sliding window across the file.

        Args:
            window_size: Size of the sliding window in bytes.
            step: Step size for sliding the window.

        Returns:
            Tuple of (positions, entropy_values) arrays.
        """
        if self.data is None:
            self.load()

        data = self.data
        positions = []
        entropies = []

        for i in range(0, len(data) - window_size + 1, step):
            window = data[i:i + window_size]
            positions.append(i)
            entropies.append(self.calculate_entropy(window))

        return np.array(positions), np.array(entropies)

    def byte_distribution(self) -> np.ndarray:
        """Calculate byte frequency distribution.

        Returns:
            Array of 256 values representing frequency of each byte value.
        """
        if self.data is None:
            self.load()

        distribution = np.zeros(256)
        for byte in self.data:
            distribution[byte] += 1

        return distribution / len(self.data) if self.data else distribution

    def visualize_entropy(self, window_size: Optional[int] = None,
                          step: Optional[int] = None,
                          output: Optional[str] = None) -> None:
        """Create entropy visualization with sliding window.

        Args:
            window_size: Size of the sliding window. Uses config value if None.
            step: Step size for the sliding window. Uses config value if None.
            output: Output file path. Uses self.outputfile if None.

        Raises:
            SecurityError: If output path validation fails.
        """
        if output:
            validated_path = utils.validate_output_path(output)
            output = str(validated_path)
        else:
            output = f"{self.outputfile}_entropy.{self.format}"

        logger.debug(f"Creating entropy visualization at {output}")

        # Get style and config
        style = self.style.get("entropy", self._default_style()["entropy"])
        config = self.config.get("entropy_analysis", self._default_config()["entropy_analysis"])

        # Use config values if not explicitly provided
        window_size = window_size if window_size is not None else config.get("window_size", 256)
        step = step if step is not None else config.get("step", 64)

        positions, entropies = self.sliding_entropy(window_size, step)

        fig, ax = plt.subplots(figsize=style.get("figsize", [12, 4]))

        # Use config for fill alpha
        fill_alpha = config.get("fill_alpha", 0.3)
        ax.fill_between(positions, entropies, alpha=fill_alpha)
        ax.plot(positions, entropies, linewidth=style.get("linewidth", 1.0))

        ax.set_xlabel("File Offset (bytes)")
        ax.set_ylabel("Entropy (bits)")
        ax.set_title(f"Entropy Analysis: {os.path.basename(self.inputfile)}")
        ax.set_ylim(0, 8)

        # Use config for grid
        if config.get("show_grid", True):
            ax.grid(True, alpha=config.get("grid_alpha", 0.3))

        # Add threshold lines from config
        if config.get("show_thresholds", True):
            thresholds = config.get("thresholds", [])
            for threshold in thresholds:
                ax.axhline(
                    y=threshold.get("value", 0),
                    color=threshold.get("color", "r"),
                    linestyle=threshold.get("style", "--"),
                    alpha=threshold.get("alpha", 0.5),
                    label=threshold.get("label", "")
                )
            ax.legend(loc='upper right', fontsize='small')

        plt.tight_layout()
        plt.savefig(output, dpi=config.get("dpi", 150), format=self.format)
        plt.close()

        logger.info(f"Saved entropy visualization to {output}")

    def visualize_distribution(self, output: Optional[str] = None) -> None:
        """Create byte frequency distribution visualization.

        Args:
            output: Output file path. Uses self.outputfile if None.

        Raises:
            SecurityError: If output path validation fails.
        """
        if output:
            validated_path = utils.validate_output_path(output)
            output = str(validated_path)
        else:
            output = f"{self.outputfile}_distribution.{self.format}"

        logger.debug(f"Creating distribution visualization at {output}")

        # Get style and config
        style = self.style.get("distribution", self._default_style()["distribution"])
        config = self.config.get("byte_distribution", self._default_config()["byte_distribution"])

        distribution = self.byte_distribution()

        fig, ax = plt.subplots(figsize=style.get("figsize", [12, 6]))

        # Use config for bar parameters
        bars = ax.bar(range(256), distribution,
                      color=style.get("bar_color", "#3498db"),
                      alpha=config.get("bar_alpha", 0.7),
                      width=config.get("bar_width", 1.0))

        ax.set_xlabel("Byte Value (0-255)")
        ax.set_ylabel("Frequency")
        ax.set_title(f"Byte Distribution: {os.path.basename(self.inputfile)}")
        ax.set_xlim(-1, 256)

        # Highlight special regions from config
        if config.get("show_regions", True):
            regions = config.get("regions", [])
            for region in regions:
                ax.axvspan(
                    region.get("start", 0),
                    region.get("end", 0),
                    alpha=region.get("alpha", 0.1),
                    color=region.get("color", "gray"),
                    label=region.get("label", "")
                )
            ax.legend(loc='upper right', fontsize='small')

        plt.tight_layout()
        plt.savefig(output, dpi=config.get("dpi", 150), format=self.format)
        plt.close()

        logger.info(f"Saved distribution visualization to {output}")

    def visualize_windrose(self, output: Optional[str] = None) -> None:
        """Create wind rose diagram showing byte pair patterns.

        The wind rose shows the distribution of byte values in a polar format,
        useful for identifying patterns in binary data.

        Args:
            output: Output file path. Uses self.outputfile if None.

        Raises:
            SecurityError: If output path validation fails.
        """
        if output:
            validated_path = utils.validate_output_path(output)
            output = str(validated_path)
        else:
            output = f"{self.outputfile}_windrose.{self.format}"

        logger.debug(f"Creating windrose visualization at {output}")

        # Get style and config
        style = self.style.get("windrose", self._default_style()["windrose"])
        config = self.config.get("wind_rose", self._default_config()["wind_rose"])

        if self.data is None:
            self.load()

        # Calculate byte pair frequencies
        pair_counts = Counter()
        for i in range(len(self.data) - 1):
            pair = (self.data[i], self.data[i + 1])
            pair_counts[pair] += 1

        # Create polar plot
        fig, ax = plt.subplots(figsize=style.get("figsize", [8, 8]),
                                subplot_kw=dict(projection='polar'))

        # Group by first byte (direction) and aggregate second byte (magnitude)
        directions = np.zeros(256)
        for (b1, b2), count in pair_counts.items():
            directions[b1] += count

        # Normalize
        if directions.max() > 0:
            directions = directions / directions.max()

        # Create bars
        theta = np.linspace(0, 2 * np.pi, 256, endpoint=False)
        width = 2 * np.pi / 256

        # Use config for bar alpha
        bars = ax.bar(theta, directions, width=width, alpha=config.get("bar_alpha", 0.7))

        # Color by value
        cmap = plt.get_cmap(style.get("colormap", "plasma"))
        for i, bar in enumerate(bars):
            bar.set_facecolor(cmap(i / 255))

        ax.set_title(f"Byte Pattern Wind Rose: {os.path.basename(self.inputfile)}")

        # Use config for rticks and rlabel position
        ax.set_rticks(config.get("rticks", [0.25, 0.5, 0.75, 1.0]))
        ax.set_rlabel_position(config.get("rlabel_position", 0))

        plt.tight_layout()
        plt.savefig(output, dpi=config.get("dpi", 150), format=self.format)
        plt.close()

        logger.info(f"Saved windrose visualization to {output}")

    def visualize_heatmap(self, block_size: Optional[int] = None,
                          output: Optional[str] = None) -> None:
        """Create a 2D heatmap visualization of the binary file.

        Displays the file as a 2D image where each pixel represents a byte.

        Args:
            block_size: Width of the heatmap in bytes. Uses config value if None.
            output: Output file path. Uses self.outputfile if None.

        Raises:
            SecurityError: If output path validation fails.
        """
        if output:
            validated_path = utils.validate_output_path(output)
            output = str(validated_path)
        else:
            output = f"{self.outputfile}_heatmap.{self.format}"

        logger.debug(f"Creating heatmap visualization at {output}")

        # Get style and config
        style = self.style.get("heatmap", self._default_style()["heatmap"])
        config = self.config.get("heatmap", self._default_config()["heatmap"])

        # Use config value if not explicitly provided
        block_size = block_size if block_size is not None else config.get("block_size", 256)

        if self.data is None:
            self.load()

        # Pad data to fill complete rows
        data_array = np.frombuffer(self.data, dtype=np.uint8)
        padding = (block_size - len(data_array) % block_size) % block_size
        if padding:
            data_array = np.pad(data_array, (0, padding), mode='constant', constant_values=0)

        # Reshape to 2D
        height = len(data_array) // block_size
        image = data_array.reshape((height, block_size))

        fig, ax = plt.subplots(figsize=style.get("figsize", [12, 12]))

        # Use config for interpolation and aspect
        im = ax.imshow(image, cmap=style.get("colormap", "inferno"),
                       aspect=config.get("aspect", "auto"),
                       interpolation=config.get("interpolation", "nearest"))

        ax.set_xlabel("Byte Offset in Block")
        ax.set_ylabel("Block Number")
        ax.set_title(f"Binary Heatmap: {os.path.basename(self.inputfile)}")

        # Use config for colorbar
        if config.get("show_colorbar", True):
            plt.colorbar(im, ax=ax, label=config.get("colorbar_label", "Byte Value"))

        plt.tight_layout()
        plt.savefig(output, dpi=config.get("dpi", 150), format=self.format)
        plt.close()

        logger.info(f"Saved heatmap visualization to {output}")

    def visualize_all(self, output_prefix: Optional[str] = None) -> List[str]:
        """Generate all visualization types.

        Args:
            output_prefix: Prefix for output files. Uses self.outputfile if None.

        Returns:
            List of generated output file paths.

        Raises:
            SecurityError: If output path validation fails.
        """
        if output_prefix:
            # Validate the base output path
            validated_path = utils.validate_output_path(output_prefix)
            prefix = str(validated_path)
        else:
            prefix = self.outputfile

        logger.info(f"Generating all visualizations with prefix {prefix}")
        outputs = []

        self.load()  # Load once for all visualizations

        self.visualize_entropy(output=f"{prefix}_entropy.{self.format}")
        outputs.append(f"{prefix}_entropy.{self.format}")

        self.visualize_distribution(output=f"{prefix}_distribution.{self.format}")
        outputs.append(f"{prefix}_distribution.{self.format}")

        self.visualize_windrose(output=f"{prefix}_windrose.{self.format}")
        outputs.append(f"{prefix}_windrose.{self.format}")

        self.visualize_heatmap(output=f"{prefix}_heatmap.{self.format}")
        outputs.append(f"{prefix}_heatmap.{self.format}")

        logger.info(f"Generated {len(outputs)} visualizations")
        return outputs

    def get_file_stats(self) -> Dict[str, Any]:
        """Get statistical summary of the binary file.

        Returns:
            Dictionary containing file statistics.
        """
        if self.data is None:
            self.load()

        distribution = self.byte_distribution()

        return {
            "file_size": len(self.data),
            "entropy": self.calculate_entropy(self.data),
            "unique_bytes": len(set(self.data)),
            "most_common": Counter(self.data).most_common(10),
            "null_percentage": (distribution[0] * 100),
            "printable_percentage": sum(distribution[32:127]) * 100,
            "high_byte_percentage": sum(distribution[128:256]) * 100,
        }

    def BuildBinVis(self, visualization: str = "all") -> None:
        """Main entry point for binary visualization.

        Args:
            visualization: Type of visualization to generate.
                Options: 'entropy', 'distribution', 'windrose', 'heatmap', 'all'
        """
        self.load()

        if visualization == "all":
            self.visualize_all()
        elif visualization == "entropy":
            self.visualize_entropy()
        elif visualization == "distribution":
            self.visualize_distribution()
        elif visualization == "windrose":
            self.visualize_windrose()
        elif visualization == "heatmap":
            self.visualize_heatmap()
        else:
            raise ValueError(f"Unknown visualization type: {visualization}")

    # Common interface methods for API consistency

    def get_stats(self) -> Dict[str, Any]:
        """Get statistical summary of the binary file.

        Alias for get_file_stats() for API consistency with other modules.

        Returns:
            Dictionary containing file statistics.
        """
        return self.get_file_stats()

    def validate(self) -> List[str]:
        """Validate the binary file.

        Returns:
            List of validation error messages. Empty if valid.
        """
        errors = []

        if not os.path.isfile(self.inputfile):
            errors.append(f"Input file not found: {self.inputfile}")
            return errors

        try:
            file_size = os.path.getsize(self.inputfile)
            if file_size == 0:
                errors.append("Input file is empty")
            elif file_size > self.MAX_FILE_SIZE:
                errors.append(f"File size ({file_size} bytes) exceeds maximum ({self.MAX_FILE_SIZE} bytes)")
        except OSError as e:
            errors.append(f"Cannot read file stats: {e}")

        return errors

    def build(self, visualization: str = "all") -> 'BinVis':
        """Build visualization with fluent interface.

        Args:
            visualization: Type of visualization to generate.

        Returns:
            Self for method chaining.
        """
        self.BuildBinVis(visualization)
        return self

    @property
    def is_loaded(self) -> bool:
        """Check if binary data has been loaded."""
        return self._loaded
