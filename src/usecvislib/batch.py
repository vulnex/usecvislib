#
# VULNEX -Universal Security Visualization Library-
#
# File: batch.py
# Author: Simon Roses Femerling
# Created: 2025-12-25
# Last Modified: 2025-12-25
# Version: 0.3.1
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""
Batch processing for multiple visualization files.

This module provides utilities for processing multiple visualization
files in parallel, with support for progress tracking, validation,
and aggregated statistics.

Example:
    >>> from usecvislib.batch import BatchProcessor
    >>> processor = BatchProcessor("attack_tree", "/output", format="png")
    >>> result = processor.process_files(["tree1.toml", "tree2.toml"])
    >>> print(result.summary())
"""

import os
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional, Callable, Type
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class BatchResult:
    """Result of batch processing operation.

    Attributes:
        successes: Dictionary mapping filenames to their processing results.
        failures: Dictionary mapping filenames to error messages.
    """
    successes: Dict[str, Any] = field(default_factory=dict)
    failures: Dict[str, str] = field(default_factory=dict)

    @property
    def total(self) -> int:
        """Get total number of files processed."""
        return len(self.successes) + len(self.failures)

    @property
    def success_count(self) -> int:
        """Get number of successful processings."""
        return len(self.successes)

    @property
    def failure_count(self) -> int:
        """Get number of failed processings."""
        return len(self.failures)

    @property
    def success_rate(self) -> float:
        """Get success rate as a fraction (0-1)."""
        if self.total == 0:
            return 0.0
        return len(self.successes) / self.total

    @property
    def success_percentage(self) -> float:
        """Get success rate as a percentage (0-100)."""
        return self.success_rate * 100

    def summary(self) -> Dict[str, Any]:
        """Get a summary of the batch processing results.

        Returns:
            Dictionary with processing statistics.
        """
        return {
            "total": self.total,
            "successes": self.success_count,
            "failures": self.failure_count,
            "success_rate": self.success_rate,
            "success_percentage": round(self.success_percentage, 2),
            "failed_files": list(self.failures.keys())
        }

    def get_stats(self, filename: str) -> Optional[Dict[str, Any]]:
        """Get statistics for a specific file.

        Args:
            filename: The file to get stats for.

        Returns:
            Stats dictionary or None if file not found.
        """
        if filename in self.successes:
            return self.successes[filename].get("stats")
        return None

    def get_error(self, filename: str) -> Optional[str]:
        """Get error message for a specific file.

        Args:
            filename: The file to get error for.

        Returns:
            Error message or None if file succeeded.
        """
        return self.failures.get(filename)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "summary": self.summary(),
            "successes": self.successes,
            "failures": self.failures
        }


class BatchProcessor:
    """Process multiple visualization files in batch.

    Supports parallel processing with configurable workers,
    progress callbacks, and aggregated reporting.

    Example:
        >>> processor = BatchProcessor("attack_graph", "/output")
        >>> result = processor.process_files(["graph1.toml", "graph2.toml"])
        >>> print(f"Processed {result.success_count} files successfully")
    """

    # Lazy module mapping to avoid circular imports
    _MODULES: Optional[Dict[str, Type]] = None

    @classmethod
    def _get_modules(cls) -> Dict[str, Type]:
        """Get module mapping, loading lazily to avoid circular imports."""
        if cls._MODULES is None:
            from .attacktrees import AttackTrees
            from .attackgraphs import AttackGraphs
            from .threatmodeling import ThreatModeling
            from .binvis import BinVis

            cls._MODULES = {
                "attack_tree": AttackTrees,
                "attack_graph": AttackGraphs,
                "threat_model": ThreatModeling,
                "binary": BinVis,
            }
        return cls._MODULES

    def __init__(
        self,
        module_type: str,
        output_dir: str,
        format: str = "png",
        style: Optional[str] = None,
        max_workers: int = 4
    ):
        """Initialize batch processor.

        Args:
            module_type: Type of visualization to process.
                Options: "attack_tree", "attack_graph", "threat_model", "binary"
            output_dir: Directory for output files.
            format: Output format (png, svg, pdf, dot).
            style: Optional style ID to apply.
            max_workers: Maximum number of parallel workers.

        Raises:
            ValueError: If module_type is not recognized.
        """
        modules = self._get_modules()
        if module_type not in modules:
            valid_types = ", ".join(modules.keys())
            raise ValueError(
                f"Unknown module type: {module_type}. "
                f"Valid types: {valid_types}"
            )

        self.module_type = module_type
        self.module_class = modules[module_type]
        self.output_dir = Path(output_dir)
        self.format = format
        self.style = style
        self.max_workers = max_workers

        # Create output directory
        self.output_dir.mkdir(parents=True, exist_ok=True)
        logger.debug(f"BatchProcessor initialized for {module_type}")

    def process_files(
        self,
        input_files: List[str],
        collect_stats: bool = True,
        validate: bool = True,
        skip_on_error: bool = True,
        on_progress: Optional[Callable[[str, bool, Optional[str]], None]] = None
    ) -> BatchResult:
        """Process multiple input files.

        Args:
            input_files: List of input file paths.
            collect_stats: Whether to collect statistics for each file.
            validate: Whether to validate files before processing.
            skip_on_error: Whether to continue processing on errors.
            on_progress: Optional callback(filename, success, error_msg)
                for progress updates.

        Returns:
            BatchResult containing successes and failures.

        Example:
            >>> def progress(filename, success, error):
            ...     status = "OK" if success else f"FAILED: {error}"
            ...     print(f"{filename}: {status}")
            >>> result = processor.process_files(files, on_progress=progress)
        """
        result = BatchResult()

        if not input_files:
            logger.warning("No input files provided")
            return result

        logger.info(f"Processing {len(input_files)} files with {self.max_workers} workers")

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all tasks
            futures = {
                executor.submit(
                    self._process_single,
                    f,
                    collect_stats,
                    validate
                ): f
                for f in input_files
            }

            # Collect results as they complete
            for future in as_completed(futures):
                filename = futures[future]
                try:
                    data = future.result()
                    result.successes[filename] = data
                    logger.debug(f"Successfully processed: {filename}")
                    if on_progress:
                        on_progress(filename, True, None)
                except Exception as e:
                    error_msg = str(e)
                    result.failures[filename] = error_msg
                    logger.error(f"Failed to process {filename}: {error_msg}")
                    if on_progress:
                        on_progress(filename, False, error_msg)
                    if not skip_on_error:
                        # Cancel remaining futures
                        for f in futures:
                            f.cancel()
                        raise

        logger.info(
            f"Batch processing complete: {result.success_count} succeeded, "
            f"{result.failure_count} failed"
        )
        return result

    def _process_single(
        self,
        input_file: str,
        collect_stats: bool,
        validate: bool
    ) -> Dict[str, Any]:
        """Process a single file.

        Args:
            input_file: Path to input file.
            collect_stats: Whether to collect statistics.
            validate: Whether to validate before processing.

        Returns:
            Dictionary with processing results.

        Raises:
            ValueError: If validation fails.
            Exception: If processing fails.
        """
        filename = Path(input_file).stem
        output_path = str(self.output_dir / filename)

        # Prepare kwargs for instance creation
        kwargs: Dict[str, Any] = {"format": self.format}
        if self.style:
            kwargs["styleid"] = self.style

        # Create instance
        instance = self.module_class(input_file, output_path, **kwargs)

        result: Dict[str, Any] = {
            "file": input_file,
            "output": f"{output_path}.{self.format}"
        }

        # Validate if requested
        if validate:
            errors = instance.validate()
            result["validation"] = {
                "valid": len(errors) == 0,
                "errors": errors
            }
            if errors:
                raise ValueError(f"Validation failed: {errors}")

        # Generate visualization based on module type
        if self.module_type == "binary":
            instance.BuildBinVis("all")
        elif self.module_type == "attack_tree":
            instance.BuildAttackTree()
        elif self.module_type == "attack_graph":
            instance.BuildAttackGraph()
        elif self.module_type == "threat_model":
            instance.BuildThreatModel()

        # Collect stats if requested
        if collect_stats:
            if self.module_type == "attack_graph":
                result["stats"] = instance.get_graph_stats()
            elif self.module_type == "binary":
                result["stats"] = instance.get_file_stats()
            elif hasattr(instance, 'get_stats'):
                result["stats"] = instance.get_stats()

        return result

    def process_directory(
        self,
        input_dir: str,
        extensions: Optional[List[str]] = None,
        recursive: bool = False,
        **kwargs
    ) -> BatchResult:
        """Process all matching files in a directory.

        Args:
            input_dir: Input directory path.
            extensions: File extensions to include (with dot, e.g., ['.toml']).
                Defaults to ['.toml', '.tml', '.json', '.yaml', '.yml'].
            recursive: Whether to search recursively in subdirectories.
            **kwargs: Additional arguments passed to process_files().

        Returns:
            BatchResult containing successes and failures.

        Example:
            >>> result = processor.process_directory(
            ...     "/input",
            ...     extensions=[".toml"],
            ...     recursive=True
            ... )
        """
        if extensions is None:
            extensions = ['.toml', '.tml', '.json', '.yaml', '.yml']

        input_path = Path(input_dir)

        if not input_path.exists():
            raise ValueError(f"Input directory does not exist: {input_dir}")

        if not input_path.is_dir():
            raise ValueError(f"Not a directory: {input_dir}")

        # Collect files
        files: List[Path] = []
        for ext in extensions:
            if recursive:
                files.extend(input_path.rglob(f"*{ext}"))
            else:
                files.extend(input_path.glob(f"*{ext}"))

        logger.info(f"Found {len(files)} files in {input_dir}")
        return self.process_files([str(f) for f in files], **kwargs)

    def aggregate_stats(self, result: BatchResult) -> Dict[str, Any]:
        """Aggregate statistics from batch processing results.

        Combines statistics from all successfully processed files
        into a summary.

        Args:
            result: BatchResult from a processing operation.

        Returns:
            Dictionary with aggregated statistics.

        Example:
            >>> result = processor.process_files(files)
            >>> stats = processor.aggregate_stats(result)
            >>> print(f"Total nodes: {stats['total_nodes']}")
        """
        if not result.successes:
            return {"file_count": 0}

        aggregated: Dict[str, Any] = {
            "file_count": len(result.successes),
            "total_nodes": 0,
            "total_edges": 0,
            "total_vulnerabilities": 0,
            "max_cvss": 0.0,
            "avg_cvss": 0.0,
            "by_file": {}
        }

        cvss_values = []

        for filename, data in result.successes.items():
            stats = data.get("stats", {})
            aggregated["by_file"][filename] = stats

            # Sum common metrics
            aggregated["total_nodes"] += stats.get("total_nodes", 0)
            aggregated["total_nodes"] += stats.get("total_hosts", 0)
            aggregated["total_edges"] += stats.get("total_edges", 0)
            aggregated["total_edges"] += stats.get("network_edges", 0)
            aggregated["total_vulnerabilities"] += stats.get("total_vulnerabilities", 0)

            # Track CVSS scores
            if "average_cvss" in stats:
                cvss_values.append(stats["average_cvss"])
            if "max_cvss" in stats:
                aggregated["max_cvss"] = max(
                    aggregated["max_cvss"],
                    stats["max_cvss"]
                )

        # Calculate average CVSS
        if cvss_values:
            aggregated["avg_cvss"] = sum(cvss_values) / len(cvss_values)

        return aggregated


def process_batch(
    module_type: str,
    input_files: List[str],
    output_dir: str,
    format: str = "png",
    style: Optional[str] = None,
    max_workers: int = 4,
    **kwargs
) -> BatchResult:
    """Convenience function for batch processing.

    Creates a BatchProcessor and processes files in one call.

    Args:
        module_type: Type of visualization to process.
        input_files: List of input file paths.
        output_dir: Directory for output files.
        format: Output format.
        style: Optional style ID.
        max_workers: Maximum parallel workers.
        **kwargs: Additional arguments for process_files().

    Returns:
        BatchResult containing successes and failures.

    Example:
        >>> from usecvislib.batch import process_batch
        >>> result = process_batch(
        ...     "attack_tree",
        ...     ["tree1.toml", "tree2.toml"],
        ...     "/output"
        ... )
    """
    processor = BatchProcessor(
        module_type,
        output_dir,
        format=format,
        style=style,
        max_workers=max_workers
    )
    return processor.process_files(input_files, **kwargs)
