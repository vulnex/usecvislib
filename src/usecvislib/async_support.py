#
# VULNEX -Universal Security Visualization Library-
#
# File: async_support.py
# Author: Simon Roses Femerling
# Created: 2025-12-25
# Last Modified: 2025-12-25
# Version: 0.3.1
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""
Async support for visualization operations.

This module provides async wrappers for visualization classes,
enabling non-blocking I/O operations in async applications.

Example:
    >>> import asyncio
    >>> from usecvislib import AttackGraphs
    >>> from usecvislib.async_support import async_wrap
    >>>
    >>> async def main():
    ...     ag = AttackGraphs("network.toml", "output")
    ...     async_ag = async_wrap(ag)
    ...     await async_ag.build()
    ...     stats = await async_ag.get_stats()
    ...     return stats
    >>>
    >>> stats = asyncio.run(main())
"""

import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor
from typing import TypeVar, Generic, Optional, Any, Dict, List, Callable
from functools import partial

logger = logging.getLogger(__name__)

T = TypeVar('T')


class AsyncVisualization(Generic[T]):
    """Async wrapper for visualization classes.

    Provides async versions of I/O-bound operations by running
    them in a thread pool executor.

    Example:
        >>> ag = AttackGraphs("network.toml", "output")
        >>> async_ag = AsyncVisualization(ag)
        >>> await async_ag.load()
        >>> await async_ag.render()
        >>> await async_ag.draw()
    """

    def __init__(
        self,
        sync_instance: T,
        executor: Optional[ThreadPoolExecutor] = None,
        max_workers: int = 4
    ):
        """Initialize async wrapper.

        Args:
            sync_instance: The synchronous visualization instance to wrap.
            executor: Optional ThreadPoolExecutor to use. If None, creates one.
            max_workers: Number of workers if creating executor.
        """
        self._sync = sync_instance
        self._owns_executor = executor is None
        self._executor = executor or ThreadPoolExecutor(max_workers=max_workers)
        logger.debug(f"Created AsyncVisualization for {type(sync_instance).__name__}")

    @property
    def sync(self) -> T:
        """Access the underlying synchronous instance."""
        return self._sync

    async def load(self) -> T:
        """Async file loading.

        Returns:
            The underlying sync instance after loading.
        """
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(self._executor, self._sync.load)
        logger.debug("Async load completed")
        return self._sync

    async def render(self) -> T:
        """Async rendering.

        Returns:
            The underlying sync instance after rendering.
        """
        loop = asyncio.get_event_loop()
        # Handle different render method names
        if hasattr(self._sync, 'Render'):
            await loop.run_in_executor(self._executor, self._sync.Render)
        elif hasattr(self._sync, 'render'):
            await loop.run_in_executor(self._executor, self._sync.render)
        logger.debug("Async render completed")
        return self._sync

    async def draw(self) -> T:
        """Async drawing/output generation.

        Returns:
            The underlying sync instance after drawing.
        """
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(self._executor, self._sync.draw)
        logger.debug("Async draw completed")
        return self._sync

    async def build(self) -> T:
        """Async complete build (load + render + draw).

        Returns:
            The underlying sync instance after building.
        """
        await self.load()
        await self.render()
        await self.draw()
        logger.debug("Async build completed")
        return self._sync

    async def validate(self) -> List[str]:
        """Async validation.

        Returns:
            List of validation errors.
        """
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            self._executor,
            self._sync.validate
        )
        logger.debug(f"Async validate completed with {len(result)} issues")
        return result

    async def get_stats(self) -> Dict[str, Any]:
        """Async statistics collection.

        Returns:
            Dictionary of statistics.
        """
        loop = asyncio.get_event_loop()

        # Try different stats method names
        if hasattr(self._sync, 'get_graph_stats'):
            method = self._sync.get_graph_stats
        elif hasattr(self._sync, 'get_file_stats'):
            method = self._sync.get_file_stats
        elif hasattr(self._sync, 'get_stats'):
            method = self._sync.get_stats
        else:
            return {}

        result = await loop.run_in_executor(self._executor, method)
        logger.debug("Async get_stats completed")
        return result

    async def export_json(self, output: Optional[str] = None) -> str:
        """Async JSON export.

        Args:
            output: Optional output file path.

        Returns:
            JSON string.
        """
        loop = asyncio.get_event_loop()
        if hasattr(self._sync, 'export_json'):
            result = await loop.run_in_executor(
                self._executor,
                partial(self._sync.export_json, output)
            )
            return result
        raise NotImplementedError("Instance does not support export_json")

    async def close(self) -> None:
        """Close the executor if we own it."""
        if self._owns_executor:
            self._executor.shutdown(wait=True)
            logger.debug("Async executor shutdown")

    async def __aenter__(self) -> 'AsyncVisualization[T]':
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit."""
        await self.close()


def async_wrap(visualization_instance: T) -> AsyncVisualization[T]:
    """Wrap a visualization instance for async use.

    Convenience function to create an AsyncVisualization wrapper.

    Args:
        visualization_instance: The sync instance to wrap.

    Returns:
        AsyncVisualization wrapper.

    Example:
        >>> ag = AttackGraphs("network.toml", "output")
        >>> async_ag = async_wrap(ag)
        >>> await async_ag.build()
    """
    return AsyncVisualization(visualization_instance)


class AsyncBatchProcessor:
    """Async version of BatchProcessor.

    Processes multiple files concurrently using asyncio.

    Example:
        >>> processor = AsyncBatchProcessor("attack_graph", "/output")
        >>> result = await processor.process_files(["a.toml", "b.toml"])
    """

    def __init__(
        self,
        module_type: str,
        output_dir: str,
        format: str = "png",
        style: Optional[str] = None,
        max_concurrent: int = 4
    ):
        """Initialize async batch processor.

        Args:
            module_type: Type of visualization to process.
            output_dir: Directory for output files.
            format: Output format.
            style: Optional style ID.
            max_concurrent: Maximum concurrent operations.
        """
        from .batch import BatchProcessor

        self._sync_processor = BatchProcessor(
            module_type,
            output_dir,
            format=format,
            style=style,
            max_workers=1  # Each task runs sequentially
        )
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._executor = ThreadPoolExecutor(max_workers=max_concurrent)

    async def process_files(
        self,
        input_files: List[str],
        collect_stats: bool = True,
        validate: bool = True,
        on_progress: Optional[Callable[[str, bool, Optional[str]], None]] = None
    ) -> 'BatchResult':
        """Process multiple files concurrently.

        Args:
            input_files: List of input file paths.
            collect_stats: Whether to collect statistics.
            validate: Whether to validate files.
            on_progress: Optional progress callback.

        Returns:
            BatchResult with successes and failures.
        """
        from .batch import BatchResult

        result = BatchResult()

        async def process_one(filepath: str) -> tuple:
            async with self._semaphore:
                loop = asyncio.get_event_loop()
                try:
                    data = await loop.run_in_executor(
                        self._executor,
                        partial(
                            self._sync_processor._process_single,
                            filepath,
                            collect_stats,
                            validate
                        )
                    )
                    return filepath, True, data, None
                except Exception as e:
                    return filepath, False, None, str(e)

        # Create tasks
        tasks = [process_one(f) for f in input_files]

        # Process with progress reporting
        for coro in asyncio.as_completed(tasks):
            filepath, success, data, error = await coro
            if success:
                result.successes[filepath] = data
            else:
                result.failures[filepath] = error

            if on_progress:
                on_progress(filepath, success, error)

        return result

    async def close(self) -> None:
        """Close the executor."""
        self._executor.shutdown(wait=True)


async def process_files_async(
    module_type: str,
    input_files: List[str],
    output_dir: str,
    format: str = "png",
    max_concurrent: int = 4,
    **kwargs
) -> 'BatchResult':
    """Convenience function for async batch processing.

    Args:
        module_type: Type of visualization.
        input_files: List of input files.
        output_dir: Output directory.
        format: Output format.
        max_concurrent: Maximum concurrent operations.
        **kwargs: Additional arguments for process_files.

    Returns:
        BatchResult with successes and failures.

    Example:
        >>> result = await process_files_async(
        ...     "attack_tree",
        ...     ["tree1.toml", "tree2.toml"],
        ...     "/output"
        ... )
    """
    processor = AsyncBatchProcessor(
        module_type,
        output_dir,
        format=format,
        max_concurrent=max_concurrent
    )
    try:
        return await processor.process_files(input_files, **kwargs)
    finally:
        await processor.close()


class AsyncContextManager:
    """Helper for creating async context managers from sync instances.

    Example:
        >>> async with AsyncContextManager(AttackGraphs, "net.toml", "out") as ag:
        ...     await ag.build()
    """

    def __init__(self, cls, *args, **kwargs):
        """Initialize with class and constructor arguments.

        Args:
            cls: The visualization class.
            *args: Positional arguments for the constructor.
            **kwargs: Keyword arguments for the constructor.
        """
        self._cls = cls
        self._args = args
        self._kwargs = kwargs
        self._instance = None
        self._async_wrapper = None

    async def __aenter__(self) -> AsyncVisualization:
        """Create instance and return async wrapper."""
        self._instance = self._cls(*self._args, **self._kwargs)
        self._async_wrapper = async_wrap(self._instance)
        return self._async_wrapper

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Clean up resources."""
        if self._async_wrapper:
            await self._async_wrapper.close()
