#
# VULNEX -Universal Security Visualization Library-
#
# File: diff.py
# Author: Simon Roses Femerling
# Created: 2025-12-25
# Last Modified: 2025-12-25
# Version: 0.3.1
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""
Comparison and diff functionality for visualizations.

This module provides tools for comparing two visualizations and
identifying changes between versions. Useful for tracking model
evolution over time and security posture changes.

Example:
    >>> from usecvislib import AttackGraphs
    >>> from usecvislib.diff import VisualizationDiff
    >>>
    >>> old = AttackGraphs("network_v1.toml", "output")
    >>> new = AttackGraphs("network_v2.toml", "output")
    >>> diff = VisualizationDiff(old, new)
    >>> result = diff.compare()
    >>> print(diff.summary_report())
"""

import logging
from typing import Dict, Any, List, Set, Optional, Union
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

logger = logging.getLogger(__name__)


class ChangeType(Enum):
    """Type of change detected between two versions."""
    ADDED = "added"
    REMOVED = "removed"
    MODIFIED = "modified"
    UNCHANGED = "unchanged"


@dataclass
class Change:
    """Represents a single change between two versions.

    Attributes:
        change_type: Type of change (added, removed, modified).
        path: Dot-notation path to the changed element.
        old_value: Previous value (None for additions).
        new_value: New value (None for removals).
        description: Optional human-readable description.
    """
    change_type: ChangeType
    path: str
    old_value: Any = None
    new_value: Any = None
    description: Optional[str] = None

    def __str__(self) -> str:
        if self.change_type == ChangeType.ADDED:
            return f"+ {self.path}: {self._format_value(self.new_value)}"
        elif self.change_type == ChangeType.REMOVED:
            return f"- {self.path}: {self._format_value(self.old_value)}"
        elif self.change_type == ChangeType.MODIFIED:
            return (
                f"~ {self.path}: {self._format_value(self.old_value)} "
                f"-> {self._format_value(self.new_value)}"
            )
        return f"  {self.path}"

    def _format_value(self, value: Any) -> str:
        """Format a value for display."""
        if value is None:
            return "null"
        if isinstance(value, str):
            if len(value) > 50:
                return f'"{value[:47]}..."'
            return f'"{value}"'
        if isinstance(value, (dict, list)):
            return f"<{type(value).__name__}>"
        return str(value)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "type": self.change_type.value,
            "path": self.path,
            "old_value": self.old_value,
            "new_value": self.new_value,
            "description": self.description
        }


@dataclass
class DiffResult:
    """Result of comparing two visualizations.

    Attributes:
        changes: List of all changes detected.
        old_source: Source path of old visualization.
        new_source: Source path of new visualization.
        metadata: Additional metadata about the comparison.
    """
    changes: List[Change] = field(default_factory=list)
    old_source: Optional[str] = None
    new_source: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def summary(self) -> Dict[str, int]:
        """Get summary counts by change type."""
        return {
            "added": len(self.added()),
            "removed": len(self.removed()),
            "modified": len(self.modified()),
            "total": len([c for c in self.changes if c.change_type != ChangeType.UNCHANGED])
        }

    @property
    def has_changes(self) -> bool:
        """Check if any changes were detected."""
        return any(c.change_type != ChangeType.UNCHANGED for c in self.changes)

    def added(self) -> List[Change]:
        """Get all additions."""
        return [c for c in self.changes if c.change_type == ChangeType.ADDED]

    def removed(self) -> List[Change]:
        """Get all removals."""
        return [c for c in self.changes if c.change_type == ChangeType.REMOVED]

    def modified(self) -> List[Change]:
        """Get all modifications."""
        return [c for c in self.changes if c.change_type == ChangeType.MODIFIED]

    def by_path_prefix(self, prefix: str) -> List[Change]:
        """Get changes under a specific path prefix.

        Args:
            prefix: Path prefix to filter by (e.g., "hosts").

        Returns:
            List of changes with paths starting with the prefix.
        """
        return [c for c in self.changes if c.path.startswith(prefix)]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "summary": self.summary,
            "has_changes": self.has_changes,
            "old_source": self.old_source,
            "new_source": self.new_source,
            "changes": [c.to_dict() for c in self.changes],
            "metadata": self.metadata
        }


class VisualizationDiff:
    """Compare two visualizations and identify changes.

    Useful for tracking model evolution over time, identifying
    security posture changes, and auditing modifications.

    Example:
        >>> old_ag = AttackGraphs("network_v1.toml", "output")
        >>> new_ag = AttackGraphs("network_v2.toml", "output")
        >>> diff = VisualizationDiff(old_ag, new_ag)
        >>> result = diff.compare()
        >>> if result.has_changes:
        ...     print(f"Found {result.summary['total']} changes")
    """

    def __init__(self, old_instance, new_instance):
        """Initialize diff comparison.

        Args:
            old_instance: The older visualization instance.
            new_instance: The newer visualization instance.
        """
        self.old = old_instance
        self.new = new_instance

        # Ensure both are loaded
        if not getattr(self.old, '_loaded', False):
            self.old.load()
        if not getattr(self.new, '_loaded', False):
            self.new.load()

    def compare(self, ignore_paths: Optional[List[str]] = None) -> DiffResult:
        """Compare the two visualizations.

        Args:
            ignore_paths: Optional list of path prefixes to ignore.

        Returns:
            DiffResult with detailed changes.
        """
        changes = []
        ignore_paths = ignore_paths or []

        # Compare based on inputdata
        old_data = getattr(self.old, 'inputdata', {})
        new_data = getattr(self.new, 'inputdata', {})

        changes = self._compare_dicts(old_data, new_data, path="")

        # Filter ignored paths
        if ignore_paths:
            changes = [
                c for c in changes
                if not any(c.path.startswith(p) for p in ignore_paths)
            ]

        return DiffResult(
            changes=changes,
            old_source=getattr(self.old, 'inputfile', None),
            new_source=getattr(self.new, 'inputfile', None),
            metadata={
                "old_type": type(self.old).__name__,
                "new_type": type(self.new).__name__
            }
        )

    def _compare_dicts(
        self,
        old: Dict,
        new: Dict,
        path: str
    ) -> List[Change]:
        """Recursively compare two dictionaries.

        Args:
            old: Old dictionary.
            new: New dictionary.
            path: Current path prefix.

        Returns:
            List of changes.
        """
        changes = []

        all_keys = set(old.keys()) | set(new.keys())

        for key in sorted(all_keys):
            key_path = f"{path}.{key}" if path else key

            if key not in old:
                # Added
                changes.append(Change(
                    ChangeType.ADDED,
                    key_path,
                    new_value=new[key],
                    description=f"Added {key}"
                ))
            elif key not in new:
                # Removed
                changes.append(Change(
                    ChangeType.REMOVED,
                    key_path,
                    old_value=old[key],
                    description=f"Removed {key}"
                ))
            elif old[key] != new[key]:
                # Modified - check if we can recurse
                if isinstance(old[key], dict) and isinstance(new[key], dict):
                    changes.extend(self._compare_dicts(
                        old[key], new[key], key_path
                    ))
                elif isinstance(old[key], list) and isinstance(new[key], list):
                    changes.extend(self._compare_lists(
                        old[key], new[key], key_path
                    ))
                else:
                    changes.append(Change(
                        ChangeType.MODIFIED,
                        key_path,
                        old_value=old[key],
                        new_value=new[key],
                        description=f"Changed {key}"
                    ))

        return changes

    def _compare_lists(
        self,
        old: List,
        new: List,
        path: str
    ) -> List[Change]:
        """Compare two lists.

        For lists of dicts with 'id' fields, compares by ID.
        Otherwise, compares by index.

        Args:
            old: Old list.
            new: New list.
            path: Current path prefix.

        Returns:
            List of changes.
        """
        changes = []

        # Check if items have 'id' field for better comparison
        old_has_ids = all(isinstance(x, dict) and 'id' in x for x in old)
        new_has_ids = all(isinstance(x, dict) and 'id' in x for x in new)

        if old_has_ids and new_has_ids:
            # Compare by ID
            old_by_id = {x['id']: x for x in old}
            new_by_id = {x['id']: x for x in new}

            all_ids = set(old_by_id.keys()) | set(new_by_id.keys())

            for item_id in sorted(all_ids, key=str):
                item_path = f"{path}[id={item_id}]"

                if item_id not in old_by_id:
                    changes.append(Change(
                        ChangeType.ADDED,
                        item_path,
                        new_value=new_by_id[item_id],
                        description=f"Added item {item_id}"
                    ))
                elif item_id not in new_by_id:
                    changes.append(Change(
                        ChangeType.REMOVED,
                        item_path,
                        old_value=old_by_id[item_id],
                        description=f"Removed item {item_id}"
                    ))
                elif old_by_id[item_id] != new_by_id[item_id]:
                    changes.extend(self._compare_dicts(
                        old_by_id[item_id],
                        new_by_id[item_id],
                        item_path
                    ))
        else:
            # Compare by index
            max_len = max(len(old), len(new))
            for i in range(max_len):
                item_path = f"{path}[{i}]"

                if i >= len(old):
                    changes.append(Change(
                        ChangeType.ADDED,
                        item_path,
                        new_value=new[i],
                        description=f"Added item at index {i}"
                    ))
                elif i >= len(new):
                    changes.append(Change(
                        ChangeType.REMOVED,
                        item_path,
                        old_value=old[i],
                        description=f"Removed item at index {i}"
                    ))
                elif old[i] != new[i]:
                    if isinstance(old[i], dict) and isinstance(new[i], dict):
                        changes.extend(self._compare_dicts(
                            old[i], new[i], item_path
                        ))
                    else:
                        changes.append(Change(
                            ChangeType.MODIFIED,
                            item_path,
                            old_value=old[i],
                            new_value=new[i],
                            description=f"Modified item at index {i}"
                        ))

        return changes

    def summary_report(self, include_details: bool = True) -> str:
        """Generate a human-readable diff summary.

        Args:
            include_details: Whether to include detailed changes.

        Returns:
            Markdown-formatted report string.
        """
        diff = self.compare()

        lines = [
            "# Visualization Diff Report",
            "",
            "## Summary",
            "",
            f"- **Old Version:** `{diff.old_source or 'unknown'}`",
            f"- **New Version:** `{diff.new_source or 'unknown'}`",
            "",
            f"| Change Type | Count |",
            f"|-------------|-------|",
            f"| Added       | {diff.summary['added']} |",
            f"| Removed     | {diff.summary['removed']} |",
            f"| Modified    | {diff.summary['modified']} |",
            f"| **Total**   | **{diff.summary['total']}** |",
            "",
        ]

        if not diff.has_changes:
            lines.append("*No changes detected.*")
            return "\n".join(lines)

        if include_details:
            if diff.added():
                lines.append("## Added")
                lines.append("")
                for change in diff.added():
                    lines.append(f"- `{change.path}`")
                lines.append("")

            if diff.removed():
                lines.append("## Removed")
                lines.append("")
                for change in diff.removed():
                    lines.append(f"- `{change.path}`")
                lines.append("")

            if diff.modified():
                lines.append("## Modified")
                lines.append("")
                for change in diff.modified():
                    old_str = self._truncate(str(change.old_value), 30)
                    new_str = self._truncate(str(change.new_value), 30)
                    lines.append(f"- `{change.path}`: {old_str} -> {new_str}")
                lines.append("")

        return "\n".join(lines)

    def _truncate(self, s: str, max_len: int) -> str:
        """Truncate string for display."""
        if len(s) <= max_len:
            return s
        return s[:max_len - 3] + "..."

    def save_report(
        self,
        output: str,
        format: str = "md",
        include_details: bool = True
    ) -> None:
        """Save diff report to file.

        Args:
            output: Output file path.
            format: Output format ('md' or 'json').
            include_details: Whether to include detailed changes.
        """
        output_path = Path(output)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        if format == "json":
            import json
            diff = self.compare()
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(diff.to_dict(), f, indent=2, default=str)
        else:
            report = self.summary_report(include_details=include_details)
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(report)

        logger.info(f"Saved diff report to: {output}")


def compare_files(
    old_file: str,
    new_file: str,
    visualization_type: str
) -> DiffResult:
    """Convenience function to compare two files.

    Args:
        old_file: Path to old file.
        new_file: Path to new file.
        visualization_type: Type of visualization.
            Options: "attack_tree", "attack_graph", "threat_model"

    Returns:
        DiffResult with changes.

    Example:
        >>> result = compare_files(
        ...     "network_v1.toml",
        ...     "network_v2.toml",
        ...     "attack_graph"
        ... )
    """
    # Import visualization classes
    from .attacktrees import AttackTrees
    from .attackgraphs import AttackGraphs
    from .threatmodeling import ThreatModeling

    classes = {
        "attack_tree": AttackTrees,
        "attack_graph": AttackGraphs,
        "threat_model": ThreatModeling,
    }

    if visualization_type not in classes:
        raise ValueError(f"Unknown type: {visualization_type}")

    cls = classes[visualization_type]

    old_instance = cls(old_file, "old_output", validate_paths=False)
    new_instance = cls(new_file, "new_output", validate_paths=False)

    diff = VisualizationDiff(old_instance, new_instance)
    return diff.compare()
