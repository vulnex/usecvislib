#
# VULNEX -Universal Security Visualization Library-
#
# File: exporters.py
# Author: Simon Roses Femerling
# Created: 2025-12-25
# Last Modified: 2025-12-25
# Version: 0.3.1
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""
Export functionality for visualization data.

This module provides mixins and utilities for exporting visualization
data to various formats including JSON, CSV, and YAML.

Example:
    >>> from usecvislib import AttackGraphs
    >>> ag = AttackGraphs("network.toml", "output")
    >>> ag.load()
    >>> json_data = ag.export_json()
    >>> ag.export_csv("hosts.csv", section="hosts")
"""

import json
import csv
import logging
from typing import Dict, Any, List, Optional, Union, TextIO
from pathlib import Path
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)


class ExportMixin:
    """Mixin class providing data export functionality.

    This mixin adds export methods to visualization classes,
    enabling export to JSON, CSV, and other formats.

    Note:
        Classes using this mixin must have:
        - self.inputdata: Dict containing the loaded data
        - self.inputfile: str with the source file path
        - self._loaded: bool indicating if data is loaded
        - self.load(): method to load data
    """

    def export_json(
        self,
        output: Optional[str] = None,
        include_stats: bool = True,
        include_metadata: bool = True,
        pretty: bool = True
    ) -> str:
        """Export data as JSON.

        Args:
            output: Output file path. If None, returns JSON string.
            include_stats: Whether to include statistics.
            include_metadata: Whether to include metadata.
            pretty: Whether to use pretty formatting.

        Returns:
            JSON string representation.

        Example:
            >>> ag = AttackGraphs("network.toml", "output")
            >>> json_str = ag.export_json()
            >>> ag.export_json("export.json")  # Write to file
        """
        # Ensure data is loaded
        if not getattr(self, '_loaded', False):
            self.load()

        data: Dict[str, Any] = {}

        # Add metadata
        if include_metadata:
            data["metadata"] = {
                "type": self.__class__.__name__,
                "source": getattr(self, 'inputfile', 'unknown'),
                "version": "0.2.3"
            }

        # Add main data
        data["data"] = getattr(self, 'inputdata', {})

        # Add stats if available and requested
        if include_stats:
            stats_method = None
            if hasattr(self, 'get_graph_stats'):
                stats_method = self.get_graph_stats
            elif hasattr(self, 'get_file_stats'):
                stats_method = self.get_file_stats
            elif hasattr(self, 'get_stats'):
                stats_method = self.get_stats

            if stats_method:
                try:
                    data["stats"] = stats_method()
                except Exception as e:
                    logger.warning(f"Could not collect stats: {e}")
                    data["stats"] = {}

        # Serialize
        indent = 2 if pretty else None
        json_str = json.dumps(data, indent=indent, default=str)

        # Write to file if output specified
        if output:
            output_path = Path(output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(json_str)
            logger.info(f"Exported JSON to: {output}")

        return json_str

    def export_csv(
        self,
        output: str,
        section: str = "nodes",
        delimiter: str = ",",
        include_header: bool = True
    ) -> int:
        """Export specific section as CSV.

        Args:
            output: Output file path.
            section: Data section to export. Available sections depend
                on the visualization type.
            delimiter: CSV delimiter character.
            include_header: Whether to include header row.

        Returns:
            Number of rows written.

        Raises:
            ValueError: If section is not found or has no data.

        Example:
            >>> ag = AttackGraphs("network.toml", "output")
            >>> ag.export_csv("hosts.csv", section="hosts")
            >>> ag.export_csv("vulns.csv", section="vulnerabilities")
        """
        # Ensure data is loaded
        if not getattr(self, '_loaded', False):
            self.load()

        # Get data for section
        data = self._get_csv_data(section)

        if not data:
            raise ValueError(f"No data for section: {section}")

        # Ensure output directory exists
        output_path = Path(output)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Write CSV
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            # Get all possible keys from all rows
            all_keys = set()
            for row in data:
                all_keys.update(row.keys())
            fieldnames = sorted(all_keys)

            writer = csv.DictWriter(
                f,
                fieldnames=fieldnames,
                delimiter=delimiter,
                extrasaction='ignore'
            )

            if include_header:
                writer.writeheader()

            writer.writerows(data)

        logger.info(f"Exported {len(data)} rows to CSV: {output}")
        return len(data)

    def _get_csv_data(self, section: str) -> List[Dict[str, Any]]:
        """Get data for CSV export from a specific section.

        Override in subclasses to provide section-specific data.

        Args:
            section: The section name to export.

        Returns:
            List of dictionaries suitable for CSV export.
        """
        inputdata = getattr(self, 'inputdata', {})

        # Handle common section patterns
        if section in inputdata:
            data = inputdata[section]
            # If it's a list of dicts, return as-is
            if isinstance(data, list):
                return data
            # If it's a dict of dicts, convert to list with id
            if isinstance(data, dict):
                return [{"id": k, **v} for k, v in data.items()]

        # Try nested sections
        for key, value in inputdata.items():
            if isinstance(value, dict) and section in value:
                sub_data = value[section]
                if isinstance(sub_data, list):
                    return sub_data
                if isinstance(sub_data, dict):
                    return [{"id": k, **v} for k, v in sub_data.items()]

        return []

    def get_exportable_sections(self) -> List[str]:
        """Get list of sections that can be exported.

        Returns:
            List of section names available for export.
        """
        if not getattr(self, '_loaded', False):
            self.load()

        sections = []
        inputdata = getattr(self, 'inputdata', {})

        for key, value in inputdata.items():
            if isinstance(value, (list, dict)):
                sections.append(key)

        return sections


class Exporter:
    """Standalone exporter for visualization data.

    Use this when you need more control over the export process
    or want to export data from multiple sources.

    Example:
        >>> exporter = Exporter()
        >>> exporter.to_json(data, "output.json")
        >>> exporter.to_csv(data["hosts"], "hosts.csv")
    """

    @staticmethod
    def to_json(
        data: Dict[str, Any],
        output: Optional[str] = None,
        pretty: bool = True
    ) -> str:
        """Export dictionary to JSON.

        Args:
            data: Dictionary to export.
            output: Optional output file path.
            pretty: Whether to use pretty formatting.

        Returns:
            JSON string.
        """
        indent = 2 if pretty else None
        json_str = json.dumps(data, indent=indent, default=str)

        if output:
            Path(output).parent.mkdir(parents=True, exist_ok=True)
            with open(output, 'w', encoding='utf-8') as f:
                f.write(json_str)

        return json_str

    @staticmethod
    def to_csv(
        data: List[Dict[str, Any]],
        output: str,
        fieldnames: Optional[List[str]] = None,
        delimiter: str = ","
    ) -> int:
        """Export list of dictionaries to CSV.

        Args:
            data: List of dictionaries to export.
            output: Output file path.
            fieldnames: Optional list of field names. If None, uses
                keys from all rows.
            delimiter: CSV delimiter.

        Returns:
            Number of rows written.
        """
        if not data:
            return 0

        # Determine fieldnames
        if fieldnames is None:
            all_keys = set()
            for row in data:
                all_keys.update(row.keys())
            fieldnames = sorted(all_keys)

        # Write
        Path(output).parent.mkdir(parents=True, exist_ok=True)
        with open(output, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(
                f,
                fieldnames=fieldnames,
                delimiter=delimiter,
                extrasaction='ignore'
            )
            writer.writeheader()
            writer.writerows(data)

        return len(data)

    @staticmethod
    def to_yaml(
        data: Dict[str, Any],
        output: Optional[str] = None
    ) -> str:
        """Export dictionary to YAML.

        Args:
            data: Dictionary to export.
            output: Optional output file path.

        Returns:
            YAML string.
        """
        import yaml

        yaml_str = yaml.dump(
            data,
            default_flow_style=False,
            allow_unicode=True,
            sort_keys=False
        )

        if output:
            Path(output).parent.mkdir(parents=True, exist_ok=True)
            with open(output, 'w', encoding='utf-8') as f:
                f.write(yaml_str)

        return yaml_str

    @staticmethod
    def to_markdown_table(
        data: List[Dict[str, Any]],
        output: Optional[str] = None,
        columns: Optional[List[str]] = None
    ) -> str:
        """Export list of dictionaries to Markdown table.

        Args:
            data: List of dictionaries to export.
            output: Optional output file path.
            columns: Optional list of columns. If None, uses keys from first row.

        Returns:
            Markdown table string.
        """
        if not data:
            return ""

        # Determine columns
        if columns is None:
            columns = list(data[0].keys())

        # Build table
        lines = []

        # Header
        lines.append("| " + " | ".join(columns) + " |")
        lines.append("| " + " | ".join(["---"] * len(columns)) + " |")

        # Rows
        for row in data:
            values = [str(row.get(col, "")) for col in columns]
            lines.append("| " + " | ".join(values) + " |")

        md_str = "\n".join(lines)

        if output:
            Path(output).parent.mkdir(parents=True, exist_ok=True)
            with open(output, 'w', encoding='utf-8') as f:
                f.write(md_str)

        return md_str


class ReportGenerator:
    """Generate comprehensive reports from visualization data.

    Combines multiple export formats into a single report.

    Example:
        >>> generator = ReportGenerator(attack_graph)
        >>> generator.generate_report("/reports", formats=["json", "csv", "md"])
    """

    def __init__(self, visualization):
        """Initialize report generator.

        Args:
            visualization: A visualization instance (AttackGraphs, etc.)
        """
        self.viz = visualization
        if not getattr(self.viz, '_loaded', False):
            self.viz.load()

    def generate_report(
        self,
        output_dir: str,
        formats: Optional[List[str]] = None,
        prefix: str = "report"
    ) -> Dict[str, str]:
        """Generate a report in multiple formats.

        Args:
            output_dir: Directory for output files.
            formats: List of formats to generate. Options: json, csv, yaml, md.
                Defaults to all formats.
            prefix: Filename prefix for output files.

        Returns:
            Dictionary mapping format to output file path.
        """
        if formats is None:
            formats = ["json", "csv", "md"]

        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        outputs = {}
        exporter = Exporter()

        # JSON export
        if "json" in formats:
            json_file = str(output_path / f"{prefix}.json")
            if hasattr(self.viz, 'export_json'):
                self.viz.export_json(json_file)
            else:
                exporter.to_json(self.viz.inputdata, json_file)
            outputs["json"] = json_file

        # CSV exports for each section
        if "csv" in formats:
            sections = []
            if hasattr(self.viz, 'get_exportable_sections'):
                sections = self.viz.get_exportable_sections()
            else:
                sections = list(self.viz.inputdata.keys())

            for section in sections:
                try:
                    csv_file = str(output_path / f"{prefix}_{section}.csv")
                    if hasattr(self.viz, 'export_csv'):
                        self.viz.export_csv(csv_file, section=section)
                    outputs[f"csv_{section}"] = csv_file
                except (ValueError, KeyError) as e:
                    logger.debug(f"Could not export section {section}: {e}")

        # YAML export
        if "yaml" in formats:
            yaml_file = str(output_path / f"{prefix}.yaml")
            exporter.to_yaml(self.viz.inputdata, yaml_file)
            outputs["yaml"] = yaml_file

        # Markdown summary
        if "md" in formats:
            md_file = str(output_path / f"{prefix}.md")
            self._generate_markdown_report(md_file)
            outputs["md"] = md_file

        logger.info(f"Generated report with {len(outputs)} files in {output_dir}")
        return outputs

    def _generate_markdown_report(self, output: str) -> None:
        """Generate a Markdown summary report."""
        lines = [
            f"# {self.viz.__class__.__name__} Report",
            "",
            f"**Source:** `{self.viz.inputfile}`",
            "",
        ]

        # Add stats if available
        stats = None
        if hasattr(self.viz, 'get_graph_stats'):
            stats = self.viz.get_graph_stats()
        elif hasattr(self.viz, 'get_file_stats'):
            stats = self.viz.get_file_stats()
        elif hasattr(self.viz, 'get_stats'):
            stats = self.viz.get_stats()

        if stats:
            lines.append("## Statistics")
            lines.append("")
            for key, value in stats.items():
                lines.append(f"- **{key}:** {value}")
            lines.append("")

        # Add data sections
        lines.append("## Data Sections")
        lines.append("")
        for key, value in self.viz.inputdata.items():
            if isinstance(value, list):
                lines.append(f"- **{key}:** {len(value)} items")
            elif isinstance(value, dict):
                lines.append(f"- **{key}:** {len(value)} entries")
            else:
                lines.append(f"- **{key}:** {type(value).__name__}")

        # Write
        with open(output, 'w', encoding='utf-8') as f:
            f.write("\n".join(lines))
