#
# VULNEX -Universal Security Visualization Library-
#
# File: threatmodeling.py
# Author: Simon Roses Femerling
# Created: 2025-01-01
# Last Modified: 2025-12-31
# Version: 0.3.3
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Threat Modeling Visualization Module.

This module provides visualization tools for threat modeling using Data Flow
Diagrams (DFD). Supports STRIDE methodology and custom threat analysis.

Supports two engines:
- usecvislib: Native visualization engine using Graphviz
- pytm: OWASP PyTM framework for comprehensive threat modeling

Elements supported:
- Processes: Internal system components
- Data Stores: Databases, files, caches
- External Entities: Users, external systems
- Data Flows: Communication between elements
- Trust Boundaries: Security perimeters
"""

import os
import sys
import tempfile
import html as html_module
from enum import Enum
from typing import Optional, List, Dict, Any, Tuple

import graphviz as gv

from . import utils
from .base import VisualizationBase
from .constants import cvss_to_severity_label
from .cvss_unified import get_cvss_score_unified as get_cvss_score
from .settings import is_cvss_enabled


class ThreatModelEngine(str, Enum):
    """Available threat modeling engines."""
    USECVISLIB = "usecvislib"
    PYTM = "pytm"


class PyTMWrapper:
    """Wrapper for OWASP PyTM framework.

    Converts our TOML-based threat model format to PyTM objects and
    generates visualizations and threat reports using PyTM's engine.
    """

    def __init__(self, inputdata: Dict[str, Any], outputfile: str, format: str = "png"):
        """Initialize PyTM wrapper.

        Args:
            inputdata: Parsed threat model data from TOML.
            outputfile: Output file path for visualization.
            format: Output format (png, svg, etc.).
        """
        self.inputdata = inputdata
        self.outputfile = outputfile
        self.format = format
        self.tm = None
        self.elements: Dict[str, Any] = {}
        self._pytm_available = self._check_pytm()

    def _check_pytm(self) -> bool:
        """Check if PyTM is available."""
        try:
            import pytm
            return True
        except ImportError:
            return False

    def build_model(self) -> None:
        """Build PyTM threat model from input data with full property mapping."""
        if not self._pytm_available:
            raise ImportError("pytm is not installed. Install it with: pip install pytm")

        from pytm import TM, Server, Process, Datastore, ExternalEntity, Dataflow, Boundary, Actor, Lambda

        model_data = self.inputdata.get("model", {})
        processes = self.inputdata.get("processes", {})
        datastores = self.inputdata.get("datastores", {})
        externals = self.inputdata.get("externals", {})
        dataflows = self.inputdata.get("dataflows", {})
        boundaries = self.inputdata.get("boundaries", {})

        # Create the threat model
        model_name = model_data.get("name", "Threat Model")
        model_desc = model_data.get("description", "")

        self.tm = TM(model_name)
        self.tm.description = model_desc
        self.tm.isOrdered = True

        # Create boundaries first
        boundary_objects: Dict[str, Boundary] = {}
        for boundary_id, boundary_data in boundaries.items():
            boundary_objects[boundary_id] = Boundary(boundary_data.get("label", boundary_id))

        # Helper to get boundary for an element
        def get_boundary(element_id: str) -> Optional[Boundary]:
            for b_id, b_data in boundaries.items():
                if element_id in b_data.get("elements", []):
                    return boundary_objects.get(b_id)
            return None

        # Helper to safely set PyTM attributes
        def set_attr_safe(obj: Any, attr: str, value: Any) -> None:
            """Set attribute on object if it exists."""
            if hasattr(obj, attr):
                try:
                    setattr(obj, attr, value)
                except Exception:
                    pass

        # Create external entities (as Actors in PyTM)
        for ext_id, ext_data in externals.items():
            label = ext_data.get("label", ext_id)
            boundary = get_boundary(ext_id)

            use_actor = ext_data.get("isHuman", True) or ext_data.get("isAdmin", False)

            if use_actor:
                element = Actor(label)
            else:
                element = ExternalEntity(label)

            if boundary:
                element.inBoundary = boundary

            ext_property_mappings = {
                "isAdmin": "isAdmin",
                "providesSourceAuthentication": "providesSourceAuthentication",
                "providesDestinationAuthentication": "providesDestinationAuthentication",
                "protocol": "protocol",
                "data": "data",
                "isTrusted": "isTrusted",
                "inScope": "inScope",
                "handlesInput": "handlesInput",
                "sanitizesInput": "sanitizesInput",
            }

            if ext_data.get("description"):
                set_attr_safe(element, 'description', ext_data.get("description"))

            for our_prop, pytm_prop in ext_property_mappings.items():
                if ext_data.get(our_prop) is not None:
                    set_attr_safe(element, pytm_prop, ext_data.get(our_prop))

            self.elements[ext_id] = element

        # Create processes with full property mapping
        for proc_id, proc_data in processes.items():
            label = proc_data.get("label", proc_id)
            boundary = get_boundary(proc_id)

            if proc_data.get("isLambda", False):
                element = Lambda(label)
            elif proc_data.get("isServer", False):
                element = Server(label)
            else:
                element = Process(label)

            if boundary:
                element.inBoundary = boundary

            if proc_data.get("description"):
                set_attr_safe(element, 'description', proc_data.get("description"))

            property_mappings = {
                "authenticatesSource": "authenticatesSource",
                "authenticatesDestination": "authenticatesDestination",
                "authorizesSource": "authorizesSource",
                "implementsAuthenticationScheme": "implementsAuthenticationScheme",
                "usesSessionTokens": "usesSessionTokens",
                "implementsPasswordPolicy": "implementsPasswordPolicy",
                "sanitizesInput": "sanitizesInput",
                "validatesInput": "validatesInput",
                "validatesHeaders": "validatesHeaders",
                "encodesOutput": "encodesOutput",
                "checksInputBounds": "checksInputBounds",
                "implementsServerSideValidation": "implementsServerSideValidation",
                "implementsStrictHTTPValidation": "implementsStrictHTTPValidation",
                "implementsCSRFToken": "implementsCSRFToken",
                "implementsNonce": "implementsNonce",
                "handlesResourceConsumption": "handlesResourceConsumption",
                "hasAccessControl": "hasAccessControl",
                "implementsPOLP": "implementsPOLP",
                "isHardened": "isHardened",
                "disablesdebugCode": "disablesdebugCode",
                "usesLatestTLSversion": "usesLatestTLSversion",
                "usesVPN": "usesVPN",
                "protocol": "protocol",
                "isEncrypted": "isEncrypted",
                "usesEnvironmentVariables": "usesEnvironmentVariables",
                "usesCache": "usesCache",
                "implementsAPI": "implementsAPI",
                "logsAllActions": "logsAllActions",
                "inScope": "inScope",
                "OS": "OS",
                "Environment": "Environment",
                "providesConfidentiality": "providesConfidentiality",
                "providesIntegrity": "providesIntegrity",
            }

            for our_prop, pytm_prop in property_mappings.items():
                if proc_data.get(our_prop) is not None:
                    set_attr_safe(element, pytm_prop, proc_data.get(our_prop))

            self.elements[proc_id] = element

        # Create datastores with full property mapping
        for ds_id, ds_data in datastores.items():
            label = ds_data.get("label", ds_id)
            boundary = get_boundary(ds_id)
            datastore = Datastore(label)

            if boundary:
                datastore.inBoundary = boundary

            if ds_data.get("description"):
                set_attr_safe(datastore, 'description', ds_data.get("description"))

            ds_property_mappings = {
                "isSQL": "isSQL",
                "type": "type",
                "isEncrypted": "isEncrypted",
                "isShared": "isShared",
                "hasAccessControl": "hasAccessControl",
                "isHardened": "isHardened",
                "implementsPOLP": "implementsPOLP",
                "storesPII": "storesPII",
                "storesCredentials": "storesCredentials",
                "storesLogData": "storesLogData",
                "storesSensitiveData": "storesSensitiveData",
                "hasBackup": "hasBackup",
                "isResilient": "isResilient",
                "isAuditLogged": "isAuditLogged",
                "validatesInput": "validatesInput",
                "usesEnvironmentVariables": "usesEnvironmentVariables",
                "usesFileSystem": "usesFileSystem",
                "inScope": "inScope",
                "maxClassification": "maxClassification",
            }

            for our_prop, pytm_prop in ds_property_mappings.items():
                if ds_data.get(our_prop) is not None:
                    set_attr_safe(datastore, pytm_prop, ds_data.get(our_prop))

            self.elements[ds_id] = datastore

        # Create dataflows with full property mapping
        for flow_id, flow_data in dataflows.items():
            source_id = flow_data.get("from", "")
            target_id = flow_data.get("to", "")
            label = flow_data.get("label", flow_id)

            source = self.elements.get(source_id)
            target = self.elements.get(target_id)

            if source and target:
                flow = Dataflow(source, target, label)

                if flow_data.get("protocol"):
                    set_attr_safe(flow, 'protocol', flow_data.get("protocol"))

                flow_property_mappings = {
                    "isEncrypted": "isEncrypted",
                    "usesLatestTLSversion": "usesLatestTLSversion",
                    "usesVPN": "usesVPN",
                    "authenticatesSource": "authenticatesSource",
                    "authenticatesDestination": "authenticatesDestination",
                    "authorizesSource": "authorizesSource",
                    "implementsAuthenticationScheme": "implementsAuthenticationScheme",
                    "checksDestinationRevocation": "checksDestinationRevocation",
                    "sanitizesInput": "sanitizesInput",
                    "validatesInput": "validatesInput",
                    "validatesHeaders": "validatesHeaders",
                    "isPII": "isPII",
                    "isCredentials": "isCredentials",
                    "maxClassification": "maxClassification",
                    "srcPort": "srcPort",
                    "dstPort": "dstPort",
                    "isResponse": "isResponse",
                    "responseTo": "responseTo",
                    "inScope": "inScope",
                    "order": "order",
                }

                for our_prop, pytm_prop in flow_property_mappings.items():
                    if flow_data.get(our_prop) is not None:
                        set_attr_safe(flow, pytm_prop, flow_data.get(our_prop))

                data_class = flow_data.get("data")
                if data_class:
                    set_attr_safe(flow, 'data', data_class)

                if flow_data.get("note"):
                    set_attr_safe(flow, 'note', flow_data.get("note"))

    def render(self) -> str:
        """Render the threat model visualization."""
        if not self.tm:
            self.build_model()
        return self._render_with_graphviz(None)

    def _render_with_graphviz(self, tmpdir: str = None) -> str:
        """Render using graphviz directly."""
        dot_content = None

        if self._pytm_available and self.tm:
            try:
                dot_content = self.tm.dfd()
            except Exception:
                pass

        if not dot_content:
            dot_content = self._generate_dot()

        graph = gv.Source(dot_content)
        graph.format = self.format
        output_path = graph.render(self.outputfile, cleanup=True)
        return output_path

    @staticmethod
    def _escape_dot_string(s: str) -> str:
        """Escape a string for safe use in DOT label attributes.

        SECURITY: Properly escapes all DOT special characters to prevent
        DOT injection attacks where malicious input could modify graph structure.
        """
        if not isinstance(s, str):
            s = str(s)
        # SECURITY: Escape backslash first to avoid double-escaping
        s = s.replace('\\', '\\\\')
        # Escape quotes
        s = s.replace('"', '\\"')
        # Escape control characters
        s = s.replace('\n', '\\n')
        s = s.replace('\r', '\\r')
        s = s.replace('\t', '\\t')
        # SECURITY: Escape HTML-like characters for HTML labels
        s = s.replace('<', '&lt;')
        s = s.replace('>', '&gt;')
        s = s.replace('&', '&amp;')
        # SECURITY: Escape DOT record/HTML label special characters
        s = s.replace('{', '\\{')
        s = s.replace('}', '\\}')
        s = s.replace('|', '\\|')
        # SECURITY: Escape semicolon to prevent statement injection
        s = s.replace(';', '\\;')
        return s

    @staticmethod
    def _sanitize_node_id(node_id: str) -> str:
        """Sanitize a node ID for safe use in DOT graphs."""
        import re
        if not isinstance(node_id, str):
            node_id = str(node_id)
        sanitized = re.sub(r'[^a-zA-Z0-9_-]', '_', node_id)
        if sanitized and sanitized[0].isdigit():
            sanitized = 'n_' + sanitized
        return sanitized or 'unnamed'

    def _generate_dot(self) -> str:
        """Generate DOT representation of the threat model."""
        lines = ['digraph ThreatModel {']
        lines.append('    rankdir=LR;')
        lines.append('    node [fontname="Arial"];')
        lines.append('    edge [fontname="Arial"];')

        model_data = self.inputdata.get("model", {})
        model_name = self._escape_dot_string(model_data.get("name", "Threat Model"))
        lines.append(f'    label="{model_name}";')
        lines.append('    labelloc=t;')

        boundaries = self.inputdata.get("boundaries", {})
        processes = self.inputdata.get("processes", {})
        datastores = self.inputdata.get("datastores", {})
        externals = self.inputdata.get("externals", {})
        dataflows = self.inputdata.get("dataflows", {})

        elements_in_boundaries: Dict[str, str] = {}
        for b_id, b_data in boundaries.items():
            for elem in b_data.get("elements", []):
                elements_in_boundaries[self._sanitize_node_id(elem)] = self._sanitize_node_id(b_id)

        for b_id, b_data in boundaries.items():
            safe_b_id = self._sanitize_node_id(b_id)
            safe_label = self._escape_dot_string(b_data.get("label", b_id))
            lines.append(f'    subgraph cluster_{safe_b_id} {{')
            lines.append(f'        label="{safe_label}";')
            lines.append('        style=dashed;')
            lines.append('        color=red;')

            for elem_id in b_data.get("elements", []):
                safe_elem_id = self._sanitize_node_id(elem_id)
                if elem_id in processes:
                    label = self._escape_dot_string(processes[elem_id].get("label", elem_id))
                    lines.append(f'        {safe_elem_id} [label="{label}", shape=box, style=filled, fillcolor="#4da6ff"];')
                elif elem_id in datastores:
                    label = self._escape_dot_string(datastores[elem_id].get("label", elem_id))
                    lines.append(f'        {safe_elem_id} [label="{label}", shape=cylinder, style=filled, fillcolor="#90EE90"];')
                elif elem_id in externals:
                    label = self._escape_dot_string(externals[elem_id].get("label", elem_id))
                    lines.append(f'        {safe_elem_id} [label="{label}", shape=box, style="filled,dashed", fillcolor="#D3D3D3"];')

            lines.append('    }')

        for proc_id, proc_data in processes.items():
            safe_proc_id = self._sanitize_node_id(proc_id)
            if safe_proc_id not in elements_in_boundaries:
                label = self._escape_dot_string(proc_data.get("label", proc_id))
                lines.append(f'    {safe_proc_id} [label="{label}", shape=box, style=filled, fillcolor="#4da6ff"];')

        for ds_id, ds_data in datastores.items():
            safe_ds_id = self._sanitize_node_id(ds_id)
            if safe_ds_id not in elements_in_boundaries:
                label = self._escape_dot_string(ds_data.get("label", ds_id))
                lines.append(f'    {safe_ds_id} [label="{label}", shape=cylinder, style=filled, fillcolor="#90EE90"];')

        for ext_id, ext_data in externals.items():
            safe_ext_id = self._sanitize_node_id(ext_id)
            if safe_ext_id not in elements_in_boundaries:
                label = self._escape_dot_string(ext_data.get("label", ext_id))
                lines.append(f'    {safe_ext_id} [label="{label}", shape=box, style="filled,dashed", fillcolor="#D3D3D3"];')

        for flow_id, flow_data in dataflows.items():
            source = self._sanitize_node_id(flow_data.get("from", ""))
            target = self._sanitize_node_id(flow_data.get("to", ""))
            label = self._escape_dot_string(flow_data.get("label", ""))
            lines.append(f'    {source} -> {target} [label="{label}"];')

        lines.append('}')
        return '\n'.join(lines)

    def get_threats(self) -> List[Dict[str, Any]]:
        """Get threats identified by PyTM."""
        if not self._pytm_available:
            return []

        if not self.tm:
            self.build_model()

        threats = []
        try:
            for finding in self.tm.findings:
                threats.append({
                    "id": finding.id if hasattr(finding, 'id') else "",
                    "threat": finding.description if hasattr(finding, 'description') else str(finding),
                    "severity": finding.severity if hasattr(finding, 'severity') else "Unknown",
                    "element": finding.target.name if hasattr(finding, 'target') else "",
                    "mitigation": finding.mitigations if hasattr(finding, 'mitigations') else ""
                })
        except Exception:
            pass

        return threats

    def generate_markdown_report(self) -> str:
        """Generate a Markdown threat report.

        Returns:
            Markdown formatted threat report.
        """
        if not self.tm:
            self.build_model()

        model_data = self.inputdata.get("model", {})
        model_name = model_data.get("name", "Threat Model")
        model_desc = model_data.get("description", "")

        lines = [
            f"# Threat Model Report: {model_name}",
            "",
            f"**Description:** {model_desc}" if model_desc else "",
            "",
            "## Model Overview",
            "",
            f"- **Processes:** {len(self.inputdata.get('processes', {}))}",
            f"- **Data Stores:** {len(self.inputdata.get('datastores', {}))}",
            f"- **External Entities:** {len(self.inputdata.get('externals', {}))}",
            f"- **Data Flows:** {len(self.inputdata.get('dataflows', {}))}",
            f"- **Trust Boundaries:** {len(self.inputdata.get('boundaries', {}))}",
            "",
            "## Identified Threats",
            "",
        ]

        threats = self.get_threats()
        if threats:
            for i, threat in enumerate(threats, 1):
                lines.append(f"### {i}. {threat.get('threat', 'Unknown Threat')}")
                lines.append("")
                if threat.get('element'):
                    lines.append(f"- **Element:** {threat['element']}")
                if threat.get('severity'):
                    lines.append(f"- **Severity:** {threat['severity']}")
                if threat.get('mitigation'):
                    lines.append(f"- **Mitigation:** {threat['mitigation']}")
                lines.append("")
        else:
            lines.append("No threats identified by the analysis engine.")
            lines.append("")

        lines.append("---")
        lines.append("*Report generated by USecVisLib*")

        return "\n".join(lines)

    def generate_html_report(self) -> str:
        """Generate an HTML threat report.

        SECURITY: All user-provided content is HTML-escaped to prevent XSS attacks.

        Returns:
            HTML formatted threat report.
        """
        if not self.tm:
            self.build_model()

        model_data = self.inputdata.get("model", {})
        # SECURITY: HTML-escape all user-provided content
        model_name = html_module.escape(str(model_data.get("name", "Threat Model")))
        model_desc = html_module.escape(str(model_data.get("description", "")))

        threats = self.get_threats()

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Threat Model Report: {model_name}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ max-width: 900px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 15px; }}
        h2 {{ color: #34495e; margin-top: 30px; }}
        .overview {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin: 20px 0; }}
        .stat {{ background: #ecf0f1; padding: 15px; border-radius: 6px; text-align: center; }}
        .stat-value {{ font-size: 2em; font-weight: bold; color: #3498db; }}
        .stat-label {{ color: #7f8c8d; font-size: 0.9em; }}
        .threat {{ background: #fff; border-left: 4px solid #e74c3c; padding: 15px 20px; margin: 15px 0; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
        .threat h3 {{ margin: 0 0 10px 0; color: #c0392b; }}
        .threat-meta {{ color: #7f8c8d; font-size: 0.9em; }}
        .threat-meta strong {{ color: #2c3e50; }}
        .footer {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid #ecf0f1; color: #95a5a6; font-size: 0.85em; text-align: center; }}
        .no-threats {{ background: #d5f5e3; padding: 20px; border-radius: 6px; color: #27ae60; text-align: center; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Threat Model Report: {model_name}</h1>
        {"<p>" + model_desc + "</p>" if model_desc else ""}

        <h2>Model Overview</h2>
        <div class="overview">
            <div class="stat">
                <div class="stat-value">{len(self.inputdata.get('processes', {}))}</div>
                <div class="stat-label">Processes</div>
            </div>
            <div class="stat">
                <div class="stat-value">{len(self.inputdata.get('datastores', {}))}</div>
                <div class="stat-label">Data Stores</div>
            </div>
            <div class="stat">
                <div class="stat-value">{len(self.inputdata.get('externals', {}))}</div>
                <div class="stat-label">External Entities</div>
            </div>
            <div class="stat">
                <div class="stat-value">{len(self.inputdata.get('dataflows', {}))}</div>
                <div class="stat-label">Data Flows</div>
            </div>
            <div class="stat">
                <div class="stat-value">{len(self.inputdata.get('boundaries', {}))}</div>
                <div class="stat-label">Trust Boundaries</div>
            </div>
        </div>

        <h2>Identified Threats</h2>
"""

        if threats:
            for i, threat in enumerate(threats, 1):
                # SECURITY: HTML-escape all user-provided threat data
                threat_name = html_module.escape(str(threat.get('threat', 'Unknown Threat')))
                threat_element = html_module.escape(str(threat.get('element', ''))) if threat.get('element') else ''
                threat_severity = html_module.escape(str(threat.get('severity', ''))) if threat.get('severity') else ''
                threat_mitigation = html_module.escape(str(threat.get('mitigation', ''))) if threat.get('mitigation') else ''

                html += f"""
        <div class="threat">
            <h3>{i}. {threat_name}</h3>
            <div class="threat-meta">
                {"<p><strong>Element:</strong> " + threat_element + "</p>" if threat_element else ""}
                {"<p><strong>Severity:</strong> " + threat_severity + "</p>" if threat_severity else ""}
                {"<p><strong>Mitigation:</strong> " + threat_mitigation + "</p>" if threat_mitigation else ""}
            </div>
        </div>
"""
        else:
            html += """
        <div class="no-threats">No threats identified by the analysis engine.</div>
"""

        html += """
        <div class="footer">
            Report generated by USecVisLib
        </div>
    </div>
</body>
</html>"""

        return html


class ThreatModeling(VisualizationBase):
    """Threat modeling visualization class using Data Flow Diagrams.

    Creates visual representations of system architecture for security
    analysis using the STRIDE methodology or custom threat frameworks.

    Supports TOML, JSON, and YAML input formats.

    Supports two engines:
    - usecvislib: Native visualization engine with custom styling
    - pytm: OWASP PyTM framework for comprehensive threat analysis

    Attributes:
        inputfile: Path to the configuration file (TOML, JSON, or YAML).
        outputfile: Path for the output visualization.
        format: Output format (png, pdf, svg, dot).
        styleid: Style identifier for visualization theming.
        engine: Threat modeling engine to use (usecvislib or pytm).
        inputdata: Parsed threat model data.
        style: Style configuration dictionary.
        graph: Graphviz graph object.
    """

    # Configuration for base class
    STYLE_FILE = "config_threatmodeling.tml"
    DEFAULT_STYLE_ID = "tm_default"
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
        engine: str = "usecvislib",
        validate_paths: bool = True
    ) -> None:
        """Initialize ThreatModeling with input/output paths and styling options.

        Args:
            inputfile: Path to the threat model file (TOML, JSON, or YAML).
            outputfile: Path for the output visualization.
            format: Output format (png, pdf, svg, dot). Defaults to png.
            styleid: Style identifier from config. Defaults to tm_default.
            engine: Engine to use ('usecvislib' or 'pytm'). Defaults to usecvislib.
            validate_paths: Whether to validate paths on initialization.

        Raises:
            SecurityError: If path validation fails (when validate_paths=True).
            FileNotFoundError: If input file doesn't exist (when validate_paths=True).
        """
        # Handle empty strings for backward compatibility
        if format == "":
            format = "png"
        if styleid == "":
            styleid = None  # Will use DEFAULT_STYLE_ID

        # Store engine before calling super().__init__
        self.engine = ThreatModelEngine(engine) if isinstance(engine, str) else engine

        # Initialize base class
        super().__init__(
            inputfile=inputfile,
            outputfile=outputfile,
            format=format,
            styleid=styleid,
            validate_paths=validate_paths
        )

        # Threat modeling specific state
        self.graph: Optional[gv.Digraph] = None
        self._pytm_wrapper: Optional[PyTMWrapper] = None

        # Backward compatibility
        self.stylefile = self.STYLE_FILE

        # SECURITY: Track temp input file for cleanup (used by builder)
        self._temp_input: Optional[str] = None

    def __del__(self):
        """SECURITY: Cleanup temporary input files on object destruction.

        This ensures temp files created by ThreatModelBuilder are properly
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
        """Return default style configuration for threat models."""
        return {
            "graph": {
                "rankdir": "LR",
                "bgcolor": "white",
                "fontname": "Arial"
            },
            "process": {
                "shape": "rectangle",
                "style": "filled",
                "fillcolor": "#3498db",
                "fontcolor": "white",
                "fontname": "Arial"
            },
            "datastore": {
                "shape": "cylinder",
                "style": "filled",
                "fillcolor": "#2ecc71",
                "fontcolor": "white",
                "fontname": "Arial"
            },
            "external": {
                "shape": "rectangle",
                "style": "filled,dashed",
                "fillcolor": "#95a5a6",
                "fontcolor": "white",
                "fontname": "Arial"
            },
            "dataflow": {
                "color": "#34495e",
                "style": "solid",
                "fontname": "Arial",
                "fontsize": "10"
            },
            "trustboundary": {
                "color": "#e74c3c",
                "style": "dashed",
                "penwidth": "2",
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
            'model' as the root key for threat models.
        """
        return "model"

    def _load_impl(self) -> Dict[str, Any]:
        """Load threat model data from configuration file."""
        try:
            data = utils.ReadConfigFile(self.inputfile)
            self.logger.debug(f"Loaded threat model with {len(data.get('processes', {}))} processes")
            return data
        except (utils.FileError, utils.ConfigError) as e:
            self.logger.error(f"Failed to load threat model from {self.inputfile}: {e}")
            raise

    def _render_impl(self) -> None:
        """Build the threat model graph from loaded data."""
        model = self.inputdata.get("model", {})
        processes = self.inputdata.get("processes", {})
        datastores = self.inputdata.get("datastores", {})
        externals = self.inputdata.get("externals", {})
        dataflows = self.inputdata.get("dataflows", {})
        boundaries = self.inputdata.get("boundaries", {})

        # Get styles
        graph_style = self.style.get("graph", self._default_style()["graph"])
        process_style = self.style.get("process", self._default_style()["process"])
        datastore_style = self.style.get("datastore", self._default_style()["datastore"])
        external_style = self.style.get("external", self._default_style()["external"])
        dataflow_style = self.style.get("dataflow", self._default_style()["dataflow"])

        # Create main graph
        self.graph = gv.Digraph(
            name=model.get("name", "Threat Model"),
            format=self.format
        )

        # Apply graph attributes
        graph_attrs = utils.stringify_dict(graph_style)
        self.graph.attr(**graph_attrs)

        # Track which elements are in boundaries
        elements_in_boundaries: Dict[str, str] = {}
        for boundary_id, boundary_data in boundaries.items():
            for element_id in boundary_data.get("elements", []):
                elements_in_boundaries[element_id] = boundary_id

        # Create boundary subgraphs
        boundary_subgraphs: Dict[str, gv.Digraph] = {}
        for boundary_id, boundary_data in boundaries.items():
            boundary_subgraphs[boundary_id] = self._create_subgraph_for_boundary(
                boundary_id, boundary_data, {}
            )

        # Add processes
        for proc_id, proc_data in processes.items():
            node_attrs = proc_data.copy() if isinstance(proc_data, dict) else {}
            # Check if node has an image and if user wants a styled background
            has_image = 'image' in node_attrs and node_attrs['image']
            proc_user_shape = proc_data.get('shape', '') if isinstance(proc_data, dict) else ''
            proc_user_style = proc_data.get('style', '') if isinstance(proc_data, dict) else ''
            proc_user_fillcolor = proc_data.get('fillcolor', '') if isinstance(proc_data, dict) else ''
            proc_wants_no_bg = proc_user_shape in ('none', 'plaintext', 'point')
            proc_wants_bg = ('filled' in str(proc_user_style).lower()) or bool(proc_user_fillcolor)
            proc_has_visible_shape = bool(proc_user_shape) and not proc_wants_no_bg
            user_set_shape = (proc_has_visible_shape or proc_wants_bg) and not proc_wants_no_bg
            # Strip style attributes when a non-default style is selected
            # This allows the selected style to override template colors
            node_attrs = self._strip_style_attrs(node_attrs)
            # Merge with defaults (style values take precedence when style selected)
            node_attrs = utils.merge_dicts(process_style, node_attrs)
            # Process image AFTER merge so icon settings take priority
            utils.process_node_image(node_attrs, proc_id, self.logger, preserve_shape=user_set_shape)
            # For nodes with icons, set fontcolor to black for readability
            if has_image and "fontcolor" not in proc_data:
                node_attrs["fontcolor"] = "black"
            node_attrs = utils.stringify_dict(node_attrs)
            label = node_attrs.pop("label", proc_id)

            if proc_id in elements_in_boundaries:
                boundary_subgraphs[elements_in_boundaries[proc_id]].node(proc_id, label, **node_attrs)
            else:
                self.graph.node(proc_id, label, **node_attrs)

        # Add data stores
        for ds_id, ds_data in datastores.items():
            node_attrs = ds_data.copy() if isinstance(ds_data, dict) else {}
            # Check if node has an image and if user wants a styled background
            has_image = 'image' in node_attrs and node_attrs['image']
            ds_user_shape = ds_data.get('shape', '') if isinstance(ds_data, dict) else ''
            ds_user_style = ds_data.get('style', '') if isinstance(ds_data, dict) else ''
            ds_user_fillcolor = ds_data.get('fillcolor', '') if isinstance(ds_data, dict) else ''
            ds_wants_no_bg = ds_user_shape in ('none', 'plaintext', 'point')
            ds_wants_bg = ('filled' in str(ds_user_style).lower()) or bool(ds_user_fillcolor)
            ds_has_visible_shape = bool(ds_user_shape) and not ds_wants_no_bg
            user_set_shape = (ds_has_visible_shape or ds_wants_bg) and not ds_wants_no_bg
            # Strip style attributes when a non-default style is selected
            # This allows the selected style to override template colors
            node_attrs = self._strip_style_attrs(node_attrs)
            # Merge with defaults (style values take precedence when style selected)
            node_attrs = utils.merge_dicts(datastore_style, node_attrs)
            # Process image AFTER merge so icon settings take priority
            utils.process_node_image(node_attrs, ds_id, self.logger, preserve_shape=user_set_shape)
            # For nodes with icons, set fontcolor to black for readability
            if has_image and "fontcolor" not in ds_data:
                node_attrs["fontcolor"] = "black"
            node_attrs = utils.stringify_dict(node_attrs)
            label = node_attrs.pop("label", ds_id)

            if ds_id in elements_in_boundaries:
                boundary_subgraphs[elements_in_boundaries[ds_id]].node(ds_id, label, **node_attrs)
            else:
                self.graph.node(ds_id, label, **node_attrs)

        # Add external entities
        for ext_id, ext_data in externals.items():
            node_attrs = ext_data.copy() if isinstance(ext_data, dict) else {}
            # Check if node has an image and if user wants a styled background
            has_image = 'image' in node_attrs and node_attrs['image']
            ext_user_shape = ext_data.get('shape', '') if isinstance(ext_data, dict) else ''
            ext_user_style = ext_data.get('style', '') if isinstance(ext_data, dict) else ''
            ext_user_fillcolor = ext_data.get('fillcolor', '') if isinstance(ext_data, dict) else ''
            ext_wants_no_bg = ext_user_shape in ('none', 'plaintext', 'point')
            ext_wants_bg = ('filled' in str(ext_user_style).lower()) or bool(ext_user_fillcolor)
            ext_has_visible_shape = bool(ext_user_shape) and not ext_wants_no_bg
            user_set_shape = (ext_has_visible_shape or ext_wants_bg) and not ext_wants_no_bg
            # Strip style attributes when a non-default style is selected
            # This allows the selected style to override template colors
            node_attrs = self._strip_style_attrs(node_attrs)
            # Merge with defaults (style values take precedence when style selected)
            node_attrs = utils.merge_dicts(external_style, node_attrs)
            # Process image AFTER merge so icon settings take priority
            utils.process_node_image(node_attrs, ext_id, self.logger, preserve_shape=user_set_shape)
            # For nodes with icons, set fontcolor to black for readability
            if has_image and "fontcolor" not in ext_data:
                node_attrs["fontcolor"] = "black"
            node_attrs = utils.stringify_dict(node_attrs)
            label = node_attrs.pop("label", ext_id)

            if ext_id in elements_in_boundaries:
                boundary_subgraphs[elements_in_boundaries[ext_id]].node(ext_id, label, **node_attrs)
            else:
                self.graph.node(ext_id, label, **node_attrs)

        # Add boundary subgraphs to main graph
        for subgraph in boundary_subgraphs.values():
            self.graph.subgraph(subgraph)

        # Add data flows (edges)
        for flow_id, flow_data in dataflows.items():
            source = flow_data.get("from", "")
            target = flow_data.get("to", "")
            label = flow_data.get("label", "")

            edge_attrs = {k: v for k, v in flow_data.items() if k not in ["from", "to", "label"]}
            edge_attrs = utils.merge_dicts(edge_attrs, dataflow_style)
            edge_attrs = utils.stringify_dict(edge_attrs)

            self.graph.edge(source, target, label=label, **edge_attrs)

        self.logger.debug(f"Rendered threat model with {len(processes)} processes")

    def _draw_impl(self, outputfile: str) -> None:
        """Save the threat model visualization to file."""
        if self.graph is None:
            raise utils.RenderError("Graph not rendered. Call render() first.")

        try:
            self.graph.render(outputfile, cleanup=True)
            self.logger.debug("Successfully wrote threat model visualization")
        except Exception as e:
            self.logger.error(f"Failed to render graph to {outputfile}: {e}")
            raise

    def _validate_impl(self) -> List[str]:
        """Validate the threat model structure."""
        errors = []

        processes = self.inputdata.get("processes", {})
        datastores = self.inputdata.get("datastores", {})
        externals = self.inputdata.get("externals", {})
        dataflows = self.inputdata.get("dataflows", {})
        boundaries = self.inputdata.get("boundaries", {})

        # Check for at least some elements
        if not processes and not datastores and not externals:
            errors.append("No elements (processes, datastores, externals) defined")

        # Check dataflow references
        all_elements = set(processes.keys()) | set(datastores.keys()) | set(externals.keys())

        for flow_id, flow_data in dataflows.items():
            source = flow_data.get("from", "")
            target = flow_data.get("to", "")

            if source and source not in all_elements:
                errors.append(f"Dataflow '{flow_id}' source '{source}' not defined")
            if target and target not in all_elements:
                errors.append(f"Dataflow '{flow_id}' target '{target}' not defined")

        # Check boundary element references
        for boundary_id, boundary_data in boundaries.items():
            for element_id in boundary_data.get("elements", []):
                if element_id not in all_elements:
                    errors.append(f"Boundary '{boundary_id}' references undefined element '{element_id}'")

        return errors

    def _get_stats_impl(self) -> Dict[str, Any]:
        """Get statistical summary of the threat model including STRIDE analysis."""
        processes = self.inputdata.get("processes", {})
        datastores = self.inputdata.get("datastores", {})
        externals = self.inputdata.get("externals", {})
        dataflows = self.inputdata.get("dataflows", {})
        boundaries = self.inputdata.get("boundaries", {})

        # Count flows crossing boundaries
        boundary_elements = set()
        for boundary_data in boundaries.values():
            boundary_elements.update(boundary_data.get("elements", []))

        crossing_flows = 0
        for flow_data in dataflows.values():
            source = flow_data.get("from", "")
            target = flow_data.get("to", "")
            source_in = source in boundary_elements
            target_in = target in boundary_elements
            if source_in != target_in:
                crossing_flows += 1

        # Get STRIDE threat statistics
        threats = self.analyze_stride()
        all_cvss = []
        threat_counts = {}
        for category, threat_list in threats.items():
            threat_counts[category] = len(threat_list)
            for threat in threat_list:
                if threat.get("cvss"):
                    all_cvss.append(threat["cvss"])

        total_threats = sum(threat_counts.values())
        avg_cvss = sum(all_cvss) / len(all_cvss) if all_cvss else 0
        max_cvss = max(all_cvss) if all_cvss else 0
        critical_threats = len([c for c in all_cvss if c >= 9.0])
        high_threats = len([c for c in all_cvss if 7.0 <= c < 9.0])

        return {
            "total_processes": len(processes),
            "total_datastores": len(datastores),
            "total_externals": len(externals),
            "total_dataflows": len(dataflows),
            "total_boundaries": len(boundaries),
            "flows_crossing_boundaries": crossing_flows,
            "total_elements": len(processes) + len(datastores) + len(externals),
            # STRIDE threat statistics
            "total_threats": total_threats,
            "threats_by_category": threat_counts,
            "average_cvss": round(avg_cvss, 2),
            "max_cvss": round(max_cvss, 1),
            "critical_threats": critical_threats,
            "high_threats": high_threats,
        }

    def _create_subgraph_for_boundary(self, boundary_id: str, boundary_data: Dict[str, Any],
                                       elements: Dict[str, Dict[str, Any]]) -> gv.Digraph:
        """Create a subgraph for a trust boundary."""
        boundary_style = self.style.get("trustboundary", self._default_style()["trustboundary"])

        subgraph = gv.Digraph(name=f"cluster_{boundary_id}")

        subgraph.attr(
            label=boundary_data.get("label", boundary_id),
            style=boundary_style.get("style", "dashed"),
            color=boundary_style.get("color", "#e74c3c"),
            penwidth=str(boundary_style.get("penwidth", "2")),
            fontname=boundary_style.get("fontname", "Arial")
        )

        return subgraph

    # Threat modeling specific methods

    def analyze_stride(self) -> Dict[str, List[Dict[str, Any]]]:
        """Analyze the threat model using STRIDE methodology.

        Returns threats with estimated CVSS scores based on severity.
        CVSS estimates:
        - CRITICAL threats: 9.0-10.0
        - HIGH threats: 7.0-8.9
        - MEDIUM threats: 4.0-6.9
        - LOW threats: 0.1-3.9
        """
        if not self._loaded:
            self.load()

        threats: Dict[str, List[Dict[str, Any]]] = {
            "Spoofing": [],
            "Tampering": [],
            "Repudiation": [],
            "Information Disclosure": [],
            "Denial of Service": [],
            "Elevation of Privilege": []
        }

        processes = self.inputdata.get("processes", {})
        datastores = self.inputdata.get("datastores", {})
        externals = self.inputdata.get("externals", {})
        dataflows = self.inputdata.get("dataflows", {})
        boundaries = self.inputdata.get("boundaries", {})

        # Check for user-defined threats with custom CVSS
        custom_threats = self.inputdata.get("threats", {})
        for threat_id, threat_data in custom_threats.items():
            category = threat_data.get("category", "Tampering")
            if category in threats:
                cvss_value = threat_data.get("cvss")
                cvss_vector = threat_data.get("cvss_vector")
                score, _ = get_cvss_score(cvss_value, cvss_vector)

                threats[category].append({
                    "element": threat_data.get("element", threat_id),
                    "threat": threat_data.get("threat", "User-defined threat"),
                    "mitigation": threat_data.get("mitigation", "Implement appropriate controls"),
                    "cvss": score,
                    "cvss_vector": cvss_vector,
                    "user_defined": True
                })

        # Build boundary membership map
        element_boundaries: Dict[str, Optional[str]] = {}
        for b_id, b_data in boundaries.items():
            for elem in b_data.get("elements", []):
                element_boundaries[elem] = b_id

        def crosses_trust_boundary(source: str, target: str) -> bool:
            source_boundary = element_boundaries.get(source)
            target_boundary = element_boundaries.get(target)
            return source_boundary != target_boundary

        # Analyze external entities
        for ext_id, ext_data in externals.items():
            label = ext_data.get("label", ext_id)
            is_admin = ext_data.get("isAdmin", False)
            is_trusted = ext_data.get("isTrusted", False)

            if is_admin:
                threats["Spoofing"].append({
                    "element": label,
                    "threat": f"CRITICAL: Admin user {label} could be impersonated",
                    "mitigation": "Implement MFA and privileged access management",
                    "cvss": 9.8  # Critical - admin impersonation
                })
            elif not is_trusted:
                threats["Spoofing"].append({
                    "element": label,
                    "threat": f"Untrusted entity {label} could be spoofed",
                    "mitigation": "Implement strong authentication",
                    "cvss": 7.5  # High - identity spoofing
                })

            threats["Repudiation"].append({
                "element": label,
                "threat": f"{label} could deny performing actions",
                "mitigation": "Implement comprehensive audit logging",
                "cvss": 5.3  # Medium - non-repudiation
            })

        # Analyze processes
        for proc_id, proc_data in processes.items():
            label = proc_data.get("label", proc_id)
            sanitizes_input = proc_data.get("sanitizesInput", False)
            has_access_control = proc_data.get("hasAccessControl", False)
            handles_resources = proc_data.get("handlesResourceConsumption", False)

            if not sanitizes_input:
                threats["Tampering"].append({
                    "element": label,
                    "threat": f"{label} does not sanitize inputs",
                    "mitigation": "Implement input validation and sanitization",
                    "cvss": 8.6  # High - input tampering can lead to injection
                })

            if not handles_resources:
                threats["Denial of Service"].append({
                    "element": label,
                    "threat": f"{label} may not handle resource exhaustion",
                    "mitigation": "Implement rate limiting and resource quotas",
                    "cvss": 7.5  # High - availability impact
                })

            if not has_access_control:
                threats["Elevation of Privilege"].append({
                    "element": label,
                    "threat": f"{label} lacks access control",
                    "mitigation": "Implement RBAC/ABAC",
                    "cvss": 8.8  # High - privilege escalation
                })

        # Analyze data stores
        for ds_id, ds_data in datastores.items():
            label = ds_data.get("label", ds_id)
            is_encrypted = ds_data.get("isEncrypted", False)
            stores_pii = ds_data.get("storesPII", False)
            stores_credentials = ds_data.get("storesCredentials", False)

            if not is_encrypted:
                if stores_credentials:
                    cvss_score = 9.8  # Critical - credential exposure
                    severity = "CRITICAL"
                elif stores_pii:
                    cvss_score = 9.1  # Critical - PII exposure
                    severity = "CRITICAL"
                else:
                    cvss_score = 7.5  # High - data exposure
                    severity = "HIGH"

                threats["Information Disclosure"].append({
                    "element": label,
                    "threat": f"{severity}: {label} is not encrypted at rest",
                    "mitigation": "Enable encryption at rest",
                    "cvss": cvss_score
                })

        # Analyze data flows
        for flow_id, flow_data in dataflows.items():
            source = flow_data.get("from", "")
            target = flow_data.get("to", "")
            label = flow_data.get("label", flow_id)
            is_encrypted = flow_data.get("isEncrypted", False)

            if not is_encrypted:
                threats["Information Disclosure"].append({
                    "element": label,
                    "threat": f"Flow '{label}' transmits data unencrypted",
                    "mitigation": "Encrypt all data in transit using TLS",
                    "cvss": 7.5  # High - data in transit exposure
                })

            if crosses_trust_boundary(source, target) and not is_encrypted:
                threats["Tampering"].append({
                    "element": label,
                    "threat": f"Flow '{label}' crosses trust boundary without encryption",
                    "mitigation": "Encrypt all data crossing trust boundaries",
                    "cvss": 8.1  # High - cross-boundary tampering
                })

        return threats

    def generate_stride_report(self, output: Optional[str] = None) -> str:
        """Generate a STRIDE threat analysis report with CVSS scores."""
        threats = self.analyze_stride()
        model = self.inputdata.get("model", {})
        model_name = model.get("name", "Threat Model")

        # Check if CVSS display is enabled for threat models
        show_cvss = is_cvss_enabled("threat_model")

        # Calculate summary statistics
        all_cvss = []
        for threat_list in threats.values():
            for threat in threat_list:
                if threat.get("cvss"):
                    all_cvss.append(threat["cvss"])

        total_threats = sum(len(tl) for tl in threats.values())

        report_lines = [
            f"# STRIDE Threat Analysis Report",
            f"## Model: {model_name}",
            "",
            "## Risk Summary",
            f"- **Total Threats:** {total_threats}",
        ]

        # Include CVSS statistics only if CVSS display is enabled
        if show_cvss and all_cvss:
            avg_cvss = sum(all_cvss) / len(all_cvss) if all_cvss else 0
            max_cvss = max(all_cvss) if all_cvss else 0
            critical_count = len([c for c in all_cvss if c >= 9.0])
            high_count = len([c for c in all_cvss if 7.0 <= c < 9.0])
            report_lines.extend([
                f"- **Average CVSS:** {avg_cvss:.1f}",
                f"- **Maximum CVSS:** {max_cvss:.1f}",
                f"- **Critical Threats (CVSS >= 9.0):** {critical_count}",
                f"- **High Threats (CVSS 7.0-8.9):** {high_count}",
            ])

        report_lines.extend([
            "",
            "---",
            ""
        ])

        for category, threat_list in threats.items():
            report_lines.append(f"## {category}")
            report_lines.append("")

            if not threat_list:
                report_lines.append("No threats identified in this category.")
            else:
                # Sort by CVSS score (highest first) if CVSS is shown
                if show_cvss:
                    sorted_threats = sorted(
                        threat_list,
                        key=lambda t: t.get("cvss", 0),
                        reverse=True
                    )
                else:
                    sorted_threats = threat_list

                for i, threat in enumerate(sorted_threats, 1):
                    user_defined = " (User-defined)" if threat.get("user_defined") else ""

                    report_lines.append(f"### {i}. {threat['element']}{user_defined}")
                    # Include CVSS only if display is enabled
                    if show_cvss:
                        cvss = threat.get("cvss")
                        if cvss:
                            severity = cvss_to_severity_label(cvss)
                            report_lines.append(f"- **CVSS Score:** {cvss} ({severity})")
                    report_lines.append(f"- **Threat:** {threat['threat']}")
                    report_lines.append(f"- **Mitigation:** {threat['mitigation']}")
                    report_lines.append("")

            report_lines.append("---")
            report_lines.append("")

        report = "\n".join(report_lines)

        if output:
            with open(output, 'w') as f:
                f.write(report)

        return report

    # Backward compatibility methods

    def Render(self) -> None:
        """Deprecated: Use render() instead."""
        self.render()

    def get_model_stats(self) -> Dict[str, Any]:
        """Deprecated: Use get_stats() instead."""
        return self.get_stats()

    def BuildThreatModel(self) -> None:
        """Main entry point for threat model visualization.

        Deprecated: Use build() instead.
        """
        self.load()

        if self.engine == ThreatModelEngine.PYTM:
            self._pytm_wrapper = PyTMWrapper(
                self.inputdata,
                self.outputfile,
                self.format
            )
            self._pytm_wrapper.render()
        else:
            self.render()
            self.draw()

    def get_pytm_threats(self) -> List[Dict[str, Any]]:
        """Get threats identified by PyTM engine."""
        if self.engine != ThreatModelEngine.PYTM:
            return []

        if not self._pytm_wrapper:
            self.load()
            self._pytm_wrapper = PyTMWrapper(
                self.inputdata,
                self.outputfile,
                self.format
            )
            self._pytm_wrapper.build_model()

        return self._pytm_wrapper.get_threats()

    @staticmethod
    def get_available_engines() -> List[str]:
        """Get list of available threat modeling engines."""
        return [e.value for e in ThreatModelEngine]

    @staticmethod
    def is_pytm_available() -> bool:
        """Check if PyTM is installed and available."""
        try:
            import pytm
            return True
        except ImportError:
            return False

    # =========================================================================
    # Export/Conversion Methods
    # =========================================================================

    def to_mermaid_diagram(self) -> "MermaidDiagrams":
        """Convert to MermaidDiagrams format.

        Returns:
            MermaidDiagrams instance ready to render.

        Example:
            >>> tm = ThreatModeling("model.toml", "output")
            >>> md = tm.to_mermaid_diagram()
            >>> md.render("output", format="svg")
        """
        from .mermaiddiagrams import MermaidDiagrams
        return MermaidDiagrams.from_threat_model(self.inputfile)

    def to_cloud_diagram(self) -> "CloudDiagrams":
        """Convert to CloudDiagrams format.

        Returns:
            CloudDiagrams instance ready to render.

        Example:
            >>> tm = ThreatModeling("model.toml", "output")
            >>> cd = tm.to_cloud_diagram()
            >>> cd.render("output", format="png")
        """
        from .clouddiagrams import CloudDiagrams
        return CloudDiagrams.from_threat_model(self.inputfile)

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
