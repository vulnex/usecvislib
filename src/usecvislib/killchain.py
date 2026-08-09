#
# VULNEX -Universal Security Visualization Library-
#
# File: killchain.py
# Author: Simon Roses Femerling
# Created: 2026-08-09
# Last Modified: 2026-08-09
# Version: 0.4.1
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Kill Chain / MITRE ATT&CK visualization module (CLI mode 9).

Renders attack progression through a standardized framework as a linear
sequence of phases, each holding the techniques mapped to it:

- **Cyber Kill Chain** (Lockheed Martin): 7 phases, reconnaissance ->
  actions on objectives.
- **MITRE ATT&CK**: 14 Enterprise tactics as the phase axis.
- **Custom**: phases declared in the input file.

Built SVG-native on the engine's LinearLayout (the Graphviz path draws the
same phases as ranked clusters). Techniques carry detection/mitigation
coverage, which drives a coverage heat coloring and a small D/M badge, so
the diagram doubles as a detection-gap map.

Input schema (TOML/JSON/YAML)::

    [killchain]
    name = "..."
    framework = "kill_chain" | "attack" | "custom"
    phases = ["Recon", ...]        # custom framework only

    [techniques."T1566"]
    name = "Phishing"
    phase = "Delivery"             # kill-chain phase or ATT&CK tactic
    severity = "high"
    detected = true
    mitigated = false

    [[incidents]]
    id = "INC-1"
    name = "..."
    techniques = ["T1566", "T1204", ...]   # ordered path
"""

from dataclasses import dataclass, field
from enum import Enum
from itertools import pairwise
from typing import Any, Optional

from . import utils
from .base import VisualizationBase

try:  # Graphviz is optional at import time (SVG engine works without it)
    from graphviz import Digraph
except ImportError:  # pragma: no cover
    Digraph = None  # type: ignore[assignment,misc]


class KillChainError(utils.RenderError):
    """Raised when kill chain rendering or validation fails."""


class KillChainPhase(str, Enum):
    """Lockheed Martin Cyber Kill Chain phases (in order)."""

    RECONNAISSANCE = "Reconnaissance"
    WEAPONIZATION = "Weaponization"
    DELIVERY = "Delivery"
    EXPLOITATION = "Exploitation"
    INSTALLATION = "Installation"
    COMMAND_AND_CONTROL = "Command and Control"
    ACTIONS_ON_OBJECTIVES = "Actions on Objectives"


class ATTACKTactic(str, Enum):
    """MITRE ATT&CK Enterprise tactics (in order)."""

    RECONNAISSANCE = "Reconnaissance"
    RESOURCE_DEVELOPMENT = "Resource Development"
    INITIAL_ACCESS = "Initial Access"
    EXECUTION = "Execution"
    PERSISTENCE = "Persistence"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    DEFENSE_EVASION = "Defense Evasion"
    CREDENTIAL_ACCESS = "Credential Access"
    DISCOVERY = "Discovery"
    LATERAL_MOVEMENT = "Lateral Movement"
    COLLECTION = "Collection"
    COMMAND_AND_CONTROL = "Command and Control"
    EXFILTRATION = "Exfiltration"
    IMPACT = "Impact"


KILL_CHAIN_ORDER = [p.value for p in KillChainPhase]
ATTACK_TACTIC_ORDER = [t.value for t in ATTACKTactic]

# Alternate spellings accepted for a phase/tactic on a technique.
_PHASE_ALIASES = {
    "recon": "Reconnaissance",
    "c2": "Command and Control",
    "command and control": "Command and Control",
    "command & control": "Command and Control",
    "actions on objective": "Actions on Objectives",
    "actions": "Actions on Objectives",
    "priv esc": "Privilege Escalation",
    "privesc": "Privilege Escalation",
}

_VALID_SEVERITIES = {"critical", "high", "medium", "low", "none", "info"}


def _html_escape(text: str) -> str:
    """Escape text for use inside a Graphviz HTML-like label."""
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


@dataclass
class Technique:
    """A single technique/step mapped to a phase."""

    id: str
    name: str
    phase: str
    description: str = ""
    severity: str = "medium"
    detected: bool = False
    mitigated: bool = False
    detection: str = ""
    mitigation: str = ""

    @property
    def coverage_score(self) -> float:
        """Detection+mitigation coverage in [0, 1] (0.5 each)."""
        return 0.5 * self.detected + 0.5 * self.mitigated


@dataclass
class IncidentMapping:
    """An ordered technique path through the chain (one incident)."""

    incident_id: str
    name: str
    techniques: list[str] = field(default_factory=list)
    threat_actor: Optional[str] = None
    campaign: Optional[str] = None


class KillChain(VisualizationBase):
    """Kill Chain / MITRE ATT&CK linear progression visualization.

    Supports ``render_engine="svg"`` (native, LinearLayout swimlane) and
    ``render_engine="graphviz"`` (ranked phase clusters).
    """

    STYLE_FILE = "config_killchain.tml"
    DEFAULT_STYLE_ID = "kc_default"
    SVG_DEFAULT_STYLE_ID = "sv_default"
    SUPPORTED_VIEWS = ("chain",)

    def __init__(
        self,
        inputfile: str,
        outputfile: str,
        format: str = "png",
        styleid: Optional[str] = None,
        validate_paths: bool = True,
        render_engine: str = "graphviz",
        view: str = "chain",
    ) -> None:
        super().__init__(
            inputfile,
            outputfile,
            format=format or "png",
            styleid=styleid,
            validate_paths=validate_paths,
            render_engine=render_engine,
        )
        self.view = view if view in self.SUPPORTED_VIEWS else "chain"
        self.dot: Optional[Any] = None
        self.framework: str = "kill_chain"
        self.techniques: dict[str, Technique] = {}
        self.incidents: list[IncidentMapping] = []
        self.phase_order: list[str] = list(KILL_CHAIN_ORDER)
        self.warnings: list[str] = []

    # --------------------------------------------------------- framework order

    def _resolve_phase_order(self, data: dict[str, Any]) -> list[str]:
        """Pick the ordered phase axis for the configured framework."""
        kc = data.get("killchain", {}) if isinstance(data.get("killchain"), dict) else {}
        self.framework = str(kc.get("framework", "kill_chain")).lower().replace("-", "_")
        if self.framework in ("attack", "mitre", "mitre_attack", "attck"):
            self.framework = "attack"
            return list(ATTACK_TACTIC_ORDER)
        if self.framework == "custom":
            phases = kc.get("phases")
            if not isinstance(phases, list) or not phases:
                raise KillChainError("Custom framework requires a non-empty killchain.phases list")
            return [str(p) for p in phases]
        self.framework = "kill_chain"
        return list(KILL_CHAIN_ORDER)

    def _canonical_phase(self, raw: str) -> Optional[str]:
        """Map a technique's declared phase onto the framework axis."""
        value = str(raw).strip()
        if value in self.phase_order:
            return value
        alias = _PHASE_ALIASES.get(value.lower())
        if alias and alias in self.phase_order:
            return alias
        # Case-insensitive match against the axis.
        for phase in self.phase_order:
            if phase.lower() == value.lower():
                return phase
        return None

    # --------------------------------------------------------- VisualizationBase

    def _default_style(self) -> dict[str, Any]:
        """Fallback style if the config file is unavailable (clean, light)."""
        return {
            "graph": {
                "rankdir": "LR",
                "bgcolor": "#f8fafc",
                "fontname": "Helvetica",
                "fontcolor": "#334155",
                "fontsize": "16",
                "pad": "0.4",
                "nodesep": "0.28",
                "ranksep": "0.6",
                "labelloc": "t",
            },
            "phase": {
                "style": "filled,rounded",
                "fillcolor": "#eef2f7",
                "color": "#cbd5e1",
                "fontcolor": "#1e3a5f",
                "fontname": "Helvetica-Bold",
                "fontsize": "13",
                "penwidth": "1",
            },
            "technique": {
                "fontname": "Helvetica",
                "fontcolor": "#ffffff",
                "fillcolor": "#e0a53f",
                "color": "#64748b",
                "fontsize": "10",
                "penwidth": "1",
            },
            "edge": {"color": "#94a3b8", "penwidth": "1.6", "arrowhead": "vee", "arrowsize": "0.7"},
            "detected": {"fillcolor": "#27ae60", "fontcolor": "#ffffff"},
            "partial": {"fillcolor": "#e0a53f", "fontcolor": "#1a2733"},
            "not_detected": {"fillcolor": "#e74c3c", "fontcolor": "#ffffff"},
        }

    def _load_impl(self) -> dict[str, Any]:
        """Load and parse the kill chain configuration."""
        data = utils.ReadConfigFile(self.inputfile)
        if not isinstance(data, dict):
            raise KillChainError("Kill chain input must be a mapping")

        self.phase_order = self._resolve_phase_order(data)
        self.techniques.clear()
        self.incidents.clear()
        self.warnings.clear()

        raw_techniques = data.get("techniques", {})
        if not isinstance(raw_techniques, dict):
            raise KillChainError("'techniques' must be a table of technique definitions")

        for tech_id, td in raw_techniques.items():
            td = td if isinstance(td, dict) else {}
            declared = td.get("phase") or td.get("tactic") or ""
            phase = self._canonical_phase(declared)
            if phase is None:
                self.warnings.append(
                    f"Technique '{tech_id}': phase '{declared}' not in the {self.framework} axis; placed in the first phase"
                )
                phase = self.phase_order[0]
            severity = str(td.get("severity", "medium")).lower()
            if severity not in _VALID_SEVERITIES:
                self.warnings.append(f"Technique '{tech_id}': unknown severity '{severity}', using medium")
                severity = "medium"
            self.techniques[str(tech_id)] = Technique(
                id=str(tech_id),
                name=str(td.get("name", tech_id)),
                phase=phase,
                description=str(td.get("description", "")),
                severity=severity,
                detected=bool(td.get("detected", False)),
                mitigated=bool(td.get("mitigated", False)),
                detection=str(td.get("detection", "")),
                mitigation=str(td.get("mitigation", "")),
            )

        raw_incidents = data.get("incidents", [])
        if isinstance(raw_incidents, list):
            for inc in raw_incidents:
                if not isinstance(inc, dict):
                    continue
                self.incidents.append(
                    IncidentMapping(
                        incident_id=str(inc.get("id", "")),
                        name=str(inc.get("name", inc.get("id", "incident"))),
                        techniques=[str(t) for t in inc.get("techniques", []) if isinstance(t, str | int)],
                        threat_actor=inc.get("threat_actor"),
                        campaign=inc.get("campaign"),
                    )
                )

        utils.check_graph_complexity(len(self.techniques), sum(len(i.techniques) for i in self.incidents))
        return data

    def techniques_by_phase(self) -> dict[str, list[Technique]]:
        """Techniques grouped under each phase, in declaration order."""
        grouped: dict[str, list[Technique]] = {phase: [] for phase in self.phase_order}
        for tech in self.techniques.values():
            grouped.setdefault(tech.phase, []).append(tech)
        return grouped

    def active_phases(self) -> list[str]:
        """Phases that actually hold techniques, in framework order."""
        grouped = self.techniques_by_phase()
        return [phase for phase in self.phase_order if grouped.get(phase)]

    def _render_impl(self) -> None:
        """Build the Graphviz representation (ranked phase columns)."""
        if Digraph is None:  # pragma: no cover
            raise KillChainError("graphviz is required for render_engine='graphviz'")

        style = self.style if isinstance(self.style, dict) else self._default_style()
        name = self.inputdata.get("killchain", {}).get("name", "Kill Chain")
        self.dot = Digraph(name=name, format=self.format)
        self.dot.attr(**utils.stringify_dict(style.get("graph", self._default_style()["graph"])))
        self.dot.attr(label=name, labelloc="t", fontsize="16")

        phase_style = style.get("phase", self._default_style()["phase"])
        grouped = self.techniques_by_phase()
        phases = self.active_phases() or self.phase_order

        # One cluster per phase, ranked left to right. Technique nodes are
        # added to the CLUSTER (not the root graph) so each lands under its
        # phase header; a hidden anchor per phase orders the columns via
        # invisible anchor->anchor edges (works even for empty phases).
        prev_anchor = None
        for phase in phases:
            key = utils.sanitize_node_id(phase)
            with self.dot.subgraph(name=f"cluster_{key}") as sub:
                attrs = utils.stringify_dict(dict(phase_style))
                sub.attr(label=f"  {phase}  ", **{k: v for k, v in attrs.items() if k != "label"})
                anchor = f"__anchor_{key}"
                sub.node(anchor, "", shape="point", width="0", height="0", style="invis")
                for tech in grouped.get(phase, []):
                    sub.node(tech.id, label=self._graphviz_label(tech), **self._graphviz_tech_style(tech, style))
            if prev_anchor is not None:
                self.dot.edge(prev_anchor, anchor, style="invis")
            prev_anchor = anchor

        # Incident technique-to-technique flow edges.
        edge_style = utils.stringify_dict(style.get("edge", self._default_style()["edge"]))
        for incident in self.incidents:
            for src, dst in pairwise(incident.techniques):
                if src in self.techniques and dst in self.techniques:
                    self.dot.edge(src, dst, **edge_style)

    @staticmethod
    def _coverage_state(tech: Technique) -> str:
        if tech.detected and tech.mitigated:
            return "covered"
        if tech.detected or tech.mitigated:
            return "partial"
        return "gap"

    def _graphviz_label(self, tech: Technique) -> str:
        """HTML-like node label: id (bold) / name / a readable coverage line.

        Beats raw ``[D-]`` bracket text jammed into a plain label - the
        coverage reads as words, and HTML tables keep the card tidy.
        """
        state = self._coverage_state(tech)
        if state == "covered":
            coverage = "Detected + Mitigated"
        elif state == "partial":
            coverage = "Detected" if tech.detected else "Mitigated"
        else:
            coverage = "No coverage"
        name = _html_escape(tech.name)
        rows = ""
        if tech.id and tech.id != tech.name:
            rows += f"<TR><TD><B>{_html_escape(tech.id)}</B></TD></TR>"
        rows += f"<TR><TD>{name}</TD></TR>"
        rows += f'<TR><TD><FONT POINT-SIZE="9">{coverage}</FONT></TD></TR>'
        return f'<<TABLE BORDER="0" CELLBORDER="0" CELLSPACING="0" CELLPADDING="1">{rows}</TABLE>>'

    def _graphviz_tech_style(self, tech: Technique, style: dict[str, Any]) -> dict[str, str]:
        base = dict(style.get("technique", self._default_style()["technique"]))
        # 3-state coverage palette: covered=green, partial=amber, gap=red.
        key = {"covered": "detected", "partial": "partial", "gap": "not_detected"}[self._coverage_state(tech)]
        override = style.get(key, {})
        if override.get("fillcolor"):
            base["fillcolor"] = override["fillcolor"]
        if override.get("fontcolor"):
            base["fontcolor"] = override["fontcolor"]
        base.setdefault("shape", "box")
        base.setdefault("style", "rounded,filled")
        base.setdefault("margin", "0.14,0.07")
        return utils.stringify_dict(base)

    def _draw_impl(self, outputfile: str) -> None:
        if self.dot is None:
            raise KillChainError("Graph not rendered; call render() first")
        self.dot.render(outputfile, cleanup=True)

    def _validate_impl(self) -> list[str]:
        errors = list(self.warnings)
        if not self.techniques:
            errors.append("No techniques defined")
        for incident in self.incidents:
            for tech_id in incident.techniques:
                if tech_id not in self.techniques:
                    errors.append(f"Incident '{incident.name}' references unknown technique: {tech_id}")
        return errors

    def _get_stats_impl(self) -> dict[str, Any]:
        total = len(self.techniques)
        detected = sum(1 for t in self.techniques.values() if t.detected)
        mitigated = sum(1 for t in self.techniques.values() if t.mitigated)
        grouped = self.techniques_by_phase()
        return {
            "name": self.inputdata.get("killchain", {}).get("name", "Kill Chain"),
            "framework": self.framework,
            "total_techniques": total,
            "total_incidents": len(self.incidents),
            "detected_techniques": detected,
            "mitigated_techniques": mitigated,
            "detection_coverage": (detected / total) if total else 0.0,
            "mitigation_coverage": (mitigated / total) if total else 0.0,
            "active_phases": self.active_phases(),
            "techniques_per_phase": {p: len(grouped.get(p, [])) for p in self.phase_order},
            "warnings": list(self.warnings),
        }

    # -------------------------------------------------------------- analysis

    def analyze_coverage_gaps(self) -> dict[str, list[str]]:
        """Detection/mitigation gap lists for the loaded techniques."""
        return {
            "undetected": [t.id for t in self.techniques.values() if not t.detected],
            "unmitigated": [t.id for t in self.techniques.values() if not t.mitigated],
            "critical_gaps": [
                t.id
                for t in self.techniques.values()
                if not t.detected and not t.mitigated and t.severity in ("critical", "high")
            ],
        }

    def _get_metadata_root_key(self) -> str:
        return "killchain"

    # Convenience wrapper mirroring the other modules' Build* entry points.
    def BuildKillChain(self) -> "KillChain":
        """Load, render, and draw in one call."""
        self.build()
        return self
