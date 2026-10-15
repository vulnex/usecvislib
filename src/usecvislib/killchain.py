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
- **MITRE ATLAS**: the 16 tactics of the AI/ML counterpart to ATT&CK
  (ATLAS 5.6.0). A technique's phase may also be a tactic ID
  (``AML.TA0004``); technique IDs (``AML.T0051``) are free-form, as for
  ATT&CK.
- **Custom**: phases declared in the input file.

Built SVG-native on the engine's LinearLayout (the Graphviz path draws the
same phases as ranked clusters). Techniques carry detection/mitigation
coverage, which drives a coverage heat coloring and a small D/M badge, so
the diagram doubles as a detection-gap map.

Input schema (TOML/JSON/YAML)::

    [killchain]
    name = "..."
    framework = "kill_chain" | "attack" | "atlas" | "custom"
    phases = ["Recon", ...]        # custom framework only

    [techniques."T1566"]
    name = "Phishing"
    phase = "Delivery"             # kill-chain phase, ATT&CK or ATLAS tactic
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
from itertools import chain, count, pairwise
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


class ATLASTactic(str, Enum):
    """MITRE ATLAS tactics, in matrix order (ATLAS 5.6.0)."""

    RECONNAISSANCE = "Reconnaissance"
    RESOURCE_DEVELOPMENT = "Resource Development"
    INITIAL_ACCESS = "Initial Access"
    AI_MODEL_ACCESS = "AI Model Access"
    EXECUTION = "Execution"
    PERSISTENCE = "Persistence"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    DEFENSE_EVASION = "Defense Evasion"
    CREDENTIAL_ACCESS = "Credential Access"
    DISCOVERY = "Discovery"
    LATERAL_MOVEMENT = "Lateral Movement"
    COLLECTION = "Collection"
    AI_ATTACK_STAGING = "AI Attack Staging"
    COMMAND_AND_CONTROL = "Command and Control"
    EXFILTRATION = "Exfiltration"
    IMPACT = "Impact"


# ATLAS tactic IDs (the IDs are not in matrix order)
ATLAS_TACTIC_IDS = {
    "AML.TA0002": ATLASTactic.RECONNAISSANCE.value,
    "AML.TA0003": ATLASTactic.RESOURCE_DEVELOPMENT.value,
    "AML.TA0004": ATLASTactic.INITIAL_ACCESS.value,
    "AML.TA0000": ATLASTactic.AI_MODEL_ACCESS.value,
    "AML.TA0005": ATLASTactic.EXECUTION.value,
    "AML.TA0006": ATLASTactic.PERSISTENCE.value,
    "AML.TA0012": ATLASTactic.PRIVILEGE_ESCALATION.value,
    "AML.TA0007": ATLASTactic.DEFENSE_EVASION.value,
    "AML.TA0013": ATLASTactic.CREDENTIAL_ACCESS.value,
    "AML.TA0008": ATLASTactic.DISCOVERY.value,
    "AML.TA0015": ATLASTactic.LATERAL_MOVEMENT.value,
    "AML.TA0009": ATLASTactic.COLLECTION.value,
    "AML.TA0001": ATLASTactic.AI_ATTACK_STAGING.value,
    "AML.TA0014": ATLASTactic.COMMAND_AND_CONTROL.value,
    "AML.TA0010": ATLASTactic.EXFILTRATION.value,
    "AML.TA0011": ATLASTactic.IMPACT.value,
}

KILL_CHAIN_ORDER = [p.value for p in KillChainPhase]
ATTACK_TACTIC_ORDER = [t.value for t in ATTACKTactic]
ATLAS_TACTIC_ORDER = [t.value for t in ATLASTactic]

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
    # ATLAS tactics before ATLAS renamed "ML" to "AI"
    "ml model access": "AI Model Access",
    "ml attack staging": "AI Attack Staging",
}

_VALID_SEVERITIES = {"critical", "high", "medium", "low", "none", "info"}


def _slot_id(phase_key: str, row: int) -> str:
    """Node id of a phase's invisible placeholder slot."""
    return f"__slot_{phase_key}_{row}"


# Invisible slot filler with the same row structure as a technique card
# (id / name / coverage), so placeholders take a card's height.
_PLACEHOLDER_LABEL = (
    '<<TABLE BORDER="0" CELLBORDER="0" CELLSPACING="0" CELLPADDING="1">'
    "<TR><TD><B> </B></TD></TR><TR><TD> </TD></TR>"
    '<TR><TD><FONT POINT-SIZE="9"> </FONT></TD></TR></TABLE>>'
)


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
        if self.framework in ("atlas", "mitre_atlas"):
            self.framework = "atlas"
            return list(ATLAS_TACTIC_ORDER)
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
        if self.framework == "atlas" and value.upper() in ATLAS_TACTIC_IDS:
            return ATLAS_TACTIC_IDS[value.upper()]
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
        phases = self.active_phases() or self.phase_order

        # One cluster per phase, ranked left to right. Technique nodes are
        # added to the CLUSTER (not the root graph) so each lands under its
        # phase header. Graphviz places clusters independently, so phases
        # with fewer techniques would float up or down; instead all phases
        # share one row grid: every phase gets the same number of row slots
        # (techniques or invisible card-sized placeholders) and slot k of each
        # phase is chained to slot k of the next by a heavy invisible edge.
        # The rows lay out straight, giving every phase box the same top and
        # height (works for empty phases).
        grid, flows, waypoints = self.plan_grid(phases)
        slot_count = max((row + 1 for rows in grid.values() for row in rows), default=1)

        # Incident technique-to-technique flow edges. An edge skipping phases
        # runs straight through the placeholder reserved on its row in each
        # skipped phase (clipping off, so the segments join into one line);
        # otherwise dot would detour it around the full-height phase boxes.
        edge_style = utils.stringify_dict(style.get("edge", self._default_style()["edge"]))
        segments: list[tuple[str, str, dict[str, str]]] = []
        for src, dst in flows:
            path = [
                src,
                *(_slot_id(utils.sanitize_node_id(phase), row) for phase, row in waypoints.get((src, dst), [])),
            ]
            path.append(dst)
            for index, (tail, head) in enumerate(pairwise(path)):
                segment = dict(edge_style)
                if index > 0:
                    segment["tailclip"] = "false"
                if index < len(path) - 2:
                    segment.update(headclip="false", arrowhead="none")
                if self.techniques[src].phase == self.techniques[dst].phase:
                    # Same-phase step: keep both cards stacked in the phase
                    # column (a ranking edge would open a new column).
                    segment["constraint"] = "false"
                segments.append((tail, head, segment))
        segment_pairs = {(tail, head): attrs for tail, head, attrs in segments}

        placeholder_style = {
            **self._graphviz_tech_style(Technique(id="", name="", phase=""), style),
            "style": "invis",
        }
        # A flow passing through a placeholder is split there, and Graphviz
        # stops unclipped edge ends 1pt short of the node center. Pass-through
        # placeholders therefore draw a tiny edge-colored dot (fixedsize=shape:
        # the blank label still reserves a card's footprint) that bridges the
        # 2pt break; a dot one line-width across reads as a round join (a
        # rectangular bar antialiased into a visible blip).
        pen = float(edge_style.get("penwidth", "1"))
        bridge_style = {
            **placeholder_style,
            "style": "filled",
            "shape": "circle",
            "fixedsize": "shape",
            "width": f"{max(pen, 2.2) / 72:.4f}",
            "height": f"{max(pen, 2.2) / 72:.4f}",
            "penwidth": "0",
            "color": edge_style.get("color", "black"),
            "fillcolor": edge_style.get("color", "black"),
        }
        prev_slots: list[str] = []
        for phase in phases:
            key = utils.sanitize_node_id(phase)
            slots: list[str] = []
            with self.dot.subgraph(name=f"cluster_{key}") as sub:
                attrs = utils.stringify_dict(dict(phase_style))
                sub.attr(label=f"  {phase}  ", **{k: v for k, v in attrs.items() if k != "label"})
                for row in range(slot_count):
                    tech_id = grid[phase].get(row)
                    if tech_id:
                        tech = self.techniques[tech_id]
                        sub.node(tech.id, label=self._graphviz_label(tech), **self._graphviz_tech_style(tech, style))
                        slots.append(tech.id)
                    else:
                        slot = _slot_id(key, row)
                        is_pass_through = grid[phase].get(row) == ""
                        sub.node(
                            slot, label=_PLACEHOLDER_LABEL, **(bridge_style if is_pass_through else placeholder_style)
                        )
                        slots.append(slot)
            if prev_slots:
                for prev, cur in zip(prev_slots, slots, strict=True):
                    if (prev, cur) in segment_pairs:
                        # A visible flow segment already links this row pair;
                        # a parallel invisible edge would push it off-center.
                        segment_pairs[(prev, cur)]["weight"] = "100"
                    else:
                        self.dot.edge(prev, cur, style="invis", weight="100")
            prev_slots = slots

        for tail, head, attrs in segments:
            self.dot.edge(tail, head, **attrs)

    def plan_grid(
        self, phases: list[str]
    ) -> tuple[
        dict[str, dict[int, str]],
        list[tuple[str, str]],
        dict[tuple[str, str], list[tuple[str, int]]],
    ]:
        """Assign techniques to grid rows so incident flows run straight.

        Walking the incident flows in order, an edge's target takes the
        source's row when it can, and every phase the edge skips reserves
        that same row as an empty pass-through (a row free in all of them
        is chosen otherwise). Techniques outside any flow fill the remaining
        rows top-down in declaration order.

        Returns (grid, flows, waypoints): grid maps phase -> {row: tech id,
        or "" for a reserved pass-through}; waypoints maps a skipping flow
        to the (phase, row) slots it passes through.
        """
        column = {phase: index for index, phase in enumerate(phases)}
        grid: dict[str, dict[int, str]] = {phase: {} for phase in phases}
        placed: dict[str, int] = {}

        def first_free(phase: str) -> int:
            row = 0
            while row in grid[phase]:
                row += 1
            return row

        def place(tech_id: str, row: int) -> None:
            grid[self.techniques[tech_id].phase][row] = tech_id
            placed[tech_id] = row

        flows: list[tuple[str, str]] = []
        waypoints: dict[tuple[str, str], list[tuple[str, int]]] = {}
        for incident in self.incidents:
            for src, dst in pairwise(incident.techniques):
                if src not in self.techniques or dst not in self.techniques:
                    continue
                flows.append((src, dst))
                if (src, dst) in waypoints:
                    continue
                src_phase, dst_phase = self.techniques[src].phase, self.techniques[dst].phase
                if src not in placed:
                    place(src, first_free(src_phase))
                if column[dst_phase] <= column[src_phase]:  # same-phase or backward edge
                    if dst not in placed:
                        place(dst, first_free(dst_phase))
                    continue
                skipped = phases[column[src_phase] + 1 : column[dst_phase]]

                def straight(row: int, skipped=skipped, dst=dst, dst_phase=dst_phase) -> bool:
                    clear = all(row not in grid[phase] for phase in skipped)
                    return clear and (dst in placed or row not in grid[dst_phase])

                preferred = [placed[src]] + ([placed[dst]] if dst in placed else [])
                row = next(r for r in chain(preferred, count()) if straight(r))
                if dst not in placed:
                    place(dst, row)
                for phase in skipped:
                    grid[phase][row] = ""
                waypoints[(src, dst)] = [(phase, row) for phase in skipped]

        for tech in self.techniques.values():
            if tech.id not in placed and tech.phase in grid:
                place(tech.id, first_free(tech.phase))
        return grid, flows, waypoints

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
        utils.ortho_edge_xlabels(self.dot)
        utils.render_graph(self.dot, outputfile)

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
