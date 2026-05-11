#
# VULNEX -Universal Security Visualization Library-
#
# File: maestro.py
# Author: Simon Roses Femerling
# Created: 2026-05-11
# Last Modified: 2026-05-11
# Version: 0.4.0
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""MAESTRO Agentic AI Threat Modeling.

Implements the MAESTRO (Multi-Agent Environment, Security, Threat, Risk, & Outcome)
framework for threat modeling agentic AI systems. Renders a 7-layer architecture
view with agents, assets, threats, and cross-layer attack chains.

Framework reference:
    https://cloudsecurityalliance.org/blog/2025/02/06/agentic-ai-threat-modeling-framework-maestro

Supports TOML, JSON, and YAML input formats. Ships a built-in threat catalog
(``models/maestro_catalog.json``) that auto-populates threats based on the layers
each agent touches and the architecture patterns declared by the model.
"""

import json
import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from graphviz import Digraph

from . import utils
from .base import VisualizationBase


class MaestroError(utils.RenderError):
    """Exception raised for MAESTRO threat model generation errors."""
    pass


class MaestroLayer(Enum):
    FOUNDATION_MODELS = "foundation-models"
    DATA_OPERATIONS = "data-operations"
    AGENT_FRAMEWORKS = "agent-frameworks"
    INFRASTRUCTURE = "infrastructure"
    OBSERVABILITY = "observability"
    SECURITY = "security"
    AGENT_ECOSYSTEM = "agent-ecosystem"


# Display order for the layered render (top to bottom).
# L6 (Security) is the vertical gutter — not rendered as a band.
LAYER_DISPLAY_ORDER = [
    MaestroLayer.AGENT_ECOSYSTEM,
    MaestroLayer.AGENT_FRAMEWORKS,
    MaestroLayer.FOUNDATION_MODELS,
    MaestroLayer.DATA_OPERATIONS,
    MaestroLayer.INFRASTRUCTURE,
    MaestroLayer.OBSERVABILITY,
]


class AutonomyLevel(Enum):
    REACTIVE = "reactive"
    DELIBERATIVE = "deliberative"
    LEARNING = "learning"
    SELF_MODIFYING = "self-modifying"


class ArchitecturePattern(Enum):
    SINGLE_AGENT = "single-agent"
    MULTI_AGENT = "multi-agent"
    HIERARCHICAL = "hierarchical"
    DISTRIBUTED = "distributed"
    HUMAN_IN_THE_LOOP = "human-in-the-loop"
    SELF_LEARNING = "self-learning"
    UNCONSTRAINED_CONVERSATIONAL = "unconstrained-conversational"
    TASK_ORIENTED = "task-oriented"


class ThreatStatus(Enum):
    IDENTIFIED = "identified"
    MITIGATED = "mitigated"
    ACCEPTED = "accepted"
    IN_PROGRESS = "in-progress"
    NOT_APPLICABLE = "not-applicable"


class CatalogMode(Enum):
    AUTO = "auto"
    FULL = "full"
    MANUAL = "manual"


SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITY_COLORS = {
    "low": "#4caf50",
    "medium": "#ffb300",
    "high": "#fb8c00",
    "critical": "#e53935",
    "unknown": "#9e9e9e",
}


@dataclass
class Agent:
    id: str
    name: str
    type: str = "task-oriented"
    autonomy: str = "reactive"
    goals: list[str] = field(default_factory=list)
    capabilities: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    layers: list[str] = field(default_factory=list)


@dataclass
class Asset:
    id: str
    name: str
    layer: str
    sensitivity: str = "medium"
    owner_agent: Optional[str] = None


@dataclass
class Threat:
    id: str
    layer: str
    name: str
    description: str = ""
    target_id: str = ""
    severity: str = "medium"
    likelihood: str = "medium"
    status: str = "identified"
    mitigations: list[str] = field(default_factory=list)
    stride_category: Optional[str] = None
    stride_mapping: str = "informational"
    mitre_attack: Optional[str] = None
    from_catalog: bool = False


@dataclass
class CrossLayerThreat:
    id: str
    name: str
    layers: list[str]
    description: str = ""
    attack_chain: list[str] = field(default_factory=list)
    severity: str = "high"
    likelihood: str = "medium"


@dataclass
class Mitigation:
    id: str
    layer: str
    name: str
    type: str = "preventive"
    implemented: bool = False


class MaestroThreatModel(VisualizationBase):
    """MAESTRO agentic AI threat model.

    Renders a layered architecture view of an agentic system with auto-populated
    threats from the built-in MAESTRO catalog. Supports TOML, JSON, and YAML
    configuration files.

    Attributes:
        agents: Parsed agents keyed by id.
        assets: Parsed assets keyed by id.
        threats: All threats attached to the model (catalog + user-defined).
        cross_layer_threats: User-defined and pattern-implied cross-layer chains.
        mitigations: Mitigations referenced by threats.
        patterns: Declared architecture patterns.
        warnings: Validation warnings surfaced during load/auto-populate.
    """

    STYLE_FILE = "config_maestro.tml"
    DEFAULT_STYLE_ID = "ma_default"
    ALLOWED_EXTENSIONS = ['.toml', '.tml', '.json', '.yaml', '.yml']
    MAX_INPUT_SIZE = 10 * 1024 * 1024  # 10 MB

    CLUSTER_THRESHOLD_DEFAULT = 8

    CATALOG_FILE = "maestro_catalog.json"

    def __init__(self, inputfile: str, outputfile: str, format: str = "",
                 styleid: str = "", validate_paths: bool = True) -> None:
        if format == "":
            format = "png"
        if styleid == "":
            styleid = None

        super().__init__(
            inputfile=inputfile,
            outputfile=outputfile,
            format=format,
            styleid=styleid,
            validate_paths=validate_paths
        )

        self.graph: Optional[Digraph] = None

        # Parsed entities
        self.agents: dict[str, Agent] = {}
        self.assets: dict[str, Asset] = {}
        self.threats: dict[str, Threat] = {}
        self.cross_layer_threats: dict[str, CrossLayerThreat] = {}
        self.mitigations: dict[str, Mitigation] = {}
        self.patterns: list[str] = []

        # Config
        self.catalog_mode: str = CatalogMode.AUTO.value
        self.cluster_threshold: int = self.CLUSTER_THRESHOLD_DEFAULT
        self.clustering_enabled: bool = True

        # Catalog (lazy-loaded)
        self._catalog: Optional[dict[str, Any]] = None

        # Warnings surfaced from auto-populate and validation
        self.warnings: list[str] = []

    # ------------------------------------------------------------------ catalog

    def _load_catalog(self) -> dict[str, Any]:
        """Load the built-in MAESTRO threat catalog."""
        if self._catalog is not None:
            return self._catalog

        catalog_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "models",
            self.CATALOG_FILE,
        )

        try:
            with open(catalog_path, encoding='utf-8') as f:
                self._catalog = json.load(f)
        except OSError as e:
            raise MaestroError(f"Failed to read MAESTRO catalog: {e}") from e
        except json.JSONDecodeError as e:
            raise MaestroError(f"Invalid MAESTRO catalog JSON: {e}") from e

        return self._catalog

    def get_catalog(self) -> dict[str, Any]:
        """Public accessor for the loaded catalog."""
        return self._load_catalog()

    # --------------------------------------------------------- VisualizationBase

    def _default_style(self) -> dict[str, Any]:
        return {
            "graph": {
                "rankdir": "TB",
                "bgcolor": "white",
                "fontname": "Arial",
                "splines": "ortho",
                "nodesep": "0.6",
                "ranksep": "0.8",
                "pad": "0.5",
                "compound": "true",
            },
            "layer": {
                "style": "filled,rounded",
                "fillcolor": "#f5f5f5",
                "color": "#cccccc",
                "fontname": "Arial Bold",
                "fontsize": "14",
                "fontcolor": "#333333",
                "penwidth": "1",
            },
            "agent": {
                "shape": "box",
                "style": "filled,rounded",
                "fontname": "Arial",
                "fontsize": "11",
                "fontcolor": "white",
                "fillcolor": "#4a90d9",
                "color": "#357abd",
                "penwidth": "1.5",
                "margin": "0.2,0.1",
            },
            "asset": {
                "shape": "cylinder",
                "style": "filled",
                "fontname": "Arial",
                "fontsize": "10",
                "fontcolor": "white",
                "fillcolor": "#7e57c2",
                "color": "#5e35b1",
                "penwidth": "1.2",
            },
            "security_gutter": {
                "style": "filled,rounded",
                "fillcolor": "#fff3e0",
                "color": "#fb8c00",
                "fontname": "Arial Bold",
                "fontsize": "13",
                "fontcolor": "#e65100",
                "penwidth": "1.5",
            },
            "cross_layer_edge": {
                "style": "dashed",
                "color": "#e53935",
                "fontname": "Arial",
                "fontsize": "9",
                "fontcolor": "#c62828",
                "penwidth": "1.5",
                "arrowhead": "open",
            },
        }

    def _get_metadata_root_key(self) -> str:
        return "meta"

    def _load_impl(self) -> dict[str, Any]:
        try:
            data = utils.ReadConfigFile(self.inputfile)
        except (utils.FileError, utils.ConfigError) as e:
            self.logger.error(f"Failed to load MAESTRO model from {self.inputfile}: {e}")
            raise MaestroError(f"Failed to load MAESTRO model: {e}") from e
        except FileNotFoundError as e:
            self.logger.error(f"Input file not found: {self.inputfile}")
            raise MaestroError(f"Input file not found: {e}") from e

        self.inputdata = data
        self._parse(data)
        self._apply_render_config(data)
        self.auto_populate_threats()
        self.logger.debug(
            f"Loaded MAESTRO model: {len(self.agents)} agents, "
            f"{len(self.assets)} assets, {len(self.threats)} threats, "
            f"{len(self.cross_layer_threats)} cross-layer threats"
        )
        return data

    def _parse(self, data: dict[str, Any]) -> None:
        """Parse raw config into typed entities."""
        # Reset state in case of re-load
        self.agents = {}
        self.assets = {}
        self.threats = {}
        self.cross_layer_threats = {}
        self.mitigations = {}
        self.patterns = []
        self.warnings = []

        valid_layers = {layer.value for layer in MaestroLayer}

        # Agents
        for raw in data.get("agents", []):
            if not isinstance(raw, dict):
                continue
            agent_id = raw.get("id")
            if not agent_id:
                self.warnings.append("Agent without 'id' skipped")
                continue
            layers = [layer for layer in raw.get("layers", []) if layer in valid_layers]
            if len(layers) != len(raw.get("layers", [])):
                bad = set(raw.get("layers", [])) - valid_layers
                if bad:
                    self.warnings.append(
                        f"Agent '{agent_id}' references unknown layers: {sorted(bad)}"
                    )
            self.agents[agent_id] = Agent(
                id=agent_id,
                name=raw.get("name", agent_id),
                type=raw.get("type", "task-oriented"),
                autonomy=raw.get("autonomy", "reactive"),
                goals=list(raw.get("goals", [])),
                capabilities=list(raw.get("capabilities", [])),
                tools=list(raw.get("tools", [])),
                layers=layers,
            )

        # Assets
        for raw in data.get("assets", []):
            if not isinstance(raw, dict):
                continue
            asset_id = raw.get("id")
            if not asset_id:
                continue
            layer = raw.get("layer")
            if layer not in valid_layers:
                self.warnings.append(f"Asset '{asset_id}' uses unknown layer '{layer}'")
                continue
            self.assets[asset_id] = Asset(
                id=asset_id,
                name=raw.get("name", asset_id),
                layer=layer,
                sensitivity=raw.get("sensitivity", "medium"),
                owner_agent=raw.get("owner_agent"),
            )

        # Architecture patterns
        arch = data.get("architecture", {})
        if isinstance(arch, dict):
            valid_patterns = {p.value for p in ArchitecturePattern}
            for pat in arch.get("patterns", []):
                if pat in valid_patterns:
                    self.patterns.append(pat)
                else:
                    self.warnings.append(f"Unknown architecture pattern: {pat}")

        # Catalog mode
        catalog_cfg = data.get("catalog", {})
        if isinstance(catalog_cfg, dict):
            mode = catalog_cfg.get("mode", CatalogMode.AUTO.value)
            if mode in {m.value for m in CatalogMode}:
                self.catalog_mode = mode
            else:
                self.warnings.append(f"Unknown catalog mode '{mode}', using 'auto'")

        # Mitigations (user-defined override catalog)
        for raw in data.get("mitigations", []):
            if not isinstance(raw, dict):
                continue
            mit_id = raw.get("id")
            if not mit_id:
                continue
            self.mitigations[mit_id] = Mitigation(
                id=mit_id,
                layer=raw.get("layer", "security"),
                name=raw.get("name", mit_id),
                type=raw.get("type", "preventive"),
                implemented=bool(raw.get("implemented", False)),
            )

        # User-defined threat overrides — stored for later application after
        # auto-populate, so user values win.
        self._threat_overrides = [t for t in data.get("threats", []) if isinstance(t, dict)]

        # Cross-layer threats (user-defined)
        for raw in data.get("cross_layer_threats", []):
            if not isinstance(raw, dict):
                continue
            clt_id = raw.get("id")
            if not clt_id:
                continue
            layers = [layer for layer in raw.get("layers", []) if layer in valid_layers]
            self.cross_layer_threats[clt_id] = CrossLayerThreat(
                id=clt_id,
                name=raw.get("name", clt_id),
                description=raw.get("description", ""),
                layers=layers,
                attack_chain=list(raw.get("attack_chain", [])),
                severity=raw.get("severity", "high"),
                likelihood=raw.get("likelihood", "medium"),
            )

    def _apply_render_config(self, data: dict[str, Any]) -> None:
        """Apply render-time configuration (clustering, etc.)."""
        render_cfg = data.get("render", {})
        if not isinstance(render_cfg, dict):
            return

        clustering = render_cfg.get("clustering", "auto")
        self.clustering_enabled = clustering != "off"

        threshold = render_cfg.get("cluster_threshold")
        if isinstance(threshold, int) and threshold > 0:
            self.cluster_threshold = threshold

    # ---------------------------------------------------------- auto-populate

    def auto_populate_threats(self) -> None:
        """Attach catalog threats based on declared layers, agents, and patterns.

        Resolved decisions:
        - **Pattern x layer mismatch**: if a pattern implies threats on a layer
          that no agent touches, emit a warning and do NOT attach those threats.
        - **Catalog mode "manual"**: skip auto-population entirely.
        - **Catalog mode "full"**: attach every catalog threat to every agent
          touching the threat's layer.
        - **Catalog mode "auto"** (default): attach catalog threats only for
          layers actually declared by agents, plus pattern threats whose layer
          is covered.
        """
        if self.catalog_mode == CatalogMode.MANUAL.value:
            self._apply_threat_overrides()
            return

        catalog = self._load_catalog()
        catalog_threats: dict[str, dict[str, Any]] = {
            t["id"]: t for t in catalog.get("threats", [])
        }
        catalog_cross: dict[str, dict[str, Any]] = {
            t["id"]: t for t in catalog.get("cross_layer_threats", [])
        }
        pattern_map: dict[str, list[str]] = catalog.get("pattern_threats", {})

        # Compute layers actually declared across all agents
        declared_layers: set[str] = set()
        for agent in self.agents.values():
            declared_layers.update(agent.layers)

        # 1) Attach threats matching declared layers (one threat per agent that
        # touches the layer).
        for threat_id, ct in catalog_threats.items():
            layer = ct["layer"]
            if self.catalog_mode == CatalogMode.AUTO.value and layer not in declared_layers:
                continue
            # Find agents whose layers include this layer
            targets = [a for a in self.agents.values() if layer in a.layers]
            for target in targets:
                self._attach_threat_for_agent(ct, target.id)

            # If FULL mode and no agent touches the layer, still attach one
            # untargeted instance to surface the layer's threats.
            if self.catalog_mode == CatalogMode.FULL.value and not targets:
                self._attach_threat_for_agent(ct, "")

        # 2) Pattern-specific threats — attach only when at least one agent
        # touches the relevant layer.
        for pattern in self.patterns:
            for threat_id in pattern_map.get(pattern, []):
                # Cross-layer-pattern threats
                if threat_id in catalog_cross:
                    clt = catalog_cross[threat_id]
                    covered = any(layer in declared_layers for layer in clt["layers"])
                    if not covered:
                        self.warnings.append(
                            f"Pattern '{pattern}' implies cross-layer threat "
                            f"'{threat_id}' but no agent covers its layers — skipping"
                        )
                        continue
                    if clt["id"] not in self.cross_layer_threats:
                        self.cross_layer_threats[clt["id"]] = CrossLayerThreat(
                            id=clt["id"],
                            name=clt["name"],
                            description=clt.get("description", ""),
                            layers=list(clt["layers"]),
                            attack_chain=[],
                            severity=clt.get("default_severity", "high"),
                            likelihood=clt.get("default_likelihood", "medium"),
                        )
                    continue

                ct = catalog_threats.get(threat_id)
                if not ct:
                    continue
                layer = ct["layer"]
                if layer not in declared_layers:
                    self.warnings.append(
                        f"Pattern '{pattern}' implies threat '{threat_id}' "
                        f"on layer '{layer}' but no agent touches that layer — skipping"
                    )
                    continue
                targets = [a for a in self.agents.values() if layer in a.layers]
                for target in targets:
                    self._attach_threat_for_agent(ct, target.id)

        # 3) Apply user overrides last so they win
        self._apply_threat_overrides()

    def _attach_threat_for_agent(self, catalog_threat: dict[str, Any], agent_id: str) -> None:
        """Attach a catalog threat to an agent (idempotent by composite id)."""
        composite_id = f"{catalog_threat['id']}@{agent_id}" if agent_id else catalog_threat['id']
        if composite_id in self.threats:
            return
        self.threats[composite_id] = Threat(
            id=composite_id,
            layer=catalog_threat["layer"],
            name=catalog_threat["name"],
            description=catalog_threat.get("description", ""),
            target_id=agent_id,
            severity=catalog_threat.get("default_severity", "medium"),
            likelihood=catalog_threat.get("default_likelihood", "medium"),
            status=ThreatStatus.IDENTIFIED.value,
            mitigations=list(catalog_threat.get("default_mitigations", [])),
            stride_category=catalog_threat.get("stride_category"),
            stride_mapping=catalog_threat.get("stride_mapping", "informational"),
            mitre_attack=catalog_threat.get("mitre_attack"),
            from_catalog=True,
        )

    def _apply_threat_overrides(self) -> None:
        """Apply user-supplied threat overrides on top of auto-populated set."""
        for raw in getattr(self, "_threat_overrides", []):
            catalog_id = raw.get("id")
            if not catalog_id:
                continue
            target_id = raw.get("target", "")
            composite_id = f"{catalog_id}@{target_id}" if target_id else catalog_id

            existing = self.threats.get(composite_id)
            if existing is None:
                # User added a threat not auto-populated — create a fresh entry
                self.threats[composite_id] = Threat(
                    id=composite_id,
                    layer=raw.get("layer", "agent-ecosystem"),
                    name=raw.get("name", catalog_id),
                    description=raw.get("description", ""),
                    target_id=target_id,
                    severity=raw.get("severity", "medium"),
                    likelihood=raw.get("likelihood", "medium"),
                    status=raw.get("status", ThreatStatus.IDENTIFIED.value),
                    mitigations=list(raw.get("mitigations", [])),
                    stride_category=raw.get("stride_category"),
                    stride_mapping=raw.get("stride_mapping", "informational"),
                    mitre_attack=raw.get("mitre_attack"),
                    from_catalog=False,
                )
                continue

            # Override fields when provided
            for attr in ("severity", "likelihood", "status", "description"):
                if attr in raw and raw[attr]:
                    setattr(existing, attr, raw[attr])
            if "mitigations" in raw and isinstance(raw["mitigations"], list):
                existing.mitigations = list(raw["mitigations"])
            if "mitre_attack" in raw and raw["mitre_attack"]:
                existing.mitre_attack = raw["mitre_attack"]

    # ----------------------------------------------------------------- render

    def _render_impl(self) -> None:
        title = self.inputdata.get("meta", {}).get("name", "MAESTRO Threat Model")

        graph_style = self.style.get("graph", self._default_style()["graph"])
        layer_style = self.style.get("layer", self._default_style()["layer"])
        agent_style = self.style.get("agent", self._default_style()["agent"])
        asset_style = self.style.get("asset", self._default_style()["asset"])
        security_style = self.style.get("security_gutter", self._default_style()["security_gutter"])
        cross_style = self.style.get("cross_layer_edge", self._default_style()["cross_layer_edge"])

        self.graph = Digraph(name=title, format=self.format)
        self.graph.attr(**utils.stringify_dict(graph_style))
        self.graph.attr(label=title, labelloc="t", fontsize="16")

        # Background colors per band
        layer_colors = {
            MaestroLayer.AGENT_ECOSYSTEM.value: "#e3f2fd",
            MaestroLayer.AGENT_FRAMEWORKS.value: "#f3e5f5",
            MaestroLayer.FOUNDATION_MODELS.value: "#e8f5e9",
            MaestroLayer.DATA_OPERATIONS.value: "#fff3e0",
            MaestroLayer.INFRASTRUCTURE.value: "#fce4ec",
            MaestroLayer.OBSERVABILITY.value: "#e0f7fa",
        }

        previous_anchor: Optional[str] = None

        for layer in LAYER_DISPLAY_ORDER:
            layer_key = layer.value
            display_name = self._layer_display_name(layer_key)
            anchor_id = utils.sanitize_node_id(f"anchor_{layer_key}")

            with self.graph.subgraph(name=f"cluster_{layer_key}") as sub:
                sub_attrs = utils.stringify_dict(layer_style.copy())
                fill = sub_attrs.pop("fillcolor", layer_colors[layer_key])
                border = sub_attrs.pop("color", "#cccccc")
                sub.attr(
                    label=display_name,
                    fillcolor=fill,
                    color=border,
                    **{k: v for k, v in sub_attrs.items() if k != "label"},
                )

                # Invisible anchor for vertical ordering between layers
                sub.node(anchor_id, "", shape="point", style="invis", width="0", height="0")

                self._render_layer_contents(sub, layer_key, agent_style, asset_style)

            # Force top-to-bottom order between layers
            if previous_anchor is not None:
                self.graph.edge(previous_anchor, anchor_id, style="invis")
            previous_anchor = anchor_id

        # Security vertical gutter — drawn as a sidebar cluster
        with self.graph.subgraph(name="cluster_security_gutter") as gut:
            sub_attrs = utils.stringify_dict(security_style.copy())
            fill = sub_attrs.pop("fillcolor", "#fff3e0")
            border = sub_attrs.pop("color", "#fb8c00")
            gut.attr(
                label="L6 Security (vertical)",
                fillcolor=fill,
                color=border,
                **{k: v for k, v in sub_attrs.items() if k != "label"},
            )
            gut.node(
                utils.sanitize_node_id("security_gutter_anchor"),
                self._security_gutter_label(),
                shape="note",
                fillcolor="#ffe0b2",
                fontname="Arial",
                fontsize="10",
                fontcolor="#bf360c",
                style="filled",
            )

        # Cross-layer threats — dashed edges between agents in their layers
        for clt in self.cross_layer_threats.values():
            self._render_cross_layer(clt, cross_style)

        self.logger.debug(
            f"Rendered MAESTRO model with {len(self.agents)} agents, "
            f"{len(self.threats)} threats, "
            f"{len(self.cross_layer_threats)} cross-layer threats"
        )

    def _layer_display_name(self, layer_key: str) -> str:
        catalog = self._load_catalog()
        layers = catalog.get("layers", {})
        entry = layers.get(layer_key, {})
        layer_id = entry.get("id", "?")
        name = entry.get("name", layer_key)
        return f"L{layer_id} — {name}"

    def _render_layer_contents(
        self,
        sub: Any,
        layer_key: str,
        agent_style: dict[str, Any],
        asset_style: dict[str, Any],
    ) -> None:
        """Render agents and assets within a single layer band."""
        agents_in_layer = [a for a in self.agents.values() if layer_key in a.layers]
        assets_in_layer = [a for a in self.assets.values() if a.layer == layer_key]

        agent_attrs = utils.stringify_dict(agent_style)
        asset_attrs = utils.stringify_dict(asset_style)

        # Auto-clustering when count exceeds threshold
        if (
            self.clustering_enabled
            and len(agents_in_layer) > self.cluster_threshold
        ):
            self._render_clustered_agents(sub, layer_key, agents_in_layer, agent_attrs)
        else:
            for agent in agents_in_layer:
                label = self._agent_label(agent)
                sub.node(utils.sanitize_node_id(agent.id), label, **agent_attrs)

        for asset in assets_in_layer:
            label = self._asset_label(asset)
            sub.node(utils.sanitize_node_id(f"asset_{asset.id}"), label, **asset_attrs)

    def _render_clustered_agents(
        self,
        sub: Any,
        layer_key: str,
        agents_in_layer: list[Agent],
        agent_attrs: dict[str, str],
    ) -> None:
        """Group agents by type into subclusters when a layer is crowded."""
        by_type: dict[str, list[Agent]] = {}
        for agent in agents_in_layer:
            by_type.setdefault(agent.type, []).append(agent)

        for agent_type, members in by_type.items():
            cluster_name = f"cluster_{layer_key}_{utils.sanitize_node_id(agent_type)}"
            severities = [
                self._max_severity_for_agent(a.id) for a in members
            ]
            worst = max(
                severities,
                key=lambda s: SEVERITY_RANK.get(s, 0),
                default="unknown",
            )
            badge = f"{len(members)} agents | worst: {worst}"

            with sub.subgraph(name=cluster_name) as cluster:
                cluster.attr(
                    label=f"{agent_type}\\n{badge}",
                    style="dashed",
                    color=SEVERITY_COLORS.get(worst, "#9e9e9e"),
                    fontname="Arial",
                    fontsize="10",
                )
                for agent in members:
                    label = self._agent_label(agent)
                    cluster.node(utils.sanitize_node_id(agent.id), label, **agent_attrs)

    def _agent_label(self, agent: Agent) -> str:
        worst = self._max_severity_for_agent(agent.id)
        threat_count = sum(
            1 for t in self.threats.values()
            if t.target_id == agent.id and t.status not in (
                ThreatStatus.MITIGATED.value,
                ThreatStatus.NOT_APPLICABLE.value,
            )
        )
        severity_label = ""
        if threat_count > 0:
            color = SEVERITY_COLORS.get(worst, "#9e9e9e")
            severity_label = (
                f"<BR/><FONT POINT-SIZE='9' COLOR='{color}'>"
                f"{threat_count} open ({worst})</FONT>"
            )
        return (
            f"<<B>{utils.escape_dot_label(agent.name)}</B>"
            f"<BR/><FONT POINT-SIZE='9'><I>{utils.escape_dot_label(agent.type)} "
            f"| {utils.escape_dot_label(agent.autonomy)}</I></FONT>"
            f"{severity_label}>"
        )

    def _asset_label(self, asset: Asset) -> str:
        return (
            f"<<B>{utils.escape_dot_label(asset.name)}</B>"
            f"<BR/><FONT POINT-SIZE='9'>sensitivity: "
            f"{utils.escape_dot_label(asset.sensitivity)}</FONT>>"
        )

    def _max_severity_for_agent(self, agent_id: str) -> str:
        agent_threats = [
            t for t in self.threats.values()
            if t.target_id == agent_id and t.status not in (
                ThreatStatus.MITIGATED.value,
                ThreatStatus.NOT_APPLICABLE.value,
            )
        ]
        if not agent_threats:
            return "unknown"
        return max(
            (t.severity for t in agent_threats),
            key=lambda s: SEVERITY_RANK.get(s, 0),
        )

    def _security_gutter_label(self) -> str:
        detective_count = sum(
            1 for m in self.mitigations.values()
            if m.type == "detective" and m.implemented
        )
        preventive_count = sum(
            1 for m in self.mitigations.values()
            if m.type == "preventive" and m.implemented
        )
        return (
            f"Security & Compliance\\n"
            f"{preventive_count} preventive | {detective_count} detective"
        )

    def _render_cross_layer(self, clt: CrossLayerThreat, cross_style: dict[str, Any]) -> None:
        """Render a cross-layer threat as a dashed chain of edges."""
        edge_attrs = utils.stringify_dict(cross_style)

        # If the chain references concrete threats, walk them in order
        chain_targets: list[str] = []
        for threat_ref in clt.attack_chain:
            # attack_chain entries can be composite ids or just threat catalog ids
            matched = None
            for tid, threat in self.threats.items():
                if tid == threat_ref or threat.id.startswith(f"{threat_ref}@"):
                    matched = threat.target_id or tid
                    break
            if matched:
                chain_targets.append(matched)

        # Fallback: pick one agent per layer the chain spans
        if not chain_targets:
            for layer in clt.layers:
                agent = next(
                    (a for a in self.agents.values() if layer in a.layers),
                    None,
                )
                if agent:
                    chain_targets.append(agent.id)

        if len(chain_targets) < 2:
            return

        label = f" {clt.id}: {clt.name}"
        for src, tgt in zip(chain_targets, chain_targets[1:]):
            self.graph.edge(
                utils.sanitize_node_id(src),
                utils.sanitize_node_id(tgt),
                label=label,
                **edge_attrs,
            )
            label = ""  # Only label the first edge of the chain

    def _draw_impl(self, outputfile: str) -> None:
        if self.graph is None:
            raise MaestroError("Graph not rendered. Call render() first.")
        try:
            self.graph.render(outputfile, cleanup=True)
            self.logger.debug("Successfully wrote MAESTRO visualization")
        except Exception as e:
            self.logger.error(f"Failed to render graph to {outputfile}: {e}")
            raise MaestroError(f"Failed to render graph: {e}") from e

    # --------------------------------------------------------------- validate

    def _validate_impl(self) -> list[str]:
        errors: list[str] = []

        if not self.agents:
            errors.append("No agents defined")

        valid_layers = {layer.value for layer in MaestroLayer}
        for agent in self.agents.values():
            if not agent.layers:
                errors.append(f"Agent '{agent.id}' has no declared layers")
            for layer in agent.layers:
                if layer not in valid_layers:
                    errors.append(f"Agent '{agent.id}' references unknown layer '{layer}'")

        for asset in self.assets.values():
            if asset.layer not in valid_layers:
                errors.append(f"Asset '{asset.id}' references unknown layer '{asset.layer}'")
            if asset.owner_agent and asset.owner_agent not in self.agents:
                errors.append(
                    f"Asset '{asset.id}' owner_agent '{asset.owner_agent}' does not exist"
                )

        agent_ids = set(self.agents.keys())
        for threat in self.threats.values():
            if threat.target_id and threat.target_id not in agent_ids:
                errors.append(
                    f"Threat '{threat.id}' targets unknown agent '{threat.target_id}'"
                )

        for clt in self.cross_layer_threats.values():
            if len(clt.layers) < 2:
                errors.append(
                    f"Cross-layer threat '{clt.id}' must span at least 2 layers"
                )

        return errors

    # ---------------------------------------------------------------- stats

    def _get_stats_impl(self) -> dict[str, Any]:
        threats_by_layer: dict[str, int] = {}
        threats_by_severity: dict[str, int] = {}
        threats_by_status: dict[str, int] = {}
        for threat in self.threats.values():
            threats_by_layer[threat.layer] = threats_by_layer.get(threat.layer, 0) + 1
            threats_by_severity[threat.severity] = threats_by_severity.get(threat.severity, 0) + 1
            threats_by_status[threat.status] = threats_by_status.get(threat.status, 0) + 1

        unmitigated = sum(
            1 for t in self.threats.values()
            if t.status not in (
                ThreatStatus.MITIGATED.value,
                ThreatStatus.NOT_APPLICABLE.value,
            )
        )

        return {
            "name": self.inputdata.get("meta", {}).get("name", "MAESTRO Threat Model"),
            "total_agents": len(self.agents),
            "total_assets": len(self.assets),
            "total_threats": len(self.threats),
            "total_cross_layer_threats": len(self.cross_layer_threats),
            "total_mitigations": len(self.mitigations),
            "patterns": list(self.patterns),
            "unmitigated_threats": unmitigated,
            "threats_by_layer": threats_by_layer,
            "threats_by_severity": threats_by_severity,
            "threats_by_status": threats_by_status,
            "warnings": list(self.warnings),
        }
