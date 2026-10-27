#
# VULNEX -Universal Security Visualization Library-
#
# File: registry.py
# Author: Simon Roses Femerling
# Created: 2026-10-27
# Last Modified: 2026-10-27
# Version: 0.6.0
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""
The visualization modules, in one table.

Each module has a CLI mode number, a label and, for the modules built from
one input file through a class, a key (used by batch, diff, export and the
API) and that class. Batch processing and the CLI read their module lists
from here; the SVG engine keeps its own painter registry, keyed by class
name (see ``svgengine.register_painter``).

Adding a module: add its row here, then its painter (if any), drift adapter
(if any) and CLI branch.
"""

from __future__ import annotations

import importlib
from dataclasses import dataclass


@dataclass(frozen=True)
class ModuleInfo:
    """One visualization module."""

    mode: int
    label: str
    key: str = ""  # "" for modules with no single-file class (Mermaid, Cloud)
    target: str = ""  # "package.module:ClassName"

    @property
    def class_name(self) -> str:
        return self.target.rpartition(":")[2]

    def load(self) -> type:
        """Import and return the module's class."""
        if not self.target:
            raise LookupError(f"Mode {self.mode} ({self.label}) has no visualization class")
        module_path, _, name = self.target.partition(":")
        return getattr(importlib.import_module(module_path), name)


MODULES: tuple[ModuleInfo, ...] = (
    ModuleInfo(0, "Attack Trees", "attack_tree", "usecvislib.attacktrees:AttackTrees"),
    ModuleInfo(1, "Threat Modeling", "threat_model", "usecvislib.threatmodeling:ThreatModeling"),
    ModuleInfo(2, "Binary Visualization", "binary", "usecvislib.binvis:BinVis"),
    ModuleInfo(3, "Attack Graphs", "attack_graph", "usecvislib.attackgraphs:AttackGraphs"),
    ModuleInfo(4, "Mermaid Diagrams"),
    ModuleInfo(5, "Cloud Diagrams"),
    ModuleInfo(6, "Privilege Gradient Graphs", "privilege_gradient", "usecvislib.privilegegradient:PrivilegeGradient"),
    ModuleInfo(7, "Component Diagrams", "component_diagram", "usecvislib.componentdiagram:ComponentDiagram"),
    ModuleInfo(8, "Dependency Graphs", "dependency_graph", "usecvislib.dependencygraph:DependencyGraph"),
    ModuleInfo(9, "Kill Chain / MITRE ATT&CK", "kill_chain", "usecvislib.killchain:KillChain"),
    ModuleInfo(10, "Incident Timeline", "incident_timeline", "usecvislib.timeline:IncidentTimeline"),
    ModuleInfo(11, "Vulnerability Dependency Tree", "vuln_tree", "usecvislib.vulntree:VulnDependencyTree"),
    ModuleInfo(12, "MAESTRO Agentic Threat Model", "maestro", "usecvislib.maestro:MaestroThreatModel"),
)

_BY_MODE = {m.mode: m for m in MODULES}
_BY_KEY = {m.key: m for m in MODULES if m.key}


def by_mode(mode: int) -> ModuleInfo:
    """The module for a CLI mode number (KeyError if there is none)."""
    return _BY_MODE[mode]


def by_key(key: str) -> ModuleInfo:
    """The module for a key such as "attack_graph" (KeyError if there is none)."""
    return _BY_KEY[key]


def modes() -> list[int]:
    """All CLI mode numbers, in order."""
    return [m.mode for m in MODULES]


def file_module_classes() -> dict[str, type]:
    """Key -> class for every module built from one input file (imports them)."""
    return {m.key: m.load() for m in MODULES if m.key}


def svg_modules() -> list[ModuleInfo]:
    """Modules the SVG engine can paint (those with a registered painter)."""
    from . import svgengine

    return [m for m in MODULES if m.target and svgengine.is_supported(m.class_name)]
