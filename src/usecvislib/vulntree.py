#
# VULNEX -Universal Security Visualization Library-
#
# File: vulntree.py
# Author: Simon Roses Femerling
# Created: 2026-08-27
# Last Modified: 2026-08-27
# Version: 0.4.1
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Vulnerability Dependency Tree visualization module (CLI mode 11).

Renders a software supply chain as a dependency tree annotated with the
CVEs affecting each package, coloured by the highest severity present.
Graphviz-based, top-down. Three render modes:

- **tree** (default): the full dependency tree reachable from the roots.
- **vulnerable_only**: prune to packages that are vulnerable or lead to one.
- **critical_path**: prune to packages on a path to a critical/high CVE.

Beyond the picture, the module reports impact propagation (which top-level
packages are exposed by a transitive CVE) and remediation hints (fixed
versions), so it doubles as a supply-chain triage aid.

Input schema (TOML/JSON/YAML)::

    [vulntree]
    name = "my-app dependencies"
    root_packages = ["app"]           # optional; inferred if omitted

    [dependencies."app"]
    name = "app"
    version = "1.0.0"
    direct = true
    dependencies = ["lodash", "express"]

    [[dependencies."lodash".vulnerabilities]]
    id = "CVE-2021-23337"
    severity = "high"
    cvss = 7.2
    fixed_version = "4.17.21"
    exploited = false
    cwe = "CWE-77"
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from . import utils
from .base import VisualizationBase

try:  # Graphviz is optional at import time
    from graphviz import Digraph
except ImportError:  # pragma: no cover
    Digraph = None  # type: ignore[assignment,misc]


class VulnTreeError(utils.RenderError):
    """Raised when vulnerability tree rendering or validation fails."""


class VulnSeverity(str, Enum):
    """Vulnerability severity levels (ordered high -> low)."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


# Severity ordering, most severe first.
_SEVERITY_ORDER = [
    VulnSeverity.CRITICAL,
    VulnSeverity.HIGH,
    VulnSeverity.MEDIUM,
    VulnSeverity.LOW,
    VulnSeverity.NONE,
]
_SEVERITY_RANK = {sev: i for i, sev in enumerate(_SEVERITY_ORDER)}
_VALID_SEVERITIES = {s.value for s in VulnSeverity}

SEVERITY_COLORS = {
    VulnSeverity.CRITICAL: "#7b1fa2",
    VulnSeverity.HIGH: "#c62828",
    VulnSeverity.MEDIUM: "#ef6c00",
    VulnSeverity.LOW: "#fbc02d",
    VulnSeverity.NONE: "#4caf50",
}

SUPPORTED_MODES = ("tree", "vulnerable_only", "critical_path")

_MAX_DEPTH = 64  # cycle/blow-up guard for pathological dependency graphs


def _html_escape(text: str) -> str:
    """Escape text for use inside a Graphviz HTML-like label."""
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


@dataclass
class Vulnerability:
    """A vulnerability (CVE) affecting a dependency."""

    id: str
    severity: VulnSeverity = VulnSeverity.NONE
    cvss: float = 0.0
    description: str = ""
    fixed_version: Optional[str] = None
    exploited: bool = False
    cwe: Optional[str] = None


@dataclass
class Dependency:
    """A software dependency (package node)."""

    id: str
    name: str
    version: str = ""
    direct: bool = True
    dependencies: list[str] = field(default_factory=list)
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    license: str = ""

    @property
    def highest_severity(self) -> VulnSeverity:
        if not self.vulnerabilities:
            return VulnSeverity.NONE
        return min(self.vulnerabilities, key=lambda v: _SEVERITY_RANK[v.severity]).severity

    @property
    def total_cvss(self) -> float:
        return sum(v.cvss for v in self.vulnerabilities)

    @property
    def max_cvss(self) -> float:
        return max((v.cvss for v in self.vulnerabilities), default=0.0)


class VulnDependencyTree(VisualizationBase):
    """Vulnerability dependency tree visualization (Graphviz, three modes)."""

    STYLE_FILE = "config_vulntree.tml"
    DEFAULT_STYLE_ID = "vt_default"
    SVG_DEFAULT_STYLE_ID = "sv_default"

    def __init__(
        self,
        inputfile: str,
        outputfile: str,
        format: str = "png",
        styleid: Optional[str] = None,
        validate_paths: bool = True,
        mode: str = "tree",
        render_engine: str = "graphviz",
    ) -> None:
        super().__init__(
            inputfile,
            outputfile,
            format=format or "png",
            styleid=styleid,
            validate_paths=validate_paths,
            render_engine=render_engine,
        )
        self.mode = mode if mode in SUPPORTED_MODES else "tree"
        self.dot: Optional[Any] = None
        self.dependencies: dict[str, Dependency] = {}
        self.root_packages: list[str] = []
        self.warnings: list[str] = []

    # --------------------------------------------------------- VisualizationBase

    def _default_style(self) -> dict[str, Any]:
        """Fallback style if the config file is unavailable (clean, light)."""
        return {
            "graph": {
                "rankdir": "TB",
                "bgcolor": "#f8fafc",
                "fontname": "Helvetica",
                "fontcolor": "#334155",
                "fontsize": "16",
                "pad": "0.4",
                "nodesep": "0.3",
                "ranksep": "0.55",
                "labelloc": "t",
            },
            "node": {
                "shape": "box",
                "style": "rounded,filled",
                "fontname": "Helvetica",
                "fontcolor": "#ffffff",
                "color": "#64748b",
                "fontsize": "10",
                "penwidth": "1",
            },
            "clean": {"fillcolor": "#4caf50", "fontcolor": "#ffffff"},
            "edge": {"color": "#94a3b8", "penwidth": "1.4", "arrowhead": "vee", "arrowsize": "0.7"},
            "direct": {"penwidth": "2.2", "color": "#1e293b"},
            "exploited": {"color": "#000000", "penwidth": "2.6"},
        }

    def _load_impl(self) -> dict[str, Any]:
        """Load and parse the vulnerability tree configuration."""
        data = utils.ReadConfigFile(self.inputfile)
        if not isinstance(data, dict):
            raise VulnTreeError("Vulnerability tree input must be a mapping")

        self.dependencies.clear()
        self.warnings.clear()

        raw_deps = data.get("dependencies", {})
        if not isinstance(raw_deps, dict):
            raise VulnTreeError("'dependencies' must be a table of dependency definitions")

        for dep_id, dd in raw_deps.items():
            dd = dd if isinstance(dd, dict) else {}
            vulns = []
            for vd in dd.get("vulnerabilities", []) or []:
                if not isinstance(vd, dict):
                    continue
                severity = str(vd.get("severity", "none")).lower()
                if severity not in _VALID_SEVERITIES:
                    self.warnings.append(
                        f"Vulnerability '{vd.get('id', '?')}': unknown severity '{severity}', using none"
                    )
                    severity = "none"
                vulns.append(
                    Vulnerability(
                        id=str(vd.get("id", "CVE-UNKNOWN")),
                        severity=VulnSeverity(severity),
                        cvss=float(vd.get("cvss", 0.0) or 0.0),
                        description=str(vd.get("description", "")),
                        fixed_version=vd.get("fixed_version"),
                        exploited=bool(vd.get("exploited", False)),
                        cwe=vd.get("cwe"),
                    )
                )
            self.dependencies[str(dep_id)] = Dependency(
                id=str(dep_id),
                name=str(dd.get("name", dep_id)),
                version=str(dd.get("version", "")),
                direct=bool(dd.get("direct", True)),
                dependencies=[str(c) for c in dd.get("dependencies", []) if isinstance(c, str | int)],
                vulnerabilities=vulns,
                license=str(dd.get("license", "")),
            )

        self.root_packages = self._resolve_roots(data)
        utils.check_graph_complexity(
            len(self.dependencies), sum(len(d.dependencies) for d in self.dependencies.values())
        )
        return data

    def _resolve_roots(self, data: dict[str, Any]) -> list[str]:
        """Determine root packages: explicit list, else in-degree-0 nodes."""
        vt = data.get("vulntree", {}) if isinstance(data.get("vulntree"), dict) else {}
        explicit = vt.get("root_packages") or data.get("root_packages")
        if isinstance(explicit, list) and explicit:
            roots = [str(r) for r in explicit if str(r) in self.dependencies]
            if roots:
                return roots
        # No explicit roots: pick nodes that nothing depends on (in-degree 0).
        child_ids = {c for d in self.dependencies.values() for c in d.dependencies}
        roots = [dep_id for dep_id in self.dependencies if dep_id not in child_ids]
        # Fully cyclic graph with no clear root: fall back to declared-direct.
        return roots or [d.id for d in self.dependencies.values() if d.direct] or list(self.dependencies)

    # ------------------------------------------------------------------ traversal

    def _reachable(self) -> set[str]:
        """Dependency ids reachable from the roots (cycle-safe DFS)."""
        seen: set[str] = set()

        def walk(dep_id: str, depth: int) -> None:
            if dep_id in seen or depth > _MAX_DEPTH or dep_id not in self.dependencies:
                return
            seen.add(dep_id)
            for child in self.dependencies[dep_id].dependencies:
                walk(child, depth + 1)

        for root in self.root_packages:
            walk(root, 0)
        return seen

    def _subtree_min_rank(self) -> dict[str, int]:
        """Best (lowest-rank = most severe) severity in each node's subtree."""
        memo: dict[str, int] = {}

        def rank_of(dep_id: str, stack: frozenset[str]) -> int:
            if dep_id in memo:
                return memo[dep_id]
            if dep_id in stack or dep_id not in self.dependencies:
                return _SEVERITY_RANK[VulnSeverity.NONE]
            dep = self.dependencies[dep_id]
            best = _SEVERITY_RANK[dep.highest_severity]
            for child in dep.dependencies:
                best = min(best, rank_of(child, stack | {dep_id}))
            memo[dep_id] = best
            return best

        return {dep_id: rank_of(dep_id, frozenset()) for dep_id in self.dependencies}

    def _visible_nodes(self) -> set[str]:
        """Nodes shown for the active mode."""
        reachable = self._reachable()
        if self.mode == "tree":
            return reachable
        threshold = (
            _SEVERITY_RANK[VulnSeverity.HIGH] if self.mode == "critical_path" else _SEVERITY_RANK[VulnSeverity.LOW]
        )
        subtree = self._subtree_min_rank()
        return {dep_id for dep_id in reachable if subtree.get(dep_id, 99) <= threshold}

    # ------------------------------------------------------------------ render

    def _render_impl(self) -> None:
        if Digraph is None:  # pragma: no cover
            raise VulnTreeError("graphviz is required to render the vulnerability tree")

        style = self.style if isinstance(self.style, dict) else self._default_style()
        name = self.inputdata.get("vulntree", {}).get("name", "Vulnerability Dependency Tree")
        self.dot = Digraph(name=name, format=self.format)
        self.dot.attr(**utils.stringify_dict(style.get("graph", self._default_style()["graph"])))
        self.dot.attr(label=name, labelloc="t", fontsize="16")

        visible = self._visible_nodes()
        edge_style = utils.stringify_dict(style.get("edge", self._default_style()["edge"]))
        exploited_style = style.get("exploited", self._default_style()["exploited"])

        for dep_id in visible:
            dep = self.dependencies[dep_id]
            self.dot.node(dep_id, label=self._graphviz_label(dep), **self._graphviz_node_style(dep, style))

        for dep_id in visible:
            dep = self.dependencies[dep_id]
            for child in dep.dependencies:
                if child in visible:
                    attrs = dict(edge_style)
                    if self.dependencies[child].vulnerabilities and any(
                        v.exploited for v in self.dependencies[child].vulnerabilities
                    ):
                        attrs.update(utils.stringify_dict(exploited_style))
                    self.dot.edge(dep_id, child, **attrs)

    def _graphviz_label(self, dep: Dependency) -> str:
        """HTML-like node label: name@version, CVE count and worst severity."""
        title = _html_escape(f"{dep.name}@{dep.version}" if dep.version else dep.name)
        rows = f"<TR><TD><B>{title}</B></TD></TR>"
        if dep.vulnerabilities:
            worst = dep.highest_severity.value
            cve = f"{len(dep.vulnerabilities)} CVE - {worst} (CVSS {dep.max_cvss:g})"
            rows += f'<TR><TD><FONT POINT-SIZE="9">{_html_escape(cve)}</FONT></TD></TR>'
        else:
            rows += '<TR><TD><FONT POINT-SIZE="9">no known CVEs</FONT></TD></TR>'
        return f'<<TABLE BORDER="0" CELLBORDER="0" CELLSPACING="0" CELLPADDING="1">{rows}</TABLE>>'

    def _graphviz_node_style(self, dep: Dependency, style: dict[str, Any]) -> dict[str, str]:
        base = dict(style.get("node", self._default_style()["node"]))
        sev = dep.highest_severity
        if sev == VulnSeverity.NONE:
            clean = style.get("clean", self._default_style()["clean"])
            base["fillcolor"] = clean.get("fillcolor", SEVERITY_COLORS[VulnSeverity.NONE])
            base["fontcolor"] = clean.get("fontcolor", "#ffffff")
        else:
            base["fillcolor"] = SEVERITY_COLORS[sev]
            base["fontcolor"] = "#000000" if sev == VulnSeverity.LOW else "#ffffff"
        if dep.direct:
            direct = style.get("direct", self._default_style()["direct"])
            base["penwidth"] = direct.get("penwidth", "2.2")
            base["color"] = direct.get("color", "#1e293b")
        base.setdefault("shape", "box")
        base.setdefault("style", "rounded,filled")
        base.setdefault("margin", "0.14,0.07")
        return utils.stringify_dict(base)

    def _draw_impl(self, outputfile: str) -> None:
        if self.dot is None:
            raise VulnTreeError("Graph not rendered; call render() first")
        self.dot.render(outputfile, cleanup=True)

    def _validate_impl(self) -> list[str]:
        errors = list(self.warnings)
        if not self.dependencies:
            errors.append("No dependencies defined")
        for dep in self.dependencies.values():
            for child in dep.dependencies:
                if child not in self.dependencies:
                    errors.append(f"Dependency '{dep.id}' references unknown dependency: {child}")
        for root in self.root_packages:
            if root not in self.dependencies:
                errors.append(f"Root package not found in dependencies: {root}")
        return errors

    # -------------------------------------------------------------- analysis

    def severity_distribution(self) -> dict[str, int]:
        """Count of dependencies bucketed by their highest severity."""
        dist = {s.value: 0 for s in VulnSeverity}
        for dep in self.dependencies.values():
            dist[dep.highest_severity.value] += 1
        return dist

    def impact_propagation(self) -> dict[str, list[str]]:
        """For each root, the vulnerable packages reachable beneath it."""
        impact: dict[str, list[str]] = {}
        for root in self.root_packages:
            vulnerable: list[str] = []
            self._collect_vulnerable(root, 0, set(), vulnerable)
            if vulnerable:
                impact[root] = vulnerable
        return impact

    def _collect_vulnerable(self, dep_id: str, depth: int, seen: set[str], vulnerable: list[str]) -> None:
        """Depth-first collect vulnerable packages beneath ``dep_id`` (cycle-safe)."""
        if dep_id in seen or depth > _MAX_DEPTH or dep_id not in self.dependencies:
            return
        seen.add(dep_id)
        if self.dependencies[dep_id].vulnerabilities:
            vulnerable.append(dep_id)
        for child in self.dependencies[dep_id].dependencies:
            self._collect_vulnerable(child, depth + 1, seen, vulnerable)

    def remediation(self) -> list[dict[str, str]]:
        """Fixed-version upgrade hints for vulnerable dependencies."""
        fixes: list[dict[str, str]] = []
        for dep in self.dependencies.values():
            for v in dep.vulnerabilities:
                if v.fixed_version:
                    fixes.append(
                        {
                            "dependency": dep.id,
                            "current": dep.version,
                            "cve": v.id,
                            "fixed_version": v.fixed_version,
                            "severity": v.severity.value,
                        }
                    )
        return fixes

    def _get_stats_impl(self) -> dict[str, Any]:
        deps = self.dependencies.values()
        all_vulns = [v for d in deps for v in d.vulnerabilities]
        vulnerable = [d for d in deps if d.vulnerabilities]
        return {
            "name": self.inputdata.get("vulntree", {}).get("name", "Vulnerability Dependency Tree"),
            "total_dependencies": len(self.dependencies),
            "direct_dependencies": sum(1 for d in deps if d.direct),
            "transitive_dependencies": sum(1 for d in deps if not d.direct),
            "vulnerable_dependencies": len(vulnerable),
            "total_vulnerabilities": len(all_vulns),
            "exploited_vulnerabilities": sum(1 for v in all_vulns if v.exploited),
            "severity_distribution": self.severity_distribution(),
            "max_cvss": max((v.cvss for v in all_vulns), default=0.0),
            "root_packages": list(self.root_packages),
            "impacted_roots": list(self.impact_propagation().keys()),
            "remediation_available": sum(1 for v in all_vulns if v.fixed_version),
            "warnings": list(self.warnings),
        }

    def _get_metadata_root_key(self) -> str:
        return "vulntree"

    # Convenience wrapper mirroring the other modules' Build* entry points.
    def BuildVulnTree(self) -> "VulnDependencyTree":
        """Load, render, and draw in one call."""
        self.build()
        return self
