#
# VULNEX -Universal Security Visualization Library-
#
# File: test_vulntree.py
# Author: Simon Roses Femerling
# Created: 2026-08-27
# Last Modified: 2026-08-27
# Version: 0.4.1
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Tests for the Vulnerability Dependency Tree module (CLI mode 11)."""

import glob
import shutil
from pathlib import Path

import pytest

from usecvislib.builders import VulnTreeBuilder
from usecvislib.vulntree import (
    SUPPORTED_MODES,
    Dependency,
    Vulnerability,
    VulnDependencyTree,
    VulnSeverity,
    VulnTreeError,
)

TESTS_DIR = Path(__file__).parent
TEMPLATES_DIR = TESTS_DIR.parent / "templates" / "vuln-trees"
TEMPLATES = sorted(glob.glob(str(TEMPLATES_DIR / "*.tml")))
NPM = str(TEMPLATES_DIR / "npm_supply_chain.tml")
PY = str(TEMPLATES_DIR / "python_requirements.tml")
LOG4J = str(TEMPLATES_DIR / "java_log4shell.tml")

HAVE_DOT = shutil.which("dot") is not None
requires_dot = pytest.mark.skipif(not HAVE_DOT, reason="graphviz 'dot' not installed")


def _build(inputfile, tmp_path, mode="tree", fmt="png", styleid="", name="out"):
    vt = VulnDependencyTree(inputfile, str(tmp_path / name), format=fmt, styleid=styleid, mode=mode)
    vt.build()
    return tmp_path / f"{name}.{fmt}"


class TestModel:
    def test_highest_severity_empty(self):
        assert Dependency("a", "a").highest_severity == VulnSeverity.NONE

    def test_highest_severity_picks_worst(self):
        dep = Dependency(
            "a",
            "a",
            vulnerabilities=[
                Vulnerability("CVE-1", VulnSeverity.LOW, cvss=3.0),
                Vulnerability("CVE-2", VulnSeverity.CRITICAL, cvss=9.5),
                Vulnerability("CVE-3", VulnSeverity.MEDIUM, cvss=5.0),
            ],
        )
        assert dep.highest_severity == VulnSeverity.CRITICAL

    def test_total_and_max_cvss(self):
        dep = Dependency(
            "a", "a", vulnerabilities=[Vulnerability("C1", VulnSeverity.HIGH, 7.0), Vulnerability("C2", VulnSeverity.LOW, 3.0)]
        )
        assert dep.total_cvss == 10.0
        assert dep.max_cvss == 7.0


class TestLoad:
    def test_load_npm(self):
        vt = VulnDependencyTree(NPM, "unused")
        vt.load()
        assert len(vt.dependencies) == 11
        assert vt.root_packages == ["web-app"]

    def test_missing_dependencies_errors(self, tmp_path):
        bad = tmp_path / "bad.tml"
        bad.write_text('dependencies = "notatable"\n[vulntree]\nname="x"\n')
        with pytest.raises(VulnTreeError):
            VulnDependencyTree(str(bad), "unused").load()

    def test_roots_inferred_when_absent(self, tmp_path):
        src = tmp_path / "t.tml"
        src.write_text(
            '[dependencies."a"]\nname="a"\ndependencies=["b"]\n'
            '[dependencies."b"]\nname="b"\ndirect=false\n'
        )
        vt = VulnDependencyTree(str(src), "unused")
        vt.load()
        assert vt.root_packages == ["a"]  # b is a child, a has in-degree 0

    def test_unknown_severity_falls_back(self, tmp_path):
        src = tmp_path / "t.tml"
        src.write_text(
            '[dependencies."a"]\nname="a"\n'
            '[[dependencies."a".vulnerabilities]]\nid="CVE-X"\nseverity="spicy"\ncvss=1.0\n'
        )
        vt = VulnDependencyTree(str(src), "unused")
        vt.load()
        assert vt.dependencies["a"].vulnerabilities[0].severity == VulnSeverity.NONE
        assert any("severity" in w for w in vt.warnings)

    def test_cycle_safe_load(self, tmp_path):
        src = tmp_path / "cycle.tml"
        src.write_text(
            '[dependencies."a"]\nname="a"\ndependencies=["b"]\n'
            '[dependencies."b"]\nname="b"\ndependencies=["a"]\n'
        )
        vt = VulnDependencyTree(str(src), "unused")
        vt.load()
        assert vt.validate() == []
        assert vt._reachable() == {"a", "b"}


class TestModes:
    def test_tree_shows_all_reachable(self):
        vt = VulnDependencyTree(LOG4J, "unused", mode="tree")
        vt.load()
        assert len(vt._visible_nodes()) == 6

    def test_vulnerable_only_prunes_clean_leaves(self):
        vt = VulnDependencyTree(LOG4J, "unused", mode="vulnerable_only")
        vt.load()
        vis = vt._visible_nodes()
        assert "commons-io" not in vis  # clean leaf pruned
        assert "log4j-api" not in vis  # clean leaf pruned
        assert "log4j-core" in vis  # keeps path to the CVE

    def test_critical_path_keeps_only_high_and_above(self):
        vt = VulnDependencyTree(PY, "unused", mode="critical_path")
        vt.load()
        vis = vt._visible_nodes()
        assert "pyyaml" in vis  # critical
        assert "urllib3" in vis  # high
        assert "werkzeug" not in vis  # medium -> pruned from critical_path

    def test_invalid_mode_falls_back_to_tree(self):
        vt = VulnDependencyTree(NPM, "unused", mode="nonsense")
        assert vt.mode == "tree"


class TestStats:
    def test_stats_shape(self):
        vt = VulnDependencyTree(NPM, "unused")
        s = vt.get_stats()
        assert s["total_dependencies"] == 11
        assert s["vulnerable_dependencies"] == 5
        assert s["total_vulnerabilities"] == 5
        assert s["exploited_vulnerabilities"] == 1
        assert s["max_cvss"] == 9.1
        assert s["severity_distribution"]["critical"] == 1
        assert s["remediation_available"] == 5

    def test_impact_propagation(self):
        vt = VulnDependencyTree(NPM, "unused")
        vt.load()
        impact = vt.impact_propagation()
        assert "web-app" in impact
        assert "follow-redirects" in impact["web-app"]

    def test_remediation(self):
        vt = VulnDependencyTree(NPM, "unused")
        vt.load()
        fixes = vt.remediation()
        assert len(fixes) == 5
        assert all("fixed_version" in f for f in fixes)


class TestValidate:
    def test_valid_templates(self):
        for t in (NPM, PY, LOG4J):
            assert VulnDependencyTree(t, "unused").validate() == []

    def test_unknown_child_flagged(self, tmp_path):
        src = tmp_path / "t.tml"
        src.write_text('[dependencies."a"]\nname="a"\ndependencies=["ghost"]\n')
        vt = VulnDependencyTree(str(src), "unused")
        errors = vt.validate()
        assert any("ghost" in e for e in errors)

    def test_no_dependencies_flagged(self, tmp_path):
        src = tmp_path / "t.tml"
        src.write_text('[vulntree]\nname="x"\n')
        vt = VulnDependencyTree(str(src), "unused")
        assert any("No dependencies" in e for e in vt.validate())


@requires_dot
class TestRender:
    @pytest.mark.parametrize("mode", SUPPORTED_MODES)
    def test_render_all_modes(self, tmp_path, mode):
        out = _build(NPM, tmp_path, mode=mode)
        assert out.exists()

    @pytest.mark.parametrize("template", [NPM, PY, LOG4J])
    def test_render_all_templates(self, tmp_path, template):
        out = _build(template, tmp_path, name=Path(template).stem)
        assert out.exists()

    def test_render_with_style(self, tmp_path):
        assert _build(NPM, tmp_path, styleid="vt_dark").exists()

    def test_render_svg(self, tmp_path):
        out = _build(NPM, tmp_path, fmt="svg")
        assert "<svg" in out.read_text(encoding="utf-8")[:2000]


class TestBuilder:
    def test_build_dict(self):
        b = (
            VulnTreeBuilder("app", root_packages=["a"])
            .add_dependency("a", "a", "1.0", dependencies=["b"])
            .add_dependency("b", "b", "2.0", direct=False)
            .add_vulnerability("b", "CVE-1", "critical", cvss=9.9, fixed_version="2.1", exploited=True)
        )
        data = b.build()
        assert list(data["dependencies"]) == ["a", "b"]
        assert data["dependencies"]["b"]["vulnerabilities"][0]["id"] == "CVE-1"

    def test_builder_stats(self, tmp_path):
        vt = (
            VulnTreeBuilder("app", root_packages=["a"])
            .add_dependency("a", "a", "1.0", dependencies=["b"])
            .add_dependency("b", "b", "2.0", direct=False)
            .add_vulnerability("b", "CVE-1", "high", cvss=7.7)
            .to_vuln_tree(str(tmp_path / "b"))
        )
        vt.load()
        assert vt.get_stats()["vulnerable_dependencies"] == 1

    def test_to_json(self):
        b = VulnTreeBuilder("app").add_dependency("a", "a")
        assert '"a"' in b.to_json()


class TestTemplates:
    def test_all_templates_present(self):
        assert len(TEMPLATES) >= 3

    @pytest.mark.parametrize("template", TEMPLATES)
    def test_template_loads_and_validates(self, template):
        assert VulnDependencyTree(template, "unused").validate() == []
