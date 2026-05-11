#
# VULNEX -Universal Security Visualization Library-
#
# File: test_maestro.py
# Author: Simon Roses Femerling
# Created: 2026-05-11
# Last Modified: 2026-05-11
# Version: 0.4.0
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Unit tests for the MAESTRO agentic threat modeling module."""

import json
import os
import shutil
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from usecvislib.maestro import (
    CatalogMode,
    MaestroLayer,
    MaestroThreatModel,
    ThreatStatus,
)

GRAPHVIZ_INSTALLED = shutil.which('dot') is not None


VALID_TOML = '''
[meta]
name = "Test Single-Agent RAG"
version = "1.0"

[architecture]
patterns = ["single-agent", "task-oriented"]

[[agents]]
id = "support"
name = "Support Agent"
type = "task-oriented"
autonomy = "reactive"
layers = ["foundation-models", "data-operations", "agent-frameworks", "agent-ecosystem"]

[[assets]]
id = "kb"
name = "Knowledge Base"
layer = "data-operations"
sensitivity = "medium"

[catalog]
mode = "auto"
'''


PATTERN_MISMATCH_TOML = '''
# Multi-agent pattern declared but no agent touches L7 (agent-ecosystem).
# Loader must warn and not attach L7 pattern threats.

[meta]
name = "Pattern Mismatch Test"

[architecture]
patterns = ["multi-agent"]

[[agents]]
id = "internal_a"
layers = ["foundation-models", "agent-frameworks"]

[[agents]]
id = "internal_b"
layers = ["foundation-models", "agent-frameworks"]

[catalog]
mode = "auto"
'''


MANUAL_MODE_TOML = '''
[meta]
name = "Manual Mode Test"

[[agents]]
id = "agent_only"
layers = ["foundation-models"]

[catalog]
mode = "manual"
'''


OVERRIDE_TOML = '''
[meta]
name = "Override Test"

[[agents]]
id = "support"
layers = ["foundation-models", "data-operations"]

[[threats]]
id = "T-L2-002"
target = "support"
severity = "critical"
status = "mitigated"
mitigations = ["M-access-control"]

[catalog]
mode = "auto"
'''


class TestCatalog:
    """Tests for the built-in MAESTRO threat catalog."""

    def test_catalog_loads(self):
        m = MaestroThreatModel("dummy.toml", "out", validate_paths=False)
        catalog = m.get_catalog()
        assert catalog["catalog_version"].startswith("2026.")
        assert "threats" in catalog
        assert "cross_layer_threats" in catalog
        assert "pattern_threats" in catalog
        assert "mitigations" in catalog

    def test_catalog_threat_ids_unique(self):
        """Threat IDs are immutable identifiers — must be globally unique."""
        m = MaestroThreatModel("dummy.toml", "out", validate_paths=False)
        catalog = m.get_catalog()
        ids = [t["id"] for t in catalog["threats"]]
        cross_ids = [t["id"] for t in catalog["cross_layer_threats"]]
        all_ids = ids + cross_ids
        assert len(all_ids) == len(set(all_ids)), "Duplicate catalog IDs found"

    def test_catalog_covers_all_seven_layers(self):
        m = MaestroThreatModel("dummy.toml", "out", validate_paths=False)
        catalog = m.get_catalog()
        layers_with_threats = {t["layer"] for t in catalog["threats"]}
        expected = {layer.value for layer in MaestroLayer}
        assert layers_with_threats == expected

    def test_catalog_mitigations_well_formed(self):
        m = MaestroThreatModel("dummy.toml", "out", validate_paths=False)
        catalog = m.get_catalog()
        for mit in catalog["mitigations"]:
            assert "id" in mit
            assert "layer" in mit
            assert "type" in mit
            assert mit["type"] in ("preventive", "detective", "responsive", "compensating")


class TestParse:
    """Tests for config parsing."""

    def test_parse_valid_toml(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.toml', delete=False) as f:
            f.write(VALID_TOML)
            f.flush()
            try:
                m = MaestroThreatModel(f.name, "out", validate_paths=False)
                m.load()
                assert "support" in m.agents
                assert m.agents["support"].name == "Support Agent"
                assert m.agents["support"].autonomy == "reactive"
                assert "kb" in m.assets
                assert m.assets["kb"].sensitivity == "medium"
                assert "single-agent" in m.patterns
                assert "task-oriented" in m.patterns
            finally:
                os.unlink(f.name)

    def test_parse_valid_json(self):
        config = {
            "meta": {"name": "JSON Test"},
            "agents": [
                {"id": "a", "layers": ["foundation-models"]}
            ],
            "architecture": {"patterns": ["single-agent"]},
            "catalog": {"mode": "auto"},
        }
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(config, f)
            f.flush()
            try:
                m = MaestroThreatModel(f.name, "out", validate_paths=False)
                m.load()
                assert "a" in m.agents
                assert m.agents["a"].layers == ["foundation-models"]
            finally:
                os.unlink(f.name)

    def test_unknown_layer_warns(self):
        config = '''
[meta]
name = "Unknown Layer Test"

[[agents]]
id = "a"
layers = ["foundation-models", "nonexistent-layer"]
'''
        with tempfile.NamedTemporaryFile(mode='w', suffix='.toml', delete=False) as f:
            f.write(config)
            f.flush()
            try:
                m = MaestroThreatModel(f.name, "out", validate_paths=False)
                m.load()
                # Bad layer dropped, warning emitted
                assert m.agents["a"].layers == ["foundation-models"]
                assert any("nonexistent-layer" in w for w in m.warnings)
            finally:
                os.unlink(f.name)


class TestAutoPopulate:
    """Tests for catalog auto-population."""

    def test_auto_attaches_layer_threats(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.toml', delete=False) as f:
            f.write(VALID_TOML)
            f.flush()
            try:
                m = MaestroThreatModel(f.name, "out", validate_paths=False)
                m.load()
                # The agent touches L1, L2, L3, L7 — expect threats on each
                layers_seen = {t.layer for t in m.threats.values()}
                assert "foundation-models" in layers_seen
                assert "data-operations" in layers_seen
                assert "agent-frameworks" in layers_seen
                assert "agent-ecosystem" in layers_seen
                # Should not include layers the agent doesn't touch
                assert "infrastructure" not in layers_seen
                assert "observability" not in layers_seen
            finally:
                os.unlink(f.name)

    def test_pattern_layer_mismatch_warns(self):
        """multi-agent pattern implies L7 threats; with no L7 agent, must warn."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.toml', delete=False) as f:
            f.write(PATTERN_MISMATCH_TOML)
            f.flush()
            try:
                m = MaestroThreatModel(f.name, "out", validate_paths=False)
                m.load()
                # Expect a warning about pattern -> layer mismatch
                pattern_warnings = [
                    w for w in m.warnings if "multi-agent" in w and "skipping" in w
                ]
                assert len(pattern_warnings) > 0
                # L7 ecosystem threats must NOT be attached
                assert not any(
                    t.layer == "agent-ecosystem" for t in m.threats.values()
                )
            finally:
                os.unlink(f.name)

    def test_manual_mode_skips_auto_populate(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.toml', delete=False) as f:
            f.write(MANUAL_MODE_TOML)
            f.flush()
            try:
                m = MaestroThreatModel(f.name, "out", validate_paths=False)
                m.load()
                assert m.catalog_mode == CatalogMode.MANUAL.value
                # No catalog threats should have been attached
                assert all(not t.from_catalog for t in m.threats.values())
                assert len(m.threats) == 0
            finally:
                os.unlink(f.name)

    def test_user_override_wins(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.toml', delete=False) as f:
            f.write(OVERRIDE_TOML)
            f.flush()
            try:
                m = MaestroThreatModel(f.name, "out", validate_paths=False)
                m.load()
                composite_id = "T-L2-002@support"
                assert composite_id in m.threats
                threat = m.threats[composite_id]
                assert threat.severity == "critical"
                assert threat.status == ThreatStatus.MITIGATED.value
                assert "M-access-control" in threat.mitigations
            finally:
                os.unlink(f.name)


class TestValidate:
    """Tests for validation."""

    def test_no_agents_fails(self):
        config = '[meta]\nname = "Empty"\n'
        with tempfile.NamedTemporaryFile(mode='w', suffix='.toml', delete=False) as f:
            f.write(config)
            f.flush()
            try:
                m = MaestroThreatModel(f.name, "out", validate_paths=False)
                m.load()
                errors = m.validate()
                assert any("No agents" in e for e in errors)
            finally:
                os.unlink(f.name)

    def test_agent_without_layers_fails(self):
        config = '''
[meta]
name = "Layerless"

[[agents]]
id = "a"
'''
        with tempfile.NamedTemporaryFile(mode='w', suffix='.toml', delete=False) as f:
            f.write(config)
            f.flush()
            try:
                m = MaestroThreatModel(f.name, "out", validate_paths=False)
                m.load()
                errors = m.validate()
                assert any("no declared layers" in e for e in errors)
            finally:
                os.unlink(f.name)

    def test_valid_config_passes_validation(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.toml', delete=False) as f:
            f.write(VALID_TOML)
            f.flush()
            try:
                m = MaestroThreatModel(f.name, "out", validate_paths=False)
                m.load()
                errors = m.validate()
                assert errors == []
            finally:
                os.unlink(f.name)


@pytest.mark.skipif(not GRAPHVIZ_INSTALLED, reason="Graphviz 'dot' not installed")
class TestRender:
    """Smoke tests for rendering."""

    def test_render_produces_output(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with tempfile.NamedTemporaryFile(
                mode='w', suffix='.toml', delete=False, dir=tmpdir
            ) as f:
                f.write(VALID_TOML)
                f.flush()
                input_path = f.name

            output_path = os.path.join(tmpdir, "out")
            m = MaestroThreatModel(input_path, output_path, format="png", validate_paths=False)
            m.build()
            assert os.path.exists(output_path + ".png")

    def test_render_dot_format(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with tempfile.NamedTemporaryFile(
                mode='w', suffix='.toml', delete=False, dir=tmpdir
            ) as f:
                f.write(VALID_TOML)
                f.flush()
                input_path = f.name

            output_path = os.path.join(tmpdir, "out")
            m = MaestroThreatModel(input_path, output_path, format="dot", validate_paths=False)
            m.build()
            assert os.path.exists(output_path + ".dot")


class TestStats:
    """Tests for stats output."""

    def test_stats_shape(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.toml', delete=False) as f:
            f.write(VALID_TOML)
            f.flush()
            try:
                m = MaestroThreatModel(f.name, "out", validate_paths=False)
                m.load()
                stats = m.get_stats()
                # Required keys
                for key in (
                    "name", "total_agents", "total_assets", "total_threats",
                    "total_cross_layer_threats", "total_mitigations",
                    "patterns", "unmitigated_threats", "threats_by_layer",
                    "threats_by_severity", "threats_by_status", "warnings",
                ):
                    assert key in stats
                assert stats["total_agents"] == 1
                assert stats["total_threats"] > 0
            finally:
                os.unlink(f.name)


class TestStylePresets:
    """All 5 ma_* style presets must load (Phase 4)."""

    PRESETS = ("ma_default", "ma_dark", "ma_blueprint", "ma_severity", "ma_compact")

    def test_all_presets_loadable(self):
        for sid in self.PRESETS:
            m = MaestroThreatModel("dummy.toml", "out", styleid=sid, validate_paths=False)
            style = m.style
            assert "graph" in style
            assert "agent" in style
            assert "layer" in style
            assert "cross_layer_edge" in style


class TestHeatmapView:
    """Matplotlib heatmap render view (Phase 4)."""

    HEATMAP_CONFIG = '''
[meta]
name = "Heatmap Smoke Test"

[architecture]
patterns = ["single-agent", "task-oriented"]

[[agents]]
id = "alpha"
type = "task-oriented"
autonomy = "reactive"
layers = ["foundation-models", "data-operations", "agent-ecosystem"]
'''

    def test_heatmap_renders_to_png(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = os.path.join(tmpdir, "model.toml")
            with open(input_path, "w") as f:
                f.write(self.HEATMAP_CONFIG)
            output_base = os.path.join(tmpdir, "heatmap_out")
            m = MaestroThreatModel(
                input_path, output_base, format="png",
                view="heatmap", validate_paths=False,
            )
            m.build()
            assert os.path.exists(output_base + ".png")
            assert os.path.getsize(output_base + ".png") > 1000

    def test_view_falls_back_to_layered_on_invalid(self):
        m = MaestroThreatModel("dummy.toml", "out", view="nonexistent", validate_paths=False)
        assert m.view == "layered"

    def test_heatmap_with_no_agents_does_not_crash(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = os.path.join(tmpdir, "empty.toml")
            with open(input_path, "w") as f:
                f.write('[meta]\nname = "Empty"\n')
            output_base = os.path.join(tmpdir, "empty_out")
            m = MaestroThreatModel(
                input_path, output_base, format="png",
                view="heatmap", validate_paths=False,
            )
            # Validation will report no agents but build should still produce a placeholder
            m.load().render().draw()
            assert os.path.exists(output_base + ".png")


class TestExports:
    """Tests for the cross-reference export methods (Phase 3)."""

    EXPORT_CONFIG = '''
[meta]
name = "Export Test"

[architecture]
patterns = ["multi-agent", "hierarchical"]

[[agents]]
id = "router"
name = "Router"
type = "task-oriented"
autonomy = "reactive"
layers = ["foundation-models", "agent-frameworks", "agent-ecosystem"]

[[agents]]
id = "billing"
name = "Billing"
type = "task-oriented"
autonomy = "deliberative"
layers = ["foundation-models", "data-operations", "agent-ecosystem"]

[[assets]]
id = "kb"
name = "Knowledge Base"
layer = "data-operations"
sensitivity = "high"

[[cross_layer_threats]]
id = "CL-test"
name = "Test chain"
layers = ["agent-ecosystem", "data-operations"]
attack_chain = ["T-L7-005", "T-L2-002"]
severity = "critical"
'''

    def _build(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.toml', delete=False) as f:
            f.write(self.EXPORT_CONFIG)
            f.flush()
            m = MaestroThreatModel(f.name, "out", validate_paths=False)
            m.load()
            try:
                return m
            finally:
                os.unlink(f.name)

    def test_to_stride_shape(self):
        m = self._build()
        s = m.to_stride()
        assert s["_meta"]["source_framework"] == "MAESTRO"
        assert s["_meta"]["target_framework"] == "STRIDE"
        assert "exact" in s["_meta"]["mapping_counts"]
        assert "partial" in s["_meta"]["mapping_counts"]
        assert "informational" in s["_meta"]["mapping_counts"]
        # Sum of counts equals total threats
        total = sum(s["_meta"]["mapping_counts"].values())
        assert total == s["_meta"]["total_threats"]
        # Required STRIDE structural sections present
        for key in ("model", "externals", "processes", "datastores", "dataflows", "threats"):
            assert key in s
        # Each threat carries a mapping label
        for t in s["threats"].values():
            assert t["mapping"] in ("exact", "partial", "informational")

    def test_to_stride_unmapped_pct_is_proportional(self):
        m = self._build()
        s = m.to_stride()
        counts = s["_meta"]["mapping_counts"]
        if s["_meta"]["total_threats"] > 0:
            expected = counts["informational"] / s["_meta"]["total_threats"] * 100
            assert abs(s["_meta"]["unmapped_pct"] - expected) < 0.001

    def test_to_attack_graph_shape(self):
        m = self._build()
        ag = m.to_attack_graph()
        assert ag["_meta"]["target_framework"] == "AttackGraph"
        # 2 agents -> 2 hosts
        assert len(ag["hosts"]) == 2
        host_ids = {h["id"] for h in ag["hosts"]}
        assert "router" in host_ids
        assert "billing" in host_ids
        # Chain produced edges
        assert len(ag["edges"]) >= 1
        for edge in ag["edges"]:
            assert "from" in edge and "to" in edge

    def test_to_privilege_gradient_zones_from_autonomy(self):
        m = self._build()
        pg = m.to_privilege_gradient()
        assert pg["_meta"]["target_framework"] == "PrivilegeGradient"
        # 5 zones (Z0..Z4)
        assert len(pg["zones"]) == 5
        # router has reactive autonomy -> Z1
        # billing has deliberative autonomy -> Z2
        comp_zones = {c["id"]: c["zone"] for c in pg["components"]}
        assert comp_zones["router"] == "Z1"
        assert comp_zones["billing"] == "Z2"

    def test_attack_chain_edges_match_targets(self):
        m = self._build()
        ag = m.to_attack_graph()
        # The chain T-L7-005@router -> T-L2-002@billing should produce
        # an edge from "router" to "billing".
        edge_pairs = {(e["from"], e["to"]) for e in ag["edges"]}
        assert ("router", "billing") in edge_pairs


class TestATTCKTagging:
    """Catalog should expose ATT&CK placeholders for selected threats (Phase 3)."""

    def test_catalog_version_bumped(self):
        m = MaestroThreatModel("dummy.toml", "out", validate_paths=False)
        catalog = m.get_catalog()
        assert catalog["catalog_version"] == "2026.2"

    def test_known_threats_have_attack_tags(self):
        m = MaestroThreatModel("dummy.toml", "out", validate_paths=False)
        catalog = m.get_catalog()
        threats_by_id = {t["id"]: t for t in catalog["threats"]}
        # A handful of obvious mappings — keep deliberately small;
        # full tagging is a deferred human pass.
        expected = {
            "T-L2-002": "TA0010",     # Data Exfiltration
            "T-L4-006": "TA0008",     # Lateral Movement
            "T-L7-002": "T1656",      # Agent Impersonation
        }
        for tid, expected_attack in expected.items():
            assert threats_by_id[tid]["mitre_attack"] == expected_attack


class TestTemplate:
    """End-to-end test against the shipped template."""

    def test_shipped_template_loads(self):
        template_path = os.path.join(
            os.path.dirname(__file__),
            "..",
            "templates",
            "maestro",
            "single-agent-rag.toml",
        )
        if not os.path.exists(template_path):
            pytest.skip("Template not found")
        m = MaestroThreatModel(template_path, "out", validate_paths=False)
        m.load()
        errors = m.validate()
        assert errors == []
        stats = m.get_stats()
        assert stats["total_agents"] == 1
        # User overrides applied: T-L2-002 critical/in-progress, T-L2-005 mitigated
        assert "T-L2-002@support_agent" in m.threats
        assert m.threats["T-L2-002@support_agent"].severity == "critical"
        assert m.threats["T-L2-002@support_agent"].status == "in-progress"
        assert "T-L2-005@support_agent" in m.threats
        assert m.threats["T-L2-005@support_agent"].status == "mitigated"
