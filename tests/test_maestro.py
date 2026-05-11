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
        assert catalog["catalog_version"] == "2026.1"
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
