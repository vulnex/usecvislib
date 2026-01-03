#
# VULNEX -Universal Security Visualization Library-
#
# File: test_threatmodeling.py
# Author: Simon Roses Femerling
# Created: 2025-01-01
# Last Modified: 2025-12-23
# Version: 0.3.1
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Unit tests for threatmodeling module."""

import os
import shutil
import sys
import tempfile
import pytest

# Add src to path for testing
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from usecvislib.threatmodeling import ThreatModeling

# Check if graphviz is installed
GRAPHVIZ_INSTALLED = shutil.which('dot') is not None


# Sample valid threat model TOML content
VALID_THREAT_MODEL = '''
[model]
name = "Test Threat Model"
description = "A test model"

[externals]
[externals.user]
label = "User"

[processes]
[processes.webapp]
label = "Web Application"

[processes.api]
label = "API Server"

[datastores]
[datastores.database]
label = "Database"

[dataflows]
[dataflows.user_to_web]
from = "user"
to = "webapp"
label = "HTTP Request"

[dataflows.web_to_api]
from = "webapp"
to = "api"
label = "API Call"

[dataflows.api_to_db]
from = "api"
to = "database"
label = "SQL Query"

[boundaries]
[boundaries.internal]
label = "Internal Network"
elements = ["api", "database"]
'''

MINIMAL_THREAT_MODEL = '''
[model]
name = "Minimal Model"

[externals]

[processes]

[datastores]

[dataflows]

[boundaries]
'''


class TestThreatModelingInit:
    """Tests for ThreatModeling initialization."""

    def test_init_defaults(self):
        """Test default initialization values."""
        tm = ThreatModeling("input.tml", "output", validate_paths=False)
        assert tm.format == "png"
        assert tm.styleid == "tm_default"
        assert tm.inputfile == "input.tml"
        assert tm.outputfile == "output"

    def test_init_custom_format(self):
        """Test custom format initialization."""
        tm = ThreatModeling("input.tml", "output", format="svg", validate_paths=False)
        assert tm.format == "svg"

    def test_init_custom_style(self):
        """Test custom style initialization."""
        tm = ThreatModeling("input.tml", "output", styleid="tm_stride", validate_paths=False)
        assert tm.styleid == "tm_stride"


class TestThreatModelingLoad:
    """Tests for threat model data loading."""

    def test_load_valid_file(self):
        """Test loading a valid threat model file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(VALID_THREAT_MODEL)
            f.flush()
            try:
                tm = ThreatModeling(f.name, "output", validate_paths=False)
                tm.load()
                data = tm.inputdata
                assert "model" in data
                assert "externals" in data
                assert "processes" in data
                assert "datastores" in data
                assert "dataflows" in data
                assert data["model"]["name"] == "Test Threat Model"
            finally:
                os.unlink(f.name)


class TestThreatModelingRender:
    """Tests for threat model rendering."""

    def test_render_valid_model(self):
        """Test rendering a valid threat model."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(VALID_THREAT_MODEL)
            f.flush()
            try:
                tm = ThreatModeling(f.name, "output", validate_paths=False)
                tm.load()
                tm.Render()
                assert tm.graph is not None
            finally:
                os.unlink(f.name)

    def test_render_minimal_model(self):
        """Test rendering a minimal threat model."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(MINIMAL_THREAT_MODEL)
            f.flush()
            try:
                tm = ThreatModeling(f.name, "output", validate_paths=False)
                tm.load()
                tm.Render()
                assert tm.graph is not None
            finally:
                os.unlink(f.name)


class TestThreatModelingDraw:
    """Tests for threat model output generation."""

    @pytest.mark.skipif(not GRAPHVIZ_INSTALLED, reason="Graphviz not installed")
    def test_full_build(self):
        """Test complete build process."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(VALID_THREAT_MODEL)
            f.flush()
            try:
                with tempfile.TemporaryDirectory() as tmpdir:
                    output = os.path.join(tmpdir, "output")
                    tm = ThreatModeling(f.name, output, format="dot")
                    tm.BuildThreatModel()
                    assert os.path.exists(f"{output}.dot")
            finally:
                os.unlink(f.name)


class TestThreatModelingStats:
    """Tests for threat model statistics."""

    def test_get_model_stats(self):
        """Test getting model statistics."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(VALID_THREAT_MODEL)
            f.flush()
            try:
                tm = ThreatModeling(f.name, "output", validate_paths=False)
                stats = tm.get_model_stats()
                assert stats["total_externals"] == 1
                assert stats["total_processes"] == 2
                assert stats["total_datastores"] == 1
                assert stats["total_dataflows"] == 3
                assert stats["total_boundaries"] == 1
                assert stats["total_elements"] == 4
            finally:
                os.unlink(f.name)


class TestThreatModelingSTRIDE:
    """Tests for STRIDE analysis."""

    def test_analyze_stride(self):
        """Test STRIDE threat analysis."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(VALID_THREAT_MODEL)
            f.flush()
            try:
                tm = ThreatModeling(f.name, "output", validate_paths=False)
                tm.load()
                threats = tm.analyze_stride()
                # Check all STRIDE categories present
                assert "Spoofing" in threats
                assert "Tampering" in threats
                assert "Repudiation" in threats
                assert "Information Disclosure" in threats
                assert "Denial of Service" in threats
                assert "Elevation of Privilege" in threats
                # Should have identified some threats
                assert len(threats["Spoofing"]) > 0
                assert len(threats["Tampering"]) > 0
            finally:
                os.unlink(f.name)

    def test_generate_stride_report(self):
        """Test STRIDE report generation."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(VALID_THREAT_MODEL)
            f.flush()
            try:
                tm = ThreatModeling(f.name, "output", validate_paths=False)
                tm.load()
                report = tm.generate_stride_report()
                assert "STRIDE Threat Analysis Report" in report
                assert "Test Threat Model" in report
                assert "Spoofing" in report
                assert "Tampering" in report
            finally:
                os.unlink(f.name)

    def test_generate_stride_report_to_file(self):
        """Test STRIDE report file generation."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(VALID_THREAT_MODEL)
            f.flush()
            try:
                with tempfile.TemporaryDirectory() as tmpdir:
                    report_file = os.path.join(tmpdir, "report.md")
                    tm = ThreatModeling(f.name, "output", validate_paths=False)
                    tm.load()
                    tm.generate_stride_report(report_file)
                    assert os.path.exists(report_file)
                    with open(report_file, 'r') as rf:
                        content = rf.read()
                        assert "STRIDE" in content
            finally:
                os.unlink(f.name)

    def test_stride_boundary_crossing(self):
        """Test detection of flows crossing trust boundaries."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(VALID_THREAT_MODEL)
            f.flush()
            try:
                tm = ThreatModeling(f.name, "output", validate_paths=False)
                tm.load()
                threats = tm.analyze_stride()
                # Should detect information disclosure threats (e.g., unencrypted flows)
                info_disclosure = threats["Information Disclosure"]
                # Check we have some information disclosure threats
                assert len(info_disclosure) > 0
            finally:
                os.unlink(f.name)


class TestThreatModelingBoundaries:
    """Tests for trust boundary handling."""

    def test_elements_in_boundaries(self):
        """Test that elements are properly grouped in boundaries."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(VALID_THREAT_MODEL)
            f.flush()
            try:
                tm = ThreatModeling(f.name, "output", validate_paths=False)
                tm.load()
                tm.Render()
                # Check that the graph was created with subgraphs
                source = tm.graph.source
                assert "cluster_internal" in source
            finally:
                os.unlink(f.name)


# Test data with comprehensive properties for PyTM testing
PYTM_THREAT_MODEL = '''
[model]
name = "PyTM Test Model"
description = "Test model with full PyTM properties"

[externals]
[externals.admin_user]
label = "Admin User"
isAdmin = true
isTrusted = true

[externals.public_user]
label = "Public User"
isAdmin = false
isTrusted = false

[processes]
[processes.web_server]
label = "Web Server"
isServer = true
authenticatesSource = true
sanitizesInput = true
hasAccessControl = true
isHardened = true
implementsCSRFToken = true
handlesResourceConsumption = true

[processes.api_service]
label = "API Service"
authenticatesSource = true
authenticatesDestination = true
encodesOutput = true
checksInputBounds = true

[datastores]
[datastores.main_db]
label = "Main Database"
isSQL = true
isEncrypted = true
hasAccessControl = true
storesPII = true
storesCredentials = false
hasBackup = true
isAuditLogged = true

[datastores.cache]
label = "Cache Server"
isSQL = false
isEncrypted = false
isShared = true

[dataflows]
[dataflows.user_to_web]
from = "public_user"
to = "web_server"
label = "HTTPS Request"
protocol = "HTTPS"
isEncrypted = true
authenticatesSource = true

[dataflows.web_to_api]
from = "web_server"
to = "api_service"
label = "Internal API Call"
protocol = "gRPC"
isEncrypted = true

[dataflows.api_to_db]
from = "api_service"
to = "main_db"
label = "SQL Query"
protocol = "TLS"
isEncrypted = true
isPII = true

[dataflows.api_to_cache]
from = "api_service"
to = "cache"
label = "Cache Access"
isEncrypted = false

[boundaries]
[boundaries.dmz]
label = "DMZ"
elements = ["web_server"]
trustLevel = 30

[boundaries.internal]
label = "Internal Network"
elements = ["api_service", "main_db", "cache"]
trustLevel = 70
'''


class TestPyTMWrapper:
    """Tests for PyTM wrapper functionality."""

    def test_pytm_wrapper_init(self):
        """Test PyTMWrapper initialization."""
        from usecvislib.threatmodeling import PyTMWrapper

        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(VALID_THREAT_MODEL)
            f.flush()
            try:
                tm = ThreatModeling(f.name, "output", validate_paths=False)
                tm.load()

                wrapper = PyTMWrapper(tm.inputdata, "output_test", "png")
                assert wrapper.inputdata == tm.inputdata
                assert wrapper.outputfile == "output_test"
                assert wrapper.format == "png"
            finally:
                os.unlink(f.name)

    def test_pytm_availability_check(self):
        """Test that PyTM availability is correctly detected."""
        from usecvislib.threatmodeling import PyTMWrapper

        wrapper = PyTMWrapper({}, "output", "png")
        # This should not raise an error
        is_available = wrapper._pytm_available
        assert isinstance(is_available, bool)

    def test_pytm_static_availability(self):
        """Test static method to check PyTM availability."""
        is_available = ThreatModeling.is_pytm_available()
        assert isinstance(is_available, bool)

    def test_available_engines(self):
        """Test getting list of available engines."""
        engines = ThreatModeling.get_available_engines()
        assert "usecvislib" in engines
        assert "pytm" in engines


@pytest.mark.skip(reason="PyTMWrapper report generation methods not yet implemented")
class TestPyTMReportGeneration:
    """Tests for PyTM report generation."""

    def test_generate_markdown_report_structure(self):
        """Test Markdown report generation structure."""
        from usecvislib.threatmodeling import PyTMWrapper

        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(PYTM_THREAT_MODEL)
            f.flush()
            try:
                tm = ThreatModeling(f.name, "output", validate_paths=False)
                tm.load()

                wrapper = PyTMWrapper(tm.inputdata, "output_test", "png")

                # Only test if PyTM is available
                if wrapper._pytm_available:
                    report = wrapper.generate_markdown_report()

                    # Check report structure
                    assert "# Threat Model Report" in report
                    assert "PyTM Test Model" in report
                    assert "## Executive Summary" in report
                    assert "## System Components" in report
                    assert "### Processes" in report
                    assert "### Data Stores" in report
                    assert "### External Entities" in report
                    assert "### Data Flows" in report
                    assert "## Threat Analysis" in report
                    assert "### STRIDE Analysis" in report
            finally:
                os.unlink(f.name)

    def test_generate_markdown_report_content(self):
        """Test Markdown report contains model data."""
        from usecvislib.threatmodeling import PyTMWrapper

        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(PYTM_THREAT_MODEL)
            f.flush()
            try:
                tm = ThreatModeling(f.name, "output", validate_paths=False)
                tm.load()

                wrapper = PyTMWrapper(tm.inputdata, "output_test", "png")

                if wrapper._pytm_available:
                    report = wrapper.generate_markdown_report()

                    # Check element names appear
                    assert "Web Server" in report
                    assert "API Service" in report
                    assert "Main Database" in report
                    assert "Cache Server" in report
            finally:
                os.unlink(f.name)

    def test_generate_html_report_structure(self):
        """Test HTML report generation structure."""
        from usecvislib.threatmodeling import PyTMWrapper

        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(PYTM_THREAT_MODEL)
            f.flush()
            try:
                tm = ThreatModeling(f.name, "output", validate_paths=False)
                tm.load()

                wrapper = PyTMWrapper(tm.inputdata, "output_test", "png")

                if wrapper._pytm_available:
                    report = wrapper.generate_html_report()

                    # Check HTML structure
                    assert "<!DOCTYPE html>" in report
                    assert "<html" in report
                    assert "</html>" in report
                    assert "<style>" in report
                    assert "Threat Model Report" in report
                    assert "PyTM Test Model" in report
            finally:
                os.unlink(f.name)

    def test_generate_html_report_styling(self):
        """Test HTML report includes styling."""
        from usecvislib.threatmodeling import PyTMWrapper

        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(PYTM_THREAT_MODEL)
            f.flush()
            try:
                tm = ThreatModeling(f.name, "output", validate_paths=False)
                tm.load()

                wrapper = PyTMWrapper(tm.inputdata, "output_test", "png")

                if wrapper._pytm_available:
                    report = wrapper.generate_html_report()

                    # Check CSS styling
                    assert "font-family" in report
                    assert ".stat-card" in report
                    assert ".threat-card" in report
                    assert ".stride-section" in report
            finally:
                os.unlink(f.name)


@pytest.mark.skip(reason="PyTMWrapper threat library methods not yet implemented")
class TestPyTMThreatLibrary:
    """Tests for PyTM threat library access."""

    def test_get_threat_library_returns_list(self):
        """Test that threat library returns a list."""
        from usecvislib.threatmodeling import PyTMWrapper

        wrapper = PyTMWrapper({}, "output", "png")
        threats = wrapper.get_threat_library()

        assert isinstance(threats, list)

    def test_get_threats_by_element_type(self):
        """Test filtering threats by element type."""
        from usecvislib.threatmodeling import PyTMWrapper

        wrapper = PyTMWrapper({}, "output", "png")

        # Get filtered threats
        process_threats = wrapper.get_threats_by_element_type("Process")
        server_threats = wrapper.get_threats_by_element_type("Server")

        assert isinstance(process_threats, list)
        assert isinstance(server_threats, list)


class TestPyTMPropertyMapping:
    """Tests for PyTM property mapping."""

    def test_process_properties_mapped(self):
        """Test that process properties are correctly mapped."""
        from usecvislib.threatmodeling import PyTMWrapper

        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(PYTM_THREAT_MODEL)
            f.flush()
            try:
                tm = ThreatModeling(f.name, "output", validate_paths=False)
                tm.load()

                wrapper = PyTMWrapper(tm.inputdata, "output_test", "png")

                if wrapper._pytm_available:
                    wrapper.build_model()

                    # Check elements were created
                    assert "web_server" in wrapper.elements
                    assert "api_service" in wrapper.elements

                    # Check web_server properties
                    web_server = wrapper.elements["web_server"]
                    assert hasattr(web_server, 'name')
            finally:
                os.unlink(f.name)

    def test_datastore_properties_mapped(self):
        """Test that datastore properties are correctly mapped."""
        from usecvislib.threatmodeling import PyTMWrapper

        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(PYTM_THREAT_MODEL)
            f.flush()
            try:
                tm = ThreatModeling(f.name, "output", validate_paths=False)
                tm.load()

                wrapper = PyTMWrapper(tm.inputdata, "output_test", "png")

                if wrapper._pytm_available:
                    wrapper.build_model()

                    # Check datastore elements were created
                    assert "main_db" in wrapper.elements
                    assert "cache" in wrapper.elements
            finally:
                os.unlink(f.name)

    def test_external_entity_properties_mapped(self):
        """Test that external entity properties are correctly mapped."""
        from usecvislib.threatmodeling import PyTMWrapper

        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(PYTM_THREAT_MODEL)
            f.flush()
            try:
                tm = ThreatModeling(f.name, "output", validate_paths=False)
                tm.load()

                wrapper = PyTMWrapper(tm.inputdata, "output_test", "png")

                if wrapper._pytm_available:
                    wrapper.build_model()

                    # Check external entities were created
                    assert "admin_user" in wrapper.elements
                    assert "public_user" in wrapper.elements
            finally:
                os.unlink(f.name)

    def test_boundary_assignment(self):
        """Test that elements are correctly assigned to boundaries."""
        from usecvislib.threatmodeling import PyTMWrapper

        with tempfile.NamedTemporaryFile(mode='w', suffix='.tml', delete=False) as f:
            f.write(PYTM_THREAT_MODEL)
            f.flush()
            try:
                tm = ThreatModeling(f.name, "output", validate_paths=False)
                tm.load()

                wrapper = PyTMWrapper(tm.inputdata, "output_test", "png")

                if wrapper._pytm_available:
                    wrapper.build_model()

                    # Check that elements have boundaries assigned
                    web_server = wrapper.elements.get("web_server")
                    if web_server and hasattr(web_server, 'inBoundary'):
                        # Web server should be in DMZ
                        assert web_server.inBoundary is not None
            finally:
                os.unlink(f.name)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
