#
# VULNEX -Universal Security Visualization Library-
#
# File: test_cli.py
# Author: Simon Roses Femerling
# Created: 2026-10-05
# Last Modified: 2026-10-05
# Version: 0.6.0
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""CLI regressions found by an exhaustive pass over usecvis modes and flags."""

import json
import shutil
from pathlib import Path

import pytest

from usecvislib import usecvis

TEMPLATES = Path(__file__).parent.parent / "templates"
DOT = shutil.which("dot") is not None


def _run(args):
    """Run the CLI; return its exit code (error_exit raises SystemExit)."""
    try:
        return usecvis.main(args)
    except SystemExit as e:
        return e.code


@pytest.mark.parametrize("target", ["toml", "json", "yaml"])
def test_convert_standard_formats(tmp_path, target):
    # --convert passed a file path where content was expected: always failed.
    src = TEMPLATES / "attack-trees" / "ransomware_attack.tml"
    assert _run(["-i", str(src), "-o", str(tmp_path / "out"), "--convert", target]) == 0
    out = tmp_path / f"out.{target}"
    assert out.exists() and out.stat().st_size > 0
    if target == "json":
        assert "tree" in json.loads(out.read_text(encoding="utf-8"))


def test_convert_mermaid_parses_toml_the_library_accepts(tmp_path):
    # The legacy toml package rejected this template ("implicitly defined table").
    src = TEMPLATES / "custom-diagrams" / "general" / "flowchart.toml"
    assert _run(["-i", str(src), "-o", str(tmp_path / "out"), "--convert", "mermaid"]) == 0
    assert (tmp_path / "out.mmd").read_text(encoding="utf-8").startswith("flowchart")


def test_output_extension_not_doubled(tmp_path):
    src = TEMPLATES / "attack-trees" / "ransomware_attack.tml"
    assert _run(["-i", str(src), "-o", str(tmp_path / "o.json"), "--convert", "json"]) == 0
    assert (tmp_path / "o.json").exists() and not (tmp_path / "o.json.json").exists()


@pytest.mark.skipif(not DOT, reason="Graphviz 'dot' binary required")
def test_png_output_extension_not_doubled(tmp_path):
    src = TEMPLATES / "attack-trees" / "ransomware_attack.tml"
    assert _run(["-i", str(src), "-o", str(tmp_path / "o.png"), "-m", "0"]) == 0
    assert (tmp_path / "o.png").exists() and not (tmp_path / "o.png.png").exists()


@pytest.mark.skipif(not DOT, reason="Graphviz 'dot' binary required")
def test_cloud_mode_runs(tmp_path):
    # Mode 5 passed a direction kwarg CloudDiagrams does not take: always failed.
    pytest.importorskip("diagrams")
    src = TEMPLATES / "cloud" / "aws" / "web-application.toml"
    assert _run(["-i", str(src), "-o", str(tmp_path / "c"), "-m", "5", "-d", "LR"]) == 0
    assert (tmp_path / "c.png").exists()


@pytest.mark.parametrize(
    "args,needle",
    [
        (["-m", "13"], "Must be 0-12"),
        (["-m", "10", "-v", "bogus"], "Invalid -v value"),
        (["-m", "2", "-f", "dot"], "Graphviz-only"),
        (["-S", "x.tml"], "--stylefile is not supported"),
    ],
)
def test_invalid_options_fail_clearly(tmp_path, capsys, args, needle):
    src = TEMPLATES / "timelines" / "ransomware_incident.tml"
    assert _run(["-i", str(src), "-o", str(tmp_path / "o"), *args]) != 0
    assert needle in capsys.readouterr().err


def test_wrong_schema_input_rejected(tmp_path, capsys):
    # A kill-chain file in the threat-model mode rendered an empty diagram, exit 0.
    src = TEMPLATES / "kill-chains" / "apt_intrusion.tml"
    assert _run(["-i", str(src), "-o", str(tmp_path / "o"), "-m", "1"]) != 0
    assert "not a mode 1 configuration" in capsys.readouterr().err


def test_extra_positional_argument_reported(tmp_path, capsys):
    src = TEMPLATES / "attack-trees" / "ransomware_attack.tml"
    assert _run(["-i", str(src), "stray", "-o", str(tmp_path / "o")]) != 0
    assert "Unexpected argument" in capsys.readouterr().err


def test_usage_lists_real_presets(capsys):
    _run(["-h"])
    out = capsys.readouterr().out
    assert "ma_severity" in out and "sv_security" in out and "sv_print" in out
