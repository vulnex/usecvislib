#
# VULNEX -Universal Security Visualization Library-
#
# File: test_svg_timeline.py
# Author: Simon Roses Femerling
# Created: 2026-08-28
# Last Modified: 2026-08-28
# Version: 0.5.0
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Tests for the Incident Timeline SVG painter (Phase 2, mode 10, all 4 modes)."""

import glob
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from usecvislib.svgengine.scene import StyleEngineMismatchError
from usecvislib.timeline import SUPPORTED_MODES, IncidentTimeline

TESTS_DIR = Path(__file__).parent
TEMPLATE_DIR = TESTS_DIR.parent / "templates" / "timelines"
FIXTURE = str(TEMPLATE_DIR / "ransomware_incident.tml")
TEMPLATES = sorted(glob.glob(str(TEMPLATE_DIR / "*")))
SVG_PRESETS = ["sv_default", "sv_dark", "sv_print", "sv_corporate", "sv_minimal"]
SVG_NS = "{http://www.w3.org/2000/svg}"

VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}


def _render(inputfile: str, tmp_path, styleid: str = "", mode: str = "swimlane", name: str = "out") -> str:
    tl = IncidentTimeline(
        inputfile, str(tmp_path / name), format="svg", styleid=styleid, mode=mode, render_engine="svg"
    )
    tl.build()
    return (tmp_path / f"{name}.svg").read_text(encoding="utf-8")


def _loaded(inputfile: str) -> IncidentTimeline:
    tl = IncidentTimeline(inputfile, "unused")
    tl.load()
    return tl


def _events(root):
    return [g for g in root.iter(f"{SVG_NS}g") if "usv-event" in g.get("class", "").split()]


def _phases(root):
    return [g for g in root.iter(f"{SVG_NS}g") if "usv-phase" in g.get("class", "").split()]


class TestPresets:
    @pytest.mark.parametrize("preset", SVG_PRESETS)
    def test_fixture_renders_in_preset(self, tmp_path, preset):
        root = ET.fromstring(_render(FIXTURE, tmp_path, styleid=preset))
        assert root.get("data-usv-theme") == preset
        assert root.get("data-usv-module") == "timeline"


class TestModes:
    @pytest.mark.parametrize("template", TEMPLATES, ids=[Path(t).stem for t in TEMPLATES])
    @pytest.mark.parametrize("mode", SUPPORTED_MODES)
    def test_template_renders_in_every_mode(self, tmp_path, template, mode):
        root = ET.fromstring(_render(template, tmp_path, mode=mode, name=f"{Path(template).stem}_{mode}"))
        # Every event appears as a marker group in every mode
        assert len(_events(root)) == len(_loaded(template).events)


class TestInteractivityContract:
    def test_event_count_matches_loaded(self, tmp_path):
        root = ET.fromstring(_render(FIXTURE, tmp_path))
        assert len(_events(root)) == len(_loaded(FIXTURE).events)

    def test_events_carry_contract(self, tmp_path):
        root = ET.fromstring(_render(FIXTURE, tmp_path))
        evs = _events(root)
        assert evs
        for g in evs:
            assert g.get("data-node-id")
            assert g.get("data-label")
            assert g.get("data-severity") in VALID_SEVERITIES
            assert g.get("data-timestamp")

    def test_severity_classes_are_canonical(self, tmp_path):
        root = ET.fromstring(_render(FIXTURE, tmp_path))
        seen = {
            cls.removeprefix("usv-sev--")
            for g in root.iter(f"{SVG_NS}g")
            for cls in g.get("class", "").split()
            if cls.startswith("usv-sev--")
        }
        assert seen
        assert seen <= VALID_SEVERITIES

    def test_phase_bands_present(self, tmp_path):
        root = ET.fromstring(_render(FIXTURE, tmp_path))
        assert len(_phases(root)) == len(_loaded(FIXTURE).phases)

    def test_no_active_content(self, tmp_path):
        content = _render(FIXTURE, tmp_path)
        assert "<script" not in content
        assert "foreignObject" not in content
        assert "onclick" not in content and "onload" not in content
        assert "url(http" not in content
        assert "@import" not in content


class TestSemantics:
    def test_marker_color_follows_severity(self, tmp_path):
        from usecvislib.timeline import SEVERITY_COLORS

        root = ET.fromstring(_render(FIXTURE, tmp_path))
        for g in _events(root):
            sev = g.get("data-severity")
            circle = g.find(f"{SVG_NS}circle")
            assert circle is not None
            assert circle.get("fill") == SEVERITY_COLORS[sev]

    def test_duration_bar_in_swimlane(self, tmp_path):
        # ransomware fixture has events with a duration -> at least one bar
        vt = _loaded(FIXTURE)
        assert any(e.duration for e in vt.events)
        content = _render(FIXTURE, tmp_path, mode="swimlane")
        assert 'class="usv-svg usv-timeline"' in content

    def test_gantt_has_one_bar_per_event(self, tmp_path):
        root = ET.fromstring(_render(FIXTURE, tmp_path, mode="gantt"))
        # each event group carries exactly one rect bar
        for g in _events(root):
            assert g.find(f"{SVG_NS}rect") is not None

    def test_deterministic_across_runs(self, tmp_path):
        assert _render(FIXTURE, tmp_path, name="one") == _render(FIXTURE, tmp_path, name="two")

    def test_empty_timeline_degrades_gracefully(self, tmp_path):
        src = tmp_path / "empty.tml"
        src.write_text('[incident]\nname = "Nothing"\n', encoding="utf-8")
        content = _render(str(src), tmp_path, name="empty")
        assert "No events to display" in content
        assert content.startswith("<?xml")


class TestEngineGuards:
    def test_matplotlib_preset_rejected_under_svg_engine(self, tmp_path):
        with pytest.raises(StyleEngineMismatchError):
            _render(FIXTURE, tmp_path, styleid="tl_default")

    def test_svg_preset_rejected_under_graphviz_engine(self):
        with pytest.raises(StyleEngineMismatchError):
            IncidentTimeline(FIXTURE, "unused", styleid="sv_default", render_engine="graphviz").load()


class TestRasterOutputs:
    @pytest.fixture(autouse=True)
    def _require_cairosvg(self):
        pytest.importorskip("cairosvg")

    @pytest.mark.parametrize("mode", SUPPORTED_MODES)
    def test_png_output(self, tmp_path, mode):
        IncidentTimeline(FIXTURE, str(tmp_path / "o"), format="png", mode=mode, render_engine="svg").build()
        assert (tmp_path / "o.png").read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"

    def test_pdf_output(self, tmp_path):
        IncidentTimeline(FIXTURE, str(tmp_path / "o"), format="pdf", render_engine="svg").build()
        assert (tmp_path / "o.pdf").read_bytes()[:5] == b"%PDF-"


class TestCli:
    @pytest.mark.parametrize("mode", SUPPORTED_MODES)
    def test_cli_svg_engine_end_to_end(self, tmp_path, mode):
        from usecvislib import usecvis

        rc = usecvis.main(
            ["-i", FIXTURE, "-o", str(tmp_path / "cli"), "-f", "svg", "-m", "10", "-v", mode, "--render-engine", "svg"]
        )
        assert rc == 0
        assert 'data-usv-engine="svg"' in (tmp_path / "cli.svg").read_text(encoding="utf-8")

    def test_cli_rejects_dot_format_under_svg(self, tmp_path):
        from usecvislib import usecvis

        with pytest.raises(SystemExit) as exc:
            usecvis.main(["-i", FIXTURE, "-o", str(tmp_path / "x"), "-f", "dot", "-m", "10", "--render-engine", "svg"])
        assert exc.value.code == 2


class TestLabelLayout:
    def test_placer_never_overlaps(self):
        from usecvislib.svgengine.painters.timeline import _LabelPlacer

        placer = _LabelPlacer()
        boxes = []
        for x in (0, 20, 40, 60, 80):  # tightly clustered markers, wide labels
            top = placer.place(x, 160.0, 30.0)
            boxes.append((x - 80, top, x + 80, top + 30))
        for i, a in enumerate(boxes):
            for b in boxes[i + 1 :]:
                assert a[2] <= b[0] or b[2] <= a[0] or a[3] <= b[1] or b[3] <= a[1], (a, b)

    def test_ticks_fall_on_round_times(self):
        from datetime import datetime

        from usecvislib.svgengine.painters.timeline import _ticks

        ticks = _ticks(datetime(2026, 3, 1, 8, 7, 30), 11 * 3600, "%H:%M")
        assert 4 <= len(ticks) <= 8
        for t, _ in ticks:
            assert t.second == 0 and t.minute == 0  # hourly or coarser for an 11h span


def test_side_by_side_labels_keep_a_word_gap():
    from usecvislib.svgengine.painters import timeline as tl

    placer = tl._LabelPlacer()
    first = placer.place(100.0, 100.0, 20.0)
    # 3px apart read as one string: the second label moves to another slot
    second = placer.place(100.0 + 100.0 + tl._LABEL_GAP_X - 2.0, 100.0, 20.0)
    assert second != first
    third = placer.place(100.0 + 100.0 + tl._LABEL_GAP_X + 2.0, 100.0, 20.0)
    assert third == first
