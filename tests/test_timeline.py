#
# VULNEX -Universal Security Visualization Library-
#
# File: test_timeline.py
# Author: Simon Roses Femerling
# Created: 2026-08-27
# Last Modified: 2026-08-27
# Version: 0.4.1
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Tests for the Incident Timeline module (CLI mode 10)."""

import glob
from datetime import timedelta
from pathlib import Path

import pytest

from usecvislib.builders import TimelineBuilder
from usecvislib.timeline import (
    SEVERITY_COLORS,
    SUPPORTED_MODES,
    IncidentTimeline,
    TimelineError,
    TimelineEvent,
    TimelinePhase,
    parse_duration,
    parse_timestamp,
)

TESTS_DIR = Path(__file__).parent
TEMPLATES_DIR = TESTS_DIR.parent / "templates" / "timelines"
TEMPLATES = sorted(glob.glob(str(TEMPLATES_DIR / "*.tml")))
RANSOM = str(TEMPLATES_DIR / "ransomware_incident.tml")
PHISH = str(TEMPLATES_DIR / "phishing_compromise.tml")
INSIDER = str(TEMPLATES_DIR / "insider_data_exfil.tml")


def _build(inputfile, tmp_path, mode="swimlane", fmt="png", styleid="", name="out"):
    tl = IncidentTimeline(inputfile, str(tmp_path / name), format=fmt, styleid=styleid, mode=mode)
    tl.build()
    return tmp_path / f"{name}.{fmt}"


class TestParsing:
    def test_parse_timestamp_z_suffix(self):
        dt = parse_timestamp("2026-01-15T08:30:00Z")
        assert dt.year == 2026 and dt.hour == 8 and dt.minute == 30
        assert dt.tzinfo is not None

    def test_parse_timestamp_naive(self):
        dt = parse_timestamp("2026-01-15T08:30:00")
        assert dt.tzinfo is None

    def test_parse_timestamp_invalid(self):
        with pytest.raises(TimelineError):
            parse_timestamp("not-a-date")

    def test_parse_duration_units(self):
        assert parse_duration("45s") == timedelta(seconds=45)
        assert parse_duration("2m") == timedelta(minutes=2)
        assert parse_duration("1h30m") == timedelta(hours=1, minutes=30)
        assert parse_duration("2d") == timedelta(days=2)

    def test_parse_duration_numeric_is_minutes(self):
        assert parse_duration(5) == timedelta(minutes=5)

    def test_parse_duration_empty(self):
        assert parse_duration(None) is None
        assert parse_duration("") is None
        assert parse_duration("garbage") is None


class TestModel:
    def test_event_end_time_with_duration(self):
        ev = TimelineEvent("E1", parse_timestamp("2026-01-01T00:00:00Z"), "t", duration=timedelta(minutes=10))
        assert ev.end_time == ev.timestamp + timedelta(minutes=10)

    def test_event_end_time_without_duration(self):
        ev = TimelineEvent("E1", parse_timestamp("2026-01-01T00:00:00Z"), "t")
        assert ev.end_time == ev.timestamp

    def test_event_color_by_severity(self):
        ev = TimelineEvent("E1", parse_timestamp("2026-01-01T00:00:00Z"), "t", severity="critical")
        assert ev.color == SEVERITY_COLORS["critical"]

    def test_event_unknown_severity_color_defaults_info(self):
        ev = TimelineEvent("E1", parse_timestamp("2026-01-01T00:00:00Z"), "t", severity="weird")
        assert ev.color == SEVERITY_COLORS["info"]

    def test_phase_dataclass(self):
        ph = TimelinePhase("Detection", parse_timestamp("2026-01-01T00:00:00Z"), parse_timestamp("2026-01-01T01:00:00Z"))
        assert ph.name == "Detection"


class TestLoad:
    def test_load_ransomware(self):
        tl = IncidentTimeline(RANSOM, "unused")
        tl.load()
        assert len(tl.events) == 10
        assert len(tl.phases) == 4
        assert "User Workstation" in tl.lanes

    def test_events_sorted_chronologically(self):
        tl = IncidentTimeline(RANSOM, "unused")
        tl.load()
        ts = [e.timestamp for e in tl.events]
        assert ts == sorted(ts)

    def test_missing_events_key_errors(self, tmp_path):
        bad = tmp_path / "bad.tml"
        # Top-level `events` must precede any table header in TOML.
        bad.write_text('events = "notalist"\n[incident]\nname="x"\n')
        with pytest.raises(TimelineError):
            IncidentTimeline(str(bad), "unused").load()

    def test_event_without_timestamp_warns_and_skips(self, tmp_path):
        src = tmp_path / "t.tml"
        src.write_text('[incident]\nname="x"\n[[events]]\nid="E1"\ntitle="no ts"\n')
        tl = IncidentTimeline(str(src), "unused")
        tl.load()
        assert len(tl.events) == 0
        assert any("timestamp" in w for w in tl.warnings)

    def test_unknown_severity_falls_back(self, tmp_path):
        src = tmp_path / "t.tml"
        src.write_text('[incident]\nname="x"\n[[events]]\nid="E1"\ntimestamp="2026-01-01T00:00:00Z"\ntitle="t"\nseverity="spicy"\n')
        tl = IncidentTimeline(str(src), "unused")
        tl.load()
        assert tl.events[0].severity == "info"
        assert any("severity" in w for w in tl.warnings)

    def test_phase_missing_bounds_skipped(self, tmp_path):
        src = tmp_path / "t.tml"
        src.write_text(
            '[incident]\nname="x"\n[[phases]]\nname="P"\n'
            '[[events]]\nid="E1"\ntimestamp="2026-01-01T00:00:00Z"\ntitle="t"\n'
        )
        tl = IncidentTimeline(str(src), "unused")
        tl.load()
        assert len(tl.phases) == 0


class TestStats:
    def test_stats_shape(self):
        tl = IncidentTimeline(RANSOM, "unused")
        stats = tl.get_stats()
        assert stats["total_events"] == 10
        assert stats["total_phases"] == 4
        assert stats["tagged_events"] == 6
        assert sum(stats["severity_distribution"].values()) == 10
        assert stats["time_span"]

    def test_response_metrics(self):
        tl = IncidentTimeline(RANSOM, "unused")
        rm = tl.get_stats()["response_metrics"]
        assert rm["time_to_detect"] is not None
        assert rm["time_to_contain"] is not None
        assert rm["time_to_resolve"] is not None

    def test_response_metrics_none_without_phases(self, tmp_path):
        src = tmp_path / "t.tml"
        src.write_text('[incident]\nname="x"\n[[events]]\nid="E1"\ntimestamp="2026-01-01T00:00:00Z"\ntitle="t"\n')
        tl = IncidentTimeline(str(src), "unused")
        rm = tl.get_stats()["response_metrics"]
        assert rm["time_to_detect"] is None

    def test_events_per_lane(self):
        tl = IncidentTimeline(RANSOM, "unused")
        stats = tl.get_stats()
        assert sum(stats["events_per_lane"].values()) == 10


class TestValidate:
    def test_valid_template(self):
        tl = IncidentTimeline(RANSOM, "unused")
        assert tl.validate() == []

    def test_no_events_flagged(self, tmp_path):
        src = tmp_path / "t.tml"
        src.write_text('[incident]\nname="x"\nevents = []\n')
        tl = IncidentTimeline(str(src), "unused")
        errors = tl.validate()
        assert any("No events" in e for e in errors)

    def test_phase_end_before_start_flagged(self, tmp_path):
        src = tmp_path / "t.tml"
        src.write_text(
            '[incident]\nname="x"\n'
            '[[phases]]\nname="P"\nstart="2026-01-01T05:00:00Z"\nend="2026-01-01T01:00:00Z"\n'
            '[[events]]\nid="E1"\ntimestamp="2026-01-01T00:00:00Z"\ntitle="t"\n'
        )
        tl = IncidentTimeline(str(src), "unused")
        assert any("before start" in e for e in tl.validate())


class TestRender:
    @pytest.mark.parametrize("mode", SUPPORTED_MODES)
    def test_render_all_modes_png(self, tmp_path, mode):
        out = _build(RANSOM, tmp_path, mode=mode)
        assert out.exists()
        assert out.read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"

    @pytest.mark.parametrize("template", [RANSOM, PHISH, INSIDER])
    def test_render_all_templates(self, tmp_path, template):
        out = _build(template, tmp_path, name=Path(template).stem)
        assert out.exists()

    def test_render_svg_format(self, tmp_path):
        out = _build(RANSOM, tmp_path, fmt="svg")
        assert out.exists()
        assert "<svg" in out.read_text(encoding="utf-8")[:2000]

    def test_render_with_style_preset(self, tmp_path):
        out = _build(RANSOM, tmp_path, styleid="tl_dark")
        assert out.exists()

    @pytest.mark.parametrize("mode", SUPPORTED_MODES)
    def test_dark_preset_themes_plot_area(self, tmp_path, mode):
        # tl_dark only colored the figure; the plot area stayed white under
        # light event text.
        import matplotlib.colors as mcolors

        tl = IncidentTimeline(RANSOM, str(tmp_path / "o"), styleid="tl_dark", mode=mode)
        tl.load()
        tl.render()
        ax = tl._fig.axes[0]
        assert mcolors.to_hex(ax.get_facecolor()) == tl.style["figure"]["facecolor"]
        legend = ax.get_legend()
        if legend is not None:
            assert mcolors.to_hex(legend.get_frame().get_facecolor()) == tl.style["figure"]["facecolor"]

    def test_multi_day_vertical_axis_shows_dates(self, tmp_path):
        tl = IncidentTimeline(INSIDER, str(tmp_path / "o"), mode="vertical")
        tl.load()
        tl.render()
        assert "%m-%d" in tl._fig.axes[0].yaxis.get_major_formatter().fmt

    def test_empty_timeline_still_renders(self, tmp_path):
        src = tmp_path / "empty.tml"
        src.write_text('[incident]\nname="x"\nevents = []\n')
        tl = IncidentTimeline(str(src), str(tmp_path / "e"), format="png")
        tl.build()
        assert (tmp_path / "e.png").exists()

    def test_invalid_mode_falls_back_to_swimlane(self, tmp_path):
        tl = IncidentTimeline(RANSOM, str(tmp_path / "o"), mode="nonsense")
        assert tl.mode == "swimlane"

    def test_dot_format_rejected(self, tmp_path):
        with pytest.raises(TimelineError):
            IncidentTimeline(RANSOM, str(tmp_path / "o"), format="dot")


class TestLabelSlots:
    def test_far_apart_events_share_top_tier(self):
        span = timedelta(hours=10)
        evs = [
            TimelineEvent("E1", parse_timestamp("2026-01-01T00:00:00Z"), "a"),
            TimelineEvent("E2", parse_timestamp("2026-01-01T05:00:00Z"), "b"),
        ]
        slots = IncidentTimeline._label_slots(evs, span)
        assert slots[0] == slots[1]  # both use tier 0, no collision

    def test_clustered_events_stagger(self):
        span = timedelta(hours=10)
        base = "2026-01-01T00:0{}:00Z"
        evs = [TimelineEvent(f"E{i}", parse_timestamp(base.format(i)), "x") for i in range(3)]
        slots = IncidentTimeline._label_slots(evs, span)
        # Tightly clustered -> distinct tiers (no two identical in a row)
        assert len({s for s in slots}) >= 2

    def test_empty_events(self):
        assert IncidentTimeline._label_slots([], timedelta(hours=1)) == []


class TestBuilder:
    def test_build_dict(self):
        b = (
            TimelineBuilder("Test", incident_id="INC-1", analyst="SOC")
            .add_phase("Detection", "2026-01-01T00:00:00Z", "2026-01-01T01:00:00Z")
            .add_event("E1", "2026-01-01T00:10:00Z", "First", severity="high", technique="T1566", duration="5m")
            .add_event("E2", "2026-01-01T00:40:00Z", "Second", severity="critical")
        )
        data = b.build()
        assert data["incident"]["id"] == "INC-1"
        assert len(data["events"]) == 2
        assert len(data["phases"]) == 1

    def test_to_json(self):
        b = TimelineBuilder("Test").add_event("E1", "2026-01-01T00:00:00Z", "t")
        assert '"E1"' in b.to_json()

    def test_to_timeline_renders(self, tmp_path):
        tl = (
            TimelineBuilder("Test")
            .add_event("E1", "2026-01-01T00:00:00Z", "t", severity="high")
            .add_event("E2", "2026-01-01T00:30:00Z", "t2")
            .to_timeline(str(tmp_path / "b"), mode="compact")
        )
        tl.build()
        assert (tmp_path / "b.png").exists()
        assert tl.get_stats()["total_events"] == 2


class TestTemplates:
    def test_all_templates_present(self):
        assert len(TEMPLATES) >= 3

    @pytest.mark.parametrize("template", TEMPLATES)
    def test_template_loads_and_validates(self, template):
        tl = IncidentTimeline(template, "unused")
        assert tl.validate() == []
