#
# VULNEX -Universal Security Visualization Library-
#
# File: test_trend.py
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
#

"""Trend chart: metric-over-time small multiples (Atajo request A1)."""

import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from usecvislib import TrendBuilder, TrendChart, TrendError
from usecvislib.utils import ConfigModel

TEMPLATE = Path(__file__).parent.parent / "templates" / "trends" / "engagement_metrics.toml"
GOLDEN = Path(__file__).parent / "golden" / "trend" / "engagement_metrics.tr_default.svg"
UPDATE = os.environ.get("USECVISLIB_UPDATE_GOLDEN") == "1"
PRESETS = ["tr_default", "tr_light", "tr_dark", "tr_print", "tr_minimal", "tr_corporate"]


def _chart(tmp_path, data, **kwargs):
    path = tmp_path / "trend.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    chart = TrendChart(str(path), str(tmp_path / "out"), **kwargs)
    chart.load()
    return chart


def _points(*values, start="2026-10-01"):
    day = datetime.fromisoformat(start)
    return [{"t": (day + timedelta(days=i)).isoformat(), "value": v} for i, v in enumerate(values)]


class TestLoad:
    def test_series_and_panels(self, tmp_path):
        chart = _chart(
            tmp_path,
            {
                "trend": {"name": "M"},
                "panels": {"Vulns": {"stacked": True, "unit": "findings"}},
                "series": [
                    {"name": "Hosts", "unit": "hosts", "points": _points(10, 15)},
                    {"name": "Critical", "panel": "Vulns", "severity": "critical", "points": _points(1, 2)},
                    {"name": "High", "panel": "Vulns", "severity": "high", "points": _points(3, 4)},
                ],
            },
        )
        assert [p.name for p in chart.panels] == ["Hosts", "Vulns"]
        vulns = chart.panels[1]
        assert vulns.stacked and vulns.unit == "findings" and [s.name for s in vulns.series] == ["Critical", "High"]
        assert chart.panels[0].unit == "hosts"  # from the series when the panel has none

    def test_points_sorted_and_timezones_normalized(self, tmp_path):
        chart = _chart(
            tmp_path,
            {
                "series": [
                    {
                        "name": "A",
                        "points": [
                            {"t": "2026-10-02T00:00:00Z", "value": 2},
                            ["2026-10-01T02:00:00+02:00", 1],  # = 2026-10-01T00:00 UTC
                        ],
                    }
                ]
            },
        )
        assert chart.series[0].points == [(datetime(2026, 10, 1), 1.0), (datetime(2026, 10, 2), 2.0)]

    def test_tidy_rows(self, tmp_path):
        rows = [
            {"t": "2026-10-01", "metric": "Paths", "value": 3, "unit": "paths"},
            {"t": "2026-10-02", "metric": "Paths", "value": 5},
            {"t": "2026-10-01", "metric": "KEV", "value": 0, "kind": "bar"},
        ]
        chart = _chart(tmp_path, {"rows": rows})
        by_name = {s.name: s for s in chart.series}
        assert [v for _, v in by_name["Paths"].points] == [3.0, 5.0] and by_name["Paths"].unit == "paths"
        assert by_name["KEV"].kind == "bar"

    def test_warnings(self, tmp_path):
        chart = _chart(
            tmp_path,
            {
                "series": [
                    {"name": "A", "kind": "pie", "color": "red", "severity": "huge", "points": _points(1)},
                    {"name": "A", "points": [{"t": "2026-10-01", "value": 1}, {"t": "2026-10-01", "value": 2}]},
                ]
            },
        )
        text = " ".join(chart.warnings)
        for fragment in ("unknown kind 'pie'", "not a hex color", "unknown severity", "same time", "more than once"):
            assert fragment in text
        assert chart.series[0].kind == "line" and chart.series[0].color is None

    @pytest.mark.parametrize(
        "points,message",
        [
            ([{"t": "yesterday", "value": 1}], "Invalid timestamp"),
            ([{"t": "2026-10-01", "value": "many"}], "not a number"),
            ([{"t": "2026-10-01", "value": float("nan")}], "finite"),
            ("2026-10-01=1", "must be a list"),
            ([[1, 2, 3]], "time and a value"),
        ],
    )
    def test_errors(self, tmp_path, points, message):
        with pytest.raises(TrendError, match=message):
            _chart(tmp_path, {"series": [{"name": "A", "points": points}]})


class TestStats:
    def test_stats_and_validate(self, tmp_path):
        chart = TrendChart(str(TEMPLATE), str(tmp_path / "o"))
        chart.load()
        assert chart.validate() == []
        stats = chart.get_stats()
        assert stats["total_series"] == 7 and stats["total_panels"] == 4 and stats["total_points"] == 42
        assert stats["series"]["Hosts"] == {
            "unit": "hosts",
            "panel": "Hosts",
            "points": 6,
            "first": 10.0,
            "last": 23.0,
            "min": 10.0,
            "max": 24.0,
            "change": 13.0,
        }
        assert stats["start_time"] == "2026-10-01T09:00:00"

    def test_validate_reports_empty(self, tmp_path):
        chart = _chart(tmp_path, {"series": [{"name": "A", "points": []}]})
        assert "Series 'A' has no points" in chart.validate()
        assert "No series defined" in _chart(tmp_path, {}).validate()


class TestRender:
    @pytest.mark.parametrize("fmt", ["png", "svg", "pdf"])
    def test_formats(self, tmp_path, fmt):
        TrendChart(str(TEMPLATE), str(tmp_path / "t"), format=fmt).build()
        assert (tmp_path / f"t.{fmt}").stat().st_size > 1000

    @pytest.mark.parametrize("styleid", PRESETS)
    def test_presets(self, tmp_path, styleid):
        TrendChart(str(TEMPLATE), str(tmp_path / "t"), format="svg", styleid=styleid).build()
        svg = (tmp_path / "t.svg").read_text(encoding="utf-8")
        assert "Engagement metrics" in svg

    def test_every_preset_is_tested(self):
        assert set(ConfigModel(TrendChart.STYLE_FILE).config) == set(PRESETS)

    @pytest.mark.parametrize("kind", ["line", "area", "step", "bar"])
    def test_kinds_and_single_point(self, tmp_path, kind):
        chart = _chart(
            tmp_path,
            {"series": [{"name": "A", "kind": kind, "points": _points(4, 2, 7)}, {"name": "B", "points": _points(1)}]},
            format="svg",
        )
        chart.render().draw()
        assert (tmp_path / "out.svg").exists()

    def test_no_data(self, tmp_path):
        _chart(tmp_path, {"series": []}, format="svg").render().draw()
        assert "No data to display" in (tmp_path / "out.svg").read_text(encoding="utf-8")

    @pytest.mark.parametrize("fmt", ["svg", "pdf", "png"])
    def test_reproducible(self, tmp_path, fmt):
        digests = []
        for name in ("a", "b"):
            TrendChart(str(TEMPLATE), str(tmp_path / name), format=fmt).build()
            digests.append(hashlib.sha256((tmp_path / f"{name}.{fmt}").read_bytes()).hexdigest())
        assert digests[0] == digests[1]

    def test_dot_format_rejected(self, tmp_path):
        with pytest.raises(TrendError, match="png, pdf, or svg"):
            TrendChart(str(TEMPLATE), str(tmp_path / "t"), format="dot")

    def test_golden(self, tmp_path):
        TrendChart(str(TEMPLATE), str(tmp_path / "t"), format="svg").build()
        actual = (tmp_path / "t.svg").read_text(encoding="utf-8")
        if UPDATE:
            GOLDEN.parent.mkdir(parents=True, exist_ok=True)
            GOLDEN.write_text(actual, encoding="utf-8")
        assert GOLDEN.exists(), "run with USECVISLIB_UPDATE_GOLDEN=1"
        assert actual == GOLDEN.read_text(encoding="utf-8")


class TestBuilder:
    def test_build_and_render(self, tmp_path):
        day = datetime(2026, 10, 1, tzinfo=timezone.utc)
        builder = (
            TrendBuilder("Built")
            .add_series("Hosts", [(day, 10), (day + timedelta(days=1), 15)], unit="hosts")
            .add_series("Critical", [{"t": "2026-10-01", "value": 2}], panel="Vulns", severity="critical")
            .add_panel("Vulns", stacked=True, unit="findings")
        )
        data = builder.build()
        assert data["series"][0]["points"][0] == {"t": "2026-10-01T00:00:00+00:00", "value": 10}
        assert data["panels"]["Vulns"] == {"stacked": True, "unit": "findings"}
        chart = builder.to_trend_chart(str(tmp_path / "b"), format="svg")
        temp_input = chart._temp_input
        chart.build()
        assert (tmp_path / "b.svg").exists()
        assert not os.path.exists(temp_input)  # removed once loaded
        assert chart.panels[1].stacked

    def test_unloaded_chart_removes_its_temp_input(self, tmp_path):
        chart = TrendBuilder("x").add_series("A", [("2026-10-01", 1)]).to_trend_chart(str(tmp_path / "x"))
        temp_input = chart._temp_input
        del chart
        import gc

        gc.collect()
        assert not os.path.exists(temp_input)
