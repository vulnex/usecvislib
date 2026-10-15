#
# VULNEX -Universal Security Visualization Library-
#
# File: trend.py
# Author: Simon Roses Femerling
# Created: 2026-10-15
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Metric-over-time trend chart: small multiples on a shared time axis.

Shows how metrics evolve across snapshots (hosts, vulnerabilities by
severity, exploitable paths, ...): one panel per metric, all panels sharing
the time axis. Series that name the same ``panel`` are drawn together, and a
panel can stack its series (e.g. vulnerabilities by severity). Matplotlib
based, PNG / SVG / PDF, ``tr_*`` style presets; SVG and PDF output are
byte-reproducible.

Input schema (TOML/JSON/YAML)::

    [trend]
    name = "Engagement metrics"

    [panels."Vulnerabilities"]       # optional, per panel
    stacked = true                   # stack the panel's series
    unit = "findings"

    [[series]]
    name = "Hosts"
    unit = "hosts"
    kind = "line"                    # line (default) | area | step | bar
    points = [
        {t = "2026-10-01T09:00:00Z", value = 10},
        {t = "2026-10-02T09:00:00Z", value = 15},
    ]

    [[series]]
    name = "Critical"
    panel = "Vulnerabilities"        # drawn in this panel (default: own panel)
    severity = "critical"            # severity color; or color = "#hex"
    points = [...]

    [[rows]]                         # alternative tidy form: one row per value
    t = "2026-10-01T09:00:00Z"
    metric = "Exploitable paths"
    value = 3
"""

import contextlib
import math
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from itertools import pairwise
from typing import Any, Optional

from . import utils
from .base import VisualizationBase
from .timeline import _quiet_numpy_timedelta


class TrendError(utils.RenderError):
    """Raised when trend chart loading or rendering fails."""


KINDS = ("line", "area", "step", "bar")

# Severity colors, shared with the incident timeline so the views match
SEVERITY_COLORS = {
    "critical": "#c0392b",
    "high": "#e74c3c",
    "medium": "#e0a53f",
    "low": "#27ae60",
    "info": "#3498db",
    "none": "#95a5a6",
}

_DEFAULT_PALETTE = ["#3d5a80", "#e07a5f", "#81b29a", "#9b5de5", "#f2cc8f", "#00bbf9", "#ee6c4d", "#577590"]
_HEX = re.compile(r"^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$")


def parse_time(value: Any) -> datetime:
    """Parse an ISO-8601 timestamp (a trailing ``Z`` is UTC; dates without a time are midnight)."""
    if isinstance(value, datetime):
        return value
    text = str(value).strip()
    if not text:
        raise TrendError("Empty timestamp")
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text)
    except ValueError as e:
        raise TrendError(f"Invalid timestamp '{value}': expected ISO-8601 (YYYY-MM-DD[THH:MM:SS])") from e


def _naive_utc(moment: datetime) -> datetime:
    """Comparable timestamps: aware ones converted to UTC, all made naive."""
    return moment.astimezone(timezone.utc).replace(tzinfo=None) if moment.tzinfo else moment


@dataclass
class TrendSeries:
    """One metric's values over time."""

    name: str
    points: list[tuple[datetime, float]] = field(default_factory=list)
    unit: str = ""
    panel: str = ""
    kind: str = "line"
    color: Optional[str] = None
    severity: Optional[str] = None

    @property
    def first(self) -> Optional[float]:
        return self.points[0][1] if self.points else None

    @property
    def last(self) -> Optional[float]:
        return self.points[-1][1] if self.points else None


@dataclass
class TrendPanel:
    """A panel: one or more series sharing a y axis."""

    name: str
    series: list[TrendSeries] = field(default_factory=list)
    stacked: bool = False
    unit: str = ""


class TrendChart(VisualizationBase):
    """Metric-over-time small multiples (Matplotlib)."""

    STYLE_FILE = "config_trend.tml"
    DEFAULT_STYLE_ID = "tr_default"
    ALLOWED_FORMATS = ("png", "pdf", "svg")

    def __init__(
        self,
        inputfile: str,
        outputfile: str,
        format: str = "png",
        styleid: Optional[str] = None,
        validate_paths: bool = True,
    ) -> None:
        super().__init__(inputfile, outputfile, format=format or "png", styleid=styleid, validate_paths=validate_paths)
        if self.format not in self.ALLOWED_FORMATS:
            raise TrendError(f"Format '{self.format}' is not supported by the trend chart. Use png, pdf, or svg.")
        self._fig: Optional[Any] = None
        self.series: list[TrendSeries] = []
        self.panels: list[TrendPanel] = []
        self.warnings: list[str] = []
        self._temp_input: Optional[str] = None

    # --------------------------------------------------------- VisualizationBase

    def _default_style(self) -> dict[str, Any]:
        """Fallback style if the config file is unavailable (clean, light)."""
        return {
            "figure": {"width": 12.0, "panel_height": 2.4, "dpi": 150, "facecolor": "#ffffff"},
            "title": {"fontsize": 15, "fontweight": "bold", "color": "#1e293b"},
            "axis": {"fontsize": 9, "color": "#334155", "gridcolor": "#e2e8f0"},
            "panel": {"fontsize": 10, "color": "#1e3a5f"},
            "line": {"width": 2.0, "marker_size": 5, "fill_alpha": 0.25},
            "value": {"fontsize": 9, "color": "#334155", "show": True},
            "palette": list(_DEFAULT_PALETTE),
        }

    def _load_impl(self) -> dict[str, Any]:
        data = utils.ReadConfigFile(self.inputfile)
        if self._temp_input:  # builder input: loaded, no longer needed
            import os

            with contextlib.suppress(OSError):
                os.unlink(self._temp_input)
            self._temp_input = None
        if not isinstance(data, dict):
            raise TrendError("Trend input must be a mapping")

        self.series.clear()
        self.warnings.clear()

        raw_series = data.get("series", [])
        if not isinstance(raw_series, list):
            raise TrendError("'series' must be a list of series")
        for index, entry in enumerate(raw_series):
            if not isinstance(entry, dict):
                raise TrendError(f"Series #{index + 1} must be a mapping")
            self.series.append(self._parse_series(entry, index))
        self._add_rows(data.get("rows", []))

        names = [s.name for s in self.series]
        for name in sorted({n for n in names if names.count(n) > 1}):
            self.warnings.append(f"Series name '{name}' is used more than once")
        self.panels = self._build_panels(data.get("panels", {}))
        return data

    def _parse_series(self, entry: dict[str, Any], index: int) -> TrendSeries:
        name = str(entry.get("name") or f"Series {index + 1}")
        kind = str(entry.get("kind", "line")).lower()
        if kind not in KINDS:
            self.warnings.append(f"Series '{name}': unknown kind '{kind}', using line")
            kind = "line"
        color = entry.get("color")
        if color is not None and not _HEX.match(str(color)):
            self.warnings.append(f"Series '{name}': color '{color}' is not a hex color; ignored")
            color = None
        severity = str(entry["severity"]).lower() if entry.get("severity") else None
        if severity is not None and severity not in SEVERITY_COLORS:
            self.warnings.append(f"Series '{name}': unknown severity '{severity}'")
            severity = None
        points = self._parse_points(name, entry.get("points", []))
        return TrendSeries(
            name=name,
            points=points,
            unit=str(entry.get("unit", "")),
            panel=str(entry.get("panel") or name),
            kind=kind,
            color=color,
            severity=severity,
        )

    def _parse_points(self, name: str, raw: Any) -> list[tuple[datetime, float]]:
        if not isinstance(raw, list):
            raise TrendError(f"Series '{name}': 'points' must be a list")
        points: list[tuple[datetime, float]] = []
        for point in raw:
            if isinstance(point, dict):
                t, value = point.get("t", point.get("time")), point.get("value")
            elif isinstance(point, list | tuple) and len(point) == 2:
                t, value = point
            else:
                raise TrendError(f"Series '{name}': each point needs a time and a value, got {point!r}")
            try:
                number = float(value)
            except (TypeError, ValueError) as e:
                raise TrendError(f"Series '{name}': value {value!r} is not a number") from e
            if not math.isfinite(number):
                raise TrendError(f"Series '{name}': value {value!r} is not a finite number")
            points.append((_naive_utc(parse_time(t)), number))
        points.sort(key=lambda p: p[0])
        times = [t for t, _ in points]
        if len(set(times)) != len(times):
            self.warnings.append(f"Series '{name}': more than one value at the same time")
        return points

    def _add_rows(self, rows: Any) -> None:
        """Tidy rows (t, metric, value[, unit]) become series, one per metric."""
        if not rows:
            return
        if not isinstance(rows, list):
            raise TrendError("'rows' must be a list of {t, metric, value} rows")
        grouped: dict[str, dict[str, Any]] = {}
        for row in rows:
            if not isinstance(row, dict) or "metric" not in row:
                raise TrendError(f"Each row needs t, metric and value, got {row!r}")
            entry = grouped.setdefault(str(row["metric"]), {"name": str(row["metric"]), "points": []})
            entry["points"].append({"t": row.get("t", row.get("time")), "value": row.get("value")})
            for key in ("unit", "panel", "kind", "color", "severity"):
                if row.get(key) is not None:
                    entry.setdefault(key, row[key])
        for entry in grouped.values():
            self.series.append(self._parse_series(entry, len(self.series)))

    def _build_panels(self, config: Any) -> list[TrendPanel]:
        config = config if isinstance(config, dict) else {}
        panels: dict[str, TrendPanel] = {}
        for series in self.series:
            panel = panels.get(series.panel)
            if panel is None:
                cfg = config.get(series.panel) if isinstance(config.get(series.panel), dict) else {}
                panel = TrendPanel(
                    name=series.panel, stacked=bool(cfg.get("stacked", False)), unit=str(cfg.get("unit", ""))
                )
                panels[series.panel] = panel
            panel.series.append(series)
        for panel in panels.values():
            panel.unit = panel.unit or next((s.unit for s in panel.series if s.unit), "")
        return list(panels.values())

    def _name(self) -> str:
        meta = self.inputdata.get("trend", {}) if isinstance(self.inputdata, dict) else {}
        return str(meta.get("name", "Trend")) if isinstance(meta, dict) else "Trend"

    # ------------------------------------------------------------------ render

    def _render_impl(self) -> None:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        style = self.style if isinstance(self.style, dict) else self._default_style()
        cfg = {
            key: {**value, **style.get(key, {})}
            for key, value in self._default_style().items()
            if isinstance(value, dict)
        }
        palette = list(style.get("palette") or _DEFAULT_PALETTE)

        panels = [p for p in self.panels if any(s.points for s in p.series)]
        if not panels:
            fig, ax = plt.subplots(figsize=(8, 2), facecolor=cfg["figure"]["facecolor"])
            ax.text(0.5, 0.5, "No data to display", ha="center", va="center", fontsize=12, color="#94a3b8")
            ax.axis("off")
            self._fig = fig
            return

        with plt.rc_context({"svg.hashsalt": "usecvislib-trend"}), _quiet_numpy_timedelta():
            self._draw_panels(plt, panels, cfg, palette)

    def _draw_panels(self, plt, panels: list[TrendPanel], cfg: dict[str, Any], palette: list[str]) -> None:
        """One subplot per panel on a shared time axis."""
        fig, axes = plt.subplots(
            len(panels),
            1,
            sharex=True,
            squeeze=False,
            figsize=(float(cfg["figure"]["width"]), float(cfg["figure"]["panel_height"]) * len(panels) + 0.9),
            facecolor=cfg["figure"]["facecolor"],
        )
        colors = iter(palette * (1 + len(self.series) // max(len(palette), 1)))
        for ax, panel in zip((row[0] for row in axes), panels, strict=True):
            series_colors = [
                s.color or (SEVERITY_COLORS[s.severity] if s.severity else next(colors)) for s in panel.series
            ]
            if panel.stacked:
                self._draw_stacked(ax, panel, series_colors, cfg)
            else:
                for series, color in zip(panel.series, series_colors, strict=True):
                    self._draw_series(ax, series, color, cfg)
            self._style_panel(ax, panel, cfg)

        self._time_axis(axes[-1][0], cfg)
        fig.suptitle(self._name(), **cfg["title"])
        fig.tight_layout(rect=(0, 0, 1, 0.97))
        self._fig = fig

    def _draw_series(self, ax, series: TrendSeries, color: str, cfg: dict[str, Any]) -> None:
        import matplotlib.dates as mdates

        if not series.points:
            return
        xs = [mdates.date2num(t) for t, _ in series.points]
        ys = [v for _, v in series.points]
        line = cfg["line"]
        if series.kind == "bar":
            width = (min(b - a for a, b in pairwise(xs)) * 0.6) if len(xs) > 1 else 0.5
            ax.bar(xs, ys, width=width, color=color, label=series.name, zorder=2)
        else:
            drawstyle = "steps-post" if series.kind == "step" else "default"
            ax.plot(
                xs,
                ys,
                color=color,
                linewidth=line["width"],
                marker="o",
                markersize=line["marker_size"],
                drawstyle=drawstyle,
                label=series.name,
                zorder=3,
            )
            if series.kind == "area":
                ax.fill_between(xs, ys, color=color, alpha=line["fill_alpha"], step=None, zorder=2)
        self._label_last(ax, xs[-1], ys[-1], color, cfg)

    def _draw_stacked(self, ax, panel: TrendPanel, colors: list[str], cfg: dict[str, Any]) -> None:
        """Stacked areas over the union of the panel's timestamps (a missing value counts as 0)."""
        import matplotlib.dates as mdates

        times = sorted({t for s in panel.series for t, _ in s.points})
        xs = [mdates.date2num(t) for t in times]
        layers = [[dict(s.points).get(t, 0.0) for t in times] for s in panel.series]
        ax.stackplot(xs, layers, colors=colors, labels=[s.name for s in panel.series], alpha=0.85, zorder=2)
        if xs:
            self._label_last(ax, xs[-1], sum(layer[-1] for layer in layers), cfg["value"]["color"], cfg)

    def _label_last(self, ax, x: float, y: float, color: str, cfg: dict[str, Any]) -> None:
        """The latest value next to the last point."""
        value = cfg["value"]
        if not value.get("show", True):
            return
        text = f"{y:g}" if abs(y) < 1e6 else f"{y:.3g}"
        ax.annotate(
            text,
            (x, y),
            xytext=(6, 0),
            textcoords="offset points",
            va="center",
            fontsize=value["fontsize"],
            color=color,
            fontweight="bold",
        )

    def _style_panel(self, ax, panel: TrendPanel, cfg: dict[str, Any]) -> None:
        axis, panel_cfg, face = cfg["axis"], cfg["panel"], cfg["figure"]["facecolor"]
        ax.set_facecolor(face)
        ax.set_title(
            panel.name, loc="left", fontsize=panel_cfg["fontsize"], color=panel_cfg["color"], fontweight="bold"
        )
        if panel.unit:
            ax.set_ylabel(panel.unit, fontsize=axis["fontsize"], color=axis["color"])
        ax.grid(True, color=axis["gridcolor"], linewidth=0.8)
        ax.set_axisbelow(True)
        ax.tick_params(colors=axis["color"], labelsize=axis["fontsize"])
        for spine in ("top", "right"):
            ax.spines[spine].set_visible(False)
        for spine in ("left", "bottom"):
            ax.spines[spine].set_edgecolor(axis["color"])
        values = [v for s in panel.series for _, v in s.points]
        if values and min(values) >= 0:
            ax.set_ylim(bottom=0)  # counts: start at zero
        ax.margins(x=0.06)
        if len(panel.series) > 1:
            legend = ax.legend(
                loc="upper left", fontsize=axis["fontsize"] - 1, framealpha=0.85, ncol=min(len(panel.series), 5)
            )
            legend.get_frame().set_facecolor(face)
            legend.get_frame().set_edgecolor(axis["gridcolor"])
            for text in legend.get_texts():
                text.set_color(axis["color"])

    def _time_axis(self, ax, cfg: dict[str, Any]) -> None:
        import matplotlib.dates as mdates

        locator = mdates.AutoDateLocator(minticks=3, maxticks=10)
        ax.xaxis.set_major_locator(locator)
        ax.xaxis.set_major_formatter(mdates.ConciseDateFormatter(locator))
        ax.tick_params(axis="x", labelsize=cfg["axis"]["fontsize"], colors=cfg["axis"]["color"])

    def _draw_impl(self, outputfile: str) -> None:
        if self._fig is None:
            raise TrendError("Trend chart not rendered; call render() first")
        output_path = f"{outputfile}.{self.format}"
        # No creation date in SVG/PDF metadata, fixed SVG ids: reproducible output
        metadata = {"svg": {"Date": None}, "pdf": {"CreationDate": None}}.get(self.format)
        try:
            import matplotlib.pyplot as plt

            with plt.rc_context({"svg.hashsalt": "usecvislib-trend"}), _quiet_numpy_timedelta():
                self._fig.savefig(
                    output_path,
                    format=self.format,
                    dpi=self.style.get("figure", {}).get("dpi", 150) if isinstance(self.style, dict) else 150,
                    bbox_inches="tight",
                    facecolor=self._fig.get_facecolor(),
                    metadata=metadata,
                )
        except Exception as e:  # pragma: no cover - matplotlib IO failure
            raise TrendError(f"Failed to write trend chart: {e}") from e
        finally:
            import matplotlib.pyplot as plt

            plt.close(self._fig)
            self._fig = None

    # ------------------------------------------------------------ analysis

    def _validate_impl(self) -> list[str]:
        errors = list(self.warnings)
        if not self.series:
            errors.append("No series defined")
        errors += [f"Series '{s.name}' has no points" for s in self.series if not s.points]
        return errors

    def _get_stats_impl(self) -> dict[str, Any]:
        times = [t for s in self.series for t, _ in s.points]
        return {
            "name": self._name(),
            "total_series": len(self.series),
            "total_panels": len(self.panels),
            "total_points": sum(len(s.points) for s in self.series),
            "start_time": min(times).isoformat() if times else "",
            "end_time": max(times).isoformat() if times else "",
            "series": {
                s.name: {
                    "unit": s.unit,
                    "panel": s.panel,
                    "points": len(s.points),
                    "first": s.first,
                    "last": s.last,
                    "min": min((v for _, v in s.points), default=None),
                    "max": max((v for _, v in s.points), default=None),
                    "change": (s.last - s.first) if s.points else None,
                }
                for s in self.series
            },
            "warnings": list(self.warnings),
        }

    def _get_metadata_root_key(self) -> str:
        return "trend"

    def __del__(self):
        """Remove a builder's temp input if the chart was never loaded."""
        if getattr(self, "_temp_input", None):
            import os

            with contextlib.suppress(OSError):
                os.unlink(self._temp_input)
