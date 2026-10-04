#
# VULNEX -Universal Security Visualization Library-
#
# File: timeline.py
# Author: Simon Roses Femerling
# Created: 2026-08-27
# Last Modified: 2026-08-27
# Version: 0.4.1
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Incident Timeline visualization module (CLI mode 10).

Renders the chronology of a security incident as a time-ordered set of
events, optionally grouped into swimlanes (asset/actor) and overlaid with
response phases (detection -> containment -> eradication -> recovery).
Matplotlib-based; four render modes:

- **swimlane** (default): horizontal lanes, events as markers/duration bars.
- **gantt**: one bar per event spanning its duration, emphasising overlap.
- **vertical**: top-down timeline with alternating side annotations.
- **compact**: single-row strip, minimal height.

Events carry a severity that drives marker/bar coloring, an optional ATT&CK
technique tag, and an optional duration, so the diagram doubles as an IR
narrative and a response-time map (MTTD / MTTR summary statistics).

Input schema (TOML/JSON/YAML)::

    [incident]
    name = "Ransomware Incident"
    id = "INC-2026-0042"
    analyst = "SOC Team"

    [[phases]]
    name = "Detection"
    start = "2026-01-15T08:00:00Z"
    end   = "2026-01-15T10:00:00Z"
    color = "#e74c3c"

    [[events]]
    id = "EVT-001"
    timestamp = "2026-01-15T08:32:00Z"
    title = "Phishing email opened"
    severity = "high"
    lane = "User Workstation"
    technique = "T1566.001"
    duration = "2m"
"""

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Optional

from . import utils
from .base import VisualizationBase


class TimelineError(utils.RenderError):
    """Raised when timeline rendering or validation fails."""


# Severity ordering (high -> low) and the canonical color ramp.
_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
_VALID_SEVERITIES = set(_SEVERITY_ORDER)
SEVERITY_COLORS = {
    "critical": "#c0392b",
    "high": "#e74c3c",
    "medium": "#e0a53f",
    "low": "#27ae60",
    "info": "#3498db",
}

# Response phases recognised for MTTD/MTTR analysis (matched case-insensitively
# against phase names by substring).
_DETECTION_KEYS = ("detect",)
_CONTAINMENT_KEYS = ("contain",)
_RESOLUTION_KEYS = ("recover", "resolut", "eradicat")

SUPPORTED_MODES = ("swimlane", "gantt", "vertical", "compact")

_DURATION_UNITS = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}
_DURATION_RE = re.compile(r"(\d+(?:\.\d+)?)\s*([smhd])", re.IGNORECASE)


def parse_timestamp(value: Any) -> datetime:
    """Parse an ISO-8601 timestamp (accepts a trailing ``Z``)."""
    if isinstance(value, datetime):
        return value
    text = str(value).strip()
    if not text:
        raise TimelineError("Empty timestamp")
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text)
    except ValueError as e:
        raise TimelineError(f"Invalid timestamp '{value}': expected ISO-8601 (YYYY-MM-DDTHH:MM:SS)") from e


def parse_duration(value: Any) -> Optional[timedelta]:
    """Parse a compact duration string like ``2m``, ``1h30m``, ``45s``, ``2d``."""
    if value is None or value == "":
        return None
    if isinstance(value, int | float):
        return timedelta(minutes=float(value))
    text = str(value).strip()
    matches = _DURATION_RE.findall(text)
    if not matches:
        return None
    total = timedelta()
    for amount, unit in matches:
        total += timedelta(**{_DURATION_UNITS[unit.lower()]: float(amount)})
    return total or None


def _humanize(delta: timedelta) -> str:
    """Render a timedelta as a compact human string (e.g. ``1h 5m``)."""
    seconds = int(delta.total_seconds())
    if seconds < 0:
        return "0s"
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if minutes:
        parts.append(f"{minutes}m")
    if secs and not days and not hours:
        parts.append(f"{secs}s")
    return " ".join(parts) if parts else "0s"


@dataclass
class TimelineEvent:
    """A single event on the incident timeline."""

    id: str
    timestamp: datetime
    title: str
    description: str = ""
    severity: str = "info"
    lane: str = "Events"
    duration: Optional[timedelta] = None
    technique: Optional[str] = None
    source: Optional[str] = None
    indicators: list[str] = field(default_factory=list)

    @property
    def end_time(self) -> datetime:
        """Event end (``timestamp`` when no duration is set)."""
        return self.timestamp + self.duration if self.duration else self.timestamp

    @property
    def color(self) -> str:
        return SEVERITY_COLORS.get(self.severity, SEVERITY_COLORS["info"])


@dataclass
class TimelinePhase:
    """A response phase / milestone band spanning a time range."""

    name: str
    start: datetime
    end: datetime
    color: str = "#3498db"
    description: str = ""


class IncidentTimeline(VisualizationBase):
    """Incident timeline visualization (Matplotlib, four render modes)."""

    STYLE_FILE = "config_timeline.tml"
    DEFAULT_STYLE_ID = "tl_default"
    SVG_DEFAULT_STYLE_ID = "sv_default"
    ALLOWED_FORMATS = ("png", "pdf", "svg")

    def __init__(
        self,
        inputfile: str,
        outputfile: str,
        format: str = "png",
        styleid: Optional[str] = None,
        validate_paths: bool = True,
        mode: str = "swimlane",
        render_engine: str = "graphviz",
    ) -> None:
        # Default path is Matplotlib; render_engine="svg" routes to the native
        # SVG painter (all four modes) via the engine's paint dispatch.
        super().__init__(
            inputfile,
            outputfile,
            format=format or "png",
            styleid=styleid,
            validate_paths=validate_paths,
            render_engine=render_engine,
        )
        if (self.format or "png") == "dot":
            raise TimelineError("Format 'dot' is not supported by the timeline renderer. Use png, pdf, or svg.")
        self.mode = mode if mode in SUPPORTED_MODES else "swimlane"
        self._fig: Optional[Any] = None
        self.events: list[TimelineEvent] = []
        self.phases: list[TimelinePhase] = []
        self.lanes: list[str] = []
        self.warnings: list[str] = []

    # --------------------------------------------------------- VisualizationBase

    def _default_style(self) -> dict[str, Any]:
        """Fallback style if the config file is unavailable (clean, light)."""
        return {
            "figure": {"width": 16.0, "height": 9.0, "dpi": 150, "facecolor": "#ffffff"},
            "title": {"fontsize": 16, "fontweight": "bold", "color": "#1e293b"},
            "axis": {"fontsize": 10, "color": "#334155", "gridcolor": "#e2e8f0"},
            "lane": {"fontsize": 10, "color": "#1e3a5f", "band_alpha": 0.06},
            "event": {"marker_size": 130, "fontsize": 8, "text_color": "#334155", "edgecolor": "#334155"},
            "phase": {"alpha": 0.12, "fontsize": 9, "color": "#64748b"},
        }

    def _load_impl(self) -> dict[str, Any]:
        """Load and parse the timeline configuration."""
        data = utils.ReadConfigFile(self.inputfile)
        if not isinstance(data, dict):
            raise TimelineError("Timeline input must be a mapping")

        self.events.clear()
        self.phases.clear()
        self.warnings.clear()

        raw_events = data.get("events", [])
        if not isinstance(raw_events, list):
            raise TimelineError("'events' must be a list of event definitions")

        lanes_seen: list[str] = []
        for idx, ev in enumerate(raw_events):
            if not isinstance(ev, dict):
                continue
            ts_raw = ev.get("timestamp")
            if ts_raw is None:
                self.warnings.append(f"Event #{idx + 1} has no timestamp; skipped")
                continue
            timestamp = parse_timestamp(ts_raw)
            severity = str(ev.get("severity", "info")).lower()
            if severity not in _VALID_SEVERITIES:
                self.warnings.append(f"Event '{ev.get('id', idx + 1)}': unknown severity '{severity}', using info")
                severity = "info"
            lane = str(ev.get("lane", "Events"))
            if lane not in lanes_seen:
                lanes_seen.append(lane)
            indicators = ev.get("indicators", [])
            self.events.append(
                TimelineEvent(
                    id=str(ev.get("id", f"EVT-{idx + 1}")),
                    timestamp=timestamp,
                    title=str(ev.get("title", ev.get("id", "event"))),
                    description=str(ev.get("description", "")),
                    severity=severity,
                    lane=lane,
                    duration=parse_duration(ev.get("duration")),
                    technique=ev.get("technique"),
                    source=ev.get("source"),
                    indicators=[str(i) for i in indicators] if isinstance(indicators, list) else [],
                )
            )

        # Keep events chronological; the whole module assumes sorted order.
        self.events.sort(key=lambda e: e.timestamp)
        self.lanes = lanes_seen

        raw_phases = data.get("phases", [])
        if isinstance(raw_phases, list):
            for ph in raw_phases:
                if not isinstance(ph, dict):
                    continue
                start_raw, end_raw = ph.get("start"), ph.get("end")
                if start_raw is None or end_raw is None:
                    self.warnings.append(f"Phase '{ph.get('name', '?')}' missing start/end; skipped")
                    continue
                self.phases.append(
                    TimelinePhase(
                        name=str(ph.get("name", "Phase")),
                        start=parse_timestamp(start_raw),
                        end=parse_timestamp(end_raw),
                        color=str(ph.get("color", "#3498db")),
                        description=str(ph.get("description", "")),
                    )
                )

        utils.check_graph_complexity(len(self.events), len(self.phases))
        return data

    # ------------------------------------------------------------------ helpers

    def _incident_name(self) -> str:
        incident = self.inputdata.get("incident", {})
        if isinstance(incident, dict):
            return str(incident.get("name", "Incident Timeline"))
        return "Incident Timeline"

    def events_by_lane(self) -> dict[str, list[TimelineEvent]]:
        """Events grouped under each lane, in chronological order."""
        grouped: dict[str, list[TimelineEvent]] = {lane: [] for lane in self.lanes}
        for ev in self.events:
            grouped.setdefault(ev.lane, []).append(ev)
        return grouped

    def severity_distribution(self) -> dict[str, int]:
        dist = dict.fromkeys(_SEVERITY_ORDER, 0)
        for ev in self.events:
            dist[ev.severity] = dist.get(ev.severity, 0) + 1
        return dist

    def time_span(self) -> Optional[timedelta]:
        if not self.events:
            return None
        return self.events[-1].end_time - self.events[0].timestamp

    def _phase_time(self, keys: tuple[str, ...]) -> Optional[datetime]:
        """End time of the first phase whose name matches any of ``keys``."""
        for ph in self.phases:
            if any(k in ph.name.lower() for k in keys):
                return ph.end
        return None

    def response_metrics(self) -> dict[str, Optional[str]]:
        """MTTD / MTTR style deltas derived from phase boundaries.

        Uses the incident start (first event) as the baseline and measures to
        the end of the detection / containment / recovery phases when present.
        """
        if not self.events:
            return {"time_to_detect": None, "time_to_contain": None, "time_to_resolve": None}
        start = self.events[0].timestamp
        detect = self._phase_time(_DETECTION_KEYS)
        contain = self._phase_time(_CONTAINMENT_KEYS)
        resolve = self._phase_time(_RESOLUTION_KEYS)
        return {
            "time_to_detect": _humanize(detect - start) if detect else None,
            "time_to_contain": _humanize(contain - start) if contain else None,
            "time_to_resolve": _humanize(resolve - start) if resolve else None,
        }

    # ------------------------------------------------------------------ render

    def _render_impl(self) -> None:
        """Build the Matplotlib figure for the selected mode."""
        # Local import keeps matplotlib off the import path for callers that
        # only touch load()/validate()/get_stats() (mirrors maestro.py).
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        style = self.style if isinstance(self.style, dict) else self._default_style()
        fig_cfg = {**self._default_style()["figure"], **style.get("figure", {})}

        if not self.events:
            fig, ax = plt.subplots(figsize=(8, 2))
            ax.text(0.5, 0.5, "No events to display", ha="center", va="center", fontsize=12, color="#94a3b8")
            ax.axis("off")
            fig.tight_layout()
            self._fig = fig
            return

        renderer = {
            "swimlane": self._render_swimlane,
            "gantt": self._render_gantt,
            "vertical": self._render_vertical,
            "compact": self._render_compact,
        }[self.mode]
        self._fig = renderer(plt, style, fig_cfg)

    def _apply_time_axis(self, ax, style: dict[str, Any]) -> None:
        """Format an x-axis carrying matplotlib date numbers."""
        import matplotlib.dates as mdates

        span = self.time_span() or timedelta(minutes=1)
        fmt = "%H:%M" if span <= timedelta(days=1) else "%m-%d %H:%M"
        ax.xaxis.set_major_formatter(mdates.DateFormatter(fmt))
        ax.xaxis_date()
        for label in ax.get_xticklabels():
            label.set_rotation(30)
            label.set_horizontalalignment("right")
            label.set_fontsize(style.get("axis", {}).get("fontsize", 9))

    def _draw_phase_bands(self, ax, style: dict[str, Any], vertical: bool = False) -> None:
        """Shade response-phase bands behind the events."""
        import matplotlib.dates as mdates

        phase_cfg = {**self._default_style()["phase"], **style.get("phase", {})}
        for ph in self.phases:
            lo, hi = mdates.date2num(ph.start), mdates.date2num(ph.end)
            if vertical:
                ax.axhspan(lo, hi, color=ph.color, alpha=phase_cfg["alpha"], zorder=0)
            else:
                ax.axvspan(lo, hi, color=ph.color, alpha=phase_cfg["alpha"], zorder=0)
                mid = lo + (hi - lo) / 2
                ax.text(
                    mid,
                    0.995,
                    ph.name,
                    transform=ax.get_xaxis_transform(),
                    ha="center",
                    va="top",
                    fontsize=phase_cfg["fontsize"],
                    color=ph.color,
                    fontweight="bold",
                    clip_on=True,
                )

    def _severity_legend(self, ax) -> None:
        from matplotlib.lines import Line2D

        present = [s for s in _SEVERITY_ORDER if any(e.severity == s for e in self.events)]
        handles = [
            Line2D([0], [0], marker="o", color="w", markerfacecolor=SEVERITY_COLORS[s], markersize=9, label=s.title())
            for s in present
        ]
        if handles:
            ax.legend(handles=handles, loc="upper right", fontsize=8, framealpha=0.9, title="Severity")

    def _finish(self, fig, ax, style: dict[str, Any]) -> Any:
        title_cfg = {**self._default_style()["title"], **style.get("title", {})}
        fig.suptitle(self._incident_name(), **title_cfg)
        fig.tight_layout(rect=(0, 0, 1, 0.97))
        return fig

    @staticmethod
    def _label_slots(events: list[TimelineEvent], span: timedelta) -> list[tuple[int, str]]:
        """Assign each event's label an offset slot to avoid overlap.

        Greedily packs labels of time-clustered events into staggered tiers
        alternating above (``bottom`` va) and below (``top`` va) the marker.
        Events further apart than ~7% of the total span reuse the nearest
        free tier, so sparse lanes stay clean while dense ones fan out.
        """
        # (dy in points, matplotlib va). Alternates above / below, widening.
        tiers = [(11, "bottom"), (-12, "top"), (25, "bottom"), (-26, "top"), (39, "bottom"), (-40, "top")]
        threshold = (span.total_seconds() or 1) * 0.07
        last_ts: list[Optional[datetime]] = [None] * len(tiers)
        result: list[tuple[int, str]] = []
        for ev in events:
            for i, tier in enumerate(tiers):
                prev = last_ts[i]
                if prev is None or (ev.timestamp - prev).total_seconds() >= threshold:
                    result.append(tier)
                    last_ts[i] = ev.timestamp
                    break
            else:
                # Every tier is still occupied by a near neighbour; reuse tier 0.
                result.append(tiers[0])
                last_ts[0] = ev.timestamp
        return result

    def _render_swimlane(self, plt, style: dict[str, Any], fig_cfg: dict[str, Any]) -> Any:
        import matplotlib.dates as mdates

        lanes = self.lanes or ["Events"]
        grouped = self.events_by_lane()
        ev_cfg = {**self._default_style()["event"], **style.get("event", {})}
        lane_cfg = {**self._default_style()["lane"], **style.get("lane", {})}

        height = max(3.0, 0.9 * len(lanes) + 2.0)
        fig, ax = plt.subplots(figsize=(fig_cfg["width"], height), dpi=fig_cfg["dpi"], facecolor=fig_cfg["facecolor"])
        y_of = {lane: i for i, lane in enumerate(reversed(lanes))}

        self._draw_phase_bands(ax, style)

        # Alternating lane background bands for readability.
        for y in y_of.values():
            ax.axhspan(
                y - 0.5, y + 0.5, color=lane_cfg["color"], alpha=lane_cfg["band_alpha"] if y % 2 else 0.0, zorder=0
            )

        span = self.time_span() or timedelta(minutes=1)
        for lane in lanes:
            y = y_of[lane]
            lane_events = grouped.get(lane, [])
            slots = self._label_slots(lane_events, span)
            for ev, (dy, va) in zip(lane_events, slots, strict=True):
                x = mdates.date2num(ev.timestamp)
                if ev.duration:
                    x_end = mdates.date2num(ev.end_time)
                    ax.plot(
                        [x, x_end], [y, y], color=ev.color, linewidth=6, alpha=0.55, solid_capstyle="round", zorder=2
                    )
                ax.scatter(
                    x, y, s=ev_cfg["marker_size"], c=ev.color, edgecolors=ev_cfg["edgecolor"], linewidths=0.8, zorder=3
                )
                label = ev.title if not ev.technique else f"{ev.title}\n{ev.technique}"
                ax.annotate(
                    label,
                    (x, y),
                    xytext=(0, dy),
                    textcoords="offset points",
                    ha="center",
                    va=va,
                    fontsize=ev_cfg["fontsize"],
                    color=ev_cfg["text_color"],
                    zorder=4,
                )

        ax.set_yticks(list(y_of.values()))
        ax.set_yticklabels(list(y_of.keys()), fontsize=lane_cfg["fontsize"], color=lane_cfg["color"])
        ax.set_ylim(-0.7, len(lanes) - 0.3)
        ax.set_xlabel("Time", fontsize=style.get("axis", {}).get("fontsize", 10))
        ax.grid(True, axis="x", linestyle="--", alpha=0.5, color=style.get("axis", {}).get("gridcolor", "#e2e8f0"))
        ax.set_axisbelow(True)
        self._apply_time_axis(ax, style)
        self._severity_legend(ax)
        return self._finish(fig, ax, style)

    def _render_gantt(self, plt, style: dict[str, Any], fig_cfg: dict[str, Any]) -> Any:
        import matplotlib.dates as mdates

        ev_cfg = {**self._default_style()["event"], **style.get("event", {})}
        n = len(self.events)
        height = max(3.0, 0.5 * n + 2.0)
        fig, ax = plt.subplots(figsize=(fig_cfg["width"], height), dpi=fig_cfg["dpi"], facecolor=fig_cfg["facecolor"])

        self._draw_phase_bands(ax, style)

        min_bar = (self.time_span() or timedelta(minutes=10)) / max(n, 1) * 0.15
        for row, ev in enumerate(reversed(self.events)):
            x = mdates.date2num(ev.timestamp)
            width = mdates.date2num(ev.end_time + (min_bar if not ev.duration else timedelta())) - x
            ax.barh(
                row, width, left=x, height=0.6, color=ev.color, edgecolor=ev_cfg["edgecolor"], linewidth=0.6, zorder=3
            )
            tag = f"  {ev.title}" + (f" [{ev.technique}]" if ev.technique else "")
            ax.text(
                x, row, tag, va="center", ha="left", fontsize=ev_cfg["fontsize"], color=ev_cfg["text_color"], zorder=4
            )

        ax.set_yticks(range(n))
        ax.set_yticklabels([ev.id for ev in reversed(self.events)], fontsize=8)
        ax.set_ylim(-0.7, n - 0.3)
        ax.set_xlabel("Time", fontsize=style.get("axis", {}).get("fontsize", 10))
        ax.grid(True, axis="x", linestyle="--", alpha=0.5, color=style.get("axis", {}).get("gridcolor", "#e2e8f0"))
        ax.set_axisbelow(True)
        self._apply_time_axis(ax, style)
        self._severity_legend(ax)
        return self._finish(fig, ax, style)

    def _render_vertical(self, plt, style: dict[str, Any], fig_cfg: dict[str, Any]) -> Any:
        import matplotlib.dates as mdates

        ev_cfg = {**self._default_style()["event"], **style.get("event", {})}
        n = len(self.events)
        height = max(4.0, 0.6 * n + 2.0)
        fig, ax = plt.subplots(
            figsize=(max(8.0, fig_cfg["width"] * 0.6), height), dpi=fig_cfg["dpi"], facecolor=fig_cfg["facecolor"]
        )

        self._draw_phase_bands(ax, style, vertical=True)

        ys = [mdates.date2num(ev.timestamp) for ev in self.events]
        ax.plot([0.5] * n, ys, color="#cbd5e1", linewidth=2, zorder=1)
        for i, ev in enumerate(self.events):
            y = ys[i]
            ax.scatter(
                0.5, y, s=ev_cfg["marker_size"], c=ev.color, edgecolors=ev_cfg["edgecolor"], linewidths=0.8, zorder=3
            )
            side = 1 if i % 2 == 0 else -1
            label = ev.title if not ev.technique else f"{ev.title} [{ev.technique}]"
            ax.annotate(
                label,
                (0.5, y),
                xytext=(side * 40, 0),
                textcoords="offset points",
                ha="left" if side > 0 else "right",
                va="center",
                fontsize=ev_cfg["fontsize"],
                color=ev_cfg["text_color"],
                zorder=4,
            )

        ax.set_xlim(-0.2, 1.2)
        ax.set_xticks([])
        ax.yaxis_date()
        ax.yaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))
        ax.invert_yaxis()
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
        ax.spines["bottom"].set_visible(False)
        self._severity_legend(ax)
        return self._finish(fig, ax, style)

    def _render_compact(self, plt, style: dict[str, Any], fig_cfg: dict[str, Any]) -> Any:
        import matplotlib.dates as mdates

        ev_cfg = {**self._default_style()["event"], **style.get("event", {})}
        fig, ax = plt.subplots(figsize=(fig_cfg["width"], 2.6), dpi=fig_cfg["dpi"], facecolor=fig_cfg["facecolor"])

        self._draw_phase_bands(ax, style)
        xs = [mdates.date2num(ev.timestamp) for ev in self.events]
        ax.plot([min(xs), max(xs)], [0, 0], color="#cbd5e1", linewidth=2, zorder=1)
        for i, ev in enumerate(self.events):
            ax.scatter(
                xs[i], 0, s=ev_cfg["marker_size"], c=ev.color, edgecolors=ev_cfg["edgecolor"], linewidths=0.8, zorder=3
            )
            ax.annotate(
                ev.title,
                (xs[i], 0),
                xytext=(0, 12 if i % 2 == 0 else -12),
                textcoords="offset points",
                ha="center",
                va="bottom" if i % 2 == 0 else "top",
                fontsize=ev_cfg["fontsize"],
                color=ev_cfg["text_color"],
                rotation=0,
                zorder=4,
            )

        ax.set_ylim(-1, 1)
        ax.set_yticks([])
        ax.set_xlabel("Time", fontsize=style.get("axis", {}).get("fontsize", 10))
        ax.spines["top"].set_visible(False)
        ax.spines["left"].set_visible(False)
        ax.spines["right"].set_visible(False)
        self._apply_time_axis(ax, style)
        return self._finish(fig, ax, style)

    def _draw_impl(self, outputfile: str) -> None:
        if self._fig is None:
            raise TimelineError("Timeline not rendered; call render() first")
        output_path = f"{outputfile}.{self.format}"
        try:
            self._fig.savefig(
                output_path, format=self.format, dpi=self.style.get("figure", {}).get("dpi", 150), bbox_inches="tight"
            )
        except Exception as e:  # pragma: no cover - matplotlib IO failure
            raise TimelineError(f"Failed to write timeline: {e}") from e
        finally:
            import matplotlib.pyplot as plt

            plt.close(self._fig)

    def _validate_impl(self) -> list[str]:
        errors = list(self.warnings)
        if not self.events:
            errors.append("No events defined in timeline")
        for ph in self.phases:
            if ph.end < ph.start:
                errors.append(f"Phase '{ph.name}': end is before start")
        return errors

    def _get_stats_impl(self) -> dict[str, Any]:
        grouped = self.events_by_lane()
        span = self.time_span()
        return {
            "name": self._incident_name(),
            "total_events": len(self.events),
            "total_phases": len(self.phases),
            "lanes": list(self.lanes),
            "severity_distribution": self.severity_distribution(),
            "events_per_lane": {lane: len(grouped.get(lane, [])) for lane in self.lanes},
            "start_time": self.events[0].timestamp.isoformat() if self.events else "",
            "end_time": self.events[-1].end_time.isoformat() if self.events else "",
            "time_span": _humanize(span) if span else "",
            "tagged_events": sum(1 for e in self.events if e.technique),
            "response_metrics": self.response_metrics(),
            "warnings": list(self.warnings),
        }

    def _get_metadata_root_key(self) -> str:
        return "incident"

    # Convenience wrapper mirroring the other modules' Build* entry points.
    def BuildTimeline(self) -> "IncidentTimeline":
        """Load, render, and draw in one call."""
        self.build()
        return self
