#
# VULNEX -Universal Security Visualization Library-
#
# File: themes.py
# Author: Simon Roses Femerling
# Created: 2026-08-08
# Last Modified: 2026-08-08
# Version: 0.4.1
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Theme handling for the SVG engine.

``sv_*`` presets live in the existing per-module ``config_*.tml`` files and
are loaded through the standard style machinery. This module validates that
a loaded style actually targets the requested engine (via the preset's
``meta.engine`` marker), merges it over engine defaults, and parses value
syntaxes like ``gradient:#from>#to``.
"""

import copy
from typing import Any

from .scene import StyleEngineMismatchError

# Engine-level defaults; presets override selectively.
DEFAULTS: dict[str, Any] = {
    "meta": {"engine": "svg"},
    "page": {"background": "#f8fafc", "padding": 44, "text": "#111827"},
    "font": {"family": "Helvetica Neue, Helvetica, Arial, sans-serif", "size": 13, "root_size": 16},
    "card": {
        "radius": 10,
        "padding_x": 16,
        "padding_y": 11,
        "border_width": 1.0,
        "min_width": 104,
        "max_label_width": 280,
    },
    "title": {"show": True, "size": 15},
    "node": {"fill": "#3d5a80", "border": "#1e3a5f", "text": "#ffffff"},
    "root": {"fill": "#1e3a5f", "border": "#0d1b2a", "text": "#ffffff"},
    "edge": {"color": "#94a3b8", "width": 1.6, "routing": "ortho", "label_size": 10, "label_color": "#64748b"},
    "effects": {"shadow": True, "shadow_blur": 2.2, "hover_glow": True},
    "severity": {"use_cvss_colors": True},
    "badges": {"cvss": True, "gate": True, "coverage": True, "fill": "#0f172a", "text": "#ffffff"},
    "images": {"size": 48},
    "layout": {"h_gap": 40, "v_gap": 76},
    # General-graph cluster (SceneGroup) fallback styling. Painters that use
    # clusters (e.g. Component Diagram layers) usually set per-group colors;
    # these are the defaults the shared painter falls back to.
    "cluster": {"fill": "#eef2f7", "border": "#cbd5e1", "text": "#475569", "label_size": 12, "radius": 10},
    # Kill Chain (mode 9) swimlane: phase-header and flow-arrow colors.
    "killchain": {"phase_fill": "#1e3a5f", "phase_text": "#ffffff", "flow_color": "#94a3b8"},
    # Vuln Dependency Tree (mode 11): direct-dependency border + exploited-edge accent.
    "vulntree": {"direct_border": "#1e293b", "direct_border_width": 2.2, "exploited_color": "#0f172a", "exploited_width": 2.6},
    # Attack Graphs (mode 3): per-node-kind fills, edge-kind colors, and the
    # Graphviz-oracle layout spacing (rankdir + node/rank separation in inches).
    "attackgraph": {
        "host": "#3d5a80",
        "vulnerability": "#e74c3c",
        "privilege": "#e08e0b",
        "service": "#2f8f4e",
        "exploit": "#8e44ad",
        "border": "#1e293b",
        "network_edge": "#3b82c4",
        "exploit_edge": "#c0392b",
        "structural_edge": "#94a3b8",
        "exploit_edge_width": 2.4,
        "rankdir": "LR",
        "nodesep": 0.4,
        "ranksep": 0.7,
    },
    # Component Diagram (mode 7): a single component fill (types vary by
    # shape, not color — matching the Graphviz path), one connection color,
    # and a pastel palette cycled across layer clusters.
    "componentdiagram": {
        "component": "#4a90d9",
        "component_border": "#1e293b",
        "text": "#ffffff",
        "connection": "#64748b",
        "layer_palette": [
            "#e3f2fd",
            "#f3e5f5",
            "#e8f5e9",
            "#fff3e0",
            "#fce4ec",
            "#e0f7fa",
            "#f1f8e9",
            "#ede7f6",
        ],
        "layer_border": "#cbd5e1",
        "layer_text": "#334155",
        "rankdir": "TB",
        "nodesep": 0.5,
        "ranksep": 0.7,
    },
    # Dependency Graph (mode 8): per-group internal fills, external/muted
    # styling, the circular-dependency edge accent, and oracle spacing. Groups
    # convey the module's cluster (the general-graph path draws no cluster box
    # yet), so a group's color is its category.
    "dependencygraph": {
        "groups": {
            "core": "#4a90d9",
            "features": "#50c878",
            "api": "#e67e22",
            "infrastructure": "#9b59b6",
            "tests": "#1abc9c",
            "utils": "#f39c12",
        },
        "internal": "#5dade2",
        "external_fill": "#e5e9ef",
        "external_border": "#9aa8b5",
        "external_text": "#475569",
        "border": "#1e293b",
        "circular_edge": "#cc0000",
        "circular_width": 2.6,
        "rankdir": "LR",
        "nodesep": 0.4,
        "ranksep": 0.7,
    },
    # Incident Timeline (mode 10): time-chart lane/phase/axis colors (severity
    # marker colors are fixed in the module, not themed).
    "timeline": {
        "axis_length": 920,
        "lane_height": 58,
        "row_height": 34,
        "marker_radius": 6.5,
        "axis_color": "#94a3b8",
        "grid_color": "#e2e8f0",
        "axis_text": "#64748b",
        "lane_band": "#1e3a5f",
        "lane_band_alpha": 0.06,
        "lane_text": "#1e3a5f",
        "phase_alpha": 0.14,
        "connector": "#cbd5e1",
        "duration_alpha": 0.5,
    },
}


def deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Recursively merge ``override`` into a deep copy of ``base``."""
    merged = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = deep_merge(merged[key], value)
        else:
            merged[key] = copy.deepcopy(value)
    return merged


def require_svg_theme(style: dict[str, Any], styleid: str) -> None:
    """Raise unless the loaded style is marked for the SVG engine.

    Args:
        style: Style dict as loaded by the module's style machinery.
        styleid: The requested preset ID (for the error message).

    Raises:
        StyleEngineMismatchError: If the preset lacks ``meta.engine = "svg"``.
    """
    marker = style.get("meta", {}).get("engine") if isinstance(style, dict) else None
    if marker != "svg":
        raise StyleEngineMismatchError(
            f"Style '{styleid}' is not an SVG-engine preset. "
            f"Use an sv_* preset with render_engine='svg' (e.g. sv_default)."
        )


def reject_svg_theme(style: dict[str, Any], styleid: str) -> None:
    """Raise if an SVG-engine preset was selected for the Graphviz engine."""
    marker = style.get("meta", {}).get("engine") if isinstance(style, dict) else None
    if marker == "svg":
        raise StyleEngineMismatchError(
            f"Style '{styleid}' is an SVG-engine preset and cannot be used with "
            f"render_engine='graphviz'. Use a Graphviz preset or render_engine='svg'."
        )


def resolve(style: dict[str, Any]) -> dict[str, Any]:
    """Merge a loaded ``sv_*`` preset over the engine defaults."""
    return deep_merge(DEFAULTS, style if isinstance(style, dict) else {})


def parse_fill(value: str) -> tuple[str, ...]:
    """Parse a fill value.

    Returns:
        ("gradient", color_from, color_to) for ``gradient:a>b`` syntax,
        otherwise ("solid", value).
    """
    if isinstance(value, str) and value.startswith("gradient:"):
        body = value[len("gradient:") :]
        parts = body.split(">", 1)
        if len(parts) == 2 and parts[0] and parts[1]:
            return ("gradient", parts[0], parts[1])
    return ("solid", value)
