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
    "page": {"background": "#f8fafc", "padding": 32},
    "font": {"family": "Helvetica Neue, Helvetica, Arial, sans-serif", "size": 12, "root_size": 14},
    "card": {
        "radius": 10,
        "padding_x": 14,
        "padding_y": 10,
        "border_width": 1.0,
        "min_width": 90,
        "max_label_width": 260,
    },
    "node": {"fill": "#3d5a80", "border": "#1e3a5f", "text": "#ffffff"},
    "root": {"fill": "#1e3a5f", "border": "#0d1b2a", "text": "#ffffff"},
    "edge": {"color": "#94a3b8", "width": 1.6, "routing": "ortho"},
    "effects": {"shadow": True, "shadow_blur": 1.8, "hover_glow": True},
    "severity": {"use_cvss_colors": True},
    "badges": {"cvss": True, "fill": "#0f172a", "text": "#ffffff"},
    "layout": {"h_gap": 28, "v_gap": 60},
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
