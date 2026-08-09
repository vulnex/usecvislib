#
# VULNEX -Universal Security Visualization Library-
#
# File: metrics.py
# Author: Simon Roses Femerling
# Created: 2026-08-08
# Last Modified: 2026-08-08
# Version: 0.4.1
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Text measurement for the SVG engine.

Accurate text extents are what keep labels inside their cards: painters
measure before layout runs. Measurement uses matplotlib's font machinery
(already a project dependency); unknown font families fall back to
matplotlib's bundled DejaVu Sans, so results stay correct — and, when a
theme pins DejaVu explicitly, identical across platforms.

matplotlib is imported lazily so importing usecvislib stays fast.
"""

import logging
from functools import lru_cache

logger = logging.getLogger(__name__)

LINE_HEIGHT = 1.45  # line advance as a multiple of font size


def _font_families(family: str) -> tuple[str, ...]:
    """Split a CSS-style font stack into a matplotlib family list."""
    names = []
    for part in family.split(","):
        name = part.strip().strip("'\"")
        if name:
            names.append(name)
    return tuple(names) or ("DejaVu Sans",)


@lru_cache(maxsize=8192)
def measure_text(text: str, family: str, size: float, bold: bool = False) -> float:
    """Measure the rendered width of a single line of text.

    Args:
        text: The text to measure (single line, no newlines).
        family: CSS-style font stack, e.g. "Helvetica, Arial, sans-serif".
        size: Font size in SVG user units (px).
        bold: Measure the bold weight. Text drawn bold but measured
            regular under-reports by ~5-8%, eating the card padding.

    Returns:
        Width in SVG user units.
    """
    if not text:
        return 0.0

    from matplotlib.font_manager import FontProperties
    from matplotlib.textpath import TextPath

    prop = FontProperties(family=list(_font_families(family)), size=size, weight="bold" if bold else "normal")
    # findfont logs a warning per missing family in the stack; falling back
    # through the stack (ultimately to DejaVu) is intended, so silence it.
    findfont_logger = logging.getLogger("matplotlib.font_manager")
    previous_level = findfont_logger.level
    findfont_logger.setLevel(logging.ERROR)
    try:
        path = TextPath((0, 0), text, prop=prop)
    finally:
        findfont_logger.setLevel(previous_level)
    return float(path.get_extents().width)


def wrap_text(text: str, family: str, size: float, max_width: float, bold: bool = False) -> list[str]:
    """Greedy word-wrap of text against a maximum line width.

    Explicit newlines (both ``\\n`` escapes and literal newlines) are
    honored as hard breaks. A single word wider than ``max_width`` is kept
    on its own line rather than split mid-word.

    Returns:
        List of wrapped lines (at least one entry, possibly empty string).
    """
    lines: list[str] = []
    for hard_line in text.replace("\\n", "\n").split("\n"):
        words = hard_line.split()
        if not words:
            lines.append("")
            continue
        current = words[0]
        for word in words[1:]:
            candidate = f"{current} {word}"
            if measure_text(candidate, family, size, bold) <= max_width:
                current = candidate
            else:
                lines.append(current)
                current = word
        lines.append(current)
    return lines or [""]


def measure_block(lines: list[str], family: str, size: float, bold: bool = False) -> tuple[float, float]:
    """Measure the bounding box of a block of wrapped lines.

    Returns:
        (width, height) in SVG user units. Height uses the engine line
        height rather than glyph extents, for cross-font stability.
    """
    width = max((measure_text(line, family, size, bold) for line in lines), default=0.0)
    height = len(lines) * size * LINE_HEIGHT
    return (width, height)
