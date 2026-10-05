#
# VULNEX -Universal Security Visualization Library-
#
# File: shinepack.py
# Author: Simon Roses Femerling
# Created: 2026-08-08
# Last Modified: 2026-08-08
# Version: 0.4.1
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Shine pack: modernize Graphviz SVG output via post-processing.

Takes SVG produced by the Graphviz engine and injects a presentation layer:
a CSS block (font stack, rounded stroke joins, optional hover emphasis) and
a drop-shadow filter applied to node shapes. Layout, geometry, and all
existing attributes — including forwarded ``class`` attributes — are
preserved untouched.

Scope notes:
- Output is marked with ``data-usv-shine="1"``; re-applying is a no-op.
- The embedded CSS is presentation-only (no scripts, no external references)
  and scoped under the marker attribute so it cannot leak into a host page.
- Drop shadows use ``feDropShadow``, honored by browsers; raster converters
  with partial filter support (e.g. cairosvg) ignore them gracefully.
- Fonts: Graphviz sized node boxes for its own font metrics, so the default
  replacement stack is metrically close to avoid label overflow. Exact text
  sizing is solved properly by the Phase 1 SVG engine, not here.
"""

import logging
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional

from .. import utils

logger = logging.getLogger(__name__)

SVG_NS = "http://www.w3.org/2000/svg"
XLINK_NS = "http://www.w3.org/1999/xlink"

ET.register_namespace("", SVG_NS)
ET.register_namespace("xlink", XLINK_NS)

SHINE_MARKER = "data-usv-shine"
FILTER_ID = "usv-shine-shadow"
XML_DECLARATION = '<?xml version="1.0" encoding="UTF-8" standalone="no"?>\n'

DEFAULT_FONT_FAMILY = "'Helvetica Neue', Helvetica, Arial, sans-serif"

# Shapes that carry a node's visible body and receive the drop shadow.
_SHADOW_SHAPES = {f"{{{SVG_NS}}}polygon", f"{{{SVG_NS}}}ellipse", f"{{{SVG_NS}}}path"}


class ShineError(utils.RenderError):
    """Raised when shine post-processing fails."""


def _q(name: str) -> str:
    """Qualify a tag name with the SVG namespace."""
    return f"{{{SVG_NS}}}{name}"


def _has_class_token(element: ET.Element, token: str) -> bool:
    """Check whether an element's class attribute contains a token."""
    return token in element.get("class", "").split()


def _build_css(font_family: str, hover: bool) -> str:
    """Build the presentation-only CSS block, scoped under the shine marker."""
    rules = [
        f"[{SHINE_MARKER}] text {{ font-family: {font_family}; }}",
        f"[{SHINE_MARKER}] .node polygon, [{SHINE_MARKER}] .node ellipse {{ stroke-linejoin: round; }}",
    ]
    if hover:
        rules.append(
            f"[{SHINE_MARKER}] .node:hover polygon, "
            f"[{SHINE_MARKER}] .node:hover ellipse, "
            f"[{SHINE_MARKER}] .node:hover path {{ stroke-width: 2; }}"
        )
    return "\n".join(rules)


def _build_shadow_defs() -> ET.Element:
    """Build the <defs> element holding the drop-shadow filter."""
    defs = ET.Element(_q("defs"))
    filt = ET.SubElement(
        defs,
        _q("filter"),
        {"id": FILTER_ID, "x": "-20%", "y": "-20%", "width": "140%", "height": "140%"},
    )
    ET.SubElement(
        filt,
        _q("feDropShadow"),
        {
            "dx": "0",
            "dy": "1.5",
            "stdDeviation": "1.8",
            "flood-color": "#0f172a",
            "flood-opacity": "0.35",
        },
    )
    return defs


def _shape_width(group: ET.Element) -> float:
    """Inner width of a Graphviz node's shape (ellipse or polygon), 0 if unknown."""
    for child in group:
        if child.tag == _q("ellipse"):
            try:
                return 2 * float(child.get("rx", "0"))
            except ValueError:
                return 0.0
        if child.tag == _q("polygon"):
            try:
                xs = [float(p.split(",")[0]) for p in child.get("points", "").split()]
            except ValueError:
                return 0.0
            return max(xs) - min(xs) if xs else 0.0
    return 0.0


def _fit_text_to_graphviz_widths(root: ET.Element, font_family: str) -> None:
    """Keep re-fonted labels inside the node shapes Graphviz sized.

    Graphviz sized each node for its own font (Times by default); the shine
    font renders wider, so some labels overflowed their ellipses. A label
    whose estimated width (with a safety margin for wide fallback fonts)
    exceeds its shape's inner width is pinned to fit via textLength.
    """
    from . import metrics

    for group in root.iter(_q("g")):
        if not _has_class_token(group, "node"):
            continue
        available = _shape_width(group) - 12.0
        if available <= 0:
            continue
        for text in group.iter(_q("text")):
            content = "".join(text.itertext()).strip()
            if not content:
                continue
            try:
                size = float(text.get("font-size", "14"))
            except ValueError:
                continue
            if metrics.measure_text(content, font_family, size) * 1.1 > available:
                text.set("textLength", f"{available:.2f}")
                text.set("lengthAdjust", "spacingAndGlyphs")


def apply_shine(
    svg_text: str,
    *,
    font_family: str = DEFAULT_FONT_FAMILY,
    shadow: bool = True,
    hover: bool = True,
) -> str:
    """Apply shine styling to Graphviz SVG text.

    Args:
        svg_text: Complete SVG document as text.
        font_family: CSS font stack replacing the Graphviz default.
        shadow: Whether to add a drop shadow to node shapes.
        hover: Whether to add a hover stroke emphasis rule.

    Returns:
        The restyled SVG document. If the input is already shined
        (``data-usv-shine`` marker present), it is returned unchanged.

    Raises:
        ShineError: If the input is not a parseable SVG document.
    """
    try:
        root = ET.fromstring(svg_text)  # noqa: S314  (input is locally generated Graphviz output; expat >=2.4 caps entity expansion)
    except ET.ParseError as e:
        raise ShineError(f"Input is not valid SVG: {e}") from e

    if root.tag != _q("svg"):
        raise ShineError(f"Input is not an SVG document (root element: {root.tag})")

    if root.get(SHINE_MARKER):
        logger.debug("Shine marker already present; returning input unchanged")
        return svg_text

    root.set(SHINE_MARKER, "1")

    style = ET.Element(_q("style"), {"type": "text/css"})
    style.text = "\n" + _build_css(font_family, hover) + "\n"
    root.insert(0, style)

    _fit_text_to_graphviz_widths(root, font_family)

    if shadow:
        root.insert(0, _build_shadow_defs())
        for group in root.iter(_q("g")):
            if not _has_class_token(group, "node"):
                continue
            for child in group:
                if child.tag in _SHADOW_SHAPES and child.get("fill", "none") != "none":
                    child.set("filter", f"url(#{FILTER_ID})")

    return XML_DECLARATION + ET.tostring(root, encoding="unicode")


def apply_shine_file(
    path: str,
    *,
    font_family: str = DEFAULT_FONT_FAMILY,
    shadow: bool = True,
    hover: bool = True,
    logger_instance: Optional[logging.Logger] = None,
) -> str:
    """Apply shine styling to an SVG file in place.

    Args:
        path: Path to an existing ``.svg`` file.
        font_family: CSS font stack replacing the Graphviz default.
        shadow: Whether to add a drop shadow to node shapes.
        hover: Whether to add a hover stroke emphasis rule.
        logger_instance: Optional logger for progress messages.

    Returns:
        The path that was processed.

    Raises:
        ShineError: If the path is not an existing .svg file or the content
            is not valid SVG.
    """
    log = logger_instance or logger
    svg_path = Path(path)

    if svg_path.suffix.lower() != ".svg":
        raise ShineError(f"Shine requires an .svg file, got: {path}")
    if not svg_path.is_file():
        raise ShineError(f"SVG file not found: {path}")

    original = svg_path.read_text(encoding="utf-8")
    shined = apply_shine(original, font_family=font_family, shadow=shadow, hover=hover)

    if shined != original:
        svg_path.write_text(shined, encoding="utf-8")
        log.info(f"Shine applied: {path}")
    else:
        log.debug(f"Shine already applied, file unchanged: {path}")

    return str(svg_path)
