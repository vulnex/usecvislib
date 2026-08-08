#
# VULNEX -Universal Security Visualization Library-
#
# File: canvas.py
# Author: Simon Roses Femerling
# Created: 2026-08-08
# Last Modified: 2026-08-08
# Version: 0.4.1
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""SVG document builder for the SVG engine.

Pure-stdlib (ElementTree) construction with deterministic output: fixed
attribute insertion order, fixed float precision, content-hash-deduplicated
defs with sequential IDs, no timestamps or random IDs. Same scene + theme
produces byte-identical SVG — the property golden-file tests rely on.

Draw order is enforced through named layers: groups, edges, nodes, badges,
labels (labels always on top). The embedded <style> block is presentation
only; the engine never emits scripts, foreignObject, event-handler
attributes, or external references.
"""

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional

XML_DECLARATION = '<?xml version="1.0" encoding="UTF-8" standalone="no"?>\n'
SVG_XMLNS = "http://www.w3.org/2000/svg"

LAYERS = ("groups", "edges", "nodes", "badges", "labels")


def fmt(value: float) -> str:
    """Format a coordinate with fixed 2-decimal precision, trimmed."""
    text = f"{value:.2f}"
    return text.rstrip("0").rstrip(".") if "." in text else text


class SvgCanvas:
    """Deterministic SVG document builder."""

    def __init__(self, module: str, theme_id: str) -> None:
        """Initialize a canvas for one document.

        Args:
            module: Module slug for classes/data attrs (e.g. "attacktrees").
            theme_id: Style preset ID recorded on the root element.
        """
        self.module = module
        self.theme_id = theme_id
        self._defs: list[ET.Element] = []
        self._def_index: dict[tuple, str] = {}
        self._layers: dict[str, list[ET.Element]] = {layer: [] for layer in LAYERS}
        self._css = ""
        self._viewbox: Optional[tuple[float, float, float, float]] = None

    def add(self, layer: str, element: ET.Element) -> None:
        """Append an element to a named layer."""
        self._layers[layer].append(element)

    def set_css(self, css: str) -> None:
        """Set the embedded presentation-only CSS block."""
        self._css = css

    def finalize(self, min_x: float, min_y: float, width: float, height: float) -> None:
        """Set the document viewBox (and width/height for rasterizers)."""
        self._viewbox = (min_x, min_y, width, height)

    def _def_id(self, key: tuple, prefix: str) -> tuple[str, bool]:
        """Return (id, created) for a def keyed by content."""
        existing = self._def_index.get(key)
        if existing is not None:
            return existing, False
        def_id = f"usv-{prefix}-{len(self._def_index)}"
        self._def_index[key] = def_id
        return def_id, True

    def gradient(self, color_from: str, color_to: str) -> str:
        """Register a vertical linear gradient def; returns a url() reference."""
        def_id, created = self._def_id(("lg", color_from, color_to), "grad")
        if created:
            grad = ET.Element(
                "linearGradient",
                {"id": def_id, "x1": "0", "y1": "0", "x2": "0", "y2": "1"},
            )
            ET.SubElement(grad, "stop", {"offset": "0", "stop-color": color_from})
            ET.SubElement(grad, "stop", {"offset": "1", "stop-color": color_to})
            self._defs.append(grad)
        return f"url(#{def_id})"

    def shadow(self, blur: float = 1.8, dy: float = 1.5, opacity: float = 0.35) -> str:
        """Register a drop-shadow filter def; returns a url() reference."""
        def_id, created = self._def_id(("shadow", fmt(blur), fmt(dy), fmt(opacity)), "shadow")
        if created:
            filt = ET.Element(
                "filter",
                {"id": def_id, "x": "-20%", "y": "-20%", "width": "140%", "height": "140%"},
            )
            ET.SubElement(
                filt,
                "feDropShadow",
                {
                    "dx": "0",
                    "dy": fmt(dy),
                    "stdDeviation": fmt(blur),
                    "flood-color": "#0f172a",
                    "flood-opacity": fmt(opacity),
                },
            )
            self._defs.append(filt)
        return f"url(#{def_id})"

    def arrow_marker(self, color: str) -> str:
        """Register an arrowhead marker def for a color; returns a url() reference."""
        def_id, created = self._def_id(("arrow", color), "arrow")
        if created:
            marker = ET.Element(
                "marker",
                {
                    "id": def_id,
                    "viewBox": "0 0 10 10",
                    "refX": "9",
                    "refY": "5",
                    "markerWidth": "7",
                    "markerHeight": "7",
                    "orient": "auto-start-reverse",
                },
            )
            ET.SubElement(marker, "path", {"d": "M 0 1 L 9 5 L 0 9 z", "fill": color})
            self._defs.append(marker)
        return f"url(#{def_id})"

    def to_string(self) -> str:
        """Serialize the document to SVG text (with XML declaration)."""
        if self._viewbox is None:
            raise ValueError("Canvas not finalized: call finalize() before serializing")
        min_x, min_y, width, height = self._viewbox

        root = ET.Element(
            "svg",
            {
                "xmlns": SVG_XMLNS,
                "width": fmt(width),
                "height": fmt(height),
                "viewBox": f"{fmt(min_x)} {fmt(min_y)} {fmt(width)} {fmt(height)}",
                "preserveAspectRatio": "xMidYMid meet",
                "class": f"usv-svg usv-{self.module}",
                "data-usv-engine": "svg",
                "data-usv-module": self.module,
                "data-usv-theme": self.theme_id,
            },
        )

        if self._defs:
            defs = ET.SubElement(root, "defs")
            defs.extend(self._defs)

        if self._css:
            style = ET.SubElement(root, "style", {"type": "text/css"})
            style.text = "\n" + self._css + "\n"

        for layer in LAYERS:
            root.extend(self._layers[layer])

        return XML_DECLARATION + ET.tostring(root, encoding="unicode")

    def save(self, path: str) -> str:
        """Write the document to a file; returns the path."""
        Path(path).write_text(self.to_string(), encoding="utf-8")
        return path
