#
# VULNEX -Universal Security Visualization Library-
#
# File: __init__.py
# Author: Simon Roses Femerling
# Created: 2026-08-08
# Last Modified: 2026-08-08
# Version: 0.4.1
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""SVG rendering engine: modern hand-painted SVG as a second engine.

Selectable via ``render_engine="svg"`` on supported modules (Graphviz
remains the default engine). The package also ships the Phase 0 shine
pack, a post-processor for Graphviz SVG output.

Design and task tracker: devnotes/SVG_ENGINE_DESIGN.md.
"""

import importlib
from pathlib import Path

from .scene import EngineNotSupportedError, StyleEngineMismatchError
from .shinepack import ShineError, apply_shine, apply_shine_file

__all__ = [
    "EngineNotSupportedError",
    "ShineError",
    "StyleEngineMismatchError",
    "apply_shine",
    "apply_shine_file",
    "is_supported",
    "paint",
    "register_painter",
    "supported_modules",
]

# Visualization class name -> painter module path
_PAINTERS: dict[str, str] = {
    "AttackTrees": "usecvislib.svgengine.painters.attacktrees",
    "KillChain": "usecvislib.svgengine.painters.killchain",
    "VulnDependencyTree": "usecvislib.svgengine.painters.vulntree",
    "IncidentTimeline": "usecvislib.svgengine.painters.timeline",
}


def register_painter(class_name: str, module_path: str) -> None:
    """Register a painter module for a visualization class name.

    The module must expose ``render_svg(viz) -> str``.
    """
    _PAINTERS[class_name] = module_path


def supported_modules() -> list[str]:
    """Visualization class names the SVG engine can paint."""
    return sorted(_PAINTERS)


def is_supported(class_name: str) -> bool:
    """Check whether a visualization class has a registered painter."""
    return class_name in _PAINTERS


def paint(viz, outputfile: str) -> str:
    """Paint a visualization instance with the SVG engine.

    Writes ``<outputfile>.<format>``: SVG natively, PNG/PDF via cairosvg
    conversion of the same bytes.

    Args:
        viz: A loaded visualization instance (``render_engine="svg"``).
        outputfile: Output path without extension.

    Returns:
        The written file path.

    Raises:
        EngineNotSupportedError: If the module has no painter or the
            format is Graphviz-specific ("dot") / unknown.
    """
    class_name = type(viz).__name__
    if not is_supported(class_name):
        raise EngineNotSupportedError(
            f"render_engine='svg' does not support {class_name} yet. Supported: {', '.join(supported_modules())}"
        )
    if viz.format not in ("svg", "png", "pdf"):
        raise EngineNotSupportedError(
            f"Format '{viz.format}' is not supported by render_engine='svg'. Use svg, png, or pdf."
        )

    painter = importlib.import_module(_PAINTERS[class_name])
    svg_text = painter.render_svg(viz)

    out_path = Path(f"{outputfile}.{viz.format}")
    if viz.format == "svg":
        out_path.write_text(svg_text, encoding="utf-8")
    else:
        try:
            import cairosvg
        except ImportError as e:
            raise EngineNotSupportedError(
                f"'{viz.format}' output with render_engine='svg' requires cairosvg "
                f"(pip install cairosvg). SVG output works without it."
            ) from e

        if viz.format == "png":
            # 2x raster for crisp display on high-DPI screens
            cairosvg.svg2png(bytestring=svg_text.encode("utf-8"), write_to=str(out_path), scale=2.0)
        else:
            cairosvg.svg2pdf(bytestring=svg_text.encode("utf-8"), write_to=str(out_path))
    return str(out_path)
