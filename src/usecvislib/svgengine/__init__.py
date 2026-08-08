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

"""SVG rendering engine package.

Phase 0 ships the shine pack: a post-processor that modernizes Graphviz SVG
output (fonts, drop shadows, hover affordances) without touching layout.

The full hand-painted SVG engine (canvas, layouts, painters, sv_* themes)
lands in Phase 1. Design: devnotes/SVG_ENGINE_DESIGN.md.
"""

from .shinepack import ShineError, apply_shine, apply_shine_file

__all__ = [
    "ShineError",
    "apply_shine",
    "apply_shine_file",
]
