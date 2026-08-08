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

"""Painters: one module per visualization type.

A painter translates a visualization instance's ``inputdata`` + theme into
an SVG document, using the shared scene/layout/shapes/canvas toolkit. The
contract is a single function::

    def render_svg(viz) -> str

where ``viz`` is the module instance (loaded, with ``inputdata`` and
``style`` populated) and the return value is the complete SVG text.
"""
