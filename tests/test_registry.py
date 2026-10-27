#
# VULNEX -Universal Security Visualization Library-
#
# File: test_registry.py
# Author: Simon Roses Femerling
# Created: 2026-10-27
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
#

"""The module table stays in step with the classes, batch and the SVG engine."""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from usecvislib import registry, svgengine  # noqa: E402
from usecvislib.base import VisualizationBase  # noqa: E402
from usecvislib.batch import BatchProcessor  # noqa: E402


def test_modes_are_contiguous_and_unique():
    assert registry.modes() == list(range(len(registry.MODULES)))


@pytest.mark.parametrize("info", [m for m in registry.MODULES if m.target], ids=lambda m: m.key)
def test_targets_import(info):
    cls = info.load()
    assert cls.__name__ == info.class_name
    assert registry.by_key(info.key) is info and registry.by_mode(info.mode) is info


def test_batch_uses_the_table():
    assert list(BatchProcessor._get_modules()) == [m.key for m in registry.MODULES if m.key]


def test_every_painter_belongs_to_a_module():
    """A painter for a class the table does not know would be unreachable from the CLI."""
    painted = set(svgengine.supported_modules())
    assert painted == {m.class_name for m in registry.svg_modules()}


def test_file_modules_are_visualizations():
    for key, cls in registry.file_module_classes().items():
        if key != "binary":  # BinVis predates the base class
            assert issubclass(cls, VisualizationBase), key


def test_modes_without_class():
    with pytest.raises(LookupError):
        registry.by_mode(4).load()
