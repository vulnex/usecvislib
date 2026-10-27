#
# VULNEX -Universal Security Visualization Library-
#
# File: test_matplotlib_lock.py
# Author: Simon Roses Femerling
# Created: 2026-10-27
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
#

"""Matplotlib drawing waits for utils.MATPLOTLIB_LOCK (pyplot state is global)."""

import os
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from usecvislib import utils  # noqa: E402
from usecvislib.binvis import BinVis  # noqa: E402
from usecvislib.maestro import MaestroThreatModel  # noqa: E402
from usecvislib.timeline import IncidentTimeline  # noqa: E402
from usecvislib.trend import TrendChart  # noqa: E402

TEMPLATES = Path(__file__).parent.parent / "templates"


def _binary(tmp_path):
    data = tmp_path / "blob.bin"
    data.write_bytes(bytes(range(256)) * 64)
    viz = BinVis(str(data), str(tmp_path / "bv"), format="png")
    return lambda: viz.visualize_distribution()


def _graph_module(cls, template, **kwargs):
    def make(tmp_path):
        viz = cls(str(TEMPLATES / template), str(tmp_path / "out"), format="png", **kwargs)
        return viz.build

    return make


CASES = {
    "binvis": _binary,
    "timeline": _graph_module(IncidentTimeline, "timelines/phishing_compromise.tml"),
    "trend": _graph_module(TrendChart, "trends/engagement_metrics.toml"),
    "maestro_heatmap": _graph_module(MaestroThreatModel, "maestro/single-agent-rag.toml", view="heatmap"),
}


@pytest.mark.parametrize("kind", list(CASES))
def test_drawing_waits_for_the_lock(kind, tmp_path):
    draw = CASES[kind](tmp_path)
    done = threading.Event()
    errors = []

    def run():
        try:
            draw()
        except Exception as e:  # surfaced below
            errors.append(e)
        finally:
            done.set()

    with utils.MATPLOTLIB_LOCK:
        worker = threading.Thread(target=run)
        worker.start()
        assert not done.wait(0.5), "drew while another thread held MATPLOTLIB_LOCK"
    assert done.wait(30)
    worker.join()
    assert not errors, errors
