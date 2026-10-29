#
# VULNEX -Universal Security Visualization Library-
#
# File: test_grouping.py
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
#

"""Shared grouping and collapse pieces (attack graph and privilege gradient)."""

import pytest

from usecvislib import attackgraph_view
from usecvislib.drift import ElementMark, GroupInfo
from usecvislib.grouping import (
    DEFAULT_MAX_NODES,
    SUMMARY_PREFIX,
    auto_collapse,
    collapse_requested,
    combined_status,
    groups_to_collapse,
    merged_label,
)


def _groups(**sizes):
    return {gid: GroupInfo(id=gid, members=[f"{gid}{i}" for i in range(n)]) for gid, n in sizes.items()}


@pytest.mark.parametrize(
    ("value", "expected"),
    [(None, False), (False, False), ("none", False), (" No ", False), ("", False),
     (True, True), ("all", True), ("auto", True), ("a,b", True), (["a"], True)],
)  # fmt: skip
def test_collapse_requested(value, expected):
    assert collapse_requested(value) is expected


class TestGroupsToCollapse:
    def test_all_skips_one_member_groups(self):
        assert groups_to_collapse(_groups(a=3, b=1, c=2), {}, True, 300, 6) == ["a", "c"]
        assert groups_to_collapse(_groups(a=3, b=1), {}, "all", 300, 4) == ["a"]

    def test_list_keeps_group_order_and_warns_on_unknown(self, caplog):
        assert groups_to_collapse(_groups(a=2, b=2, c=2), {}, "c, a, zz", 300, 6) == ["a", "c"]
        assert "zz" in caplog.text

    def test_explicit_setting_wins(self):
        meta = {"a": {"collapsed": False}, "b": {"collapsed": True}, "other": {"collapsed": True}}
        assert groups_to_collapse(_groups(a=3, b=1), meta, True, 300, 4) == ["b"]

    def test_none(self):
        assert groups_to_collapse(_groups(a=3), {}, None, 300, 3) == []


class TestAutoCollapse:
    def test_largest_first_until_the_target(self):
        # 100 nodes drawn: collapsing a (60 -> 1) reaches 41 <= 50
        assert auto_collapse(_groups(a=60, b=30, c=5), {}, 50, 100) == {"a"}

    def test_ties_break_by_id(self):
        assert auto_collapse(_groups(b=10, a=10), {}, 12, 20) == {"a"}

    def test_explicit_groups_are_counted_not_chosen(self):
        # b is always collapsed (10 -> 1): 21 drawn, so a must collapse too
        assert auto_collapse(_groups(a=10, b=10), {"b": True}, 12, 30) == {"a"}

    def test_warns_when_the_target_is_out_of_reach(self, caplog):
        assert auto_collapse(_groups(a=3), {}, 5, 100) == {"a"}
        assert "98 nodes remain" in caplog.text

    def test_through_groups_to_collapse(self):
        assert groups_to_collapse(_groups(a=60, b=30), {}, "auto", 50, 100) == ["a"]


@pytest.mark.parametrize(
    ("statuses", "expected"),
    [([], None), ([None, None], None), (["added", "added"], "added"), (["added", None], "added"),
     (["added", "removed"], "unchanged"), (["modified", "unchanged"], "unchanged")],
)  # fmt: skip
def test_combined_status(statuses, expected):
    assert combined_status(statuses) == expected


def test_merged_label():
    assert merged_label(ElementMark(count=3), "x") == "\u00d73"
    assert merged_label(ElementMark(), "x") == "x" and merged_label(None) is None


def test_attackgraph_view_reexports():
    assert attackgraph_view.SUMMARY_PREFIX == SUMMARY_PREFIX == "__group_"
    assert attackgraph_view.DEFAULT_MAX_NODES == DEFAULT_MAX_NODES == 300
    assert attackgraph_view.merged_label is merged_label
