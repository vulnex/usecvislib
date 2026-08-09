#
# VULNEX -Universal Security Visualization Library-
#
# File: layout.py
# Author: Simon Roses Femerling
# Created: 2026-08-08
# Last Modified: 2026-08-08
# Version: 0.4.1
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Layout algorithms for the SVG engine (native layouts, no Graphviz).

- TidyTreeLayout: tree-structured scenes (Attack Trees, Vuln Tree)
- LinearLayout: ordered sequences (Kill Chain, Privilege Gradient)
- StackLayout: fixed ordered bands (MAESTRO layered view)
- AxisLayout: value-scaled axis with overlap lanes (Incident Timeline)

The Graphviz-JSON layout for general graphs lands in Phase 3 (task T3.1
in devnotes/SVG_ENGINE_DESIGN.md).

All layouts write center coordinates to ``node.x`` / ``node.y``.
"""

import logging
from itertools import pairwise
from typing import Optional

from .scene import Scene

logger = logging.getLogger(__name__)


class TidyTreeLayout:
    """Tidy tree layout with variable-width nodes.

    Subtree-extent variant of the classic tidy-tree family: each subtree
    occupies a contiguous horizontal extent (max of the node's own width
    and the sum of its children's extents), children are placed left to
    right inside it, and every parent is centered over its children.
    Guarantees no sibling overlap; iterative traversals, so arbitrarily
    deep trees cannot hit the recursion limit.

    Coordinates are written to ``node.x`` / ``node.y`` as centers.
    Orientation "TB" is top-down; "LR" is left-right (axes swapped).
    """

    def __init__(self, h_gap: float = 28.0, v_gap: float = 60.0, orientation: str = "TB") -> None:
        """Configure gaps (in SVG user units) and orientation ("TB" | "LR")."""
        self.h_gap = h_gap
        self.v_gap = v_gap
        self.orientation = "LR" if str(orientation).upper() == "LR" else "TB"

    def solve(self, scene: Scene, root_id: str) -> None:
        """Assign center coordinates to all scene nodes.

        Nodes unreachable from the root are placed in a row below the tree
        (the Graphviz engine also renders orphans rather than dropping them).
        """
        nodes = {n.id: n for n in scene.nodes}
        if root_id not in nodes:
            logger.warning(f"Layout root '{root_id}' not found in scene; skipping layout")
            return
        children = scene.children_map()

        # In LR orientation a node's "breadth" (cross-axis size) is its
        # height and its "depth" (main-axis size) is its width.
        def breadth(node_id: str) -> float:
            node = nodes[node_id]
            return node.height if self.orientation == "LR" else node.width

        def depth_size(node_id: str) -> float:
            node = nodes[node_id]
            return node.width if self.orientation == "LR" else node.height

        # Post-order subtree extents (iterative).
        extent: dict[str, float] = {}
        stack: list[tuple[str, bool]] = [(root_id, False)]
        reachable: set[str] = set()
        while stack:
            node_id, processed = stack.pop()
            if processed:
                kids = [k for k in children.get(node_id, []) if k in nodes]
                if kids:
                    kids_extent = sum(extent[k] for k in kids) + self.h_gap * (len(kids) - 1)
                    extent[node_id] = max(breadth(node_id), kids_extent)
                else:
                    extent[node_id] = breadth(node_id)
                continue
            if node_id in reachable or node_id not in nodes:
                continue
            reachable.add(node_id)
            stack.append((node_id, True))
            for kid in reversed(children.get(node_id, [])):
                if kid not in reachable and kid in nodes:
                    stack.append((kid, False))

        # Depth of each reachable node, then per-depth row size.
        depth: dict[str, int] = {root_id: 0}
        order: list[str] = [root_id]
        queue = [root_id]
        while queue:
            node_id = queue.pop(0)
            for kid in children.get(node_id, []):
                if kid in reachable and kid not in depth:
                    depth[kid] = depth[node_id] + 1
                    order.append(kid)
                    queue.append(kid)

        max_depth = max(depth.values())
        row_size = [0.0] * (max_depth + 1)
        for node_id, d in depth.items():
            row_size[d] = max(row_size[d], depth_size(node_id))
        # Rows are TOP-aligned (leading-edge aligned in LR): with mixed node
        # heights in a row, top alignment keeps every parent->child drop the
        # same length so arrowheads land on one line.
        row_start = []
        cursor = 0.0
        for d in range(max_depth + 1):
            row_start.append(cursor)
            cursor += row_size[d] + self.v_gap

        # Placement, two passes. Pre-order assigns each subtree's left edge
        # inside its parent extent; post-order then centers every parent
        # over its children's FINAL positions. (An internal child recenters
        # over its own kids, so its extent midpoint is not a valid
        # prediction of where it lands - predicting from extents kinks a
        # single-child chain the moment grandchild extents are asymmetric.)
        left: dict[str, float] = {root_id: 0.0}
        kids_of: dict[str, list[str]] = {}
        pre_stack: list[str] = [root_id]
        while pre_stack:
            node_id = pre_stack.pop()
            kids = [k for k in children.get(node_id, []) if k in reachable and depth.get(k) == depth[node_id] + 1]
            kids_of[node_id] = kids
            kids_extent = sum(extent[k] for k in kids) + self.h_gap * (len(kids) - 1)
            kid_left = left[node_id] + (extent[node_id] - kids_extent) / 2
            for kid in kids:
                left[kid] = kid_left
                kid_left += extent[kid] + self.h_gap
                pre_stack.append(kid)

        cross: dict[str, float] = {}
        post_stack: list[tuple[str, bool]] = [(root_id, False)]
        while post_stack:
            node_id, processed = post_stack.pop()
            kids = kids_of[node_id]
            if not kids:
                cross[node_id] = left[node_id] + extent[node_id] / 2
            elif processed:
                cross[node_id] = (cross[kids[0]] + cross[kids[-1]]) / 2
            else:
                post_stack.append((node_id, True))
                post_stack.extend((k, False) for k in kids)

        for node_id in order:
            node = nodes[node_id]
            if self.orientation == "LR":
                node.x = row_start[depth[node_id]] + node.width / 2
                node.y = cross[node_id]
            else:
                node.x = cross[node_id]
                node.y = row_start[depth[node_id]] + node.height / 2

        self._barycenter_multi_parent(scene, nodes, children, reachable, depth)

        # Orphans: a row below (TB) / right of (LR) the tree.
        orphans = [n for n in scene.nodes if n.id not in reachable]
        self._place_orphans(scene, orphans, root_id)

    # Weight of a single-parent (tree) node in the row solve: sticky against
    # displacement, but still movable when a sink needs to squeeze past.
    _FIXED_WEIGHT = 6.0

    def _barycenter_multi_parent(self, scene: Scene, nodes: dict, children: dict, reachable: set, depth: dict) -> None:
        """Center multi-parent nodes under ALL their parents (Graphviz-style).

        The tidy tree attaches a shared node under its first parent only, so
        a convergence sink (e.g. one impact node fed by nine techniques) ends
        up far to one side with a merge rail spanning the whole diagram.

        Per row (top-down, so deeper rows see corrected parents): every
        multi-parent node's desired position is the barycenter of its
        parents in the rows above; tree nodes want to stay put. The row is
        re-ordered by desired position (sinks may swap past each other -
        a one-pass clamp would pin the leftmost sink against a neighbor
        that itself is about to move away) and solved as an ordered
        min-displacement chain (weighted pool-adjacent-violators), so
        conflicting sinks split the difference instead of one being shoved
        to the margin. Nodes move together with their tree descendants.
        """
        is_lr = self.orientation == "LR"

        def get_cross(node) -> float:
            return node.y if is_lr else node.x

        def half_of(node) -> float:
            return (node.height if is_lr else node.width) / 2

        parents_of: dict[str, list[str]] = {}
        for edge in scene.edges:
            if edge.src in reachable and edge.dst in reachable and edge.src != edge.dst:
                parents = parents_of.setdefault(edge.dst, [])
                if edge.src not in parents:
                    parents.append(edge.src)

        rows: dict[int, list[str]] = {}
        for node_id, d in depth.items():
            rows.setdefault(d, []).append(node_id)

        for d in sorted(rows):
            desired: dict[str, float] = {}
            movers: set[str] = set()
            for node_id in rows[d]:
                # Barycenter over parents already placed in rows above;
                # same-row parents (lateral links) would skew it.
                upper = [p for p in parents_of.get(node_id, []) if depth.get(p, d) < d]
                if len(upper) >= 2:
                    desired[node_id] = sum(get_cross(nodes[p]) for p in upper) / len(upper)
                    movers.add(node_id)
                else:
                    desired[node_id] = get_cross(nodes[node_id])
            if not movers:
                continue

            # Order by desired position; ties keep current order (tree nodes
            # all desire their current spot, so their relative order holds).
            ordered = sorted(rows[d], key=lambda n: (desired[n], get_cross(nodes[n])))
            weights = [1.0 if n in movers else self._FIXED_WEIGHT for n in ordered]

            # Minimum-separation chain: offset[i] = required distance from
            # item 0; subtracting it turns the separation constraints into a
            # plain monotonicity constraint solved by weighted PAVA.
            offsets = [0.0]
            for prev, cur in pairwise(ordered):
                offsets.append(offsets[-1] + half_of(nodes[prev]) + self.h_gap + half_of(nodes[cur]))
            targets = [desired[n] - off for n, off in zip(ordered, offsets, strict=False)]

            # Weighted pool-adjacent-violators: merge blocks until monotone.
            blocks: list[tuple[float, float, int]] = []  # (value, weight, count)
            for value, weight in zip(targets, weights, strict=False):
                blocks.append((value, weight, 1))
                while len(blocks) > 1 and blocks[-2][0] >= blocks[-1][0]:
                    v2, w2, c2 = blocks.pop()
                    v1, w1, c1 = blocks.pop()
                    blocks.append(((v1 * w1 + v2 * w2) / (w1 + w2), w1 + w2, c1 + c2))

            solved: list[float] = []
            for value, _, count in blocks:
                solved.extend([value] * count)

            for node_id, base, off in zip(ordered, solved, offsets, strict=False):
                delta = (base + off) - get_cross(nodes[node_id])
                if abs(delta) < 1.0:
                    continue
                # Shift the node together with its tree descendants
                stack = [node_id]
                shifted: set[str] = set()
                while stack:
                    shift_id = stack.pop()
                    if shift_id in shifted:
                        continue
                    shifted.add(shift_id)
                    target = nodes[shift_id]
                    if is_lr:
                        target.y += delta
                    else:
                        target.x += delta
                    stack.extend(k for k in children.get(shift_id, []) if k in reachable)

    def _place_orphans(self, scene: Scene, orphans: list, root_id: str) -> None:
        """Place nodes unreachable from the root in a row past the tree."""
        if not orphans:
            return
        logger.warning(f"{len(orphans)} node(s) unreachable from root '{root_id}'; placed apart")
        placed = [n for n in scene.nodes if n not in orphans]
        if self.orientation == "LR":
            main = max((n.x + n.width / 2 for n in placed), default=0.0) + self.v_gap
        else:
            main = max((n.y + n.height / 2 for n in placed), default=0.0) + self.v_gap
        offset = 0.0
        for node in orphans:
            if self.orientation == "LR":
                node.x = main + node.width / 2
                node.y = offset + node.height / 2
                offset += node.height + self.h_gap
            else:
                node.x = offset + node.width / 2
                node.y = main + node.height / 2
                offset += node.width + self.h_gap


class LinearLayout:
    """Ordered sequence along one axis, centered on the other.

    Used for linear structures: kill chain phases, privilege ladders.
    Orientation "TB" flows top-down (sequence along y); "LR" flows
    left-right (sequence along x).
    """

    def __init__(self, gap: float = 48.0, orientation: str = "TB") -> None:
        """Configure the inter-node gap (SVG user units) and flow direction."""
        self.gap = gap
        self.orientation = "LR" if str(orientation).upper() == "LR" else "TB"

    def solve(self, scene: Scene, order: Optional[list[str]] = None) -> None:
        """Place nodes sequentially.

        Args:
            scene: Scene whose nodes are placed (centers written in place).
            order: Node IDs in sequence order; defaults to scene node order.
                IDs not present in the scene are skipped with a warning;
                scene nodes missing from ``order`` are appended at the end.
        """
        nodes = {n.id: n for n in scene.nodes}
        sequence = []
        for node_id in order or [n.id for n in scene.nodes]:
            if node_id in nodes:
                sequence.append(nodes[node_id])
            else:
                logger.warning(f"LinearLayout: unknown node '{node_id}' in order; skipped")
        placed = {n.id for n in sequence}
        sequence.extend(n for n in scene.nodes if n.id not in placed)

        cursor = 0.0
        for node in sequence:
            extent = node.height if self.orientation == "TB" else node.width
            if self.orientation == "TB":
                node.x = 0.0
                node.y = cursor + extent / 2
            else:
                node.x = cursor + extent / 2
                node.y = 0.0
            cursor += extent + self.gap


class StackLayout:
    """Fixed ordered bands with items placed in a row inside each band.

    Used for layered architectures (e.g. the MAESTRO 7-layer stack): each
    band occupies the full cross-axis extent of the widest band, items are
    centered as a group inside their band, and bands stack along the main
    axis. Orientation "TB" stacks bands top-down; "LR" stacks left-right.
    """

    def __init__(self, band_gap: float = 36.0, item_gap: float = 24.0, orientation: str = "TB") -> None:
        """Configure gaps between bands and between items within a band."""
        self.band_gap = band_gap
        self.item_gap = item_gap
        self.orientation = "LR" if str(orientation).upper() == "LR" else "TB"

    def solve(self, scene: Scene, bands: list[list[str]]) -> None:
        """Place nodes band by band.

        Args:
            scene: Scene whose nodes are placed (centers written in place).
            bands: Ordered list of bands, each an ordered list of node IDs.
                Unknown IDs are skipped with a warning; scene nodes not
                assigned to any band are appended as a final band.
        """
        nodes = {n.id: n for n in scene.nodes}
        resolved: list[list] = []
        assigned: set[str] = set()
        for band in bands:
            row = []
            for node_id in band:
                if node_id in nodes:
                    row.append(nodes[node_id])
                    assigned.add(node_id)
                else:
                    logger.warning(f"StackLayout: unknown node '{node_id}' in band; skipped")
            resolved.append(row)
        leftover = [n for n in scene.nodes if n.id not in assigned]
        if leftover:
            logger.warning(f"StackLayout: {len(leftover)} node(s) not assigned to a band; appended as final band")
            resolved.append(leftover)

        def cross_size(node) -> float:
            return node.width if self.orientation == "TB" else node.height

        def main_size(node) -> float:
            return node.height if self.orientation == "TB" else node.width

        main_cursor = 0.0
        for row in resolved:
            if not row:
                continue
            band_main = max(main_size(n) for n in row)
            row_cross = sum(cross_size(n) for n in row) + self.item_gap * (len(row) - 1)
            cross_cursor = -row_cross / 2  # bands centered on the cross axis
            for node in row:
                if self.orientation == "TB":
                    node.x = cross_cursor + node.width / 2
                    node.y = main_cursor + band_main / 2
                else:
                    node.x = main_cursor + band_main / 2
                    node.y = cross_cursor + node.height / 2
                cross_cursor += cross_size(node) + self.item_gap
            main_cursor += band_main + self.band_gap


class AxisLayout:
    """Value-scaled placement along an axis with overlap-avoiding lanes.

    Used for timelines: each node has a scalar value (e.g. a timestamp),
    mapped linearly onto the axis. Nodes that would overlap on the axis
    are pushed into additional lanes (greedy first-fit, stable for equal
    values). Orientation "LR" runs the axis along x (lanes stack down);
    "TB" runs it along y (lanes stack right).
    """

    def __init__(self, axis_length: float = 800.0, lane_gap: float = 24.0, orientation: str = "LR") -> None:
        """Configure the axis span (SVG user units) and gap between lanes."""
        self.axis_length = axis_length
        self.lane_gap = lane_gap
        self.orientation = "TB" if str(orientation).upper() == "TB" else "LR"

    def solve(self, scene: Scene, values: dict[str, float]) -> None:
        """Place nodes along the value axis.

        Args:
            scene: Scene whose nodes are placed (centers written in place).
            values: Node ID -> scalar axis value. Nodes without a value are
                placed at the axis start with a warning.
        """
        if not scene.nodes:
            return

        known = [values[n.id] for n in scene.nodes if n.id in values]
        for node in scene.nodes:
            if node.id not in values:
                logger.warning(f"AxisLayout: node '{node.id}' has no axis value; placed at axis start")
        lo = min(known) if known else 0.0
        hi = max(known) if known else 0.0
        span = hi - lo

        def axis_pos(node) -> float:
            value = values.get(node.id, lo)
            return ((value - lo) / span * self.axis_length) if span > 0 else 0.0

        def axis_size(node) -> float:
            return node.width if self.orientation == "LR" else node.height

        def lane_size(node) -> float:
            return node.height if self.orientation == "LR" else node.width

        # Greedy first-fit lanes: stable sort by value keeps input order
        # for ties, so equal-value nodes stack deterministically.
        ordered = sorted(scene.nodes, key=lambda n: axis_pos(n))
        lane_ends: list[float] = []  # axis coordinate where each lane is free again
        lane_of: dict[str, int] = {}
        for node in ordered:
            start = axis_pos(node) - axis_size(node) / 2
            end = axis_pos(node) + axis_size(node) / 2
            for lane, free_at in enumerate(lane_ends):
                if start >= free_at:
                    lane_of[node.id] = lane
                    lane_ends[lane] = end + self.lane_gap
                    break
            else:
                lane_of[node.id] = len(lane_ends)
                lane_ends.append(end + self.lane_gap)

        lane_extent = [0.0] * len(lane_ends)
        for node in ordered:
            lane = lane_of[node.id]
            lane_extent[lane] = max(lane_extent[lane], lane_size(node))
        lane_centers = []
        cursor = 0.0
        for extent in lane_extent:
            lane_centers.append(cursor + extent / 2)
            cursor += extent + self.lane_gap

        for node in ordered:
            if self.orientation == "LR":
                node.x = axis_pos(node)
                node.y = lane_centers[lane_of[node.id]]
            else:
                node.x = lane_centers[lane_of[node.id]]
                node.y = axis_pos(node)
