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

import json
import logging
from itertools import pairwise
from typing import Optional

from .scene import EngineNotSupportedError, Scene

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
        children, depth, order = self._tree_from_dag(scene, root_id, nodes)

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

        # Per-depth row size.
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
        if self._spread_middle_children(nodes, kids_of, depth, root_id):
            # shared children follow their (moved) parents
            self._barycenter_multi_parent(scene, nodes, children, reachable, depth)

        # Orphans: a row below (TB) / right of (LR) the tree.
        orphans = [n for n in scene.nodes if n.id not in reachable]
        self._place_orphans(scene, orphans, root_id)

    def _spread_middle_children(self, nodes: dict, kids_of: dict, depth: dict, root_id: str) -> bool:
        """Even out middle siblings between the outer ones, where room allows.

        Placement packs subtrees left to right by their extents, and a
        shared (multi-parent) subtree inflates the extent of the branch it
        was first attached to; after the barycenter pass moves it away, a
        middle sibling is left hugging its right neighbour while the parent
        centers over the outer two ("Exploit Vulnerability" sat right of
        "Initial Access"). Each middle child's subtree slides toward an even
        spacing, stopping short of any card in the rows it occupies.
        """
        horizontal = self.orientation == "LR"
        moved = False

        def c(n) -> float:
            return n.y if horizontal else n.x

        def half(n) -> float:
            return (n.height if horizontal else n.width) / 2

        def subtree(node_id: str) -> set[str]:
            seen, stack = set(), [node_id]
            while stack:
                cur = stack.pop()
                if cur in seen:
                    continue
                seen.add(cur)
                stack.extend(kids_of.get(cur, []))
            return seen

        order, stack = [], [root_id]  # top-down so parents settle first
        while stack:
            cur = stack.pop()
            order.append(cur)
            stack.extend(reversed(kids_of.get(cur, [])))

        rows: dict[int, list[str]] = {}
        for node_id, d in depth.items():
            if node_id in nodes:
                rows.setdefault(d, []).append(node_id)

        for parent_id in order:
            kids = kids_of.get(parent_id, [])
            if len(kids) < 3:
                continue
            first, last = c(nodes[kids[0]]), c(nodes[kids[-1]])
            step = (last - first) / (len(kids) - 1)
            for i, kid in enumerate(kids[1:-1], start=1):
                want = first + i * step - c(nodes[kid])
                if abs(want) < 0.5:
                    continue
                moving = subtree(kid)
                room = abs(want)
                for node_id in moving:
                    n = nodes[node_id]
                    for other_id in rows.get(depth.get(node_id, -1), []):
                        if other_id in moving:
                            continue
                        m = nodes[other_id]
                        gap = (c(m) - c(n)) if want > 0 else (c(n) - c(m))
                        if gap > 0:  # m lies in the direction of travel
                            room = min(room, gap - half(n) - half(m) - self.h_gap)
                if room <= 0.5:
                    continue
                delta = room if want > 0 else -room
                for node_id in moving:
                    n = nodes[node_id]
                    if horizontal:
                        n.y += delta
                    else:
                        n.x += delta
                moved = True
        return moved

    @staticmethod
    def _tree_from_dag(scene: Scene, root_id: str, nodes: dict) -> tuple[dict, dict, list]:
        """Spanning tree, row depths and BFS order for a DAG rooted at ``root_id``.

        A node's row is its LONGEST path from the root (as Graphviz ranks
        it), and its tree parent is a parent on the row directly above. With
        first-parent attachment and shortest depth, a node fed from two
        depths landed on the same row as its deeper parent, so that edge ran
        sideways and looped back into it. Cycles (invalid for a tree, but
        tolerated) fall back to the first parent.

        Returns:
            (children, depth, order): tree parent -> children in edge order,
            node -> row index, and breadth-first order over the tree.
        """
        parents_of: dict[str, list[str]] = {}
        kids_all: dict[str, list[str]] = {}
        for edge in scene.edges:
            src, dst = edge.src, edge.dst
            if src == dst or src not in nodes or dst not in nodes or dst == root_id:
                continue
            if src not in parents_of.setdefault(dst, []):
                parents_of[dst].append(src)
                kids_all.setdefault(src, []).append(dst)

        reachable = {root_id}
        queue = [root_id]
        while queue:
            for kid in kids_all.get(queue.pop(0), []):
                if kid not in reachable:
                    reachable.add(kid)
                    queue.append(kid)

        # Longest-path depth via Kahn's algorithm over the reachable subgraph.
        indegree = {n: sum(1 for p in parents_of.get(n, []) if p in reachable) for n in reachable}
        longest = dict.fromkeys(reachable, 0)
        ready = [n for n in reachable if indegree[n] == 0]
        while ready:
            node_id = ready.pop()
            for kid in kids_all.get(node_id, []):
                longest[kid] = max(longest[kid], longest[node_id] + 1)
                indegree[kid] -= 1
                if indegree[kid] == 0:
                    ready.append(kid)

        tree_parent: dict[str, str] = {}
        for node_id in reachable - {root_id}:
            parents = [p for p in parents_of.get(node_id, []) if p in reachable]
            above = [p for p in parents if longest[p] == longest[node_id] - 1]
            tree_parent[node_id] = (above or parents)[0]

        children: dict[str, list[str]] = {}
        for edge in scene.edges:  # edge order keeps sibling order stable
            if tree_parent.get(edge.dst) == edge.src and edge.dst not in children.get(edge.src, []):
                children.setdefault(edge.src, []).append(edge.dst)

        # Final rows follow the tree (equal to the longest path on a DAG).
        depth = {root_id: 0}
        order = [root_id]
        queue = [root_id]
        while queue:
            node_id = queue.pop(0)
            for kid in children.get(node_id, []):
                if kid not in depth:
                    depth[kid] = depth[node_id] + 1
                    order.append(kid)
                    queue.append(kid)
        return children, depth, order

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


def _dot_escape(text: str) -> str:
    """Escape a string for use inside a double-quoted DOT identifier."""
    return str(text).replace("\\", "\\\\").replace('"', '\\"')


class GraphvizJsonLayout:
    """General-graph layout that uses Graphviz purely as a coordinate oracle.

    Unlike the native layouts above, arbitrary directed graphs (attack
    graphs, dependency graphs, DFDs) have no cheap closed-form placement.
    This layout builds a minimal DOT document from the scene — node IDs, our
    own text-metric sizes, and the edge list — runs it through
    ``graphviz.pipe(engine, "json0", ...)``, and reads back node centers and
    edge B-spline control points. Graphviz computes geometry; it never paints.

    Sizes are fed to Graphviz in inches as ``pixels / 72`` with
    ``fixedsize=true``, so one returned point maps 1:1 to one engine pixel.
    Coordinates are converted from Graphviz's bottom-left origin to the
    engine's top-left convention (Y flipped about the graph height) and
    written to ``node.x`` / ``node.y`` (centers) and ``edge.points``.

    Requires the system Graphviz ``dot`` binary; general graphs have no
    native fallback yet, so an unavailable binary raises
    ``EngineNotSupportedError`` (the networkx spring fallback is deferred).
    """

    _PT_PER_INCH = 72.0

    def __init__(
        self,
        rankdir: str = "LR",
        nodesep: float = 0.35,
        ranksep: float = 0.55,
        splines: str = "spline",
        engine: str = "dot",
    ) -> None:
        """Configure the layout direction and Graphviz spacing/engine."""
        self.rankdir = rankdir if str(rankdir).upper() in ("LR", "TB", "RL", "BT") else "LR"
        self.nodesep = nodesep
        self.ranksep = ranksep
        self.splines = splines
        self.engine = engine

    def solve(self, scene: Scene) -> None:
        """Place all scene nodes and route all edges via Graphviz."""
        if not scene.nodes:
            return
        data = self._run(self._build_dot(scene))
        self._apply(scene, data)

    def _build_dot(self, scene: Scene) -> str:
        """Serialize the scene to a minimal DOT document for layout only.

        Groups with members are emitted as ``cluster_*`` subgraphs so Graphviz
        reserves space for them and keeps their members contiguous; the reserved
        cluster bounding boxes are read back in :meth:`_apply`.
        """
        lines = [
            "digraph G {",
            f'  graph [rankdir="{self.rankdir}", nodesep="{self.nodesep}", '
            f'ranksep="{self.ranksep}", splines="{self.splines}"];',
            "  node [shape=box, fixedsize=true];",
        ]

        # A node belongs to the innermost group listing it; groups may nest
        # via `parent`, emitted as nested cluster subgraphs.
        group_ids = {g.id for g in scene.groups}
        depth: dict[str, int] = {}

        def group_depth(group) -> int:
            if group.id not in depth:
                parent = next((g for g in scene.groups if g.id == group.parent), None)
                depth[group.id] = 0 if parent is None or group.parent not in group_ids else group_depth(parent) + 1
            return depth[group.id]

        member_of: dict[str, str] = {}
        for group in sorted(scene.groups, key=group_depth):
            for member in group.members:
                member_of[member] = group.id  # deeper groups override

        children_of: dict[Optional[str], list] = {}
        for group in scene.groups:
            parent = group.parent if group.parent in group_ids else None
            children_of.setdefault(parent, []).append(group)

        def has_content(group) -> bool:
            return any(member_of.get(n.id) == group.id for n in scene.nodes) or any(
                has_content(child) for child in children_of.get(group.id, [])
            )

        def emit(group, indent: str) -> None:
            if not has_content(group):
                return
            lines.append(f'{indent}subgraph "cluster_{_dot_escape(group.id)}" {{')
            if group.label:
                lines.append(f'{indent}  label="{_dot_escape(group.label)}";')
            for child in children_of.get(group.id, []):
                emit(child, indent + "  ")
            for node in scene.nodes:
                if member_of.get(node.id) == group.id:
                    lines.append(f"{indent}{self._node_line(node)}")
            lines.append(f"{indent}}}")

        for group in children_of.get(None, []):
            emit(group, "  ")

        for node in scene.nodes:
            if node.id not in member_of:
                lines.append(self._node_line(node))
        for edge in scene.edges:
            lines.append(f'  "{_dot_escape(edge.src)}" -> "{_dot_escape(edge.dst)}"{self._edge_attrs(edge)};')
        lines.append("}")
        return "\n".join(lines)

    @staticmethod
    def _edge_attrs(edge) -> str:
        """Reserve the edge label's painted size so Graphviz routes around it.

        The label is a fixed-size empty HTML table cell rather than text, so
        the reserved box is exactly our own text-metric size and independent
        of whichever fonts the Graphviz host has installed. The chosen label
        center comes back as the edge's ``lp``.
        """
        attrs = []
        if getattr(edge, "layout_only", False):
            # Ordering constraint only (e.g. zone anchors left to right)
            attrs.append("style=invis")
        if getattr(edge, "weight", None) is not None:
            attrs.append(f"weight={int(edge.weight)}")
        if edge.label and edge.label_width > 0 and edge.label_height > 0:
            w = max(1, round(edge.label_width))
            h = max(1, round(edge.label_height))
            attrs.append(
                'label=<<TABLE BORDER="0" CELLBORDER="0" CELLPADDING="0" CELLSPACING="0">'
                f'<TR><TD WIDTH="{w}" HEIGHT="{h}" FIXEDSIZE="TRUE"></TD></TR></TABLE>>'
            )
        return f" [{', '.join(attrs)}]" if attrs else ""

    def _node_line(self, node) -> str:
        """DOT declaration for one node, sized in inches (px / 72)."""
        w_in = max(node.width, 1.0) / self._PT_PER_INCH
        h_in = max(node.height, 1.0) / self._PT_PER_INCH
        return f'  "{_dot_escape(node.id)}" [width={w_in:.4f}, height={h_in:.4f}, label=""];'

    def _run(self, dot: str) -> dict:
        """Pipe the DOT document through Graphviz and parse the JSON result."""
        try:
            import graphviz
        except ImportError as exc:  # pragma: no cover - graphviz is a hard dep
            raise EngineNotSupportedError(
                "General-graph SVG layout requires the 'graphviz' package and the 'dot' binary."
            ) from exc
        try:
            raw = graphviz.pipe(self.engine, "json0", dot.encode("utf-8"))
        except Exception as exc:
            raise EngineNotSupportedError(
                "General-graph SVG layout requires the Graphviz 'dot' binary; it could not be run. "
                "Install Graphviz or use render_engine='graphviz'."
            ) from exc
        return json.loads(raw.decode("utf-8"))

    def _apply(self, scene: Scene, data: dict) -> None:
        """Write oracle positions/splines back onto the scene (Y-flipped)."""
        height = self._bb_height(data.get("bb", ""))

        by_id = {n.id: n for n in scene.nodes}
        group_by_id = {g.id: g for g in scene.groups}
        gvid_to_id: dict[int, str] = {}
        for obj in data.get("objects", []):
            name = obj.get("name")
            if name is not None and "_gvid" in obj:
                gvid_to_id[obj["_gvid"]] = name

            # Cluster subgraphs carry a bbox (no pos); map it back to the group.
            if isinstance(name, str) and name.startswith("cluster_"):
                group = group_by_id.get(name[len("cluster_") :])
                if group is not None:
                    self._apply_cluster_bbox(group, obj.get("bb", ""), height)
                continue

            node = by_id.get(name)
            pos = obj.get("pos")
            if node is None or not pos:
                continue
            x_str, y_str = pos.split(",")
            node.x = float(x_str)
            node.y = height - float(y_str)

        # Match json edges back to scene edges by (tail, head); a repeated
        # pair (parallel edges) consumes successive scene edges in order.
        buckets: dict[tuple[str, str], list] = {}
        for edge in scene.edges:
            buckets.setdefault((edge.src, edge.dst), []).append(edge)
        used: dict[tuple[str, str], int] = {}
        for gv_edge in data.get("edges", []):
            tail = gvid_to_id.get(gv_edge.get("tail"))
            head = gvid_to_id.get(gv_edge.get("head"))
            if tail is None or head is None:
                continue
            bucket = buckets.get((tail, head))
            if not bucket:
                continue
            idx = used.get((tail, head), 0)
            if idx >= len(bucket):
                continue
            bucket[idx].points = self._parse_spline(gv_edge.get("pos", ""), height)
            lp = gv_edge.get("lp")
            if lp:
                x_str, y_str = lp.split(",")
                bucket[idx].label_pos = (float(x_str), height - float(y_str))
            used[(tail, head)] = idx + 1

    @staticmethod
    def _apply_cluster_bbox(group, bb: str, height: float) -> None:
        """Write a Graphviz cluster ``bb`` onto a group as a top-left rect.

        Graphviz ``bb`` is ``x0,y0,x1,y1`` (lower-left / upper-right, bottom-left
        origin). Convert to the engine's top-left origin by flipping about the
        graph height: the box top is ``height - y1``.
        """
        parts = bb.split(",") if bb else []
        if len(parts) != 4:
            return
        try:
            x0, y0, x1, y1 = (float(p) for p in parts)
        except ValueError:
            return
        group.x = x0
        group.y = height - y1
        group.width = x1 - x0
        group.height = y1 - y0

    @staticmethod
    def _bb_height(bb: str) -> float:
        """Graph bounding-box height (upper-right Y) for the Y-axis flip."""
        parts = bb.split(",") if bb else []
        if len(parts) == 4:
            try:
                return float(parts[3])
            except ValueError:
                return 0.0
        return 0.0

    @staticmethod
    def _parse_spline(pos: str, height: float) -> list[tuple[float, float]]:
        """Parse a Graphviz edge ``pos`` spline into flipped control points.

        Format: optional ``s,x,y`` (arrow-tail tip) and ``e,x,y`` (arrow-head
        tip) tokens plus the B-spline points. We keep the spline points in
        order and append the head tip last so the stroke reaches the
        arrowhead; the tail tip is unused (our edges carry head arrows only).
        """
        if not pos:
            return []
        end_tip: Optional[tuple[float, float]] = None
        points: list[tuple[float, float]] = []
        for token in pos.split():
            if token.startswith("e,"):
                x_str, y_str = token[2:].split(",")
                end_tip = (float(x_str), height - float(y_str))
            elif token.startswith("s,"):
                continue
            else:
                x_str, y_str = token.split(",")
                points.append((float(x_str), height - float(y_str)))
        if end_tip is not None:
            points.append(end_tip)
        return points
