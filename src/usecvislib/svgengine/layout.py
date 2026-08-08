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

Phase 1 ships TidyTreeLayout for tree-structured scenes. Linear, stack,
axis, and Graphviz-JSON layouts follow in later phases (tasks T1.7, T3.1
in devnotes/SVG_ENGINE_DESIGN.md).
"""

import logging

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
        row_center = []
        cursor = 0.0
        for d in range(max_depth + 1):
            row_center.append(cursor + row_size[d] / 2)
            cursor += row_size[d] + self.v_gap

        # Pre-order placement: children packed inside the parent extent,
        # then the parent centered over them (iterative).
        place_stack: list[tuple[str, float]] = [(root_id, 0.0)]
        cross: dict[str, float] = {}
        while place_stack:
            node_id, left = place_stack.pop()
            kids = [k for k in children.get(node_id, []) if k in reachable and depth.get(k) == depth[node_id] + 1]
            if kids:
                kids_extent = sum(extent[k] for k in kids) + self.h_gap * (len(kids) - 1)
                kid_left = left + (extent[node_id] - kids_extent) / 2
                first_center = last_center = 0.0
                for i, kid in enumerate(kids):
                    center = kid_left + extent[kid] / 2
                    if i == 0:
                        first_center = center
                    last_center = center
                    place_stack.append((kid, kid_left))
                    kid_left += extent[kid] + self.h_gap
                cross[node_id] = (first_center + last_center) / 2
            else:
                cross[node_id] = left + extent[node_id] / 2

        for node_id in order:
            node = nodes[node_id]
            if self.orientation == "LR":
                node.x = row_center[depth[node_id]]
                node.y = cross[node_id]
            else:
                node.x = cross[node_id]
                node.y = row_center[depth[node_id]]

        # Orphans: a row below (TB) / right of (LR) the tree.
        orphans = [n for n in scene.nodes if n.id not in reachable]
        if orphans:
            logger.warning(f"{len(orphans)} node(s) unreachable from root '{root_id}'; placed apart")
            main = cursor + self.v_gap
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
