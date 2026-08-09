#
# VULNEX -Universal Security Visualization Library-
#
# File: attacktrees.py
# Author: Simon Roses Femerling
# Created: 2026-08-08
# Last Modified: 2026-08-08
# Version: 0.4.1
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Attack Trees painter for the SVG engine (pilot module).

Consumes the exact same input schema as the Graphviz path in
``attacktrees.py`` — tree/nodes/edges sections, CVSS values or vectors,
per-node style overrides — and mirrors its semantics: CVSS coloring gated
by ``settings.is_cvss_enabled("attack_tree")``, template color overrides
honored only on the default preset, CVSS annotation appended to labels
(with ``*`` marking vector-derived scores), ``tree.params.rankdir`` mapped
to layout orientation. Unsupported Graphviz attributes are logged and
ignored per the Feature Subset Contract (devnotes/SVG_ENGINE_DESIGN.md).
"""

import logging
from typing import Any, Optional

from ... import utils
from ...constants import cvss_to_color, cvss_to_severity_label
from ...cvss_unified import get_cvss_score_unified as get_cvss_score
from ...settings import is_cvss_enabled
from .. import images, metrics, shapes, themes
from ..canvas import SvgCanvas
from ..layout import TidyTreeLayout
from ..scene import Scene, SceneEdge, SceneNode

logger = logging.getLogger(__name__)

MODULE_SLUG = "attacktrees"
DEFAULT_SVG_STYLE = "sv_default"

# Graphviz shape vocabulary -> SVG engine shapes
_SHAPE_MAP = {
    "": "card",
    "box": "card",
    "rect": "card",
    "rectangle": "card",
    "square": "card",
    "ellipse": "pill",
    "oval": "pill",
    "circle": "pill",
    "diamond": "diamond",
    "octagon": "chamfer",
    "doubleoctagon": "chamfer",
    "hexagon": "chamfer",
    "none": "plain",
    "plaintext": "plain",
}

# Per-node input keys the engine consumes; everything else is warn-and-ignore.
_CONSUMED_KEYS = {"label", "fillcolor", "fontcolor", "color", "shape", "style", "cvss", "cvss_vector", "image", "gate"}

# Vertical gap between an embedded icon and its label
_IMAGE_TEXT_GAP = 4.0


def _node_shape(user_shape: str, node_id: str) -> str:
    """Map a Graphviz shape name to an engine shape, warning on unknowns."""
    shape = _SHAPE_MAP.get(str(user_shape).lower())
    if shape is None:
        logger.warning(f"Node '{node_id}': shape '{user_shape}' not supported by SVG engine, using card")
        return "card"
    return shape


def _warn_unsupported(attrs: dict[str, Any], node_id: str) -> None:
    """Log input attributes the SVG engine does not consume."""
    for key in attrs:
        if key not in _CONSUMED_KEYS:
            logger.warning(f"Node '{node_id}': attribute '{key}' ignored by SVG engine")


def _build_scene(viz, theme: dict[str, Any]) -> tuple[Scene, str, str]:
    """Translate attack tree input data into a Scene.

    Returns:
        (scene, root_id, rankdir)
    """
    data = viz.inputdata
    for section in ("tree", "nodes", "edges"):
        if section not in data:
            raise utils.RenderError(f"Missing '{section}' section in input file")

    tree = data["tree"]
    nodes = data["nodes"]
    edges = data["edges"]
    root_id = tree.get("root")
    if not root_id:
        raise utils.RenderError("Missing 'root' in tree section")

    total_edges = sum(len(e) if isinstance(e, list) else 0 for e in edges.values())
    utils.check_graph_complexity(len(nodes), total_edges)

    params = tree.get("params", {}) if isinstance(tree.get("params"), dict) else {}
    rankdir = str(params.get("rankdir", "TB")).upper()
    for key in params:
        if key != "rankdir":
            logger.warning(f"tree.params.{key} ignored by SVG engine")
    if rankdir not in ("TB", "LR"):
        logger.warning(f"rankdir '{rankdir}' not supported by SVG engine, using TB")
        rankdir = "TB"

    font = theme["font"]
    card_cfg = theme["card"]
    # Template color overrides only apply on the default preset, mirroring
    # _strip_style_attrs semantics on the Graphviz path.
    honor_overrides = viz.styleid == DEFAULT_SVG_STYLE
    use_cvss_colors = bool(theme["severity"]["use_cvss_colors"]) and is_cvss_enabled("attack_tree")

    scene = Scene(module=MODULE_SLUG, meta={"name": tree.get("name", "Attack Tree")})

    for name, raw_attrs in nodes.items():
        attrs = raw_attrs if isinstance(raw_attrs, dict) else {}
        _warn_unsupported(attrs, name)
        kind = "root" if name == root_id else "node"
        label = str(attrs.get("label", name))

        # Image nodes render as plain icon + label, no card — mirroring the
        # Graphviz path, which clears shape/style for image nodes.
        image_href = images.resolve_data_uri(attrs["image"], name) if attrs.get("image") else None

        fill = border = text_color = None
        severity = None
        score = None
        # Image nodes ignore color overrides entirely — the Graphviz path
        # clears all attributes (incl. fontcolor) when rendering an icon.
        if honor_overrides and not image_href:
            user_style = str(attrs.get("style", ""))
            if attrs.get("fillcolor"):
                fill = str(attrs["fillcolor"])
            elif "filled" in user_style.lower() and attrs.get("color"):
                # Graphviz fills with 'color' when style=filled and no fillcolor
                fill = str(attrs["color"])
            if attrs.get("color") and fill != str(attrs.get("color")):
                border = str(attrs["color"])
            if attrs.get("fontcolor"):
                text_color = str(attrs["fontcolor"])

        # CVSS handling (root nodes are exempt, as on the Graphviz path)
        if kind != "root":
            cvss_value = attrs.get("cvss")
            cvss_vector = attrs.get("cvss_vector")
            score, _ = get_cvss_score(cvss_value, cvss_vector)
            if score is not None and is_cvss_enabled("attack_tree"):
                severity_label = cvss_to_severity_label(score)
                severity = severity_label.lower()
                # Icon nodes have no card to color (Graphviz path skips
                # fillcolor for images too); label annotation still applies.
                if use_cvss_colors and not image_href:
                    fill = cvss_to_color(score)
                    if not attrs.get("fontcolor"):
                        text_color = "#ffffff"
                if "CVSS" not in label:
                    marker = "*" if cvss_vector and cvss_value is None else ""
                    label = f"{label}\n(CVSS: {score} - {severity_label}){marker}"

        size = font["root_size"] if kind == "root" else font["size"]
        bold = kind == "root"
        lines = metrics.wrap_text(label, font["family"], size, card_cfg["max_label_width"], bold=bold)
        text_w, text_h = metrics.measure_block(lines, font["family"], size, bold=bold)
        if bold:
            # Rasterizers draw the real bold face slightly wider than the
            # measured fallback font; guard so titles keep their padding.
            text_w *= 1.04
        img_size = float(theme["images"]["size"]) if image_href else 0.0
        # Padding scales with the font (the root's larger, bolder title
        # needs proportionally more breathing room than a 13px node label).
        pad_x = card_cfg["padding_x"] * size / font["size"]
        pad_y = card_cfg["padding_y"] * size / font["size"]
        width = max(card_cfg["min_width"], text_w + 2 * pad_x, img_size + 2 * pad_x)
        height = text_h + 2 * pad_y
        if image_href:
            height += img_size + _IMAGE_TEXT_GAP
        shape = "plain" if image_href else _node_shape(attrs.get("shape", ""), name)
        if shape == "pill":
            # Pill end-caps (radius = height/2) curve into the padding zone;
            # widen so the text stays clear of the rounded ends.
            width = max(width, text_w + height)

        gate = str(attrs.get("gate", "")).upper() if attrs.get("gate") else None
        if gate and gate not in ("AND", "OR"):
            logger.warning(f"Node '{name}': gate '{gate}' not supported (AND|OR); ignored")
            gate = None

        node_data = {"node-id": utils.sanitize_node_id(name), "label": name}
        if score is not None:
            node_data["cvss"] = str(score)
        if gate:
            node_data["gate"] = gate

        scene.nodes.append(
            SceneNode(
                id=name,
                label=label,
                kind=kind,
                lines=lines,
                width=width,
                height=height,
                shape=shape,
                inset_top=float(card_cfg["padding_y"]) if image_href else 0.0,
                fill=fill,
                border=border,
                text_color=text_color,
                severity=severity,
                cvss=score,
                gate=gate,
                image_href=image_href,
                data=node_data,
            )
        )

    for parent, children in edges.items():
        if not isinstance(children, list):
            raise utils.RenderError(f"Edges for '{parent}' must be a list, got {type(children).__name__}")
        for child in children:
            if not isinstance(child, dict) or "to" not in child:
                raise utils.RenderError(f"Edge entry must be a dict with 'to' key: {child}")
            scene.edges.append(
                SceneEdge(
                    src=parent,
                    dst=child["to"],
                    color=str(child["color"]) if child.get("color") else None,
                    dashed="dashed" in str(child.get("style", "")).lower(),
                    label=str(child["label"]) if child.get("label") else None,
                )
            )

    return scene, root_id, rankdir


def _edge_endpoints(src, dst, horizontal: bool) -> tuple[float, float, float, float]:
    """Border-to-border endpoints along the flow axis.

    Top-down edges land on the node's visual content (``inset_top`` skips
    the invisible padding of plain/icon nodes so arrows touch the icon).
    """
    if horizontal:
        return (src.x + src.width / 2, src.y, dst.x - dst.width / 2, dst.y)
    return (src.x, src.y + src.height / 2, dst.x, dst.y - dst.height / 2 + dst.inset_top)


def _paint_edges(
    scene: Scene,
    canvas: SvgCanvas,
    edge_cfg: dict[str, Any],
    horizontal: bool,
    page_bg: str = "",
    sizing: bool = False,
) -> Optional[dict[float, float]]:
    """Paint edges as trunk + rail + drops plumbing (ortho) or fan-out curves.

    Overlapping full parent->child paths superimpose into junction artifacts,
    so ortho routing draws real plumbing per parent: one trunk, one rail with
    rounded corners at its outer ends, and a T-junction drop per child (each
    drop carries the edge's interactivity contract and arrowhead).

    DAG-shaped input (attack trees allow shared subtrees) needs four extra
    mechanisms to stay readable:

    - Merge rails: many single-child parents converging on one sink collapse
      into the inverse of a fan-out - each parent trunks down onto ONE shared
      rail, which feeds a single arrowed stem into the sink (instead of a
      harness of parallel paths).
    - Rail staggering: rails that would overlap horizontally in the same row
      gap get distinct heights (greedy interval coloring). Pure trees keep a
      single shared height.
    - Drop separation: remaining edges converging on a multi-parent child
      land on distinct x-slots along its top edge (ordered by parent
      position) instead of stacking on its center.
    - Cross-links: lateral/upward edges are drawn as curves so derived
      connections read differently from the structural plumbing; per-edge
      color/dash overrides keep individual paths.
    """
    width = float(edge_cfg["width"])
    default_color = edge_cfg["color"]
    label_size = float(edge_cfg["label_size"])
    label_color = edge_cfg["label_color"]
    corner = 10.0
    stagger_margin = 18.0  # min horizontal clearance before rails must split levels

    def draw_edge(edge, d: str, color: str, arrow: bool = True) -> None:
        edge_group = shapes.group(["usv-edge", "usv-edge--tree"], {"from": edge.src, "to": edge.dst})
        marker = canvas.arrow_marker(color) if arrow else ""
        edge_group.append(shapes.edge_path(d, color, width, dashed=edge.dashed, marker_url=marker))
        canvas.add("edges", edge_group)

    def add_label(edge, cross: float, main: float) -> None:
        """Label an edge at (cross, main) - Graphviz renders edge label= too."""
        if not edge.label:
            return
        x, y = (main, cross) if horizontal else (cross, main)
        canvas.add("labels", shapes.edge_label(x, y, str(edge.label), label_size, label_color, page_bg))

    def start_of(node) -> float:
        return (node.x + node.width / 2) if horizontal else (node.y + node.height / 2)

    def visual_top(node) -> float:
        return (node.x - node.width / 2) if horizontal else (node.y - node.height / 2 + node.inset_top)

    def bbox_top(node) -> float:
        return (node.x - node.width / 2) if horizontal else (node.y - node.height / 2)

    def cross_of(node) -> float:
        return node.y if horizontal else node.x

    def line(c1: float, m1: float, c2: float, m2: float) -> str:
        """Straight segment in (cross, main) coordinates."""
        if horizontal:
            return f"M {shapes.fmt(m1)} {shapes.fmt(c1)} L {shapes.fmt(m2)} {shapes.fmt(c2)}"
        return f"M {shapes.fmt(c1)} {shapes.fmt(m1)} L {shapes.fmt(c2)} {shapes.fmt(m2)}"

    def ortho(c1: float, m1: float, c2: float, m2: float, mid) -> str:
        if horizontal:
            return shapes.ortho_path_d(m1, c1, m2, c2, corner=corner, horizontal=True, mid=mid)
        return shapes.ortho_path_d(c1, m1, c2, m2, corner=corner, horizontal=False, mid=mid)

    def curve(c1: float, m1: float, c2: float, m2: float) -> str:
        if horizontal:
            return shapes.curve_path_d(m1, c1, m2, c2, horizontal=True)
        return shapes.curve_path_d(c1, m1, c2, m2, horizontal=False)

    def rail_path(lo: float, hi: float, bus: float, r_lo: float, r_hi: float) -> str:
        """Rail along ``bus`` from lo to hi; end radii signed: >0 turns toward
        the children side, <0 toward the parents side, 0 square end."""
        if horizontal:
            if r_lo:
                a, side = abs(r_lo), (1 if r_lo > 0 else -1)
                head = (
                    f"M {shapes.fmt(bus + side * a)} {shapes.fmt(lo)} "
                    f"Q {shapes.fmt(bus)} {shapes.fmt(lo)} {shapes.fmt(bus)} {shapes.fmt(lo + a)}"
                )
            else:
                head = f"M {shapes.fmt(bus)} {shapes.fmt(lo)}"
            if r_hi:
                a, side = abs(r_hi), (1 if r_hi > 0 else -1)
                tail = (
                    f"L {shapes.fmt(bus)} {shapes.fmt(hi - a)} "
                    f"Q {shapes.fmt(bus)} {shapes.fmt(hi)} {shapes.fmt(bus + side * a)} {shapes.fmt(hi)}"
                )
            else:
                tail = f"L {shapes.fmt(bus)} {shapes.fmt(hi)}"
            return f"{head} {tail}"
        if r_lo:
            a, side = abs(r_lo), (1 if r_lo > 0 else -1)
            head = (
                f"M {shapes.fmt(lo)} {shapes.fmt(bus + side * a)} "
                f"Q {shapes.fmt(lo)} {shapes.fmt(bus)} {shapes.fmt(lo + a)} {shapes.fmt(bus)}"
            )
        else:
            head = f"M {shapes.fmt(lo)} {shapes.fmt(bus)}"
        if r_hi:
            a, side = abs(r_hi), (1 if r_hi > 0 else -1)
            tail = (
                f"L {shapes.fmt(hi - a)} {shapes.fmt(bus)} "
                f"Q {shapes.fmt(hi)} {shapes.fmt(bus)} {shapes.fmt(hi)} {shapes.fmt(bus + side * a)}"
            )
        else:
            tail = f"L {shapes.fmt(hi)} {shapes.fmt(bus)}"
        return f"{head} {tail}"

    valid = []
    for edge in scene.edges:
        src = scene.node_by_id(edge.src)
        dst = scene.node_by_id(edge.dst)
        if src is None or dst is None:
            logger.warning(f"Edge {edge.src} -> {edge.dst} references unknown node; skipped")
            continue
        valid.append((edge, src, dst))

    if edge_cfg["routing"] == "curve":
        if sizing:
            return {}  # curves keep the layout's uniform row gap
        for edge, src, dst in valid:
            d = curve(cross_of(src), start_of(src), cross_of(dst), visual_top(dst))
            draw_edge(edge, d, edge.color or default_color)
            add_label(edge, (cross_of(src) + cross_of(dst)) / 2, (start_of(src) + visual_top(dst)) / 2)
        return None

    # ---- Pass 1: per-parent groups, split into plumbable drops vs cross-links
    groups = []
    for edge, src, dst in valid:
        for record in groups:
            if record["src"] is src:
                break
        else:
            record = {"src": src, "plumbed": [], "others": []}
            groups.append(record)
        if visual_top(dst) > start_of(src) and not edge.color and not edge.dashed:
            record["plumbed"].append((edge, dst))
        else:
            record["others"].append((edge, dst))

    # ---- Pass 2: merge rails - one collector per sink fed by >=2 plumbed
    # parents. Covers single-child parents AND multi-child parents whose
    # child sets overlap: without the latter, N parents sharing the same two
    # sinks each draw a private full-span rail (N stacked parallel lines)
    # and every sink collects N arrowheads on its top edge. A collector
    # rail per sink keeps it to one line and one arrow.
    arrivals_by_sink: dict[str, list] = {}
    for record in groups:
        for edge, dst in record["plumbed"]:
            arrivals_by_sink.setdefault(dst.id, []).append((edge, record, dst))
    merges = []
    for _sink_id, arrivals in arrivals_by_sink.items():
        if len(arrivals) < 2:
            continue
        sink = arrivals[0][2]
        members = []
        for edge, record, _ in arrivals:
            record["plumbed"] = [(e, d) for e, d in record["plumbed"] if e is not edge]
            members.append((edge, record["src"]))
        members.sort(key=lambda m: cross_of(m[1]))
        merges.append({"sink": sink, "members": members})

    # ---- Pass 3: drop positions - every remaining plumbed sink has exactly
    # one arrival (multi-arrival sinks were extracted into merge rails).
    # Drops that land almost under their trunk snap onto the trunk line.
    drop_crosses: dict[int, float] = {}
    for record in groups:
        src_cross = cross_of(record["src"])
        for edge, dst in record["plumbed"]:
            cross = cross_of(dst)
            offset = abs(cross - src_cross)
            limit = min(24.0, (dst.height if horizontal else dst.width) / 4)
            if 0.01 < offset <= limit:
                cross = src_cross
            drop_crosses[id(edge)] = cross

    # ---- Pass 4: rail heights - stagger overlapping rails in each row gap
    rail_records = []
    for record in groups:
        if not record["plumbed"]:
            continue
        crosses = [drop_crosses[id(e)] for e, _ in record["plumbed"]] + [cross_of(record["src"])]
        record["lo"], record["hi"] = min(crosses), max(crosses)
        record["nearest"] = min(visual_top(d) for _, d in record["plumbed"])
        record["row_key"] = round(min(bbox_top(d) for _, d in record["plumbed"]), 1)
        record["parents_end"] = start_of(record["src"])
        rail_records.append(record)
    for merge in merges:
        sink = merge["sink"]
        # Sink stem snaps onto a member trunk when nearly aligned.
        merge["stem"] = cross_of(sink)
        limit = min(24.0, (sink.height if horizontal else sink.width) / 4)
        aligned = min((cross_of(s) for _, s in merge["members"]), key=lambda c: abs(c - merge["stem"]))
        if abs(aligned - merge["stem"]) <= limit:
            merge["stem"] = aligned
        crosses = [cross_of(s) for _, s in merge["members"]] + [merge["stem"]]
        merge["lo"], merge["hi"] = min(crosses), max(crosses)
        merge["nearest"] = visual_top(sink)
        merge["row_key"] = round(bbox_top(sink), 1)
        merge["parents_end"] = max(start_of(s) for _, s in merge["members"])
        rail_records.append(merge)

    buckets: dict[float, list] = {}
    for record in rail_records:
        buckets.setdefault(record["row_key"], []).append(record)
    for bucket in buckets.values():
        band_start = max(record["parents_end"] for record in bucket)
        band_end = min(record["nearest"] for record in bucket)
        if band_end <= band_start:
            for record in bucket:
                record["bus"] = (record["parents_end"] + record["nearest"]) / 2
            continue
        levels: list[list] = []
        bucket.sort(key=lambda g: g["lo"])
        for record in bucket:
            for index, placed in enumerate(levels):
                if all(record["lo"] > hi + stagger_margin or lo > record["hi"] + stagger_margin for lo, hi in placed):
                    placed.append((record["lo"], record["hi"]))
                    record["level"] = index
                    break
            else:
                levels.append([(record["lo"], record["hi"])])
                record["level"] = len(levels) - 1
        for record in bucket:
            record["bus"] = band_start + (record["level"] + 1) * (band_end - band_start) / (len(levels) + 1)

    if sizing:
        # Clearance each child row needs from the row above: room for the
        # rail track levels running through that band (stagger count is
        # purely cross-axis, so respacing rows cannot change it), plus a
        # little extra when drops carry labels.
        requirements: dict[float, float] = {}
        for row_key, bucket in buckets.items():
            track_count = max(record.get("level", 0) for record in bucket) + 1
            labeled = any(
                edge.label
                for record in bucket
                for edge, _ in (record.get("plumbed") or []) + (record.get("members") or [])
            )
            need = 12.0 + 16.0 * track_count + 16.0 + (10.0 if labeled else 0.0)
            requirements[row_key] = max(requirements.get(row_key, 0.0), need)
        return requirements

    # ---- Pass 5: draw fan-out plumbing and cross-links
    for record in groups:
        src = record["src"]
        src_cross, src_end = cross_of(src), start_of(src)
        bus = record.get("bus")

        for edge, dst in record["others"]:
            c2, m2 = cross_of(dst), visual_top(dst)
            color = edge.color or default_color
            if m2 > src_end:
                mid = bus if bus is not None and src_end < bus < m2 else None
                draw_edge(edge, ortho(src_cross, src_end, c2, m2, mid), color)
                add_label(edge, c2, ((mid if mid is not None else (src_end + m2) / 2) + m2) / 2)
            elif start_of(dst) > bbox_top(src):
                # Lateral (same-row) cross-link: swing below the source and
                # enter the target's NEAR SIDE at mid-height - a bottom
                # entry reads as an upward edge in a top-down tree, and a
                # straight diagonal would slice between the cards with no
                # readable direction.
                direction = 1.0 if c2 < src_cross else -1.0  # +1: enter dst's right side
                entry_cross = c2 + direction * ((dst.height if horizontal else dst.width) / 2)
                entry_main = dst.x if horizontal else dst.y
                dip = max(src_end, start_of(dst)) + 24.0
                approach = entry_cross + direction * 38.0

                def pt(c: float, m: float) -> str:
                    return f"{shapes.fmt(m)} {shapes.fmt(c)}" if horizontal else f"{shapes.fmt(c)} {shapes.fmt(m)}"

                d = (
                    f"M {pt(src_cross, src_end)} "
                    f"C {pt(src_cross, dip)} {pt(approach, entry_main)} {pt(entry_cross, entry_main)}"
                )
                draw_edge(edge, d, color)
                # Cubic midpoint (t=0.5) of the swing
                mid_cross = 0.125 * src_cross + 0.375 * src_cross + 0.375 * approach + 0.125 * entry_cross
                mid_main = 0.125 * src_end + 0.375 * dip + 0.375 * entry_main + 0.125 * entry_main
                add_label(edge, mid_cross, mid_main)
            else:
                draw_edge(edge, curve(src_cross, src_end, c2, m2), color)
                add_label(edge, (src_cross + c2) / 2, (src_end + m2) / 2)

        plumbed = record["plumbed"]
        if not plumbed or bus is None:
            continue
        if len(plumbed) == 1:
            edge, dst = plumbed[0]
            draw_edge(edge, ortho(src_cross, src_end, drop_crosses[id(edge)], visual_top(dst), bus), default_color)
            add_label(edge, drop_crosses[id(edge)], (bus + visual_top(dst)) / 2)
            continue

        lo, hi = record["lo"], record["hi"]
        r = max(0.0, min(corner, (hi - lo) / 2, record["nearest"] - bus, bus - record["parents_end"]))
        drop_ends = {round(drop_crosses[id(e)], 2) for e, _ in plumbed}

        # End radii: turn down (+r) toward a drop, up (-r) where the rail
        # ends at the parent trunk (which arrives from above - a downward
        # cap there dangles into empty space), square (0) when a snapped
        # drop continues straight through the trunk end.
        radii = []
        for end in (lo, hi):
            at_trunk = abs(end - src_cross) < 0.01
            at_drop = round(end, 2) in drop_ends
            if at_trunk and at_drop:
                radii.append(0.0)
            elif at_trunk:
                radii.append(-r)
            else:
                radii.append(r)

        trunk_end = bus
        if (abs(lo - src_cross) < 0.01 or abs(hi - src_cross) < 0.01) and round(src_cross, 2) not in drop_ends:
            trunk_end = bus - r  # meets the upward-turning rail corner

        rail_group = shapes.group(["usv-rail"], {"from": plumbed[0][0].src})
        rail_group.append(shapes.edge_path(rail_path(lo, hi, bus, radii[0], radii[1]), default_color, width))
        rail_group.append(shapes.edge_path(line(src_cross, src_end, src_cross, trunk_end), default_color, width))
        canvas.add("edges", rail_group)

        for edge, dst in plumbed:
            cross = drop_crosses[id(edge)]
            end_r = 0.0
            if abs(cross - lo) < 0.01:
                end_r = radii[0]
            elif abs(cross - hi) < 0.01:
                end_r = radii[1]
            start = bus + r if end_r > 0 else bus
            draw_edge(edge, line(cross, start, cross, visual_top(dst)), default_color)
            add_label(edge, cross, (bus + visual_top(dst)) / 2)

    # ---- Pass 6: draw merge rails
    for merge in merges:
        sink = merge["sink"]
        bus = merge["bus"]
        stem = merge["stem"]
        lo, hi = merge["lo"], merge["hi"]
        member_crosses = {round(cross_of(s), 2) for _, s in merge["members"]}
        r = max(0.0, min(corner, (hi - lo) / 2, merge["nearest"] - bus, bus - merge["parents_end"]))
        stem_on_member = round(stem, 2) in member_crosses

        # End radii: turn down (+r) toward the sink stem, up (-r) toward a
        # member trunk, square (0) when a through-line crosses at that end.
        radii = []
        for end in (lo, hi):
            if abs(end - stem) < 0.01:
                radii.append(0.0 if stem_on_member else r)
            else:
                radii.append(-r)

        rail_group = shapes.group(["usv-rail", "usv-rail--merge"], {"to": sink.id})
        rail_group.append(shapes.edge_path(rail_path(lo, hi, bus, radii[0], radii[1]), default_color, width))
        stem_start = bus
        if not stem_on_member and (abs(stem - lo) < 0.01 or abs(stem - hi) < 0.01):
            stem_start = bus + r  # continue the down-turning end curve
        rail_group.append(
            shapes.edge_path(
                line(stem, stem_start, stem, visual_top(sink)),
                default_color,
                width,
                marker_url=canvas.arrow_marker(default_color),
            )
        )
        canvas.add("edges", rail_group)

        # Member trunks carry the per-edge interactivity contract; the shared
        # stem carries the single arrowhead.
        for edge, member in merge["members"]:
            member_cross = cross_of(member)
            trunk_end = bus
            at_end = abs(member_cross - lo) < 0.01 or abs(member_cross - hi) < 0.01
            if at_end and abs(member_cross - stem) > 0.01:
                trunk_end = bus - r  # meets the upward-turning rail corner
            draw_edge(edge, line(member_cross, start_of(member), member_cross, trunk_end), default_color, arrow=False)
            add_label(edge, member_cross, (start_of(member) + bus) / 2)


_MIN_ROW_GAP = 36.0  # bands with no rail tracks: just a trunk + arrowhead


def _respace_rows(scene: Scene, requirements: dict[float, float], horizontal: bool) -> None:
    """Resize the gap between rows to what their edge bands actually need.

    The layout spaces rows uniformly with the theme's v_gap, sized for the
    worst case; most bands hold a single track or none (plain chains), so
    uniform spacing makes tall diagrams. Requirements are keyed by the
    child row's leading edge as produced by the layout.
    """
    rows: dict[float, list] = {}
    for node in scene.nodes:
        top = (node.x - node.width / 2) if horizontal else (node.y - node.height / 2)
        rows.setdefault(round(top, 1), []).append(node)

    prev_bottom = None
    for row_top in sorted(rows):
        row_nodes = rows[row_top]
        new_top = row_top if prev_bottom is None else prev_bottom + requirements.get(row_top, _MIN_ROW_GAP)
        delta = new_top - row_top
        row_size = 0.0
        for node in row_nodes:
            if horizontal:
                node.x += delta
                row_size = max(row_size, node.width)
            else:
                node.y += delta
                row_size = max(row_size, node.height)
        prev_bottom = new_top + row_size


def _paint_scene(viz, scene: Scene, root_id: str, rankdir: str, theme: dict[str, Any]) -> str:
    """Lay out and paint a scene; returns SVG text."""
    layout_cfg = theme["layout"]
    TidyTreeLayout(
        h_gap=float(layout_cfg["h_gap"]),
        v_gap=float(layout_cfg["v_gap"]),
        orientation=rankdir,
    ).solve(scene, root_id)

    font = theme["font"]
    card_cfg = theme["card"]
    edge_cfg = theme["edge"]
    effects = theme["effects"]
    page = theme["page"]
    horizontal = rankdir == "LR"

    canvas = SvgCanvas(MODULE_SLUG, viz.styleid)

    shadow_url = ""
    if effects["shadow"]:
        shadow_url = canvas.shadow(blur=float(effects["shadow_blur"]))

    css = [f".usv-{MODULE_SLUG} text {{ font-family: {font['family']}; }}"]
    if effects["hover_glow"]:
        css.append(
            f".usv-{MODULE_SLUG} .usv-node:hover rect, "
            f".usv-{MODULE_SLUG} .usv-node:hover polygon "
            f"{{ stroke-width: {shapes.fmt(float(card_cfg['border_width']) + 1.2)}; }}"
        )
    canvas.set_css("\n".join(css))

    # Tighten row gaps to what each edge band actually needs (must happen
    # before the canvas is sized from the scene bounds)
    requirements = _paint_edges(scene, canvas, edge_cfg, horizontal, sizing=True)
    if requirements is not None:
        _respace_rows(scene, requirements, horizontal)

    # Page background sized to content + padding
    pad = float(page["padding"])
    min_x, min_y, max_x, max_y = scene.bounds()
    min_x, min_y = min_x - pad, min_y - pad
    width, height = (max_x + pad) - min_x, (max_y + pad) - min_y
    canvas.finalize(min_x, min_y, width, height)
    canvas.add(
        "groups",
        shapes.card(min_x, min_y, width, height, 0, fill=page["background"], stroke="none", stroke_width=0),
    )

    # Muted diagram title in the top padding band
    title_cfg = theme["title"]
    title = str(scene.meta.get("name", "")).strip()
    if title_cfg["show"] and title:
        canvas.add(
            "labels",
            shapes.title_text(min_x + pad * 0.5, min_y + pad * 0.55, title, float(title_cfg["size"]), page["text"]),
        )

    _paint_edges(scene, canvas, edge_cfg, horizontal, page_bg=page["background"])

    # Nodes: card/pill/diamond/plain body + centered label block
    for node in scene.nodes:
        role = theme["root"] if node.kind == "root" else theme["node"]
        fill_value = node.fill or role["fill"]
        fill_kind = themes.parse_fill(fill_value)
        fill = canvas.gradient(fill_kind[1], fill_kind[2]) if fill_kind[0] == "gradient" else fill_kind[1]
        border = node.border or role["border"]
        # Plain nodes (incl. icon nodes) sit directly on the page background,
        # so their text uses the page contrast color, not the card text color.
        default_text = page["text"] if node.shape == "plain" else role["text"]
        text_color = node.text_color or default_text
        size = font["root_size"] if node.kind == "root" else font["size"]

        classes = ["usv-node", f"usv-node--{node.kind}"]
        if node.severity:
            classes.append(f"usv-sev--{node.severity}")
        node_group = shapes.group(classes, node.data)

        x, y = node.x - node.width / 2, node.y - node.height / 2
        if node.shape == "diamond":
            node_group.append(
                shapes.diamond(
                    node.x,
                    node.y,
                    node.width * 1.35,
                    node.height * 1.6,
                    fill,
                    border,
                    float(card_cfg["border_width"]),
                    shadow_url,
                )
            )
        elif node.shape == "chamfer":
            cut = min(12.0, node.height / 3)
            node_group.append(
                shapes.chamfer_card(
                    x, y, node.width, node.height, cut, fill, border, float(card_cfg["border_width"]), shadow_url
                )
            )
        elif node.shape != "plain":
            radius = node.height / 2 if node.shape == "pill" else float(card_cfg["radius"])
            node_group.append(
                shapes.card(
                    x, y, node.width, node.height, radius, fill, border, float(card_cfg["border_width"]), shadow_url
                )
            )

        text_h = len(node.lines) * size * metrics.LINE_HEIGHT
        if node.image_href:
            # Icon centered at the top, label block below it
            img_size = float(theme["images"]["size"])
            content_h = img_size + _IMAGE_TEXT_GAP + text_h
            img_top = node.y - content_h / 2
            node_group.append(shapes.image(node.x - img_size / 2, img_top, img_size, img_size, node.image_href))
            text_top = img_top + img_size + _IMAGE_TEXT_GAP
        else:
            text_top = node.y - text_h / 2
        node_group.extend(shapes.text_lines(node.x, text_top, node.lines, size, text_color, bold=node.kind == "root"))
        canvas.add("nodes", node_group)

        # CVSS badge docked on the top-right corner (cutout ring in the
        # page color makes it read as a floating chip)
        if node.cvss is not None and theme["badges"]["cvss"]:
            badge_size = size * 0.78
            badge_label = str(node.cvss)
            badge_w = metrics.measure_text(badge_label, font["family"], badge_size, bold=True)
            if node.image_href:
                # No card corner to dock on; sit the chip beside the icon's
                # top-right so it stays clear of the glyph itself.
                img_size = float(theme["images"]["size"])
                content_h = img_size + _IMAGE_TEXT_GAP + len(node.lines) * size * metrics.LINE_HEIGHT
                chip_w = badge_w + 1.1 * badge_size
                corner_x = node.x + img_size / 2 + chip_w / 2 - 4
                corner_y = node.y - content_h / 2 + 2
            else:
                corner_x = node.x + node.width / 2 - float(card_cfg["radius"]) * 0.4
                corner_y = y
            canvas.add(
                "badges",
                shapes.badge(
                    corner_x,
                    corner_y,
                    badge_label,
                    badge_w,
                    fill=theme["badges"]["fill"],
                    text_color=theme["badges"]["text"],
                    size=badge_size,
                    ring=page["background"],
                ),
            )

        # AND/OR gate chip docked bottom-center, where the trunk leaves the
        # node - states how this node's children combine
        if node.gate and theme["badges"]["gate"]:
            gate_size = size * 0.68
            gate_w = metrics.measure_text(node.gate, font["family"], gate_size, bold=True)
            if node.image_href:
                # Icon nodes have no card border to straddle; drop the chip
                # a touch so its ring clears the label descenders.
                content_h = float(theme["images"]["size"]) + _IMAGE_TEXT_GAP + text_h
                gate_y = node.y + content_h / 2 + 3
            else:
                gate_y = y + node.height
            canvas.add(
                "badges",
                shapes.badge(
                    node.x,
                    gate_y,
                    node.gate,
                    gate_w,
                    fill=theme["badges"]["fill"],
                    text_color=theme["badges"]["text"],
                    size=gate_size,
                    ring=page["background"],
                    variant="gate",
                ),
            )

    return canvas.to_string()


def render_svg(viz) -> str:
    """Render an attack tree visualization instance to SVG text."""
    theme = themes.resolve(viz.style)
    scene, root_id, rankdir = _build_scene(viz, theme)
    return _paint_scene(viz, scene, root_id, rankdir, theme)
