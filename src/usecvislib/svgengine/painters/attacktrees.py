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
from typing import Any

from ... import utils
from ...constants import cvss_to_color, cvss_to_severity_label
from ...cvss_unified import get_cvss_score_unified as get_cvss_score
from ...settings import is_cvss_enabled
from .. import metrics, shapes, themes
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
    "none": "plain",
    "plaintext": "plain",
}

# Per-node input keys the engine consumes; everything else is warn-and-ignore.
_CONSUMED_KEYS = {"label", "fillcolor", "fontcolor", "color", "shape", "style", "cvss", "cvss_vector"}


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

        fill = border = text_color = None
        severity = None
        score = None
        if honor_overrides:
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
                if use_cvss_colors:
                    fill = cvss_to_color(score)
                    if not attrs.get("fontcolor"):
                        text_color = "#ffffff"
                if "CVSS" not in label:
                    marker = "*" if cvss_vector and cvss_value is None else ""
                    label = f"{label}\n(CVSS: {score} - {severity_label}){marker}"

        size = font["root_size"] if kind == "root" else font["size"]
        lines = metrics.wrap_text(label, font["family"], size, card_cfg["max_label_width"])
        text_w, text_h = metrics.measure_block(lines, font["family"], size)
        width = max(card_cfg["min_width"], text_w + 2 * card_cfg["padding_x"])
        height = text_h + 2 * card_cfg["padding_y"]

        node_data = {"node-id": utils.sanitize_node_id(name), "label": name}
        if score is not None:
            node_data["cvss"] = str(score)

        scene.nodes.append(
            SceneNode(
                id=name,
                label=label,
                kind=kind,
                lines=lines,
                width=width,
                height=height,
                shape=_node_shape(attrs.get("shape", ""), name),
                fill=fill,
                border=border,
                text_color=text_color,
                severity=severity,
                cvss=score,
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
                )
            )

    return scene, root_id, rankdir


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

    # Edges: from parent border to child border along the flow axis
    for edge in scene.edges:
        src = scene.node_by_id(edge.src)
        dst = scene.node_by_id(edge.dst)
        if src is None or dst is None:
            logger.warning(f"Edge {edge.src} -> {edge.dst} references unknown node; skipped")
            continue
        if horizontal:
            x1, y1 = src.x + src.width / 2, src.y
            x2, y2 = dst.x - dst.width / 2, dst.y
        else:
            x1, y1 = src.x, src.y + src.height / 2
            x2, y2 = dst.x, dst.y - dst.height / 2
        color = edge.color or edge_cfg["color"]
        if edge_cfg["routing"] == "curve":
            d = shapes.curve_path_d(x1, y1, x2, y2, horizontal=horizontal)
        else:
            d = shapes.ortho_path_d(x1, y1, x2, y2, horizontal=horizontal)
        edge_group = shapes.group(["usv-edge", "usv-edge--tree"], {"from": edge.src, "to": edge.dst})
        edge_group.append(
            shapes.edge_path(
                d, color, float(edge_cfg["width"]), dashed=edge.dashed, marker_url=canvas.arrow_marker(color)
            )
        )
        canvas.add("edges", edge_group)

    # Nodes: card/pill/diamond/plain body + centered label block
    for node in scene.nodes:
        role = theme["root"] if node.kind == "root" else theme["node"]
        fill_value = node.fill or role["fill"]
        fill_kind = themes.parse_fill(fill_value)
        fill = canvas.gradient(fill_kind[1], fill_kind[2]) if fill_kind[0] == "gradient" else fill_kind[1]
        border = node.border or role["border"]
        text_color = node.text_color or role["text"]
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
        elif node.shape != "plain":
            radius = node.height / 2 if node.shape == "pill" else float(card_cfg["radius"])
            node_group.append(
                shapes.card(
                    x, y, node.width, node.height, radius, fill, border, float(card_cfg["border_width"]), shadow_url
                )
            )

        text_h = len(node.lines) * size * metrics.LINE_HEIGHT
        node_group.extend(
            shapes.text_lines(node.x, node.y - text_h / 2, node.lines, size, text_color, bold=node.kind == "root")
        )
        canvas.add("nodes", node_group)

        # CVSS badge at the card's top-right corner
        if node.cvss is not None and theme["badges"]["cvss"]:
            badge_size = size * 0.8
            badge_label = str(node.cvss)
            badge_w = metrics.measure_text(badge_label, font["family"], badge_size)
            canvas.add(
                "badges",
                shapes.badge(
                    node.x + node.width / 2 + badge_size,
                    y,
                    badge_label,
                    badge_w,
                    fill=theme["badges"]["fill"],
                    text_color=theme["badges"]["text"],
                    size=badge_size,
                ),
            )

    return canvas.to_string()


def render_svg(viz) -> str:
    """Render an attack tree visualization instance to SVG text."""
    theme = themes.resolve(viz.style)
    scene, root_id, rankdir = _build_scene(viz, theme)
    return _paint_scene(viz, scene, root_id, rankdir, theme)
