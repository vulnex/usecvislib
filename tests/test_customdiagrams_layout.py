#
# VULNEX -Universal Security Visualization Library-
#
# File: test_customdiagrams_layout.py
# Author: Simon Roses Femerling
# Created: 2026-10-05
# Last Modified: 2026-10-05
# Version: 0.6.0
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Custom diagram structure fixes found by a visual review."""

import re
from pathlib import Path

from usecvislib.customdiagrams import CustomDiagrams
from usecvislib.mermaid import serialize_to_mermaid
from usecvislib.utils import parse_content

TEMPLATES = Path(__file__).parent.parent / "templates" / "custom-diagrams"


def _source(template: str, style: str = "") -> str:
    cd = CustomDiagrams()
    cd.load(str(TEMPLATES / template))
    if style:
        cd.settings.style = style
    return cd._render_impl().source


def test_nested_clusters():
    # Region / VPC / subnets used to be loose "container" nodes.
    src = _source("network/infrastructure.toml")
    vpc = src.index("subgraph cluster_vpc")
    us_east = src.index("subgraph cluster_us_east")
    aws = src.index("subgraph cluster_aws")
    assert aws < us_east < vpc < src.index("subgraph cluster_public")
    # the region's closing brace comes after the VPC's subnets
    assert src.count("subgraph cluster_") == 8


def test_cluster_parent_cycle_still_emits_every_cluster():
    cd = CustomDiagrams()
    cd.load(str(TEMPLATES / "network/infrastructure.toml"))
    for c in cd.clusters:
        if c["id"] == "aws":
            c["parent"] = "data"  # cycle aws > ... > data > aws
    src = cd._render_impl().source
    assert len(set(re.findall(r"subgraph (cluster_\w+)", src))) == 8


def test_mermaid_nests_clusters():
    path = TEMPLATES / "network/infrastructure.toml"
    mmd = serialize_to_mermaid(parse_content(path.read_text(encoding="utf-8"), "toml"), diagram_type="custom_diagram")
    lines = mmd.splitlines()
    vpc = next(ln for ln in lines if "subgraph cl_vpc" in ln)
    aws = next(ln for ln in lines if "subgraph cl_aws" in ln)
    assert len(vpc) - len(vpc.lstrip()) > len(aws) - len(aws.lstrip())


def test_presets_keep_semantic_edge_line_style():
    # cd_sketch's edge style "bold" turned dotted/dashed edges solid.
    src = _source("software/architecture.toml", "cd_sketch")
    assert "dotted" in src or "dashed" in src


def test_icon_edges_end_at_the_icon():
    src = _source("software/deployment-diagram_icons.toml")
    assert "headport=icon" in src and "tailport=icon" not in src
    assert 'PORT="icon" FIXEDSIZE="TRUE"' in src


def test_import_attack_tree_keeps_edges():
    # The importer read a per-node "parent" key the schema does not have.
    cd = CustomDiagrams.from_attack_tree(str(TEMPLATES.parent / "attack-trees" / "ransomware_attack.tml"))
    assert len(cd.edges) >= len(cd.nodes) - 1
    assert any(n["type"] == "root" for n in cd.nodes)


def test_import_attack_graph_keeps_attack_path():
    cd = CustomDiagrams.from_attack_graph(str(TEMPLATES.parent / "attack-graphs" / "corporate_network.tml"))
    steps = [e for e in cd.edges if e["type"] == "attack_step"]
    assert steps
    exploits = {n["id"] for n in cd.nodes if n["type"] == "exploit"}
    assert all(e["from"] in exploits or e["to"] in exploits for e in steps)


def test_force_layouts_use_a_fixed_seed():
    # fdp started from a random placement, so the force-layout topology
    # template came out with a different size and shape on every render.
    cd = CustomDiagrams()
    cd.load(str(TEMPLATES / "network/topology.toml"))
    graph = cd._render_impl()
    assert graph.engine == "fdp"
    assert re.search(r"\bstart=1\b", graph.source)
