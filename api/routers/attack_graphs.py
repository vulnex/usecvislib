#
# VULNEX -Universal Security Visualization Library-
#
# File: routers/attack_graphs.py
# Description: Attack Graphs API endpoints
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
#

import logging
import os
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, File, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse

from usecvislib import AttackGraphs
from usecvislib.attackgraphs import AttackGraphError
from usecvislib.utils import ConfigError, FileError

from ..config import (
    RATE_LIMIT_ANALYZE,
    RATE_LIMIT_VISUALIZE,
    REQUEST_TIMEOUT_VISUALIZE,
    TEMP_DIR,
    limiter,
)
from ..helpers import (
    TempFiles,
    collapse_option,
    file_response,
    handle_errors,
    resolve_images_to_temp,
    run_sync_with_timeout,
    save_upload_file,
    validate_config_file_extension,
)
from ..schemas import (
    AttackGraphStyle,
    AttackPath,
    AttackPathsResponse,
    CriticalNode,
    GraphStats,
    OutputFormat,
    RenderEngine,
    TemplateMetadata,
)

logger = logging.getLogger("usecvislib.api")


router = APIRouter(tags=["Attack Graphs"])

# Errors in the uploaded definition: reported to the client as 400
_CLIENT_ERRORS = (AttackGraphError, FileError, ConfigError)


@router.post(
    "/visualize/attack-graph",
    summary="Generate attack graph visualization",
    response_class=FileResponse,
    responses={
        200: {
            "content": {
                "image/png": {},
                "image/svg+xml": {},
                "application/pdf": {},
            },
            "description": "Generated visualization image",
        }
    },
)
@limiter.limit(RATE_LIMIT_VISUALIZE)
async def visualize_attack_graph(
    request: Request,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(..., description="Configuration file containing attack graph definition"),
    format: OutputFormat = Query(default=OutputFormat.PNG, description="Output format"),
    style: AttackGraphStyle = Query(default=AttackGraphStyle.DEFAULT, description="Style preset"),
    render_engine: RenderEngine = Query(
        default=RenderEngine.GRAPHVIZ,
        description="Rendering engine: graphviz (default) or svg (modern cards over a Graphviz-computed layout, sv_* styles)",
    ),
    group_by: Optional[str] = Query(
        default=None,
        max_length=64,
        description="Cluster hosts by this host field (e.g. zone), or by network with ip/N or ip6/N (e.g. ip/24). "
        "Overrides graph.group_by in the file.",
    ),
    collapse: Optional[str] = Query(
        default=None,
        max_length=1000,
        description="Draw groups as one summary node: none, all, auto (largest first until max_nodes), "
        "or comma-separated group ids. Overrides graph.collapse in the file.",
    ),
    max_nodes: Optional[int] = Query(
        default=None, ge=1, le=10000, description="Node target for collapse=auto (default 300)"
    ),
):
    """
    Generate an attack graph visualization from an uploaded configuration file.

    The configuration file should contain:
    - `[graph]` section with name and description
    - `[hosts]` section with network hosts
    - `[vulnerabilities]` section with CVEs/weaknesses
    - `[privileges]` section with access levels
    - `[services]` section with running services (optional)
    - `[exploits]` section with preconditions/postconditions
    - `[network]` section with connectivity

    Example TOML structure:
    ```toml
    [graph]
    name = "Network Attack Graph"

    [hosts.webserver]
    label = "Web Server"
    ip = "192.168.1.10"

    [vulnerabilities.cve_2024_1234]
    label = "CVE-2024-1234"
    host = "webserver"
    cvss = 9.8

    [privileges.web_root]
    label = "Root Access"
    host = "webserver"
    level = "root"

    [exploits.exploit_web]
    label = "Exploit CVE"
    preconditions = ["cve_2024_1234"]
    postconditions = ["web_root"]

    [network]
    internet = ["webserver"]
    ```
    """
    temps = TempFiles()
    with handle_errors(temps, _CLIENT_ERRORS):
        validate_config_file_extension(file.filename)
        input_path = temps.add(save_upload_file(file))
        output_base = temps.add_prefix(os.path.join(TEMP_DIR, f"output_{os.urandom(8).hex()}"))

        # Resolve image_id references in the config
        input_for_viz = resolve_images_to_temp(input_path, temps)

        styleid = style.value
        if render_engine == RenderEngine.SVG and style == AttackGraphStyle.DEFAULT:
            styleid = ""  # let the engine pick sv_default

        # Generate visualization with timeout protection
        # SECURITY: Prevents resource exhaustion from complex/slow visualizations
        ag = AttackGraphs(
            input_for_viz,
            output_base,
            format=format.value,
            styleid=styleid,
            render_engine=render_engine.value,
            group_by=group_by,
            collapse=collapse_option(collapse),
            max_nodes=max_nodes,
        )
        await run_sync_with_timeout(
            ag.BuildAttackGraph, REQUEST_TIMEOUT_VISUALIZE, "attack graph visualization", on_abandon=temps.cleanup
        )

        return file_response(
            f"{output_base}.{format.value}", format, f"attack_graph.{format.value}", temps, background_tasks
        )


@router.post("/analyze/attack-graph", response_model=GraphStats, summary="Analyze attack graph structure")
@limiter.limit(RATE_LIMIT_ANALYZE)
async def analyze_attack_graph(
    request: Request,
    file: UploadFile = File(..., description="Configuration file containing attack graph definition"),
    group_by: Optional[str] = Query(
        default=None, max_length=64, description="Report per-group counts for hosts grouped by this field, or ip/N"
    ),
):
    """
    Analyze an attack graph and return statistics without generating visualization.

    Returns host counts, vulnerability counts, CVSS averages, and structural information.
    """
    temps = TempFiles()
    with handle_errors(temps, _CLIENT_ERRORS):
        validate_config_file_extension(file.filename)
        input_path = temps.add(save_upload_file(file))
        ag = AttackGraphs(input_path, "unused", group_by=group_by)
        stats = ag.get_graph_stats()

        # Get metadata
        metadata_obj = ag.get_metadata()
        stats["metadata"] = TemplateMetadata(
            name=metadata_obj.name,
            description=metadata_obj.description,
            engineversion=metadata_obj.engineversion,
            version=metadata_obj.version,
            type=metadata_obj.type,
            date=metadata_obj.date,
            last_modified=metadata_obj.last_modified,
            author=metadata_obj.author,
            email=metadata_obj.email,
            url=metadata_obj.url,
        )

        return GraphStats(**stats)


@router.post("/analyze/attack-paths", response_model=AttackPathsResponse, summary="Find attack paths in graph")
@limiter.limit(RATE_LIMIT_ANALYZE)
async def analyze_attack_paths(
    request: Request,
    file: UploadFile = File(..., description="Configuration file containing attack graph definition"),
    source: str = Query(..., description="Source node ID (e.g., 'internet' or a host)"),
    target: str = Query(..., description="Target node ID (e.g., a privilege node)"),
    max_paths: int = Query(10, ge=1, le=100, description="Maximum number of paths to return"),
):
    """
    Find all attack paths from source to target in the attack graph.

    Uses depth-first search to find paths. Also returns the shortest path.

    Example: Find paths from 'internet' to 'db_root' privilege.
    """
    temps = TempFiles()
    with handle_errors(temps, _CLIENT_ERRORS):
        validate_config_file_extension(file.filename)
        input_path = temps.add(save_upload_file(file))
        ag = AttackGraphs(input_path, "unused")
        ag.load()

        # Find all paths
        paths = ag.find_attack_paths(source, target, max_paths=max_paths)

        # Find shortest path
        shortest = ag.shortest_path(source, target)

        # Format response
        attack_paths = [AttackPath(path=p, length=len(p)) for p in paths]

        return AttackPathsResponse(
            source=source,
            target=target,
            paths=attack_paths,
            total_paths=len(paths),
            shortest_path_length=len(shortest) if shortest else None,
        )


@router.post("/analyze/critical-nodes", summary="Identify critical nodes in attack graph")
@limiter.limit(RATE_LIMIT_ANALYZE)
async def analyze_critical_nodes(
    request: Request,
    file: UploadFile = File(..., description="Configuration file containing attack graph definition"),
    limit: int = Query(10, ge=1, le=50, description="Number of top critical nodes to return"),
):
    """
    Identify the most critical nodes in the attack graph based on connectivity.

    Critical nodes are those with high in-degree and out-degree, making them
    important chokepoints or targets in the network.

    Returns nodes sorted by criticality score (total degree).
    """
    temps = TempFiles()
    with handle_errors(temps, _CLIENT_ERRORS):
        validate_config_file_extension(file.filename)
        input_path = temps.add(save_upload_file(file))
        ag = AttackGraphs(input_path, "unused")
        ag.load()

        critical = ag.analyze_critical_nodes()[:limit]

        return {"critical_nodes": [CriticalNode(**node) for node in critical], "total_nodes": len(ag._adjacency)}


@router.post("/analyze/centrality", summary="Calculate centrality metrics for attack graph nodes")
@limiter.limit(RATE_LIMIT_ANALYZE)
async def analyze_centrality(
    request: Request,
    file: UploadFile = File(..., description="Configuration file containing attack graph definition"),
    algorithm: str = Query("all", description="Centrality algorithm: betweenness, closeness, pagerank, or all"),
    limit: int = Query(10, ge=1, le=100, description="Number of top nodes to return"),
):
    """
    Calculate centrality metrics for nodes in the attack graph.

    Centrality measures help identify important nodes:
    - **Betweenness**: Nodes that lie on many shortest paths (chokepoints)
    - **Closeness**: Nodes that can quickly reach other nodes
    - **PageRank**: Nodes with many important incoming connections

    Use 'all' to calculate all three metrics at once.
    """
    temps = TempFiles()
    with handle_errors(temps, _CLIENT_ERRORS):
        validate_config_file_extension(file.filename)
        input_path = temps.add(save_upload_file(file))
        ag = AttackGraphs(input_path, "unused")
        ag.load()

        nodes = []
        if algorithm in ("betweenness", "all"):
            betweenness = ag.betweenness_centrality(top_n=limit)
            for node in betweenness:
                nodes.append(
                    {
                        "id": node["id"],
                        "label": node["label"],
                        "type": node["type"],
                        "betweenness_centrality": node.get("betweenness_centrality"),
                    }
                )

        if algorithm in ("closeness", "all"):
            closeness = ag.closeness_centrality(top_n=limit)
            if algorithm == "closeness":
                for node in closeness:
                    nodes.append(
                        {
                            "id": node["id"],
                            "label": node["label"],
                            "type": node["type"],
                            "closeness_centrality": node.get("closeness_centrality"),
                        }
                    )
            else:
                # Merge with existing nodes
                closeness_map = {n["id"]: n.get("closeness_centrality") for n in closeness}
                for node in nodes:
                    node["closeness_centrality"] = closeness_map.get(node["id"])

        if algorithm in ("pagerank", "all"):
            pr = ag.pagerank(top_n=limit)
            if algorithm == "pagerank":
                for node in pr:
                    nodes.append(
                        {
                            "id": node["id"],
                            "label": node["label"],
                            "type": node["type"],
                            "pagerank": node.get("pagerank"),
                        }
                    )
            else:
                # Merge with existing nodes
                pr_map = {n["id"]: n.get("pagerank") for n in pr}
                for node in nodes:
                    node["pagerank"] = pr_map.get(node["id"])

        return {"nodes": nodes[:limit], "algorithm": algorithm, "total_nodes": len(ag._adjacency)}


@router.post("/analyze/graph-metrics", summary="Get comprehensive graph metrics")
@limiter.limit(RATE_LIMIT_ANALYZE)
async def analyze_graph_metrics(
    request: Request,
    file: UploadFile = File(..., description="Configuration file containing attack graph definition"),
):
    """
    Get comprehensive metrics about the attack graph structure.

    Returns:
    - Node and edge counts
    - Graph density
    - Diameter (longest shortest path)
    - Strongly connected components
    - Cycle detection
    - Node type distribution
    """
    temps = TempFiles()
    with handle_errors(temps, _CLIENT_ERRORS):
        validate_config_file_extension(file.filename)
        input_path = temps.add(save_upload_file(file))
        ag = AttackGraphs(input_path, "unused")
        ag.load()

        metrics = ag.get_graph_metrics()
        return metrics


@router.post("/analyze/chokepoints", summary="Identify network chokepoints")
@limiter.limit(RATE_LIMIT_ANALYZE)
async def analyze_chokepoints(
    request: Request,
    file: UploadFile = File(..., description="Configuration file containing attack graph definition"),
    limit: int = Query(10, ge=1, le=50, description="Number of top chokepoints to return"),
):
    """
    Identify network chokepoints based on betweenness centrality.

    Chokepoints are nodes that many attack paths must traverse.
    Securing these nodes can disrupt multiple attack vectors.

    Returns nodes sorted by betweenness score with criticality assessment.
    """
    temps = TempFiles()
    with handle_errors(temps, _CLIENT_ERRORS):
        validate_config_file_extension(file.filename)
        input_path = temps.add(save_upload_file(file))
        ag = AttackGraphs(input_path, "unused")
        ag.load()

        chokepoints = ag.find_chokepoints(top_n=limit)

        return {"chokepoints": chokepoints, "total_analyzed": len(ag._adjacency)}


@router.post("/analyze/attack-surface", summary="Identify attack surface entry points")
@limiter.limit(RATE_LIMIT_ANALYZE)
async def analyze_attack_surface(
    request: Request,
    file: UploadFile = File(..., description="Configuration file containing attack graph definition"),
):
    """
    Identify attack surface entry points in the network.

    Entry points are nodes with no incoming edges (sources) or
    nodes explicitly marked as external/internet-facing.

    Returns entry points sorted by reachable nodes (attack surface size).
    """
    temps = TempFiles()
    with handle_errors(temps, _CLIENT_ERRORS):
        validate_config_file_extension(file.filename)
        input_path = temps.add(save_upload_file(file))
        ag = AttackGraphs(input_path, "unused")
        ag.load()

        entry_points = ag.find_attack_surfaces()

        return {"entry_points": entry_points, "total_attack_surface": len(entry_points)}


@router.post("/analyze/vulnerability-impact", summary="Calculate vulnerability impact score")
@limiter.limit(RATE_LIMIT_ANALYZE)
async def analyze_vulnerability_impact(
    request: Request,
    file: UploadFile = File(..., description="Configuration file containing attack graph definition"),
    vulnerability_id: str = Query(..., description="Vulnerability node ID to analyze"),
):
    """
    Calculate impact score for a specific vulnerability.

    Combines CVSS score with graph position to estimate real impact.
    Vulnerabilities that lead to more critical assets score higher.

    Returns impact metrics including reachable nodes and privilege targets.
    """
    temps = TempFiles()
    with handle_errors(temps, _CLIENT_ERRORS):
        validate_config_file_extension(file.filename)
        input_path = temps.add(save_upload_file(file))
        ag = AttackGraphs(input_path, "unused")
        ag.load()

        impact = ag.vulnerability_impact_score(vulnerability_id)

        if "error" in impact:
            # SECURITY: Use generic error message to prevent information disclosure
            logger.warning(f"Vulnerability impact error: {impact.get('error', 'unknown')}")
            raise HTTPException(status_code=404, detail="Vulnerability not found or cannot be analyzed")

        return impact


@router.post("/validate/attack-graph", summary="Validate attack graph structure")
@limiter.limit(RATE_LIMIT_ANALYZE)
async def validate_attack_graph(
    request: Request,
    file: UploadFile = File(..., description="Configuration file containing attack graph definition"),
):
    """
    Validate an attack graph structure and return any errors found.

    Checks for:
    - Missing required sections
    - Undefined host references
    - Invalid exploit preconditions/postconditions
    - Network connectivity issues
    """
    temps = TempFiles()
    with handle_errors(temps, _CLIENT_ERRORS):
        validate_config_file_extension(file.filename)
        input_path = temps.add(save_upload_file(file))
        ag = AttackGraphs(input_path, "unused")
        errors = ag.validate()

        return {"valid": len(errors) == 0, "errors": errors}
