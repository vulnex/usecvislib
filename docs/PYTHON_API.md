# USecVisLib Python API Guide

Complete Python API reference for the Universal Security Visualization Library.

---

## Table of Contents

1. [Installation](#installation)
2. [Quick Start](#quick-start)
3. [Module Reference](#module-reference)
   - [AttackTrees](#attacktrees)
   - [AttackGraphs](#attackgraphs)
     - [NetworkX Advanced Analysis](#networkx-advanced-analysis)
   - [ThreatModeling](#threatmodeling)
   - [BinVis](#binvis)
     - [Configuration System](#configuration-system)
   - [CustomDiagrams](#customdiagrams)
   - [CVSS Module](#cvss-module)
   - [Settings Module](#settings-module)
   - [Templates](#templates)
4. [Fluent Interface](#fluent-interface)
5. [Builder Pattern](#builder-pattern)
6. [Result Classes](#result-classes)
7. [Batch Processing](#batch-processing)
8. [Export Functionality](#export-functionality)
9. [Async Support](#async-support)
10. [Diff and Comparison](#diff-and-comparison)
11. [Constants and Enums](#constants-and-enums)
12. [Utility Functions](#utility-functions)
13. [Error Handling](#error-handling)
14. [Advanced Usage](#advanced-usage)
15. [Integration Examples](#integration-examples)

---

## Installation

```bash
# Install from source
pip install -e .

# Or install dependencies directly
pip install -r requirements.txt
```

### Verify Installation

```python
import usecvislib
print(usecvislib.__version__)  # 0.2.9
```

---

## Quick Start

### Classic API

```python
from usecvislib import AttackTrees, AttackGraphs, ThreatModeling, BinVis, CustomDiagrams

# Attack Tree
at = AttackTrees("attack.toml", "output", format="png", styleid="at_neon")
at.BuildAttackTree()

# Attack Graph
ag = AttackGraphs("network.toml", "graph", format="png", styleid="ag_security")
ag.BuildAttackGraph()
paths = ag.find_attack_paths("attacker", "database")

# Threat Model
tm = ThreatModeling("threat.toml", "diagram", format="png")
tm.BuildThreatModel()
threats = tm.analyze_stride()

# Binary Visualization
bv = BinVis("binary.exe", "analysis", format="png")
bv.BuildBinVis("all")
stats = bv.get_file_stats()
```

### Modern Fluent API

```python
from usecvislib import AttackTrees, AttackGraphs

# Method chaining
at = AttackTrees("attack.toml", "output").load().render().draw()

# Or use build() shorthand
ag = AttackGraphs("network.toml", "graph").build()

# Context manager
with AttackGraphs("network.toml", "graph") as ag:
    ag.build()
    stats = ag.get_stats()
```

### Builder Pattern

```python
from usecvislib import AttackTreeBuilder

# Programmatic tree creation
tree = (
    AttackTreeBuilder("Web Attack", "Compromise Server")
    .add_node("Compromise Server", fillcolor="red")
    .add_node("SQL Injection", fillcolor="orange")
    .add_node("XSS Attack", fillcolor="orange")
    .add_edge("Compromise Server", "SQL Injection", label="OR")
    .add_edge("Compromise Server", "XSS Attack", label="OR")
    .to_attack_tree("output")
    .build()
)
```

### Batch Processing

```python
from usecvislib import BatchProcessor

processor = BatchProcessor("attack_graph", "./output", format="png")
result = processor.process_directory("./configs")
print(f"Success: {result.success_count}/{result.total}")
```

### Async Support

```python
import asyncio
from usecvislib import AttackGraphs, async_wrap

async def main():
    ag = AttackGraphs("network.toml", "output")
    async_ag = async_wrap(ag)
    await async_ag.build()
    stats = await async_ag.get_stats()
    return stats

stats = asyncio.run(main())
```

---

## Module Reference

### AttackTrees

Create hierarchical attack tree visualizations with AND/OR gates.

#### Import

```python
from usecvislib import AttackTrees, AttackTreeError
```

#### Constructor

```python
AttackTrees(
    inputfile: str,      # Path to configuration file (TOML/JSON/YAML)
    outputfile: str,     # Output file path (without extension)
    format: str = "png", # Output format: png, pdf, svg, dot
    styleid: str = "at_default"  # Style identifier
)
```

#### Methods

##### `load(inputfile: str = None) -> Dict[str, Any]`

Load attack tree data from configuration file.

```python
at = AttackTrees("attack.toml", "output")
data = at.load()
print(data["tree"]["name"])  # "Web Application Attack"
```

##### `Render() -> None`

Build the attack tree graph from loaded data. Must call `load()` first.

```python
at.load()
at.Render()  # Creates internal Graphviz object
```

##### `draw(outputfile: str = None) -> None`

Render the graph to file. Must call `Render()` first.

```python
at.load()
at.Render()
at.draw()  # Saves to output.png
```

##### `BuildAttackTree() -> None`

Main entry point - loads, renders, and draws in one call.

```python
at = AttackTrees("attack.toml", "output")
at.BuildAttackTree()  # Complete workflow
```

##### `get_tree_stats() -> Dict[str, Any]`

Get statistical summary of the attack tree.

```python
at = AttackTrees("attack.toml", "output")
stats = at.get_tree_stats()
print(stats)
# {
#     "name": "Web Application Attack",
#     "root": "Compromise Web App",
#     "total_nodes": 12,
#     "total_edges": 14,
#     "leaf_nodes": 5,
#     "internal_nodes": 7
# }
```

##### `validate() -> List[str]`

Validate the attack tree structure. Returns list of error messages.

```python
at = AttackTrees("attack.toml", "output")
errors = at.validate()
if errors:
    for error in errors:
        print(f"Validation error: {error}")
else:
    print("Attack tree is valid")
```

##### `loadstyle() -> None`

Load style configuration. Called automatically in constructor.

```python
at = AttackTrees("attack.toml", "output", styleid="at_neon")
# Style is loaded automatically
print(at.style)  # Style configuration dict
```

#### Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `inputfile` | `str` | Input configuration file path |
| `outputfile` | `str` | Output file path |
| `format` | `str` | Output format |
| `styleid` | `str` | Style identifier |
| `inputdata` | `Dict` | Parsed configuration data |
| `style` | `Dict` | Style configuration |
| `dot` | `Digraph` | Graphviz Digraph object |

#### Configuration Format

```toml
[tree]
name = "Attack Tree Name"
root = "Root Node"
params = { rankdir = "TB" }  # TB, LR, BT, RL

[nodes]
"Root Node" = {style="filled", fillcolor="red", fontcolor="white"}
"Child Node" = {style="filled", fillcolor="orange"}

[edges]
"Root Node" = [
    {to = "Child Node", label = "OR"},
    {to = "Another Child", label = "AND"}
]
```

#### Available Styles

```python
# Use any of these style IDs
styles = [
    "at_default", "at_white_black", "at_black_white", "at_corporate",
    "at_neon", "at_pastel", "at_forest", "at_fire", "at_blueprint",
    "at_sunset", "at_hacker", "at_minimal", "at_plain"
]
```

---

### AttackGraphs

Create network attack path visualizations with path finding and critical node analysis.

#### Import

```python
from usecvislib import AttackGraphs, AttackGraphError
```

#### Constructor

```python
AttackGraphs(
    inputfile: str,      # Path to configuration file (TOML/JSON/YAML)
    outputfile: str,     # Output file path (without extension)
    format: str = "png", # Output format: png, pdf, svg, dot
    styleid: str = "ag_default"  # Style identifier
)
```

#### Methods

##### `load(inputfile: str = None) -> Dict[str, Any]`

Load attack graph data from configuration file.

```python
ag = AttackGraphs("network.toml", "graph")
data = ag.load()
print(data["graph"]["name"])  # "Corporate Network"
```

##### `Render() -> None`

Build the attack graph from loaded data.

```python
ag.load()
ag.Render()
```

##### `draw(outputfile: str = None) -> None`

Render the graph to file.

```python
ag.load()
ag.Render()
ag.draw()
```

##### `BuildAttackGraph() -> None`

Main entry point - complete workflow.

```python
ag = AttackGraphs("network.toml", "graph", styleid="ag_security")
ag.BuildAttackGraph()
```

##### `find_attack_paths(source: str, target: str, max_paths: int = 10, max_depth: int = 20) -> List[List[str]]`

Find all attack paths from source to target using DFS.

```python
ag = AttackGraphs("network.toml", "graph")
ag.load()

# Find paths from attacker to database admin privilege
paths = ag.find_attack_paths("attacker", "priv_db_admin")

for i, path in enumerate(paths, 1):
    print(f"Path {i}: {' -> '.join(path)}")
# Path 1: attacker -> exploit_rce -> priv_web_shell -> exploit_sqli -> priv_db_admin
```

##### `shortest_path(source: str, target: str) -> List[str]`

Find shortest attack path using BFS.

```python
ag = AttackGraphs("network.toml", "graph")
ag.load()

shortest = ag.shortest_path("attacker", "priv_db_admin")
print(f"Shortest path: {' -> '.join(shortest)}")
print(f"Length: {len(shortest)}")
```

##### `analyze_critical_nodes(top_n: int = 10) -> List[Dict[str, Any]]`

Identify critical nodes based on connectivity (degree centrality).

```python
ag = AttackGraphs("network.toml", "graph")
ag.load()

critical = ag.analyze_critical_nodes(top_n=5)

for node in critical:
    print(f"{node['label']} ({node['type']})")
    print(f"  In-degree: {node['in_degree']}")
    print(f"  Out-degree: {node['out_degree']}")
    print(f"  Criticality: {node['criticality_score']}")
```

**Returns:**

```python
[
    {
        "id": "webserver",
        "label": "Web Server",
        "type": "host",
        "in_degree": 2,
        "out_degree": 3,
        "total_degree": 5,
        "criticality_score": 5
    },
    # ...
]
```

##### `get_graph_stats() -> Dict[str, Any]`

Get statistical summary of the attack graph.

```python
ag = AttackGraphs("network.toml", "graph")
stats = ag.get_graph_stats()
print(stats)
# {
#     "name": "Corporate Network",
#     "total_hosts": 4,
#     "total_vulnerabilities": 3,
#     "total_privileges": 5,
#     "total_services": 3,
#     "total_exploits": 5,
#     "network_edges": 3,
#     "exploit_edges": 10,
#     "total_nodes": 15,
#     "total_edges": 13,
#     "average_cvss": 8.43,
#     "critical_vulnerabilities": 1
# }
```

##### `validate() -> List[str]`

Validate the attack graph structure.

```python
ag = AttackGraphs("network.toml", "graph")
errors = ag.validate()
if errors:
    for error in errors:
        print(f"Error: {error}")
```

---

#### NetworkX Advanced Analysis

These methods leverage NetworkX for advanced graph analysis. They provide deeper insights into attack graph structure and security implications.

##### `betweenness_centrality(top_n: int = 10) -> List[Dict[str, Any]]`

Calculate betweenness centrality - nodes that appear on many shortest paths.

```python
ag = AttackGraphs("network.toml", "graph")
ag.load()

centrality = ag.betweenness_centrality(top_n=5)
for node in centrality:
    print(f"{node['label']}: {node['betweenness_centrality']:.4f}")
```

##### `closeness_centrality(top_n: int = 10) -> List[Dict[str, Any]]`

Calculate closeness centrality - nodes closest to all other nodes.

```python
closeness = ag.closeness_centrality(top_n=5)
for node in closeness:
    print(f"{node['label']}: {node['closeness_centrality']:.4f}")
```

##### `pagerank(top_n: int = 10, alpha: float = 0.85) -> List[Dict[str, Any]]`

Calculate PageRank centrality - node importance based on incoming connections.

```python
pr = ag.pagerank(top_n=5)
for node in pr:
    print(f"{node['label']}: {node['pagerank']:.4f}")
```

##### `k_shortest_paths(source: str, target: str, k: int = 5) -> List[List[str]]`

Find the k shortest paths between two nodes.

```python
paths = ag.k_shortest_paths("attacker", "priv_db_admin", k=3)
for i, path in enumerate(paths, 1):
    print(f"Path {i} (length {len(path)}): {' -> '.join(path)}")
```

##### `all_paths_between(source: str, target: str, cutoff: int = 10) -> Iterator[List[str]]`

Generator that yields all simple paths between two nodes (up to cutoff length).

```python
for path in ag.all_paths_between("attacker", "database", cutoff=8):
    print(f"Path: {' -> '.join(path)}")
```

##### `find_cycles() -> List[List[str]]`

Find all cycles in the attack graph.

```python
cycles = ag.find_cycles()
print(f"Found {len(cycles)} cycles")
for cycle in cycles:
    print(f"  Cycle: {' -> '.join(cycle)}")
```

##### `strongly_connected_components() -> List[Set[str]]`

Find strongly connected components (SCCs).

```python
sccs = ag.strongly_connected_components()
print(f"Found {len(sccs)} strongly connected components")
for i, scc in enumerate(sccs, 1):
    print(f"  SCC {i}: {scc}")
```

##### `graph_density() -> float`

Calculate the density of the graph (0 to 1).

```python
density = ag.graph_density()
print(f"Graph density: {density:.4f}")
```

##### `diameter() -> int`

Calculate the diameter (longest shortest path) of the graph.

```python
d = ag.diameter()
print(f"Graph diameter: {d}")
```

##### `find_chokepoints(top_n: int = 10) -> List[Dict[str, Any]]`

Find network chokepoints - critical nodes that many attack paths traverse.

```python
chokepoints = ag.find_chokepoints(top_n=5)
for cp in chokepoints:
    print(f"{cp['label']} ({cp['type']})")
    print(f"  Betweenness score: {cp['betweenness_score']:.4f}")
    print(f"  Is critical: {cp['is_critical']}")
```

**Returns:**

```python
[
    {
        "id": "webserver",
        "label": "Web Server",
        "type": "host",
        "betweenness_score": 0.4523,
        "in_degree": 2,
        "out_degree": 3,
        "is_critical": True
    },
    # ...
]
```

##### `find_attack_surfaces() -> List[Dict[str, Any]]`

Find attack entry points sorted by reachability.

```python
surfaces = ag.find_attack_surfaces()
for ep in surfaces:
    print(f"{ep['label']}: {ep['reachable_nodes']} nodes reachable")
```

**Returns:**

```python
[
    {
        "id": "attacker",
        "label": "External Attacker",
        "type": "host",
        "out_degree": 3,
        "reachable_nodes": 12
    },
    # ...
]
```

##### `vulnerability_impact_score(vuln_id: str) -> Dict[str, Any]`

Calculate the network-wide impact of a specific vulnerability.

```python
impact = ag.vulnerability_impact_score("vuln_rce")
print(f"Impact score: {impact['impact_score']:.2f}")
print(f"Reachable nodes: {impact['reachable_nodes']}")
print(f"Affected hosts: {impact['affected_hosts']}")
```

**Returns:**

```python
{
    "vulnerability_id": "vuln_rce",
    "cvss_score": 9.8,
    "impact_score": 8.75,
    "reachable_nodes": 8,
    "affected_hosts": 3,
    "paths_through": 5
}
```

##### `get_graph_metrics() -> Dict[str, Any]`

Get comprehensive graph metrics in one call.

```python
metrics = ag.get_graph_metrics()
print(f"Density: {metrics['density']:.4f}")
print(f"Diameter: {metrics['diameter']}")
print(f"Number of cycles: {metrics['num_cycles']}")
print(f"SCCs: {metrics['num_strongly_connected_components']}")
print(f"Is DAG: {metrics['is_dag']}")
print(f"Avg clustering: {metrics['average_clustering']:.4f}")
```

**Returns:**

```python
{
    "density": 0.1234,
    "diameter": 5,
    "num_cycles": 0,
    "num_strongly_connected_components": 1,
    "is_dag": True,
    "average_clustering": 0.0
}
```

---

#### Configuration Format

```toml
[graph]
name = "Network Attack Graph"
description = "Description of the network"

[[hosts]]
id = "attacker"
label = "External Attacker"
zone = "external"

[[hosts]]
id = "webserver"
label = "Web Server"
ip = "10.0.1.10"
zone = "dmz"
os = "Linux"

[[vulnerabilities]]
id = "vuln_rce"
label = "Remote Code Execution"
cvss = 9.8
affected_host = "webserver"

[[privileges]]
id = "priv_shell"
label = "Shell Access"
host = "webserver"
level = "user"

[[services]]
id = "svc_http"
label = "HTTP"
host = "webserver"
port = 80

[[exploits]]
id = "exploit_rce"
label = "Exploit RCE"
vulnerability = "vuln_rce"
precondition = "attacker"
postcondition = "priv_shell"

[[network_edges]]
from = "attacker"
to = "webserver"
label = "Internet Access"
```

#### Node Types

| Type | Prefix | Description |
|------|--------|-------------|
| Host | H | Network machines/servers |
| Vulnerability | V | CVEs or weaknesses |
| Privilege | P | Access levels (user, root, admin) |
| Service | S | Running services/ports |

---

### ThreatModeling

Create Data Flow Diagrams with STRIDE threat analysis.

#### Import

```python
from usecvislib import ThreatModeling
```

#### Constructor

```python
ThreatModeling(
    inputfile: str,           # Path to configuration file
    outputfile: str,          # Output file path
    format: str = "png",      # Output format
    styleid: str = "tm_default",  # Style identifier
    engine: str = "usecvislib"    # Engine: "usecvislib" or "pytm"
)
```

#### Methods

##### `load(inputfile: str = None) -> Dict[str, Any]`

Load threat model data from configuration file.

```python
tm = ThreatModeling("threat.toml", "diagram")
data = tm.load()
print(data["model"]["name"])
```

##### `Render() -> None`

Build the threat model graph from loaded data.

```python
tm.load()
tm.Render()
```

##### `draw(outputfile: str = None) -> None`

Render the graph to file.

```python
tm.load()
tm.Render()
tm.draw()
```

##### `BuildThreatModel() -> None`

Main entry point - complete workflow.

```python
tm = ThreatModeling("threat.toml", "diagram")
tm.BuildThreatModel()
```

##### `analyze_stride() -> Dict[str, List[Dict[str, str]]]`

Perform STRIDE threat analysis based on element properties.

```python
tm = ThreatModeling("threat.toml", "diagram")
tm.load()

threats = tm.analyze_stride()

for category, threat_list in threats.items():
    print(f"\n{category}:")
    for threat in threat_list[:3]:  # Top 3 per category
        print(f"  - {threat['element']}: {threat['threat']}")
        print(f"    Mitigation: {threat['mitigation']}")
```

**Returns:**

```python
{
    "Spoofing": [
        {
            "element": "Customer",
            "threat": "An attacker could impersonate Customer",
            "mitigation": "Implement strong authentication"
        }
    ],
    "Tampering": [...],
    "Repudiation": [...],
    "Information Disclosure": [...],
    "Denial of Service": [...],
    "Elevation of Privilege": [...]
}
```

##### `generate_stride_report(output: str = None) -> str`

Generate a STRIDE threat analysis report in Markdown format.

```python
tm = ThreatModeling("threat.toml", "diagram")
tm.load()

# Save to file
tm.generate_stride_report("stride_report.md")

# Or get as string
report = tm.generate_stride_report()
print(report)
```

##### `get_model_stats() -> Dict[str, Any]`

Get statistical summary of the threat model.

```python
tm = ThreatModeling("threat.toml", "diagram")
stats = tm.get_model_stats()
print(stats)
# {
#     "total_processes": 5,
#     "total_datastores": 3,
#     "total_externals": 2,
#     "total_dataflows": 8,
#     "total_boundaries": 2,
#     "flows_crossing_boundaries": 3,
#     "total_elements": 10
# }
```

##### `get_pytm_threats() -> List[Dict[str, Any]]`

Get threats from PyTM engine (only when using `engine="pytm"`).

```python
tm = ThreatModeling("threat.toml", "diagram", engine="pytm")
tm.BuildThreatModel()
pytm_threats = tm.get_pytm_threats()
```

##### `is_pytm_available() -> bool` (static)

Check if PyTM is installed.

```python
if ThreatModeling.is_pytm_available():
    tm = ThreatModeling("threat.toml", "diagram", engine="pytm")
else:
    tm = ThreatModeling("threat.toml", "diagram", engine="usecvislib")
```

##### `get_available_engines() -> List[str]` (static)

Get list of available engines.

```python
engines = ThreatModeling.get_available_engines()
print(engines)  # ["usecvislib", "pytm"]
```

#### Configuration Format

```toml
[model]
name = "System Name"
description = "System description"

[externals.user]
label = "User"
isAdmin = false
isTrusted = false

[externals.admin]
label = "Administrator"
isAdmin = true
isTrusted = true

[processes.webserver]
label = "Web Server"
authenticatesSource = true
sanitizesInput = true
checksInputBounds = true
hasAccessControl = true
isHardened = true

[datastores.database]
label = "Database"
isSQL = true
isEncrypted = true
storesPII = true
storesCredentials = true
hasBackup = true
isAuditLogged = true

[dataflows.user_to_web]
from = "user"
to = "webserver"
label = "HTTPS Request"
protocol = "HTTPS"
isEncrypted = true
authenticatesDestination = true

[boundaries.dmz]
label = "DMZ"
elements = ["webserver"]
trustLevel = 50
```

#### Element Properties

**Processes:**

| Property | Type | STRIDE Impact |
|----------|------|---------------|
| `authenticatesSource` | bool | Spoofing |
| `sanitizesInput` | bool | Tampering |
| `checksInputBounds` | bool | Tampering, DoS |
| `hasAccessControl` | bool | Elevation of Privilege |
| `isHardened` | bool | DoS |
| `implementsCSRFToken` | bool | Tampering |
| `handlesResourceConsumption` | bool | DoS |

**Data Stores:**

| Property | Type | STRIDE Impact |
|----------|------|---------------|
| `isEncrypted` | bool | Information Disclosure |
| `isSQL` | bool | Tampering |
| `storesPII` | bool | Information Disclosure |
| `storesCredentials` | bool | Information Disclosure |
| `hasAccessControl` | bool | Tampering |
| `hasBackup` | bool | DoS |
| `isAuditLogged` | bool | Repudiation |

**Data Flows:**

| Property | Type | STRIDE Impact |
|----------|------|---------------|
| `isEncrypted` | bool | Tampering, Info Disclosure |
| `authenticatesSource` | bool | Spoofing |
| `authenticatesDestination` | bool | Spoofing |
| `isPII` | bool | Information Disclosure |
| `isCredentials` | bool | Information Disclosure |
| `checksDestinationRevocation` | bool | Spoofing |

---

### BinVis

Visualize binary file patterns, entropy, and structure.

#### Import

```python
from usecvislib import BinVis
```

#### Constructor

```python
BinVis(
    inputfile: str,      # Path to binary file
    outputfile: str,     # Output file path (without extension)
    format: str = "png", # Output format: png, pdf, svg
    styleid: str = "bv_default"  # Style identifier
)
```

#### Methods

##### `load() -> bytes`

Load binary data from input file.

```python
bv = BinVis("binary.exe", "analysis")
data = bv.load()
print(f"Loaded {len(data)} bytes")
```

##### `calculate_entropy(data: bytes, base: int = 2) -> float`

Calculate Shannon entropy of binary data.

```python
bv = BinVis("binary.exe", "analysis")
bv.load()

entropy = bv.calculate_entropy(bv.data)
print(f"Entropy: {entropy:.4f} bits")
# 0.0 = completely uniform (e.g., all zeros)
# 8.0 = maximum randomness (encrypted/compressed)
```

##### `sliding_entropy(window_size: int = 256, step: int = 64) -> Tuple[ndarray, ndarray]`

Calculate entropy using a sliding window across the file.

```python
bv = BinVis("binary.exe", "analysis")
bv.load()

positions, entropies = bv.sliding_entropy(window_size=512, step=128)

# Find sections with high entropy (possibly encrypted)
high_entropy_sections = positions[entropies > 7.5]
```

##### `byte_distribution() -> ndarray`

Calculate byte frequency distribution (256 values).

```python
bv = BinVis("binary.exe", "analysis")
bv.load()

dist = bv.byte_distribution()
print(f"Null byte frequency: {dist[0]:.4f}")
print(f"Most common printable: {dist[32:127].argmax() + 32}")
```

##### `visualize_entropy(window_size: int = 256, step: int = 64, output: str = None) -> None`

Create entropy visualization with sliding window.

```python
bv = BinVis("binary.exe", "analysis")
bv.load()
bv.visualize_entropy(window_size=512)
# Creates: analysis_entropy.png
```

##### `visualize_distribution(output: str = None) -> None`

Create byte frequency distribution visualization.

```python
bv = BinVis("binary.exe", "analysis")
bv.load()
bv.visualize_distribution()
# Creates: analysis_distribution.png
```

##### `visualize_windrose(output: str = None) -> None`

Create wind rose diagram showing byte pair patterns.

```python
bv = BinVis("binary.exe", "analysis")
bv.load()
bv.visualize_windrose()
# Creates: analysis_windrose.png
```

##### `visualize_heatmap(block_size: int = 256, output: str = None) -> None`

Create a 2D heatmap visualization of the binary file.

```python
bv = BinVis("binary.exe", "analysis")
bv.load()
bv.visualize_heatmap(block_size=512)
# Creates: analysis_heatmap.png
```

##### `visualize_all(output_prefix: str = None) -> List[str]`

Generate all visualization types.

```python
bv = BinVis("binary.exe", "analysis")
outputs = bv.visualize_all()
print(outputs)
# ['analysis_entropy.png', 'analysis_distribution.png',
#  'analysis_windrose.png', 'analysis_heatmap.png']
```

##### `BuildBinVis(visualization: str = "all") -> None`

Main entry point for binary visualization.

```python
bv = BinVis("binary.exe", "analysis")

# All visualizations
bv.BuildBinVis("all")

# Specific visualization
bv.BuildBinVis("entropy")
bv.BuildBinVis("distribution")
bv.BuildBinVis("windrose")
bv.BuildBinVis("heatmap")
```

##### `get_file_stats() -> Dict[str, Any]`

Get statistical summary of the binary file.

```python
bv = BinVis("binary.exe", "analysis")
stats = bv.get_file_stats()
print(stats)
# {
#     "file_size": 1234567,
#     "entropy": 7.4523,
#     "unique_bytes": 256,
#     "most_common": [(0, 12345), (255, 9876), ...],
#     "null_percentage": 2.34,
#     "printable_percentage": 45.67,
#     "high_byte_percentage": 28.90
# }
```

#### Interpreting Results

| Entropy Range | Typical Content | Interpretation |
|---------------|-----------------|----------------|
| 0.0 - 1.0 | Sparse data | Repeated patterns, padding |
| 1.0 - 4.0 | Text, code | Source code, ASCII text |
| 4.0 - 6.0 | Mixed content | Compiled code, structured data |
| 6.0 - 7.5 | Complex data | Compressed data |
| 7.5 - 8.0 | Random data | Encrypted or highly compressed |

#### Configuration System

BinVis supports user-configurable visualization parameters via TOML configuration files.

##### Loading Configuration

```python
# Load with configuration file
bv = BinVis("binary.exe", "analysis", configfile="binvis_config.toml")

# Or load configuration after initialization
bv = BinVis("binary.exe", "analysis")
bv.loadconfig("binvis_config.toml")
```

##### Configuration Parameters

```toml
# binvis_config.toml

[entropy]
window_size = 256       # Sliding window size
step = 64               # Step between windows
dpi = 150               # Output DPI
show_thresholds = true  # Show threshold lines
fill_alpha = 0.3        # Fill transparency
show_grid = true        # Show grid
grid_alpha = 0.3        # Grid transparency

[[entropy.thresholds]]
value = 7.0
label = "Encrypted"
color = "red"

[[entropy.thresholds]]
value = 6.0
label = "Compressed"
color = "orange"

[distribution]
bar_width = 0.8         # Bar width
bar_alpha = 0.8         # Bar transparency
dpi = 150               # Output DPI
show_regions = true     # Show byte regions

[[distribution.regions]]
start = 0
end = 31
label = "Control"
color = "lightblue"

[[distribution.regions]]
start = 32
end = 126
label = "Printable"
color = "lightgreen"

[windrose]
bar_alpha = 0.8         # Bar transparency
dpi = 150               # Output DPI
rticks = [25, 50, 75, 100]  # Radial tick marks
rlabel_position = 45    # Label position (degrees)

[heatmap]
block_size = 256        # Bytes per block
dpi = 150               # Output DPI
interpolation = "nearest"  # Image interpolation
aspect = "auto"         # Aspect ratio
show_colorbar = true    # Show color bar
colorbar_label = "Byte Value"  # Colorbar label
```

##### Method Parameter Override

```python
# Config values can be overridden by method parameters
bv = BinVis("binary.exe", "analysis", configfile="config.toml")
bv.visualize_entropy(window_size=512)  # Overrides config value
```

---

### CustomDiagrams

Create flexible, schema-driven diagrams with custom node and edge types.

#### Import

```python
from usecvislib import CustomDiagrams
```

#### Constructor

```python
CustomDiagrams()
```

Unlike other modules, CustomDiagrams doesn't take constructor arguments. Configuration is loaded separately.

#### Methods

##### `load(filepath: str) -> Dict[str, Any]`

Load diagram configuration from file (TOML/JSON/YAML).

```python
cd = CustomDiagrams()
data = cd.load("diagram.toml")
print(data["diagram"]["title"])  # "My Diagram"
```

##### `load_template(template_name: str) -> Dict[str, Any]`

Load a built-in template.

```python
cd = CustomDiagrams()

# Load by name (searches in templates/custom-diagrams/)
cd.load_template("flowchart")

# Load by category/name
cd.load_template("software/architecture")
cd.load_template("network/topology")
```

##### `load_from_content(content: str, format: str = "toml") -> Dict[str, Any]`

Load configuration from string content.

```python
toml_content = """
[diagram]
title = "My Diagram"
layout = "hierarchical"

[schema.nodes.process]
shape = "rectangle"
style = { fillcolor = "#3498DB" }

[[nodes]]
id = "node1"
type = "process"
name = "Process 1"
"""

cd = CustomDiagrams()
cd.load_from_content(toml_content, format="toml")
```

##### `BuildCustomDiagram(output: str, format: str = "png", style: str = None) -> VisualizationResult`

Generate the diagram visualization.

```python
cd = CustomDiagrams()
cd.load("diagram.toml")

result = cd.BuildCustomDiagram(
    output="diagram",      # Output filename (without extension)
    format="png",          # Output format (png, svg, pdf, dot)
    style="cd_default"     # Style preset (optional)
)

print(f"Output: {result.output_path}")
print(f"Nodes: {result.stats['node_count']}")
print(f"Edges: {result.stats['edge_count']}")
```

**Returns:** `VisualizationResult`

```python
@dataclass
class VisualizationResult:
    output_path: str        # Path to generated file
    format: str             # Output format
    stats: Dict[str, Any]   # Diagram statistics
    success: bool           # Operation success
```

##### `validate() -> List[str]`

Validate the diagram configuration. Returns list of error messages.

```python
cd = CustomDiagrams()
cd.load("diagram.toml")
errors = cd.validate()

if errors:
    for error in errors:
        print(f"Error: {error}")
else:
    print("Configuration is valid")
```

##### `get_stats() -> Dict[str, Any]`

Get diagram statistics.

```python
cd = CustomDiagrams()
cd.load("diagram.toml")
stats = cd.get_stats()

print(stats)
# {
#     "title": "My Diagram",
#     "description": "...",
#     "node_count": 10,
#     "edge_count": 12,
#     "node_types": ["server", "database"],
#     "edge_types": ["connection"],
#     "layout": "hierarchical",
#     "direction": "TB"
# }
```

##### `get_available_shapes(category: str = None) -> List[Dict]`

Get available shapes from the gallery.

```python
cd = CustomDiagrams()

# Get all shapes
all_shapes = cd.get_available_shapes()

# Get shapes by category
security_shapes = cd.get_available_shapes(category="security")

for shape in security_shapes:
    print(f"{shape['id']}: {shape['name']}")
    # server: Server
    # database: Database
    # firewall: Firewall
    # ...
```

**Returns:**

```python
[
    {
        "id": "server",
        "name": "Server",
        "category": "security",
        "description": "A server or computing node",
        "graphviz": { "shape": "box3d", "style": "filled" },
        "default_style": { "fillcolor": "#4A90D9", "fontcolor": "white" },
        "tags": ["infrastructure", "compute"]
    },
    # ...
]
```

##### `get_available_templates() -> Dict[str, List[str]]`

Get available templates organized by category.

```python
cd = CustomDiagrams()
templates = cd.get_available_templates()

for category, template_list in templates.items():
    print(f"\n{category}:")
    for template in template_list:
        print(f"  - {template}")

# general:
#   - flowchart
#   - mindmap
#   - hierarchy
# software:
#   - architecture
#   - class-diagram
# ...
```

##### `get_shape_categories() -> List[str]`

Get list of available shape categories.

```python
cd = CustomDiagrams()
categories = cd.get_shape_categories()
print(categories)  # ["basic", "security", "network", "flow", "uml", "containers"]
```

#### Configuration Format

```toml
# Diagram settings
[diagram]
title = "My Diagram"
description = "Diagram description"
layout = "hierarchical"    # hierarchical, circular, force, grid
direction = "TB"           # TB, LR, BT, RL
style = "cd_default"       # Style preset
splines = "ortho"          # ortho, polyline, curved, line, spline
nodesep = 0.5              # Horizontal node spacing
ranksep = 1.0              # Vertical rank spacing

# Schema: Define node types
[schema.nodes.my_node_type]
shape = "rectangle"        # Shape from gallery
required_fields = ["name"] # Required fields
optional_fields = ["desc"] # Optional fields
style = { fillcolor = "#3498DB", fontcolor = "white" }
label_template = "{name}"  # Label format

# Schema: Define edge types
[schema.edges.my_edge_type]
style = "solid"            # solid, dashed, dotted, bold
color = "#333333"
arrowhead = "normal"       # normal, vee, dot, none, diamond

# Node data
[[nodes]]
id = "unique_id"
type = "my_node_type"
name = "Node Name"

# Edge data
[[edges]]
from = "node1_id"
to = "node2_id"
type = "my_edge_type"
label = "Optional label"

# Clusters (optional)
[[clusters]]
id = "cluster1"
label = "Group Name"
style = { bgcolor = "#F0F0F0" }
nodes = ["node1", "node2"]
```

#### Shape Categories

| Category | Description | Examples |
|----------|-------------|----------|
| `basic` | Geometric shapes | rectangle, circle, diamond, ellipse, hexagon |
| `security` | Security elements | server, database, firewall, cloud, user, attacker |
| `network` | Network components | router, switch, endpoint, laptop, mobile |
| `flow` | Flowchart shapes | process, decision, document, terminator |
| `uml` | UML elements | class, interface, package, component, actor |
| `containers` | Grouping elements | cluster, boundary, zone, subnet |

#### Available Styles

```python
styles = [
    "cd_default",      # Default light theme
    "cd_dark",         # Dark theme
    "cd_corporate",    # Professional colors
    "cd_neon",         # Vibrant neon
    "cd_minimal",      # Clean minimal
    "cd_blueprint",    # Blueprint style
    "cd_hacker",       # Green on black
    "cd_pastel",       # Soft pastels
    "cd_plain"         # No styling
]
```

#### Complete Example

```python
from usecvislib import CustomDiagrams

# Create instance
cd = CustomDiagrams()

# Load configuration
cd.load("network_diagram.toml")

# Validate
errors = cd.validate()
if errors:
    print("Validation errors:")
    for e in errors:
        print(f"  - {e}")
    exit(1)

# Get statistics
stats = cd.get_stats()
print(f"Diagram: {stats['title']}")
print(f"Nodes: {stats['node_count']}")
print(f"Edges: {stats['edge_count']}")

# Generate visualization
result = cd.BuildCustomDiagram(
    output="network",
    format="png",
    style="cd_corporate"
)

if result.success:
    print(f"Generated: {result.output_path}")
else:
    print("Failed to generate diagram")
```

See [Custom Diagrams Guide](CUSTOM_DIAGRAMS_GUIDE.md) for complete documentation.

---

### CVSS Module

Calculate and parse CVSS 3.x scores.

#### Import

```python
from usecvislib.cvss import (
    CVSSVersion,
    CVSSVector,
    parse_cvss_vector,
    calculate_cvss_from_vector,
    validate_cvss_vector,
    get_cvss_score
)
```

#### Parse CVSS Vector

```python
from usecvislib.cvss import parse_cvss_vector

# Parse a CVSS 3.1 vector string
vector = parse_cvss_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

print(f"Version: {vector.version}")      # CVSSVersion.V3_1
print(f"Base Score: {vector.base_score}")  # 9.8
print(f"Attack Vector: {vector.attack_vector}")  # AttackVector.NETWORK
print(f"Scope: {vector.scope}")           # Scope.UNCHANGED
```

#### Calculate Score from Vector

```python
from usecvislib.cvss import calculate_cvss_from_vector

score = calculate_cvss_from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N")
print(f"Score: {score}")  # 6.1
```

#### Validate Vector String

```python
from usecvislib.cvss import validate_cvss_vector

is_valid, error = validate_cvss_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
if is_valid:
    print("Valid vector")
else:
    print(f"Invalid: {error}")
```

#### Get Score from Value or Vector

```python
from usecvislib.cvss import get_cvss_score

# From numeric value
score, calculated = get_cvss_score(9.8, None)
print(f"Score: {score}, Calculated: {calculated}")  # 9.8, False

# From vector string
score, calculated = get_cvss_score(None, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
print(f"Score: {score}, Calculated: {calculated}")  # 9.8, True
```

#### CVSS Enums

```python
from usecvislib.cvss import (
    CVSSVersion,      # V3_0, V3_1
    AttackVector,     # NETWORK, ADJACENT, LOCAL, PHYSICAL
    AttackComplexity, # LOW, HIGH
    PrivilegesRequired,  # NONE, LOW, HIGH
    UserInteraction,  # NONE, REQUIRED
    Scope,            # UNCHANGED, CHANGED
    Impact            # NONE, LOW, HIGH
)
```

#### Severity Helpers

```python
from usecvislib.constants import (
    cvss_to_color,
    cvss_to_severity_label,
    cvss_to_risk_level,
    validate_cvss_score
)

# Get severity color
color = cvss_to_color(9.8)  # "#8b0000" (dark red for Critical)

# Get severity label
label = cvss_to_severity_label(9.8)  # "Critical"

# Validate score range
is_valid = validate_cvss_score(9.8)  # True (0.0-10.0)
```

---

### Settings Module

Manage display settings including CVSS visibility.

#### Import

```python
from usecvislib.settings import DisplaySettings
```

#### Get Settings Instance

```python
# DisplaySettings is a singleton
settings = DisplaySettings()
```

#### CVSS Display Control

```python
settings = DisplaySettings()

# Check if CVSS is enabled globally
if settings.is_cvss_enabled():
    print("CVSS display is enabled")

# Check for specific visualization type
if settings.is_cvss_enabled("attack_graph"):
    print("CVSS enabled for attack graphs")

# Enable/disable for specific type
settings.set_cvss_enabled("attack_tree", True)
settings.set_cvss_enabled("threat_model", False)

# Enable/disable all
settings.enable_cvss_all()
settings.disable_cvss_all()

# Reset to defaults
settings.reset()
```

#### Get/Set All Settings

```python
# Get current settings as dict
current = settings.get_cvss_display()
# {
#     "enabled": True,
#     "attack_tree": True,
#     "attack_graph": True,
#     "threat_model": True
# }

# Update settings
settings.set_cvss_display({
    "enabled": True,
    "attack_tree": True,
    "attack_graph": False,
    "threat_model": True
})
```

#### Export/Import Settings

```python
# Export to dict
data = settings.to_dict()

# Import from dict
settings.from_dict(data)
```

---

### Templates

Access built-in configuration templates.

#### Available Templates

| Category | Templates |
|----------|-----------|
| Attack Trees | `insider_threat`, `ransomware_attack`, `web_application_attack` |
| Attack Graphs | `cloud_infrastructure`, `corporate_network`, `simple_network` |
| Threat Models | `banking_api`, `cicd_pipeline`, `cloud_infrastructure`, `ecommerce_platform`, `healthcare_system`, `iot_system`, `microservices_architecture`, `saas_multitenant` |

#### Loading Templates

```python
from usecvislib import AttackTrees

# Load from templates directory
at = AttackTrees("templates/attack-trees/ransomware_attack.tml", "output")
at.BuildAttackTree()
```

#### Template Formats

All templates are available in three formats:
- TOML (`.tml`)
- JSON (`.json`)
- YAML (`.yaml`)

#### Template Metadata

Templates include metadata fields:

```python
from usecvislib import AttackGraphs

ag = AttackGraphs("templates/attack-graphs/corporate_network.tml", "output")
ag.load()

# Get metadata
metadata = ag.get_metadata()
print(metadata)
# TemplateMetadata(
#     name="Corporate Network Attack",
#     description="Attack paths through corporate infrastructure",
#     version="1.0.0",
#     engineversion="0.2.9",
#     type="Attack Graph",
#     date="2025-12-25",
#     last_modified="2025-12-27",
#     author="VULNEX",
#     email="info@vulnex.com",
#     url="https://www.vulnex.com"
# )
```

---

## Fluent Interface

All visualization classes support method chaining for cleaner code:

### Method Chaining

```python
from usecvislib import AttackGraphs

# Chain methods together
ag = (
    AttackGraphs("network.toml", "output")
    .load()
    .render()
    .draw()
)

# Or use build() as shorthand for load().render().draw()
ag = AttackGraphs("network.toml", "output").build()
```

### Context Manager

```python
from usecvislib import AttackTrees

with AttackTrees("attack.toml", "output") as at:
    at.build()
    stats = at.get_stats()
    # Resources cleaned up automatically
```

### Available Methods

| Method | Description | Returns |
|--------|-------------|---------|
| `load()` | Load configuration file | `self` |
| `render()` | Build visualization graph | `self` |
| `draw()` | Save to output file | `self` |
| `build()` | Shorthand for load().render().draw() | `self` |
| `validate()` | Check configuration validity | `List[str]` |
| `get_stats()` | Get statistics | `Dict` |

---

## Builder Pattern

Create visualizations programmatically without configuration files:

### AttackTreeBuilder

```python
from usecvislib import AttackTreeBuilder

tree = (
    AttackTreeBuilder("API Security Attack", "Compromise API")
    .add_node("Compromise API", fillcolor="#e74c3c", fontcolor="white")
    .add_node("Authentication Bypass", fillcolor="#3498db")
    .add_node("Broken Auth", fillcolor="#5dade2")
    .add_node("Token Theft", fillcolor="#5dade2")
    .add_edge("Compromise API", "Authentication Bypass")
    .add_edge("Authentication Bypass", "Broken Auth", label="OR")
    .add_edge("Authentication Bypass", "Token Theft", label="OR")
    .to_attack_tree("output", format="png")
    .build()
)
```

#### Methods

| Method | Description |
|--------|-------------|
| `add_node(id, label=None, **attrs)` | Add a node with attributes |
| `add_edge(from_node, to_node, label="", **attrs)` | Add an edge |
| `set_params(**params)` | Set graph parameters (rankdir, etc.) |
| `build()` | Get the data dictionary |
| `to_attack_tree(output, format="png")` | Create AttackTrees instance |

### AttackGraphBuilder

```python
from usecvislib import AttackGraphBuilder

graph = (
    AttackGraphBuilder("Corporate Network")
    .add_host("attacker", "External Attacker", zone="external")
    .add_host("webserver", "Web Server", ip="10.0.1.10", zone="dmz")
    .add_host("database", "Database", ip="10.0.2.10", zone="internal")
    .add_vulnerability("vuln_rce", "RCE", cvss=9.8, affected_host="webserver")
    .add_privilege("priv_shell", "Shell Access", host="webserver", level="user")
    .add_service("svc_http", "HTTP", host="webserver", port=80)
    .add_exploit("exploit_rce", "Exploit RCE",
                 vulnerability="vuln_rce",
                 precondition="attacker",
                 postcondition="priv_shell")
    .add_network_edge("attacker", "webserver", label="Internet")
    .to_attack_graph("output")
    .build()
)
```

### ThreatModelBuilder

```python
from usecvislib import ThreatModelBuilder

model = (
    ThreatModelBuilder("E-Commerce System")
    .add_external("customer", "Customer", isAdmin=False)
    .add_external("admin", "Administrator", isAdmin=True)
    .add_process("webserver", "Web Server",
                 authenticatesSource=True, sanitizesInput=True)
    .add_datastore("userdb", "User Database",
                   isSQL=True, isEncrypted=True, storesPII=True)
    .add_dataflow("customer", "webserver", "HTTPS Request",
                  protocol="HTTPS", isEncrypted=True)
    .add_dataflow("webserver", "userdb", "SQL Queries",
                  protocol="PostgreSQL", isEncrypted=True)
    .add_boundary("dmz", "DMZ", elements=["webserver"])
    .to_threat_model("output")
    .build()
)
```

---

## Result Classes

Structured result objects for analysis operations:

### ValidationResult

```python
from usecvislib import ValidationResult, ValidationIssue, Severity

# Returned by validate() methods
result = ag.validate()

if not result.is_valid:
    for issue in result.errors:
        print(f"ERROR: {issue.message} at {issue.location}")
    for issue in result.warnings:
        print(f"WARNING: {issue.message}")
```

#### Properties

| Property | Type | Description |
|----------|------|-------------|
| `is_valid` | `bool` | True if no errors |
| `issues` | `List[ValidationIssue]` | All issues |
| `errors` | `List[ValidationIssue]` | Error-level issues |
| `warnings` | `List[ValidationIssue]` | Warning-level issues |

### AnalysisResult

```python
from usecvislib import AnalysisResult

# Generic analysis result
result = AnalysisResult(
    stats={"nodes": 10, "edges": 15},
    recommendations=["Consider adding authentication"],
    risk_score=7.5
)

print(result.stats)
print(result.risk_score)
```

### PathResult

```python
from usecvislib import PathResult

# Path finding results
result = PathResult(
    source="attacker",
    target="database",
    paths=[["attacker", "web", "db"], ["attacker", "vpn", "db"]],
    shortest_path=["attacker", "web", "db"],
    shortest_length=3
)

print(f"Found {result.total_paths} paths")
print(f"Shortest: {result.shortest_length} hops")
```

### CriticalNodeResult

```python
from usecvislib import CriticalNodeResult, CriticalNode

# Critical node analysis
result = CriticalNodeResult(
    nodes=[
        CriticalNode(id="web", label="Web Server",
                    node_type="host", criticality_score=8.5)
    ],
    analysis_method="degree_centrality"
)

for node in result.top(5):
    print(f"{node.label}: {node.criticality_score}")
```

### STRIDEResult

```python
from usecvislib import STRIDEResult, STRIDEThreat

# STRIDE analysis results
result = tm.analyze_stride()

# Get all threats
print(f"Total threats: {result.total_count}")

# Filter by severity
critical = result.by_severity("critical")

# Get threats for specific element
webserver_threats = result.for_element("webserver")
```

### RenderResult

```python
from usecvislib import RenderResult

result = RenderResult(
    success=True,
    output_file="output.png",
    format="png",
    render_time=0.45
)
```

---

## Batch Processing

Process multiple visualization files efficiently:

### BatchProcessor

```python
from usecvislib import BatchProcessor, BatchResult

# Initialize processor
processor = BatchProcessor(
    module_type="attack_graph",  # attack_tree, attack_graph, threat_model, binary
    output_dir="./output",
    format="png",
    style="ag_security",
    max_workers=4
)

# Process list of files
result = processor.process_files([
    "network1.toml",
    "network2.toml",
    "network3.toml"
])

# Or process entire directory
result = processor.process_directory(
    "./configs",
    extensions=[".toml", ".json"],
    recursive=True
)

# Check results
print(f"Total: {result.total}")
print(f"Success: {result.success_count}")
print(f"Failed: {result.failure_count}")
print(f"Success rate: {result.success_percentage:.1f}%")

# Get details
for filename, data in result.successes.items():
    print(f"✓ {filename}: {data.get('stats', {})}")

for filename, error in result.failures.items():
    print(f"✗ {filename}: {error}")
```

### Progress Callback

```python
def on_progress(filename, success, error):
    status = "✓" if success else "✗"
    print(f"{status} {filename}")

result = processor.process_files(
    files,
    on_progress=on_progress
)
```

### Aggregate Statistics

```python
# Get combined stats across all files
aggregated = processor.aggregate_stats(result)
print(f"Total nodes: {aggregated['total_nodes']}")
print(f"Total edges: {aggregated['total_edges']}")
```

### Convenience Function

```python
from usecvislib import process_batch

result = process_batch(
    "attack_graph",
    ["file1.toml", "file2.toml"],
    "./output"
)
```

---

## Export Functionality

Export visualization data to various formats:

### ExportMixin Methods

All visualization classes include export methods:

```python
from usecvislib import AttackGraphs

ag = AttackGraphs("network.toml", "output")
ag.load()

# Export to JSON
json_str = ag.export_json()  # Returns string
ag.export_json("export.json")  # Saves to file

# Export section to CSV
ag.export_csv("hosts.csv", section="hosts")
ag.export_csv("vulns.csv", section="vulnerabilities")

# Get exportable sections
sections = ag.get_exportable_sections()
print(sections)  # ['hosts', 'vulnerabilities', 'privileges', ...]
```

### Exporter Utility

```python
from usecvislib import Exporter

# Export dictionary to JSON
data = {"key": "value", "count": 42}
Exporter.to_json(data, "output.json", pretty=True)

# Export list of dicts to CSV
rows = [{"name": "Alice", "age": 30}, {"name": "Bob", "age": 25}]
Exporter.to_csv(rows, "users.csv", delimiter=",")

# Export to YAML
Exporter.to_yaml(data, "output.yaml")

# Export to Markdown table
Exporter.to_markdown_table(rows, "users.md")
```

### ReportGenerator

```python
from usecvislib import ReportGenerator, AttackGraphs

ag = AttackGraphs("network.toml", "output")
ag.load()

# Generate comprehensive report
generator = ReportGenerator(ag)
outputs = generator.generate_report(
    output_dir="./reports",
    formats=["json", "csv", "yaml", "md"],
    prefix="security_report"
)

print(outputs)
# {
#     "json": "./reports/security_report.json",
#     "csv_hosts": "./reports/security_report_hosts.csv",
#     "yaml": "./reports/security_report.yaml",
#     "md": "./reports/security_report.md"
# }
```

---

## Async Support

Non-blocking operations for async applications:

### AsyncVisualization Wrapper

```python
import asyncio
from usecvislib import AttackGraphs, AsyncVisualization, async_wrap

async def main():
    # Create sync instance
    ag = AttackGraphs("network.toml", "output")

    # Wrap for async use
    async_ag = AsyncVisualization(ag)
    # Or use convenience function
    async_ag = async_wrap(ag)

    # Async operations
    await async_ag.load()
    await async_ag.render()
    await async_ag.draw()

    # Or use build() shorthand
    await async_ag.build()

    # Get stats asynchronously
    stats = await async_ag.get_stats()

    # Validate asynchronously
    errors = await async_ag.validate()

    # Export asynchronously
    json_data = await async_ag.export_json()

    # Clean up
    await async_ag.close()

    return stats

stats = asyncio.run(main())
```

### Async Context Manager

```python
async def process():
    ag = AttackGraphs("network.toml", "output")
    async with AsyncVisualization(ag) as async_ag:
        await async_ag.build()
        return await async_ag.get_stats()
```

### AsyncBatchProcessor

```python
from usecvislib import AsyncBatchProcessor

async def batch_process():
    processor = AsyncBatchProcessor(
        module_type="attack_graph",
        output_dir="./output",
        max_concurrent=4
    )

    result = await processor.process_files([
        "file1.toml",
        "file2.toml",
        "file3.toml"
    ])

    await processor.close()
    return result

result = asyncio.run(batch_process())
```

### Convenience Function

```python
from usecvislib import process_files_async

async def main():
    result = await process_files_async(
        module_type="attack_graph",
        input_files=["file1.toml", "file2.toml"],
        output_dir="./output",
        format="png",
        max_concurrent=4
    )
    return result
```

---

## Diff and Comparison

Compare visualizations to track changes over time:

### VisualizationDiff

```python
from usecvislib import AttackGraphs, VisualizationDiff

# Load two versions
old_ag = AttackGraphs("network_v1.toml", "old")
new_ag = AttackGraphs("network_v2.toml", "new")

# Create diff
diff = VisualizationDiff(old_ag, new_ag)

# Compare
result = diff.compare()

# Check if changes exist
if result.has_changes:
    print(f"Changes detected!")
    print(f"Added: {result.summary['added']}")
    print(f"Removed: {result.summary['removed']}")
    print(f"Modified: {result.summary['modified']}")

# Get specific changes
for change in result.added():
    print(f"+ {change.path}: {change.new_value}")

for change in result.removed():
    print(f"- {change.path}: {change.old_value}")

for change in result.modified():
    print(f"~ {change.path}: {change.old_value} -> {change.new_value}")

# Filter by path prefix
host_changes = result.by_path_prefix("hosts")
```

### Summary Report

```python
# Generate human-readable report
report = diff.summary_report(include_details=True)
print(report)

# Save report
diff.save_report("diff_report.md", format="md")
diff.save_report("diff_report.json", format="json")
```

### Ignore Paths

```python
# Ignore certain paths during comparison
result = diff.compare(ignore_paths=["metadata", "timestamps"])
```

### Convenience Function

```python
from usecvislib import compare_files

result = compare_files(
    old_file="network_v1.toml",
    new_file="network_v2.toml",
    visualization_type="attack_graph"  # attack_tree, attack_graph, threat_model
)

print(f"Total changes: {result.summary['total']}")
```

### Change Types

```python
from usecvislib import ChangeType, Change

# ChangeType enum
ChangeType.ADDED      # New element
ChangeType.REMOVED    # Deleted element
ChangeType.MODIFIED   # Changed element
ChangeType.UNCHANGED  # No change

# Change object
change = Change(
    change_type=ChangeType.MODIFIED,
    path="hosts.webserver.ip",
    old_value="10.0.1.10",
    new_value="10.0.1.20"
)
print(str(change))  # "~ hosts.webserver.ip: 10.0.1.10 -> 10.0.1.20"
```

---

## Constants and Enums

Type-safe constants for configuration:

### Output Formats

```python
from usecvislib import OutputFormat

OutputFormat.PNG   # "png"
OutputFormat.PDF   # "pdf"
OutputFormat.SVG   # "svg"
OutputFormat.DOT   # "dot"

# Get all values
print(OutputFormat.values())  # ["png", "pdf", "svg", "dot"]
```

### Configuration Formats

```python
from usecvislib import ConfigFormat

ConfigFormat.TOML  # "toml"
ConfigFormat.JSON  # "json"
ConfigFormat.YAML  # "yaml"
```

### Node Types (Attack Graphs)

```python
from usecvislib import NodeType

NodeType.HOST           # "host"
NodeType.VULNERABILITY  # "vulnerability"
NodeType.PRIVILEGE      # "privilege"
NodeType.SERVICE        # "service"
NodeType.EXPLOIT        # "exploit"
```

### Gate Types (Attack Trees)

```python
from usecvislib import GateType

GateType.AND   # "AND"
GateType.OR    # "OR"
GateType.XOR   # "XOR"
GateType.NAND  # "NAND"
GateType.NOR   # "NOR"
```

### Element Types (Threat Models)

```python
from usecvislib import ElementType

ElementType.PROCESS    # "process"
ElementType.DATASTORE  # "datastore"
ElementType.EXTERNAL   # "external"
ElementType.DATAFLOW   # "dataflow"
ElementType.BOUNDARY   # "boundary"
```

### STRIDE Categories

```python
from usecvislib import STRIDECategory

STRIDECategory.SPOOFING               # "Spoofing"
STRIDECategory.TAMPERING              # "Tampering"
STRIDECategory.REPUDIATION            # "Repudiation"
STRIDECategory.INFORMATION_DISCLOSURE # "Information Disclosure"
STRIDECategory.DENIAL_OF_SERVICE      # "Denial of Service"
STRIDECategory.ELEVATION_OF_PRIVILEGE # "Elevation of Privilege"
```

### Binary Visualization Types

```python
from usecvislib import BinaryVisualization

BinaryVisualization.ENTROPY       # "entropy"
BinaryVisualization.DISTRIBUTION  # "distribution"
BinaryVisualization.WINDROSE      # "windrose"
BinaryVisualization.HEATMAP       # "heatmap"
BinaryVisualization.ALL           # "all"
```

### Risk Levels

```python
from usecvislib import RiskLevel

RiskLevel.CRITICAL  # "critical"
RiskLevel.HIGH      # "high"
RiskLevel.MEDIUM    # "medium"
RiskLevel.LOW       # "low"
RiskLevel.INFO      # "info"
```

### Default Values

```python
from usecvislib import DEFAULTS, COLORS

# Access default configuration
print(DEFAULTS["output_format"])  # OutputFormat.PNG
print(DEFAULTS["max_file_sizes"]["config"])  # 10485760 (10MB)

# Access color schemes
print(COLORS["risk"]["critical"])  # "#e74c3c"
```

---

## Utility Functions

### Configuration

```python
from usecvislib import (
    ConfigModel,
    ReadTomlFile,
    merge_dicts,
    stringify_dict
)

# Load style configurations
config = ConfigModel("config_attacktrees.tml")
style = config.get("at_neon")

# Read TOML file
data = ReadTomlFile("config.toml")

# Merge dictionaries (second takes priority)
base = {"color": "red", "size": 10}
override = {"color": "blue"}
result = merge_dicts(base, override)
# {"color": "blue", "size": 10}

# Convert dict values to strings (for Graphviz)
attrs = {"width": 2.5, "height": 100}
str_attrs = stringify_dict(attrs)
# {"width": "2.5", "height": "100"}
```

### Node Icons and Images

```python
from usecvislib.utils import process_node_image, resolve_icon_path

# Resolve bundled icon path
icon_path = resolve_icon_path("@icon:aws/compute/ec2.png")
# Returns absolute path to bundled icon

# Process node image in attributes dict
node_attrs = {"label": "Web Server", "image": "@icon:aws/compute/ec2.png"}
process_node_image(node_attrs, "webserver", logger)
# Modifies node_attrs in-place:
# - Resolves @icon: prefix to absolute path
# - Sets shape="none" for image display
# - Sets labelloc="b" to place label below image
```

**Using Icons in Templates:**

```toml
# Attack Tree with icons
[nodes]
WebServer = { label = "Web Server", image = "@icon:aws/compute/ec2.png" }
Database = { label = "Database", image = "@icon:aws/database/rds.png" }
Attacker = { label = "Attacker", image = "@icon:bootstrap/person-fill.svg" }

# Attack Graph with icons
[hosts.webserver]
label = "Web Server"
image = "@icon:aws/compute/ec2.png"

# Threat Model with icons
[processes.api]
name = "API Gateway"
image = "@icon:aws/networking/api-gateway.png"
```

**Bundled Icon Libraries:**

| Provider | Path Prefix | Examples |
|----------|-------------|----------|
| AWS | `@icon:aws/` | `aws/compute/ec2.png`, `aws/database/rds.png` |
| Azure | `@icon:azure/` | `azure/compute/vm.svg`, `azure/storage/blob.svg` |
| Bootstrap | `@icon:bootstrap/` | `bootstrap/shield.svg`, `bootstrap/server.svg` |

**Icon Behavior:**
- Icons are automatically sized and positioned
- By default, nodes with icons use `shape="none"` (no background shape)
- Font color is set to black for readability on white backgrounds
- User-specified `fontcolor` in templates takes precedence
- Custom images can use absolute or relative file paths

**Adding a Background Shape to Icon Nodes:**

By default, nodes with icons render cleanly without a background shape. If you want to display both an icon and a background shape (e.g., a colored box behind the icon), explicitly set the `shape` attribute in your configuration:

```toml
# Attack Tree - node with icon AND background shape
[nodes]
WebServer = {
    label = "Web Server",
    image = "@icon:aws/compute/ec2.png",
    shape = "box",           # Explicitly set shape to preserve it
    style = "filled",
    fillcolor = "#3498db"
}

# Attack Graph - host with icon AND background shape
[hosts.webserver]
label = "Web Server"
image = "@icon:aws/compute/ec2.png"
shape = "box3d"              # Explicitly set shape
style = "filled"
fillcolor = "#2ecc71"

# Threat Model - process with icon AND background shape
[processes.api]
name = "API Gateway"
image = "@icon:aws/networking/api-gateway.png"
shape = "ellipse"            # Explicitly set shape
```

When `shape` is explicitly set, the icon is positioned at the top-center of the node using Graphviz's native `image` attribute, allowing both the icon and the background shape to be visible.

---

### Security Utilities

```python
from usecvislib import (
    validate_input_path,
    validate_output_path,
    escape_dot_label,
    sanitize_node_id,
    SecurityError
)

# Validate paths for security
try:
    safe_path = validate_input_path("/path/to/file.toml")
    safe_output = validate_output_path("/path/to/output")
except SecurityError as e:
    print(f"Security violation: {e}")

# Escape special characters in DOT labels (prevents injection)
safe_label = escape_dot_label('User "Admin" <script>')
# 'User \"Admin\" &lt;script&gt;'

# Sanitize node IDs for safe Graphviz usage
safe_id = sanitize_node_id("node with spaces & special!")
# 'node_with_spaces___special_'
```

### Caching Utilities

```python
from usecvislib import (
    cached_result,
    content_hash,
    file_hash,
    StyleManager
)

# Calculate content hash (for cache invalidation)
hash_val = content_hash({"key": "value"})

# Calculate file hash
file_hash_val = file_hash("/path/to/file.toml")

# Cache decorator for expensive operations
@cached_result
def expensive_calculation(data):
    # ... complex computation
    return result

# Style manager with caching
style_mgr = StyleManager()
style = style_mgr.get_style("at_neon", "attacktrees")
```

### Logging

```python
from usecvislib import configure_logging, get_logger

# Configure library logging
configure_logging(level="DEBUG", log_file="usecvislib.log")

# Get a logger instance
logger = get_logger(__name__)
logger.info("Processing started")
logger.debug("Debug details...")
```

---

## Error Handling

### Exception Hierarchy

```python
from usecvislib import (
    USecVisLibError,     # Base exception for all library errors
    ConfigError,         # Configuration parsing/validation errors
    FileError,           # File I/O errors
    SecurityError,       # Security-related errors (path traversal, etc.)
    ValidationError,     # Data validation errors
    RenderError,         # Visualization rendering errors
    AnalysisError,       # Analysis operation errors
    AttackTreeError,     # Attack tree specific errors
    AttackGraphError,    # Attack graph specific errors
)
```

### Exception Handling

```python
from usecvislib import (
    AttackTrees,
    USecVisLibError,
    FileError,
    ConfigError,
    SecurityError,
    ValidationError,
    RenderError
)

try:
    at = AttackTrees("config.toml", "output")
    at.BuildAttackTree()
except FileError as e:
    print(f"File error: {e}")
    # File not found, permission denied, etc.
except ConfigError as e:
    print(f"Configuration error: {e}")
    # Invalid TOML/JSON/YAML syntax, missing required fields
except SecurityError as e:
    print(f"Security error: {e}")
    # Path traversal attempt, unsafe input
except ValidationError as e:
    print(f"Validation error: {e}")
    # Invalid node references, missing required data
except RenderError as e:
    print(f"Render error: {e}")
    # Graphviz errors, output generation failures
except USecVisLibError as e:
    print(f"Library error: {e}")
    # Catch-all for any library error
```

### Validation Before Processing

```python
from usecvislib import AttackGraphs

ag = AttackGraphs("network.toml", "graph")
errors = ag.validate()

if errors:
    print("Validation failed:")
    for error in errors:
        print(f"  - {error}")
else:
    ag.BuildAttackGraph()
```

### Safe Path Validation

```python
from usecvislib import validate_input_path, validate_output_path, SecurityError

try:
    # Validates path is safe (no traversal, within allowed directories)
    safe_input = validate_input_path("/path/to/config.toml")
    safe_output = validate_output_path("/path/to/output")
except SecurityError as e:
    print(f"Unsafe path: {e}")

---

## Advanced Usage

### Custom Workflow

```python
from usecvislib import AttackTrees

at = AttackTrees("attack.toml", "output", styleid="at_neon")

# Step 1: Load data
data = at.load()
print(f"Loaded tree: {data['tree']['name']}")

# Step 2: Validate
errors = at.validate()
if errors:
    raise ValueError(f"Invalid tree: {errors}")

# Step 3: Get stats before rendering
stats = at.get_tree_stats()
print(f"Nodes: {stats['total_nodes']}, Edges: {stats['total_edges']}")

# Step 4: Render to internal graph
at.Render()

# Step 5: Save to multiple formats
for fmt in ["png", "pdf", "svg"]:
    at.format = fmt
    at.draw(f"output_{fmt}")
```

### Loading from String/Dict

```python
from usecvislib import AttackTrees
import json

# Load configuration from API response
api_response = '{"tree": {"name": "Test", "root": "Root"}, "nodes": {...}, "edges": {...}}'
config = json.loads(api_response)

at = AttackTrees("", "output")  # Empty input file
at.inputdata = config  # Set data directly
at.Render()
at.draw()
```

### Batch Processing

```python
from usecvislib import AttackTrees
from pathlib import Path

input_dir = Path("./configs")
output_dir = Path("./output")

for config_file in input_dir.glob("*.toml"):
    output_name = output_dir / config_file.stem

    at = AttackTrees(str(config_file), str(output_name))
    try:
        at.BuildAttackTree()
        print(f"Generated: {output_name}.png")
    except Exception as e:
        print(f"Failed: {config_file} - {e}")
```

### Combining Multiple Analyses

```python
from usecvislib import AttackGraphs

ag = AttackGraphs("network.toml", "graph")
ag.load()

# Get comprehensive analysis
stats = ag.get_graph_stats()
critical = ag.analyze_critical_nodes(top_n=5)

# Find paths to all high-value targets
targets = ["priv_db_admin", "priv_domain_admin", "crown_jewels"]
all_paths = {}

for target in targets:
    paths = ag.find_attack_paths("attacker", target)
    if paths:
        all_paths[target] = {
            "paths": paths,
            "shortest": ag.shortest_path("attacker", target)
        }

# Generate report
print("Security Analysis Report")
print("=" * 50)
print(f"Network: {stats['name']}")
print(f"Hosts: {stats['total_hosts']}")
print(f"Critical vulnerabilities: {stats['critical_vulnerabilities']}")
print(f"\nTop Critical Nodes:")
for node in critical:
    print(f"  - {node['label']}: criticality {node['criticality_score']}")

print(f"\nAttack Paths Found:")
for target, data in all_paths.items():
    print(f"  {target}: {len(data['paths'])} paths, shortest: {len(data['shortest'])}")
```

---

## Integration Examples

### Flask Web Application

```python
from flask import Flask, request, send_file
from usecvislib import AttackTrees
import tempfile
import os

app = Flask(__name__)

@app.route('/generate', methods=['POST'])
def generate_attack_tree():
    config = request.json

    with tempfile.TemporaryDirectory() as tmpdir:
        config_file = os.path.join(tmpdir, "config.json")
        output_file = os.path.join(tmpdir, "output")

        # Save config
        import json
        with open(config_file, 'w') as f:
            json.dump(config, f)

        # Generate visualization
        at = AttackTrees(config_file, output_file, format="png")
        at.BuildAttackTree()

        return send_file(
            f"{output_file}.png",
            mimetype='image/png'
        )
```

### Jupyter Notebook

```python
from usecvislib import BinVis
from IPython.display import Image, display

# Analyze binary
bv = BinVis("sample.bin", "analysis")
bv.BuildBinVis("all")

# Display in notebook
display(Image("analysis_entropy.png"))
display(Image("analysis_distribution.png"))

# Show stats
stats = bv.get_file_stats()
print(f"File size: {stats['file_size']:,} bytes")
print(f"Entropy: {stats['entropy']:.4f}")
```

### CI/CD Pipeline (Security Gate)

```python
#!/usr/bin/env python3
"""Security analysis gate for CI/CD pipeline."""

from usecvislib import AttackGraphs
import sys

def analyze_security(config_file: str, max_critical: int = 0) -> bool:
    """Analyze attack graph and fail if too many critical paths exist."""

    ag = AttackGraphs(config_file, "analysis")
    ag.load()

    # Validate configuration
    errors = ag.validate()
    if errors:
        print("Configuration errors:")
        for e in errors:
            print(f"  - {e}")
        return False

    # Get statistics
    stats = ag.get_graph_stats()

    # Check critical vulnerabilities
    if stats['critical_vulnerabilities'] > max_critical:
        print(f"FAIL: {stats['critical_vulnerabilities']} critical vulnerabilities "
              f"(max allowed: {max_critical})")
        return False

    # Check for paths to crown jewels
    paths = ag.find_attack_paths("attacker", "crown_jewels")
    if paths:
        print(f"WARNING: {len(paths)} attack paths to crown jewels found")
        shortest = ag.shortest_path("attacker", "crown_jewels")
        print(f"  Shortest path: {len(shortest)} steps")

    print("PASS: Security analysis complete")
    return True

if __name__ == "__main__":
    config = sys.argv[1] if len(sys.argv) > 1 else "network.toml"
    success = analyze_security(config)
    sys.exit(0 if success else 1)
```

### Report Generation

```python
from usecvislib import ThreatModeling
from datetime import datetime

def generate_security_report(config_file: str, output_dir: str):
    """Generate comprehensive security report."""

    tm = ThreatModeling(config_file, f"{output_dir}/diagram")
    tm.load()

    # Generate visualization
    tm.BuildThreatModel()

    # Analyze STRIDE threats
    threats = tm.analyze_stride()

    # Generate STRIDE report
    tm.generate_stride_report(f"{output_dir}/stride_report.md")

    # Generate summary
    stats = tm.get_model_stats()

    summary = f"""
# Security Assessment Report

**Generated:** {datetime.now().strftime("%Y-%m-%d %H:%M")}
**Model:** {tm.inputdata['model'].get('name', 'Unknown')}

## System Overview

| Metric | Count |
|--------|-------|
| Processes | {stats['total_processes']} |
| Data Stores | {stats['total_datastores']} |
| External Entities | {stats['total_externals']} |
| Data Flows | {stats['total_dataflows']} |
| Trust Boundaries | {stats['total_boundaries']} |
| Flows Crossing Boundaries | {stats['flows_crossing_boundaries']} |

## Threat Summary

| Category | Count |
|----------|-------|
"""

    for category, threat_list in threats.items():
        summary += f"| {category} | {len(threat_list)} |\n"

    with open(f"{output_dir}/summary.md", "w") as f:
        f.write(summary)

    print(f"Report generated in {output_dir}/")

# Usage
generate_security_report("threat_model.toml", "./reports")
```

---

## See Also

- [CLI Guide](CLI_GUIDE.md) - Command-line interface reference
- [Custom Diagrams Guide](CUSTOM_DIAGRAMS_GUIDE.md) - Custom diagrams documentation
- [README](../README.md) - Project overview and installation
- [Templates](../templates/) - Example configuration files

---

**USecVisLib** v0.3.1 - Universal Security Visualization Library
