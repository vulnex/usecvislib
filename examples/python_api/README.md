# USecVisLib Python API Examples

This directory contains examples demonstrating how to use the USecVisLib Python API to create security visualizations programmatically.

## Prerequisites

1. Install USecVisLib:
   ```bash
   pip install usecvislib
   ```

2. Install Graphviz (required for rendering):
   - macOS: `brew install graphviz`
   - Ubuntu/Debian: `apt-get install graphviz`
   - Windows: Download from https://graphviz.org/download/

## Examples Overview

### Attack Trees

| File | Description |
|------|-------------|
| `attack_tree_basic.py` | Create attack trees without icons using builder pattern and templates |
| `attack_tree_icons.py` | Create attack trees with AWS and Bootstrap icons |

### Attack Graphs

| File | Description |
|------|-------------|
| `attack_graph_basic.py` | Create attack graphs without icons, including path analysis |
| `attack_graph_icons.py` | Create attack graphs with AWS infrastructure icons |

### Threat Models

| File | Description |
|------|-------------|
| `threat_model_basic.py` | Create STRIDE threat models without icons |
| `threat_model_icons.py` | Create threat models with AWS and Bootstrap icons |

### Custom Diagrams

| File | Description |
|------|-------------|
| `custom_diagram_basic.py` | Create custom diagrams (flowcharts, network topologies) |
| `custom_diagram_icons.py` | Create custom diagrams with icons (AWS architectures) |

### Mermaid Diagrams

| File | Description |
|------|-------------|
| `mermaid_diagram_basic.py` | Create Mermaid diagrams (flowcharts, sequence, ER, state, mindmap, Gantt) |

### Cloud Diagrams

| File | Description |
|------|-------------|
| `cloud_diagram_basic.py` | Create cloud architecture diagrams (AWS, GCP, Kubernetes, multi-cloud) |

### Utilities

| File | Description |
|------|-------------|
| `utilities.py` | Export formats, validation, statistics, CVSS features |

## Running Examples

```bash
# Run all examples in a file
python attack_tree_basic.py

# Or run specific functions
python -c "from attack_tree_icons import example_with_aws_icons; example_with_aws_icons()"
```

Output files are saved to the `output/` directory.

## Icon Reference

### Bundled Icons

Icons are referenced using the format: `bundled:<provider>/<path>`

#### AWS Icons
```python
image = "bundled:aws/Compute/EC2"
image = "bundled:aws/Database/RDS"
image = "bundled:aws/Storage/Simple-Storage-Service"
image = "bundled:aws/Security-Identity-Compliance/IAM"
image = "bundled:aws/Networking-Content-Delivery/VPC"
```

#### Bootstrap Icons
```python
image = "bundled:bootstrap/icons/icons/shield-fill"
image = "bundled:bootstrap/icons/icons/database"
image = "bundled:bootstrap/icons/icons/person-fill"
image = "bundled:bootstrap/icons/icons/lock-fill"
```

### Using Icons in Nodes

When using icons, set `shape="none"` for icon-only nodes:

```python
builder.add_node(
    "My Node",
    shape="none",
    image="bundled:aws/Compute/Lambda"
)
```

## Quick Start Examples

### Attack Tree with Builder

```python
from usecvislib.builders import AttackTreeBuilder

tree = (
    AttackTreeBuilder("My Attack Tree", "Compromise Target")
    .add_node("Compromise Target", fillcolor="#E74C3C", fontcolor="white")
    .add_node("SQL Injection", fillcolor="#3498DB", cvss=9.8)
    .add_node("XSS Attack", fillcolor="#3498DB", cvss=6.1)
    .add_edge("Compromise Target", "SQL Injection", label="OR")
    .add_edge("Compromise Target", "XSS Attack", label="OR")
    .to_attack_tree("output/my_tree", format="png")
    .load()
    .render()
    .draw()
)
```

### Attack Tree from Template

```python
from usecvislib import AttackTrees

at = AttackTrees(
    inputfile="templates/attack-trees/insider_threat.tml",
    outputfile="output/insider_threat",
    format="png"
)
at.load().render().draw()
```

### Attack Graph with Analysis

```python
from usecvislib import AttackGraphs

ag = AttackGraphs("templates/attack-graphs/simple_network.tml", "output/network")
ag.load()

# Find attack paths
paths = ag.find_attack_paths("attacker", "target_privilege")
for path in paths:
    print(" -> ".join(path))

# Analyze critical nodes
critical = ag.analyze_critical_nodes(top_n=5)
for node in critical:
    print(f"{node['id']}: degree={node['total_degree']}")

ag.render().draw()
```

### Threat Model from Template

```python
from usecvislib import ThreatModeling

tm = ThreatModeling(
    inputfile="templates/threat-models/banking_api.tml",
    outputfile="output/banking_threat_model",
    format="png"
)
tm.load()

# Get statistics
stats = tm.get_stats()
print(f"Processes: {stats['processes']}")
print(f"Data Flows: {stats['dataflows']}")

tm.render().draw()
```

### Custom Diagram

```python
from usecvislib import CustomDiagrams

cd = CustomDiagrams()
cd.load("templates/custom-diagrams/network/topology.toml")

# Validate
result = cd.validate(raise_on_error=False)
if result.get('valid'):
    cd.BuildCustomDiagram(output="output/topology", format="png")
```

### Mermaid Diagram

```python
from usecvislib import MermaidDiagrams

md = MermaidDiagrams()

# From string
md.load_from_string("""
flowchart TD
    A[Start] --> B{Valid?}
    B -->|Yes| C[Process]
    B -->|No| D[Error]
""")
result = md.render("output/flowchart", format="png", theme="default")

# Or from template
md = MermaidDiagrams()
md.load("templates/mermaid/sequence/api-auth.toml")
result = md.render("output/sequence", format="png")
```

### Cloud Diagram

```python
from usecvislib import CloudDiagrams

cd = CloudDiagrams()
cd.load("templates/cloud/aws/web-application.toml")

# Get info
print(f"Nodes: {len(cd.nodes)}")
print(f"Clusters: {len(cd.clusters)}")

# Render
result = cd.render("output/aws_arch", format="png")

# Generate Python code for advanced customization
python_code = cd.to_python_code()
```

## API Reference

### Core Classes

- `AttackTrees` - Attack tree visualization
- `AttackGraphs` - Attack graph visualization with path analysis
- `ThreatModeling` - STRIDE threat modeling
- `CustomDiagrams` - Schema-driven custom diagrams
- `MermaidDiagrams` - Mermaid syntax rendering (flowcharts, sequence, ER, etc.)
- `CloudDiagrams` - Cloud architecture diagrams (AWS, Azure, GCP, K8s)
- `BinVis` - Binary file visualization

### Builder Classes

- `AttackTreeBuilder` - Fluent builder for attack trees
- `AttackGraphBuilder` - Fluent builder for attack graphs
- `ThreatModelBuilder` - Fluent builder for threat models

### Common Methods

All visualization classes support:
- `load()` - Load configuration from file
- `validate()` - Validate the configuration
- `render()` - Build the visualization
- `draw()` - Save to output file
- `get_stats()` - Get statistics about the visualization
- `build()` - Convenience method: load + render + draw

## Output Formats

Supported output formats:
- `png` - PNG image (default)
- `svg` - SVG vector graphics
- `pdf` - PDF document
- `dot` - Graphviz DOT source

## Styles

Each visualization type has multiple built-in styles:
- Attack Trees: `at_default`, `at_dark`, `at_minimal`, etc.
- Attack Graphs: `ag_default`, `ag_security`, `ag_network`, etc.
- Threat Models: `tm_default`, `tm_dfd`, `tm_stride`, etc.
- Custom Diagrams: `cd_default`, `cd_blueprint`, `cd_dark`, etc.

Use style `"0"` to disable styling.

## License

Apache-2.0 - Copyright (c) 2025 VULNEX
