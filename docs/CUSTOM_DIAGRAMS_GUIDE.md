# Custom Diagrams User Guide

Complete guide for creating flexible, schema-driven diagrams with USecVisLib.

---

## Table of Contents

1. [Introduction](#introduction)
2. [Quick Start](#quick-start)
3. [Configuration Format](#configuration-format)
4. [Schema Definition](#schema-definition)
5. [Shape Gallery](#shape-gallery)
6. [Available Templates](#available-templates)
7. [Layout Options](#layout-options)
8. [Style Presets](#style-presets)
9. [Python API](#python-api)
10. [REST API](#rest-api)
11. [CLI Usage](#cli-usage)
12. [Advanced Features](#advanced-features)
13. [Examples](#examples)
14. [Troubleshooting](#troubleshooting)

---

## Introduction

The Custom Diagrams module is a flexible, schema-driven visualization system that allows you to create arbitrary diagrams without being constrained to domain-specific formats (Attack Trees, Attack Graphs, etc.).

### Key Features

| Feature | Description |
|---------|-------------|
| **Shape Gallery** | 100+ pre-built shapes organized by category |
| **Custom Schemas** | Define your own node types, edge types, and validation rules |
| **Template Library** | 20+ ready-to-use diagram templates |
| **Multiple Formats** | Export to PNG, SVG, PDF, DOT |
| **Flexible Layouts** | Hierarchical, circular, force-directed layouts |
| **Multi-Format Config** | TOML, JSON, YAML configuration files |

### When to Use Custom Diagrams

- You need a diagram type not covered by Attack Trees, Attack Graphs, or Threat Models
- You want full control over node shapes and styling
- You're creating UML, flowcharts, network topology, or organizational charts
- You need a custom schema with specific validation rules

---

## Quick Start

### Python API

```python
from usecvislib import CustomDiagrams

# Load and visualize a diagram
cd = CustomDiagrams()
cd.load("my_diagram.toml")
result = cd.BuildCustomDiagram(output="output.png")

print(f"Generated: {result.output_path}")
print(f"Nodes: {result.stats['node_count']}")
```

### From Template

```python
from usecvislib import CustomDiagrams

cd = CustomDiagrams()
cd.load_template("flowchart")  # Uses templates/custom-diagrams/general/flowchart.toml
result = cd.BuildCustomDiagram(output="flowchart.png")
```

### CLI

```bash
# Generate from configuration file
usecvis -m 4 -i diagram.toml -o output -f png

# Use a specific style
usecvis -m 4 -i diagram.toml -o output -f png -s cd_dark
```

### REST API

```bash
# Generate visualization
curl -X POST "http://localhost:8000/visualize/custom-diagram" \
  -F "file=@diagram.toml" \
  -F "format=png" \
  -F "style=cd_default" \
  --output diagram.png
```

---

## Configuration Format

Custom diagram configuration files have three main sections:

1. **`[diagram]`** - Global diagram settings
2. **`[schema]`** - Node and edge type definitions
3. **`[[nodes]]` / `[[edges]]`** - Actual diagram data

### Basic Structure

```toml
# 1. Diagram Settings
[diagram]
title = "My Diagram"
description = "A description of the diagram"
layout = "hierarchical"
direction = "TB"
style = "cd_default"

# 2. Schema Definition
[schema.nodes.process]
shape = "rectangle"
required_fields = ["name"]
style = { fillcolor = "#3498DB", fontcolor = "white" }

[schema.edges.flow]
style = "solid"
arrowhead = "normal"

# 3. Diagram Data
[[nodes]]
id = "node1"
type = "process"
name = "First Node"

[[nodes]]
id = "node2"
type = "process"
name = "Second Node"

[[edges]]
from = "node1"
to = "node2"
type = "flow"
```

### Diagram Settings

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `title` | string | "Custom Diagram" | Diagram title |
| `description` | string | "" | Diagram description |
| `layout` | string | "hierarchical" | Layout algorithm |
| `direction` | string | "TB" | Graph direction (TB, LR, BT, RL) |
| `style` | string | "cd_default" | Style preset name |
| `splines` | string | "ortho" | Edge routing (ortho, polyline, curved, line, spline) |
| `nodesep` | float | 0.5 | Horizontal spacing between nodes |
| `ranksep` | float | 1.0 | Vertical spacing between ranks |
| `fontname` | string | "Arial" | Default font |
| `fontsize` | string | "12" | Default font size |
| `bgcolor` | string | "" | Background color |

---

## Schema Definition

The schema section defines the types of nodes and edges available in your diagram.

### Node Types

```toml
[schema.nodes.my_node_type]
shape = "rectangle"           # Shape from gallery (required)
required_fields = ["name"]    # Fields that must be present
optional_fields = ["desc"]    # Optional fields
style = { fillcolor = "#3498DB", fontcolor = "white" }  # Default styling
label_template = "{name}"     # How to render the label
```

#### Node Type Properties

| Property | Type | Description |
|----------|------|-------------|
| `shape` | string | Shape ID from the gallery (e.g., "rectangle", "diamond", "server") |
| `required_fields` | array | Fields that must be present in node data |
| `optional_fields` | array | Fields that may be present |
| `style` | object | Default Graphviz style attributes |
| `label_template` | string | Template for node label using `{field}` placeholders |

### Edge Types

```toml
[schema.edges.my_edge_type]
style = "solid"              # Line style (solid, dashed, dotted, bold)
color = "#333333"            # Edge color
arrowhead = "normal"         # Arrow style (normal, vee, dot, none, diamond)
arrowtail = "none"           # Tail arrow style
label_field = "label"        # Field to use as edge label
```

#### Edge Type Properties

| Property | Type | Description |
|----------|------|-------------|
| `style` | string | Line style (solid, dashed, dotted, bold) |
| `color` | string | Edge color (hex or name) |
| `arrowhead` | string | Arrow style at head |
| `arrowtail` | string | Arrow style at tail |
| `penwidth` | float | Line thickness |
| `label_field` | string | Node field to use as edge label |

---

## Shape Gallery

The Custom Diagrams module includes 100+ pre-built shapes organized by category.

### Categories

| Category | Shapes | Use Cases |
|----------|--------|-----------|
| **basic** | rectangle, circle, diamond, ellipse, hexagon, triangle, star, note | General purpose |
| **security** | server, database, firewall, cloud, user, attacker, lock, shield | Security diagrams |
| **network** | router, switch, hub, endpoint, laptop, desktop, mobile, storage | Network topology |
| **flow** | process, decision, document, data, manual_input, terminator | Flowcharts |
| **uml** | class, interface, package, component, actor, usecase, state | UML diagrams |
| **containers** | cluster, boundary, zone, subnet, region, group | Grouping elements |

### Basic Shapes

| Shape ID | Description | Graphviz Shape |
|----------|-------------|----------------|
| `rectangle` | Standard rectangle | box |
| `rounded_rectangle` | Rectangle with rounded corners | box (rounded) |
| `circle` | Perfect circle | circle |
| `ellipse` | Oval shape | ellipse |
| `diamond` | Decision diamond | diamond |
| `parallelogram` | I/O shape | parallelogram |
| `hexagon` | Six-sided polygon | hexagon |
| `octagon` | Eight-sided polygon | octagon |
| `triangle` | Triangle pointing up | triangle |
| `star` | Star shape | star |
| `note` | Note with folded corner | note |
| `plain` | Plain text (no border) | plaintext |

### Security Shapes

| Shape ID | Description | Default Color |
|----------|-------------|---------------|
| `server` | Server/compute node | #4A90D9 |
| `database` | Database/data store | #50C878 |
| `firewall` | Firewall/security gateway | #FF6B6B |
| `cloud` | Cloud service | #3498DB |
| `user` | Human user/actor | #9B59B6 |
| `attacker` | Malicious actor | #E74C3C |
| `lock` | Security/encryption | #2ECC71 |
| `shield` | Protection/defense | #3498DB |
| `key` | Authentication/credential | #F39C12 |
| `certificate` | Digital certificate | #1ABC9C |
| `warning` | Alert/warning | #F39C12 |

### Network Shapes

| Shape ID | Description | Default Color |
|----------|-------------|---------------|
| `router` | Network router | #E67E22 |
| `switch` | Network switch | #9B59B6 |
| `hub` | Network hub | #7F8C8D |
| `endpoint` | Generic endpoint | #3498DB |
| `laptop` | Laptop computer | #34495E |
| `desktop` | Desktop computer | #2C3E50 |
| `mobile` | Mobile device | #1ABC9C |
| `tablet` | Tablet device | #16A085 |
| `iot` | IoT device | #27AE60 |
| `printer` | Printer | #7F8C8D |
| `storage` | Storage device | #8E44AD |

### Flow Shapes

| Shape ID | Description | Use Case |
|----------|-------------|----------|
| `process` | Process/activity | Action steps |
| `decision` | Decision point | Yes/No branches |
| `document` | Document | Output documents |
| `data` | Data store | Data objects |
| `manual_input` | Manual input | User entry |
| `display` | Display output | Screen output |
| `preparation` | Preparation | Setup steps |
| `terminator` | Start/end | Begin/end points |

### Using Shapes in Schema

```toml
# Reference shapes by ID
[schema.nodes.web_server]
shape = "server"
required_fields = ["name", "ip"]
style = { fillcolor = "#4A90D9", fontcolor = "white" }

[schema.nodes.db]
shape = "database"
required_fields = ["name"]
style = { fillcolor = "#50C878", fontcolor = "white" }

[schema.nodes.gateway]
shape = "firewall"
required_fields = ["name"]
style = { fillcolor = "#FF6B6B", fontcolor = "white" }
```

---

## Available Templates

Templates are pre-built diagram configurations that you can use as-is or customize.

### General Templates

| Template | File | Description |
|----------|------|-------------|
| Flowchart | `general/flowchart.toml` | Basic flowchart with process, decision, I/O |
| Mind Map | `general/mindmap.toml` | Radial mind mapping diagram |
| Hierarchy | `general/hierarchy.toml` | Organizational hierarchy |
| Timeline | `general/timeline.toml` | Timeline/sequence diagram |

### Software Templates

| Template | File | Description |
|----------|------|-------------|
| Architecture | `software/architecture.toml` | System architecture diagram |
| Class Diagram | `software/class-diagram.toml` | UML class diagram |
| Sequence | `software/sequence-diagram.toml` | UML sequence diagram |
| Component | `software/component-diagram.toml` | UML component diagram |
| Deployment | `software/deployment-diagram.toml` | UML deployment diagram |
| Source Code | `software/source-code.toml` | Source code structure |
| Directory Tree | `software/directory-tree.toml` | File/directory listing |

### Network Templates

| Template | File | Description |
|----------|------|-------------|
| Topology | `network/topology.toml` | Network topology |
| Data Flow | `network/data-flow.toml` | Data flow diagram |
| Infrastructure | `network/infrastructure.toml` | Infrastructure diagram |

### Security Templates

| Template | File | Description |
|----------|------|-------------|
| Risk Matrix | `security/risk-matrix.toml` | Risk assessment matrix |
| Incident Flow | `security/incident-flow.toml` | Incident response flow |
| Access Control | `security/access-control.toml` | Access control diagram |

### Business Templates

| Template | File | Description |
|----------|------|-------------|
| Process Flow | `business/process-flow.toml` | Business process |
| Swimlane | `business/swimlane.toml` | Swimlane diagram |
| Org Chart | `business/org-chart.toml` | Organization chart |

### Using Templates

```python
from usecvislib import CustomDiagrams

cd = CustomDiagrams()

# Load template by name (searches in templates/custom-diagrams/)
cd.load_template("flowchart")

# Or load by category/name
cd.load_template("software/architecture")

# Customize and render
result = cd.BuildCustomDiagram(output="my_diagram.png")
```

---

## Layout Options

### Layout Algorithms

| Layout | Value | Description |
|--------|-------|-------------|
| Hierarchical | `hierarchical` | Top-down or left-right tree layout |
| Circular | `circular` | Nodes arranged in a circle |
| Force | `force` | Force-directed graph layout |
| Grid | `grid` | Nodes in a grid pattern |

### Direction

| Direction | Value | Description |
|-----------|-------|-------------|
| Top to Bottom | `TB` | Root at top, leaves at bottom |
| Bottom to Top | `BT` | Root at bottom, leaves at top |
| Left to Right | `LR` | Root at left, leaves at right |
| Right to Left | `RL` | Root at right, leaves at left |

### Edge Routing (Splines)

| Spline | Value | Description |
|--------|-------|-------------|
| Orthogonal | `ortho` | Right-angle edges |
| Polyline | `polyline` | Straight line segments |
| Curved | `curved` | Curved edges |
| Line | `line` | Straight lines |
| Spline | `spline` | Smooth splines |

### Spacing

```toml
[diagram]
nodesep = 0.5   # Horizontal spacing (inches)
ranksep = 1.0   # Vertical spacing (inches)
```

---

## Style Presets

### Available Styles

| Style ID | Description |
|----------|-------------|
| `cd_default` | Default light theme |
| `cd_dark` | Dark theme with light text |
| `cd_corporate` | Professional corporate colors |
| `cd_neon` | Vibrant neon colors |
| `cd_minimal` | Clean minimal design |
| `cd_blueprint` | Technical blueprint style |
| `cd_hacker` | Green on black terminal style |
| `cd_pastel` | Soft pastel colors |
| `cd_plain` | No styling (black and white) |

### Applying Styles

```toml
[diagram]
style = "cd_dark"  # Apply dark theme
```

Or via Python:

```python
cd = CustomDiagrams()
cd.load("diagram.toml")
result = cd.BuildCustomDiagram(output="output.png", style="cd_dark")
```

---

## Python API

### CustomDiagrams Class

```python
from usecvislib import CustomDiagrams

cd = CustomDiagrams()
```

### Methods

#### `load(filepath: str) -> Dict[str, Any]`

Load diagram configuration from file.

```python
cd = CustomDiagrams()
data = cd.load("diagram.toml")
print(data["diagram"]["title"])
```

#### `load_template(template_name: str) -> Dict[str, Any]`

Load a built-in template.

```python
cd = CustomDiagrams()
cd.load_template("flowchart")  # Loads general/flowchart.toml
cd.load_template("software/class-diagram")  # Loads software/class-diagram.toml
```

#### `load_from_content(content: str, format: str = "toml") -> Dict[str, Any]`

Load from string content.

```python
toml_content = """
[diagram]
title = "My Diagram"
...
"""

cd = CustomDiagrams()
cd.load_from_content(toml_content, format="toml")
```

#### `BuildCustomDiagram(output: str, format: str = "png", style: str = None) -> VisualizationResult`

Generate the diagram visualization.

```python
result = cd.BuildCustomDiagram(
    output="diagram",      # Output filename (without extension)
    format="png",          # Output format
    style="cd_default"     # Style preset (optional)
)

print(f"Output: {result.output_path}")
print(f"Nodes: {result.stats['node_count']}")
print(f"Edges: {result.stats['edge_count']}")
```

#### `validate() -> List[str]`

Validate the diagram configuration.

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

#### `get_stats() -> Dict[str, Any]`

Get diagram statistics.

```python
cd = CustomDiagrams()
cd.load("diagram.toml")
stats = cd.get_stats()

print(f"Title: {stats['title']}")
print(f"Nodes: {stats['node_count']}")
print(f"Edges: {stats['edge_count']}")
print(f"Node types: {stats['node_types']}")
print(f"Edge types: {stats['edge_types']}")
```

#### `get_available_shapes(category: str = None) -> List[Dict]`

Get available shapes from the gallery.

```python
cd = CustomDiagrams()

# Get all shapes
all_shapes = cd.get_available_shapes()

# Get shapes by category
security_shapes = cd.get_available_shapes(category="security")

for shape in security_shapes:
    print(f"{shape['id']}: {shape['name']} - {shape['description']}")
```

#### `get_available_templates() -> Dict[str, List[str]]`

Get available templates organized by category.

```python
cd = CustomDiagrams()
templates = cd.get_available_templates()

for category, template_list in templates.items():
    print(f"\n{category}:")
    for template in template_list:
        print(f"  - {template}")
```

### VisualizationResult

Result object returned by `BuildCustomDiagram()`.

```python
@dataclass
class VisualizationResult:
    output_path: str        # Path to generated file
    format: str             # Output format (png, svg, etc.)
    stats: Dict[str, Any]   # Diagram statistics
    success: bool           # Whether operation succeeded
```

---

## REST API

### Endpoints

#### POST `/visualize/custom-diagram`

Generate a custom diagram visualization.

**Request:**
- `file`: Configuration file (TOML/JSON/YAML)
- `format`: Output format (png, svg, pdf) - default: png
- `style`: Style preset - default: cd_default

**Response:** Image file (binary)

```bash
curl -X POST "http://localhost:8000/visualize/custom-diagram" \
  -F "file=@diagram.toml" \
  -F "format=png" \
  -F "style=cd_default" \
  --output diagram.png
```

#### POST `/visualize/custom-diagram/content`

Generate from content string.

**Request Body (JSON):**
```json
{
  "content": "...",
  "format": "png",
  "style": "cd_default",
  "config_format": "toml"
}
```

#### POST `/validate/custom-diagram`

Validate a custom diagram configuration.

**Request:**
- `file`: Configuration file

**Response:**
```json
{
  "valid": true,
  "errors": [],
  "warnings": []
}
```

#### GET `/custom-diagrams/shapes`

Get available shapes.

**Query Parameters:**
- `category`: Filter by category (optional)

**Response:**
```json
{
  "shapes": [
    {
      "id": "rectangle",
      "name": "Rectangle",
      "category": "basic",
      "description": "A standard rectangle shape"
    }
  ],
  "categories": ["basic", "security", "network", "flow", "uml", "containers"]
}
```

#### GET `/custom-diagrams/shapes/{shape_id}`

Get details for a specific shape.

**Response:**
```json
{
  "id": "server",
  "name": "Server",
  "category": "security",
  "description": "A server or computing node",
  "graphviz": { "shape": "box3d", "style": "filled" },
  "default_style": { "fillcolor": "#4A90D9", "fontcolor": "white" },
  "ports": ["n", "s", "e", "w"],
  "tags": ["infrastructure", "compute"]
}
```

#### GET `/custom-diagrams/templates`

Get available templates.

**Query Parameters:**
- `category`: Filter by category (optional)

**Response:**
```json
{
  "templates": [
    {
      "id": "flowchart",
      "name": "Flowchart",
      "category": "general",
      "description": "Basic flowchart diagram",
      "path": "general/flowchart.toml"
    }
  ],
  "categories": ["general", "software", "network", "security", "business"]
}
```

#### GET `/custom-diagrams/templates/{template_id}`

Get template content.

**Response:**
```json
{
  "id": "flowchart",
  "name": "Flowchart",
  "category": "general",
  "content": "...",
  "format": "toml"
}
```

#### POST `/visualize/custom-diagram/template/{template_id}`

Generate diagram from template.

**Query Parameters:**
- `format`: Output format (png, svg, pdf)
- `style`: Style preset

**Response:** Image file (binary)

#### GET `/custom-diagrams/styles`

Get available style presets.

**Response:**
```json
{
  "styles": [
    {
      "id": "cd_default",
      "name": "Default",
      "description": "Default light theme"
    }
  ]
}
```

#### GET `/custom-diagrams/layouts`

Get available layout algorithms.

**Response:**
```json
{
  "layouts": [
    {
      "id": "hierarchical",
      "name": "Hierarchical",
      "description": "Top-down or left-right tree layout"
    }
  ]
}
```

#### POST `/analyze/custom-diagram`

Get statistics for a custom diagram.

**Request:**
- `file`: Configuration file

**Response:**
```json
{
  "title": "My Diagram",
  "description": "...",
  "node_count": 10,
  "edge_count": 12,
  "node_types": ["process", "decision"],
  "edge_types": ["flow", "yes", "no"],
  "layout": "hierarchical",
  "direction": "TB"
}
```

---

## CLI Usage

### Basic Usage

```bash
# Generate from configuration file
usecvis -m 4 -i diagram.toml -o output -f png

# Use a specific style
usecvis -m 4 -i diagram.toml -o output -f png -s cd_dark

# Generate SVG output
usecvis -m 4 -i diagram.toml -o output -f svg
```

### Command Options for Mode 4 (Custom Diagrams)

| Option | Description |
|--------|-------------|
| `-i, --ifile` | Input configuration file |
| `-o, --ofile` | Output file path (without extension) |
| `-f, --format` | Output format (png, svg, pdf, dot) |
| `-s, --styleid` | Style preset ID |
| `-v, --validate` | Validate only, don't generate |

### Examples

```bash
# Generate flowchart from template
usecvis -m 4 -i templates/custom-diagrams/general/flowchart.toml -o flowchart -f png

# Validate configuration
usecvis -m 4 -i diagram.toml -v

# Generate with corporate style
usecvis -m 4 -i network.toml -o network_diagram -s cd_corporate -f pdf
```

---

## Advanced Features

### Custom Node Labels

Use label templates to format node labels:

```toml
[schema.nodes.server]
shape = "server"
required_fields = ["name", "ip"]
label_template = "{name}\n{ip}"  # Multi-line label

[schema.nodes.vuln]
shape = "warning"
required_fields = ["name", "cvss"]
label_template = "{name}\nCVSS: {cvss}"
```

### Clusters/Subgraphs

Group nodes into clusters:

```toml
[[clusters]]
id = "dmz"
label = "DMZ"
style = { bgcolor = "#F0F0F0", color = "#666666" }
nodes = ["web1", "web2", "lb"]

[[clusters]]
id = "internal"
label = "Internal Network"
style = { bgcolor = "#E0E0E0", color = "#333333" }
nodes = ["app1", "app2", "db"]
```

### Conditional Styling

Apply styles based on node data:

```toml
[schema.nodes.server]
shape = "server"
required_fields = ["name", "status"]
style = { fillcolor = "#3498DB" }

# Override style based on status field
[schema.nodes.server.conditional_style]
field = "status"
values = { "up" = { fillcolor = "#27AE60" }, "down" = { fillcolor = "#E74C3C" } }
```

### Edge Labels

Add labels to edges:

```toml
[[edges]]
from = "client"
to = "server"
type = "flow"
label = "HTTPS"

[[edges]]
from = "server"
to = "database"
type = "flow"
label = "SQL"
```

### Node Images and Icons

Add images or bundled icons to nodes:

```toml
# Using bundled icons (3000+ included)
[[nodes]]
id = "web_server"
type = "server"
name = "Web Server"
image = "@icon:aws/compute/ec2.png"

[[nodes]]
id = "database"
type = "database"
name = "Database"
image = "@icon:aws/database/rds.png"

[[nodes]]
id = "firewall"
type = "security"
name = "Firewall"
image = "@icon:bootstrap/shield.svg"

# Using custom images
[[nodes]]
id = "custom_node"
type = "custom"
name = "My Node"
image = "/path/to/custom-icon.png"
```

**Bundled Icon Libraries:**

| Provider | Prefix | Examples |
|----------|--------|----------|
| AWS | `@icon:aws/` | `aws/compute/ec2.png`, `aws/database/rds.png` |
| Azure | `@icon:azure/` | `azure/compute/vm.svg`, `azure/storage/blob.svg` |
| Bootstrap | `@icon:bootstrap/` | `bootstrap/shield.svg`, `bootstrap/server.svg` |

When a node has an image:
- Shape is automatically set to `shape="none"`
- Image appears above the label
- Font color defaults to black for readability

---

### Custom Shapes (SVG)

Define custom shapes using SVG:

```toml
# In your configuration file
[custom_shapes.my_icon]
type = "svg"
svg = """
<svg viewBox="0 0 100 100">
  <rect x="10" y="10" width="80" height="80" fill="#3498DB"/>
  <text x="50" y="55" text-anchor="middle" fill="white">Icon</text>
</svg>
"""

# Then use in schema
[schema.nodes.custom_node]
shape = "my_icon"
```

---

## Examples

### Simple Flowchart

```toml
[diagram]
title = "Login Process"
layout = "hierarchical"
direction = "TB"
style = "cd_default"

[schema.nodes.start]
shape = "ellipse"
style = { fillcolor = "#27AE60", fontcolor = "white" }

[schema.nodes.process]
shape = "rectangle"
style = { fillcolor = "#3498DB", fontcolor = "white" }

[schema.nodes.decision]
shape = "diamond"
style = { fillcolor = "#F39C12", fontcolor = "white" }

[schema.nodes.end]
shape = "ellipse"
style = { fillcolor = "#E74C3C", fontcolor = "white" }

[schema.edges.flow]
arrowhead = "normal"

[[nodes]]
id = "start"
type = "start"
name = "Start"

[[nodes]]
id = "input"
type = "process"
name = "Enter Credentials"

[[nodes]]
id = "validate"
type = "decision"
name = "Valid?"

[[nodes]]
id = "success"
type = "end"
name = "Login Success"

[[nodes]]
id = "error"
type = "process"
name = "Show Error"

[[edges]]
from = "start"
to = "input"
type = "flow"

[[edges]]
from = "input"
to = "validate"
type = "flow"

[[edges]]
from = "validate"
to = "success"
type = "flow"
label = "Yes"

[[edges]]
from = "validate"
to = "error"
type = "flow"
label = "No"

[[edges]]
from = "error"
to = "input"
type = "flow"
```

### Network Topology

```toml
[diagram]
title = "Corporate Network"
layout = "hierarchical"
direction = "TB"
style = "cd_default"

[schema.nodes.router]
shape = "router"
required_fields = ["name"]
style = { fillcolor = "#E67E22", fontcolor = "white" }

[schema.nodes.firewall]
shape = "firewall"
required_fields = ["name"]
style = { fillcolor = "#E74C3C", fontcolor = "white" }

[schema.nodes.server]
shape = "server"
required_fields = ["name", "ip"]
label_template = "{name}\n{ip}"
style = { fillcolor = "#3498DB", fontcolor = "white" }

[schema.nodes.client]
shape = "laptop"
required_fields = ["name"]
style = { fillcolor = "#34495E", fontcolor = "white" }

[schema.edges.network]
style = "solid"
arrowhead = "none"

[[nodes]]
id = "internet"
type = "router"
name = "Internet"

[[nodes]]
id = "fw"
type = "firewall"
name = "Firewall"

[[nodes]]
id = "web"
type = "server"
name = "Web Server"
ip = "10.0.1.10"

[[nodes]]
id = "db"
type = "server"
name = "Database"
ip = "10.0.2.10"

[[nodes]]
id = "client1"
type = "client"
name = "Workstation 1"

[[edges]]
from = "internet"
to = "fw"
type = "network"

[[edges]]
from = "fw"
to = "web"
type = "network"

[[edges]]
from = "web"
to = "db"
type = "network"

[[edges]]
from = "client1"
to = "web"
type = "network"
```

---

## Troubleshooting

### Common Issues

#### "Shape not found"

Ensure the shape ID exists in the gallery:

```python
cd = CustomDiagrams()
shapes = cd.get_available_shapes()
print([s['id'] for s in shapes])
```

#### "Node type not defined in schema"

Define all node types in the `[schema.nodes]` section:

```toml
[schema.nodes.my_type]  # Must match type in [[nodes]]
shape = "rectangle"
```

#### "Edge references non-existent node"

Ensure `from` and `to` fields reference valid node IDs:

```toml
[[nodes]]
id = "node1"  # This ID must exist

[[edges]]
from = "node1"  # References node1
to = "node2"    # node2 must also exist
```

#### "Invalid configuration format"

Check that your TOML/JSON/YAML syntax is correct. Use a linter or validator.

### Validation

Always validate before generating:

```python
cd = CustomDiagrams()
cd.load("diagram.toml")
errors = cd.validate()

if errors:
    print("Validation errors:")
    for error in errors:
        print(f"  - {error}")
```

Or via CLI:

```bash
usecvis -m 4 -i diagram.toml -v
```

### Debug Mode

Enable debug logging:

```python
import logging
logging.basicConfig(level=logging.DEBUG)

from usecvislib import CustomDiagrams
cd = CustomDiagrams()
# Debug output will show processing details
```

---

## See Also

- [CLI Guide](CLI_GUIDE.md) - Command-line interface reference
- [Python API Guide](PYTHON_API.md) - Full Python API documentation
- [README](../README.md) - Project overview and installation
- [Templates](../templates/custom-diagrams/) - Template files

---

**USecVisLib** v0.3.1 - Universal Security Visualization Library
