# Custom Diagrams Templates

Pre-built templates for creating various diagram types using the Custom Diagrams module.

## Usage

```python
from usecvislib import CustomDiagrams

# Load a template
cd = CustomDiagrams()
cd.load("templates/custom-diagrams/software/class-diagram.toml")

# Modify the data for your needs
cd.nodes.clear()
cd.edges.clear()
cd.nodes.append({"id": "myclass", "type": "class", "name": "MyClass"})

# Generate the diagram
cd.BuildCustomDiagram(output="my-diagram.png")
```

## Template Categories

### General (`general/`)

General-purpose diagram templates.

| Template | Description |
|----------|-------------|
| `flowchart.toml` | Basic flowchart with process, decision, and terminal nodes |
| `mindmap.toml` | Radial mind mapping diagram |
| `hierarchy.toml` | Hierarchical organization diagram |
| `timeline.toml` | Sequential timeline/roadmap diagram |

### Software Engineering (`software/`)

Templates for software architecture and UML diagrams.

| Template | Description |
|----------|-------------|
| `architecture.toml` | System architecture with layers and components |
| `class-diagram.toml` | UML class diagram with relationships |
| `sequence-diagram.toml` | UML sequence diagram for interactions |
| `component-diagram.toml` | UML component diagram |
| `deployment-diagram.toml` | UML deployment diagram |
| `source-code.toml` | Source code structure visualization |
| `directory-tree.toml` | File/directory tree visualization |

### Network (`network/`)

Network infrastructure templates.

| Template | Description |
|----------|-------------|
| `topology.toml` | Network topology with routers, switches, servers |
| `data-flow.toml` | Data flow between systems |
| `infrastructure.toml` | Cloud/on-prem infrastructure diagram |

### Security (`security/`)

Security-focused diagram templates.

| Template | Description |
|----------|-------------|
| `risk-matrix.toml` | Risk assessment matrix |
| `incident-flow.toml` | Incident response workflow |
| `access-control.toml` | Access control and permission diagram |

### Business (`business/`)

Business process and organizational diagrams.

| Template | Description |
|----------|-------------|
| `process-flow.toml` | Business process flow |
| `swimlane.toml` | Cross-functional swimlane diagram |
| `org-chart.toml` | Organizational hierarchy chart |

## Template Structure

Each template contains:

1. **diagram** - Global settings (title, layout, style)
2. **schema** - Node and edge type definitions
3. **nodes** - Example nodes
4. **edges** - Example edges
5. **clusters** (optional) - Grouping definitions

## Creating Custom Templates

Copy an existing template and modify:

```toml
# my-template.toml

[diagram]
title = "My Custom Diagram"
layout = "hierarchical"
style = "cd_default"

[schema.nodes.my_type]
shape = "rectangle"
required_fields = ["name"]
style = { fillcolor = "#3498DB", fontcolor = "white" }
label_template = "{name}"

[schema.edges.connects]
style = "solid"
color = "#333333"
arrowhead = "normal"

[[nodes]]
id = "node1"
type = "my_type"
name = "First Node"

[[nodes]]
id = "node2"
type = "my_type"
name = "Second Node"

[[edges]]
from = "node1"
to = "node2"
type = "connects"
```

## Available Shapes

See the full shape gallery with `CustomDiagrams().list_shapes()`.

Common shapes:
- **Basic**: rectangle, circle, diamond, ellipse, hexagon, octagon
- **Security**: server, database, firewall, cloud, user, attacker
- **Network**: router, switch, hub, endpoint, laptop
- **Flow**: process, decision, document, terminator
- **UML**: class, interface, actor, usecase, component
- **Containers**: folder, package, boundary

## Style Presets

Available styles:
- `cd_default` - Clean and professional
- `cd_dark` - Dark theme
- `cd_light` - Light minimalist
- `cd_blueprint` - Technical blueprint
- `cd_neon` - Cyberpunk neon
- `cd_pastel` - Soft pastel colors
- `cd_monochrome` - Black and white
