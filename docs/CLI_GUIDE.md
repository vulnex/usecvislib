# USecVisLib CLI Guide

Complete command-line interface reference for the Universal Security Visualization Library.

---

## Table of Contents

1. [Installation](#installation)
2. [Quick Start](#quick-start)
3. [Command Reference](#command-reference)
4. [Visualization Modes](#visualization-modes)
   - [Attack Trees (Mode 0)](#attack-trees-mode-0)
   - [Threat Modeling (Mode 1)](#threat-modeling-mode-1)
   - [Binary Visualization (Mode 2)](#binary-visualization-mode-2)
   - [Attack Graphs (Mode 3)](#attack-graphs-mode-3)
   - [Custom Diagrams (Mode 4)](#custom-diagrams-mode-4)
5. [Image Support for Nodes](#image-support-for-nodes)
6. [Configuration File Formats](#configuration-file-formats)
7. [Available Styles](#available-styles)
8. [Examples](#examples)
9. [Using Templates](#using-templates)
10. [CVSS Support](#cvss-support)
11. [Troubleshooting](#troubleshooting)

---

## Installation

### Prerequisites

```bash
# Install Graphviz (required for graph visualizations)
# macOS
brew install graphviz

# Ubuntu/Debian
sudo apt-get install graphviz

# Windows
choco install graphviz
```

### Install USecVisLib

```bash
# Clone the repository
git clone https://github.com/vulnex/usecvislib.git
cd usecvislib

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install the package
pip install -e .

# Verify installation
usecvis --help
```

---

## Quick Start

```bash
# Generate an attack tree from TOML configuration
usecvis -i attack.toml -o output -m 0

# Generate a threat model with STRIDE report
usecvis -i threat.toml -o diagram -m 1 -r

# Analyze a binary file
usecvis -i binary.exe -o analysis -m 2 -v all

# Generate an attack graph with path analysis
usecvis -i network.toml -o graph -m 3 -p attacker,database -c

# Generate a custom diagram
usecvis -i diagram.toml -o output -m 4 -s cd_default
```

---

## Command Reference

### Synopsis

```
usecvis [options]
```

### Options

| Option | Long Form | Description | Required |
|--------|-----------|-------------|----------|
| `-h` | `--help` | Show help message | No |
| `-i` | `--ifile <file>` | Input file path | Yes |
| `-o` | `--ofile <file>` | Output file path (without extension) | Yes |
| `-f` | `--format <format>` | Output format: `png`, `pdf`, `svg`, `dot` | No (default: `png`) |
| `-m` | `--mode <mode>` | Visualization mode (0-3) | No (default: `0`) |
| `-s` | `--styleid <id>` | Style identifier from config | No |
| `-S` | `--stylefile <file>` | Custom style file path | No |
| `-v` | `--visualization <type>` | Binary visualization type | No (mode 2 only) |
| `-r` | `--report` | Generate STRIDE report | No (mode 1 only) |
| `-p` | `--paths <src,tgt>` | Find attack paths | No (mode 3 only) |
| `-c` | `--critical` | Analyze critical nodes | No (mode 3 only) |

### Visualization Modes

| Mode | Name | Description |
|------|------|-------------|
| `0` | Attack Trees | Hierarchical attack scenario diagrams |
| `1` | Threat Modeling | Data Flow Diagrams with STRIDE analysis |
| `2` | Binary Visualization | Binary file pattern analysis |
| `3` | Attack Graphs | Network attack path visualization |
| `4` | Custom Diagrams | Flexible schema-driven diagrams |

### Output Formats

| Format | Description | Use Case |
|--------|-------------|----------|
| `png` | Portable Network Graphics | Web, presentations |
| `pdf` | Portable Document Format | Documentation, printing |
| `svg` | Scalable Vector Graphics | Web, high-quality scaling |
| `dot` | Graphviz DOT language | Further processing, editing |

---

## Visualization Modes

### Attack Trees (Mode 0)

Attack trees represent security threats as hierarchical structures showing how an attacker might achieve goals.

#### Basic Usage

```bash
usecvis -m 0 -i attack_tree.toml -o output
```

#### With Style

```bash
usecvis -m 0 -i attack_tree.toml -o output -s at_neon -f png
```

#### Supported Input Formats

- TOML (`.toml`, `.tml`)
- JSON (`.json`)
- YAML (`.yaml`, `.yml`)

#### Output

- Visualization file (e.g., `output.png`)
- Console output with tree statistics

#### Example Configuration (TOML)

```toml
[tree]
name = "Web Application Attack"
root = "Compromise Web App"
params = { rankdir = "TB" }

[nodes]
"Compromise Web App" = {style="filled", fillcolor="red", fontcolor="white"}
"SQL Injection" = {style="filled", fillcolor="orange"}
"XSS Attack" = {style="filled", fillcolor="orange"}
"Data Breach" = {style="filled", fillcolor="red", fontcolor="white"}

[edges]
"Compromise Web App" = [
    {to = "SQL Injection", label = "OR"},
    {to = "XSS Attack", label = "OR"}
]
"SQL Injection" = [{to = "Data Breach"}]
"XSS Attack" = [{to = "Data Breach"}]
```

#### Available Styles

| Style ID | Description |
|----------|-------------|
| `at_default` | Default blue/red theme |
| `at_white_black` | White background, black nodes |
| `at_black_white` | Black background, white nodes |
| `at_corporate` | Professional corporate colors |
| `at_neon` | Vibrant neon colors |
| `at_pastel` | Soft pastel colors |
| `at_forest` | Green nature theme |
| `at_fire` | Red/orange fire theme |
| `at_blueprint` | Technical blueprint style |
| `at_sunset` | Warm sunset colors |
| `at_hacker` | Green on black terminal style |
| `at_minimal` | Clean minimal design |
| `at_plain` | No styling |

---

### Threat Modeling (Mode 1)

Create Data Flow Diagrams (DFD) with STRIDE threat analysis.

#### Basic Usage

```bash
usecvis -m 1 -i threat_model.toml -o diagram
```

#### With STRIDE Report

```bash
usecvis -m 1 -i threat_model.toml -o diagram -r
```

This generates:
- `diagram.png` - The DFD visualization
- `diagram_stride_report.md` - STRIDE threat analysis report

#### With Custom Style

```bash
usecvis -m 1 -i threat_model.toml -o diagram -s tm_stride -f pdf
```

#### Example Configuration (TOML)

```toml
[model]
name = "E-Commerce Platform"
description = "Online shopping system threat model"

[externals.customer]
label = "Customer"
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
hasAccessControl = true

[processes.api]
label = "API Service"
authenticatesSource = true
sanitizesInput = true
checksInputBounds = true

[datastores.userdb]
label = "User Database"
isSQL = true
isEncrypted = true
storesPII = true
storesCredentials = true
hasBackup = true

[dataflows.customer_to_web]
from = "customer"
to = "webserver"
label = "HTTPS Request"
protocol = "HTTPS"
isEncrypted = true

[dataflows.web_to_api]
from = "webserver"
to = "api"
label = "Internal API"
protocol = "gRPC"
isEncrypted = true

[dataflows.api_to_db]
from = "api"
to = "userdb"
label = "SQL Queries"
protocol = "PostgreSQL"
isEncrypted = true
sanitizesInput = true

[boundaries.dmz]
label = "DMZ"
elements = ["webserver"]

[boundaries.internal]
label = "Internal Network"
elements = ["api", "userdb"]
```

#### STRIDE Categories

The STRIDE report analyzes threats in these categories:

| Category | Description |
|----------|-------------|
| **S**poofing | Impersonating something or someone |
| **T**ampering | Modifying data or code |
| **R**epudiation | Denying actions |
| **I**nformation Disclosure | Exposing sensitive information |
| **D**enial of Service | Denying service availability |
| **E**levation of Privilege | Gaining unauthorized access |

#### Available Styles

| Style ID | Description |
|----------|-------------|
| `tm_default` | Default DFD colors |
| `tm_stride` | STRIDE-focused coloring |
| `tm_dark` | Dark theme |
| `tm_corporate` | Professional business style |
| `tm_neon` | Vibrant neon colors |
| `tm_minimal` | Clean minimal design |
| `tm_ocean` | Blue ocean theme |
| `tm_sunset` | Warm sunset colors |
| `tm_forest` | Green nature theme |
| `tm_blueprint` | Technical blueprint style |
| `tm_hacker` | Terminal green on black |
| `tm_plain` | No styling |

---

### Binary Visualization (Mode 2)

Analyze and visualize binary file patterns, entropy, and structure.

#### Basic Usage (All Visualizations)

```bash
usecvis -m 2 -i binary.exe -o analysis -v all
```

#### Specific Visualization

```bash
# Entropy analysis
usecvis -m 2 -i binary.exe -o analysis -v entropy

# Byte distribution
usecvis -m 2 -i binary.exe -o analysis -v distribution

# Wind rose pattern
usecvis -m 2 -i binary.exe -o analysis -v windrose

# File structure heatmap
usecvis -m 2 -i binary.exe -o analysis -v heatmap
```

#### Visualization Types

| Type | Description | Output File |
|------|-------------|-------------|
| `entropy` | Sliding window entropy analysis | `*_entropy.png` |
| `distribution` | Byte frequency histogram | `*_distribution.png` |
| `windrose` | Byte pair pattern polar chart | `*_windrose.png` |
| `heatmap` | 2D file structure visualization | `*_heatmap.png` |
| `all` | Generate all visualizations | All of the above |

#### Output Statistics

The CLI displays file statistics after visualization:

```
File Statistics:
  Size: 1,234,567 bytes
  Entropy: 7.4523 bits
  Unique bytes: 256/256
  Null bytes: 2.34%
  Printable ASCII: 45.67%
```

#### Interpreting Entropy

| Entropy Range | Typical Content |
|---------------|-----------------|
| 0.0 - 1.0 | Sparse data, repeated patterns |
| 1.0 - 4.0 | Text, code, structured data |
| 4.0 - 6.0 | Mixed content |
| 6.0 - 7.5 | Compressed or complex data |
| 7.5 - 8.0 | Encrypted or highly compressed |

#### Custom Configuration

Use a TOML configuration file to customize visualization parameters:

```bash
usecvis -m 2 -i binary.exe -o analysis -v entropy -C custom_config.toml
```

Example configuration file:

```toml
# custom_config.toml
[entropy]
window_size = 128
step = 32
show_thresholds = true

[[entropy.thresholds]]
value = 7.5
label = "Encrypted"
color = "red"

[distribution]
bar_width = 0.9
show_regions = true

[heatmap]
block_size = 512
dpi = 200
```

#### Available Styles

| Style ID | Description |
|----------|-------------|
| `bv_default` | Default visualization colors |
| `bv_dark` | Dark theme |
| `bv_security` | Security-focused colors |
| `bv_ocean` | Blue ocean theme |
| `bv_forest` | Green nature theme |
| `bv_sunset` | Warm colors |
| `bv_cyber` | Cyberpunk style |
| `bv_minimal` | Clean minimal design |
| `bv_corporate` | Professional style |
| `bv_fire` | Red/orange fire theme |
| `bv_purple` | Purple theme |
| `bv_rainbow` | Full spectrum colors |

---

### Attack Graphs (Mode 3)

Visualize network attack paths and analyze critical nodes.

#### Basic Usage

```bash
usecvis -m 3 -i network.toml -o graph
```

#### With Path Analysis

```bash
# Find paths from attacker to database
usecvis -m 3 -i network.toml -o graph -p attacker,database
```

#### With Critical Node Analysis

```bash
usecvis -m 3 -i network.toml -o graph -c
```

#### Combined Analysis

```bash
usecvis -m 3 -i network.toml -o graph -p attacker,priv_db_admin -c
```

#### Example Configuration (TOML)

```toml
[graph]
name = "Corporate Network Attack Graph"
description = "Attack paths through corporate infrastructure"

# Hosts
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

[[hosts]]
id = "database"
label = "Database Server"
ip = "10.0.2.10"
zone = "internal"

# Vulnerabilities
[[vulnerabilities]]
id = "vuln_web_rce"
label = "Web RCE (CVE-2024-1234)"
cvss = 9.8
affected_host = "webserver"

[[vulnerabilities]]
id = "vuln_sqli"
label = "SQL Injection"
cvss = 8.5
affected_host = "database"

# Privileges
[[privileges]]
id = "priv_web_shell"
label = "Web Shell"
host = "webserver"
level = "user"

[[privileges]]
id = "priv_db_admin"
label = "DB Admin"
host = "database"
level = "admin"

# Services
[[services]]
id = "svc_http"
label = "HTTP"
host = "webserver"
port = 80

[[services]]
id = "svc_mysql"
label = "MySQL"
host = "database"
port = 3306

# Exploits
[[exploits]]
id = "exploit_rce"
label = "Exploit Web RCE"
vulnerability = "vuln_web_rce"
precondition = "attacker"
postcondition = "priv_web_shell"

[[exploits]]
id = "exploit_sqli"
label = "SQL Injection Attack"
vulnerability = "vuln_sqli"
precondition = "priv_web_shell"
postcondition = "priv_db_admin"

# Network Connectivity
[[network_edges]]
from = "attacker"
to = "webserver"
label = "Internet Access"

[[network_edges]]
from = "webserver"
to = "database"
label = "Internal Network"
```

#### Output Statistics

```
Graph Statistics:
  Name: Corporate Network Attack Graph
  Hosts: 3
  Vulnerabilities: 2
  Privileges: 2
  Services: 2
  Exploits: 2
  Total nodes: 9
  Total edges: 6
  Average CVSS: 9.2
  Critical vulns (CVSS >= 9.0): 1
```

#### Path Analysis Output

```
Attack Paths from 'attacker' to 'priv_db_admin':
  1. attacker -> exploit_rce -> priv_web_shell -> exploit_sqli -> priv_db_admin (length: 5)

  Shortest path length: 5
```

#### Critical Node Analysis Output

```
Top Critical Nodes (by degree centrality):
  1. webserver (host)
     In-degree: 2, Out-degree: 3
     Criticality score: 5
  2. priv_web_shell (privilege)
     In-degree: 1, Out-degree: 2
     Criticality score: 3
```

#### Advanced Graph Analysis (NetworkX)

Additional analysis features are available via the Python API and Web UI:

| Feature | Description |
|---------|-------------|
| **Centrality Analysis** | Betweenness, closeness, and PageRank centrality |
| **Graph Metrics** | Density, diameter, cycle count, SCCs |
| **Chokepoints** | Critical network bottlenecks |
| **Attack Surface** | Entry points and reachability analysis |
| **Vulnerability Impact** | Network-wide impact scoring |

See [Python API Guide](PYTHON_API.md#networkx-advanced-analysis) for programmatic access.

#### Available Styles

| Style ID | Description |
|----------|-------------|
| `ag_default` | Default network colors |
| `ag_dark` | Dark theme |
| `ag_security` | Security-focused (red vulnerabilities) |
| `ag_network` | Network diagram style |
| `ag_minimal` | Clean minimal design |
| `ag_neon` | Vibrant neon colors |
| `ag_corporate` | Professional business style |
| `ag_hacker` | Terminal green on black |
| `ag_blueprint` | Technical blueprint style |
| `ag_plain` | No styling |

---

### Custom Diagrams (Mode 4)

Create flexible, schema-driven diagrams with custom node and edge types.

#### Basic Usage

```bash
usecvis -m 4 -i diagram.toml -o output
```

#### With Style

```bash
usecvis -m 4 -i diagram.toml -o output -s cd_corporate -f png
```

#### Validate Configuration

```bash
usecvis -m 4 -i diagram.toml -v
```

#### Supported Input Formats

- TOML (`.toml`, `.tml`)
- JSON (`.json`)
- YAML (`.yaml`, `.yml`)

#### Output

- Visualization file (e.g., `output.png`)
- Console output with diagram statistics

#### Example Configuration (TOML)

```toml
[diagram]
title = "System Architecture"
layout = "hierarchical"
direction = "TB"
style = "cd_default"
splines = "ortho"

# Define node types
[schema.nodes.server]
shape = "server"
required_fields = ["name", "ip"]
style = { fillcolor = "#3498DB", fontcolor = "white" }
label_template = "{name}\n{ip}"

[schema.nodes.database]
shape = "database"
required_fields = ["name"]
style = { fillcolor = "#27AE60", fontcolor = "white" }

# Define edge types
[schema.edges.connection]
style = "solid"
arrowhead = "normal"
color = "#333333"

# Diagram data
[[nodes]]
id = "web"
type = "server"
name = "Web Server"
ip = "10.0.1.10"

[[nodes]]
id = "db"
type = "database"
name = "PostgreSQL"

[[edges]]
from = "web"
to = "db"
type = "connection"
label = "SQL"
```

#### Available Templates

| Template | Description | Path |
|----------|-------------|------|
| Flowchart | Basic flowchart | `custom-diagrams/general/flowchart.toml` |
| Mind Map | Radial mind mapping | `custom-diagrams/general/mindmap.toml` |
| Architecture | System architecture | `custom-diagrams/software/architecture.toml` |
| Class Diagram | UML class diagram | `custom-diagrams/software/class-diagram.toml` |
| Network Topology | Network diagram | `custom-diagrams/network/topology.toml` |
| Risk Matrix | Risk assessment | `custom-diagrams/security/risk-matrix.toml` |
| Org Chart | Organization chart | `custom-diagrams/business/org-chart.toml` |

#### Using Templates

```bash
# Generate from template
usecvis -m 4 -i templates/custom-diagrams/general/flowchart.toml -o flowchart

# Use different category
usecvis -m 4 -i templates/custom-diagrams/software/architecture.toml -o arch
```

#### Shape Categories

| Category | Example Shapes |
|----------|----------------|
| basic | rectangle, circle, diamond, ellipse, hexagon, star |
| security | server, database, firewall, cloud, user, attacker |
| network | router, switch, endpoint, laptop, mobile, storage |
| flow | process, decision, document, terminator |
| uml | class, interface, package, component, actor |

#### Available Styles

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

See [Custom Diagrams Guide](CUSTOM_DIAGRAMS_GUIDE.md) for complete documentation.

---

## Image Support for Nodes

USecVisLib supports adding images/icons to nodes in visualizations. Images can make diagrams more intuitive by using familiar icons for servers, databases, firewalls, etc.

### Bundled Icon Libraries

USecVisLib includes 3000+ bundled icons organized by provider:

| Provider | Path Prefix | Description |
|----------|-------------|-------------|
| **AWS** | `@icon:aws/` | AWS architecture icons (EC2, S3, Lambda, RDS, etc.) |
| **Azure** | `@icon:azure/` | Microsoft Azure service icons |
| **Bootstrap** | `@icon:bootstrap/` | General-purpose icons |

Use the `@icon:` prefix to reference bundled icons:

```toml
[nodes]
"Web Server" = { image = "@icon:aws/compute/ec2.png" }
"Database" = { image = "@icon:aws/database/rds.png" }
"Firewall" = { image = "@icon:bootstrap/shield.svg" }
```

### Using Custom Images

Add an `image` attribute with a file path for custom images:

```toml
[nodes]
"Web Server" = {
    style = "filled",
    fillcolor = "#3498DB",
    image = "/path/to/server.png"
}

"Database" = {
    style = "filled",
    fillcolor = "#27AE60",
    image = "relative/path/database.png"
}
```

### Supported Image Formats

- PNG (recommended)
- JPG/JPEG
- GIF
- BMP
- SVG

### Image Validation

For security, all image paths are validated:

1. **File must exist** - Path is checked at render time
2. **Extension check** - Only supported image formats allowed
3. **Size limit** - Maximum 5 MB per image
4. **Path security** - No path traversal or null byte injection

If an image path is invalid, a warning is logged and the node renders without the image.

### Example Usage

**Attack Tree with Icons:**
```toml
[tree]
name = "Infrastructure Attack"
root = "Compromise System"

[nodes]
"Compromise System" = { fillcolor = "#E74C3C" }
"Web Server" = { image = "@icon:aws/compute/ec2.png" }
"Database" = { image = "@icon:aws/database/rds.png" }
```

**Attack Graph with Icons:**
```toml
[[hosts]]
id = "web_server"
label = "Web Server"
image = "@icon:aws/compute/ec2.png"
zone = "dmz"
```

**Threat Model with Icons:**
```toml
[processes.api]
name = "API Gateway"
image = "@icon:aws/networking/api-gateway.png"

[datastores.db]
name = "Database"
image = "@icon:aws/database/rds.png"
```

**Custom Diagram with Icons:**
```toml
[[nodes]]
id = "firewall"
type = "security"
name = "Perimeter Firewall"
image = "@icon:bootstrap/shield.svg"
```

### Icon-Enabled Templates

Several templates include icons by default:
- `templates/attack-graphs/network_infrastructure_with_icons.tml`
- `templates/attack-graphs/aws_cloud_security.tml`

Templates with icons have `_with_icons` in their filename.

### Using the Python API

```python
from usecvislib import validate_image_path, process_node_image

# Validate an image path
path = validate_image_path("icons/server.png")

# Process node attributes (used internally)
node_attrs = {"label": "Server", "image": "icons/server.png"}
process_node_image(node_attrs, "server_node")
```

### Adding a Background Shape to Icon Nodes

By default, nodes with icons render cleanly without a background shape (`shape="none"`). If you want to display both an icon and a background shape (e.g., a colored box behind the icon), explicitly set the `shape` attribute in your configuration file:

**Attack Tree Example:**
```toml
[nodes]
"Web Server" = {
    image = "@icon:aws/compute/ec2.png",
    shape = "box",           # Explicitly set shape to preserve it
    style = "filled",
    fillcolor = "#3498db"
}
```

**Attack Graph Example:**
```toml
[hosts.webserver]
label = "Web Server"
image = "@icon:aws/compute/ec2.png"
shape = "box3d"              # Explicitly set shape
style = "filled"
fillcolor = "#2ecc71"
```

**Threat Model Example:**
```toml
[processes.api]
name = "API Gateway"
image = "@icon:aws/networking/api-gateway.png"
shape = "ellipse"            # Explicitly set shape
```

When `shape` is explicitly set, the icon is positioned at the top-center of the node, allowing both the icon and the background shape to be visible.

### Tips

- Use consistent icon sizes for best results (e.g., 64x64 or 128x128 pixels)
- Store icons in a dedicated `icons/` directory alongside your config files
- Use transparent PNG for better integration with node styling
- For large diagrams, consider using smaller icons to avoid clutter
- To add a background shape to icon nodes, explicitly set `shape` in your config

---

## Configuration File Formats

USecVisLib supports three configuration formats:

### TOML (Recommended)

```toml
[section]
key = "value"
number = 42
boolean = true

[[array_section]]
id = "item1"
name = "First Item"
```

### JSON

```json
{
  "section": {
    "key": "value",
    "number": 42,
    "boolean": true
  },
  "array_section": [
    {"id": "item1", "name": "First Item"}
  ]
}
```

### YAML

```yaml
section:
  key: value
  number: 42
  boolean: true

array_section:
  - id: item1
    name: First Item
```

### Format Detection

The format is auto-detected from the file extension:

| Extensions | Format |
|------------|--------|
| `.toml`, `.tml` | TOML |
| `.json` | JSON |
| `.yaml`, `.yml` | YAML |

---

## Examples

### Complete Attack Tree Workflow

```bash
# 1. Create attack tree configuration
cat > my_attack.toml << 'EOF'
[tree]
name = "API Security Attack"
root = "Compromise API"
params = { rankdir = "TB" }

[nodes]
"Compromise API" = {style="filled", fillcolor="#e74c3c", fontcolor="white"}
"Authentication Bypass" = {style="filled", fillcolor="#3498db"}
"Broken Auth" = {style="filled", fillcolor="#5dade2"}
"Token Theft" = {style="filled", fillcolor="#5dade2"}
"Data Exfiltration" = {style="filled", fillcolor="#e74c3c", fontcolor="white"}

[edges]
"Compromise API" = [{to = "Authentication Bypass"}]
"Authentication Bypass" = [{to = "Broken Auth", label="OR"}, {to = "Token Theft", label="OR"}]
"Broken Auth" = [{to = "Data Exfiltration"}]
"Token Theft" = [{to = "Data Exfiltration"}]
EOF

# 2. Generate visualization with neon style
usecvis -m 0 -i my_attack.toml -o api_attack -s at_neon -f png

# 3. Also generate PDF for documentation
usecvis -m 0 -i my_attack.toml -o api_attack -s at_corporate -f pdf
```

### Complete Threat Model Workflow

```bash
# 1. Generate threat model visualization
usecvis -m 1 -i threat_model.toml -o threat_diagram -s tm_stride

# 2. Generate with STRIDE report
usecvis -m 1 -i threat_model.toml -o threat_diagram -s tm_stride -r

# 3. View the generated report
cat threat_diagram_stride_report.md
```

### Complete Binary Analysis Workflow

```bash
# 1. Generate all visualizations for a suspicious file
usecvis -m 2 -i suspicious.bin -o suspicious_analysis -v all

# 2. Focus on entropy to detect packed/encrypted sections
usecvis -m 2 -i suspicious.bin -o entropy_check -v entropy -s bv_security

# 3. Check byte distribution for anomalies
usecvis -m 2 -i suspicious.bin -o dist_check -v distribution
```

### Complete Attack Graph Workflow

```bash
# 1. Generate the attack graph
usecvis -m 3 -i network.toml -o network_graph -s ag_security

# 2. Find all attack paths to the crown jewels
usecvis -m 3 -i network.toml -o network_graph -p attacker,crown_jewels

# 3. Identify critical nodes for hardening priorities
usecvis -m 3 -i network.toml -o network_graph -c

# 4. Combined analysis for security report
usecvis -m 3 -i network.toml -o full_analysis -p attacker,crown_jewels -c
```

---

## Using Templates

USecVisLib includes ready-to-use templates for all visualization types.

### List Available Templates

```bash
ls templates/attack-trees/
ls templates/attack-graphs/
ls templates/threat-models/
```

### Generate from Template

```bash
# Attack tree from template
usecvis -m 0 -i templates/attack-trees/ransomware_attack.tml -o ransomware -s at_neon

# Attack graph from template
usecvis -m 3 -i templates/attack-graphs/corporate_network.tml -o corp_network -s ag_security

# Threat model from template
usecvis -m 1 -i templates/threat-models/banking_api.tml -o banking -s tm_stride -r
```

### Template Formats

All templates are available in TOML, JSON, and YAML:

```bash
# Use any format
usecvis -m 3 -i templates/attack-graphs/corporate_network.json -o output
usecvis -m 3 -i templates/attack-graphs/corporate_network.yaml -o output
```

### Available Templates

| Category | Templates |
|----------|-----------|
| Attack Trees | `insider_threat`, `ransomware_attack`, `web_application_attack` |
| Attack Graphs | `cloud_infrastructure`, `corporate_network`, `simple_network` |
| Threat Models | `banking_api`, `cicd_pipeline`, `cloud_infrastructure`, `ecommerce_platform`, `healthcare_system`, `iot_system`, `microservices_architecture`, `saas_multitenant` |

---

## CVSS Support

Attack trees, attack graphs, and threat models support CVSS (Common Vulnerability Scoring System) scores.

### CVSS in Configurations

Add CVSS scores to your configuration files:

#### Attack Graph Vulnerabilities

```toml
[[vulnerabilities]]
id = "vuln_rce"
label = "Remote Code Execution"
cvss = 9.8                    # Numeric score
affected_host = "webserver"

[[vulnerabilities]]
id = "vuln_sqli"
label = "SQL Injection"
cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"  # Or vector string
affected_host = "database"
```

#### Attack Tree Nodes

```toml
[nodes]
"SQL Injection" = {style="filled", fillcolor="orange", cvss=8.5}
"Phishing Attack" = {style="filled", cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N"}
```

#### Threat Model Threats

```toml
[threats.sql_injection]
category = "Tampering"
description = "SQL injection attack on database"
cvss = 8.5
severity = "High"
```

### CVSS in Output

When generating visualizations:
- **Attack Graphs**: Vulnerability nodes are color-coded by severity
- **Attack Trees**: Nodes with CVSS show scores and severity badges
- **Statistics**: Average CVSS, critical count, and high-risk nodes reported

```bash
# Generate attack graph - CVSS colors applied automatically
usecvis -m 3 -i network_with_cvss.toml -o output

# Output includes CVSS statistics:
# Average CVSS: 8.43
# Critical vulnerabilities (CVSS >= 9.0): 2
# High vulnerabilities (CVSS >= 7.0): 4
```

### Severity Colors

| CVSS Range | Severity | Color |
|------------|----------|-------|
| 9.0 - 10.0 | Critical | Dark Red |
| 7.0 - 8.9 | High | Red |
| 4.0 - 6.9 | Medium | Orange |
| 0.1 - 3.9 | Low | Green |
| 0.0 | None | Blue |

---

## Troubleshooting

### Common Issues

#### "Graphviz not found"

```bash
# Install Graphviz
brew install graphviz      # macOS
apt install graphviz       # Ubuntu
choco install graphviz     # Windows
```

#### "Input file not found"

Ensure the path is correct and the file exists:

```bash
ls -la your_config.toml
```

#### "Invalid format"

Supported output formats are: `png`, `pdf`, `svg`, `dot`

```bash
# Correct
usecvis -i config.toml -o output -f png

# Incorrect
usecvis -i config.toml -o output -f jpeg
```

#### "Invalid mode"

Valid modes are 0, 1, 2, or 3:

```bash
# Correct
usecvis -i config.toml -o output -m 0

# Incorrect
usecvis -i config.toml -o output -m 5
```

#### "Missing required section"

Ensure your configuration file has the required sections:

| Mode | Required Sections |
|------|-------------------|
| 0 (Attack Trees) | `tree`, `nodes`, `edges` |
| 1 (Threat Model) | `model` |
| 2 (Binary) | N/A (just a binary file) |
| 3 (Attack Graph) | `graph`, `hosts` |
| 4 (Custom Diagrams) | `diagram`, `schema`, `nodes` |

### Getting Help

```bash
# Show help message
usecvis --help
usecvis -h
```

---

## Batch Processing

For processing multiple files, use the Python API's batch processing capabilities:

```bash
# Python script for batch processing
python3 -c "
from usecvislib import BatchProcessor, process_batch

# Process all TOML files in a directory
processor = BatchProcessor('attack_graph', './output', format='png')
result = processor.process_directory('./configs')

print(f'Processed: {result.success_count}/{result.total}')
print(f'Success rate: {result.success_percentage:.1f}%')
"
```

See [Python API Guide](PYTHON_API.md#batch-processing) for full batch processing documentation.

---

## Comparing Configurations

Compare two configuration files to track changes:

```bash
# Python script for diffing configurations
python3 -c "
from usecvislib import compare_files

result = compare_files('old_network.toml', 'new_network.toml', 'attack_graph')
print(f'Changes: {result.summary}')

for change in result.added():
    print(f'+ {change.path}')
for change in result.removed():
    print(f'- {change.path}')
"
```

See [Python API Guide](PYTHON_API.md#diff-and-comparison) for full diff documentation.

---

## Running the REST API Server

USecVisLib includes a REST API server for web-based access. The API supports optional authentication.

### Starting the Server

```bash
# Without authentication (local development)
USECVISLIB_AUTH_ENABLED=false python -m uvicorn api.main:app --port 8000

# With authentication
export USECVISLIB_API_KEY=your-secure-key-here
python -m uvicorn api.main:app --port 8000
```

### Generating an API Key

```bash
python -c "import secrets; print(f'usecvis_{secrets.token_urlsafe(32)}')"
```

### Authentication Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `USECVISLIB_AUTH_ENABLED` | `true` | Enable/disable authentication |
| `USECVISLIB_API_KEY` | (none) | Single API key |
| `USECVISLIB_API_KEYS` | (none) | Multiple keys (comma-separated) |

### Making Authenticated Requests

```bash
# With authentication enabled
curl -H "X-API-Key: your-key" http://localhost:8000/health

# Check available styles
curl -H "X-API-Key: your-key" http://localhost:8000/styles
```

### Docker Deployment

```bash
# Copy environment template
cp .env.example .env

# Edit .env and set your API key
# USECVISLIB_API_KEY=your-secure-key-here

# Start services
docker-compose up -d
```

See [UI Guide](UI_GUIDE.md#api-authentication) for configuring authentication in the web interface.

---

## See Also

- [Python API Guide](PYTHON_API.md) - Programmatic access to USecVisLib
- [Custom Diagrams Guide](CUSTOM_DIAGRAMS_GUIDE.md) - Custom diagrams documentation
- [UI Guide](UI_GUIDE.md) - Web interface documentation
- [README](../README.md) - Project overview and installation
- [Templates](../templates/) - Example configuration files

---

**USecVisLib** v0.3.2 - Universal Security Visualization Library
