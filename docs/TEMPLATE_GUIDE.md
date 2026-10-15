# USecVisLib Template Guide

A comprehensive guide for creating configuration templates for USecVisLib visualizations. This document covers all supported formats (TOML, YAML, JSON) and all visualization modules (Attack Trees, Attack Graphs, Threat Models, Custom Diagrams, Component Diagrams, and Dependency Graphs).

## Table of Contents

1. [Overview](#overview)
2. [Supported Formats](#supported-formats)
3. [Attack Trees](#attack-trees)
4. [Attack Graphs](#attack-graphs)
5. [Threat Models](#threat-models)
6. [Custom Diagrams](#custom-diagrams)
7. [Component Diagrams](#component-diagrams)
8. [Dependency Graphs](#dependency-graphs)
9. [Privilege Gradients](#privilege-gradients)
10. [Common Elements](#common-elements)
11. [CVSS Integration](#cvss-integration)
12. [Icons and Images](#icons-and-images)
13. [Available Styles](#available-styles)
14. [Best Practices](#best-practices)

---

## Overview

USecVisLib supports multiple configuration formats for defining security visualizations. Each visualization type has a specific schema that defines the structure of entities, relationships, and visual properties.

### Quick Reference

| Module | CLI Mode | Root Key | Purpose |
|--------|----------|----------|---------|
| Attack Trees | `-m 0` | `tree` | Hierarchical attack scenarios |
| Threat Models | `-m 1` | `model` | Data Flow Diagrams (DFD) |
| Binary Visualization | `-m 2` | N/A | Binary file analysis |
| Attack Graphs | `-m 3` | `graph` | Network attack paths |
| Custom Diagrams | N/A | `diagram` | Schema-driven custom diagrams |
| Component Diagrams | `-m 7` | `title` + `layers` | Layered architecture visualization |
| Dependency Graphs | `-m 8` | `title` + `modules` | Module dependency analysis |

Every template in `templates/` is rendered with each engine and style preset in the [render gallery](https://vulnex.github.io/usecvislib-gallery/), so you can see what a config produces before you edit it.

---

## Supported Formats

USecVisLib accepts configurations in three formats:

### TOML (Recommended)
- File extensions: `.toml`, `.tml`
- Human-readable and easy to edit
- Best for complex nested structures
- Native comment support

### YAML
- File extensions: `.yaml`, `.yml`
- Clean indentation-based syntax
- Good for hierarchical data
- Supports comments with `#`

### JSON
- File extension: `.json`
- Universal data interchange format
- Best for programmatic generation
- No native comment support

### Format Detection
The format is automatically detected from the file extension. All three formats are functionally equivalent - choose based on preference or tooling requirements.

---

## Attack Trees

Attack trees model hierarchical attack scenarios using a tree structure with nodes and edges. They support AND/OR gates to represent alternative or combined attack paths.

### Schema Structure

```
tree (required)
├── name (required): string - Tree name
├── root (required): string - Root node identifier
├── description (optional): string - Description
├── engineversion (optional): string - USecVisLib version
├── version (optional): string - Template version
├── type (optional): string - "Attack Tree"
├── date (optional): string - Creation date
├── last_modified (optional): string - Last modified date
├── author (optional): string - Author name
├── email (optional): string - Author email
├── url (optional): string - Author URL
└── params (optional): object - Graph layout parameters
    ├── rankdir: "TB" | "BT" | "LR" | "RL"
    ├── splines: "ortho" | "polyline" | "curved" | "line"
    └── nodesep: string - Node separation

nodes (required): object
└── "<node_name>" (key): object
    ├── style (optional): string - "filled", "bold", etc.
    ├── fillcolor (optional): string - Hex color "#RRGGBB"
    ├── fontcolor (optional): string - Hex color or name
    ├── shape (optional): string - Graphviz shape
    ├── gate (optional): "AND" | "OR" - Gate type
    ├── cvss (optional): number - CVSS score (0.0-10.0)
    ├── cvss_vector (optional): string - Full CVSS vector
    └── image (optional): string - Icon path

edges (required): object
└── "<source_node>" (key): array
    └── object
        ├── to (required): string - Target node name
        └── label (optional): string - Edge label
```

### TOML Example

```toml
#
# Attack Tree: Web Application Security
#

[tree]
name = "Web Application Attack Tree"
root = "Compromise Web App"
description = "Attack vectors for web application compromise"
engineversion = "0.3.2"
version = "1.0.0"
type = "Attack Tree"
date = "2025-01-08"
author = "Security Team"
params = { rankdir = "TB", splines = "ortho", nodesep = "1.0" }

[nodes]
# Root node - Main attack goal
"Compromise Web App" = {style = "filled", fillcolor = "#E74C3C", fontcolor = "white", shape = "box", gate = "OR"}

# Level 1 - Main attack vectors
"Exploit Authentication" = {style = "filled", fillcolor = "#3498DB", fontcolor = "white", gate = "OR"}
"Exploit Input Validation" = {style = "filled", fillcolor = "#3498DB", fontcolor = "white", gate = "OR"}
"Exploit Configuration" = {style = "filled", fillcolor = "#3498DB", fontcolor = "white", gate = "AND"}

# Level 2 - Specific attacks with CVSS scores
"Brute Force Login" = {style = "filled", fillcolor = "#F39C12", cvss = 7.5}
"Credential Stuffing" = {style = "filled", fillcolor = "#F39C12", cvss = 8.1}
"Session Hijacking" = {style = "filled", fillcolor = "#F39C12", cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N"}

"SQL Injection" = {style = "filled", fillcolor = "#9B59B6", cvss = 9.8}
"XSS Attack" = {style = "filled", fillcolor = "#9B59B6", cvss = 6.1}
"Command Injection" = {style = "filled", fillcolor = "#9B59B6", cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"}

"Exposed Debug Mode" = {style = "filled", fillcolor = "#1ABC9C", cvss = 5.3}
"Default Credentials" = {style = "filled", fillcolor = "#1ABC9C", cvss = 9.1}

[edges]
"Compromise Web App" = [
    {to = "Exploit Authentication", label = "OR"},
    {to = "Exploit Input Validation", label = "OR"},
    {to = "Exploit Configuration", label = "OR"}
]
"Exploit Authentication" = [
    {to = "Brute Force Login"},
    {to = "Credential Stuffing"},
    {to = "Session Hijacking"}
]
"Exploit Input Validation" = [
    {to = "SQL Injection", label = "CRITICAL"},
    {to = "XSS Attack", label = "MEDIUM"},
    {to = "Command Injection", label = "HIGH"}
]
"Exploit Configuration" = [
    {to = "Exposed Debug Mode", label = "AND"},
    {to = "Default Credentials", label = "AND"}
]
```

### YAML Example

```yaml
tree:
  name: Web Application Attack Tree
  root: Compromise Web App
  description: Attack vectors for web application compromise
  engineversion: "0.3.2"
  version: "1.0.0"
  type: Attack Tree
  date: "2025-01-08"
  author: Security Team
  params:
    rankdir: TB
    splines: ortho
    nodesep: "1.0"

nodes:
  # Root node - Main attack goal
  Compromise Web App:
    style: filled
    fillcolor: "#E74C3C"
    fontcolor: white
    shape: box
    gate: OR

  # Level 1 - Main attack vectors
  Exploit Authentication:
    style: filled
    fillcolor: "#3498DB"
    fontcolor: white
    gate: OR

  Exploit Input Validation:
    style: filled
    fillcolor: "#3498DB"
    fontcolor: white
    gate: OR

  Exploit Configuration:
    style: filled
    fillcolor: "#3498DB"
    fontcolor: white
    gate: AND

  # Level 2 - Specific attacks with CVSS
  Brute Force Login:
    style: filled
    fillcolor: "#F39C12"
    cvss: 7.5

  Credential Stuffing:
    style: filled
    fillcolor: "#F39C12"
    cvss: 8.1

  Session Hijacking:
    style: filled
    fillcolor: "#F39C12"
    cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N"

  SQL Injection:
    style: filled
    fillcolor: "#9B59B6"
    cvss: 9.8

  XSS Attack:
    style: filled
    fillcolor: "#9B59B6"
    cvss: 6.1

  Command Injection:
    style: filled
    fillcolor: "#9B59B6"
    cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"

  Exposed Debug Mode:
    style: filled
    fillcolor: "#1ABC9C"
    cvss: 5.3

  Default Credentials:
    style: filled
    fillcolor: "#1ABC9C"
    cvss: 9.1

edges:
  Compromise Web App:
    - to: Exploit Authentication
      label: OR
    - to: Exploit Input Validation
      label: OR
    - to: Exploit Configuration
      label: OR

  Exploit Authentication:
    - to: Brute Force Login
    - to: Credential Stuffing
    - to: Session Hijacking

  Exploit Input Validation:
    - to: SQL Injection
      label: CRITICAL
    - to: XSS Attack
      label: MEDIUM
    - to: Command Injection
      label: HIGH

  Exploit Configuration:
    - to: Exposed Debug Mode
      label: AND
    - to: Default Credentials
      label: AND
```

### JSON Example

```json
{
  "tree": {
    "name": "Web Application Attack Tree",
    "root": "Compromise Web App",
    "description": "Attack vectors for web application compromise",
    "engineversion": "0.3.2",
    "version": "1.0.0",
    "type": "Attack Tree",
    "date": "2025-01-08",
    "author": "Security Team",
    "params": {
      "rankdir": "TB",
      "splines": "ortho",
      "nodesep": "1.0"
    }
  },
  "nodes": {
    "Compromise Web App": {
      "style": "filled",
      "fillcolor": "#E74C3C",
      "fontcolor": "white",
      "shape": "box",
      "gate": "OR"
    },
    "Exploit Authentication": {
      "style": "filled",
      "fillcolor": "#3498DB",
      "fontcolor": "white",
      "gate": "OR"
    },
    "Exploit Input Validation": {
      "style": "filled",
      "fillcolor": "#3498DB",
      "fontcolor": "white",
      "gate": "OR"
    },
    "Exploit Configuration": {
      "style": "filled",
      "fillcolor": "#3498DB",
      "fontcolor": "white",
      "gate": "AND"
    },
    "Brute Force Login": {
      "style": "filled",
      "fillcolor": "#F39C12",
      "cvss": 7.5
    },
    "Credential Stuffing": {
      "style": "filled",
      "fillcolor": "#F39C12",
      "cvss": 8.1
    },
    "Session Hijacking": {
      "style": "filled",
      "fillcolor": "#F39C12",
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N"
    },
    "SQL Injection": {
      "style": "filled",
      "fillcolor": "#9B59B6",
      "cvss": 9.8
    },
    "XSS Attack": {
      "style": "filled",
      "fillcolor": "#9B59B6",
      "cvss": 6.1
    },
    "Command Injection": {
      "style": "filled",
      "fillcolor": "#9B59B6",
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
    },
    "Exposed Debug Mode": {
      "style": "filled",
      "fillcolor": "#1ABC9C",
      "cvss": 5.3
    },
    "Default Credentials": {
      "style": "filled",
      "fillcolor": "#1ABC9C",
      "cvss": 9.1
    }
  },
  "edges": {
    "Compromise Web App": [
      {"to": "Exploit Authentication", "label": "OR"},
      {"to": "Exploit Input Validation", "label": "OR"},
      {"to": "Exploit Configuration", "label": "OR"}
    ],
    "Exploit Authentication": [
      {"to": "Brute Force Login"},
      {"to": "Credential Stuffing"},
      {"to": "Session Hijacking"}
    ],
    "Exploit Input Validation": [
      {"to": "SQL Injection", "label": "CRITICAL"},
      {"to": "XSS Attack", "label": "MEDIUM"},
      {"to": "Command Injection", "label": "HIGH"}
    ],
    "Exploit Configuration": [
      {"to": "Exposed Debug Mode", "label": "AND"},
      {"to": "Default Credentials", "label": "AND"}
    ]
  }
}
```

### Node Properties Reference

| Property | Type | Description | Example |
|----------|------|-------------|---------|
| `style` | string | Graphviz node style | `"filled"`, `"filled,bold"`, `"filled,rounded"` |
| `fillcolor` | string | Background color | `"#E74C3C"`, `"red"` |
| `fontcolor` | string | Text color | `"white"`, `"#333333"` |
| `shape` | string | Node shape | `"box"`, `"rectangle"`, `"ellipse"`, `"diamond"`, `"octagon"` |
| `gate` | string | Gate type for tree logic | `"AND"`, `"OR"` |
| `cvss` | number | CVSS score (0.0-10.0) | `7.5`, `9.8` |
| `cvss_vector` | string | Full CVSS v3.1 vector | `"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"` |
| `image` | string | Icon path (bundled or custom) | `"bundled:aws/Security-Identity-Compliance/IAM"` |

---

## Attack Graphs

Attack graphs model network attack scenarios with hosts, vulnerabilities, privileges, services, and exploits. They support path analysis and CVSS scoring.

### Schema Structure

```
graph (required)
├── name (required): string - Graph name
├── description (optional): string - Description
├── engineversion (optional): string - USecVisLib version
├── version (optional): string - Template version
├── type (optional): string - "Attack Graph"
├── date (optional): string - Creation date
├── last_modified (optional): string - Last modified date
├── author (optional): string - Author name
├── email (optional): string - Author email
└── url (optional): string - Author URL

hosts (required): array of objects
├── id (required): string - Unique host identifier
├── label (required): string - Display name
├── description (optional): string - Host description
├── ip (optional): string - IP address
├── zone (optional): string - Network zone
└── os (optional): string - Operating system

vulnerabilities (optional): array of objects
├── id (required): string - Unique vulnerability ID
├── label (required): string - Display name
├── description (optional): string - Vulnerability description
├── cvss_vector (optional): string - CVSS v3.1 vector
├── cvss (optional): number - CVSS score
├── cve (optional): string - CVE identifier
└── affected_host (required): string - Host ID

privileges (optional): array of objects
├── id (required): string - Unique privilege ID
├── label (required): string - Display name
├── description (optional): string - Privilege description
├── host (optional): string - Associated host ID
└── level (optional): string - Privilege level

services (optional): array of objects
├── id (required): string - Unique service ID
├── label (required): string - Display name
├── host (required): string - Host ID
├── port (optional): number - Port number
└── protocol (optional): string - Protocol (tcp/udp)

exploits (optional): array of objects
├── id (required): string - Unique exploit ID
├── label (required): string - Display name
├── description (optional): string - Exploit description
├── vulnerability (optional): string - Target vulnerability ID
├── precondition (required): string - Required privilege/state
└── postcondition (required): string - Resulting privilege/state

network_edges (optional): array of objects
├── from (required): string - Source host ID
├── to (required): string - Target host ID
└── label (optional): string - Connection label
```

### Grouping and collapse

Large graphs can cluster hosts into groups, and draw a group as one summary node. Grouping is opt-in: without `group_by` (and without host `group` fields) the graph renders exactly as before.

```toml
[graph]
name = "Segmented Enterprise"
group_by = "zone"          # host field to group on, or "ip/24" / "ip6/64" to group by network
collapse = "auto"          # false (default) | true | "auto" | ["dmz", "users"]
max_nodes = 300            # target for "auto"

[groups.dmz]               # optional per group
label = "DMZ"
color = "#fde68a"          # cluster fill
collapsed = false          # always expanded (or true: always collapsed)

[hosts.web01]
zone = "dmz"               # picked up by group_by = "zone"
group = "dmz"              # or set the group directly (wins over group_by)
```

**Membership:** a host's `group`, else its `group_by` value (for `ip/N`, the network of its `ip`). Vulnerabilities, services and privileges follow their host. An exploit belongs to a group only when all its pre/postconditions are in that group. Hosts without a group stay outside the clusters.

**Expanded** groups are drawn as labelled clusters around their members.

**Collapsed** groups become one summary node: the group's label, its host / vulnerability / service counts, and the colour (and, in the SVG engine, the CVSS badge) of its highest-CVSS vulnerability. Members are folded into it. Edges inside the group are dropped; edges into or out of it point at the summary node, and edges that end up identical are merged and labelled `×N`.

- `collapse = true` collapses every group with more than one member; a list collapses those groups; `"auto"` collapses the largest groups first until at most `max_nodes` nodes are drawn.
- A group's own `collapsed` setting always wins.
- The size limit (10,000 nodes / 50,000 edges) applies to what is drawn, so a large scan grouped by subnet and collapsed renders instead of being rejected.
- Path analysis and statistics always use the full graph. With grouping on, statistics add per-group counts (`groups`).
- The same options exist as render parameters (`AttackGraphs(..., group_by=, collapse=, max_nodes=)`, `--group-by` / `--collapse` / `--max-nodes`, and API query parameters), which override the file.
- SVG output: clusters are `usv-cluster` groups with `data-cluster-id` and `data-collapsed="false"`; summary nodes have class `usv-node--group` with `data-collapsed="true"`, `data-cluster-id`, `data-member-count`, `data-hosts`, `data-vulnerabilities`, `data-max-cvss`; merged edges carry `data-edge-count`.

Example: `templates/attack-graphs/segmented_enterprise.toml`.

### Inferred elements

Elements that are a hypothesis rather than an observation (for example an exploit step or ATT&CK mapping proposed by an AI assistant) can be marked so they are never mistaken for facts:

```toml
[exploits.proposed_step]
label = "Proposed lateral movement"
precondition = "priv_web"
postcondition = "priv_db"
inferred = true                  # or: confidence = "hypothesis"
confidence = "medium"            # optional; shown as data-confidence in SVG

[network_edges.e7]
from = "web01"
to = "db01"
confidence = "hypothesis"
```

| Module | What can be inferred | Field |
|---|---|---|
| Attack graph | an exploit (its node and pre/postcondition edges), a network edge | `inferred = true` or `confidence = "hypothesis"` (also `"inferred"`) |
| Kill chain | a technique | same fields on the technique |
| Incident timeline | an event's technique tag | `technique_inferred = true` or `technique_confidence = "hypothesis"` |

How they are drawn:

- **Attack graph:** inferred exploits get a muted grey fill, a dashed outline and an "(inferred)" line; inferred edges are dashed and muted violet (Graphviz also gives them a hollow arrowhead). When edges are merged by a collapse, the result is inferred only if every merged edge was.
- **Kill chain:** the technique keeps its coverage color but is faded, with a dashed border and an "(inferred)" line, so coverage stays readable.
- **Incident timeline:** the tag reads `T1059 (inferred)` (compact mode shows titles only).
- **SVG output:** `usv-node--inferred` / `usv-edge--inferred` classes and `data-inferred`, `data-confidence` (timeline: `data-technique-inferred`, `data-technique-confidence`), so a UI can filter hypotheses.
- Statistics count them: `inferred_techniques` (kill chain), `inferred_tags` (timeline).
- Example: `templates/kill-chains/atlas_agent_prompt_injection.tml` (AML.T0080 is a hypothesis).

### Multi-source findings

When a finding was reported by several tools, any host, vulnerability, privilege, service or exploit can say so:

```toml
[vulnerabilities.cve1]
label = "CVE-2021-41773"
host = "web01"
cvss = 9.8
sources = ["nuclei", "nessus", "nmap"]   # names, or "nuclei, nessus"

[privileges.root]
label = "root on web01"
source_count = 2                         # when only the count is known
```

The count is the larger of the two fields. With 2 or more sources, the SVG engine draws a "✓N" chip on the card's top-left corner (the CVSS chip is top-right), and the Graphviz engine adds a "✓ N sources" line to the label. The SVG node carries `data-source-count` and `data-sources` either way, so a UI can filter on them. Themes can turn the chip off with `badges.sources = false`.

### TOML Example

```toml
#
# Attack Graph: Corporate Network
#

[graph]
name = "Corporate Network Attack Scenario"
description = "Attack graph for a typical corporate network"
engineversion = "0.3.2"
version = "1.0.0"
type = "Attack Graph"
date = "2025-01-08"
author = "Security Team"
email = "security@company.com"

[[hosts]]
id = "attacker"
label = "External Attacker"
description = "Threat actor on the internet"
zone = "external"

[[hosts]]
id = "firewall"
label = "Perimeter Firewall"
ip = "203.0.113.1"
zone = "perimeter"
os = "PAN-OS"

[[hosts]]
id = "webserver"
label = "Web Server"
description = "Public-facing web application"
ip = "10.0.1.10"
zone = "dmz"
os = "Ubuntu 22.04"

[[hosts]]
id = "appserver"
label = "Application Server"
description = "Backend application services"
ip = "10.0.2.10"
zone = "internal"
os = "RHEL 9"

[[hosts]]
id = "database"
label = "Database Server"
description = "PostgreSQL database with customer data"
ip = "10.0.3.10"
zone = "data"
os = "Linux"

[[vulnerabilities]]
id = "vuln_rce"
label = "Remote Code Execution"
description = "Unauthenticated RCE in web application"
cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
affected_host = "webserver"

[[vulnerabilities]]
id = "vuln_sqli"
label = "SQL Injection"
description = "SQL injection in search functionality"
cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
affected_host = "appserver"

[[vulnerabilities]]
id = "vuln_privesc"
label = "Privilege Escalation"
description = "Local privilege escalation via kernel exploit"
cvss_vector = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
cve = "CVE-2024-1234"
affected_host = "webserver"

[[privileges]]
id = "priv_internet"
label = "Internet Access"
description = "External network access"
level = "none"

[[privileges]]
id = "priv_web_user"
label = "Web Shell"
description = "Low privilege shell on web server"
host = "webserver"
level = "user"

[[privileges]]
id = "priv_web_root"
label = "Web Root"
description = "Root access on web server"
host = "webserver"
level = "root"

[[privileges]]
id = "priv_app_access"
label = "App Access"
description = "Access to application server"
host = "appserver"
level = "user"

[[privileges]]
id = "priv_db_read"
label = "DB Read"
description = "Read access to database"
host = "database"
level = "user"

[[services]]
id = "svc_http"
label = "HTTPS"
host = "webserver"
port = 443
protocol = "tcp"

[[services]]
id = "svc_api"
label = "REST API"
host = "appserver"
port = 8080
protocol = "tcp"

[[services]]
id = "svc_postgres"
label = "PostgreSQL"
host = "database"
port = 5432
protocol = "tcp"

[[exploits]]
id = "exploit_rce"
label = "Exploit RCE"
description = "Exploit unauthenticated RCE for initial access"
vulnerability = "vuln_rce"
precondition = "attacker"
postcondition = "priv_web_user"

[[exploits]]
id = "exploit_privesc"
label = "Kernel Exploit"
description = "Escalate to root via kernel vulnerability"
vulnerability = "vuln_privesc"
precondition = "priv_web_user"
postcondition = "priv_web_root"

[[exploits]]
id = "exploit_pivot"
label = "Pivot Internal"
description = "Use web server to access internal network"
precondition = "priv_web_root"
postcondition = "priv_app_access"

[[exploits]]
id = "exploit_sqli"
label = "SQL Injection"
description = "Extract database credentials via SQLi"
vulnerability = "vuln_sqli"
precondition = "priv_app_access"
postcondition = "priv_db_read"

[[network_edges]]
from = "attacker"
to = "firewall"
label = "Internet"

[[network_edges]]
from = "firewall"
to = "webserver"
label = "HTTPS (443)"

[[network_edges]]
from = "webserver"
to = "appserver"
label = "API (8080)"

[[network_edges]]
from = "appserver"
to = "database"
label = "PostgreSQL (5432)"
```

### YAML Example

```yaml
graph:
  name: Corporate Network Attack Scenario
  description: Attack graph for a typical corporate network
  engineversion: "0.3.2"
  version: "1.0.0"
  type: Attack Graph
  date: "2025-01-08"
  author: Security Team
  email: security@company.com

hosts:
  - id: attacker
    label: External Attacker
    description: Threat actor on the internet
    zone: external

  - id: firewall
    label: Perimeter Firewall
    ip: "203.0.113.1"
    zone: perimeter
    os: PAN-OS

  - id: webserver
    label: Web Server
    description: Public-facing web application
    ip: "10.0.1.10"
    zone: dmz
    os: Ubuntu 22.04

  - id: appserver
    label: Application Server
    description: Backend application services
    ip: "10.0.2.10"
    zone: internal
    os: RHEL 9

  - id: database
    label: Database Server
    description: PostgreSQL database with customer data
    ip: "10.0.3.10"
    zone: data
    os: Linux

vulnerabilities:
  - id: vuln_rce
    label: Remote Code Execution
    description: Unauthenticated RCE in web application
    cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    affected_host: webserver

  - id: vuln_sqli
    label: SQL Injection
    description: SQL injection in search functionality
    cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
    affected_host: appserver

  - id: vuln_privesc
    label: Privilege Escalation
    description: Local privilege escalation via kernel exploit
    cvss_vector: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
    cve: CVE-2024-1234
    affected_host: webserver

privileges:
  - id: priv_internet
    label: Internet Access
    description: External network access
    level: none

  - id: priv_web_user
    label: Web Shell
    description: Low privilege shell on web server
    host: webserver
    level: user

  - id: priv_web_root
    label: Web Root
    description: Root access on web server
    host: webserver
    level: root

  - id: priv_app_access
    label: App Access
    description: Access to application server
    host: appserver
    level: user

  - id: priv_db_read
    label: DB Read
    description: Read access to database
    host: database
    level: user

services:
  - id: svc_http
    label: HTTPS
    host: webserver
    port: 443
    protocol: tcp

  - id: svc_api
    label: REST API
    host: appserver
    port: 8080
    protocol: tcp

  - id: svc_postgres
    label: PostgreSQL
    host: database
    port: 5432
    protocol: tcp

exploits:
  - id: exploit_rce
    label: Exploit RCE
    description: Exploit unauthenticated RCE for initial access
    vulnerability: vuln_rce
    precondition: attacker
    postcondition: priv_web_user

  - id: exploit_privesc
    label: Kernel Exploit
    description: Escalate to root via kernel vulnerability
    vulnerability: vuln_privesc
    precondition: priv_web_user
    postcondition: priv_web_root

  - id: exploit_pivot
    label: Pivot Internal
    description: Use web server to access internal network
    precondition: priv_web_root
    postcondition: priv_app_access

  - id: exploit_sqli
    label: SQL Injection
    description: Extract database credentials via SQLi
    vulnerability: vuln_sqli
    precondition: priv_app_access
    postcondition: priv_db_read

network_edges:
  - from: attacker
    to: firewall
    label: Internet

  - from: firewall
    to: webserver
    label: HTTPS (443)

  - from: webserver
    to: appserver
    label: API (8080)

  - from: appserver
    to: database
    label: PostgreSQL (5432)
```

### JSON Example

```json
{
  "graph": {
    "name": "Corporate Network Attack Scenario",
    "description": "Attack graph for a typical corporate network",
    "engineversion": "0.3.2",
    "version": "1.0.0",
    "type": "Attack Graph",
    "date": "2025-01-08",
    "author": "Security Team",
    "email": "security@company.com"
  },
  "hosts": [
    {
      "id": "attacker",
      "label": "External Attacker",
      "description": "Threat actor on the internet",
      "zone": "external"
    },
    {
      "id": "webserver",
      "label": "Web Server",
      "description": "Public-facing web application",
      "ip": "10.0.1.10",
      "zone": "dmz",
      "os": "Ubuntu 22.04"
    },
    {
      "id": "database",
      "label": "Database Server",
      "description": "PostgreSQL database with customer data",
      "ip": "10.0.3.10",
      "zone": "data",
      "os": "Linux"
    }
  ],
  "vulnerabilities": [
    {
      "id": "vuln_rce",
      "label": "Remote Code Execution",
      "description": "Unauthenticated RCE in web application",
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      "affected_host": "webserver"
    },
    {
      "id": "vuln_default_creds",
      "label": "Default Credentials",
      "description": "Database using default credentials",
      "cvss": 9.1,
      "affected_host": "database"
    }
  ],
  "privileges": [
    {
      "id": "priv_web_shell",
      "label": "Web Shell",
      "description": "Low privilege shell on web server",
      "host": "webserver",
      "level": "user"
    },
    {
      "id": "priv_db_admin",
      "label": "DB Admin",
      "description": "Full database admin access",
      "host": "database",
      "level": "admin"
    }
  ],
  "services": [
    {
      "id": "svc_http",
      "label": "HTTPS",
      "host": "webserver",
      "port": 443,
      "protocol": "tcp"
    },
    {
      "id": "svc_postgres",
      "label": "PostgreSQL",
      "host": "database",
      "port": 5432,
      "protocol": "tcp"
    }
  ],
  "exploits": [
    {
      "id": "exploit_rce",
      "label": "Exploit RCE",
      "description": "Exploit RCE to get initial shell",
      "vulnerability": "vuln_rce",
      "precondition": "attacker",
      "postcondition": "priv_web_shell"
    },
    {
      "id": "exploit_default_creds",
      "label": "Default Creds",
      "description": "Login with default credentials",
      "vulnerability": "vuln_default_creds",
      "precondition": "priv_web_shell",
      "postcondition": "priv_db_admin"
    }
  ],
  "network_edges": [
    {
      "from": "attacker",
      "to": "webserver",
      "label": "Internet Access"
    },
    {
      "from": "webserver",
      "to": "database",
      "label": "Internal Network"
    }
  ]
}
```

### Network Zones

Common network zones for organizing hosts:

| Zone | Description |
|------|-------------|
| `external` / `internet` | External/untrusted network |
| `perimeter` | Network perimeter (firewalls, WAFs) |
| `dmz` | Demilitarized zone (public-facing services) |
| `internal` / `private` | Internal network |
| `data` | Data tier (databases, storage) |
| `management` | Management network |

### Privilege Levels

Common privilege levels:

| Level | Description |
|-------|-------------|
| `none` | No privileges |
| `user` | Standard user access |
| `elevated` | Elevated/privileged user |
| `admin` | Administrative access |
| `root` | Root/system access |
| `container` | Container-level access |
| `node` | Node/host-level access |
| `cloud` | Cloud service access |

---

## Threat Models

Threat models create Data Flow Diagrams (DFD) with external entities, processes, data stores, data flows, and trust boundaries. They support STRIDE threat analysis.

### Schema Structure

```
model (required)
├── name (required): string - Model name
├── description (optional): string - Description
├── engineversion (optional): string - USecVisLib version
├── version (optional): string - Template version
├── type (optional): string - "Threat Model"
├── date (optional): string - Creation date
├── author (optional): string - Author name
├── email (optional): string - Author email
└── url (optional): string - Author URL

externals (optional): object
└── "<external_id>" (key): object
    ├── label (required): string - Display name
    ├── description (optional): string - Description
    ├── isTrusted (optional): boolean - Trust status
    └── isAdmin (optional): boolean - Admin status

processes (optional): object
└── "<process_id>" (key): object
    ├── label (required): string - Display name
    ├── description (optional): string - Description
    ├── isServer (optional): boolean - Server process
    ├── authenticatesSource (optional): boolean
    ├── authenticatesDestination (optional): boolean
    ├── sanitizesInput (optional): boolean
    ├── encodesOutput (optional): boolean
    ├── checksInputBounds (optional): boolean
    ├── implementsCSRFToken (optional): boolean
    ├── implementsNonce (optional): boolean
    ├── hasAccessControl (optional): boolean
    ├── isHardened (optional): boolean
    └── handlesResourceConsumption (optional): boolean

datastores (optional): object
└── "<datastore_id>" (key): object
    ├── label (required): string - Display name
    ├── description (optional): string - Description
    ├── isSQL (optional): boolean - SQL database
    ├── isEncrypted (optional): boolean - Data encrypted
    ├── hasAccessControl (optional): boolean
    ├── storesPII (optional): boolean - Stores PII
    ├── storesCredentials (optional): boolean
    ├── hasBackup (optional): boolean
    ├── isAuditLogged (optional): boolean
    └── isShared (optional): boolean

dataflows (required): object
└── "<dataflow_id>" (key): object
    ├── from (required): string - Source element ID
    ├── to (required): string - Target element ID
    ├── label (optional): string - Flow description
    ├── protocol (optional): string - Protocol used
    ├── isEncrypted (optional): boolean - Encrypted flow
    ├── authenticatesSource (optional): boolean
    ├── authenticatesDestination (optional): boolean
    ├── checksDestinationRevocation (optional): boolean
    ├── data (optional): string - Data classification
    ├── isPII (optional): boolean - Contains PII
    ├── isCredentials (optional): boolean - Contains credentials
    ├── sanitizesInput (optional): boolean
    └── note (optional): string - Additional notes

boundaries (optional): object
└── "<boundary_id>" (key): object
    ├── label (required): string - Boundary name
    ├── elements (required): array - Element IDs in boundary
    ├── isNetworkBoundary (optional): boolean
    └── trustLevel (optional): number - Trust level (0-100)

threats (optional): object
└── "<threat_id>" (key): object
    ├── category (required): string - STRIDE category
    ├── element (optional): string - Target element
    ├── target (optional): string - Target element (alias)
    ├── threat (optional): string - Threat description
    ├── description (optional): string - Threat description (alias)
    ├── mitigation (optional): string - Mitigation strategy
    ├── likelihood (optional): string - Likelihood level
    ├── impact (optional): string - Impact level
    ├── cvss (optional): number - CVSS score
    └── cvss_vector (optional): string - CVSS vector
```

### STRIDE Categories

| Category | Description | Applies To |
|----------|-------------|------------|
| `Spoofing` | Impersonating something or someone | Externals, Processes |
| `Tampering` | Modifying data or code | Processes, Datastores, Dataflows |
| `Repudiation` | Denying actions | Externals, Processes, Datastores |
| `Information Disclosure` | Exposing data to unauthorized parties | Processes, Datastores, Dataflows |
| `Denial of Service` | Denying access to services | Processes, Datastores, Dataflows |
| `Elevation of Privilege` | Gaining unauthorized capabilities | Processes |

### TOML Example

```toml
#
# Threat Model: API Gateway
#

[model]
name = "API Gateway Security"
description = "Threat model for a REST API gateway"
engineversion = "0.3.2"
version = "1.0.0"
type = "Threat Model"
date = "2025-01-08"
author = "Security Team"

# =============================================================================
# External Entities
# =============================================================================
[externals]

[externals.user]
label = "API Consumer"
description = "External API client application"
isTrusted = false

[externals.admin]
label = "Administrator"
description = "System administrator"
isAdmin = true
isTrusted = true

[externals.attacker]
label = "Threat Actor"
description = "Malicious external actor"
isTrusted = false

# =============================================================================
# Processes
# =============================================================================
[processes]

[processes.api_gateway]
label = "API Gateway"
description = "Kong/NGINX API gateway with rate limiting"
isServer = true
authenticatesSource = true
sanitizesInput = true
encodesOutput = true
implementsCSRFToken = true
checksInputBounds = true
hasAccessControl = true
isHardened = true
handlesResourceConsumption = true

[processes.auth_service]
label = "Auth Service"
description = "OAuth 2.0 / JWT authentication service"
isServer = true
authenticatesSource = true
authenticatesDestination = true
sanitizesInput = true
implementsNonce = true
hasAccessControl = true
isHardened = true

[processes.backend_api]
label = "Backend API"
description = "Core business logic API"
isServer = true
authenticatesSource = true
sanitizesInput = true
checksInputBounds = true
hasAccessControl = true

# =============================================================================
# Data Stores
# =============================================================================
[datastores]

[datastores.user_db]
label = "User Database"
description = "PostgreSQL - User accounts and profiles"
isSQL = true
isEncrypted = true
hasAccessControl = true
storesPII = true
hasBackup = true
isAuditLogged = true

[datastores.session_cache]
label = "Session Cache"
description = "Redis - JWT tokens and session data"
isSQL = false
isEncrypted = true
hasAccessControl = true
storesCredentials = true

[datastores.secrets_vault]
label = "Secrets Vault"
description = "HashiCorp Vault - API keys and secrets"
isEncrypted = true
hasAccessControl = true
storesCredentials = true
isAuditLogged = true

# =============================================================================
# Data Flows
# =============================================================================
[dataflows]

[dataflows.user_to_gateway]
from = "user"
to = "api_gateway"
label = "API Requests"
protocol = "HTTPS"
isEncrypted = true
authenticatesDestination = true
data = "CONFIDENTIAL"
isPII = true

[dataflows.attacker_to_gateway]
from = "attacker"
to = "api_gateway"
label = "Attack Traffic"
protocol = "HTTPS"
isEncrypted = true
note = "Potential malicious requests"

[dataflows.gateway_to_auth]
from = "api_gateway"
to = "auth_service"
label = "Token Validation"
protocol = "gRPC"
isEncrypted = true
authenticatesSource = true
isCredentials = true

[dataflows.gateway_to_backend]
from = "api_gateway"
to = "backend_api"
label = "Proxied Requests"
protocol = "HTTP"
authenticatesSource = true
isPII = true

[dataflows.auth_to_userdb]
from = "auth_service"
to = "user_db"
label = "User Lookup"
protocol = "PostgreSQL"
isEncrypted = true
authenticatesSource = true
isPII = true
sanitizesInput = true

[dataflows.auth_to_cache]
from = "auth_service"
to = "session_cache"
label = "Session Management"
protocol = "Redis"
isEncrypted = true
authenticatesSource = true
isCredentials = true

[dataflows.backend_to_vault]
from = "backend_api"
to = "secrets_vault"
label = "Fetch Secrets"
protocol = "HTTPS"
isEncrypted = true
authenticatesSource = true
authenticatesDestination = true
isCredentials = true

[dataflows.admin_to_gateway]
from = "admin"
to = "api_gateway"
label = "Admin Console"
protocol = "HTTPS"
isEncrypted = true
authenticatesSource = true
authenticatesDestination = true
isCredentials = true

# =============================================================================
# Trust Boundaries
# =============================================================================
[boundaries]

[boundaries.internet]
label = "Internet (Untrusted)"
elements = ["user", "attacker"]
isNetworkBoundary = true
trustLevel = 0

[boundaries.dmz]
label = "DMZ"
elements = ["api_gateway"]
isNetworkBoundary = true
trustLevel = 50

[boundaries.internal]
label = "Internal Network"
elements = ["auth_service", "backend_api"]
isNetworkBoundary = true
trustLevel = 80

[boundaries.data_tier]
label = "Data Tier"
elements = ["user_db", "session_cache", "secrets_vault"]
isNetworkBoundary = true
trustLevel = 100

# =============================================================================
# Threats
# =============================================================================
[threats]

[threats.jwt_theft]
category = "Spoofing"
target = "auth_service"
description = "JWT token theft via XSS or session hijacking"
mitigation = "HttpOnly cookies, short token expiry, token binding"
likelihood = "medium"
impact = "high"
cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N"

[threats.api_injection]
category = "Tampering"
target = "backend_api"
description = "SQL/NoSQL injection through API parameters"
mitigation = "Parameterized queries, input validation, WAF rules"
likelihood = "medium"
impact = "critical"
cvss = 9.8

[threats.rate_limit_bypass]
category = "Denial of Service"
target = "api_gateway"
description = "Distributed attack to bypass rate limiting"
mitigation = "Distributed rate limiting, IP reputation, CDN protection"
likelihood = "high"
impact = "high"

[threats.credential_exposure]
category = "Information Disclosure"
target = "secrets_vault"
description = "API keys leaked through logs or error messages"
mitigation = "Secret rotation, audit logging, log sanitization"
likelihood = "low"
impact = "critical"
cvss = 8.5

[threats.privilege_escalation]
category = "Elevation of Privilege"
target = "auth_service"
description = "Role manipulation to gain admin access"
mitigation = "JWT claim validation, RBAC enforcement, audit logging"
likelihood = "low"
impact = "critical"
cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
```

### YAML Example

```yaml
model:
  name: API Gateway Security
  description: Threat model for a REST API gateway
  engineversion: "0.3.2"
  version: "1.0.0"
  type: Threat Model
  date: "2025-01-08"
  author: Security Team

externals:
  user:
    label: API Consumer
    description: External API client application
    isTrusted: false

  admin:
    label: Administrator
    description: System administrator
    isAdmin: true
    isTrusted: true

processes:
  api_gateway:
    label: API Gateway
    description: Kong/NGINX API gateway with rate limiting
    isServer: true
    authenticatesSource: true
    sanitizesInput: true
    encodesOutput: true
    checksInputBounds: true
    hasAccessControl: true
    isHardened: true

  auth_service:
    label: Auth Service
    description: OAuth 2.0 / JWT authentication service
    isServer: true
    authenticatesSource: true
    authenticatesDestination: true
    sanitizesInput: true
    hasAccessControl: true
    isHardened: true

  backend_api:
    label: Backend API
    description: Core business logic API
    isServer: true
    authenticatesSource: true
    sanitizesInput: true
    hasAccessControl: true

datastores:
  user_db:
    label: User Database
    description: PostgreSQL - User accounts and profiles
    isSQL: true
    isEncrypted: true
    hasAccessControl: true
    storesPII: true
    isAuditLogged: true

  session_cache:
    label: Session Cache
    description: Redis - JWT tokens and session data
    isSQL: false
    isEncrypted: true
    hasAccessControl: true
    storesCredentials: true

dataflows:
  user_to_gateway:
    from: user
    to: api_gateway
    label: API Requests
    protocol: HTTPS
    isEncrypted: true
    isPII: true

  gateway_to_auth:
    from: api_gateway
    to: auth_service
    label: Token Validation
    protocol: gRPC
    isEncrypted: true
    authenticatesSource: true
    isCredentials: true

  auth_to_userdb:
    from: auth_service
    to: user_db
    label: User Lookup
    protocol: PostgreSQL
    isEncrypted: true
    authenticatesSource: true
    isPII: true
    sanitizesInput: true

boundaries:
  internet:
    label: Internet (Untrusted)
    elements:
      - user
    isNetworkBoundary: true
    trustLevel: 0

  dmz:
    label: DMZ
    elements:
      - api_gateway
    isNetworkBoundary: true
    trustLevel: 50

  internal:
    label: Internal Network
    elements:
      - auth_service
      - backend_api
    isNetworkBoundary: true
    trustLevel: 80

  data_tier:
    label: Data Tier
    elements:
      - user_db
      - session_cache
    isNetworkBoundary: true
    trustLevel: 100

threats:
  jwt_theft:
    category: Spoofing
    target: auth_service
    description: JWT token theft via XSS or session hijacking
    mitigation: HttpOnly cookies, short token expiry, token binding
    likelihood: medium
    impact: high
    cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N"

  api_injection:
    category: Tampering
    target: backend_api
    description: SQL/NoSQL injection through API parameters
    mitigation: Parameterized queries, input validation, WAF rules
    likelihood: medium
    impact: critical
    cvss: 9.8
```

### Data Classification Levels

| Level | Description |
|-------|-------------|
| `PUBLIC` | Public information |
| `INTERNAL` | Internal use only |
| `CONFIDENTIAL` | Confidential business data |
| `SECRET` | Highly sensitive data |
| `TOP SECRET` | Most sensitive data |

---

## Custom Diagrams

Custom diagrams allow creating arbitrary schema-driven visualizations with user-defined node types, edge types, and styling.

### Schema Structure

```
diagram (required)
├── title (required): string - Diagram title
├── description (optional): string - Description
├── layout (optional): string - Layout algorithm
├── direction (optional): string - Graph direction
├── style (optional): string - Style preset
├── splines (optional): string - Edge routing
├── nodesep (optional): number - Node separation
└── ranksep (optional): number - Rank separation

schema (required)
├── nodes (required): object - Node type definitions
│   └── "<type_name>" (key): object
│       ├── shape (required): string - Graphviz shape
│       ├── required_fields (optional): array - Required fields
│       ├── optional_fields (optional): array - Optional fields
│       ├── style (optional): object - Visual style
│       │   ├── fillcolor: string
│       │   ├── fontcolor: string
│       │   └── style: string
│       └── label_template (optional): string - Label format
│
└── edges (required): object - Edge type definitions
    └── "<type_name>" (key): object
        ├── style (optional): string - Line style
        ├── color (optional): string - Edge color
        ├── arrowhead (optional): string - Arrow style
        └── label_field (optional): string - Field for label

nodes (required): array of objects
├── id (required): string - Unique node ID
├── type (required): string - Node type from schema
├── name (required): string - Display name
└── <custom_fields>: any - Fields defined in schema

edges (required): array of objects
├── from (required): string - Source node ID
├── to (required): string - Target node ID
├── type (required): string - Edge type from schema
├── label (optional): string - Edge label
└── <custom_fields>: any - Fields defined in schema

clusters (optional): array of objects
├── id (required): string - Cluster ID
├── label (required): string - Cluster label
├── nodes (required): array - Node IDs in cluster
└── style (optional): object - Cluster styling
```

### Layout Options

| Layout | Description |
|--------|-------------|
| `hierarchical` | Top-down or left-right tree layout |
| `force` | Force-directed layout |
| `grid` | Grid-based arrangement |
| `circular` | Circular arrangement |

### Direction Options

| Direction | Description |
|-----------|-------------|
| `TB` | Top to bottom |
| `BT` | Bottom to top |
| `LR` | Left to right |
| `RL` | Right to left |

### Graphviz Shapes

Common shapes for custom diagrams:

| Shape | Description | Use Case |
|-------|-------------|----------|
| `rectangle` / `box` | Rectangle | Processes, containers |
| `ellipse` | Ellipse/oval | Start/end nodes |
| `diamond` | Diamond | Decision points |
| `cylinder` | Cylinder | Databases |
| `parallelogram` | Parallelogram | I/O operations |
| `octagon` | Octagon | Controls, security |
| `hexagon` | Hexagon | Preparation steps |
| `note` | Note shape | Documents |
| `folder` | Folder | File systems |
| `component` | Component | Software components |
| `database` | Database | Data stores |
| `package` | Package | Categories |
| `artifact` | Artifact | Servers, artifacts |

### TOML Example

```toml
#
# Custom Diagram: Incident Response Flow
#

[diagram]
title = "Incident Response Workflow"
description = "Security incident response process flow"
layout = "hierarchical"
direction = "TB"
style = "cd_default"
splines = "ortho"
nodesep = 0.8
ranksep = 1.0

# =============================================================================
# Schema Definition
# =============================================================================

[schema.nodes.trigger]
shape = "ellipse"
required_fields = ["name"]
style = { fillcolor = "#E74C3C", fontcolor = "white" }
label_template = "{name}"

[schema.nodes.phase]
shape = "rectangle"
required_fields = ["name"]
optional_fields = ["description", "owner"]
style = { fillcolor = "#3498DB", fontcolor = "white", style = "filled,rounded" }
label_template = "{name}"

[schema.nodes.decision]
shape = "diamond"
required_fields = ["name"]
optional_fields = ["criteria"]
style = { fillcolor = "#F39C12", fontcolor = "white" }
label_template = "{name}"

[schema.nodes.action]
shape = "rectangle"
required_fields = ["name"]
optional_fields = ["tool", "automation"]
style = { fillcolor = "#27AE60", fontcolor = "white" }
label_template = "{name}"

[schema.nodes.output]
shape = "note"
required_fields = ["name"]
optional_fields = ["format"]
style = { fillcolor = "#9B59B6", fontcolor = "white" }
label_template = "{name}"

[schema.nodes.end]
shape = "ellipse"
required_fields = ["name"]
style = { fillcolor = "#1ABC9C", fontcolor = "white" }
label_template = "{name}"

[schema.edges.flow]
style = "solid"
color = "#333333"
arrowhead = "normal"

[schema.edges.yes]
style = "solid"
color = "#27AE60"
arrowhead = "normal"
label_field = "label"

[schema.edges.no]
style = "solid"
color = "#E74C3C"
arrowhead = "normal"
label_field = "label"

[schema.edges.creates]
style = "dashed"
color = "#9B59B6"
arrowhead = "vee"

# =============================================================================
# Nodes
# =============================================================================

[[nodes]]
id = "alert"
type = "trigger"
name = "Security Alert"

[[nodes]]
id = "triage"
type = "phase"
name = "Triage"
description = "Initial assessment and classification"
owner = "SOC Analyst"

[[nodes]]
id = "is_incident"
type = "decision"
name = "Real Incident?"
criteria = "IOC validation, context analysis"

[[nodes]]
id = "false_positive"
type = "action"
name = "Mark False Positive"
tool = "SIEM"

[[nodes]]
id = "containment"
type = "phase"
name = "Containment"
description = "Isolate affected systems"
owner = "IR Team"

[[nodes]]
id = "isolate"
type = "action"
name = "Network Isolation"
tool = "Firewall/EDR"
automation = "true"

[[nodes]]
id = "preserve"
type = "action"
name = "Evidence Preservation"
tool = "Forensic Tools"

[[nodes]]
id = "eradication"
type = "phase"
name = "Eradication"
description = "Remove threat from environment"
owner = "IR Team"

[[nodes]]
id = "recovery"
type = "phase"
name = "Recovery"
description = "Restore normal operations"
owner = "IT Operations"

[[nodes]]
id = "lessons"
type = "phase"
name = "Lessons Learned"
description = "Post-incident review"
owner = "IR Lead"

[[nodes]]
id = "report"
type = "output"
name = "Incident Report"
format = "PDF"

[[nodes]]
id = "close"
type = "end"
name = "Incident Closed"

# =============================================================================
# Edges
# =============================================================================

[[edges]]
from = "alert"
to = "triage"
type = "flow"

[[edges]]
from = "triage"
to = "is_incident"
type = "flow"

[[edges]]
from = "is_incident"
to = "containment"
type = "yes"
label = "Yes"

[[edges]]
from = "is_incident"
to = "false_positive"
type = "no"
label = "No"

[[edges]]
from = "false_positive"
to = "close"
type = "flow"

[[edges]]
from = "containment"
to = "isolate"
type = "flow"

[[edges]]
from = "containment"
to = "preserve"
type = "flow"

[[edges]]
from = "isolate"
to = "eradication"
type = "flow"

[[edges]]
from = "preserve"
to = "eradication"
type = "flow"

[[edges]]
from = "eradication"
to = "recovery"
type = "flow"

[[edges]]
from = "recovery"
to = "lessons"
type = "flow"

[[edges]]
from = "lessons"
to = "report"
type = "creates"

[[edges]]
from = "lessons"
to = "close"
type = "flow"

# =============================================================================
# Clusters
# =============================================================================

[[clusters]]
id = "detection"
label = "Detection Phase"
nodes = ["alert", "triage", "is_incident", "false_positive"]
style = { color = "#3498DB", style = "dashed" }

[[clusters]]
id = "response"
label = "Response Phase"
nodes = ["containment", "isolate", "preserve", "eradication"]
style = { color = "#E74C3C", style = "dashed" }

[[clusters]]
id = "recovery_phase"
label = "Recovery Phase"
nodes = ["recovery", "lessons", "report"]
style = { color = "#27AE60", style = "dashed" }
```

### YAML Example

```yaml
diagram:
  title: Incident Response Workflow
  description: Security incident response process flow
  layout: hierarchical
  direction: TB
  style: cd_default
  splines: ortho
  nodesep: 0.8
  ranksep: 1.0

schema:
  nodes:
    trigger:
      shape: ellipse
      required_fields: [name]
      style:
        fillcolor: "#E74C3C"
        fontcolor: white
      label_template: "{name}"

    phase:
      shape: rectangle
      required_fields: [name]
      optional_fields: [description, owner]
      style:
        fillcolor: "#3498DB"
        fontcolor: white
        style: "filled,rounded"
      label_template: "{name}"

    decision:
      shape: diamond
      required_fields: [name]
      optional_fields: [criteria]
      style:
        fillcolor: "#F39C12"
        fontcolor: white
      label_template: "{name}"

    action:
      shape: rectangle
      required_fields: [name]
      optional_fields: [tool, automation]
      style:
        fillcolor: "#27AE60"
        fontcolor: white
      label_template: "{name}"

  edges:
    flow:
      style: solid
      color: "#333333"
      arrowhead: normal

    yes:
      style: solid
      color: "#27AE60"
      arrowhead: normal
      label_field: label

    no:
      style: solid
      color: "#E74C3C"
      arrowhead: normal
      label_field: label

nodes:
  - id: alert
    type: trigger
    name: Security Alert

  - id: triage
    type: phase
    name: Triage
    description: Initial assessment and classification
    owner: SOC Analyst

  - id: is_incident
    type: decision
    name: Real Incident?
    criteria: IOC validation, context analysis

  - id: containment
    type: phase
    name: Containment
    description: Isolate affected systems
    owner: IR Team

  - id: close
    type: end
    name: Incident Closed

edges:
  - from: alert
    to: triage
    type: flow

  - from: triage
    to: is_incident
    type: flow

  - from: is_incident
    to: containment
    type: yes
    label: "Yes"

clusters:
  - id: detection
    label: Detection Phase
    nodes: [alert, triage, is_incident]
    style:
      color: "#3498DB"
      style: dashed
```

---

## Component Diagrams

Component diagrams visualize layered software architecture. Components are organized into layers (Client, API, Application, Data, etc.) and connected by typed connections.

### Basic Structure (TOML)

```toml
title = "Web Application Architecture"

[[layers]]
name = "Client Tier"
order = 1

  [[layers.components]]
  id = "browser"
  name = "Web Browser"
  type = "frontend"
  tech = "React SPA"

  [[layers.components]]
  id = "mobile"
  name = "Mobile App"
  type = "frontend"
  tech = "React Native"

[[layers]]
name = "API Tier"
order = 2

  [[layers.components]]
  id = "gateway"
  name = "API Gateway"
  type = "service"
  tech = "Nginx + Lua"

  [[layers.components]]
  id = "auth_svc"
  name = "Auth Service"
  type = "service"
  tech = "Go + JWT"

[[layers]]
name = "Data Tier"
order = 3

  [[layers.components]]
  id = "user_db"
  name = "User Database"
  type = "database"
  tech = "PostgreSQL"

  [[layers.components]]
  id = "cache"
  name = "Session Cache"
  type = "cache"
  tech = "Redis"

[[connections]]
from = "browser"
to = "gateway"
label = "HTTPS"
style = "sync"

[[connections]]
from = "gateway"
to = "auth_svc"
label = "verify token"
style = "sync"

[[connections]]
from = "auth_svc"
to = "user_db"
label = "queries"
style = "sync"

[[connections]]
from = "auth_svc"
to = "cache"
label = "sessions"
style = "sync"
```

### JSON Format

```json
{
  "title": "Web Application Architecture",
  "layers": [
    {
      "name": "Client Tier",
      "order": 1,
      "components": [
        { "id": "browser", "name": "Web Browser", "type": "frontend", "tech": "React SPA" }
      ]
    },
    {
      "name": "API Tier",
      "order": 2,
      "components": [
        { "id": "gateway", "name": "API Gateway", "type": "service", "tech": "Nginx + Lua" }
      ]
    }
  ],
  "connections": [
    { "from": "browser", "to": "gateway", "label": "HTTPS", "style": "sync" }
  ]
}
```

### Layer Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Display name for the layer |
| `order` | integer | No | Layer ordering (top to bottom) |
| `components` | array | Yes | List of components in this layer |

### Component Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | Yes | Unique identifier (used in connections) |
| `name` | string | Yes | Display name |
| `type` | string | No | Component type (default: `service`) |
| `tech` | string | No | Technology label (shown below name) |

### Component Types

| Type | Graphviz Shape | Use For |
|------|---------------|---------|
| `frontend` | Rounded box | Web/mobile clients |
| `service` | Rounded box | Backend services, APIs |
| `database` | Cylinder | Databases (PostgreSQL, MongoDB, etc.) |
| `cache` | Rounded box | Caching layers (Redis, Memcached) |
| `storage` | Folder | File/object storage (S3, MinIO) |
| `queue` | Rounded box | Message queues (Kafka, RabbitMQ) |
| `external_service` | Dashed ellipse | Third-party services |
| `cli` | Rounded box | Command-line tools |

### Connection Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `from` | string | Yes | Source component ID |
| `to` | string | Yes | Target component ID |
| `label` | string | No | Edge label text |
| `style` | string | No | Connection style (default: `sync`) |

### Connection Styles

| Style | Appearance | Use For |
|-------|------------|---------|
| `sync` | Solid arrow, filled head | REST, gRPC, HTTP |
| `async` | Dashed arrow, open head | Message queues, webhooks |
| `bidirectional` | Solid, arrows both ends | WebSockets, two-way sync |
| `event` | Dotted arrow | Event bus, pub/sub |

### Available Styles

`cd_default`, `cd_blueprint`, `cd_minimal`, `cd_dark`

---

## Dependency Graphs

Dependency graphs visualize module relationships with SLOC-based node sizing, group clustering, and circular dependency highlighting.

### Basic Structure (TOML)

```toml
title = "Web Application Module Dependencies"

# Internal modules
[[modules]]
id = "app_main"
name = "app.main"
group = "core"
sloc = 350

[[modules]]
id = "app_config"
name = "app.config"
group = "core"
sloc = 120

[[modules]]
id = "routes_users"
name = "routes.users"
group = "api"
sloc = 280

[[modules]]
id = "services_auth"
name = "services.auth"
group = "services"
sloc = 400

[[modules]]
id = "db_engine"
name = "db.engine"
group = "infrastructure"
sloc = 200

# External dependencies
[[modules]]
id = "fastapi"
name = "fastapi"
type = "external"
sloc = 0

[[modules]]
id = "sqlalchemy"
name = "sqlalchemy"
type = "external"
sloc = 0

# Dependencies
[[dependencies]]
from = "app_main"
to = "routes_users"
type = "import"
weight = "heavy"

[[dependencies]]
from = "app_main"
to = "fastapi"
type = "framework"
weight = "heavy"

[[dependencies]]
from = "routes_users"
to = "services_auth"
type = "import"
weight = "medium"

[[dependencies]]
from = "db_engine"
to = "sqlalchemy"
type = "framework"
weight = "heavy"

# Circular dependency (bidirectional import)
[[dependencies]]
from = "app_config"
to = "utils_logging"
type = "import"
weight = "light"

[[dependencies]]
from = "utils_logging"
to = "app_config"
type = "runtime"
weight = "light"

# Declare circular dependencies
[[circular]]
cycle = ["app_config", "utils_logging"]
severity = "low"
```

### JSON Format

```json
{
  "title": "Module Dependencies",
  "modules": [
    { "id": "app_main", "name": "app.main", "group": "core", "sloc": 350 },
    { "id": "fastapi", "name": "fastapi", "type": "external", "sloc": 0 }
  ],
  "dependencies": [
    { "from": "app_main", "to": "fastapi", "type": "framework", "weight": "heavy" }
  ],
  "circular": [
    { "cycle": ["config", "logging"], "severity": "low" }
  ]
}
```

### Module Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | Yes | Unique identifier |
| `name` | string | Yes | Display name |
| `group` | string | No | Clustering group (see below) |
| `type` | string | No | `"internal"` (default) or `"external"` |
| `sloc` | integer | No | Source lines of code (determines node size) |
| `version` | string | No | Version string (shown on external modules) |

### Built-in Groups (with colors)

| Group | Color | Use For |
|-------|-------|---------|
| `core` | Blue | Central application modules |
| `features` | Green | Feature modules |
| `api` | Orange | API routes and endpoints |
| `infrastructure` | Purple | Database, cache, messaging |
| `tests` | Teal | Test modules |
| `utils` | Yellow | Utility and helper modules |

Custom group names are supported and receive a default blue color.

### Dependency Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `from` | string | Yes | Source module ID |
| `to` | string | Yes | Target module ID |
| `type` | string | No | Dependency type (default: `import`) |
| `weight` | string | No | Edge weight (default: `medium`) |

### Dependency Types

| Type | Edge Style | Use For |
|------|------------|---------|
| `import` | Solid line | Direct module imports |
| `framework` | Dotted line | Framework/library dependencies |
| `runtime` | Dashed line | Runtime-only dependencies |

### Edge Weights

| Weight | Penwidth | Use For |
|--------|----------|---------|
| `light` | 1px | Weak coupling, optional dependencies |
| `medium` | 2px | Standard dependencies |
| `heavy` | 3px | Core dependencies, tight coupling |

### Circular Dependency Declaration

```toml
[[circular]]
cycle = ["module_a", "module_b"]
severity = "low"
```

Circular dependencies are highlighted with red bold edges and a warning label. The `cycle` array lists module IDs forming the cycle, and `severity` is informational (`low`, `medium`, `high`).

### Available Styles

`dg_default`, `dg_dark`, `dg_minimal`, `dg_coupling`

---

## Privilege Gradients

A privilege gradient places components in trust zones, ordered left to right by trust level, and connects them with typed influences. An influence from a lower-trust component into a higher-trust one is an **inversion** (a tiering violation), drawn in red with its severity: trust gap 1 medium (`!`), 2 high (`!!`), 3 or more critical (`!!!`).

### Schema Structure

```toml
[gradient]
name = "Corporate Network"

[[zones]]                    # optional: five default zones Z0-Z4 are used when none are given
id = "dmz"
label = "DMZ"
trust_level = 1              # higher is more trusted
color = "#ffe0b2"            # zone fill
border_color = "#e65100"     # zone border, and the fill of its components
font_color = "#663300"

[[components]]
id = "web_server"
label = "Web Server"
zone = "dmz"

[[influence_types]]          # optional: data, feedback, resource, control by default
id = "data"
label = "Data Flow"
color = "#3498db"
style = "solid"              # solid | dashed | dotted | bold

[[influences]]
from = "web_server"
to = "db_server"
type = "data"                # data | feedback | resource | control
label = "SQL"
```

### Grouping and collapse

Large gradients (for example a real Active Directory with thousands of computers) can group components within their zone, and draw a group as one summary component. Grouping is opt-in: without `group_by` (and without component `group` fields) the gradient renders exactly as before.

```toml
[gradient]
name = "AD tiers"
group_by = "role"          # component field to group on
collapse = "auto"          # false (default) | true | "auto" | ["tier2/workstation", ...]
max_nodes = 300            # target for "auto": components drawn

[groups."tier2/workstation"]   # optional per group, by <zone>/<value>
label = "Tier 2 workstations"
color = "#ffe0b2"              # cluster fill
collapsed = true               # always collapsed (or false: always expanded)

[[components]]
id = "ws_0101"
zone = "tier2"
role = "workstation"       # picked up by group_by = "role"
# group = "helpdesk"       # or set the group directly (wins over group_by)
```

**Membership:** a component's `group`, else its `group_by` value. A group never spans zones: the same value in two zones is two groups, with ids `<zone>/<value>` (e.g. `tier1/server` and `tier2/server`). Components without either field stay ungrouped.

**Expanded** groups are drawn as dashed clusters inside their zone.

**Collapsed** groups become one summary component in their zone: the group's label, its member count and, when members take part in inversions, their count with the worst severity's markers (`!! 4 inversions`, inversion-coloured border). Influences between members are dropped; influences into or out of the group point at the summary, and influences that end up with the same endpoints and type are merged and labelled `×N`.

- Every component of a zone has the same trust level, so a group never hides an inversion: no influence between two members can be one, and the influences merged into one edge share one trust gap and severity (a merged inversion reads `! INVERSION ! · ×2`).
- `collapse = true` collapses every group with more than one member; a list collapses those groups; `"auto"` collapses the largest groups first until at most `max_nodes` components are drawn. A group's own `collapsed` setting always wins.
- The size limit (10,000 components / 50,000 influences) applies to what is drawn, so a large gradient grouped and collapsed renders instead of being rejected.
- Inversions, statistics and path analysis always use the full model. With grouping on, statistics add per-group counts (`groups`: zone, members, inversions, worst severity).
- The same options exist as render parameters (`PrivilegeGradient(..., group_by=, collapse=, max_nodes=, keep=, keep_ids=)`, `--group-by` / `--collapse` / `--max-nodes` / `--keep` / `--keep-ids` with `-m 6`, and API query parameters), which override the file.
- SVG output: group clusters are `usv-cluster` groups with `data-cluster-id`, `data-zone` and `data-collapsed="false"`; summary components have class `usv-node--group` with `data-collapsed="true"`, `data-cluster-id`, `data-member-count`, `data-inversion-count`, `data-max-severity`; merged edges carry `data-edge-count`.

**Keeping components visible in a collapsed group.** A collapsed group can keep chosen members drawn by name, for example the machine that breaks tiering, or the members of a path to a crown jewel:

```toml
[gradient]
group_by = "role"
collapse = "auto"
keep = "inversions"                  # every member taking part in an inversion stays drawn
keep_ids = ["ws_0103", "srv_jump1"]  # plus these components
```

- Kept members are drawn next to the summary card, and the group is framed (a dashed cluster labelled with the group name) around the card and them. Their influences stay on them; they are not re-pointed to the card.
- The card counts the folded members only, says how many are shown separately (`4 components · 1 shown separately`), and counts only the folded members' inversions.
- `keep` and `keep_ids` combine. `"auto"` counts kept members as drawn; `true` / `"auto"` leave a group with at most one foldable member expanded (an explicit collapse still applies), and a group whose members are all kept is never collapsed.
- `keep = "inversions"` keeps every endpoint of an inversion. Every upward influence is an inversion, including ordinary data flows from a lower tier, so on a real AD it can keep many machines; `keep_ids` is the precise tool. In the drift view (`render_diff`), it also keeps the endpoints of new, fixed and changed inversions, so a fixed violation stays named.
- SVG output: the frame is a `usv-cluster` with `data-collapsed="true"` and `data-kept-count`; kept components carry `data-kept="true"` and `data-cluster-id`; the card `data-kept-count`.

Example: `templates/privilege-gradient/ad_tiers_grouped.tml` (WS-0103 kept with `keep_ids`).

---

## Common Elements

### Metadata Fields

All visualization types support common metadata fields:

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Name of the visualization |
| `description` | string | Detailed description |
| `engineversion` | string | USecVisLib version (e.g., "0.3.2") |
| `version` | string | Template version |
| `type` | string | Visualization type |
| `date` | string | Creation date (YYYY-MM-DD) |
| `last_modified` | string | Last modification date |
| `author` | string | Author name |
| `email` | string | Author email |
| `url` | string | Author URL |

### Graph Parameters

Common graph layout parameters:

| Parameter | Values | Description |
|-----------|--------|-------------|
| `rankdir` | `TB`, `BT`, `LR`, `RL` | Graph direction |
| `splines` | `ortho`, `polyline`, `curved`, `line`, `true` | Edge routing |
| `nodesep` | number (string) | Minimum space between nodes |
| `ranksep` | number (string) | Minimum space between ranks |
| `fontname` | string | Default font family |
| `fontsize` | number (string) | Default font size |

### Color Formats

Supported color formats:

```toml
# Hex colors (recommended)
fillcolor = "#E74C3C"
fillcolor = "#e74c3c"

# Named colors
fillcolor = "red"
fillcolor = "lightblue"

# RGB
fillcolor = "#RGB"  # Short hex
```

---

## CVSS Integration

### CVSS Score

Direct CVSS score (0.0 - 10.0):

```toml
[nodes]
"SQL Injection" = {cvss = 9.8}
"XSS Attack" = {cvss = 6.1}
```

### CVSS Vector

Full CVSS v3.1 vector string:

```toml
[nodes]
"Remote Code Execution" = {cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
```

### CVSS Vector Components

| Metric | Values | Description |
|--------|--------|-------------|
| `AV` | N, A, L, P | Attack Vector (Network, Adjacent, Local, Physical) |
| `AC` | L, H | Attack Complexity (Low, High) |
| `PR` | N, L, H | Privileges Required (None, Low, High) |
| `UI` | N, R | User Interaction (None, Required) |
| `S` | U, C | Scope (Unchanged, Changed) |
| `C` | N, L, H | Confidentiality Impact (None, Low, High) |
| `I` | N, L, H | Integrity Impact (None, Low, High) |
| `A` | N, L, H | Availability Impact (None, Low, High) |

### Risk Level Colors

CVSS scores are automatically color-coded:

| Score Range | Risk Level | Color |
|-------------|------------|-------|
| 9.0 - 10.0 | Critical | `#8b0000` (dark red) |
| 7.0 - 8.9 | High | `#e74c3c` (red) |
| 4.0 - 6.9 | Medium | `#f39c12` (orange) |
| 0.1 - 3.9 | Low | `#27ae60` (green) |
| 0.0 | Info | `#3498db` (blue) |

---

## Icons and Images

### Bundled Icons

USecVisLib includes bundled icon sets. Reference them using the `bundled:` prefix:

```toml
[nodes]
"Attack IAM" = {image = "bundled:aws/Security-Identity-Compliance/Identity-and-Access-Management"}
"S3 Bucket" = {image = "bundled:aws/Storage/Simple-Storage-Service"}
```

### Available Icon Categories

**AWS Icons:**
- `aws/Security-Identity-Compliance/` - IAM, WAF, Shield, etc.
- `aws/Compute/` - EC2, Lambda, etc.
- `aws/Database/` - RDS, DynamoDB, etc.
- `aws/Networking-Content-Delivery/` - VPC, CloudFront, etc.
- `aws/Storage/` - S3, EBS, etc.

**Azure Icons:**
- `azure/Security/` - Azure security services
- `azure/Compute/` - VMs, Functions, etc.
- `azure/Databases/` - SQL, Cosmos DB, etc.

**Bootstrap Icons:**
- `bootstrap/` - General purpose icons

### Custom Icons

Use absolute or relative paths for custom icons:

```toml
[nodes]
"Custom Server" = {image = "/path/to/custom-icon.png"}
```

---

## Available Styles

To compare presets visually, see the `_styles (all presets)` section of each module in the [render gallery](https://vulnex.github.io/usecvislib-gallery/).

### Attack Tree Styles

| Style | Description |
|-------|-------------|
| `at_default` | Clean default style |
| `at_white_black` | White text on black |
| `at_black_white` | Black text on white |
| `at_corporate` | Professional blue/gray |
| `at_neon` | Cyberpunk neon colors |
| `at_pastel` | Soft pastel colors |
| `at_forest` | Natural green tones |
| `at_fire` | Aggressive red/orange |
| `at_blueprint` | Technical blueprint |
| `at_sunset` | Warm sunset colors |
| `at_hacker` | Matrix-style green |
| `at_minimal` | Clean minimalist |
| `at_plain` | No colors (for printing) |

### Threat Model Styles

| Style | Description |
|-------|-------------|
| `tm_default` | Clean modern style |
| `tm_stride` | STRIDE analysis focused |
| `tm_dark` | Dark theme |
| `tm_corporate` | Enterprise professional |
| `tm_neon` | Cyberpunk style |
| `tm_minimal` | Clean black and white |
| `tm_ocean` | Calm blue tones |
| `tm_sunset` | Warm sunset colors |
| `tm_forest` | Natural green tones |
| `tm_blueprint` | Technical schematic |
| `tm_hacker` | Matrix terminal style |
| `tm_plain` | No colors (for printing) |

### Attack Graph Styles

| Style | Description |
|-------|-------------|
| `ag_default` | Default style |
| `ag_dark` | Dark theme |
| `ag_corporate` | Professional style |
| `ag_neon` | Neon colors |
| `ag_minimal` | Minimalist |

### Custom Diagram Styles

| Style | Description |
|-------|-------------|
| `cd_default` | Default style |
| `cd_dark` | Dark theme |
| `cd_minimal` | Minimalist |

### Component Diagram Styles

| Style | Description |
|-------|-------------|
| `cd_default` | Clean professional with colored layer backgrounds |
| `cd_blueprint` | Technical blueprint style |
| `cd_minimal` | Minimalist grayscale |
| `cd_dark` | Dark theme with light text |

### Dependency Graph Styles

| Style | Description |
|-------|-------------|
| `dg_default` | Clean professional with group coloring |
| `dg_dark` | Dark theme |
| `dg_minimal` | Minimalist grayscale |
| `dg_coupling` | Coupling-focused visualization |

---

## Best Practices

### General Guidelines

1. **Use meaningful IDs**: Choose descriptive, unique identifiers for all elements.

2. **Consistent naming**: Use a consistent naming convention (snake_case or camelCase).

3. **Add descriptions**: Include descriptions for complex elements to improve clarity.

4. **Version your templates**: Use the `version` field to track template changes.

5. **Include metadata**: Add author, date, and description for documentation.

### Attack Trees

1. **Start with the goal**: The root node should be the attacker's ultimate objective.

2. **Use gates appropriately**:
   - `OR`: Alternative paths (any one works)
   - `AND`: Required combination (all needed)

3. **Add CVSS scores**: Include CVSS for leaf nodes to quantify risk.

4. **Keep depth reasonable**: 3-5 levels typically provide good detail without overwhelming.

### Attack Graphs

1. **Define network zones**: Group hosts by security zone for clarity.

2. **Link vulnerabilities to hosts**: Always specify `affected_host` for vulnerabilities.

3. **Chain exploits logically**: Ensure `precondition` and `postcondition` form valid attack paths.

4. **Include services**: Services help understand the attack surface.

### Threat Models

1. **Define trust boundaries**: Clearly mark where trust levels change.

2. **Use security controls**: Set process properties to indicate implemented controls.

3. **Document data flows**: Include protocol, encryption, and data classification.

4. **Map STRIDE threats**: Associate threats with specific elements and categories.

### Custom Diagrams

1. **Define schema first**: Plan your node and edge types before adding data.

2. **Use clusters**: Group related elements for visual organization.

3. **Template labels**: Use `{field}` syntax in `label_template` for dynamic labels.

4. **Choose appropriate shapes**: Match shapes to element semantics.

---

## CLI Usage Examples

### Attack Trees

```bash
# Generate PNG
usecvis -m 0 -i attack_tree.toml -o output -f png

# Generate with custom style
usecvis -m 0 -i attack_tree.yaml -o output -f png -s at_neon

# Generate PDF
usecvis -m 0 -i attack_tree.json -o output -f pdf
```

### Attack Graphs

```bash
# Generate PNG
usecvis -m 3 -i attack_graph.toml -o output -f png

# Generate SVG
usecvis -m 3 -i attack_graph.yaml -o output -f svg
```

### Threat Models

```bash
# Generate PNG
usecvis -m 1 -i threat_model.toml -o output -f png

# Generate with corporate style
usecvis -m 1 -i threat_model.yaml -o output -f png -s tm_corporate
```

---

## Template Validation

Templates are validated on load. Common validation errors:

| Error | Cause | Solution |
|-------|-------|----------|
| Missing root key | No `tree`/`graph`/`model`/`diagram` section | Add required root section |
| Missing required field | Required field not provided | Add the missing field |
| Invalid reference | Edge references non-existent node | Check node IDs match |
| Invalid CVSS | CVSS score outside 0.0-10.0 | Use valid CVSS value |
| Invalid format | Malformed TOML/YAML/JSON | Check syntax |

---

## Version History

| Version | Changes |
|---------|---------|
| 0.3.2 | Added custom diagrams, improved CVSS support |
| 0.3.1 | Added bundled icons, style presets |
| 0.3.0 | Attack graphs, threat model boundaries |
| 0.2.5 | Initial template format |

---

*This guide is part of USecVisLib documentation. For more information, visit [VULNEX](https://www.vulnex.com).*
