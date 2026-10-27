# MCP Tools Reference

Reference for the 65 tools, 19 resources (16 fixed URIs and 3 URI templates) and 10 prompt templates provided by the `usecvislib-mcp` server (v0.5.0, requires usecvislib 0.6.0).

To see what each visualization looks like before picking one, browse the [render gallery](https://vulnex.github.io/usecvislib-gallery/): every bundled template rendered with every engine, view and style preset.

## Table of Contents

- [Tool Conventions](#tool-conventions)
- [Attack Trees (4)](#attack-trees)
- [Attack Graphs (5)](#attack-graphs)
- [Threat Models (4)](#threat-models)
- [Mermaid (1)](#mermaid)
- [Binary Analysis (6)](#binary-analysis)
- [Cloud Diagrams (6)](#cloud-diagrams)
- [Privilege Gradient (5)](#privilege-gradient)
- [Custom Diagrams (3)](#custom-diagrams)
- [Architecture — Component Diagrams (3)](#component-diagrams)
- [Architecture — Dependency Graphs (3)](#dependency-graphs)
- [Kill Chain / MITRE ATT&CK (4)](#kill-chain)
- [Incident Timeline (3)](#incident-timeline)
- [Vulnerability Dependency Tree (3)](#vulnerability-dependency-tree)
- [MAESTRO (4)](#maestro)
- [Utilities (4)](#utilities)
- [Batch (1)](#batch)
- [Export (2)](#export)
- [Analysis (3)](#analysis)
- [Drift (1)](#drift)
- [Resources Reference (19)](#resources-reference)
- [Prompt Templates (10)](#prompt-templates)

---

## Tool Conventions

### Common Parameters

Most visualization tools share these parameters:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config` | dict | *(required)* | Configuration dictionary for the visualization (see the `usecvislib://schemas/...` resources) |
| `format` | str | `"png"` | Output format: `png`, `pdf`, `svg`, or `dot` (`dot` only with Graphviz output) |
| `style` | str | *(varies)* | Style preset ID (see `usecvislib://styles/list`) |
| `render_engine` | str | `"graphviz"` | `graphviz` or `svg`, on the tools whose module has an SVG-engine painter |
| `shine` | bool | `false` | Post-process Graphviz SVG with the shine pack (fonts, shadows, hover) |

**SVG engine.** `render_engine="svg"` renders with usecvislib's stdlib SVG engine: a self-contained, interactive SVG (PNG and PDF are converted from it with cairosvg). It uses the `sv_*` style presets (`sv_default`, `sv_dark`, ...). When you leave `style` at the tool's Graphviz default, the tool switches to the engine's default `sv_*` preset. `format="dot"` is rejected with the SVG engine.

**Shine.** `shine=true` needs `format="svg"` and `render_engine="graphviz"`; any other combination returns an error.

### Output Modes

Set by `USECVISLIB_MCP_OUTPUT_MODE`; the default follows the transport.

- **`file` mode** (default for stdio): returns `{"output_path": ..., "format": ..., "size_bytes": ...}`. Files are written to `USECVISLIB_MCP_OUTPUT_DIR` and removed after `USECVISLIB_MCP_OUTPUT_TTL_SECONDS`.
- **`base64` mode** (default for the `sse` and `streamable-http` transports): PNG and SVG come back as an MCP image; PDF and DOT as `{"format": ..., "data_base64": ..., "size_bytes": ...}`.

### Error Handling

All tools return JSON with an `"error"` key on failure: the exception type, a message (internal paths removed) and, when available, its context:
```json
{"error": "ValueError", "message": "Invalid render_engine 'x'. Allowed: graphviz, svg"}
```

---

## Attack Trees

Tools for creating and analyzing hierarchical attack scenario visualizations.

### `generate_attack_tree`

Generate an attack tree visualization from a configuration dictionary.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config` | dict | *(required)* | Config with `tree`, `nodes`, `edges` sections |
| `format` | str | `"png"` | Output format: `png`, `pdf`, `svg`, `dot` |
| `style` | str | `"at_default"` | Style preset (e.g. `at_corporate`, `at_neon`; `sv_*` with the SVG engine) |
| `render_engine` | str | `"graphviz"` | `graphviz` or `svg` |
| `shine` | bool | `false` | Shine pack on Graphviz SVG |

**Example config:**
```json
{
  "tree": {"name": "Web App Attack", "root": "goal"},
  "nodes": [
    {"id": "goal", "label": "Compromise Web App", "shape": "doubleoctagon"},
    {"id": "sqli", "label": "SQL Injection", "cvss": 9.8}
  ],
  "edges": [
    {"from": "goal", "to": "sqli", "label": "OR"}
  ]
}
```

### `validate_attack_tree`

Validate an attack tree configuration without generating output: structure, node references, edge consistency.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config` | dict | *(required)* | Configuration to validate |

**Response:** `{"valid": true/false, "errors": [...]}`

### `get_attack_tree_stats`

Get statistics about an attack tree.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config` | dict | *(required)* | Configuration to analyze |

**Response:** JSON with node counts, tree depth, CVSS score distribution.

### `build_attack_tree_from_spec`

Build an attack tree using the builder API (structured specification instead of a full config).

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `name` | str | *(required)* | Name of the attack tree |
| `root` | str | *(required)* | Label of the root node |
| `nodes` | list[dict] | *(required)* | Node dicts: `id`, `label`, `fillcolor`, `shape`, `cvss`, `cvss_vector` |
| `edges` | list[dict] | *(required)* | Edge dicts: `from`, `to`, `label` |
| `format` | str | `"png"` | Output format |
| `style` | str | `"at_default"` | Style preset |

---

## Attack Graphs

Tools for network attack graph visualization and path analysis.

### `generate_attack_graph`

Generate an attack graph visualization. Hosts (and the vulnerabilities, privileges and services on them) can be grouped into clusters, and groups collapsed into one summary node each, to keep large networks readable.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config` | dict | *(required)* | Config with `graph`, `hosts`, `vulnerabilities`, `privileges`, `services`, `exploits`, `network_edges` |
| `format` | str | `"png"` | Output format |
| `style` | str | `"ag_default"` | Style preset (`sv_*` with the SVG engine) |
| `render_engine` | str | `"graphviz"` | `graphviz` or `svg` |
| `shine` | bool | `false` | Shine pack on Graphviz SVG |
| `group_by` | str | `""` | Cluster hosts by a host field (e.g. `zone`), or by network with `ip/N` (e.g. `ip/24`) or `ip6/N`. Overrides `graph.group_by` |
| `collapse` | str, list or bool | `null` | Draw groups as one summary node each: `"all"` (or `true`), `"auto"` (largest groups first until at most `max_nodes` nodes remain), `"none"`, or a list of group ids (a field value, or a network such as `10.0.1.0/24`). Overrides `graph.collapse` |
| `max_nodes` | int | `null` | Node target for `collapse="auto"` (1–10000; the library default is 300) |

A collapsed group's summary node shows its member count; edges between collapsed groups merge and are labelled `×N`.

### `validate_attack_graph`

Validate an attack graph configuration.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config` | dict | *(required)* | Configuration to validate |

**Response:** `{"valid": true/false, "errors": [...]}`

### `get_attack_graph_stats`

Get statistics about an attack graph.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config` | dict | *(required)* | Configuration to analyze |
| `group_by` | str | `""` | Host field (or `ip/N` / `ip6/N`) to group by; adds per-group counts under `groups` (also used when the config sets `graph.group_by`) |

**Response:** JSON with node counts, edge counts and metrics, plus `groups` when grouping applies.

### `find_attack_paths`

Find attack paths between two nodes in an attack graph.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config` | dict | *(required)* | Attack graph configuration |
| `source` | str | *(required)* | Source node ID (attacker entry point) |
| `target` | str | *(required)* | Target node ID (goal) |
| `max_paths` | int | `10` | Maximum paths to return |
| `max_depth` | int | `20` | Maximum path depth |

**Response:** JSON list of attack paths with nodes and edges.

### `analyze_critical_nodes`

Identify the most critical nodes using centrality analysis.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config` | dict | *(required)* | Attack graph configuration |
| `top_n` | int | `10` | Number of top critical nodes |

---

## Threat Models

Tools for threat model Data Flow Diagram (DFD) generation and STRIDE analysis.

### `generate_threat_model`

Generate a threat model DFD visualization.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config` | dict | *(required)* | Config with `model`, `processes`, `datastores`, `externals`, `dataflows`, `boundaries` |
| `format` | str | `"png"` | Output format |
| `style` | str | `"tm_default"` | Style preset |
| `engine` | str | `"usecvislib"` | Analysis/rendering engine: `usecvislib` or `pytm` |
| `render_engine` | str | `"graphviz"` | `graphviz` or `svg`. The SVG engine draws the DFD only and bypasses the pytm engine |
| `shine` | bool | `false` | Shine pack on Graphviz SVG |

### `validate_threat_model`

Validate a threat model configuration.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config` | dict | *(required)* | Configuration to validate |

**Response:** `{"valid": true/false, "errors": [...]}`

### `get_threat_model_stats`

Get statistics about a threat model: element counts, flow counts.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config` | dict | *(required)* | Configuration to analyze |

### `analyze_stride_threats`

Perform STRIDE threat analysis on a threat model.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config` | dict | *(required)* | Threat model configuration |

**Response:** JSON list of identified threats categorized by STRIDE categories (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege).

---

## Mermaid

### `render_mermaid`

Render a Mermaid diagram from source text (flowchart, sequence, class, ER, state, gantt, pie, mindmap and more). Requires mermaid-cli (`mmdc`).

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `source` | str | *(required)* | Mermaid diagram source text |
| `format` | str | `"png"` | Output format: `png`, `svg`, `pdf` |
| `theme` | str | `"default"` | Theme: `default`, `dark`, `forest`, `neutral` |
| `background` | str | `"white"` | Background color (e.g. `white`, `transparent`, `#f0f0f0`) |
| `width` | int | `800` | Image width in pixels |
| `height` | int | `600` | Image height in pixels |

**Example:**
```json
{
  "source": "graph TD\n  A[Start] --> B[End]",
  "format": "png",
  "theme": "default"
}
```

---

## Binary Analysis

Tools for binary file visualization and statistical analysis. Every chart tool takes the same parameters:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `file_path` | str | *(required)* | Path to the file to analyze |
| `format` | str | `"png"` | Output format: `png`, `pdf`, `svg` |
| `style` | str | `""` | Style preset (`bv_default`, `bv_dark`, `bv_security`, ...; `""` for the default) |

### `analyze_binary_entropy`

Sliding-window entropy across the file: shows encrypted, compressed or structured regions.

### `analyze_binary_distribution`

Frequency of each byte value (0-255): shows patterns, padding and anomalies.

### `analyze_binary_heatmap`

2D heatmap of byte values across the file, for visual pattern recognition.

### `analyze_binary_digraph`

Byte-pair plot: a 256×256 image of how often byte B follows byte A, on a log scale, with guides at the printable ASCII range. Machine code, ASCII text, UTF-16, compressed and encrypted data each leave a distinct pattern; random data looks uniform. A quick format-recognition view.

### `analyze_binary_all`

Every chart in one call: entropy, byte distribution, wind rose (polar histogram of byte values), heatmap and byte-pair digraph.

**Response:** `{"charts": [...]}`, one entry per chart with its `type` and `output_path` and `size_bytes` (file mode) or `data_base64` (base64 mode).

### `get_binary_stats`

Get a statistical summary without generating a visualization.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `file_path` | str | *(required)* | Path to the file to analyze |

**Response:** JSON with file size, entropy and byte distribution statistics.

---

## Cloud Diagrams

Tools for cloud architecture diagram generation. Requires the `diagrams` Python package and Graphviz.

### `generate_cloud_diagram`

Generate a cloud architecture diagram.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config` | dict | *(required)* | Config with nodes (provider icons), edges, clusters |
| `format` | str | `"png"` | Output format: `png`, `pdf`, `svg`, `dot` |

### `validate_cloud_diagram`

Validate a cloud diagram configuration: icon paths, edge references, direction.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config` | dict | *(required)* | Configuration to validate |

**Response:** `{"valid": true/false, "errors": [...]}`

### `get_cloud_diagram_stats`

Get statistics about a cloud diagram: node counts, providers used.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config` | dict | *(required)* | Configuration to analyze |

### `search_cloud_icons`

Search for cloud provider icons by name, across every provider.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `query` | str | *(required)* | Search query (case-insensitive) |
| `limit` | int | `20` | Maximum results |

### `list_cloud_providers`

List available cloud providers. No parameters.

**Response:** JSON list of `{"id", "name"}`.

### `list_cloud_icons`

List icons for a specific cloud provider.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `provider` | str | *(required)* | Provider ID: `aws`, `gcp`, `azure`, etc. |
| `category` | str | `""` | Filter by category (empty for all) |

**Response:** JSON list of icons with `id`, `path`, `name`, `category`.

---

## Privilege Gradient

Tools for trust zone visualization with automatic inversion detection. An inversion is an influence from a lower-trust zone into a higher-trust one; its severity follows the trust gap (1 medium, 2 high, 3 or more critical).

Zones take `trust_level` (not `level`): a zone without it is at trust 0.

### `generate_privilege_gradient`

Generate a privilege gradient graph. Components can be grouped within their zone (groups never span zones), and groups collapsed into one summary component each; inversions on merged edges stay exact.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config` | dict | *(required)* | Config with `gradient`, `zones`, `components`, `influences` |
| `format` | str | `"png"` | Output format |
| `style` | str | `"pg_default"` | Style preset (`sv_*` with the SVG engine) |
| `render_engine` | str | `"graphviz"` | `graphviz` or `svg`. The SVG engine draws zones as clusters ordered by trust level and styles influences by type |
| `shine` | bool | `false` | Shine pack on Graphviz SVG |
| `group_by` | str | `""` | Group components within their zone by a component field (e.g. `role`); a component's own `group` wins. Group ids are `<zone>/<value>`. Overrides `gradient.group_by` |
| `collapse` | str, list or bool | `null` | `"all"` (or `true`), `"auto"` (with `max_nodes`), `"none"`, or a list of group ids. Overrides `gradient.collapse` |
| `max_nodes` | int | `null` | Component target for `collapse="auto"` (1–10000; the library default is 300) |
| `keep` | str | `""` | `"inversions"`: every component taking part in an inversion stays drawn individually next to its collapsed group's card |
| `keep_ids` | list[str] | `null` | Component ids kept drawn the same way |

A collapsed group's card shows its member count, the inversions its members take part in and their worst severity; kept members are framed with their group's card.

### `validate_privilege_gradient`

Validate a privilege gradient configuration.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config` | dict | *(required)* | Configuration to validate |

**Response:** `{"valid": true/false, "errors": [...]}`

### `get_privilege_gradient_stats`

Get statistics about a privilege gradient: zone counts, component counts.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config` | dict | *(required)* | Configuration to analyze |
| `group_by` | str | `""` | Component field to group by; adds per-group counts under `groups` (also used when the config sets `gradient.group_by` or components have a `group`) |

### `detect_privilege_inversions`

Detect cases where lower-trust zones influence higher-trust zones.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config` | dict | *(required)* | Configuration to analyze |

**Response:** JSON list of inversions with endpoints, zones, trust gap and severity.

### `analyze_zone_influence`

Analyze the influence matrix between trust zones.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config` | dict | *(required)* | Configuration to analyze |

**Response:** JSON influence matrix showing counts between zone pairs.

---

## Custom Diagrams

Tools for flexible, schema-driven diagram generation.

### `generate_custom_diagram`

Generate a custom diagram using Graphviz.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config` | dict | *(required)* | Config with nodes, edges, settings |
| `format` | str | `"png"` | Output format |
| `style` | str | `"cd_default"` | Style preset (`cd_default`, `cd_dark`, `cd_light`, `cd_colorful`, `cd_blueprint`, `cd_sketch`, `cd_corporate`, `cd_neon`, `cd_pastel`, `cd_minimal`, `cd_monochrome`, `cd_security`, `cd_nature`, `cd_ocean`), applied through the diagram settings |

### `validate_custom_diagram`

Validate a custom diagram configuration: schema definition, data conformance, node/edge references.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config` | dict | *(required)* | Configuration to validate |

**Response:** JSON validation report with errors and warnings.

### `get_custom_diagram_stats`

Get statistics about a custom diagram: node counts, edge counts.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config` | dict | *(required)* | Configuration to analyze |

---

## Component Diagrams

Tools for layered software architecture visualization.

### `generate_component_diagram`

Generate a component diagram with layered architecture.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config` | dict | *(required)* | Config with `title`, a list of `layers` (each with `name`, `order` and nested `components`) and `connections` (see `usecvislib://schemas/component-diagram`) |
| `format` | str | `"png"` | Output format |
| `style` | str | `"cd_default"` | Style preset (`cd_default`, `cd_dark`, `cd_blueprint`, `cd_minimal`; `sv_*` with the SVG engine) |
| `render_engine` | str | `"graphviz"` | `graphviz` or `svg` |
| `shine` | bool | `false` | Shine pack on Graphviz SVG |

### `validate_component_diagram`

Validate a component diagram configuration.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config` | dict | *(required)* | Configuration to validate |

**Response:** `{"valid": true/false, "errors": [...]}`

### `get_component_diagram_stats`

Get statistics about a component diagram.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config` | dict | *(required)* | Configuration to analyze |

**Response:** JSON with layer counts, component counts, connection statistics.

---

## Dependency Graphs

Tools for module dependency visualization with circular dependency detection.

### `generate_dependency_graph`

Generate a dependency graph with force-directed layout and SLOC-based node sizing; circular dependencies are highlighted.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config` | dict | *(required)* | Config with `title`, a list of `modules` and a list of `dependencies` (see `usecvislib://schemas/dependency-graph`) |
| `format` | str | `"png"` | Output format |
| `style` | str | `"dg_default"` | Style preset (`dg_default`, `dg_dark`, `dg_minimal`, `dg_coupling`; `sv_*` with the SVG engine) |
| `render_engine` | str | `"graphviz"` | `graphviz` or `svg` |
| `shine` | bool | `false` | Shine pack on Graphviz SVG |

### `validate_dependency_graph`

Validate a dependency graph configuration.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config` | dict | *(required)* | Configuration to validate |

**Response:** `{"valid": true/false, "errors": [...]}`

### `get_dependency_graph_stats`

Get statistics about a dependency graph.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config` | dict | *(required)* | Configuration to analyze |

**Response:** JSON with module counts, dependency counts, circular dependency information.

---

## Kill Chain

Tools for mapping an attack onto phases, with detection and mitigation coverage.

### `generate_kill_chain`

Lay techniques out in phase columns, color them by detection and mitigation coverage, and draw incident paths across phases.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config` | dict | *(required)* | Config with a `killchain` section (`name`, `framework`, `phases` for custom), `techniques` keyed by ID and optional `incidents` |
| `format` | str | `"png"` | Output format (`dot` with Graphviz only) |
| `style` | str | `"kc_default"` | Style preset (`kc_default`, `kc_light`, `kc_coverage`; `sv_default`, `sv_dark`, `sv_neon`, `sv_corporate`, `sv_minimal` with the SVG engine) |
| `render_engine` | str | `"graphviz"` | `graphviz` or `svg` |

- **Frameworks:** `kill_chain` (Lockheed Martin Cyber Kill Chain), `attack` (MITRE ATT&CK tactics), `atlas` (MITRE ATLAS tactics for AI systems), or `custom` (your own `phases`).
- **Techniques:** `name`, `phase`, `severity`, `detected`, `mitigated`. `inferred = true` marks a hypothesis, drawn faded and dashed; `sources` / `source_count` add a "confirmed by N sources" badge.
- **Incidents:** `id`, `name`, and `techniques` in order.

### `validate_kill_chain`

Validate a kill chain configuration.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config` | dict | *(required)* | Configuration to validate |

**Response:** `{"valid": true/false, "errors": [...]}`

### `get_kill_chain_stats`

Get technique counts, detection and mitigation coverage, active phases and incidents.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config` | dict | *(required)* | Configuration to analyze |

### `analyze_kill_chain_coverage`

List detection and mitigation gaps: undetected techniques, unmitigated techniques, and critical gaps (high or critical severity with neither).

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config` | dict | *(required)* | Configuration to analyze |

---

## Incident Timeline

Tools for plotting the chronology of a security incident.

### `generate_incident_timeline`

Plot events with severity markers, lanes, durations, ATT&CK technique tags and response-phase bands.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config` | dict | *(required)* | Config with `incident` (`name`, `id`, `analyst`), `events` (`id`, ISO-8601 `timestamp`, `title`, `severity` critical/high/medium/low/info, `lane`, optional `duration`, `technique`, `source`) and optional `phases` (`name`, `start`, `end`, `color`) |
| `format` | str | `"png"` | Output format: `png`, `pdf`, `svg` (no `dot`: the timeline is a chart) |
| `style` | str | `"tl_default"` | Style preset (`tl_default`, `tl_light`, `tl_dark`, `tl_print`, `tl_minimal`, `tl_corporate`; `sv_default`, `sv_dark`, `sv_print`, `sv_corporate`, `sv_minimal` with the SVG engine) |
| `mode` | str | `"swimlane"` | Layout: `swimlane`, `gantt`, `vertical`, `compact` |
| `render_engine` | str | `"graphviz"` | `graphviz` (the default path, drawn with Matplotlib) or `svg` |

### `validate_incident_timeline`

Validate an incident timeline configuration.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config` | dict | *(required)* | Configuration to validate |

**Response:** `{"valid": true/false, "errors": [...]}`

### `get_incident_timeline_stats`

Get event and phase counts, lanes, time span, severity distribution, response metrics (time to detect, contain and recover, from the phase bands) and ATT&CK-tagged events.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config` | dict | *(required)* | Configuration to analyze |

---

## Vulnerability Dependency Tree

Tools for software composition analysis: which dependencies expose the application to known CVEs.

### `generate_vuln_tree`

Draw the package dependency tree with CVEs attached. Node color is the worst CVE severity, direct dependencies get a bolder border, and edges into packages with an exploited CVE are highlighted.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config` | dict | *(required)* | Config with `vulntree` (`name`, optional `root_packages`) and `dependencies` keyed by package ID (`name`, `version`, `direct`, `dependencies` list, `vulnerabilities` list with `id`, `severity`, `cvss`, `fixed_version`, `exploited`, `cwe`) |
| `format` | str | `"png"` | Output format (`dot` with Graphviz only) |
| `style` | str | `"vt_default"` | Style preset (`vt_default`, `vt_dark`, `vt_security`, `vt_corporate`, `vt_minimal`; `sv_*` with the SVG engine) |
| `mode` | str | `"tree"` | `tree` (every reachable package), `vulnerable_only` (paths to any CVE), `critical_path` (paths to high/critical CVEs) |
| `render_engine` | str | `"graphviz"` | `graphviz` or `svg` |

### `validate_vuln_tree`

Validate a vulnerability dependency tree configuration.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config` | dict | *(required)* | Configuration to validate |

**Response:** `{"valid": true/false, "errors": [...]}`

### `get_vuln_tree_stats`

Get direct/transitive and vulnerable package counts, CVE severity distribution, exploited CVEs, max CVSS, root packages exposed through transitive CVEs (impact propagation) and remediation hints (fixed versions).

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config` | dict | *(required)* | Configuration to analyze |

---

## MAESTRO

Tools for threat modeling agentic AI systems with the CSA MAESTRO framework. MAESTRO maps agents and assets onto 7 layers (foundation models, data operations, agent frameworks, deployment, observability, security, agent ecosystem); the built-in catalog adds layer and cross-layer threats tagged with ATT&CK, OWASP and NIST AI RMF. See the [MAESTRO guide](MAESTRO_GUIDE.md).

### `generate_maestro_threat_model`

Generate a MAESTRO threat model.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config` | dict | *(required)* | Config with `meta` (`name`, `owner`), `architecture` (patterns), `agents` (`id`, `name`, `type`, `autonomy`, `layers`, `tools`), `assets` (`id`, `name`, `layer`, `sensitivity`), optional `threats` overrides (`id`, `target`, `severity`, `status`, `mitigations`), `mitigations` and `catalog` (`mode = auto`) |
| `format` | str | `"png"` | Output format (`dot` for the Graphviz views only) |
| `style` | str | `"ma_default"` | Style preset (`ma_default`, `ma_dark`, `ma_blueprint`, `ma_severity`, `ma_compact`; `sv_*` with the SVG engine) |
| `view` | str | `"layered"` | `layered` (the 7-layer stack), `graph` (agent-centric graph with cross-layer attack chains), `heatmap` (layer × severity matrix, Matplotlib) |
| `render_engine` | str | `"graphviz"` | `graphviz` or `svg` (the SVG engine supports the `graph` view only) |
| `shine` | bool | `false` | Shine pack on Graphviz SVG |

### `validate_maestro_threat_model`

Validate a MAESTRO threat model configuration.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config` | dict | *(required)* | Configuration to validate |

**Response:** `{"valid": true/false, "errors": [...]}`

### `get_maestro_stats`

Get agents, assets, threats (total, unmitigated, by severity and layer), cross-layer threats, mitigations and detected architecture patterns.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config` | dict | *(required)* | Configuration to analyze |

### `export_maestro`

Convert a MAESTRO threat model into another USecVisLib configuration, ready for the matching generate tool.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config` | dict | *(required)* | MAESTRO configuration to convert |
| `target` | str | `"stride"` | `stride` (DFD for `generate_threat_model`), `attack_graph` (for `generate_attack_graph`) or `privilege_gradient` (for `generate_privilege_gradient`) |

---

## Utilities

### `convert_to_mermaid`

Convert a visualization configuration to Mermaid diagram syntax. Supports attack trees, attack graphs, threat models, kill chains, incident timelines, vulnerability trees, privilege gradients, component diagrams, dependency graphs, MAESTRO models, and custom/cloud node-and-edge diagrams. The type is detected from the config structure.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config` | dict | *(required)* | Visualization configuration |
| `viz_type` | str | `""` | Optional expected type (e.g. `attack_tree`, `kill_chain`, `maestro`); if the config is detected as another type, an error is returned |

**Response:** `{"mermaid_source": "graph TD\n  ...", "viz_type": "..."}`

### `calculate_cvss_score`

Calculate a CVSS score from a vector string. Supports CVSS 3.0, 3.1, and 4.0; the version is detected from the prefix.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `vector` | str | *(required)* | CVSS vector (e.g. `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) |

**Response:** JSON with score, version, severity, and parsed vector components.

### `detect_config_type`

Detect the visualization type from a configuration dictionary, with usecvislib's own config detection.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config` | dict | *(required)* | Configuration to analyze |

**Response:** `{"type": "attack_tree", "confidence": "high"}`. Types: `attack_tree`, `attack_graph`, `threat_model`, `privilege_gradient`, `component_diagram`, `dependency_graph`, `kill_chain`, `incident_timeline`, `vuln_tree`, `maestro`, `cloud_diagram`, `custom_diagram`, `access_graph`, `mermaid`, or `unknown`; confidence `high`, `medium` or `low`.

### `list_shapes`

List available shapes for custom diagrams.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `category` | str | `""` | Filter by category (empty for all) |

---

## Batch

### `batch_process`

Batch-process multiple visualization configs in parallel.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `module_type` | str | *(required)* | `attack_tree`, `attack_graph`, `threat_model`, `privilege_gradient`, `component_diagram`, `dependency_graph`, `kill_chain`, `incident_timeline`, `vuln_tree`, or `maestro` |
| `configs` | list[dict] | *(required)* | Configuration dictionaries (max 100) |
| `format` | str | `"png"` | Output format |
| `style` | str | `""` | Style ID (empty for the module's default) |
| `max_workers` | int | `4` | Maximum parallel workers (max 8) |
| `render_engine` | str | `"graphviz"` | `graphviz` or `svg`, for the module types the SVG engine paints (use an `sv_*` style, or `""` for its default) |

**Response:** JSON with summary (success/failure counts) and individual results for each config.

---

## Export

### `export_data`

Export data to JSON, CSV, YAML, or Markdown table format.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `data` | dict or list | *(required)* | Data to export (a dict or a list of dicts) |
| `format` | str | `"json"` | Format: `json`, `csv`, `yaml`, `md` |

**Response:** JSON with the exported content, or the file path for CSV.

### `generate_report`

Generate a multi-format report from a visualization config.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config` | dict | *(required)* | Visualization configuration |
| `viz_type` | str | *(required)* | `attack_tree`, `attack_graph`, `threat_model`, `privilege_gradient`, `component_diagram`, `dependency_graph`, `kill_chain`, `incident_timeline`, `vuln_tree`, or `maestro` |
| `formats` | list[str] or null | `null` | Output formats: `json`, `csv`, `yaml`, `md` (defaults to `["json", "csv", "md"]`) |

**Response:** JSON mapping format names to the files written.

---

## Analysis

Cross-module analysis tools.

### `find_chokepoints`

Find network chokepoints in an attack graph: nodes that appear on the most attack paths, where defensive controls do the most.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config` | dict | *(required)* | Attack graph configuration |
| `top_n` | int | `10` | Number of top chokepoints |

**Response:** JSON list of chokepoint nodes with scores.

### `analyze_centrality`

Compute betweenness centrality for attack graph nodes: the bridges between parts of the network.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config` | dict | *(required)* | Attack graph configuration |
| `top_n` | int | `10` | Number of top central nodes |

**Response:** JSON list of nodes with centrality scores.

### `compare_visualizations`

Compare two visualization configs and return a structural diff.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `old_config` | dict | *(required)* | Previous version |
| `new_config` | dict | *(required)* | New version |
| `viz_type` | str | *(required)* | `attack_tree`, `attack_graph`, `threat_model`, `privilege_gradient`, `component_diagram`, `dependency_graph`, `kill_chain`, `incident_timeline`, `vuln_tree`, or `maestro` |

**Response:** JSON with change summary (added, removed, modified counts) and detailed changes list. To see the changes as a picture, use [`render_drift`](#render_drift).

---

## Drift

### `render_drift`

Draw the drift between two versions of an attack graph or privilege gradient as one picture of the merged graph. Added elements are outlined in pink-red with a `+`, removed ones faded and dashed with a `−`, modified ones outlined in violet with a `~`. For privilege gradients the tiering violations are compared too: new ones are labelled `NEW INVERSION`, fixed ones `FIXED INVERSION`, and ones whose severity or trust gap changed `~ INVERSION (old → new)`. Examples: the [Drift section of the gallery](https://vulnex.github.io/usecvislib-gallery/#drift), from the `templates/drift/` pairs.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `old_config` | dict | *(required)* | The earlier version |
| `new_config` | dict | *(required)* | The later version |
| `viz_type` | str | `"attack_graph"` | `attack_graph` or `privilege_gradient` |
| `format` | str | `"png"` | Output format: `png`, `pdf`, `svg` |
| `render_engine` | str | `"graphviz"` | `graphviz` or `svg` |
| `style` | str | `""` | Style preset of the module (`""` for the engine's default) |
| `show_unchanged` | bool | `true` | `false` draws only changed elements and their direct neighbours |
| `ignore_paths` | list[str] or null | `null` | Config path prefixes to ignore (e.g. `["graph.description"]`) |
| `diff_colors` | dict or null | `null` | Override any of `added`, `removed`, `modified` (hex colors) |
| `group_by`, `collapse`, `max_nodes` | | | Grouping and collapse of the merged graph, as in `generate_attack_graph` / `generate_privilege_gradient`. A collapsed group shows its members' changes (`+N −N ~N`) |
| `keep`, `keep_ids` | | | Privilege gradients only: components kept drawn next to their collapsed group. `keep="inversions"` also keeps the endpoints of new, fixed and changed inversions |

**Response:** JSON with `summary` (added/removed/modified/total), `has_changes`, `changes`, for privilege gradients `inversions` (`new`, `fixed`, `changed`), `viz_type`, `format`, and the picture: `output_path` and `size_bytes` (file mode) or `data_base64` (base64 mode).

---

## Resources Reference

### Templates

| URI | Description |
|-----|-------------|
| `usecvislib://templates/list` | List all template categories with counts |
| `usecvislib://templates/{category}/list` | List templates in a category |
| `usecvislib://templates/{category}/{name}` | Get template content |

### Styles

| URI | Description |
|-----|-------------|
| `usecvislib://styles/list` | All style presets grouped by visualization type |
| `usecvislib://styles/{visualization_type}` | Styles for a specific type |

Style types: `attack-trees`, `attack-graphs`, `threat-models`, `custom-diagrams`, `cloud-diagrams`, `privilege-gradient`, `component-diagram`, `dependency-graph`, `binary-visualization`, `kill-chain`, `incident-timeline`, `vuln-tree`, `maestro`. The lists are read from usecvislib's own preset files, so they include the `sv_*` presets of each SVG-engine module.

### Configuration Schemas

| URI | Description |
|-----|-------------|
| `usecvislib://schemas/attack-tree` | Attack tree config schema |
| `usecvislib://schemas/attack-graph` | Attack graph config schema (including host `group`, `inferred` / `confidence`, `sources`) |
| `usecvislib://schemas/threat-model` | Threat model config schema |
| `usecvislib://schemas/mermaid` | Mermaid parameter schema |
| `usecvislib://schemas/binary-analysis` | Binary analysis parameter schema |
| `usecvislib://schemas/cloud-diagram` | Cloud diagram config schema |
| `usecvislib://schemas/privilege-gradient` | Privilege gradient config schema (zones with `trust_level`, component `group`, influence `type`) |
| `usecvislib://schemas/custom-diagram` | Custom diagram config schema |
| `usecvislib://schemas/component-diagram` | Component diagram config schema |
| `usecvislib://schemas/dependency-graph` | Dependency graph config schema |
| `usecvislib://schemas/kill-chain` | Kill chain / MITRE ATT&CK / ATLAS config schema |
| `usecvislib://schemas/incident-timeline` | Incident timeline config schema |
| `usecvislib://schemas/vuln-tree` | Vulnerability dependency tree config schema |
| `usecvislib://schemas/maestro` | MAESTRO agentic-AI threat model config schema |

Each schema resource returns JSON with description, format, field definitions, and examples.

---

## Prompt Templates

Interactive guides that walk AI assistants through creating visualizations.

| Prompt | Description |
|--------|-------------|
| `create_attack_tree` | Define goals, decompose into attack vectors, assign CVSS scores, generate the visualization |
| `create_threat_model` | Identify components, map data flows, define boundaries, run STRIDE analysis |
| `create_attack_graph` | Model network hosts, map vulnerabilities, define exploits, analyze paths |
| `analyze_binary` | Generate the binary charts, interpret patterns, identify anomalies |
| `create_privilege_gradient` | Define trust zones, place components, map influences, detect inversions |
| `review_cloud_security` | Diagram the architecture, review security groups, check data flows, identify risks |
| `create_kill_chain` | Map an attack onto a kill chain / MITRE ATT&CK, then find detection and mitigation gaps |
| `create_incident_timeline` | Build an incident response timeline with events, lanes and response phases |
| `analyze_supply_chain` | Review a vulnerability dependency tree (SCA): exposed roots, exploited CVEs, fixes |
| `create_maestro_threat_model` | Threat model an agentic AI system with MAESTRO |

Usage in MCP clients:
```
Use the create_attack_tree prompt to guide me through creating an attack tree for a web application.
```
