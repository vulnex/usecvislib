# MCP Tools Reference

Comprehensive reference for the 49 tools, 15 resources, and 6 prompt templates provided by the `usecvislib-mcp` server (v0.4.0).

## Table of Contents

- [Tool Conventions](#tool-conventions)
- [Attack Trees (4)](#attack-trees)
- [Attack Graphs (5)](#attack-graphs)
- [Threat Models (4)](#threat-models)
- [Mermaid (1)](#mermaid)
- [Binary Analysis (5)](#binary-analysis)
- [Cloud Diagrams (6)](#cloud-diagrams)
- [Privilege Gradient (5)](#privilege-gradient)
- [Custom Diagrams (3)](#custom-diagrams)
- [Architecture — Component Diagrams (3)](#component-diagrams)
- [Architecture — Dependency Graphs (3)](#dependency-graphs)
- [Utilities (4)](#utilities)
- [Batch (1)](#batch)
- [Export (2)](#export)
- [Analysis (3)](#analysis)
- [Resources Reference (15)](#resources-reference)
- [Prompt Templates (6)](#prompt-templates)

---

## Tool Conventions

### Common Parameters

Most visualization tools share these parameters:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config` | dict | *(required)* | Configuration dictionary for the visualization |
| `format` | str | `"png"` | Output format: `png`, `pdf`, `svg`, or `dot` |
| `style` | str | *(varies)* | Style preset ID (see `usecvislib://styles/list`) |

### Output Modes

- **`file` mode** (stdio transport): Returns an absolute file path on disk.
- **`base64` mode** (HTTP transports): Returns base64-encoded image data with MIME type.

### Error Handling

All tools return JSON with an `"error"` key on failure:
```json
{"error": "Description of what went wrong"}
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
| `style` | str | `"at_default"` | Style preset (e.g. `at_corporate`, `at_neon`) |

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

Validate an attack tree configuration without generating output.

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

Build an attack tree using the builder API (structured specification).

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

Generate an attack graph visualization.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config` | dict | *(required)* | Config with `graph`, `hosts`, `vulnerabilities`, `privileges`, `services`, `exploits`, `network_edges` |
| `format` | str | `"png"` | Output format |
| `style` | str | `"ag_default"` | Style preset |

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

**Response:** JSON with node counts, edge counts, and metrics.

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
| `engine` | str | `"usecvislib"` | Rendering engine: `usecvislib` or `pytm` |

### `validate_threat_model`

Validate a threat model configuration.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config` | dict | *(required)* | Configuration to validate |

### `get_threat_model_stats`

Get statistics about a threat model.

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

Render a Mermaid diagram from source text. Requires mermaid-cli (`mmdc`).

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

Tools for binary file visualization and statistical analysis.

### `analyze_binary_entropy`

Generate an entropy visualization showing byte entropy distribution across the file.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `file_path` | str | *(required)* | Path to binary file |
| `format` | str | `"png"` | Output format: `png`, `pdf`, `svg` |

### `analyze_binary_distribution`

Generate a byte value frequency distribution visualization (0-255).

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `file_path` | str | *(required)* | Path to binary file |
| `format` | str | `"png"` | Output format |

### `analyze_binary_heatmap`

Generate a 2D byte heatmap for visual pattern recognition.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `file_path` | str | *(required)* | Path to binary file |
| `format` | str | `"png"` | Output format |

### `analyze_binary_all`

Generate all binary visualizations (entropy, distribution, heatmap) in one call.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `file_path` | str | *(required)* | Path to binary file |
| `format` | str | `"png"` | Output format |

### `get_binary_stats`

Get statistical summary without generating visualization.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `file_path` | str | *(required)* | Path to binary file |

**Response:** JSON with file size, entropy, byte distribution statistics.

---

## Cloud Diagrams

Tools for cloud architecture diagram generation. Requires `diagrams` Python package and Graphviz.

### `generate_cloud_diagram`

Generate a cloud architecture diagram.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config` | dict | *(required)* | Config with nodes, edges, clusters |
| `format` | str | `"png"` | Output format |

### `validate_cloud_diagram`

Validate a cloud diagram configuration.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config` | dict | *(required)* | Configuration to validate |

### `get_cloud_diagram_stats`

Get statistics about a cloud diagram.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config` | dict | *(required)* | Configuration to analyze |

### `search_cloud_icons`

Search for cloud provider icons by name.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `query` | str | *(required)* | Search query (case-insensitive) |
| `limit` | int | `20` | Maximum results |

### `list_cloud_providers`

List available cloud providers. No parameters.

### `list_cloud_icons`

List icons for a specific cloud provider.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `provider` | str | *(required)* | Provider ID: `aws`, `gcp`, `azure`, etc. |
| `category` | str | `""` | Filter by category (empty for all) |

---

## Privilege Gradient

Tools for trust zone visualization with automatic inversion detection.

### `generate_privilege_gradient`

Generate a privilege gradient graph.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config` | dict | *(required)* | Config with `gradient`, `zones`, `components`, `influences` |
| `format` | str | `"png"` | Output format |
| `style` | str | `"pg_default"` | Style preset |

### `validate_privilege_gradient`

Validate a privilege gradient configuration.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config` | dict | *(required)* | Configuration to validate |

### `get_privilege_gradient_stats`

Get statistics about a privilege gradient.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config` | dict | *(required)* | Configuration to analyze |

### `detect_privilege_inversions`

Detect cases where lower-privilege zones influence higher-privilege zones.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config` | dict | *(required)* | Configuration to analyze |

**Response:** JSON list of privilege inversions found.

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
| `style` | str | `"cd_default"` | Style preset |

### `validate_custom_diagram`

Validate a custom diagram configuration.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config` | dict | *(required)* | Configuration to validate |

### `get_custom_diagram_stats`

Get statistics about a custom diagram.

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
| `config` | dict | *(required)* | Config with `diagram`, `layers`, `components`, `connections` |
| `format` | str | `"png"` | Output format |
| `style` | str | `"comp_default"` | Style preset |

### `validate_component_diagram`

Validate a component diagram configuration.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config` | dict | *(required)* | Configuration to validate |

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

Generate a dependency graph with force-directed layout and SLOC-based node sizing.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config` | dict | *(required)* | Config with `graph`, `modules`, `dependencies` |
| `format` | str | `"png"` | Output format |
| `style` | str | `"dep_default"` | Style preset |

### `validate_dependency_graph`

Validate a dependency graph configuration.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config` | dict | *(required)* | Configuration to validate |

### `get_dependency_graph_stats`

Get statistics about a dependency graph.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config` | dict | *(required)* | Configuration to analyze |

**Response:** JSON with module counts, dependency counts, circular dependency information.

---

## Utilities

### `convert_to_mermaid`

Convert a visualization configuration to Mermaid diagram syntax.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config` | dict | *(required)* | Visualization configuration |
| `viz_type` | str | `""` | Type hint (auto-detected if empty): `attack_tree`, `attack_graph`, `threat_model` |

**Response:** `{"mermaid_source": "graph TD\n  ..."}`

### `calculate_cvss_score`

Calculate a CVSS score from a vector string. Supports CVSS 3.0, 3.1, and 4.0.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `vector` | str | *(required)* | CVSS vector (e.g. `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) |

**Response:** JSON with score, version, severity, and parsed vector components.

### `detect_config_type`

Detect the visualization type from a configuration dictionary.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config` | dict | *(required)* | Configuration to analyze |

**Response:** `{"type": "attack_tree", "confidence": "high"}`

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
| `module_type` | str | *(required)* | Visualization type: `attack_tree`, `attack_graph`, `threat_model`, `privilege_gradient`, `component_diagram`, `dependency_graph` |
| `configs` | list[dict] | *(required)* | List of configuration dictionaries |
| `format` | str | `"png"` | Output format |
| `style` | str | `""` | Style ID (empty for default) |
| `max_workers` | int | `4` | Maximum parallel workers |

**Response:** JSON with summary and individual results for each config.

---

## Export

### `export_data`

Export data to JSON, CSV, YAML, or Markdown table format.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `data` | dict or list | *(required)* | Data to export |
| `format` | str | `"json"` | Format: `json`, `csv`, `yaml`, `md` |

**Response:** JSON with exported content or file path (CSV writes to file).

### `generate_report`

Generate a multi-format report from a visualization config.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config` | dict | *(required)* | Visualization configuration |
| `viz_type` | str | *(required)* | Visualization type |
| `formats` | list[str] or null | `null` | Output formats (defaults to `["json", "csv", "md"]`) |

**Response:** JSON mapping format names to output file paths.

---

## Analysis

Cross-module analysis tools for attack graphs.

### `find_chokepoints`

Find network chokepoints — nodes appearing on the most attack paths.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config` | dict | *(required)* | Attack graph configuration |
| `top_n` | int | `10` | Number of top chokepoints |

### `analyze_centrality`

Compute betweenness centrality for attack graph nodes.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config` | dict | *(required)* | Attack graph configuration |
| `top_n` | int | `10` | Number of top central nodes |

### `compare_visualizations`

Compare two visualization configs and return a structural diff.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `old_config` | dict | *(required)* | Previous version |
| `new_config` | dict | *(required)* | New version |
| `viz_type` | str | *(required)* | Type: `attack_tree`, `attack_graph`, `threat_model` |

**Response:** JSON with change summary (added, removed, modified counts) and detailed changes list.

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

Style types: `attack-trees`, `attack-graphs`, `threat-models`, `custom-diagrams`, `cloud-diagrams`, `privilege-gradient`, `component-diagram`, `dependency-graph`, `binary-visualization`.

### Configuration Schemas

| URI | Description |
|-----|-------------|
| `usecvislib://schemas/attack-tree` | Attack tree config schema |
| `usecvislib://schemas/attack-graph` | Attack graph config schema |
| `usecvislib://schemas/threat-model` | Threat model config schema |
| `usecvislib://schemas/mermaid` | Mermaid parameter schema |
| `usecvislib://schemas/binary-analysis` | Binary analysis parameter schema |
| `usecvislib://schemas/cloud-diagram` | Cloud diagram config schema |
| `usecvislib://schemas/privilege-gradient` | Privilege gradient config schema |
| `usecvislib://schemas/custom-diagram` | Custom diagram config schema |
| `usecvislib://schemas/component-diagram` | Component diagram config schema |
| `usecvislib://schemas/dependency-graph` | Dependency graph config schema |

Each schema resource returns JSON with description, format, field definitions, and examples.

---

## Prompt Templates

Interactive guides that walk AI assistants through creating visualizations.

| Prompt | Description |
|--------|-------------|
| `create_attack_tree` | Step-by-step guide: define goals, decompose into attack vectors, assign CVSS scores, generate visualization |
| `create_threat_model` | Step-by-step guide: identify components, map data flows, define boundaries, run STRIDE analysis |
| `create_attack_graph` | Step-by-step guide: model network hosts, map vulnerabilities, define exploits, analyze paths |
| `analyze_binary` | Step-by-step guide: generate entropy/distribution/heatmap, interpret patterns, identify anomalies |
| `create_privilege_gradient` | Step-by-step guide: define trust zones, place components, map influences, detect inversions |
| `review_cloud_security` | Step-by-step guide: diagram architecture, review security groups, check data flows, identify risks |

Usage in MCP clients:
```
Use the create_attack_tree prompt to guide me through creating an attack tree for a web application.
```
