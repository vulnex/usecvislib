# Changelog

All notable changes to USecVisLib will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.1] - 2026-05-12

### Added

- **MAESTRO Agent-Centric Graph view (View 2)** — third render view for MAESTRO threat models, completing the three-view set originally specified in `devnotes/MAESTRO_DESIGN.md`
  - Native Graphviz render: agents become nodes clustered by their primary MAESTRO layer (`agent.layers[0]`); only layers actually in use get clusters (canvas stays compact, unlike View 1 which always shows all 7 bands)
  - Cross-layer attack chains render as directed edges. Multi-agent chains use a per-chain color hashed deterministically from the chain id so re-renders stay stable. Chains that run entirely through a single agent (because that agent spans the declared layers) fall back to a labeled self-loop with the layer count, rather than being silently dropped
  - L6 Security rendered as a floating mitigation-summary `note` rather than a peer cluster, matching View 1's treatment of the cross-cutting layer
  - Auto-clustering by `agent.type` when a primary-layer cluster exceeds `cluster_threshold` (default 8)
  - Selectable via `usecvis -m 12 -v graph` (CLI), `POST /visualize/maestro?view=graph` (API), the "Agent Graph" option in the MaestroPanel view dropdown (Vue), or `[render] view = "graph"` (config file)
  - Optional render config: `[render] graph_direction = "LR"` (default) | `"TB"`, `[render] chain_labels = "first"` (default) | `"all"` | `"off"`
  - Distinct from `to_attack_graph()`: that exports an AttackGraph config dict consumed by the AttackGraphs module; this paints MAESTRO's own picture in MAESTRO terminology
- 4 new graph-view unit tests in `tests/test_maestro.py` and 1 new API test in `tests/test_api_maestro.py`
- New `MaestroView.GRAPH = "graph"` enum value in `api/schemas.py`
- Graph view subsection + legend table in `docs/MAESTRO_GUIDE.md`

### Changed

- Moved `CHANGELOG.md` from `devnotes/` to the repository root for visibility
- Per-file version strings synced to 0.4.0 across source headers, Dockerfile LABEL, frontend version readouts, and documentation footers (the 0.4.0 release commit only bumped `pyproject.toml`; this aligns everything else)

## [0.4.0] - 2026-05-11

### Added

- **MAESTRO Agentic AI Threat Modeling (CLI mode 12)**
  - New `MaestroThreatModel` class implementing the Cloud Security Alliance MAESTRO framework (Multi-Agent Environment, Security, Threat, Risk, & Outcome) for agentic AI systems
  - 7 architectural layers: Foundation Models, Data Operations, Agent Frameworks, Infrastructure, Observability, Security (vertical), Agent Ecosystem
  - First-class entities: `Agent` (autonomy level, goals, capabilities, tools, layers_touched), `Asset`, `Threat`, `CrossLayerThreat`, `Mitigation`
  - Built-in threat catalog (`models/maestro_catalog.json`, version `2026.3`): 55 layer threats, 6 cross-layer chains, 93 mitigations, plus best-effort cross-framework tags (11 MITRE ATT&CK, 8 OWASP Agentic Security Initiative T1/T2/T3, 55 NIST AI RMF function tags). Threats added in 2026.3 (informed by the Snyk MAESTRO write-up): `T-L1-008` Sleeper Agents, `T-L5-007` Log Injection (Cover Tracks), `T-L5-008` False-Positive Flooding, `T-L6-008` Compliance Bypass via Policy Interpretation, `T-L7-014` Reputation Manipulation, `T-CL-006` Cascade Failure Propagation
  - Architecture patterns: single-agent, multi-agent, hierarchical, distributed, human-in-the-loop, self-learning, unconstrained-conversational, task-oriented
  - Auto-population of catalog threats from declared agent layers + architecture patterns; pattern × layer mismatches emit warnings rather than attaching phantom threats
  - Two render views: layered architecture (Graphviz with vertical gutter for L6 Security) and severity heatmap (Matplotlib, agents × layers)
  - Auto-clustering of agents within a layer when count exceeds `cluster_threshold` (default 8)
  - 5 style presets: `ma_default`, `ma_dark`, `ma_blueprint`, `ma_severity`, `ma_compact`
  - Cross-reference exports — each round-trips cleanly into the target module with zero validation errors:
    - `to_stride()` — STRIDE / `ThreatModeling` shape with per-entry `mapping` label (exact / partial / informational) and unmapped-percentage in `_meta`
    - `to_attack_graph()` — AttackGraph shape (hosts / vulnerabilities / edges from chain steps)
    - `to_privilege_gradient()` — PrivilegeGradient shape with trust zones derived from agent autonomy levels
  - API router with 8 endpoints: `POST /visualize|/analyze|/validate/maestro`, `POST /analyze/maestro/threats` (filterable detail), `POST /maestro/export/{stride|attack-graph|privilege-gradient}`, `GET /maestro/catalog`, `GET /maestro/catalog/{layer}`
  - Vue 3 panel (`MaestroPanel.vue`) with config editor, generate / analyze / validate / threat-list / catalog-browser actions, severity heatmap stat grid, per-layer threat-count bars, warnings surface, and filterable threat list
  - 5 templates: `single-agent-rag.toml`, `multi-agent-support.toml`, `autonomous-soc-agent.toml`, `agent-marketplace.toml`, `financial-trading-chain.toml` (the last demonstrates full L1->L7 vertical attack chain propagation across 5 agents and 3 cross-layer chains; uses 2026.3 threats including Sleeper Agents, Log Injection, Compliance Bypass, Cascade Failure)
  - 54 unit + API tests (`test_maestro.py`, `test_api_maestro.py`)
  - Design document: `devnotes/MAESTRO_DESIGN.md`
  - User guide: `docs/MAESTRO_GUIDE.md` — covers configuration, render views, style presets, authoring tips, cross-reference exports, and troubleshooting

- **MCP Server (`usecvislib-mcp` v0.4.0)**
  - Streamable-HTTP transport support via `USECVISLIB_MCP_TRANSPORT=streamable-http`
  - API key authentication for HTTP transports (`USECVISLIB_MCP_API_KEY`) using SHA-256 hashed constant-time comparison
  - `/health` endpoint (unauthenticated) for container health checks
  - Production `Dockerfile` based on usecvislib-api image with streamable-http defaults
  - `usecvislib-mcp` service in `docker-compose.yml` (port 8001, depends on usecvislib-api)
  - `README.md` with installation, transport options, authentication, Docker deployment, client setup examples
  - `docs/MCP_TOOLS.md` comprehensive tool reference (49 tools, 15 resources, 6 prompts)
  - 130 tests (all passing) — added `test_auth.py` (4 tests) and new config getter tests (7 tests)
  - `uvicorn` dependency for HTTP transport serving
  - MCP environment variables in `.env.example`

- **MCP Server (`usecvislib-mcp` v0.3.0)**
  - New `usecvislib-mcp` package (sibling repo) wrapping USecVisLib via the MCP SDK's `FastMCP` class
  - 49 MCP tools across 13 modules:
    - Attack Trees (4): `generate_attack_tree`, `validate_attack_tree`, `get_attack_tree_stats`, `build_attack_tree_from_spec`
    - Attack Graphs (5): `generate_attack_graph`, `validate_attack_graph`, `get_attack_graph_stats`, `find_attack_paths`, `analyze_critical_nodes`
    - Threat Models (4): `generate_threat_model`, `validate_threat_model`, `get_threat_model_stats`, `analyze_stride_threats`
    - Mermaid (1): `render_mermaid`
    - Binary Analysis (5): `analyze_binary_entropy`, `analyze_binary_distribution`, `analyze_binary_heatmap`, `analyze_binary_all`, `get_binary_stats`
    - Cloud Diagrams (6): `generate_cloud_diagram`, `validate_cloud_diagram`, `get_cloud_diagram_stats`, `search_cloud_icons`, `list_cloud_providers`, `list_cloud_icons`
    - Privilege Gradient (5): `generate_privilege_gradient`, `validate_privilege_gradient`, `get_privilege_gradient_stats`, `detect_privilege_inversions`, `analyze_zone_influence`
    - Custom Diagrams (3): `generate_custom_diagram`, `validate_custom_diagram`, `get_custom_diagram_stats`
    - Architecture (6): `generate_component_diagram`, `validate_component_diagram`, `get_component_diagram_stats`, `generate_dependency_graph`, `validate_dependency_graph`, `get_dependency_graph_stats`
    - Utilities (4): `convert_to_mermaid`, `calculate_cvss_score`, `detect_config_type`, `list_shapes`
    - Batch (1): `batch_process` — parallel processing of multiple configs via `process_batch()`
    - Export (2): `export_data` (JSON/CSV/YAML/Markdown), `generate_report` (multi-format report generation via `ReportGenerator`)
    - Analysis (3): `find_chokepoints`, `analyze_centrality` (betweenness centrality), `compare_visualizations` (structural diff via `compare_files()`)
  - 15 MCP resources:
    - Template browsing: `usecvislib://templates/list`, `usecvislib://templates/{category}/list`, `usecvislib://templates/{category}/{name}`
    - Style catalog: `usecvislib://styles/list`, `usecvislib://styles/{visualization_type}`
    - Config schemas: `usecvislib://schemas/attack-tree`, `usecvislib://schemas/attack-graph`, `usecvislib://schemas/threat-model`, `usecvislib://schemas/mermaid`, `usecvislib://schemas/binary-analysis`, `usecvislib://schemas/cloud-diagram`, `usecvislib://schemas/privilege-gradient`, `usecvislib://schemas/custom-diagram`, `usecvislib://schemas/component-diagram`, `usecvislib://schemas/dependency-graph`
  - 6 MCP prompt templates: `create_attack_tree`, `create_threat_model`, `create_attack_graph`, `analyze_binary`, `create_privilege_gradient`, `review_cloud_security`
  - Skill directory (`skill/SKILL.md`) with visualization selection guide, per-type configuration best practices, style recommendations by audience, 4 multi-step workflow orchestrations (Comprehensive Security Assessment, Binary Triage Pipeline, Cloud Security Review, Attack Surface Mapping), export/output guidance, and auto-detection guidance
  - 3 example JSON configs: `attack_tree_web_app.json`, `threat_model_microservice.json`, `cloud_aws_three_tier.json`
  - Core infrastructure: env-based config, file/base64 output modes, async executor wrapping, temp file lifecycle management, Pattern A and Pattern B helper functions
  - 119 tests (all passing in Docker with Graphviz + mermaid-cli + diagrams)
  - Entry point: `usecvislib-mcp = "usecvislib_mcp.server:main"`

## [0.3.4] - 2026-02-14

### Security

- **Critical & High Security Fixes** (commit `a5e113e`)
  - C1: DOT injection prevention — `sanitize_node_id()` applied across 5 visualization modules
  - C3: SVG XXE prevention — reject `<!DOCTYPE` and `<!ENTITY` in SVG inputs
  - H1: SVG XXE hardening in image validation
  - H2: Cache directory verification using `O_DIRECTORY|O_NOFOLLOW` flags
  - H3: Graph complexity limits — max 10,000 nodes, 50,000 edges via `check_graph_complexity()`
  - H4: Config parsing limits — 10MB max size, 50 nesting depth
  - H5: Temporary file cleanup registration on process exit
  - H6: HTML escape for image paths in Graphviz labels
  - H7: Hardened `_escape_python_string()` with `repr()` and f-string brace escaping

- **Medium Security Fixes** (commit `f15e354`)
  - M1: YAML pre-parse size check (10MB limit)
  - M2: JSON recursion limit guard
  - M5: Image validation — magic bytes check before MIME type
  - M7: Symlink pre-resolve check in `validate_input_path()`
  - M8: Per-field size limits for progress store entries

### Added

- **Architecture Diagrams (Component Diagram + Dependency Graph)**
  - New `ComponentDiagram` class for layered software architecture visualization
  - Components organized into layers (Client, Application, Data, etc.) with typed shapes
  - 8 component types: frontend, service, database, cache, storage, queue, external_service, cli
  - 4 connection styles: sync (solid), async (dashed), bidirectional (both arrows), event (dotted)
  - 4 built-in styles: cd_default, cd_blueprint, cd_minimal, cd_dark
  - New `DependencyGraph` class for module dependency visualization
  - SLOC-based node sizing with linear scale (0.5 to 2.0)
  - Force-directed layout (fdp engine) with group-based subgraph clustering
  - Circular dependency detection with red highlighted edges
  - 3 dependency types: import (solid), framework (dotted), runtime (dashed)
  - 3 edge weights: light (1px), medium (2px), heavy (3px)
  - Group coloring for internal modules (core, features, api, infrastructure, tests, utils)
  - 4 built-in styles: dg_default, dg_dark, dg_minimal, dg_coupling
  - `ComponentDiagramBuilder` and `DependencyGraphBuilder` fluent APIs
  - CLI modes 7 (Component Diagrams) and 8 (Dependency Graphs)

- **Architecture Diagram API Endpoints**
  - `POST /visualize/component-diagram` - generate component diagram visualization
  - `POST /visualize/dependency-graph` - generate dependency graph visualization
  - `POST /analyze/component-diagram` - return component diagram stats
  - `POST /analyze/dependency-graph` - return dependency graph stats
  - `POST /validate/component-diagram` - validate component diagram config
  - `POST /validate/dependency-graph` - validate dependency graph config

- **Architecture Frontend Panel**
  - Single "Architecture" tab with diagram type toggle (Component Diagram / Dependency Graph)
  - Dynamic style selector that switches between cd_* and dg_* styles based on diagram type
  - Generate Visualization, Analyze Structure, and Validate actions
  - Stats display with layer/component/connection breakdowns (component diagram) and module/dependency/circular/group breakdowns (dependency graph)
  - Template type detection for both component diagram and dependency graph configs
  - 5 example templates: webapp TOML, microservices JSON, dependency graph TOML, and 2 JSON examples

- **Privilege Gradient Graph Visualization**
  - New `PrivilegeGradient` class for trust zone visualization with automatic inversion detection
  - Components placed within trust zones rendered as vertical colored columns (low to high trust)
  - Four influence edge types: Data, Feedback, Resource, Control with distinct visual styles
  - Automatic detection of privilege gradient inversions where lower-trust components influence higher-trust components
  - Severity classification for inversions: critical (trust gap >= 3), high (>= 2), medium (1)
  - NetworkX-based analysis: degree centrality, influence path finding, zone influence matrix
  - Compact HTML-table legend rendered inline with the graph
  - 5 built-in styles: pg_default, pg_dark, pg_security, pg_neon, pg_corporate
  - CLI mode 6 for command-line generation
  - `PrivilegeGradientBuilder` fluent API for programmatic graph construction
  - Validation of config structure (zone refs, influence refs, duplicate IDs)

- **Privilege Gradient API Endpoints**
  - `POST /visualize/privilege-gradient` - generate visualization from config file
  - `POST /analyze/privilege-gradient` - return stats without rendering
  - `POST /analyze/inversions` - detect and return inversions with severity
  - `POST /validate/privilege-gradient` - validate config structure

- **Privilege Gradient Frontend Panel**
  - Full Vue 3 panel with file upload, drag-and-drop, and config editor
  - Generate Visualization, Analyze Structure, Detect Inversions, and Validate actions
  - Stats grid showing zones, components, influences, inversions, and max trust gap
  - Components per Zone bar chart with aligned count numbers
  - Inversions list with severity badges and color-coded borders
  - Template type detection for privilege gradient configs (TOML, JSON, YAML)

- **6 Example Templates**
  - `microservices_auth.tml` - Microservices authentication architecture (5 zones, 10 components)
  - `corporate_network.tml` - Enterprise network segmentation with DMZ misconfiguration
  - `iot_scada.tml` - ICS/SCADA based on IEC 62443 Purdue Model (5 levels)
  - `cloud_zero_trust.tml` - NIST 800-207 zero trust cloud-native architecture
  - `ci_cd_pipeline.tml` - Software supply chain security with CI/CD stages
  - `healthcare_ehr.tml` - HIPAA-compliant EHR system with PHI protection boundaries

- **5 New Color Schemes**
  - New attack tree styles: at_ocean, at_sunset, at_forest, at_midnight, at_blueprint
  - New attack graph styles: ag_ocean, ag_sunset, ag_forest, ag_midnight, ag_blueprint

### Changed

- **Migrate setup.py to pyproject.toml**
  - Modern Python packaging with `[build-system]` and `[project]` metadata
  - Fixed license from MIT to Apache-2.0 (matching LICENSE file and README)
  - Added `[project.optional-dependencies]` dev group (pytest, pytest-cov, pytest-asyncio, ruff)
  - Added ruff and pytest configuration sections
  - Removed legacy `setup.py`

- **Drop Python 3.8/3.9 support**
  - Minimum Python version is now 3.10+
  - Added Python 3.13 classifier

- **Split monolithic API into FastAPI routers**
  - Refactored 5,691-line `api/main.py` into focused modules
  - New `api/config.py` for constants, environment variables, and logging setup
  - New `api/middleware.py` for security headers and request logging middleware
  - New `api/helpers.py` for shared utility functions
  - 12 router modules under `api/routers/`: attack_trees, attack_graphs, threat_models, binary, custom_diagrams, mermaid, cloud, privilege_gradient, images, icons, settings, utilities
  - No changes to existing endpoint paths or behavior

- **Frontend tab layout**
  - Tighter tab spacing to accommodate 9 primary visualization tabs
  - Privilege Gradient tab positioned before Binary Analysis

### Fixed

- **Docker build compatibility**
  - Fixed setuptools build backend from `setuptools.backends._legacy` to `setuptools.build_meta`
  - Removed deprecated license classifier for PEP 639 compliance

### Added (CI/CD)

- **GitHub Actions CI/CD pipeline**
  - Ruff linting on Python 3.12
  - Test matrix across Python 3.10, 3.11, 3.12, 3.13
  - System dependency installation (graphviz)

## [0.3.3] - 2025-01-15

### Added

- **Mermaid Diagrams Module**
  - New `MermaidDiagrams` class for rendering Mermaid syntax to images via mermaid-cli
  - Support for all Mermaid diagram types: flowcharts, sequence, class, state, ER, Gantt, pie, mindmap, timeline, etc.
  - Template system with categories (flowcharts, sequence, class, state, etc.)
  - API endpoints for Mermaid visualization and template management
  - Frontend panel with editor, template browser, and zoom/pan support
  - Theme and background customization options
  - Docker support with Chromium and puppeteer configuration for sandbox environments

- **Cloud Diagrams Module**
  - New `CloudDiagrams` class for cloud architecture visualization using the `diagrams` library
  - Support for AWS, Azure, GCP, Kubernetes, and generic cloud provider icons
  - Cluster support for grouping related components
  - Edge labels and styling for connections between nodes
  - Template system with security, microservices, and infrastructure patterns
  - API endpoints for cloud diagram visualization and template management
  - Frontend panel with editor, template browser, and zoom/pan support

- **Zoom/Pan Support**
  - Added `ZoomableImage` component to Mermaid and Cloud diagram panels
  - Consistent zoom experience across all visualization modules

- **CVSS 4.0 Support**
  - Full CVSS 4.0 implementation with MacroVector scoring algorithm
  - All 11 base metrics: Attack Vector, Attack Complexity, Attack Requirements, Privileges Required, User Interaction, plus 6 impact metrics (Vulnerable/Subsequent system separation)
  - Optional Threat metric (Exploit Maturity) and Environmental metrics
  - Version-agnostic `cvss_unified` module with automatic version detection
  - CVSS 4.0 is now the default version in the calculator

- **CVSS Vector Import**
  - Reverse vector parsing: paste a CVSS vector string to auto-configure UI metrics
  - Auto-detects version (3.1 or 4.0) and switches calculator tab accordingly
  - Supports both base-only and full vectors with optional metrics

- **Python API Examples**
  - New `mermaid_diagram_basic.py` with examples for flowcharts, sequence, ER, state, mindmap, Gantt, class diagrams
  - New `cloud_diagram_basic.py` with examples for AWS, Kubernetes, multi-cloud architectures
  - Updated README with quick start examples for Mermaid and Cloud diagrams

### Documentation

- **PYTHON_API.md**
  - Rewrote CVSS Module section with unified interface (recommended), CVSS 4.0 module, and CVSS 3.1 module
  - Added CVSS 4.0 metric tables (11 base metrics + threat metric)
  - Updated enum documentation for both versions

- **UI_GUIDE.md**
  - Updated CVSS Calculator section with version toggle, vector import, and both 3.1/4.0 metrics
  - Updated tools dropdown description

### Fixed

- **Mermaid Diagrams**
  - Fixed constructor parameter handling - moved rendering options to `render()` method
  - Fixed TOML format detection for files starting with comments
  - Fixed theme/background options not being passed to visualization API

- **Cloud Diagrams**
  - Fixed format compatibility between frontend and backend TOML structures
  - Fixed template content not loading when selecting from template browser
  - Fixed icon naming issues in security templates (e.g., `NetworkFirewall` → `FirewallManager`)

- **Consistent Style Application Across All Modules**
  - Fixed Custom Diagrams API endpoint not applying the style parameter
  - Fixed Attack Trees leaf nodes ignoring selected style
  - Fixed Attack Graphs vulnerability nodes ignoring selected style

### Changed

- **CVSS Integration**
  - Attack Trees, Attack Graphs, and Threat Modeling now use unified CVSS module
  - Automatic version detection for CVSS vectors in visualization definitions

- **Custom Diagrams Style System Overhaul**
  - Custom Diagrams now loads style configuration from `config_customdiagrams.tml`
  - Added `_strip_style_attrs()` method for style attribute management
  - Style presets now fully apply to all diagram elements

## [0.3.2] - 2025-01-09

### Security

- Security hardening and vulnerability fixes
- Added per-request timeouts to prevent resource exhaustion
- Implemented CORS origin validation
- Added API key authentication with constant-time comparison

### Added

- Rate limiting for API endpoints
- Image MIME type and magic byte validation
- Automatic temporary file cleanup

## [0.3.1] - 2025-01-01

### Added

- Initial public release
- Attack Trees visualization with CVSS support
- Attack Graphs with NetworkX analysis
- Threat Modeling with STRIDE/DFD support
- Binary Visualization (entropy, distribution, heatmap)
- Custom Diagrams with schema-driven flexibility
- REST API with FastAPI
- Vue.js 3 web frontend
- CLI tool for command-line usage
- 100+ built-in shapes
- Multiple style presets per module
- Export to PNG, SVG, PDF, DOT formats
