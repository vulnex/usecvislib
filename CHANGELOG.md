# Changelog

All notable changes to USecVisLib will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Render gallery** at https://vulnex.github.io/usecvislib-gallery/ (repository [vulnex/usecvislib-gallery](https://github.com/vulnex/usecvislib-gallery)): every bundled template rendered with every engine, view and style preset, in PNG, SVG, PDF and DOT. The README and the CLI, template, custom-diagram, MAESTRO and Python API guides link to it.
- `scripts/build_gallery.py` regenerates the gallery inside the API Docker image. It fails if any render errors or if an output contains a home-directory path or an e-mail address.

### Fixed

- **SVG output with icons is self-contained.** Graphviz SVGs (every Graphviz module) and cloud-diagram SVGs linked node icons by absolute file path: temp thumbnails deleted at exit, or the icon's location in `site-packages`. Shared SVGs showed no icons and disclosed local paths, often including the user's home directory. Local images are now embedded as `data:` URIs (`utils.embed_svg_images`, applied by the new `utils.render_graph`). DOT output still references icon files, since Graphviz needs them to render.
- **Vulnerability tree output is reproducible.** Nodes and edges were emitted in set order, which follows Python's per-process string hash seed, so the same input gave different SVG bytes (and potentially a different Graphviz layout) on each run. `_visible_nodes()` now returns dependencies in declaration order.
- **Custom diagrams with force layouts are reproducible.** The `force`, `grid` and `sfdp` layouts (Graphviz `fdp`, `neato`, `sfdp`) started from a random placement, so a diagram such as the network topology template changed size and shape on every render. They now use a fixed seed (`start=1`).
- **Cloud diagrams with an empty cluster render.** A cluster without nodes generated an empty `with Cluster(...):` block, so the diagram failed with a Python `IndentationError`. It now renders as an empty cluster and logs a warning.
- **Batch processing covers every file-based module.** `BatchProcessor` / `process_batch()` accepted only `attack_tree`, `attack_graph`, `threat_model` and `binary`; `privilege_gradient`, `component_diagram`, `dependency_graph`, `kill_chain`, `incident_timeline`, `vuln_tree` and `maestro` raised "Unknown module type". They now build through the shared `build()` path.
- **Reports list only files they wrote.** `ReportGenerator.generate_report()` listed a CSV per config section, but no visualization class provides `export_csv`, so none of those CSVs were written. Tabular sections (lists of objects, or objects keyed by ID) are now written directly, and only files that exist are returned.

## [0.6.0] - 2026-09-23

### Added

- **SVG engine support for the MAESTRO agent-centric graph (mode 12) — the fifth general-graph painter; completes SVG Engine Phase 3** — the SVG rendering engine (`--render-engine svg` / `render_engine="svg"`) now paints MAESTRO's agent-centric `graph` view natively. With this, every general-graph module (Attack Graphs, Dependency Graph, Component Diagram, DFD, MAESTRO) has an SVG painter.
  - New `svgengine/painters/maestro.py` maps MAESTRO agents into a styled scene: agents become nodes clustered into their primary MAESTRO layer (Security / L6 agents float outside clusters, mirroring the Graphviz path's cross-cutting treatment), colored from the per-layer palette with a red border for agents owning a critical unmitigated threat, and labelled with type/autonomy plus a compact severity-count row. Cross-layer threats with an attack chain become directed edges between the agents they traverse, colored per chain (a chain running through a single agent renders as a labelled dashed self-loop). A `maestro` theme block (7-layer palette + border/chain colors) was added to the engine defaults.
  - **Only the agent-centric `graph` view is SVG-native**: the `layered` architecture view is a fixed 7-band stack and `heatmap` is a Matplotlib chart, so both raise a clear `EngineNotSupportedError` pointing at `view='graph'`. The CLI/API/frontend steer SVG requests to the graph view automatically.
  - 5 `sv_*` presets (`sv_default/dark/security/corporate/minimal`) added to `config_maestro.tml`; emitted SVG carries the interactivity contract (`data-node-id`, `data-kind="agent"`, `data-layer`, `usv-node--agent`, `usv-sev--*`, `usv-edge--chain`, `usv-cluster` groups) with no active content; PNG/PDF via cairosvg.
  - Wired through the CLI (`-m 12 -v graph --render-engine svg`), the REST API (`render_engine` on `POST /visualize/maestro`; when SVG is selected the view defaults to `graph` and the default style maps to `sv_default`; `sv_*` values on `MaestroStyle`), and the frontend `MaestroPanel.vue` (a Render Engine toggle that forces the graph view + sv_* styles under SVG and inlines output via `InteractiveSvg`); `api.js` threads `render_engine` through the MAESTRO visualize paths.
  - 26 tests in `tests/test_svg_maestro.py` (contract, all templates, agent→node/cluster/chain semantics, severity classes, the layered/heatmap view guard, engine-mismatch guards, cairosvg raster, CLI end-to-end). Render tests are gated on the `dot` binary; verified in the container (180 pass across all six SVG general-graph suites, no regression) and via the live REST API.
  - **Packaging fix:** `pyproject.toml` `package-data` now includes `models/*.json`, not just `models/*.tml` — the MAESTRO threat catalog (`maestro_catalog.json`) was previously omitted from installs, so a `pip install`ed MAESTRO (any view) failed to load its catalog.
- **SVG engine support for the Threat Model DFD (mode 1) — the fourth general-graph painter** — the SVG rendering engine (`--render-engine svg` / `render_engine="svg"`) now paints Data Flow Diagrams natively, with trust boundaries as dashed cluster rectangles.
  - The general-graph cluster support gained **dashed borders** (`SceneGroup.dashed`), used for DFD trust boundaries per convention.
  - New `svgengine/painters/threatmodeling.py` maps a threat model's DFD sections into a styled scene: external entities / processes / data stores become distinct card shapes (card / pill / chamfer), directed data flows become labelled edges, and each trust boundary becomes a dashed cluster group (a node lands in its first boundary only, since clusters cannot overlap). It renders the DFD diagram only; STRIDE threat analysis and the report are unaffected, and the SVG path is independent of the pytm/usecvislib analysis engine.
  - 5 `sv_*` presets (`sv_default/dark/security/corporate/minimal`) added to `config_threatmodeling.tml`; a `dfd` theme block (per-element-type fills, data-flow color, trust-boundary styling) added to the engine defaults.
  - Emitted SVG carries the interactivity contract (`data-node-id`, `data-kind` = external/process/datastore, `usv-node--<type>`, `usv-edge--dataflow`, plus dashed `usv-cluster` groups with `data-cluster-id` / `data-label`) with no active content; PNG/PDF via cairosvg.
  - Wired through the CLI (`-m 1 --render-engine svg`), the REST API (`render_engine` on `POST /visualize/threat-model`, `sv_*` values on `ThreatModelStyle`; when the SVG engine is selected the pytm analysis engine is bypassed), and the frontend `ThreatModelPanel.vue` (a Render Engine toggle distinct from the Analysis Engine, forcing usecvislib + sv_* styles under SVG and inlining output via `InteractiveSvg`); `api.js` threads `render_engine` through the threat-model visualize paths.
  - 29 tests in `tests/test_svg_threatmodeling.py` (contract, all templates, element-type shapes, trust-boundary→dashed-cluster counts + labels, data-flow labels, engine-mismatch guards, cairosvg raster, CLI end-to-end). Render tests are gated on the `dot` binary; verified in the container (154 pass across all five SVG general-graph suites, no regression) and via the live REST API. Frontend builds clean. (Also updated `test_svgengine.py::test_unsupported_module_raises` to use `PrivilegeGradient`, since `ThreatModeling` is now supported.)
- **SVG engine support for the Component Diagram (mode 7) — the third general-graph painter, with cluster support** — the SVG rendering engine (`--render-engine svg` / `render_engine="svg"`) now paints layered architecture diagrams natively, and the general-graph path gained **cluster (grouping) support** to make it possible.
  - The shared general-graph path now renders **clusters**: `SceneGroup` carries geometry + colors, `GraphvizJsonLayout` emits each group with members as a Graphviz `cluster_*` subgraph and reads its bounding box back (flipped to top-left origin), and `graph.py::render_graph_svg` paints each group as a labelled background rectangle in the bottom layer (members always paint on top). A `cluster` fallback block was added to the engine theme defaults. This is reusable by any future grouped general-graph module.
  - New `svgengine/painters/componentdiagram.py` maps architecture layers into cluster groups (one per populated layer, colored from a cycled pastel palette) and components into uniformly-colored cards whose **shape varies by type** (frontend/service/cache/queue/cli → card, database/storage → chamfer, external_service → pill) — matching the Graphviz path, where layer background color (not node color) conveys grouping. Typed connections (sync / async / event / bidirectional) map to solid / dashed / dashed / solid edges.
  - 5 `sv_*` presets (`sv_default/dark/security/corporate/minimal`) added to `config_componentdiagram.tml`; a `componentdiagram` theme block (component/connection colors, layer palette, oracle spacing) added to the engine defaults.
  - Emitted SVG carries the interactivity contract (`data-node-id`, `data-kind`, `data-layer`, `usv-node--<type>`, `usv-edge--<style>`, plus `usv-cluster` groups with `data-cluster-id` / `data-label`) with no active content; PNG/PDF via cairosvg.
  - Wired through the CLI (`-m 7 --render-engine svg`), the REST API (`render_engine` on `POST /visualize/component-diagram`, `sv_*` values on `ComponentDiagramStyle`), and the frontend `ArchitecturePanel.vue` — which now carries an engine toggle for **both** the Component Diagram and Dependency Graph (mode 8) sub-views, with SVG-engine output inlined via `InteractiveSvg`; `api.js` threads `render_engine` through both architecture visualize paths.
  - 23 tests in `tests/test_svg_componentdiagram.py` (contract, all templates, layer→cluster counts + labels, node-type and connection-style semantics, engine-mismatch guards, cairosvg raster, CLI end-to-end). Render tests are gated on the `dot` binary; verified in the container (all pass, no regression in the m3/m8/engine SVG suites — 125 total across the four SVG general-graph suites) and via the live REST API. Frontend builds clean.
- **SVG engine support for the Dependency Graph (mode 8) — the second general-graph painter** — the SVG rendering engine (`--render-engine svg` / `render_engine="svg"`) now paints module dependency graphs natively, reusing the Phase 3 general-graph path opened by Attack Graphs (see `devnotes/SVG_ENGINE_PHASE3.md`).
  - New `svgengine/painters/dependencygraph.py` maps module data into a styled scene and delegates layout to the `GraphvizJsonLayout` oracle and painting to the shared `graph.py::render_graph_svg` — so it required **no new engine infrastructure**, only a data-to-scene mapping. Internal modules are colored by group (a group's color is its category), external dependencies get a muted card, node size scales with SLOC, dependency-edge width reflects the declared weight, framework/runtime edges are dashed, and circular-dependency edges are drawn bold + red with a `⚠ circular` label — mirroring the Graphviz path's semantics. External modules are recognized from both `type = "external"` and an explicit `external = true` boolean (the Graphviz path only honored the former, so the example template's external deps now render correctly under the SVG engine).
  - 5 `sv_*` presets (`sv_default/dark/security/corporate/minimal`) added to `config_dependencygraph.tml`; a `dependencygraph` theme block (per-group fills, external/circular styling, oracle spacing) added to the engine defaults. Group colors live in the engine defaults and are inherited by every preset.
  - Emitted SVG carries the interactivity contract (`data-node-id`, `data-kind`, `usv-node--module` / `usv-node--external`, `usv-edge--dependency` / `usv-edge--circular`, `data-group` / `data-sloc`) with no active content; PNG/PDF via cairosvg.
  - Wired through the CLI (`-m 8 --render-engine svg`) and the REST API (`render_engine` on `POST /visualize/dependency-graph`, `sv_*` values on `DependencyGraphStyle`). The frontend engine toggle is deferred to the Component Diagram (mode 7) SVG work, since both diagram types share `ArchitecturePanel.vue`.
  - 23 tests in `tests/test_svg_dependencygraph.py` (contract, all templates, group/external/circular/SLOC semantics, engine-mismatch guards, cairosvg raster, CLI end-to-end). Render tests are gated on the `dot` binary; verified in the container (all 23 pass, no regression in the existing SVG suites) and via the live REST API.
- **SVG engine support for Attack Graphs (mode 3) — the first general-graph painter** — the SVG rendering engine (`--render-engine svg` / `render_engine="svg"`) now paints attack graphs natively, opening SVG Engine Phase 3 (general graphs; see `devnotes/SVG_ENGINE_PHASE3.md`).
  - New `svgengine/layout.py::GraphvizJsonLayout` uses Graphviz purely as an invisible **layout oracle**: it builds a minimal DOT document from the scene (node IDs + our own text-metric sizes + the edge list), pipes it through `graphviz.pipe("dot", "json0", …)`, and reads back node centers and edge B-spline control points — Graphviz computes geometry, we paint the SVG. Sizes are fed in inches (`pixels / 72`, `fixedsize=true`) so one returned point maps 1:1 to one engine pixel; coordinates are converted from Graphviz's bottom-left origin to the engine's top-left convention. This path **requires the system `dot` binary** (unlike the native-layout painters); the networkx spring fallback is deferred.
  - New shared `svgengine/painters/graph.py::render_graph_svg` paints any fully-styled general-graph `Scene` (edges as Bézier paths through the oracle's control points, with a straight border-to-border fallback), so future general-graph modules (Dependency Graph, Component Diagram, DFD, MAESTRO agent graph) reuse it. Adds a `spline_path_d` primitive to `shapes.py` and a `width` field to `SceneEdge`.
  - New `svgengine/painters/attackgraphs.py` maps attack-graph data into a styled scene: typed nodes (host / vulnerability / privilege / service / exploit, each with a distinct card/pill/chamfer shape and theme color) and typed edges (network / exploit / structural host-to-vuln). Vulnerability nodes recolor by CVSS severity (reusing the module's own CVSS helpers) and carry a CVSS badge, mirroring the Graphviz path's semantics.
  - 5 `sv_*` presets (`sv_default/dark/security/corporate/minimal`) added to `config_attackgraphs.tml`; an `attackgraph` theme block (per-kind fills, edge-kind colors, oracle spacing) added to the engine defaults.
  - Emitted SVG carries the full interactivity contract (`data-node-id`, `data-kind`, `usv-node--<kind>`, `usv-edge--<kind>`, `usv-sev--*`, per-vuln CVSS badge) with no active content; PNG/PDF via cairosvg.
  - Wired through the CLI (`-m 3 --render-engine svg`), the REST API (`render_engine` on `POST /visualize/attack-graph`, `sv_*` values on `AttackGraphStyle`), and the frontend `AttackGraphPanel.vue` (engine toggle + inlined `InteractiveSvg` display path).
  - 31 tests in `tests/test_svg_attackgraphs.py` (contract, all templates, node/edge-kind and severity semantics, CVSS badges, engine-mismatch guards, cairosvg raster, CLI end-to-end). Render tests are gated on the `dot` binary; verified in the container (all 31 pass) and via the live REST API + CLI.
- **SVG engine support for the Incident Timeline (mode 10), all four render modes** — the SVG rendering engine (`--render-engine svg` / `render_engine="svg"`) now paints incident timelines natively, completing SVG Engine Phase 2 across every Tier-1 module (see `devnotes/SVG_ENGINE_DESIGN.md`, T2.3).
  - New `svgengine/painters/timeline.py` reimplements all four Matplotlib modes as native SVG: `swimlane` (lanes × time axis with duration bars), `gantt` (one bar per event), `vertical` (center-line with alternating annotations), and `compact` (single strip). Events are placed by scaling timestamps onto a pixel axis (pure `timedelta` math — no Matplotlib, no Graphviz), response `[[phases]]` shade the background, and labels are greedily staggered into tiers to avoid overlap. Severity marker colors come from the module (fixed), so SVG output stays color-consistent with the Matplotlib engine.
  - Adds `dot` / `band` / `anchored_text` primitives to the engine's `shapes` module and a `timeline` block to the engine theme defaults (lane/phase/axis colors).
  - 5 `sv_*` presets (`sv_default/dark/print/corporate/minimal`) in `config_timeline.tml`.
  - Emitted SVG carries the interactivity contract (`data-node-id`, `data-severity`, `data-timestamp`, `usv-sev--*` classes, `usv-phase` bands, severity legend) with no active content; PNG/PDF via cairosvg.
  - Wired through the CLI (`-m 10 --render-engine svg -v <mode>`), the REST API (`render_engine` on `POST /visualize/timeline`, `sv_*` values on `TimelineStyle`), and the frontend `TimelinePanel.vue` (engine toggle + inlined `InteractiveSvg` for the SVG engine; Matplotlib output stays an `<img>`).
  - 39 tests in `tests/test_svg_timeline.py` (contract, all templates × 4 modes, severity/phase semantics, empty-timeline fallback, engine-mismatch guards, cairosvg raster per mode, CLI end-to-end per mode).
- **SVG engine support for the Vulnerability Dependency Tree (mode 11)** — the SVG rendering engine (`--render-engine svg` / `render_engine="svg"`) now paints supply-chain trees natively, joining Attack Trees (mode 0) and Kill Chain (mode 9). Continues SVG Engine Phase 2 (see `devnotes/SVG_ENGINE_DESIGN.md`, T2.4).
  - New `svgengine/painters/vulntree.py` builds the scene on the engine's `TidyTreeLayout` (Reingold–Tilford), so the tree renders without the system Graphviz binary. Node fill is driven by each package's highest CVE severity, direct dependencies get a bolder border, and an edge into a known-exploited package is drawn bold and dark — mirroring the Graphviz path's semantics. All three render modes (`tree` / `vulnerable_only` / `critical_path`) are honoured through the module's own `_visible_nodes()`, and multi-root supply chains lay out under a hidden synthetic root.
  - 5 `sv_*` presets (`sv_default/dark/security/corporate/minimal`) added to `config_vulntree.tml`; a `vulntree` theme block (direct-border + exploited-edge styling) added to the engine defaults.
  - Emitted SVG carries the full interactivity contract (`data-node-id`, `usv-sev--*` / `usv-node--direct` / `usv-edge--exploited` classes, per-package CVSS badge) with no active content; PNG/PDF via cairosvg.
  - Wired through the CLI (`-m 11 --render-engine svg`), the REST API (`render_engine` on `POST /visualize/vuln-tree`, `sv_*` values on `VulnTreeStyle`), and the frontend `VulnTreePanel.vue` (engine toggle + inlined `InteractiveSvg` display path).
  - 30 tests in `tests/test_svg_vulntree.py` (contract, all templates × modes, exploited/direct semantics, engine-mismatch guards, cairosvg raster, CLI end-to-end).

### Security

- **Graph-complexity limit enforced on the SVG general-graph path** — the SVG engine bypasses `_render_impl`, so the Graphviz path's `utils.check_graph_complexity` DoS guard did not apply to it. The check now runs in the shared `render_graph_svg` before the Graphviz layout oracle is invoked, bounding every general-graph painter the same way as the Graphviz path and the attack-tree SVG painter.

### Changed

- **matplotlib pinned to 3.10.8** (was `>=3.7.0`) so text metrics — and therefore SVG-engine layout and golden-file bytes — are identical across the Python 3.10–3.13 CI matrix and dev machines; the attack-tree SVG golden was regenerated against the pinned version.
- Frontend main content now widens to fill the viewport (capped at 2200px) instead of a fixed narrow column, and the footer copyright reads 2025-2026 (release year through current year).

### Added

- **Kill Chain / MITRE ATT&CK visualization (CLI mode 9)** — first-class module for mapping attack progression through a standardized framework
  - Frameworks: Lockheed Martin Cyber Kill Chain (7 phases), MITRE ATT&CK Enterprise (14 tactics), and custom phase axes declared in the input file
  - Techniques carry `detected` / `mitigated` coverage flags that drive detection-gap heat coloring (green = both, amber = one, red = neither) and a per-card D/M coverage chip, plus `analyze_coverage_gaps()` for undetected/unmitigated/critical-gap lists
  - Incidents declare ordered technique paths, drawn as cross-column connectors
  - SVG-native swimlane render on the engine's `LinearLayout` (phase-column headers + stacked technique cards + phase-progression flow arrow), selectable with `--render-engine svg` and the `sv_*` presets; Graphviz path renders ranked phase clusters (`kc_default`, `kc_light`, `kc_coverage`)
  - `KillChain` core class, `KillChainBuilder` fluent API, `config_killchain.tml` styles, 3 templates in `templates/kill-chains/`, and API endpoints `POST /visualize|/analyze|/validate/kill-chain`
  - 33 tests in `tests/test_killchain.py` + `tests/test_api_killchain.py`
- **Incident Timeline visualization (CLI mode 10)** — first-class module rendering the chronology of a security incident for IR workflows
  - Matplotlib-based with four render modes selectable via `-v` (CLI) / `mode=` (API): `swimlane` (default, lanes by asset/actor with a label de-collision packer), `gantt` (one duration bar per event), `vertical` (top-down with alternating annotations), and `compact` (single strip)
  - Events carry `severity` (drives marker/bar coloring), an optional `duration`, an optional ATT&CK `technique` tag, and a `lane`; response `[[phases]]` (Detection → Containment → Eradication → Recovery) shade the background and drive MTTD/MTTC/MTTR response metrics
  - `analyze` reports severity distribution, per-lane counts, time span, tagged-event count and response metrics; `IncidentTimeline` core class, `TimelineBuilder` fluent API, `config_timeline.tml` (6 presets: `tl_default/light/dark/print/minimal/corporate`), 3 templates in `templates/timelines/`, and API endpoints `POST /visualize|/analyze|/validate/timeline`
  - `TimelinePanel.vue` frontend tab, and 54 tests in `tests/test_timeline.py` + `tests/test_api_timeline.py`
- **Vulnerability Dependency Tree visualization (CLI mode 11)** — first-class module for software supply-chain / SCA analysis
  - Graphviz-based top-down tree with three render modes selectable via `-v` (CLI) / `mode=` (API): `tree` (default, full dependency tree), `vulnerable_only` (prune to packages that are vulnerable or lead to one), and `critical_path` (prune to paths reaching a critical/high CVE)
  - Node fill is driven by each package's highest CVE severity (critical = purple, high = red, medium = orange, low = yellow, none = green); direct dependencies get a bolder border and known-exploited CVEs draw a bold edge into the affected package
  - `analyze` reports direct/transitive counts, vulnerable/exploited counts, severity distribution, max CVSS, impact propagation (which root packages are exposed by a transitive CVE) and remediation availability (CVEs with a known fixed version); cycle-safe traversal with root inference when `root_packages` is omitted
  - `VulnDependencyTree` core class, `VulnTreeBuilder` fluent API, `config_vulntree.tml` (5 presets: `vt_default/dark/security/corporate/minimal`), 3 templates in `templates/vuln-trees/`, and API endpoints `POST /visualize|/analyze|/validate/vuln-tree`
  - `VulnTreePanel.vue` frontend tab, and 42 tests in `tests/test_vulntree.py` + `tests/test_api_vulntree.py`

### Changed

- **SVG engine (Attack Trees) layout and routing polish**, driven by a Graphviz-vs-SVG comparison across templates:
  - Per-sink collector rails: parents sharing a sink now feed one collector rail with a single arrowhead instead of stacked private rails
  - Symmetric barycenter collision resolution (weighted pool-adjacent-violators) so convergence sinks sit centered under their parents instead of shoved to the margin
  - Single-child chains render straight (parents centered over children's final positions); rail end-caps meet the parent trunk instead of dangling
  - Edge `label=` values (e.g. AND/OR, likelihood) now render as halo text on the connectors
  - `gate="AND|OR"` node chips, adaptive inter-row spacing (7–22% shorter output), chamfered card variant for octagon-family goal nodes, and font-size-scaled card padding so bold titles keep their margins

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
