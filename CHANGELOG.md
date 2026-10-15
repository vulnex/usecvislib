# Changelog

All notable changes to USecVisLib will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.0] - 2026-10-06

### Added

- **Keep chosen components visible in collapsed Privilege-Gradient groups** (Atajo request A12). `keep = "inversions"` (every inversion endpoint) and/or `keep_ids = [...]` keep members drawn by name next to their collapsed group's card, inside a dashed frame labelled with the group; their influences stay on them. The card counts the folded members only and says how many are shown separately. `"auto"` counts kept members; `true` / `"auto"` leave a group with at most one foldable member expanded. In the drift view, `keep = "inversions"` also keeps the endpoints of new, fixed and changed inversions. SVG `data-kept`, `data-kept-count`. Also render options, `set_grouping(keep=, keep_ids=)`, CLI `--keep` / `--keep-ids`, API query parameters on `POST /visualize/privilege-gradient` and `/diff/render`, and `render_diff(keep=, keep_ids=)`. The template `ad_tiers_grouped.tml` keeps WS-0103.

- **Privilege-Gradient grouping and collapse** (Atajo request A11). Opt-in with `gradient.group_by` (a component field such as `role`) or a component's own `group`; a group never spans zones (ids `<zone>/<value>`). Expanded groups are dashed clusters inside their zone; collapsed ones (`collapse = true`, a list of groups, or `"auto"` with `max_nodes`, default 300) become one summary component with the member count and the inversions its members take part in, with the worst severity. Influences inside a collapsed group are dropped (never inversions: a zone has one trust level), the rest point at the summary and merge as `×N`; inversions on merged edges are exact. A graph size limit (10,000 / 50,000) now applies to what is drawn (the module had none). Both engines; SVG `usv-node--group` with `data-collapsed`, `data-member-count`, `data-inversion-count`, `data-max-severity`, nested `usv-cluster` groups, `data-edge-count`. Also `PrivilegeGradient(group_by=, collapse=, max_nodes=)`, `[groups]` settings, `get_stats()["groups"]`, `PrivilegeGradientBuilder.set_grouping()` / `add_group()`, CLI `--group-by` / `--collapse` / `--max-nodes` with `-m 6`, the same query parameters on `POST /visualize/privilege-gradient` (and `group_by` on `/analyze/privilege-gradient`), and the template `privilege-gradient/ad_tiers_grouped.tml`. `render_diff(..., "privilege_gradient", group_by=, collapse=)` groups the merged gradient: a collapsed group shows its members' changes (`+N −N ~N`), and a merged inversion edge counts its new / fixed / changed members (`! INVERSION ! (2 new, 1 fixed) · ×12`, SVG `data-inversion="mixed"` and `data-inversion-new` / `-fixed` / `-changed`); `metadata["inversions"]` stays per influence. Shared with A6: `grouping.py` (collapse choice, merged-edge status, `×N`). A component's `group` (and the active `group_by` field) no longer reaches the Graphviz output.

- **Drift picture for the Privilege Gradient** (Atajo request A9). `render_diff(old, new, "privilege_gradient")` draws zones, components and influences added / removed / modified, as for attack graphs (zones get the change border and sign; a component moved to another zone is modified and drawn in its new zone). Influences are matched by `(from, to, type)`. Inversions (tiering violations) are detected in each version: new ones are labelled `NEW INVERSION`, fixed ones `FIXED INVERSION` in the removed color, and both are listed in `result.metadata["inversions"]`. Inversions present in both versions with another severity or trust gap (Atajo A10) are listed as `changed` with their old and new values, drawn in the modified color as `~ INVERSION (high → critical)`, and marked `data-inversion="changed"` with `data-old-severity` / `data-old-trust-gap`. Both engines; SVG adds `usv-diff--*` / `data-diff` on zones, components and influences and `data-inversion="new|fixed|changed|unchanged"`. Also the CLI (`-m 6 -i NEW --diff OLD`, which prints the new / fixed / changed inversions) and `POST /diff/render` (auto-detected; the inversions in an `X-Diff-Inversions` header). Engine additions: cluster drift marks, the modified edge color, per-edge label colors; `detect_inversions()` is now a module function.

- **SVG engine for the Privilege Gradient (mode 6)**, the last graph module without one. Trust zones are clusters ordered left to right by trust level, components are cards in their zone's color, influences are styled by type (data solid, feedback dashed, resource dotted, control thick), inversions are red with their severity (`!!! INVERSION !!!`), and a legend shows each influence's line style. Five `sv_*` presets (`sv_dark` moves the zone colors into the borders, like `pg_dark`). SVG output carries `data-zone` / `data-trust-level` on zones and components, and `data-type`, `data-inversion`, `data-severity`, `data-trust-gap` on influences. Available as `render_engine="svg"` in the library, `--render-engine svg` with `-m 6`, `render_engine` on `POST /visualize/privilege-gradient`, an engine selector in the web UI, and the gallery. Engine additions used for it: layout-only (invisible, weighted) nodes and edges, custom edge dash patterns, configurable layout spacing, and line swatches in the legend.

- **Trend chart: metrics over time** (Atajo request A1). `TrendChart` draws small multiples, one panel per metric on a shared time axis, from series of `{t, value}` points (or tidy `t, metric, value` rows): line, area, step or bar series, series sharing a `panel`, stacked panels (e.g. vulnerabilities by severity in the severity colors), the latest value labelled, and per-series statistics (first / last / min / max / change). Matplotlib, PNG / SVG / PDF, six `tr_*` presets, byte-reproducible output (fixed SVG ids, no creation date in SVG / PDF). `TrendBuilder` builds one in code. Library only (no CLI mode or API endpoint, as requested). Template `trends/engagement_metrics.toml`.

- **Drift picture: `render_diff()`** (Atajo request A5). Draws what changed between two attack-graph versions as one image and returns the `DiffResult`. Both versions are merged so removed elements still appear; each element is added (pink-red border, `+` chip), removed (faded 35%, dashed, `−`), modified (violet border, `~`, `data-changed` lists the fields) or unchanged, with fills keeping their CVSS colors and a legend. `diff_colors` overrides any color (validated hex); `show_unchanged=False` keeps only changes and their neighbours; grouping/collapse apply to the merged graph, and collapsed groups count changed members (`+2 ~1`). Edges and exploit conditions compare as sets, and the returned diff is computed on the same normalized data as the picture. Both engines; SVG adds `usv-diff--*` / `data-diff`. Also the CLI (`-i NEW --diff OLD`, `--changes-only`, `--diff-colors`) and `POST /diff/render` (image, with the summary in an `X-Diff-Summary` header exposed to browsers). Privilege gradients were added later (A9, above).

- **Inferred (hypothesis) elements are drawn distinctly** (Atajo request A4), so a proposed step or mapping is never read as an observed fact. Mark with `inferred = true` or `confidence = "hypothesis"`: attack-graph exploits (node and pre/postcondition edges) and network edges, kill-chain techniques, and timeline technique tags (`technique_inferred` / `technique_confidence`). Attack graph: muted fill, dashed outline and an "(inferred)" line; inferred edges dashed in muted violet (hollow arrowhead in Graphviz); a collapse-merged edge is inferred only if all merged edges were. Kill chain: coverage color kept but faded and dashed, with an "(inferred)" line. Timeline: the tag reads `T1059 (inferred)`. Both engines; SVG adds `usv-node--inferred` / `usv-edge--inferred` and `data-inferred` / `data-confidence`. Stats: `inferred_techniques`, `inferred_tags`. The ATLAS template marks one technique as a hypothesis.

- **Attack-graph grouping and collapse** (Atajo request A6). Opt-in with `graph.group_by` (a host field such as `zone`, or `ip/N` / `ip6/N` to group by network) or a host's own `group`; vulnerabilities, services and privileges follow their host, and exploits whose endpoints all share a group join it. Expanded groups are drawn as clusters; collapsed ones (`collapse = true`, a list of groups, or `"auto"`, which collapses the largest groups until at most `max_nodes` nodes, default 300, are drawn) become one summary node with member counts and the worst CVSS. Edges inside a collapsed group are dropped, the rest point at the summary node, and duplicates merge with an `×N` label. The size limit now applies to what is drawn, so large scans collapsed by subnet render. Both engines; SVG output carries `usv-cluster` / `usv-node--group` with `data-collapsed`, counts and `data-edge-count`. Also `--group-by` / `--collapse` / `--max-nodes` (CLI), `group_by` / `collapse` / `max_nodes` (`POST /visualize/attack-graph`, and `group_by` on `/analyze/attack-graph`), `AttackGraphBuilder.set_grouping()` / `add_group()`, per-group `groups` statistics, and the template `attack-graphs/segmented_enterprise.toml`. Analysis always uses the full graph.

- **`compare_series()`: diff an ordered series of versions** (Atajo request A2). Takes the files in order (e.g. engagement snapshots, oldest first) and returns a `SeriesDiffResult`: one `DiffResult` per consecutive pair plus the net first -> last change, with `summary` and `to_dict()`. Each file is loaded once; `ignore_paths` applies to every comparison. Works for every module `compare_files()` supports.
- **MITRE ATLAS axis for the Kill Chain** (Atajo request A8). `framework = "atlas"` (or `mitre_atlas`) lays techniques out on the 16 ATLAS tactics in matrix order (ATLAS 5.6.0, including AI Model Access and AI Attack Staging). A technique's phase may be a tactic name, a tactic ID (`AML.TA0004`), or a pre-rename "ML ..." name; technique IDs such as `AML.T0051.001` are shown as given. New template `kill-chains/atlas_agent_prompt_injection.tml`; the UI's framework stat reads "ATLAS".
- **"Confirmed by N sources" marker on attack-graph nodes** (Atajo request A7). A host, vulnerability, privilege, service or exploit can list `sources = [...]` and/or `source_count = N`. With 2 or more, the SVG engine draws a "✓N" chip on the card's top-left corner and the Graphviz engine adds a "✓ N sources" label line; SVG nodes carry `data-source-count` / `data-sources`. The chip lives in the shared graph painter (`SceneNode.sources`), so other graph modules can adopt it; themes can hide it with `badges.sources = false`.

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
- **Render gallery** at https://vulnex.github.io/usecvislib-gallery/ (repository [vulnex/usecvislib-gallery](https://github.com/vulnex/usecvislib-gallery)): every bundled template rendered with every engine, view and style preset, in PNG, SVG, PDF and DOT. The README and the CLI, template, custom-diagram, MAESTRO and Python API guides link to it.
- `scripts/build_gallery.py` regenerates the gallery inside the API Docker image. It fails if any render errors or if an output contains a home-directory path or an e-mail address.
- **Byte-pair digraph chart for binary analysis** (`-v digraph`, `visualize_digraph()`, `visualization_type=digraph`): a 256x256 plot of how often byte B follows byte A, on a log scale, with guides at the printable ASCII range. Code, text, UTF-16, compressed and encrypted data each leave a distinct pattern. All 12 `bv_*` presets apply (a preset without a `digraph` section uses its heatmap colors), and `all` now produces five charts. `byte_pair_counts()` returns the underlying counts. Requested by the BytesRevealer integration.
- `BinVis(display_name=...)` sets the name in chart titles; `""` gives titles without a name.

### Security

- **Graph-complexity limit enforced on the SVG general-graph path** — the SVG engine bypasses `_render_impl`, so the Graphviz path's `utils.check_graph_complexity` DoS guard did not apply to it. The check now runs in the shared `render_graph_svg` before the Graphviz layout oracle is invoked, bounding every general-graph painter the same way as the Graphviz path and the attack-tree SVG painter.

### Changed

- **matplotlib pinned to 3.10.8** (was `>=3.7.0`) so text metrics — and therefore SVG-engine layout and golden-file bytes — are identical across the Python 3.10–3.13 CI matrix and dev machines; the attack-tree SVG golden was regenerated against the pinned version.
- Frontend main content now widens to fill the viewport (capped at 2200px) instead of a fixed narrow column, and the footer copyright reads 2025-2026 (release year through current year).

### Fixed

- **SVG output with icons is self-contained.** Graphviz SVGs (every Graphviz module) and cloud-diagram SVGs linked node icons by absolute file path: temp thumbnails deleted at exit, or the icon's location in `site-packages`. Shared SVGs showed no icons and disclosed local paths, often including the user's home directory. Local images are now embedded as `data:` URIs (`utils.embed_svg_images`, applied by the new `utils.render_graph`). DOT output still references icon files, since Graphviz needs them to render.
- **Vulnerability tree output is reproducible.** Nodes and edges were emitted in set order, which follows Python's per-process string hash seed, so the same input gave different SVG bytes (and potentially a different Graphviz layout) on each run. `_visible_nodes()` now returns dependencies in declaration order.
- **Custom diagrams with force layouts are reproducible.** The `force`, `grid` and `sfdp` layouts (Graphviz `fdp`, `neato`, `sfdp`) started from a random placement, so a diagram such as the network topology template changed size and shape on every render. They now use a fixed seed (`start=1`).
- **Cloud diagrams with an empty cluster render.** A cluster without nodes generated an empty `with Cluster(...):` block, so the diagram failed with a Python `IndentationError`. It now renders as an empty cluster and logs a warning.
- **Batch processing covers every file-based module.** `BatchProcessor` / `process_batch()` accepted only `attack_tree`, `attack_graph`, `threat_model` and `binary`; `privilege_gradient`, `component_diagram`, `dependency_graph`, `kill_chain`, `incident_timeline`, `vuln_tree` and `maestro` raised "Unknown module type". They now build through the shared `build()` path.
- **Binary charts are much faster on large files.** Sliding-window entropy built a `Counter` per window, and the byte distribution and wind rose counted byte by byte in Python. They are now vectorised with NumPy: on a 50 MB file all five charts take about 13 s instead of about 85 s (entropy 64 s to 9 s, wind rose 11 s to 0.4 s), and results are unchanged.
- **The wind rose is described as what it draws**, a polar histogram of byte values (one direction per value), not "byte pair patterns"; its title is now "Byte Value Wind Rose". The new digraph chart is the byte-pair view.
- **`POST /visualize/binary` with `visualization_type=all` returns every chart.** It rendered all charts but returned only the entropy image. It now returns JSON, `{"charts": [{"type", "content_type", "filename", "data"}]}` with base64 data, so one upload and one rate-limit hit give all five charts.
- **Partial binary `config_json` no longer resets other fields.** The API merged whole Pydantic models, so sending one field wrote every other field's schema default over the library's defaults (e.g. any `wind_rose` setting moved the radial labels from 22.5 to 0 degrees). Only the fields a client sends are applied now, and the `rlabel_position` schema default matches the library.
- **Binary chart titles no longer show the server's temp file name** (`upload_<hex>.bin`). The new optional `title` form field sets the name; without it the titles carry none.
- **Binary charts render when the API runs on macOS.** `binvis.py` used Matplotlib's default backend, and on macOS that GUI backend refuses to create figures on the worker threads the API renders on, so every binary chart returned 500. It now selects the non-interactive `Agg` backend like the timeline and MAESTRO modules. Linux (and the container) already defaulted to `Agg`.
- **API endpoints return the right status for bad uploads and timeouts.** Most routers caught every exception in a generic `except Exception`, so an unsupported file extension (400), an oversized upload (413) and a render timeout (504) all came back as 500; malformed config also gave 500 on several analyze/validate endpoints and on cloud/mermaid analyze and export. The routers now share one request helper (`TempFiles` + `handle_errors` in `api/helpers.py`) that passes those through, maps library errors to 400 and everything else to a generic 500. It also removes the request's temp files on every path: the resolved-image copy and partial outputs leaked on some error paths, a timed-out render's late output was never removed, and a failed batch left its output directory behind. Batch items that fail with an unexpected error now report "Processing failed" instead of the raw exception text.
- **Oversized requests are rejected while they stream in.** There was no limit on a request body: Starlette spools a multipart upload to disk in full before the endpoint runs, so the per-endpoint size checks came after any amount of disk had been used, and `save_upload_file` then read the whole upload into memory. A new `RequestSizeLimitMiddleware` answers 413 for a `Content-Length` over `MAX_REQUEST_BODY_SIZE` (default 51 MB: the 50 MB binary limit plus framing; set it with the environment variable of that name) and stops reading a chunked body once it passes the limit. Uploads are copied to disk in 1 MB chunks and stop at the per-file limit, and image uploads read at most one byte past theirs.
- **Icon thumbnails no longer pile up in the temp directory.** A large icon (over 64 px) was resized into a new randomly named temp file on every render, deleted only when the process exited, so the long-running API server accumulated files (and an ever-growing list) until restart. Thumbnails now go into the shared icon cache (`usecvislib_icon_cache`, symlink-safe), named by the icon's path, size and modification time, written atomically and reused across renders; the cache grows with the number of distinct icons, not with renders. Renders with icons are now also deterministic.
- **API batch, export and compare cover every file-based module, and batch takes binaries.** `0.6.0` taught the library's `BatchProcessor` and `compare_files()` every module, but the API endpoints kept their own dispatch: `/batch/visualize` handled four modes, `/export/data` and `/diff/compare` three. All three now use the library's module registry, so privilege gradient, component diagram, dependency graph, kill chain, incident timeline, vulnerability tree and MAESTRO work too; `VisualizationMode` gains `kill_chain`, `incident_timeline`, `vuln_tree` and `maestro`. Export and compare auto-detect every module (the UI's Export and Compare panels send no mode), and `/export/sections` lists each module's sections. `/batch/visualize?mode=binary` (BytesRevealer B7) renders one chart per file, chosen with `visualization_type` (default `entropy`); the Batch panel offered Binary Analysis already but always got a 400. The panel now lists every module, with a chart picker for binaries, and `/styles` adds the component diagram, dependency graph and MAESTRO presets.
- **CORS** allows `DELETE` (for `DELETE /images/{id}`) and exposes `Content-Disposition` and `Retry-After` to browser clients.
- **429 responses carry `Retry-After`** with the seconds until the rate-limit window resets.
- **Reports list only files they wrote.** `ReportGenerator.generate_report()` listed a CSV per config section, but no visualization class provides `export_csv`, so none of those CSVs were written. Tabular sections (lists of objects, or objects keyed by ID) are now written directly, and only files that exist are returned.
- **`compare_files()` covers every file-based module.** It accepted only `attack_tree`, `attack_graph` and `threat_model`, although the diff itself works on any loaded config; it now accepts the same module types as batch processing (except `binary`).

## [0.5.0] - 2026-08-27

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
