# MAESTRO Agentic Threat Modeling Guide

Practical guide to modeling, visualizing, and analyzing agentic AI systems with USecVisLib's MAESTRO module.

---

## Table of Contents

- [What is MAESTRO?](#what-is-maestro)
- [Quick Start](#quick-start)
- [The Seven Layers](#the-seven-layers)
- [Configuration Reference](#configuration-reference)
- [Authoring Tips for Clean Visualizations](#authoring-tips-for-clean-visualizations)
- [Render Views](#render-views)
- [Style Presets](#style-presets)
- [Reading the Visualization](#reading-the-visualization)
- [Threat Catalog](#threat-catalog)
- [Cross-Reference Exports](#cross-reference-exports)
- [API Endpoints](#api-endpoints)
- [Troubleshooting](#troubleshooting)
- [Example Templates](#example-templates)

---

## What is MAESTRO?

**MAESTRO** (Multi-Agent Environment, Security, Threat, Risk, & Outcome) is a threat modeling framework published by the Cloud Security Alliance in February 2025. It's purpose-built for **agentic AI systems** and addresses gaps that STRIDE, PASTA, and LINDDUN don't cover: adversarial machine learning, model extraction, agent autonomy, and cross-layer attack chains.

USecVisLib implements MAESTRO as **CLI mode 12**, alongside the existing STRIDE/PyTM threat modeling module. Use MAESTRO when:

- Your system contains LLM-backed agents, multi-agent orchestration, or autonomous decision-making
- Adversarial ML, prompt injection, or model extraction are real risks
- You need to reason about attack chains that span the AI stack (from foundation models to the agent ecosystem)
- Classical DFD/STRIDE models don't capture autonomy properties

Use the existing **Threat Modeling** module (mode 1) for classical applications where STRIDE is sufficient. The two can be combined: a MAESTRO model can be exported to STRIDE shape with `to_stride()` for hybrid coverage.

**Framework reference:** [Cloud Security Alliance — Agentic AI Threat Modeling Framework: MAESTRO](https://cloudsecurityalliance.org/blog/2025/02/06/agentic-ai-threat-modeling-framework-maestro)

---

## Quick Start

### CLI

```bash
# Render the default layered view
usecvis -i templates/maestro/single-agent-rag.toml -o my_model -m 12

# Render the agent-centric graph (clusters by primary layer, chains as edges)
usecvis -i templates/maestro/financial-trading-chain.toml -o my_model -m 12 -v graph

# Render the severity heatmap
usecvis -i templates/maestro/multi-agent-support.toml -o my_model -m 12 -v heatmap

# Pick a style preset
usecvis -i templates/maestro/autonomous-soc-agent.toml -o my_model -m 12 -s ma_dark
```

### Python API

```python
from usecvislib import MaestroThreatModel

# Layered architecture view (default)
m = MaestroThreatModel("model.toml", "output", format="png")
m.build()

# Heatmap view
m = MaestroThreatModel("model.toml", "output", format="png", view="heatmap")
m.build()

# Stats and validation
print(m.get_stats())          # counts by layer / severity / status
print(m.validate())           # validation errors (empty list = ok)
print(m.warnings)             # auto-populate warnings (pattern x layer mismatches)
```

### REST API

```bash
# Visualize
curl -X POST -H "X-API-Key: $KEY" \
  -F "file=@model.toml" \
  "http://localhost:8003/visualize/maestro?format=png&style=ma_default&view=layered"

# Analyze (returns stats JSON)
curl -X POST -H "X-API-Key: $KEY" \
  -F "file=@model.toml" \
  http://localhost:8003/analyze/maestro

# Filtered threat list
curl -X POST -H "X-API-Key: $KEY" \
  -F "file=@model.toml" \
  "http://localhost:8003/analyze/maestro/threats?severity=critical"
```

See the [API Endpoints](#api-endpoints) section for the full surface.

---

## The Seven Layers

| # | Layer | Scope | Example Threats |
|---|---|---|---|
| L1 | Foundation Models | LLMs, base models | adversarial examples, model extraction, training data poisoning, backdoor attacks |
| L2 | Data Operations | RAG, vector stores, training corpora | data exfiltration, RAG pipeline compromise, data tampering |
| L3 | Agent Frameworks | LangChain, AutoGen, custom orchestrators | compromised dependencies, framework evasion, code injection |
| L4 | Infrastructure | Containers, K8s, IaC | compromised images, orchestration attacks, lateral movement, resource hijacking |
| L5 | Observability | Eval, monitoring, logs | log leakage, evasion of detection, observability poisoning |
| L6 | Security | Cross-cutting / vertical | security-agent poisoning, evasion of security AI, bias |
| L7 | Agent Ecosystem | Marketplace, agent-to-agent, users | impersonation, identity attacks, tool misuse, goal manipulation |

L6 Security is conceptually a **vertical layer cutting across all others** — it represents AI used as a security tool, with its own attack surface. The visualization renders it as a regular band with a distinct fill colour and an inline mitigation summary; treat its contents as cross-cutting concerns rather than a separate stage.

---

## Configuration Reference

MAESTRO configs are TOML, JSON, or YAML. The TOML form is shown throughout this guide; the structure is identical across formats.

### Minimal example

```toml
[meta]
name = "My Agent System"

[architecture]
patterns = ["single-agent", "task-oriented"]

[[agents]]
id = "support"
name = "Support Agent"
type = "task-oriented"
autonomy = "reactive"
layers = ["foundation-models", "data-operations", "agent-frameworks", "agent-ecosystem"]
```

That's enough to produce a usable model. The catalog will auto-populate ~30 threats based on declared layers and patterns.

### Full schema

```toml
[meta]
name = "Customer Support System"           # required
version = "1.0"
owner = "Security Team"
description = "Multi-agent CX with HITL escalation"

[architecture]
patterns = [                                # one or more of:
    "single-agent",                         #   "single-agent"
    "multi-agent",                          #   "multi-agent"
    "hierarchical",                         #   "hierarchical"
    "distributed",                          #   "distributed"
    "human-in-the-loop",                    #   "human-in-the-loop"
    "self-learning",                        #   "self-learning"
    "unconstrained-conversational",         #   "unconstrained-conversational"
    "task-oriented",                        #   "task-oriented"
]

[[agents]]
id = "router"                               # required, unique
name = "Triage Router"
type = "task-oriented"                      # any of the patterns above
autonomy = "reactive"                       # reactive | deliberative | learning | self-modifying
goals = ["classify query", "route to specialist"]
capabilities = ["llm-inference", "intent-classification"]
tools = ["intent-classifier"]
layers = [                                  # required: layers this agent touches
    "foundation-models",
    "agent-frameworks",
    "agent-ecosystem",
]

[[assets]]
id = "customer-pii"
name = "Customer PII"
layer = "data-operations"                   # single layer (assets don't span layers)
sensitivity = "high"                        # low | medium | high | critical
owner_agent = "router"                      # optional cross-reference

# Override catalog-populated threats
[[threats]]
id = "T-L1-007"                             # catalog ID
target = "router"                           # agent id
severity = "critical"                       # override catalog default
status = "in-progress"                      # identified | in-progress | mitigated | accepted | not-applicable
mitigations = ["M-input-sanitization", "M-system-prompt-hardening"]

# Custom cross-layer attack chains
[[cross_layer_threats]]
id = "CL-router-pivot"
name = "Router prompt-injection escalates to data exfil"
layers = ["agent-ecosystem", "data-operations"]
attack_chain = ["T-L7-005", "T-L2-002"]     # threats in order
severity = "critical"
likelihood = "medium"

# Optional: declare additional mitigations
[[mitigations]]
id = "M-mutual-auth"
layer = "agent-ecosystem"
name = "Mutual authentication between agents"
type = "preventive"                         # preventive | detective | responsive | compensating
implemented = false

[catalog]
mode = "auto"                               # auto (default) | full | manual
```

### Architecture patterns and their implied threats

Declaring a pattern attaches **pattern-specific catalog threats** to your model, on top of layer-specific ones.

| Pattern | What it implies |
|---|---|
| `single-agent` | Goal manipulation risk |
| `multi-agent` | Communication channel attacks, identity spoofing, goal misalignment cascades |
| `hierarchical` | Higher-level agent compromise → subordinates affected |
| `distributed` | Sybil attacks, registry compromise, marketplace manipulation |
| `human-in-the-loop` | Feedback manipulation skewing agent learning |
| `self-learning` | Data poisoning with backdoor triggers, model drift |
| `unconstrained-conversational` | Prompt injection / jailbreaking |
| `task-oriented` | DoS via request flooding, computational exhaustion |

If you declare a pattern whose implied threats target a layer that no agent touches, the loader emits a **warning** and does **not** attach those threats. See [Authoring Tips](#authoring-tips-for-clean-visualizations) below.

---

## Authoring Tips for Clean Visualizations

The MAESTRO model is read top-down from the L7 ecosystem layer to L6 security. The renderer infers the visual layout from how your agents touch layers. A few conventions produce cleaner output:

### 1. List an agent's `layers` from the user surface inward

```toml
# Recommended
[[agents]]
id = "support"
layers = ["agent-ecosystem", "agent-frameworks", "foundation-models", "data-operations"]
```

The order doesn't affect threat auto-population, but the renderer uses the **first declared layer** when no spine column is established. Listing user-facing layers first leads to more natural reading order.

### 2. Have at least one agent that spans most layers

The layered render uses the "agent spine" to align bands vertically: if an agent touches both layer N and layer N+1, an invisible link between its per-layer copies pulls the bands into vertical alignment. **The more layers an agent spans, the cleaner the visual stack.**

Models like `templates/maestro/autonomous-soc-agent.toml` produce the cleanest visualizations because the SOC agent spans all 7 layers, providing a continuous spine.

Models like `templates/maestro/single-agent-rag.toml` show a small staircase pattern because the agent only touches 4 of 7 layers; the bands without a shared agent fall back to anchor-based ordering, which is less precise.

This is a Graphviz cluster-layout limitation, not a bug. The content is still correct; bands may drift sideways by 10-50 pixels when content widths vary.

### 3. Declare assets in the layer that owns them

Assets only belong to one layer (`asset.layer = "data-operations"`). Put assets where they live, not where they're accessed from. The renderer places assets alongside agents in their owning layer.

### 4. Use catalog mode deliberately

| Mode | When to use |
|---|---|
| `auto` (default) | Production models. Attaches catalog threats only for layers your agents declare. |
| `full` | Threat enumeration / coverage exercises. Attaches every catalog threat, even on layers with no agents. |
| `manual` | You want to handpick threats. Disables auto-population entirely. |

### 5. Override severities and statuses rather than fork the catalog

The threat catalog is versioned and ships with sensible defaults. To express your environment's specifics, use overrides:

```toml
[[threats]]
id = "T-L2-002"          # Data Exfiltration
target = "support"
severity = "critical"    # bump from catalog default of "critical" — fine
status = "in-progress"   # workflow state
mitigations = ["M-access-control", "M-encryption-at-rest"]
```

Avoid changing IDs or adding bespoke threats for things the catalog already covers — you'll lose the cross-version compatibility guarantee.

### 6. Specify cross-layer chains explicitly when they matter

The cross-layer threat list communicates **how attacks chain across the stack**. These are often the highest-impact scenarios. A model with no `[[cross_layer_threats]]` entries reads as "isolated threats only," which is rarely the realistic case.

```toml
[[cross_layer_threats]]
id = "CL-rag-poison-exfil"
name = "RAG corpus poisoning leads to data exfiltration"
layers = ["data-operations", "agent-ecosystem"]
attack_chain = ["T-L2-001", "T-L2-002"]     # ordered threat IDs
```

The chain steps must reference threats targeting concrete agents (either auto-populated or user-defined). Cross-layer chains must span **at least 2 layers**.

---

## Render Views

### Layered Architecture (default, `view = "layered"`)

Seven horizontal bands stacked top-to-bottom (L7 → L3 → L1 → L2 → L4 → L5 → L6). Each agent appears in **every layer it declares**, with a per-layer severity badge showing the count of open unmitigated threats targeting that agent on that layer. Cross-layer attack chains appear as dashed red edges between the appropriate `(agent, layer)` nodes.

**Best for:** architecture analysis, security review, walkthroughs.

### Agent Graph (`view = "graph"`)

Graphviz-rendered diagram where each agent is a single node, clustered by its **primary layer** (`agent.layers[0]`). Cross-layer attack chains become directed edges between the targeted agents, colored deterministically per chain id so multiple chains stay visually distinguishable. Single-hop cross-layer threats render as dashed gray edges. Default layout is left-to-right (chains read like a causal sequence); switch to top-down via `[render] graph_direction = "TB"`.

Unlike the layered view, only layers that actually have agents get clusters — the canvas stays compact. L6 (Security) renders as a floating note rather than a peer cluster, respecting its cross-cutting role.

The node label shows the agent name, type/autonomy, and a one-line severity breakdown (`C:1 H:3 M:5 L:2`) aggregated across all layers. Agents owning at least one unmitigated critical threat get a red, thicker border.

**Best for:** incident analysis, walking through how a chain propagates, communicating threat narrative to non-architects.

This view is distinct from the `to_attack_graph()` export, which produces a config dict consumed by the separate `AttackGraphs` module — same source data, different audiences.

Optional render config:

```toml
[render]
view = "graph"
graph_direction = "LR"     # or "TB"
chain_labels = "first"     # "all" | "first" | "off" — first hop label by default
clustering = "auto"        # same semantics as layered view
cluster_threshold = 8      # auto-subcluster by type when a layer is crowded
```

### Severity Heatmap (`view = "heatmap"`)

Matplotlib-rendered matrix of agents (rows) × layers (columns). Each cell is colored by the **max severity of unmitigated threats** targeting that agent on that layer, with a count badge. Mitigated and "not applicable" threats are excluded.

**Best for:** executive reporting, risk distribution at a glance, comparing models.

### Selecting the view

| Surface | How |
|---|---|
| CLI | `usecvis -m 12 -i model.toml -o out -v graph` (or `heatmap`) |
| REST API | `POST /visualize/maestro?view=graph` |
| Frontend | View selector dropdown in the MAESTRO panel |
| Python | `MaestroThreatModel(..., view="graph")` |
| Config file | Add `[render] view = "graph"` (overrides the constructor) |

---

## Style Presets

| Preset | When to use |
|---|---|
| `ma_default` | Presentations, screen viewing — light pastel bands with color-coded layers. |
| `ma_dark` | Dark-themed dashboards, late-night ops. |
| `ma_blueprint` | Engineering documentation — monochrome blue, Courier font, has a printable feel. |
| `ma_severity` | Risk-heavy reporting — warm tones emphasizing severity over hierarchy. |
| `ma_compact` | Dense models (10+ agents) — minimal padding, smaller fonts. |

Select via `-s <preset_id>` on the CLI, `style=` query param on the API, or the dropdown in the Vue panel.

---

## Reading the Visualization

### Layered view legend

| Element | What it means |
|---|---|
| **Horizontal band** | One MAESTRO layer (L1–L7). Band order top-to-bottom is L7, L3, L1, L2, L4, L5, L6 — user surface to security cross-cut. |
| **Blue rounded box** | An agent, in one of the layers it declares. The same agent appears in every layer in its `layers` list. |
| **Purple cylinder** | An asset (data store), in its owning layer. |
| **Tiny red text under agent name** | Per-layer open-threat count and worst severity: `13 open (critical)` means 13 unmitigated threats target this agent on this layer, with at least one critical. |
| **Dashed red arrow with label** | A cross-layer attack chain. The label is `CL-id: description`. Arrows route between the agent's per-layer copies that the chain references. |
| **Orange note in L6** | The security-mitigation summary: `1 preventive | 0 detective` counts implemented mitigations by type. |

### Graph view legend

| Element | What it means |
|---|---|
| **Cluster (rounded rectangle)** | One MAESTRO layer that hosts at least one agent's primary layer. Empty layers are omitted to keep the canvas compact. |
| **Colored agent node** | One agent, placed in its primary layer's cluster. Fill color matches the layer; the label shows name, type/autonomy, and a severity breakdown row (`C:n H:n M:n L:n`). |
| **Red, thicker border on an agent** | The agent owns at least one unmitigated **critical** threat. |
| **Solid colored arrow** | A multi-step cross-layer attack chain. Color is hashed from the chain id (stable across renders) so multiple chains stay distinguishable. The first hop carries the label `CL-id: description`; later hops are unlabeled by default. |
| **Dashed gray arrow** | A single-hop cross-layer threat that didn't resolve into a multi-step chain. |
| **Orange floating note** | The L6 security-mitigation summary (preventive vs. detective counts). Floats outside any cluster because L6 is cross-cutting. |

### Heatmap view legend

| Element | What it means |
|---|---|
| **Row** | An agent (with autonomy level shown). |
| **Column** | A MAESTRO layer (L1–L6 by id, excludes L7 to keep matrix compact). |
| **Cell color** | Max unmitigated severity targeting that agent on that layer (5-stop scale: none / low / medium / high / critical). |
| **Cell badge number** | Count of open unmitigated threats in that cell. |

---

## Threat Catalog

USecVisLib ships a versioned threat catalog at `src/usecvislib/models/maestro_catalog.json`.

**Current version:** `2026.3` — 55 layer threats, 6 cross-layer threats, 93 mitigations, plus best-effort cross-framework tags (11 MITRE ATT&CK, 8 OWASP ASI, 55 NIST AI RMF).

**Threat IDs are immutable.** Once a threat ID ships, its meaning is frozen for the life of the project. Deprecated entries keep their ID with a `deprecated: true` flag. You can safely reference `T-L2-002` in a config and expect it to mean the same thing across catalog versions.

To browse the catalog from the running stack:

```bash
# Full catalog
GET /maestro/catalog

# Single layer
GET /maestro/catalog/foundation-models
```

Or via the **Browse Catalog** button in the Vue panel.

### Cross-framework mappings

Each catalog threat optionally carries tags for three external frameworks. All are **best-effort starting points**, not authoritative mappings — treat them as hints when correlating with framework-specific reporting tools.

| Field | Framework | Values | Coverage in 2026.3 |
|---|---|---|---|
| `mitre_attack` | MITRE ATT&CK | technique / tactic ID (e.g., `T1565.001`, `TA0010`) | 11 / 55 threats |
| `owasp_asi` | OWASP Agentic Security Initiative | `T1` (Memory Poisoning), `T2` (Tool Misuse), `T3` (Privilege Compromise) | 8 / 55 threats |
| `nist_ai_rmf` | NIST AI Risk Management Framework | `Govern`, `Map`, `Measure`, `Manage` (primary function affected) | 55 / 55 threats |

A full human-expert tagging pass for ATT&CK and ASI is planned for a future catalog version. NIST AI RMF is fully tagged because every threat naturally maps to at least one RMF function.

Programmatic access: each `Threat` returned by `MaestroThreatModel.threats` carries these as attributes, and the `POST /analyze/maestro/threats` endpoint surfaces them in the response payload.

---

## Cross-Reference Exports

Each MAESTRO model can be exported to a sibling framework's shape and consumed by the corresponding USecVisLib module. **All three exports round-trip with zero validation errors** against their target modules.

| Export | Method / Endpoint | Target module |
|---|---|---|
| STRIDE / threat-model | `mm.to_stride()` / `POST /maestro/export/stride` | `ThreatModeling` (mode 1) |
| Attack graph | `mm.to_attack_graph()` / `POST /maestro/export/attack-graph` | `AttackGraphs` (mode 3) |
| Privilege gradient | `mm.to_privilege_gradient()` / `POST /maestro/export/privilege-gradient` | `PrivilegeGradient` (mode 6) |

### STRIDE crosswalk

Roughly **60% of MAESTRO threats have a clean STRIDE mapping**. The rest (adversarial ML, prompt injection, autonomy-specific) emit as `mapping: "informational"`. The export header carries a `mapping_counts` block and `unmapped_pct` so consumers know the STRIDE view is lossy:

```json
{
  "_meta": {
    "source_framework": "MAESTRO",
    "target_framework": "STRIDE",
    "mapping_counts": { "exact": 72, "partial": 46, "informational": 20 },
    "unmapped_pct": 14.49
  },
  "model": { ... },
  "processes": { ... },
  "datastores": { ... },
  "threats": { ... }
}
```

### When to use which export

- **STRIDE crosswalk**: hybrid models, transitioning legacy STRIDE assessments, compliance reports demanding STRIDE categories.
- **Attack graph**: visualize cross-layer chains as concrete attack paths through hosts; feed into existing attack-graph tools.
- **Privilege gradient**: trust-zone analysis. Zones are derived from agent autonomy (`reactive`→Z1, `deliberative`→Z2, `learning`→Z3, `self-modifying`→Z4). The existing inversion detector then flags low-trust → high-trust hops.

---

## API Endpoints

All endpoints require the `X-API-Key` header when `USECVISLIB_AUTH_ENABLED=true` (the default).

| Method | Path | Purpose |
|---|---|---|
| POST | `/visualize/maestro` | Render the model. Query: `format` (png/svg/pdf), `style` (ma_*), `view` (layered/graph/heatmap). |
| POST | `/analyze/maestro` | Stats: counts by layer / severity / status, patterns, warnings. |
| POST | `/validate/maestro` | Validation: errors + auto-populate warnings. |
| POST | `/analyze/maestro/threats` | Per-threat detail with filters. Query: `layer`, `severity`, `status` (any combination). |
| GET | `/maestro/catalog` | Full threat catalog. |
| GET | `/maestro/catalog/{layer}` | Catalog scoped to one layer (e.g. `foundation-models`). |
| POST | `/maestro/export/{target}` | Cross-reference export. `{target}` is `stride`, `attack-graph`, or `privilege-gradient`. |

The OpenAPI schema is auto-generated; visit `http://localhost:8003/docs` for an interactive playground.

---

## What MAESTRO Doesn't Cover

MAESTRO is purpose-built for **agentic AI threat identification**. It is **not** a complete security program. Be deliberate about complementing it with frameworks that cover what it leaves out:

| Gap | What MAESTRO doesn't do | Complementary framework |
|---|---|---|
| **Policy / governance roles** | Identifies risks but doesn't assign accountability or write policies | NIST AI RMF (Govern function), CoSAI secure-by-design principles |
| **Cost / ROI of mitigations** | No economic impact modeling; severity / likelihood are qualitative | FAIR (Factor Analysis of Information Risk), enterprise risk registers |
| **Hardware / physical-layer threats** | Focuses on software and ML layers (L1-L7) | TEE / confidential-computing frameworks, supply-chain hardware audits |
| **Jurisdiction-specific compliance** | Provides audit trails but no jurisdictional rules (EU AI Act, US executive orders, etc.) | Local regulatory mappings, GRC platforms |
| **Formal verification at scale** | Risk is modeled qualitatively; no proof-based assurance | Formal methods toolchains (TLA+, Coq) for specific high-assurance components |
| **Cross-tool interoperability** | No unified API for piping MAESTRO output across tooling | The cross-reference exports (`to_stride()`, `to_attack_graph()`, `to_privilege_gradient()`) cover three sibling formats; broader integration is per-deployment |
| **Continuous runtime detection** | Static model identifies risks; doesn't watch live systems | Runtime guardrail tools (CrewAI guardrails, Lakera, Protect AI), SIEM-side anomaly detection |

In practice: use MAESTRO to *find and prioritize* risks, then plug the gaps with the frameworks above. The cross-framework tags on each threat (`nist_ai_rmf`, `owasp_asi`, `mitre_attack`) are designed to make those handoffs cheaper.

---

## Troubleshooting

### "Pattern 'multi-agent' implies cross-layer threat 'T-CL-005' but no agent covers its layers — skipping"

You declared an architecture pattern whose implied threats target a layer that none of your agents touch. The loader is warning you that those pattern-implied threats are **not** being attached — silently attaching to nothing would create phantom risk; silently skipping would hide a design gap.

**Fix:** either declare an agent that touches the relevant layer, or remove the pattern if it doesn't apply.

### "Cross-layer threat 'CL-x' must span at least 2 layers"

A `[[cross_layer_threats]]` entry has only one layer in its `layers` list. By definition, a cross-layer threat spans **at least 2**.

**Fix:** add the additional layer(s) the chain crosses.

### "Threat 'T-Lx-y' targets unknown agent 'foo'"

A threat override references an agent ID that doesn't exist in `[[agents]]`.

**Fix:** check spelling, or remove the override if the agent was deleted.

### Bands appear staircased / drifted sideways

Some agents span few or non-adjacent layers, and the visual "spine" used to align bands falls back to anchor-based ordering for layer pairs with no shared agent. The content is correct; only the alignment drifts.

**Fix options** (in order of preference):
1. Accept it — content is accurate, drift is a few dozen pixels in most cases.
2. Add an agent that spans the affected layer boundary, even a stub.
3. Switch to the `view = "heatmap"` for that model — heatmap is a strict grid and ignores spine alignment.

### Heatmap is empty / minimal

The heatmap shows only **unmitigated** threats. If all threats targeting an agent on a layer have `status = "mitigated"` or `status = "not-applicable"`, the cell renders as empty.

**Sanity check:** run `POST /analyze/maestro` and inspect `threats_by_status` — if `mitigated` is high, that's expected.

### Render fails with "failed to execute PosixPath('dot')"

Graphviz isn't installed on the host. The layered view needs it; the heatmap view doesn't.

**Fix:** install Graphviz (`brew install graphviz` on macOS, `apt install graphviz` on Debian/Ubuntu), or render in the Docker container which already includes it.

---

## Example Templates

Five shipping templates under `templates/maestro/` exercise different MAESTRO archetypes:

| File | Pattern | Notable for |
|---|---|---|
| `single-agent-rag.toml` | single-agent + task-oriented | Minimal RAG assistant. Shows the smallest useful model. Visualization shows mild staircase due to sparse layer coverage. |
| `multi-agent-support.toml` | multi-agent + hierarchical + HITL | 5 agents (router, billing/technical/account specialists, human queue). Demonstrates per-agent severity overrides and cross-layer chains. |
| `autonomous-soc-agent.toml` | self-learning + HITL | High-autonomy SOC agent. The SOC agent spans **all 7 layers**, producing the cleanest possible layered render. Shows L1/L6 self-attack threats (poisoning the security AI itself). |
| `agent-marketplace.toml` | distributed + multi-agent | 5 agents in a registry-based ecosystem. L7-heavy threat surface (sybil, registry compromise, capability misrepresentation). |
| `financial-trading-chain.toml` | all 5 main patterns | Algorithmic trading system with 5 agents, 5 assets, and **three cross-layer chains** illustrating full L1→L7 vertical attack propagation. Uses 2026.3 threats (sleeper agents, log injection, compliance bypass, cascade failure). The primary trading agent spans all 7 layers, so the layered render is the cleanest of any template. Best reference for authoring cross-layer chains. |

Copy and adapt these to your model. For minimum-friction starting points:

- **Just one agent, simple use case:** `single-agent-rag.toml`
- **Several specialist agents collaborating:** `multi-agent-support.toml`
- **High-autonomy or learning agent:** `autonomous-soc-agent.toml`
- **Marketplace, third-party agents, distributed ecosystem:** `agent-marketplace.toml`
- **Learning how to write cross-layer chains, regulated environment, or want the most realistic example:** `financial-trading-chain.toml`

---

## See Also

- [`README.md`](../README.md) — project overview and quick start
- [`docs/CLI_GUIDE.md`](CLI_GUIDE.md) — full CLI reference (all modes)
- [`docs/PYTHON_API.md`](PYTHON_API.md) — programmatic API for the entire library
- [`docs/UI_GUIDE.md`](UI_GUIDE.md) — Vue frontend usage guide
- [Cloud Security Alliance — MAESTRO blog post](https://cloudsecurityalliance.org/blog/2025/02/06/agentic-ai-threat-modeling-framework-maestro)
