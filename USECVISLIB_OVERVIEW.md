# USecVisLib — Project Overview

**Universal Security Visualization Library**

| | |
|---|---|
| **Version** | 0.5.0 |
| **License** | Apache 2.0 |
| **Author** | Simon Roses Femerling — [VULNEX](https://www.vulnex.com) |
| **Language** | Python 3.10+ / Vue.js 3 |
| **Repository** | https://github.com/vulnex/usecvislib |

> *This document is a high-level overview intended to be shared for feedback. It describes what USecVisLib is, how it works, and what it can do.*

---

## 1. What Is USecVisLib?

**USecVisLib** is a comprehensive library and web application for creating **security visualizations**. It gives security professionals, architects, and developers a single, unified platform to turn security concepts — attack scenarios, threat models, network vulnerabilities, trust boundaries, and cloud architectures — into clear, professional diagrams.

Instead of hand-drawing diagrams in generic tools, users describe their security model in a simple text configuration file (TOML, JSON, or YAML) and USecVisLib renders a polished, consistent visualization automatically. The same model can be analyzed, scored, exported, and re-styled without redrawing anything.

It is designed to be used four ways, depending on the user:

- **Web application** — a point-and-click interface for interactive use
- **Command-line tool** (`usecvis`) — for scripting and automation
- **Python library** — for embedding in tools and pipelines
- **REST API** — for integration with other applications and services

### Who It's For

- **Security engineers & pentesters** — attack trees, attack graphs, kill-chain analysis
- **Threat modelers & architects** — STRIDE data-flow diagrams, MAESTRO agentic-AI threat models
- **DevSecOps & cloud teams** — cloud architecture diagrams, component & dependency graphs
- **Reverse engineers & malware analysts** — binary file visualizations
- **Anyone writing security documentation** — consistent, reproducible, version-controllable diagrams

---

## 2. Visualization Modules

USecVisLib provides **fourteen** distinct visualization types, each purpose-built for a security use case:

| Module | What It Does | Highlights |
|--------|-------------|-----------|
| **Attack Trees** | Hierarchical attack-scenario diagrams | AND/OR gates, leaf nodes, CVSS scoring, 18 style presets |
| **Attack Graphs** | Network attack-path visualization | Path finding, critical-node analysis, CVSS 3.x/4.0 |
| **Threat Modeling** | Data Flow Diagrams with STRIDE analysis | OWASP PyTM integration, trust boundaries, auto reports |
| **MAESTRO Threat Models** | Threat modeling for **agentic AI systems** | 7-layer framework, threat catalog, layered + heatmap + graph views |
| **Kill Chain / MITRE ATT&CK** | Attack progression through a standard framework | Cyber Kill Chain / ATT&CK / custom axes, detection-gap coverage heat, Graphviz + SVG engines |
| **Incident Timeline** | Chronology of a security incident for IR | Swimlane / gantt / vertical / compact modes, response-phase bands, MTTD/MTTC/MTTR metrics |
| **Vulnerability Dependency Tree** | Software supply-chain / SCA analysis | CVE-annotated dependency tree, severity heat, exploited-edge highlighting, impact propagation |
| **Custom Diagrams** | Flexible, schema-driven diagrams | 100+ shapes, custom schemas, reusable templates |
| **Mermaid Diagrams** | Render Mermaid syntax to images | Flowcharts, sequence, class, state, ER, Gantt, pie |
| **Cloud Diagrams** | Cloud architecture visualization | AWS, Azure, GCP, Kubernetes icons; clusters |
| **Privilege Gradient** | Trust-zone & privilege-level visualization | Zone-inversion detection, escalation pathways |
| **Component Diagrams** | Software component architecture | Layered architecture, sync/async/event connections |
| **Dependency Graphs** | Module/package dependency mapping | SLOC-based sizing, circular-dependency detection |
| **Binary Analysis** | Binary file pattern visualization | Entropy, byte distribution, wind rose, heatmap |

### Spotlight: MAESTRO — Threat Modeling for Agentic AI

As AI agents move into production, traditional threat models don't fully capture their risks. The **MAESTRO** module models threats across the seven layers of an agentic AI system (foundation models, data, agent frameworks, deployment, observability, compliance, and the cross-cutting security layer). It ships with a curated threat catalog mapped to industry frameworks (MITRE ATT&CK, OWASP, and NIST AI RMF), multiple rendering views (layered diagram, heatmap, and agent-centric graph), and the ability to cross-reference findings into STRIDE, attack-graph, and privilege-gradient views.

---

## 3. How It Works

### Architecture

USecVisLib is built as three clean layers, so each can be used independently:

```
┌─────────────────────────────────────────────────────────────┐
│                     Vue.js 3 Web Frontend                     │
│     Dark-theme UI · live code editor · zoom/pan output        │
├─────────────────────────────────────────────────────────────┤
│                       FastAPI REST API                        │
│   OpenAPI docs · rate limiting · optional key authentication  │
├─────────────────────────────────────────────────────────────┤
│                      Python Core Library                      │
│      Graphviz · NetworkX · Matplotlib · Diagrams · Mermaid    │
└─────────────────────────────────────────────────────────────┘
```

### The Workflow

1. **Describe** your security model in a configuration file — TOML, JSON, or YAML (the format is auto-detected). The schema is human-readable and version-control friendly.
2. **Choose a style** from dozens of built-in presets (dark, neon, corporate, blueprint, hacker, and more).
3. **Render** to an image (PNG, SVG, PDF) or to source formats (DOT, Mermaid) via the web UI, CLI, Python, or API.
4. **Analyze** the model — find attack paths, score with CVSS, run STRIDE, detect critical nodes or privilege inversions.
5. **Export & share** the diagram, the analysis report, or the model in another format.

### Configuration-Driven by Design

Every diagram is just text. A short attack-tree definition looks like this:

```toml
[tree]
name = "Web Application Attack"
root = "Compromise App"

[nodes]
"Compromise App"  = { style = "filled", fillcolor = "red" }
"SQL Injection"   = { style = "filled", fillcolor = "orange" }
"XSS Attack"      = { style = "filled", fillcolor = "orange" }

[edges]
"Compromise App" = [
  { to = "SQL Injection", label = "OR" },
  { to = "XSS Attack",    label = "OR" }
]
```

Because the model is plain text, diagrams are **reproducible, diffable, and reviewable** — they live alongside code in a repository and update automatically.

---

## 4. Key Features

### Security Analysis
- **CVSS 3.1 & 4.0 scoring** — scores on nodes, severity color-coding, version-agnostic interface
- **STRIDE analysis** — automated threat categorization with report generation
- **Attack-path finding** — NetworkX-powered path analysis between any two nodes
- **Critical-node detection** — centrality analysis to find chokepoints
- **Privilege-inversion detection** — trust-zone gradient analysis with severity classification
- **Agentic-AI threat modeling** — the MAESTRO 7-layer framework with cross-framework mappings
- **Kill-chain coverage analysis** — map techniques to ATT&CK / Cyber Kill Chain phases and surface detection/mitigation gaps
- **Incident response timelines** — chronological IR narratives with MTTD/MTTC/MTTR response metrics
- **Supply-chain / SCA analysis** — CVE-annotated dependency trees with impact propagation and remediation hints

### Developer & User Experience
- **Multi-format configuration** — TOML, JSON, YAML with automatic detection
- **Rich template library** — ready-to-use examples across every module
- **Dozens of style presets** — consistent, professional theming out of the box
- **Multiple output formats** — PNG, SVG, PDF, plus DOT and Mermaid source export
- **Format conversion** — convert freely between configuration formats
- **Python API** — fluent interface, builder pattern, and async support

### Web Interface
- **Live editor** with syntax highlighting and real-time validation
- **Drag-and-drop** file upload for all configuration types
- **Zoom & pan** on every generated visualization
- **Batch processing** and a built-in **format converter**
- **CVSS display controls** per visualization type
- **Responsive design** that works on mobile

### Cloud & Icons
- **Thousands of bundled icons** — AWS, Azure, and Bootstrap icon sets
- **Multi-cloud support** — AWS, Azure, GCP, and Kubernetes
- **Cluster grouping** for visually organizing related components

---

## 5. Interfaces & Integration

### Web Application
A Vue.js 3 single-page app with a dark-theme UI, organized into tabs per visualization type plus a tools menu (CVSS calculator, format converter, batch processing, export, compare).

### Command Line
```bash
# Attack tree
usecvis -m 0 -i config.toml -o output -f png -s at_default

# Threat model with a STRIDE report
usecvis -m 1 -i threat.toml -o diagram -f png -r

# MAESTRO agentic-AI threat model
usecvis -m 12 -i agent.toml -o output -f png -v graph
```

### Python Library
```python
from usecvislib import AttackGraphs

ag = AttackGraphs("network.toml", "graph", format="png", styleid="ag_security")
ag.BuildAttackGraph()
paths    = ag.find_attack_paths("attacker", "database_root")
critical = ag.analyze_critical_nodes(top_n=5)
```

### REST API
A FastAPI service exposing visualize / analyze / validate endpoints for every module, with interactive OpenAPI (Swagger UI and ReDoc) documentation, configurable rate limiting, and optional API-key authentication.

### AI Assistant Integration (MCP)
A companion Model Context Protocol server lets AI assistants drive USecVisLib directly — generating and analyzing security visualizations through natural-language tooling.

---

## 6. Technology Stack

| Layer | Technologies |
|-------|--------------|
| **Frontend** | Vue.js 3, Vite, CodeMirror 6 |
| **Backend** | FastAPI, Uvicorn, Pydantic |
| **Visualization** | Graphviz, NetworkX, Matplotlib, Diagrams |
| **Mermaid** | mermaid-cli, Puppeteer, Chromium |
| **Threat modeling** | OWASP PyTM |
| **Deployment** | Docker, Docker Compose |

---

## 7. Getting Started

The fastest path is Docker Compose, which brings up the API and the web UI together:

```bash
git clone --recursive https://github.com/vulnex/usecvislib.git
cd usecvislib
docker-compose up -d

# Web UI:  http://localhost:3001
# API docs: http://localhost:8003/docs
```

Manual installation (Python package + frontend) and a CLI-only setup are also supported. The only system prerequisite beyond Python 3.10+ and Node.js 18+ is **Graphviz** for graph rendering.

---

## 8. Why It Matters

- **Consistency** — every diagram follows the same professional styling, regardless of who made it.
- **Reproducibility** — diagrams are defined as text, so they're versioned, reviewed, and regenerated like code.
- **Breadth** — one tool covers attack trees, threat models, cloud architecture, agentic-AI threats, and more.
- **Analysis, not just drawing** — CVSS scoring, STRIDE, attack-path finding, and privilege analysis come built in.
- **Open** — Apache 2.0 licensed, with a documented API and an extensible, modular core.

---

## We'd Love Your Feedback

This overview is being shared to gather input. A few questions we're especially interested in:

1. Which visualization modules are most (and least) useful for your work?
2. Is anything missing that would make this part of your day-to-day workflow?
3. How would you prefer to use it — web UI, CLI, Python library, API, or AI assistant?
4. Does the agentic-AI (MAESTRO) threat modeling resonate with where you see security heading?

Thank you for taking the time to review USecVisLib.

---

*USecVisLib · Universal Security Visualization Library · v0.5.0 · © VULNEX · Apache License 2.0*
