<!--
  VULNEX -Universal Security Visualization Library-

  File: DocumentationPanel.vue
  Author: Simon Roses Femerling
  Created: 2025-01-01
  Last Modified: 2025-12-27
  Version: 0.3.1
  License: Apache-2.0
  Copyright (c) 2025 VULNEX. All rights reserved.
  https://www.vulnex.com
-->
<template>
  <div class="panel documentation-panel">
    <div class="panel-header">
      <h2>Documentation</h2>
      <p>Learn how to use USecVisLib for security visualizations</p>
    </div>

    <div class="panel-body">
      <div class="doc-section">
        <h3>Getting Started</h3>
        <p>USecVisLib is a Universal Security Visualization Library that provides five main visualization modules:</p>
        <ul>
          <li><strong>Attack Trees</strong> - Visualize attack paths and threat scenarios</li>
          <li><strong>Attack Graphs</strong> - Model network attack paths with vulnerability and privilege analysis</li>
          <li><strong>Threat Modeling</strong> - Generate Data Flow Diagrams with STRIDE analysis</li>
          <li><strong>Binary Analysis</strong> - Analyze binary files with entropy and pattern visualizations</li>
          <li><strong>Custom Diagrams</strong> - Create user-defined diagrams with custom node and edge schemas</li>
        </ul>

        <h4>Tools Menu</h4>
        <p>Access these tools from the "Tools" dropdown in the navigation bar:</p>
        <ul>
          <li><strong>CVSS Calculator</strong> - Calculate CVSS 3.x scores from vector strings</li>
          <li><strong>Format Converter</strong> - Convert configuration files between TOML, JSON, and YAML formats</li>
          <li><strong>Batch Processing</strong> - Process multiple files at once with bulk download</li>
          <li><strong>Data Export</strong> - Export data to JSON, CSV, YAML, or Markdown for reporting</li>
          <li><strong>File Compare</strong> - Diff two configuration files to track changes</li>
        </ul>

        <h4>Supported File Formats</h4>
        <p>All configuration files can be written in TOML, JSON, or YAML format. The format is auto-detected from the file extension.</p>

        <h4>Visualization Controls</h4>
        <p>All generated visualizations include zoom controls:</p>
        <ul>
          <li><strong>+/−</strong> - Zoom in/out (25% steps)</li>
          <li><strong>⟲</strong> - Reset to 100% zoom</li>
          <li><strong>⊡</strong> - Fit image to view</li>
          <li><strong>Mouse wheel</strong> - Scroll to zoom</li>
          <li><strong>Drag</strong> - Pan when zoomed in</li>
        </ul>
      </div>

      <div class="doc-section">
        <h3>Attack Trees</h3>
        <p>Attack trees represent the hierarchical breakdown of an attack goal into sub-goals and attack steps.</p>

        <h4>TOML Format</h4>
        <pre class="code-block"><code>[meta]
title = "Web Application Attack"
description = "Attack tree for web app vulnerabilities"

[tree]
root = "Compromise Web App"

[tree.nodes.root]
label = "Compromise Web App"
type = "OR"
children = ["sql_injection", "xss", "auth_bypass"]

[tree.nodes.sql_injection]
label = "SQL Injection"
type = "AND"
children = ["find_input", "craft_payload"]

[tree.nodes.find_input]
label = "Find Vulnerable Input"
type = "LEAF"

[tree.nodes.craft_payload]
label = "Craft SQL Payload"
type = "LEAF"</code></pre>

        <h4>Node Types</h4>
        <ul>
          <li><strong>OR</strong> - Attack succeeds if ANY child succeeds</li>
          <li><strong>AND</strong> - Attack succeeds only if ALL children succeed</li>
          <li><strong>LEAF</strong> - Terminal node representing an atomic action</li>
        </ul>
      </div>

      <div class="doc-section">
        <h3>Attack Graphs</h3>
        <p>Attack graphs model all possible attack paths through a network, including hosts, vulnerabilities, privileges, and exploits.</p>

        <h4>TOML Format</h4>
        <pre class="code-block"><code>[graph]
name = "Network Attack Graph"
description = "Corporate network intrusion scenario"

[[hosts]]
id = "attacker"
label = "Attacker"
zone = "external"

[[hosts]]
id = "webserver"
label = "Web Server"
ip = "10.0.1.10"
zone = "dmz"

[[vulnerabilities]]
id = "vuln_rce"
label = "RCE Vulnerability"
cvss = 9.8
affected_host = "webserver"

[[privileges]]
id = "priv_shell"
label = "Web Shell Access"
host = "webserver"
level = "user"

[[exploits]]
id = "exploit_rce"
label = "RCE Exploit"
vulnerability = "vuln_rce"
precondition = "attacker"
postcondition = "priv_shell"

[[network_edges]]
from = "attacker"
to = "webserver"
label = "Internet Access"</code></pre>

        <h4>Node Types</h4>
        <ul>
          <li><strong>Hosts</strong> - Network machines (servers, workstations, attacker)</li>
          <li><strong>Vulnerabilities</strong> - CVEs or weaknesses with CVSS scores</li>
          <li><strong>Privileges</strong> - Access levels (user, root, admin)</li>
          <li><strong>Services</strong> - Running services with ports</li>
        </ul>

        <h4>Analysis Features</h4>
        <ul>
          <li><strong>Path Finding</strong> - Find all attack paths between source and target nodes</li>
          <li><strong>Shortest Path</strong> - Identify the shortest attack path using BFS</li>
          <li><strong>Critical Nodes</strong> - Analyze nodes by degree centrality to identify chokepoints</li>
          <li><strong>CVSS Statistics</strong> - Average and critical vulnerability counts</li>
        </ul>

        <h4>Advanced Graph Analysis (NetworkX)</h4>
        <p>Powered by NetworkX, these advanced analysis features provide deep insights into attack graph structure:</p>
        <table class="info-table">
          <tr>
            <th>Feature</th>
            <th>Description</th>
          </tr>
          <tr>
            <td><strong>Graph Metrics</strong></td>
            <td>Comprehensive metrics including density, diameter, cycle count, strongly connected components, DAG status, and clustering coefficient</td>
          </tr>
          <tr>
            <td><strong>Centrality Analysis</strong></td>
            <td>Calculate betweenness, closeness, and PageRank centrality to identify critical nodes</td>
          </tr>
          <tr>
            <td><strong>Chokepoints</strong></td>
            <td>Find network bottlenecks - critical nodes where many attack paths converge</td>
          </tr>
          <tr>
            <td><strong>Attack Surface</strong></td>
            <td>Identify entry points and measure their reachability (how many nodes can be accessed from each)</td>
          </tr>
          <tr>
            <td><strong>Vulnerability Impact</strong></td>
            <td>Calculate the impact score of a specific vulnerability based on reachability and affected assets</td>
          </tr>
        </table>

        <h4>Using Advanced Analysis</h4>
        <p>Access these features from the "Advanced Graph Analysis" section in the Attack Graphs panel:</p>
        <ol>
          <li><strong>Graph Metrics</strong> - Click to view density, diameter, cycles, SCCs, and DAG status</li>
          <li><strong>Centrality Analysis</strong> - Shows top nodes ranked by betweenness (B), closeness (C), and PageRank (PR)</li>
          <li><strong>Find Chokepoints</strong> - Displays critical bottleneck nodes with their scores</li>
          <li><strong>Attack Surface</strong> - Lists entry points sorted by reachability</li>
          <li><strong>Vulnerability Impact</strong> - Enter a vulnerability ID to calculate its network-wide impact</li>
        </ol>
      </div>

      <div class="doc-section">
        <h3>Threat Modeling</h3>
        <p>Create Data Flow Diagrams (DFDs) and perform STRIDE threat analysis. Two engines are available for visualization.</p>

        <h4>Available Engines</h4>
        <table class="info-table">
          <tr>
            <th>Engine</th>
            <th>Description</th>
            <th>Features</th>
          </tr>
          <tr>
            <td><strong>USecVisLib</strong></td>
            <td>Native visualization engine</td>
            <td>Custom styling support, fast rendering, lightweight</td>
          </tr>
          <tr>
            <td><strong>OWASP PyTM</strong></td>
            <td>OWASP threat modeling framework</td>
            <td>Industry-standard DFD generation, comprehensive threat library</td>
          </tr>
        </table>

        <h4>TOML Format</h4>
        <pre class="code-block"><code>[model]
name = "E-Commerce System"
description = "Threat model for online store"

[processes.web_server]
label = "Web Server"
is_server = true
authenticatesSource = true

[processes.api_server]
label = "API Server"
sanitizesInput = true

[datastores.user_db]
label = "User Database"
isEncrypted = true
isSQL = true

[externals.user]
label = "End User"

[dataflows.user_request]
from = "user"
to = "web_server"
label = "HTTPS Request"
isEncrypted = true
protocol = "HTTPS"

[dataflows.api_call]
from = "web_server"
to = "api_server"
label = "API Call"

[boundaries.dmz]
label = "DMZ Zone"
elements = ["web_server"]

[boundaries.internal]
label = "Internal Network"
elements = ["api_server", "user_db"]</code></pre>

        <h4>Element Types</h4>
        <ul>
          <li><strong>Processes</strong> - Internal system components (servers, services, applications)</li>
          <li><strong>Data Stores</strong> - Databases, files, caches, queues</li>
          <li><strong>External Entities</strong> - Users, external systems, third-party services</li>
          <li><strong>Data Flows</strong> - Communication between elements</li>
          <li><strong>Trust Boundaries</strong> - Security perimeters separating trust zones</li>
        </ul>

        <h4>PyTM-Compatible Attributes</h4>
        <p>When using the PyTM engine, these additional attributes enhance threat detection:</p>
        <table class="info-table">
          <tr>
            <th>Element</th>
            <th>Attribute</th>
            <th>Description</th>
          </tr>
          <tr>
            <td>Process</td>
            <td><code>is_server</code></td>
            <td>Marks element as a server (vs. client process)</td>
          </tr>
          <tr>
            <td>Process</td>
            <td><code>authenticatesSource</code></td>
            <td>Process authenticates incoming requests</td>
          </tr>
          <tr>
            <td>Process</td>
            <td><code>sanitizesInput</code></td>
            <td>Process sanitizes input data</td>
          </tr>
          <tr>
            <td>Process</td>
            <td><code>encodesOutput</code></td>
            <td>Process encodes output data</td>
          </tr>
          <tr>
            <td>Datastore</td>
            <td><code>isEncrypted</code></td>
            <td>Data at rest is encrypted</td>
          </tr>
          <tr>
            <td>Datastore</td>
            <td><code>isSQL</code></td>
            <td>SQL database (enables SQL injection checks)</td>
          </tr>
          <tr>
            <td>Dataflow</td>
            <td><code>isEncrypted</code></td>
            <td>Data in transit is encrypted</td>
          </tr>
          <tr>
            <td>Dataflow</td>
            <td><code>protocol</code></td>
            <td>Protocol used (HTTP, HTTPS, TCP, etc.)</td>
          </tr>
        </table>

        <h4>STRIDE Categories</h4>
        <ul>
          <li><strong>S</strong>poofing - Impersonating something or someone</li>
          <li><strong>T</strong>ampering - Modifying data or code</li>
          <li><strong>R</strong>epudiation - Claiming not to have performed an action</li>
          <li><strong>I</strong>nformation Disclosure - Exposing information to unauthorized entities</li>
          <li><strong>D</strong>enial of Service - Denying or degrading service</li>
          <li><strong>E</strong>levation of Privilege - Gaining unauthorized capabilities</li>
        </ul>
      </div>

      <div class="doc-section">
        <h3>Binary Visualization</h3>
        <p>Analyze binary files to identify patterns, compression, encryption, and anomalies.</p>

        <h4>Visualization Types</h4>
        <ul>
          <li><strong>Entropy Analysis</strong> - Shows randomness distribution across the file. High entropy (>7) suggests encryption or compression.</li>
          <li><strong>Byte Distribution</strong> - Histogram of byte frequencies. Flat distribution indicates encryption; peaks indicate structure.</li>
          <li><strong>Wind Rose</strong> - Polar plot of byte pair patterns. Reveals repeating sequences and structure.</li>
          <li><strong>Heatmap</strong> - 2D representation of file contents. Shows visual patterns and sections.</li>
        </ul>

        <h4>Interpreting Results</h4>
        <table class="info-table">
          <tr>
            <th>Entropy Range</th>
            <th>Interpretation</th>
          </tr>
          <tr>
            <td>0 - 3</td>
            <td>Low entropy: Text files, sparse data, lots of nulls</td>
          </tr>
          <tr>
            <td>3 - 6</td>
            <td>Medium entropy: Executable code, structured data</td>
          </tr>
          <tr>
            <td>6 - 8</td>
            <td>High entropy: Compressed, encrypted, or random data</td>
          </tr>
        </table>
      </div>

      <div class="doc-section">
        <h3>Custom Diagrams</h3>
        <p>Create user-defined diagrams with custom node and edge types. Define your own schema for creating flowcharts, network diagrams, org charts, and more.</p>

        <h4>TOML Format</h4>
        <pre class="code-block"><code>[diagram]
title = "My Custom Diagram"
layout = "hierarchical"
direction = "TB"
style = "cd_default"

[schema.nodes.process]
shape = "rectangle"
required_fields = ["name"]
style = { fillcolor = "#3498DB", fontcolor = "white" }

[schema.edges.flow]
style = "solid"
arrowhead = "normal"
color = "#333333"

[[nodes]]
id = "start"
type = "process"
name = "Start Here"

[[nodes]]
id = "end"
type = "process"
name = "End Here"

[[edges]]
from = "start"
to = "end"
type = "flow"</code></pre>

        <h4>Configuration Sections</h4>
        <ul>
          <li><strong>[diagram]</strong> - Diagram metadata (title, layout, direction, style)</li>
          <li><strong>[schema.nodes.&lt;type&gt;]</strong> - Define custom node types with shapes and styles</li>
          <li><strong>[schema.edges.&lt;type&gt;]</strong> - Define custom edge types with arrows and colors</li>
          <li><strong>[[nodes]]</strong> - List of nodes with id, type, and custom fields</li>
          <li><strong>[[edges]]</strong> - List of edges connecting nodes</li>
        </ul>

        <h4>Available Layouts</h4>
        <table class="info-table">
          <tr>
            <th>Layout</th>
            <th>Description</th>
          </tr>
          <tr>
            <td><code>hierarchical</code></td>
            <td>Tree-like layout with direction (TB, BT, LR, RL)</td>
          </tr>
          <tr>
            <td><code>circular</code></td>
            <td>Nodes arranged in a circle</td>
          </tr>
          <tr>
            <td><code>radial</code></td>
            <td>Nodes radiate from center</td>
          </tr>
          <tr>
            <td><code>force</code></td>
            <td>Force-directed layout (fdp, neato, sfdp)</td>
          </tr>
        </table>

        <h4>Style Presets</h4>
        <ul>
          <li><strong>cd_default</strong> - Clean professional look</li>
          <li><strong>cd_dark</strong> - Dark theme with light text</li>
          <li><strong>cd_corporate</strong> - Professional enterprise style</li>
          <li><strong>cd_neon</strong> - Cyberpunk neon colors</li>
          <li><strong>cd_blueprint</strong> - Technical blueprint style</li>
          <li><strong>cd_pastel</strong> - Soft pastel colors</li>
        </ul>

        <h4>Shape Gallery</h4>
        <p>55+ shapes are available organized by category:</p>
        <ul>
          <li><strong>Basic</strong> - box, ellipse, circle, diamond, triangle, parallelogram</li>
          <li><strong>3D</strong> - box3d, cylinder, folder</li>
          <li><strong>Arrows</strong> - rarrow, larrow, rpromoter, lpromoter</li>
          <li><strong>Special</strong> - star, note, tab, component, cds, signature</li>
          <li><strong>Network</strong> - cloud, firewall, server, database, laptop</li>
        </ul>
        <p>Click "Shape Gallery" in the Custom Diagrams panel to browse and copy shape IDs.</p>
      </div>

      <div class="doc-section">
        <h3>CVSS Calculator</h3>
        <p>Calculate CVSS (Common Vulnerability Scoring System) 3.x scores from vector strings. Access from the Tools dropdown menu.</p>

        <h4>Usage</h4>
        <ol>
          <li>Enter a CVSS vector string in the input field</li>
          <li>Click "Calculate" to compute the score</li>
          <li>View the base score, severity rating, and metric breakdown</li>
        </ol>

        <h4>CVSS Vector Format</h4>
        <p>CVSS 3.0/3.1 vectors follow this format:</p>
        <pre class="code-block"><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H</code></pre>

        <h4>Base Metrics</h4>
        <table class="info-table">
          <tr>
            <th>Metric</th>
            <th>Code</th>
            <th>Values</th>
          </tr>
          <tr>
            <td>Attack Vector</td>
            <td>AV</td>
            <td>N (Network), A (Adjacent), L (Local), P (Physical)</td>
          </tr>
          <tr>
            <td>Attack Complexity</td>
            <td>AC</td>
            <td>L (Low), H (High)</td>
          </tr>
          <tr>
            <td>Privileges Required</td>
            <td>PR</td>
            <td>N (None), L (Low), H (High)</td>
          </tr>
          <tr>
            <td>User Interaction</td>
            <td>UI</td>
            <td>N (None), R (Required)</td>
          </tr>
          <tr>
            <td>Scope</td>
            <td>S</td>
            <td>U (Unchanged), C (Changed)</td>
          </tr>
          <tr>
            <td>Confidentiality Impact</td>
            <td>C</td>
            <td>N (None), L (Low), H (High)</td>
          </tr>
          <tr>
            <td>Integrity Impact</td>
            <td>I</td>
            <td>N (None), L (Low), H (High)</td>
          </tr>
          <tr>
            <td>Availability Impact</td>
            <td>A</td>
            <td>N (None), L (Low), H (High)</td>
          </tr>
        </table>

        <h4>Severity Ratings</h4>
        <table class="info-table">
          <tr>
            <th>Score Range</th>
            <th>Severity</th>
            <th>Color</th>
          </tr>
          <tr>
            <td>9.0 - 10.0</td>
            <td>Critical</td>
            <td style="color: #8b0000;">Dark Red</td>
          </tr>
          <tr>
            <td>7.0 - 8.9</td>
            <td>High</td>
            <td style="color: #e74c3c;">Red</td>
          </tr>
          <tr>
            <td>4.0 - 6.9</td>
            <td>Medium</td>
            <td style="color: #f39c12;">Orange</td>
          </tr>
          <tr>
            <td>0.1 - 3.9</td>
            <td>Low</td>
            <td style="color: #27ae60;">Green</td>
          </tr>
          <tr>
            <td>0.0</td>
            <td>None</td>
            <td style="color: #3498db;">Blue</td>
          </tr>
        </table>

        <h4>Example Vectors</h4>
        <ul>
          <li><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H</code> - Critical (9.8) - Remote Code Execution</li>
          <li><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N</code> - Medium (6.1) - Cross-Site Scripting</li>
          <li><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N</code> - Medium (5.5) - Local Information Disclosure</li>
        </ul>
      </div>

      <div class="doc-section">
        <h3>Format Conversion</h3>
        <p>Convert configuration files between TOML, JSON, and YAML formats using the Format Converter tool.</p>

        <h4>Usage</h4>
        <ol>
          <li>Upload a configuration file (any supported format)</li>
          <li>Source format is auto-detected from file extension</li>
          <li>Select target format from dropdown</li>
          <li>Click Convert to transform the file</li>
          <li>Preview the result and download</li>
        </ol>

        <h4>Use Cases</h4>
        <ul>
          <li>Convert legacy JSON configs to YAML for better readability</li>
          <li>Export YAML to JSON for programmatic processing</li>
          <li>Standardize team configurations to a single format</li>
        </ul>
      </div>

      <div class="doc-section">
        <h3>Batch Processing</h3>
        <p>Process multiple configuration files at once using the Batch tab. Generate visualizations for many files in a single operation.</p>

        <h4>Usage</h4>
        <ol>
          <li>Drag and drop multiple files or click to browse</li>
          <li>Select the visualization mode (Attack Tree, Attack Graph, Threat Model, or Binary)</li>
          <li>Choose output format (PNG, SVG, PDF) and style</li>
          <li>Enable "Collect Statistics" to see aggregate stats</li>
          <li>Click "Process All Files"</li>
          <li>Download individual results or use "Download All"</li>
        </ol>

        <h4>Features</h4>
        <ul>
          <li><strong>Multi-file upload</strong> - Process up to 20 files at once</li>
          <li><strong>Progress tracking</strong> - See real-time progress bar during processing</li>
          <li><strong>Individual downloads</strong> - Download each visualization separately</li>
          <li><strong>Bulk download</strong> - Download all successful results with one click</li>
          <li><strong>Aggregate statistics</strong> - See combined stats (total nodes, edges, etc.)</li>
          <li><strong>Error handling</strong> - Failed files show error messages without stopping the batch</li>
        </ul>

        <h4>Supported Modes</h4>
        <table class="info-table">
          <tr>
            <th>Mode</th>
            <th>File Types</th>
            <th>Description</th>
          </tr>
          <tr>
            <td>Attack Tree</td>
            <td>.toml, .json, .yaml</td>
            <td>Generate attack tree visualizations</td>
          </tr>
          <tr>
            <td>Attack Graph</td>
            <td>.toml, .json, .yaml</td>
            <td>Generate attack graph visualizations</td>
          </tr>
          <tr>
            <td>Threat Model</td>
            <td>.toml, .json, .yaml</td>
            <td>Generate DFD visualizations</td>
          </tr>
          <tr>
            <td>Binary</td>
            <td>Any binary file</td>
            <td>Generate entropy/distribution visualizations</td>
          </tr>
        </table>
      </div>

      <div class="doc-section">
        <h3>Export Data</h3>
        <p>Export configuration data to various formats using the Export tab. Useful for reporting, analysis, or integration with other tools.</p>

        <h4>Usage</h4>
        <ol>
          <li>Upload a configuration file</li>
          <li>View detected sections (hosts, vulnerabilities, etc.)</li>
          <li>Select export format (JSON, CSV, YAML, or Markdown)</li>
          <li>For CSV/Markdown, optionally select a specific section</li>
          <li>Enable "Include Statistics" for metadata</li>
          <li>Click "Export Data"</li>
          <li>Preview and download the result</li>
        </ol>

        <h4>Export Formats</h4>
        <table class="info-table">
          <tr>
            <th>Format</th>
            <th>Best For</th>
            <th>Description</th>
          </tr>
          <tr>
            <td><strong>JSON</strong></td>
            <td>Programmatic use</td>
            <td>Full data export with structure preserved</td>
          </tr>
          <tr>
            <td><strong>CSV</strong></td>
            <td>Spreadsheets</td>
            <td>Tabular data, one section at a time</td>
          </tr>
          <tr>
            <td><strong>YAML</strong></td>
            <td>Human readability</td>
            <td>Clean, readable export format</td>
          </tr>
          <tr>
            <td><strong>Markdown</strong></td>
            <td>Documentation</td>
            <td>Tables formatted for Markdown rendering</td>
          </tr>
        </table>

        <h4>Use Cases</h4>
        <ul>
          <li>Export vulnerability lists to CSV for Excel analysis</li>
          <li>Generate Markdown tables for security reports</li>
          <li>Extract host inventories for documentation</li>
          <li>Create JSON exports for CI/CD pipeline integration</li>
        </ul>
      </div>

      <div class="doc-section">
        <h3>Compare Configurations</h3>
        <p>Compare two configuration files to identify changes between versions using the Compare tab. Useful for change tracking and security reviews.</p>

        <h4>Usage</h4>
        <ol>
          <li>Upload the original (old) configuration file</li>
          <li>Upload the modified (new) configuration file</li>
          <li>Enable "Generate Markdown Report" for a downloadable report</li>
          <li>Click "Compare Files"</li>
          <li>Review the changes summary and detailed diff</li>
          <li>Download the Markdown report if needed</li>
        </ol>

        <h4>Change Types</h4>
        <table class="info-table">
          <tr>
            <th>Type</th>
            <th>Color</th>
            <th>Description</th>
          </tr>
          <tr>
            <td><strong>Added</strong></td>
            <td style="color: #4ade80;">Green (+)</td>
            <td>New elements added in the modified file</td>
          </tr>
          <tr>
            <td><strong>Removed</strong></td>
            <td style="color: #f87171;">Red (-)</td>
            <td>Elements deleted from the original file</td>
          </tr>
          <tr>
            <td><strong>Modified</strong></td>
            <td style="color: #fbbf24;">Yellow (~)</td>
            <td>Elements with changed values</td>
          </tr>
        </table>

        <h4>Features</h4>
        <ul>
          <li><strong>Deep comparison</strong> - Detects changes in nested structures</li>
          <li><strong>Smart list matching</strong> - Uses ID fields to match list items</li>
          <li><strong>Path display</strong> - Shows exact location of each change (e.g., <code>hosts.webserver.ip</code>)</li>
          <li><strong>Value preview</strong> - Shows old and new values for modifications</li>
          <li><strong>Summary stats</strong> - Quick count of additions, removals, and modifications</li>
          <li><strong>Markdown report</strong> - Downloadable report for documentation</li>
        </ul>

        <h4>Use Cases</h4>
        <ul>
          <li>Review security model changes before deployment</li>
          <li>Track threat model evolution over time</li>
          <li>Audit configuration changes for compliance</li>
          <li>Document infrastructure changes for change management</li>
        </ul>
      </div>

      <div class="doc-section">
        <h3>API Reference</h3>
        <p>USecVisLib provides a REST API for programmatic access.</p>

        <h4>Visualization Endpoints</h4>
        <table class="info-table">
          <tr>
            <th>Endpoint</th>
            <th>Method</th>
            <th>Description</th>
          </tr>
          <tr>
            <td><code>/visualize/attack-tree</code></td>
            <td>POST</td>
            <td>Generate attack tree visualization</td>
          </tr>
          <tr>
            <td><code>/visualize/attack-graph</code></td>
            <td>POST</td>
            <td>Generate attack graph visualization</td>
          </tr>
          <tr>
            <td><code>/visualize/threat-model</code></td>
            <td>POST</td>
            <td>Generate DFD visualization</td>
          </tr>
          <tr>
            <td><code>/visualize/binary</code></td>
            <td>POST</td>
            <td>Generate binary visualization</td>
          </tr>
        </table>

        <h4>Analysis Endpoints</h4>
        <table class="info-table">
          <tr>
            <th>Endpoint</th>
            <th>Method</th>
            <th>Description</th>
          </tr>
          <tr>
            <td><code>/analyze/attack-tree</code></td>
            <td>POST</td>
            <td>Get attack tree statistics</td>
          </tr>
          <tr>
            <td><code>/analyze/attack-graph</code></td>
            <td>POST</td>
            <td>Get attack graph statistics</td>
          </tr>
          <tr>
            <td><code>/analyze/attack-paths</code></td>
            <td>POST</td>
            <td>Find attack paths between nodes</td>
          </tr>
          <tr>
            <td><code>/analyze/critical-nodes</code></td>
            <td>POST</td>
            <td>Analyze critical nodes by centrality</td>
          </tr>
          <tr>
            <td><code>/analyze/stride</code></td>
            <td>POST</td>
            <td>Run STRIDE threat analysis</td>
          </tr>
        </table>

        <h4>Advanced Graph Analysis Endpoints (NetworkX)</h4>
        <table class="info-table">
          <tr>
            <th>Endpoint</th>
            <th>Method</th>
            <th>Description</th>
          </tr>
          <tr>
            <td><code>/analyze/centrality</code></td>
            <td>POST</td>
            <td>Calculate betweenness, closeness, and PageRank centrality</td>
          </tr>
          <tr>
            <td><code>/analyze/graph-metrics</code></td>
            <td>POST</td>
            <td>Get graph metrics (density, diameter, cycles, SCCs)</td>
          </tr>
          <tr>
            <td><code>/analyze/chokepoints</code></td>
            <td>POST</td>
            <td>Identify critical network bottlenecks</td>
          </tr>
          <tr>
            <td><code>/analyze/attack-surface</code></td>
            <td>POST</td>
            <td>Find attack entry points and reachability</td>
          </tr>
          <tr>
            <td><code>/analyze/vulnerability-impact</code></td>
            <td>POST</td>
            <td>Calculate impact score for a specific vulnerability</td>
          </tr>
        </table>

        <h4>Batch Processing Endpoints</h4>
        <table class="info-table">
          <tr>
            <th>Endpoint</th>
            <th>Method</th>
            <th>Description</th>
          </tr>
          <tr>
            <td><code>/batch/visualize</code></td>
            <td>POST</td>
            <td>Process multiple files in batch (up to 20)</td>
          </tr>
        </table>

        <h4>Export Endpoints</h4>
        <table class="info-table">
          <tr>
            <th>Endpoint</th>
            <th>Method</th>
            <th>Description</th>
          </tr>
          <tr>
            <td><code>/export/data</code></td>
            <td>POST</td>
            <td>Export data to JSON/CSV/YAML/Markdown</td>
          </tr>
          <tr>
            <td><code>/export/sections</code></td>
            <td>POST</td>
            <td>Get available sections for export</td>
          </tr>
        </table>

        <h4>Diff/Comparison Endpoints</h4>
        <table class="info-table">
          <tr>
            <th>Endpoint</th>
            <th>Method</th>
            <th>Description</th>
          </tr>
          <tr>
            <td><code>/diff/compare</code></td>
            <td>POST</td>
            <td>Compare two configuration files</td>
          </tr>
        </table>

        <h4>Settings Endpoints</h4>
        <table class="info-table">
          <tr>
            <th>Endpoint</th>
            <th>Method</th>
            <th>Description</th>
          </tr>
          <tr>
            <td><code>/settings</code></td>
            <td>GET</td>
            <td>Get current display settings</td>
          </tr>
          <tr>
            <td><code>/settings</code></td>
            <td>PUT</td>
            <td>Update display settings (CVSS toggles)</td>
          </tr>
          <tr>
            <td><code>/settings/cvss/enable-all</code></td>
            <td>POST</td>
            <td>Enable CVSS for all visualization types</td>
          </tr>
          <tr>
            <td><code>/settings/cvss/disable-all</code></td>
            <td>POST</td>
            <td>Disable CVSS for all visualization types</td>
          </tr>
          <tr>
            <td><code>/settings/reset</code></td>
            <td>POST</td>
            <td>Reset settings to defaults</td>
          </tr>
        </table>

        <h4>Template Endpoints</h4>
        <table class="info-table">
          <tr>
            <th>Endpoint</th>
            <th>Method</th>
            <th>Description</th>
          </tr>
          <tr>
            <td><code>/templates</code></td>
            <td>GET</td>
            <td>List all available templates</td>
          </tr>
          <tr>
            <td><code>/templates/attack-tree/{id}</code></td>
            <td>GET</td>
            <td>Get attack tree template by ID</td>
          </tr>
          <tr>
            <td><code>/templates/threat-model/{id}</code></td>
            <td>GET</td>
            <td>Get threat model template by ID</td>
          </tr>
        </table>

        <h4>Threat Library Endpoints</h4>
        <table class="info-table">
          <tr>
            <th>Endpoint</th>
            <th>Method</th>
            <th>Description</th>
          </tr>
          <tr>
            <td><code>/threats/library</code></td>
            <td>GET</td>
            <td>Get paginated threat library (PyTM)</td>
          </tr>
          <tr>
            <td><code>/threats/element-types</code></td>
            <td>GET</td>
            <td>List available element types for filtering</td>
          </tr>
        </table>

        <h4>Report Endpoints</h4>
        <table class="info-table">
          <tr>
            <th>Endpoint</th>
            <th>Method</th>
            <th>Description</th>
          </tr>
          <tr>
            <td><code>/report/threat-model</code></td>
            <td>POST</td>
            <td>Generate threat model report (Markdown/HTML)</td>
          </tr>
        </table>

        <h4>Validation Endpoints</h4>
        <table class="info-table">
          <tr>
            <th>Endpoint</th>
            <th>Method</th>
            <th>Description</th>
          </tr>
          <tr>
            <td><code>/validate/attack-tree</code></td>
            <td>POST</td>
            <td>Validate attack tree structure</td>
          </tr>
          <tr>
            <td><code>/validate/attack-graph</code></td>
            <td>POST</td>
            <td>Validate attack graph structure</td>
          </tr>
        </table>

        <h4>Utility Endpoints</h4>
        <table class="info-table">
          <tr>
            <th>Endpoint</th>
            <th>Method</th>
            <th>Description</th>
          </tr>
          <tr>
            <td><code>/health</code></td>
            <td>GET</td>
            <td>Health check and version info</td>
          </tr>
          <tr>
            <td><code>/styles</code></td>
            <td>GET</td>
            <td>Get available style presets</td>
          </tr>
          <tr>
            <td><code>/formats</code></td>
            <td>GET</td>
            <td>Get supported output formats</td>
          </tr>
          <tr>
            <td><code>/engines</code></td>
            <td>GET</td>
            <td>Get available threat modeling engines</td>
          </tr>
          <tr>
            <td><code>/convert</code></td>
            <td>POST</td>
            <td>Convert between TOML/JSON/YAML</td>
          </tr>
        </table>

        <p>
          <a href="http://localhost:8000/docs" target="_blank" class="btn btn-secondary">
            View Full API Documentation
          </a>
        </p>
      </div>

      <div class="doc-section">
        <h3>Settings</h3>
        <p>Access application settings via the gear icon in the header bar.</p>

        <h4>API Connection</h4>
        <ul>
          <li><strong>Status Indicator</strong> - Shows if the API is connected</li>
          <li><strong>API URL</strong> - Current API endpoint</li>
          <li><strong>Version</strong> - API version number</li>
          <li><strong>Test Connection</strong> - Verify API connectivity</li>
        </ul>

        <h4>Module Status</h4>
        <p>Shows which visualization modules are available:</p>
        <ul>
          <li>Attack Trees</li>
          <li>Attack Graphs</li>
          <li>Threat Modeling</li>
          <li>Binary Visualization</li>
          <li>Custom Diagrams</li>
        </ul>

        <h4>Display Settings</h4>
        <ul>
          <li><strong>Default Output Format</strong> - Choose PNG, SVG, or PDF as the default</li>
          <li><strong>Theme</strong> - Dark theme (Light theme coming soon)</li>
        </ul>

        <h4>CVSS Display Settings</h4>
        <p>Control how CVSS scores appear in visualizations:</p>
        <table class="info-table">
          <tr>
            <th>Toggle</th>
            <th>Description</th>
          </tr>
          <tr>
            <td><strong>Global Toggle</strong></td>
            <td>Master on/off switch for all CVSS display. When disabled, CVSS is hidden everywhere.</td>
          </tr>
          <tr>
            <td><strong>Attack Trees</strong></td>
            <td>Show CVSS scores and severity-based coloring on attack tree nodes</td>
          </tr>
          <tr>
            <td><strong>Attack Graphs</strong></td>
            <td>Show CVSS scores and coloring on vulnerability nodes in attack graphs</td>
          </tr>
          <tr>
            <td><strong>Threat Models</strong></td>
            <td>Include CVSS scores and statistics in STRIDE analysis reports</td>
          </tr>
        </table>

        <h4>Quick Actions</h4>
        <ul>
          <li><strong>Enable All</strong> - Turn on CVSS display for all visualization types</li>
          <li><strong>Disable All</strong> - Turn off CVSS display everywhere</li>
          <li><strong>Reset to Defaults</strong> - Restore default settings (all CVSS enabled)</li>
        </ul>

        <h4>CVSS in Visualizations</h4>
        <p>When CVSS display is enabled:</p>
        <ul>
          <li><strong>Attack Trees</strong> - Nodes show CVSS score and severity label (e.g., "CVSS: 9.8 - Critical"). Nodes are color-coded by severity.</li>
          <li><strong>Attack Graphs</strong> - Vulnerability nodes display CVSS scores with severity colors.</li>
          <li><strong>Threat Models</strong> - STRIDE reports include CVSS statistics (average, max, critical/high counts) and per-threat CVSS scores.</li>
        </ul>
      </div>
    </div>
  </div>
</template>

<script setup>
</script>

<style scoped>
.documentation-panel {
  max-width: 900px;
  margin: 0 auto;
}

.doc-section {
  margin-bottom: 2rem;
  padding-bottom: 2rem;
  border-bottom: 1px solid var(--border-color);
}

.doc-section:last-child {
  border-bottom: none;
}

.doc-section h3 {
  color: var(--primary-color);
  margin-bottom: 1rem;
  font-size: 1.4rem;
}

.doc-section h4 {
  color: var(--text-color);
  margin: 1.5rem 0 0.75rem;
  font-size: 1.1rem;
}

.doc-section p {
  line-height: 1.7;
  margin-bottom: 1rem;
}

.doc-section ul {
  margin: 1rem 0;
  padding-left: 1.5rem;
}

.doc-section li {
  margin-bottom: 0.5rem;
  line-height: 1.6;
}

.code-block {
  background: var(--bg-tertiary);
  border: 1px solid var(--border-color);
  border-radius: 8px;
  padding: 1rem;
  overflow-x: auto;
  font-size: 0.85rem;
  line-height: 1.5;
}

.code-block code {
  color: var(--text-color);
  font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
}

.info-table {
  width: 100%;
  border-collapse: collapse;
  margin: 1rem 0;
}

.info-table th,
.info-table td {
  padding: 0.75rem;
  text-align: left;
  border: 1px solid var(--border-color);
}

.info-table th {
  background: var(--bg-tertiary);
  font-weight: 600;
}

.info-table code {
  background: var(--bg-tertiary);
  padding: 0.2rem 0.4rem;
  border-radius: 4px;
  font-size: 0.85rem;
}
</style>
