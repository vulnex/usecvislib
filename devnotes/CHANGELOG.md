# Changelog

All notable changes to the USecVisLib project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2025-12-22

### Added

#### BinVis Module (Full Implementation)
- `BinVis` class for binary file visualization
- Entropy analysis with sliding window (`visualize_entropy`)
- Byte frequency distribution visualization (`visualize_distribution`)
- Wind rose diagram for byte pair patterns (`visualize_windrose`)
- 2D heatmap visualization (`visualize_heatmap`)
- File statistics calculation (`get_file_stats`)
- Multiple style configurations: `bv_default`, `bv_dark`, `bv_security`

#### ThreatModeling Module (Full Implementation)
- `ThreatModeling` class for Data Flow Diagram generation
- Support for processes, data stores, external entities, and data flows
- Trust boundary visualization with cluster subgraphs
- STRIDE threat analysis (`analyze_stride`)
- Automatic STRIDE report generation (`generate_stride_report`)
- Model statistics (`get_model_stats`)
- Multiple style configurations: `tm_default`, `tm_stride`, `tm_dark`

#### CLI Enhancements
- Mode 1: Threat Modeling support (`-m 1`)
- Mode 2: Binary Visualization support (`-m 2`)
- `-v, --visualization` option for binary visualization type selection
- `-r, --report` option to generate STRIDE reports
- Improved help messages and usage examples
- Better error messages with proper exit codes

#### Testing
- `tests/test_utils.py` - 19 tests for utility functions
- `tests/test_attacktrees.py` - 15 tests for attack tree module
- `tests/test_binvis.py` - 16 tests for binary visualization
- `tests/test_threatmodeling.py` - 14 tests for threat modeling
- Total: 64 unit tests

#### Documentation
- Comprehensive README.md with:
  - Installation instructions
  - Quick start guide
  - CLI reference
  - Input format documentation for all modules
  - API reference
  - Project structure overview

#### Configuration
- `config_binvis.tml` - Binary visualization styles
- `config_threatmodeling.tml` - Threat modeling styles
- `requirements.txt` - Project dependencies
- `setup.py` - Package configuration with entry points

#### Example Files
- `tests/webapp_threatmodel.tml` - Web application threat model example

### Changed

#### AttackTrees Module
- Added type hints to all methods
- Added comprehensive docstrings
- Added error handling with `AttackTreeError` exception
- Added `get_tree_stats()` method for tree statistics
- Added `validate()` method for structure validation
- Changed to use relative imports (`from . import utils`)

#### Utils Module
- Added type hints to all functions
- Added comprehensive docstrings
- Added `ConfigError` and `FileError` exception classes
- Added `GetPackageDirectory()` function
- Added `deep_merge_dicts()` function for recursive merging
- Added `has()` and `keys()` methods to `ConfigModel`
- Improved config file path resolution (searches multiple locations)
- Changed to proper error raising instead of `sys.exit()`

#### CLI (usecvis.py)
- Complete rewrite with proper argument handling
- Added type hints and docstrings
- Added input validation functions
- Improved error handling with `error_exit()` helper

### Fixed

- **Syntax error**: Missing colon in `class BinVis()` declaration in binvis.py
- **Import errors**: Changed relative imports (`import utils`) to package imports (`from . import utils`)
- **Empty package files**: Populated `requirements.txt` and `setup.py`
- **Package initialization**: Added proper exports in `__init__.py`

---

## [0.1.1] - 2025-12-22

### Added

#### REST API (FastAPI)
- New `api/` module with FastAPI-based REST API
- **Attack Tree Endpoints**:
  - `POST /visualize/attack-tree` - Generate attack tree visualization from uploaded TOML
  - `POST /analyze/attack-tree` - Get attack tree statistics
  - `POST /validate/attack-tree` - Validate attack tree structure
- **Threat Modeling Endpoints**:
  - `POST /visualize/threat-model` - Generate DFD visualization from uploaded TOML
  - `POST /analyze/threat-model` - Get threat model statistics
  - `POST /analyze/stride` - Perform STRIDE threat analysis
- **Binary Visualization Endpoints**:
  - `POST /visualize/binary` - Generate binary visualization from uploaded file
  - `POST /analyze/binary` - Get binary file statistics
- **Configuration Endpoints**:
  - `GET /styles` - Get available style presets
  - `GET /formats` - Get supported output formats
  - `GET /health` - API health check
- Pydantic schemas for request/response validation (`api/schemas.py`)
- CORS middleware for cross-origin requests
- Automatic OpenAPI documentation at `/docs`
- File upload support with temporary file handling

#### Dependencies
- Added `fastapi>=0.109.0`
- Added `uvicorn[standard]>=0.27.0`
- Added `python-multipart>=0.0.6`
- Added `pydantic>=2.5.0`

#### Docker Support
- `Dockerfile` - Multi-stage Docker image with:
  - Python 3.12 slim base image
  - System Graphviz installation for rendering
  - Non-root user for security
  - Health check endpoint monitoring
  - Both API and CLI available
- `docker-compose.yml` - Docker Compose configuration with:
  - `usecvislib-api` service for REST API
  - `usecvislib-cli` service for CLI commands (profile-based)
  - Volume mounts for input/output files
  - Health checks and restart policies
- `.dockerignore` - Optimized build context

#### Vue.js Frontend
- New `frontend/` directory with Vue 3 application
- **Components**:
  - `AttackTreePanel.vue` - Attack tree upload, visualization, analysis, and validation
  - `ThreatModelPanel.vue` - Threat model DFD generation with STRIDE analysis
  - `BinaryVisPanel.vue` - Binary file visualization with multiple chart types
- **Features**:
  - Drag-and-drop file upload
  - Real-time API status indicator
  - Multiple visualization styles and output formats
  - Interactive STRIDE threat report with expandable categories
  - File statistics display (entropy, byte distribution)
  - Image preview and download
  - Responsive dark theme UI
- **Tech Stack**:
  - Vue 3 with Composition API
  - Vite for development and building
  - Axios for API communication
  - CSS custom properties for theming

---

## [0.1.2] - 2025-12-23

### Added

#### OWASP PyTM Integration
- Added `ThreatModelEngine` enum to support multiple engines
- `PyTMWrapper` class for OWASP PyTM integration
- Engine selector in threat modeling API and frontend
- Support for PyTM-specific attributes (authenticatesSource, sanitizesInput, isEncrypted, etc.)
- `is_pytm_available()` class method to check PyTM installation
- `/engines` API endpoint to list available threat modeling engines

#### Frontend Improvements
- **Documentation Tab** - Comprehensive in-app documentation with:
  - Getting started guide
  - Attack tree TOML format reference
  - Threat modeling TOML format with PyTM attributes
  - Binary visualization interpretation guide
  - API reference
- **Settings Tab** - API connection status moved from header
- **Clean Button** - Reset all visualization tabs with one click
- **Timestamped Downloads** - Files now download with format `{type}_{YYYYMMDD_HHMMSS}.{ext}`
- Vue provide/inject pattern for clean trigger propagation

### Changed

#### API Endpoints
- `/visualize/threat-model` now accepts `engine` query parameter (usecvislib or pytm)
- Threat model styles renamed: `default` → `tm_default`, `stride` → `tm_stride`, `dark` → `tm_dark`
- Attack tree styles renamed: `default` → `at_default`, etc.
- Binary vis styles renamed: `default` → `bv_default`, etc.

### Fixed

#### Security Fixes
- **DOT Injection (Critical)** - Added `_escape_dot_string()` and `_sanitize_node_id()` methods to escape user input in graph generation, preventing arbitrary DOT code injection
- **TOML/File Size Injection (Critical)** - Added file size limits: 1MB for TOML files, 50MB for binary files; returns HTTP 413 on oversized uploads
- **CORS Misconfiguration (High)** - Changed from `allow_origins=["*"]` to restricted whitelist; configurable via `ALLOWED_ORIGINS` environment variable; restricted methods to GET/POST/OPTIONS
- **Temp File Cleanup (Medium)** - Added background task cleanup for both input and output files after response; prevents temp directory accumulation

#### Bug Fixes
- Fixed "0" appearing in style dropdown menus (removed `NONE = "0"` from enums)
- Fixed PyTM argparse conflict by using direct DOT generation instead of `process()` method
- Fixed Docker container permissions with `chown -R appuser:appuser /app`

### Security
- Input validation on all user-provided strings in DOT graphs
- Node IDs restricted to alphanumeric characters, underscores, and hyphens
- File uploads validated for size before processing
- CORS restricted to localhost development origins by default
- Background cleanup prevents sensitive data persistence in temp files

---

## [0.1.3] - 2025-12-23

### Added

#### API Quick Wins
- **Structured Logging** - Request IDs, client IP, timing, configurable via `LOG_LEVEL` environment variable
- **Rate Limiting** - Configurable limits using slowapi: 10/min for visualization, 20/min for analysis endpoints; configurable via `RATE_LIMIT_VISUALIZE` and `RATE_LIMIT_ANALYZE` environment variables
- **Security Headers Middleware** - CSP, X-Frame-Options (DENY), X-Content-Type-Options (nosniff), Referrer-Policy (strict-origin-when-cross-origin), Permissions-Policy
- **SSE Progress Endpoint** - `GET /progress/{job_id}` for real-time Server-Sent Events progress streaming on long operations
- **Templates API** - `GET /templates` lists all available templates; `GET /templates/attack-tree/{id}` and `GET /templates/threat-model/{id}` fetch template content

#### New Visualization Styles
- **Attack Tree Styles (10 new)**: `at_corporate`, `at_neon`, `at_pastel`, `at_forest`, `at_fire`, `at_blueprint`, `at_sunset`, `at_hacker`, `at_minimal`, `at_plain`
- **Threat Model Styles (9 new)**: `tm_corporate`, `tm_neon`, `tm_minimal`, `tm_ocean`, `tm_sunset`, `tm_forest`, `tm_blueprint`, `tm_hacker`, `tm_plain`
- **Binary Visualization Styles (9 new)**: `bv_ocean`, `bv_forest`, `bv_sunset`, `bv_cyber`, `bv_minimal`, `bv_corporate`, `bv_fire`, `bv_purple`, `bv_rainbow`
- **Plain Styles** - `at_plain` and `tm_plain` styles with no colors (black outlines only), ideal for printing and documents

#### Property-Aware Threat Modeling
- **Full pytm Property Support** - Threat model elements now support comprehensive security properties compatible with OWASP PyTM:
  - **Processes**: `isServer`, `authenticatesSource`, `authenticatesDestination`, `sanitizesInput`, `encodesOutput`, `implementsCSRFToken`, `implementsNonce`, `checksInputBounds`, `hasAccessControl`, `isHardened`, `handlesResourceConsumption`
  - **Data Stores**: `isSQL`, `isEncrypted`, `hasAccessControl`, `storesPII`, `storesCredentials`, `hasBackup`, `isAuditLogged`, `isShared`
  - **Data Flows**: `isEncrypted`, `authenticatesSource`, `authenticatesDestination`, `checksDestinationRevocation`, `sanitizesInput`, `isPII`, `isCredentials`, `data` (classification), `note`
  - **External Entities**: `isAdmin`, `isTrusted`
  - **Trust Boundaries**: `isNetworkBoundary`, `trustLevel` (0-100)
- **Property-Aware STRIDE Analysis** - Threat detection now considers element properties for context-specific threats with severity levels
- **PyTM Wrapper Enhancement** - Full property mapping when using PyTM engine

#### New Threat Model Templates (5)
- **`ecommerce_platform.tml`** - Full e-commerce platform with PCI-DSS focus (5 externals, 9 processes, 7 datastores, 20+ dataflows)
- **`healthcare_system.tml`** - HIPAA-compliant EHR system with PHI protection (8 externals, 9 processes, 7 datastores, 25+ dataflows)
- **`banking_api.tml`** - High-security financial API with PSD2/PCI compliance (10 externals, 12 processes, 8 datastores, 30+ dataflows)
- **`cicd_pipeline.tml`** - DevSecOps pipeline with supply chain security (7 externals, 13 processes, 7 datastores, 25+ dataflows)
- **`saas_multitenant.tml`** - Multi-tenant SaaS with tenant isolation (8 externals, 12 processes, 10 datastores, 35+ dataflows)

#### Dependencies
- Added `slowapi>=0.1.9` for rate limiting

### Changed
- Updated `microservices_architecture.tml` template with full property support
- Dockerfile now includes templates directory
- STRIDE analysis generates more specific threats based on security property posture
- **Style Precedence Fix** - Selected style now takes precedence over template-defined attributes, ensuring consistent styling regardless of template content

---

## [0.1.4] - 2025-12-23

### Added

#### TOML Editor with Syntax Highlighting
- **TomlEditor.vue Component** - Reusable CodeMirror 6-based editor component with:
  - TOML syntax highlighting (comments, strings, numbers, tables, keys, dates)
  - Line numbers and active line highlighting
  - Dark theme matching existing UI design
  - Copy to clipboard and Clear buttons
  - Configurable min/max height
- **Live Validation** - Real-time TOML validation as you type with 300ms debounce:
  - Syntax validation using smol-toml parser
  - Attack tree structure validation (checks for [tree], [nodes], [edges] sections)
  - Threat model structure validation (checks for [model], [dataflows], elements)
  - Errors displayed inline and in summary below editor
  - Warnings (amber) vs errors (red) differentiation
- **Edit Before Generate** - Users can now modify TOML content before generating visualizations
- **File Actions** - "Change File" button to upload a different file

#### Frontend Utility Modules
- `frontend/src/utils/toml-language.js` - TOML StreamLanguage parser for CodeMirror 6
- `frontend/src/utils/editor-theme.js` - Dark theme with syntax highlighting colors
- `frontend/src/utils/toml-validator.js` - TOML validation with structure checking

#### API Service Extensions
- `visualizeAttackTreeFromContent()` - Generate visualization from text content
- `analyzeAttackTreeFromContent()` - Analyze from text content
- `validateAttackTreeFromContent()` - Validate from text content
- `visualizeThreatModelFromContent()` - Generate DFD from text content
- `analyzeThreatModelFromContent()` - Analyze from text content
- `analyzeStrideFromContent()` - STRIDE analysis from text content

#### Dependencies
- Added `@codemirror/state@^6.4.0`
- Added `@codemirror/view@^6.23.0`
- Added `@codemirror/language@^6.10.0`
- Added `@codemirror/commands@^6.3.0`
- Added `@codemirror/search@^6.5.0`
- Added `@codemirror/lint@^6.5.0`
- Added `@lezer/highlight@^1.2.0`
- Added `smol-toml@^1.1.0`

### Changed
- **AttackTreePanel.vue** - Integrated TomlEditor, file content read with FileReader before display
- **ThreatModelPanel.vue** - Integrated TomlEditor with threat-model validation type
- Generate/Analyze/Validate buttons now disabled until TOML is valid (no syntax errors)

### Fixed
- **Editor Clear Bug** - Fixed issue where both upload area and editor displayed after clicking Clear button (changed `v-if="editorContent !== null"` to `v-if="editorContent"`)

---

## [0.1.5] - 2025-12-23

### Added

#### Multi-Format Configuration Support (JSON & YAML)
- **Backend Format Support** - Configuration files can now be in TOML, JSON, or YAML format:
  - Auto-detection from file extension (`.toml`, `.tml`, `.json`, `.yaml`, `.yml`)
  - Content-based format detection as fallback
  - Unified parsing with `ReadConfigFile()` function
  - Format conversion utilities: `serialize_to_toml()`, `serialize_to_json()`, `serialize_to_yaml()`
  - Cross-format conversion with `convert_format()`
- **CLI Updates** - Accepts JSON and YAML files for attack trees and threat models
- **API Updates**:
  - All endpoints now accept `.json`, `.yaml`, `.yml` files in addition to TOML
  - Templates endpoint returns format type for each template
  - API description updated to reflect multi-format support
- **Frontend Multi-Format Editor**:
  - **ConfigEditor.vue** - New component replacing TomlEditor with format detection
  - Format badge showing detected format (TOML/JSON/YAML) with color coding
  - Syntax highlighting for all three formats using CodeMirror 6 language modes
  - Live validation for all formats with structure checking
  - File upload accepts `.tml`, `.toml`, `.json`, `.yaml`, `.yml` extensions
- **Template Files** - Added JSON and YAML versions of templates for testing:
  - `templates/attack-trees/ransomware_attack.json`
  - `templates/attack-trees/ransomware_attack.yaml`
  - `templates/threat-models/cicd_pipeline.json`
  - `templates/threat-models/cicd_pipeline.yaml`

#### Frontend Utility Modules
- `frontend/src/utils/config-validator.js` - Multi-format validation with:
  - `detectFormat()` - Format detection from content and filename
  - `parseContent()` - Unified parsing for all formats
  - `validateConfig()` - Syntax validation for any format
  - `validateAttackTreeStructure()` - Structure validation with format parameter
  - `validateThreatModelStructure()` - Structure validation with format parameter

#### Dependencies
- Added `pyyaml>=6.0` to requirements.txt
- Added `js-yaml@^4.1.0` to frontend
- Added `@codemirror/lang-json@^6.0.1` to frontend
- Added `@codemirror/lang-yaml@^6.1.0` to frontend

### Changed
- **utils.py** - Added comprehensive format detection and parsing infrastructure
- **AttackTrees.load()** - Now uses `ReadConfigFile()` for multi-format support
- **ThreatModeling.load()** - Now uses `ReadConfigFile()` for multi-format support
- **AttackTreePanel.vue** - Updated to use ConfigEditor, accepts multiple formats
- **ThreatModelPanel.vue** - Updated to use ConfigEditor, accepts multiple formats
- **api.js** - API functions now accept configFormat parameter for proper file extension handling
- API version bumped to 0.1.4

---

## [0.2.0] - 2025-12-23

### Added

#### Multi-Format Parser Unit Tests
- **TestDetectFormat** - 7 tests for file extension format detection (TOML, JSON, YAML, case-insensitive)
- **TestDetectFormatFromContent** - 4 tests for content-based format detection
- **TestParseJson** - 3 tests for JSON parsing (valid, invalid, empty)
- **TestParseYaml** - 4 tests for YAML parsing (valid, invalid, empty, non-dict)
- **TestReadConfigFile** - 6 tests for multi-format file reading with format override
- **TestSerializeFunctions** - 5 tests for TOML/JSON/YAML serialization
- **TestConvertFormat** - 6 tests for format conversion including roundtrip testing

#### Test Data Files
- `tests/test_attacktree.json` - JSON format attack tree test file
- `tests/test_attacktree.yaml` - YAML format attack tree test file

### Changed
- Total test count increased from 55 to 87 tests (32 new tests)
- Test coverage now includes all multi-format parser functions

---

## [0.2.1] - 2025-12-23

### Added

#### Format Conversion API
- **`POST /convert` Endpoint** - Convert configuration files between TOML, JSON, and YAML formats:
  - Auto-detects source format from file extension
  - Returns converted content with suggested filename
  - Rate limited at 20 requests/minute
  - Full error handling with descriptive messages

#### API Schema Extensions
- **`ConfigFormat` Enum** - Defines supported formats (toml, json, yaml)
- **`ConvertResponse` Model** - Response schema with content, source_format, target_format, filename

#### Frontend Format Conversion
- **ConvertPanel.vue Component** - New panel for format conversion with:
  - Drag-and-drop file upload
  - Auto-detected source format display with color-coded badge
  - Target format dropdown (filters out source format)
  - Preview of converted content with syntax highlighting
  - Download button with suggested filename
  - Copy to clipboard functionality
- **Convert Tab** - New tab in main navigation with 🔄 icon
- **API Service Methods**:
  - `convertFormat(file, targetFormat)` - Convert uploaded file
  - `convertFormatFromContent(content, sourceFormat, targetFormat)` - Convert from text
  - `downloadTextFile(content, filename)` - Download text as file

### Changed
- Updated `api/main.py` imports to include `detect_format` and `convert_format` utilities
- App.vue now includes ConvertPanel in tab navigation
- API version updated to reflect new endpoint

---

## [0.2.2] - 2025-12-23

### Added

#### Comprehensive PyTM Support
- **Report Generation** - Generate comprehensive threat model reports:
  - `generate_markdown_report()` - Markdown format with executive summary, system components, and STRIDE analysis
  - `generate_html_report()` - Styled HTML with CSS, stat cards, threat cards, and expandable STRIDE sections
  - API endpoint `POST /report/threat-model` with format parameter (markdown/html)
  - Frontend "Generate Report" button in Threat Model panel with format selector

#### Threat Library Access
- **`get_threat_library()` Method** - Access PyTM's built-in threat database
- **`get_threats_by_element_type()` Method** - Filter threats by target element type
- **API Endpoints**:
  - `GET /threats/library` - Paginated threat library with element type filtering
  - `GET /threats/element-types` - List available element types for filtering
- **Schema Extensions**:
  - `ThreatLibraryItem` - Single threat with id, description, severity, target, mitigations
  - `ThreatLibraryResponse` - Paginated response with total count
  - `ReportFormat` enum (markdown, html)
  - `ReportResponse` - Report content with format and filename

#### Enhanced Property Mapping
- **Process/Server Properties** (38 properties):
  - Authentication: `authenticatesSource`, `authenticatesDestination`, `authorizesSource`, `implementsAuthenticationScheme`, `usesSessionTokens`, `implementsPasswordPolicy`
  - Input/Output: `sanitizesInput`, `validatesInput`, `validatesHeaders`, `encodesOutput`, `checksInputBounds`, `implementsServerSideValidation`, `implementsStrictHTTPValidation`
  - Security Controls: `implementsCSRFToken`, `implementsNonce`, `handlesResourceConsumption`, `hasAccessControl`, `implementsPOLP`, `isHardened`, `disablesdebugCode`
  - Network: `usesLatestTLSversion`, `usesVPN`, `protocol`, `isEncrypted`
  - Infrastructure: `usesEnvironmentVariables`, `usesCache`, `implementsAPI`, `logsAllActions`
  - Metadata: `inScope`, `OS`, `Environment`, `providesConfidentiality`, `providesIntegrity`

- **Datastore Properties** (17 properties):
  - Type: `isSQL`, `type`
  - Security: `isEncrypted`, `isShared`, `hasAccessControl`, `isHardened`, `implementsPOLP`
  - Data Classification: `storesPII`, `storesCredentials`, `storesLogData`, `storesSensitiveData`
  - Resilience: `hasBackup`, `isResilient`
  - Audit: `isAuditLogged`, `validatesInput`
  - Infrastructure: `usesEnvironmentVariables`, `usesFileSystem`, `maxClassification`

- **Dataflow Properties** (19 properties):
  - Encryption: `isEncrypted`, `usesLatestTLSversion`, `usesVPN`
  - Authentication: `authenticatesSource`, `authenticatesDestination`, `authorizesSource`, `implementsAuthenticationScheme`, `checksDestinationRevocation`
  - Data Handling: `sanitizesInput`, `validatesInput`, `validatesHeaders`
  - Classification: `isPII`, `isCredentials`, `maxClassification`
  - Network: `srcPort`, `dstPort`, `isResponse`, `responseTo`, `order`

- **External Entity Properties** (9 properties):
  - `isAdmin`, `isHuman`, `isTrusted`, `inScope`
  - `providesSourceAuthentication`, `providesDestinationAuthentication`
  - `protocol`, `data`, `handlesInput`, `sanitizesInput`

#### Improved Boundary Crossing Detection
- Fixed trust boundary crossing detection to properly identify flows between elements in different boundaries or between boundary and non-boundary elements
- Added `crosses_trust_boundary()` helper function for accurate boundary analysis
- Information Disclosure threats now include boundary crossing warnings

#### Comprehensive PyTM Test Suite (14 tests)
- **TestPyTMWrapper** (4 tests) - Initialization, availability checking, static methods
- **TestPyTMReportGeneration** (4 tests) - Markdown structure, content, HTML structure, styling
- **TestPyTMThreatLibrary** (2 tests) - Library access, element type filtering
- **TestPyTMPropertyMapping** (4 tests) - Process, datastore, external entity mapping, boundary assignment

### Changed
- Total test count increased from 97 to 111 tests (14 new PyTM tests)
- `PyTMWrapper.build_model()` now maps 90%+ of PyTM element properties
- STRIDE analysis now detects boundary crossing for Information Disclosure threats
- External entities can be created as Actor or ExternalEntity based on `isHuman` property

### Fixed
- Boundary crossing detection no longer relies only on trust levels - now correctly detects flows between different boundaries
- STRIDE test for boundary crossing (`test_stride_boundary_crossing`) now passes

---

## [0.2.3] - 2025-12-24

### Added

#### VULNEX Copyright Headers
- Added standardized VULNEX copyright headers to all source code files:
  - **Python source files** (7 files): `src/usecvislib/__init__.py`, `usecvis.py`, `utils.py`, `attacktrees.py`, `attackgraphs.py`, `threatmodeling.py`, `binvis.py`
  - **API files** (3 files): `api/__init__.py`, `main.py`, `schemas.py`
  - **Test files** (6 files): `tests/__init__.py`, `test_binvis.py`, `test_utils.py`, `test_attackgraphs.py`, `test_attacktrees.py`, `test_threatmodeling.py`
  - **JavaScript files** (6 files): `main.js`, `services/api.js`, `utils/toml-language.js`, `utils/editor-theme.js`, `utils/toml-validator.js`, `utils/config-validator.js`
  - **Vue components** (9 files): `App.vue`, `AttackTreePanel.vue`, `AttackGraphPanel.vue`, `ThreatModelPanel.vue`, `BinaryVisPanel.vue`, `ConvertPanel.vue`, `DocumentationPanel.vue`, `SettingsPanel.vue`, `ZoomableImage.vue`
- Header includes: VULNEX branding, filename, author (Simon Roses Femerling), creation date, last modified date, version, Apache-2.0 license, copyright notice, and website URL

#### Attack Graphs Module
- **`attackgraphs.py`** - New module for attack graph visualization and analysis:
  - `AttackGraphs` class with full visualization pipeline
  - `load()` - Load attack graph from TOML, JSON, or YAML
  - `Render()` - Generate Graphviz digraph
  - `draw()` - Save visualization to file
  - `BuildAttackGraph()` - Complete build pipeline
  - `find_attack_paths(source, target)` - DFS-based path finding
  - `shortest_path(source, target)` - BFS-based shortest path
  - `get_graph_stats()` - Graph statistics and CVSS analysis
  - `analyze_critical_nodes(top_n)` - Degree centrality analysis
  - `validate()` - Structure validation

#### Attack Graph Node Types
- **Host Nodes** - Network machines (box3d shape)
- **Vulnerability Nodes** - CVEs and weaknesses (diamond shape)
- **Privilege Nodes** - Access levels (ellipse shape)
- **Service Nodes** - Running services (component shape)

#### Attack Graph Edge Types
- **Network Edges** - Connectivity between hosts (dashed style)
- **Exploit Edges** - Attack preconditions/postconditions (bold style)

#### Path Finding Algorithms
- **DFS All Paths** - Find all attack paths between nodes with cycle detection
- **BFS Shortest Path** - Find shortest attack path using Breadth-First Search
- **Adjacency List Building** - Efficient graph representation for analysis

#### Critical Node Analysis
- Degree centrality scoring (in-degree + out-degree)
- Node type classification
- Top-N ranking by criticality score

#### Attack Graph Styles (10 presets)
- `ag_default` - Clean professional look
- `ag_dark` - Dark theme with high contrast
- `ag_security` - Red/orange threat-focused
- `ag_network` - Cisco-like network diagram style
- `ag_minimal` - Clean minimalist
- `ag_neon` - Cyberpunk neon style
- `ag_corporate` - Professional enterprise
- `ag_hacker` - Matrix-inspired green on black
- `ag_blueprint` - Technical blueprint style
- `ag_plain` - Black outlines only (for printing)

#### CLI Mode 3
- `usecvis -m 3 -i graph.toml -o output` - Generate attack graph
- `-p, --paths <src,tgt>` - Find attack paths between nodes
- `-c, --critical` - Analyze critical nodes
- Statistics output (hosts, vulnerabilities, CVSS scores, etc.)

#### API Endpoints (5 new)
- `POST /visualize/attack-graph` - Generate attack graph visualization
- `POST /analyze/attack-graph` - Get graph statistics
- `POST /analyze/attack-paths` - Find paths between nodes
- `POST /analyze/critical-nodes` - Analyze critical nodes
- `POST /validate/attack-graph` - Validate graph structure

#### API Schemas
- `AttackGraphStyle` enum - 10 style presets
- `AttackGraphRequest` - Visualization request model
- `GraphStats` - Graph statistics response
- `CriticalNode` - Critical node analysis result
- `AttackPath` - Single attack path
- `AttackPathsResponse` - Path finding response

#### Frontend Attack Graph Panel
- **AttackGraphPanel.vue** - Full-featured attack graph interface:
  - Drag-and-drop file upload (TOML, JSON, YAML)
  - Style and format selection
  - Path analysis inputs (source/target)
  - Critical node analysis
  - Statistics display with CVSS information
  - Path visualization with step count
  - Critical node ranking display

#### Example Templates (3)
- `templates/attack-graphs/corporate_network.tml` - Corporate network intrusion scenario
- `templates/attack-graphs/cloud_infrastructure.tml` - AWS/Cloud attack paths
- `templates/attack-graphs/simple_network.tml` - Basic learning example

#### Unit Tests (30+ new)
- `TestAttackGraphsInit` - Initialization tests
- `TestAttackGraphsLoad` - File loading tests
- `TestAttackGraphsRender` - Rendering tests
- `TestAttackGraphsDraw` - Output generation tests
- `TestAttackGraphsStats` - Statistics tests
- `TestAttackGraphsPathFinding` - Path finding algorithm tests
- `TestAttackGraphsCriticalNodes` - Critical node analysis tests
- `TestAttackGraphsValidation` - Validation tests
- `TestAttackGraphsFormats` - Multi-format support tests

#### Zoomable Visualizations
- **ZoomableImage.vue Component** - New reusable component for all visualization panels:
  - Zoom in/out buttons (+/−) with 25% step increments
  - Zoom range from 25% to 500%
  - Reset button (⟲) to return to 100% and reset pan
  - Fit to view button (⊡) to scale image to container
  - Mouse wheel zoom support
  - Drag to pan when zoomed in
  - Zoom level percentage indicator
- Integrated into AttackTreePanel, AttackGraphPanel, and ThreatModelPanel

#### Documentation Updates
- **DocumentationPanel.vue** - Comprehensive documentation overhaul:
  - Added Attack Graphs section with TOML format example
  - Added Supported File Formats section (TOML, JSON, YAML)
  - Added Visualization Controls section (zoom features)
  - Added Format Conversion section with usage guide
  - Reorganized API Reference into Visualization, Analysis, and Utility endpoints
  - Updated Getting Started to list all 4 modules

#### Settings Updates
- **SettingsPanel.vue** - Added Attack Graphs module status card with 🕸️ icon
- Updated frontend version display to v0.2.3

### Changed
- `__init__.py` - Added `AttackGraphs` and `AttackGraphError` exports
- `api/main.py` - Added attack_graphs to health check modules
- `api/schemas.py` - Added attack graph request/response models
- `/styles` endpoint now returns attack_graph styles
- App.vue - Added Attack Graphs tab with 🕸️ icon
- Frontend version updated to v0.2.3
- Library version updated to 0.2.3
- Test files now skip graphviz-dependent tests when `dot` executable is not installed

### Fixed
- **TOML Array Format Handling** - Fixed "unhashable type: 'dict'" error when using TOML array syntax (`[[hosts]]`) in attack graph templates:
  - Added `_normalize_data()` method to convert array format to dict format keyed by `id`
  - Supports both `[[section]]` array syntax and `[section.id]` dict syntax
  - Handles both `affected_host` and `host` keys for vulnerabilities
  - Supports both singular (`precondition`) and plural (`preconditions`) keys for exploits
- **Exploit Vulnerability Validation** - `validate()` now checks that exploit `vulnerability` field references an existing vulnerability
- **STRIDE Category Icons** - Fixed HTML entities (e.g., `&#x1F3AD;`) displaying as text instead of emojis by using actual Unicode characters
- **API Documentation (Swagger UI)** - Fixed CSP blocking Swagger UI resources:
  - Updated `connect-src` to allow `cdn.jsdelivr.net` for source maps
  - Updated API docs links to point directly to backend (`http://localhost:8000/docs`)
  - Added `root_path` support via `API_ROOT_PATH` environment variable
  - Updated API version to 0.2.3

---

## [0.2.4] - 2025-12-25

### Added

#### Phase 5: Library Improvements (Python Library)

**Result Classes**
- `RenderResult` - Immutable result from rendering operations with output path, format, dimensions, and success status
- `AnalysisResult` - Analysis operation results with statistics, validation errors, warnings, and metadata
- `ValidationResult` - Validation results with valid flag, errors list, and warnings list
- `BatchResult` - Batch processing results with total, success/failure counts, individual results, and aggregate statistics

**Fluent Interface (Builder Pattern)**
- `AttackTreeBuilder` - Chainable builder for attack trees: `AttackTreeBuilder().name("Tree").root("root").add_node(...).add_edge(...).style("at_neon").build()`
- `AttackGraphBuilder` - Chainable builder for attack graphs with hosts, vulnerabilities, services, privileges, and exploits
- `ThreatModelBuilder` - Chainable builder for threat models with processes, datastores, externals, dataflows, and boundaries
- All builders support `.to_dict()`, `.to_toml()`, `.to_json()`, `.to_yaml()`, `.validate()`, and `.build()` methods

**Batch Processing (`batch.py`)**
- `BatchProcessor` class - Process multiple files in batch with configurable concurrency
- Support for all visualization types (attack_tree, attack_graph, threat_model, binary)
- Progress callbacks for real-time status updates
- Aggregate statistics collection across all processed files
- Error handling with individual file error tracking

**Export Functionality (`exporters.py`)**
- `Exporter` class - Static methods for data export: `to_json()`, `to_csv()`, `to_yaml()`, `to_markdown_table()`
- `ExportMixin` - Mixin class for visualization classes with `export_json()`, `export_csv()`, `get_exportable_sections()`
- `ReportGenerator` - Generate comprehensive reports in JSON, YAML, CSV, and Markdown formats

**Diff/Comparison (`diff.py`)**
- `VisualizationDiff` class - Compare two visualization configurations
- `Change` dataclass - Represents a single change with type, path, old_value, new_value
- `ChangeType` enum - ADDED, REMOVED, MODIFIED, UNCHANGED
- `DiffResult` dataclass - Complete diff results with summary, filtering methods, and report generation
- Deep comparison of nested structures with dot-notation paths
- List comparison using ID fields for smart matching
- Markdown and JSON report generation
- Path filtering with `ignore_paths` parameter

**Async Support (`async_support.py`)**
- `AsyncVisualization` - Async wrapper for any visualization class
- `async_wrap()` - Function to wrap sync visualizations for async use
- `AsyncBatchProcessor` - Async batch processing with semaphore-based concurrency control
- `process_files_async()` - Convenience function for async file processing
- `AsyncContextManager` - Context manager for automatic cleanup

**Constants and Enums (`constants.py`)**
- `VisualizationMode` - Enum for visualization types
- `OutputFormat` - Enum for output formats (PNG, PDF, SVG)
- `StylePrefix` - Enum for style prefixes (at_, ag_, tm_, bv_)
- `DEFAULT_STYLES`, `ALL_STYLES`, `STYLE_DESCRIPTIONS` - Style constants
- `FILE_LIMITS`, `RATE_LIMITS` - Configuration constants

**Security Utilities (`security.py`)**
- `sanitize_node_id()` - Sanitize node IDs for safe graph rendering
- `escape_dot_label()` - Escape special characters in DOT labels
- `validate_file_size()` - Validate file sizes against limits
- `is_safe_path()` - Check for path traversal attacks
- `sanitize_filename()` - Sanitize filenames for safe storage
- `InputValidator` - Class with validation methods for all input types

**Caching Utilities (`cache.py`)**
- `cached_result` decorator - Cache method results with automatic invalidation
- `ContentCache` - Content-addressable cache with TTL and size limits
- `StyleCache` - Specialized cache for style configurations
- Thread-safe implementations with lock-based synchronization

**Exception Hierarchy (`exceptions.py`)**
- `UsecvislibError` - Base exception class
- `ConfigurationError` - Configuration-related errors
- `RenderError` - Rendering failures
- `ValidationError` - Validation failures with details
- `FileError` - File I/O errors
- `FormatError` - Format conversion errors
- `BatchError` - Batch processing errors with partial results

#### API Updates

**New Endpoints**
- `POST /batch/visualize` - Batch process multiple files with progress tracking and aggregate statistics
- `POST /export/data` - Export configuration data to JSON, CSV, YAML, or Markdown
- `POST /export/sections` - Get available exportable sections from a configuration file
- `POST /diff/compare` - Compare two configuration files with detailed change tracking

**New Schemas (`api/schemas.py`)**
- `BatchItemResult` - Individual file result in batch processing
- `BatchResponse` - Complete batch processing response with summary
- `ExportFormat` enum - JSON, CSV, YAML, MARKDOWN
- `ExportResponse` - Export operation response
- `ChangeType` enum - ADDED, REMOVED, MODIFIED
- `ChangeItem` - Single change in diff
- `DiffSummary` - Summary of changes (added, removed, modified, total)
- `DiffResponse` - Complete diff response with changes list and optional report
- `ValidationSeverity` enum - ERROR, WARNING, INFO
- `ValidationIssue` - Single validation issue
- `ValidationResponse` - Enhanced validation response with issue list

#### Frontend Updates

**New API Service Functions (`services/api.js`)**
- `batchVisualize(mode, files, format, style, collectStats, onProgress)` - Batch process files
- `downloadBatchResults(results)` - Download batch results
- `exportData(file, exportFormat, section, includeStats)` - Export data
- `exportDataFromContent(content, configFormat, exportFormat, section, includeStats)` - Export from content
- `getExportSections(file)` - Get exportable sections
- `getExportSectionsFromContent(content, configFormat)` - Get sections from content
- `compareFiles(oldFile, newFile, ignorePaths, generateReport)` - Compare files
- `compareContents(oldContent, newContent, configFormat, ignorePaths, generateReport)` - Compare contents
- `getDiffSummary(oldFile, newFile)` - Get diff summary

**New Vue Components**
- `BatchPanel.vue` - Multi-file batch processing with:
  - Drag-and-drop multiple file upload
  - Visualization mode selector (Attack Tree, Attack Graph, Threat Model, Binary)
  - Progress bar with file count
  - Results list with success/failure indicators
  - Aggregate statistics display
- `ExportPanel.vue` - Data export interface with:
  - File upload with section detection
  - Format selector (JSON, CSV, YAML, Markdown)
  - Section selector for CSV/Markdown exports
  - Export preview with syntax highlighting
  - Download button
- `ComparePanel.vue` - Configuration comparison with:
  - Side-by-side file upload (original and modified)
  - Visual diff display with color-coded changes
  - Change summary (added, removed, modified counts)
  - Markdown report generation and download

**App.vue Updates**
- Added Batch tab with 📦 icon
- Added Export tab with 📤 icon
- Added Compare tab with 🔀 icon

#### Documentation Updates

**CLI_GUIDE.md**
- Added Batch Processing section with examples
- Added Configuration Comparison section with examples

**PYTHON_API.md**
- Expanded from ~1,250 to 2,106 lines
- Added Fluent Interface / Builder Pattern section
- Added Result Classes section
- Added Batch Processing section
- Added Export Functionality section
- Added Async Support section
- Added Diff/Comparison section
- Added Constants and Enums section
- Added Security Utilities section
- Added Caching Utilities section
- Added Exception Hierarchy section

#### Unit Tests (70+ new tests)
- `test_batch.py` - BatchProcessor, BatchResult tests
- `test_builders.py` - All builder classes tests
- `test_result_classes.py` - Result class tests
- `test_exporters.py` - Exporter, ExportMixin, ReportGenerator tests
- `test_diff.py` - VisualizationDiff, DiffResult tests
- `test_async.py` - AsyncVisualization, AsyncBatchProcessor tests
- Total test count: 431 tests passing

### Changed
- Library version updated to 0.2.4
- API version updated to 0.2.4
- Frontend version updated to 0.2.4

---

## [0.2.5] - 2025-12-25

### Added

#### Tab State Persistence (Keep-Alive)
- **Vue Keep-Alive Integration** - Tab components now preserve their state when switching between tabs:
  - Generated visualizations persist when navigating away and returning
  - Form inputs, editor content, and selections are maintained
  - Implemented using Vue's `<keep-alive>` wrapper with dynamic components
  - `currentComponent` computed property maps active tab to component
  - `currentProps` computed property provides correct props per component
- **Clean Button** - Global reset button in header clears all tab states via `cleanTrigger` inject/provide pattern

#### Collapsible Code Editor
- **ConfigEditor.vue Enhancement** - Added fold/collapse functionality to code editors:
  - Collapse button (▼/▶) in editor header to hide/show editor content
  - Click anywhere on collapsed header to expand
  - "(click to expand)" hint shown when collapsed
  - Validation summary and success messages hidden when collapsed
  - Reduces visual clutter when reviewing generated visualizations
- Applied to Attack Tree, Attack Graph, and Threat Model panels

#### Template Metadata Fields
- **Standardized Template Headers** - All templates now include comprehensive metadata fields:
  - `engineversion` - USecVisLib engine version compatibility (e.g., "0.2.5")
  - `version` - Template file version (e.g., "1.0.0")
  - `type` - Template category ("Attack Graph", "Attack Tree", or "Threat Model")
  - `date` - Template creation date
  - `last_modified` - Last modification date
  - `author` - Author name (default: "VULNEX")
  - `email` - Author email (default: "info@vulnex.com")
  - `url` - Author URL (default: "https://www.vulnex.com")
- Metadata placed after `name` and `description` fields in the root section

#### Multi-Format Template Files
- **All Templates in TOML, JSON, and YAML** - Every template now available in all three formats:
  - **Attack Graphs (3 templates, 9 files)**:
    - `cloud_infrastructure` (.tml, .json, .yaml)
    - `corporate_network` (.tml, .json, .yaml)
    - `simple_network` (.tml, .json, .yaml)
  - **Attack Trees (3 templates, 9 files)**:
    - `insider_threat` (.tml, .json, .yaml)
    - `ransomware_attack` (.tml, .json, .yaml)
    - `web_application_attack` (.tml, .json, .yaml)
  - **Threat Models (8 templates, 24 files)**:
    - `banking_api` (.tml, .json, .yaml)
    - `cicd_pipeline` (.tml, .json, .yaml)
    - `cloud_infrastructure` (.tml, .json, .yaml)
    - `ecommerce_platform` (.tml, .json, .yaml)
    - `healthcare_system` (.tml, .json, .yaml)
    - `iot_system` (.tml, .json, .yaml)
    - `microservices_architecture` (.tml, .json, .yaml)
    - `saas_multitenant` (.tml, .json, .yaml)
- Total: 14 templates × 3 formats = 42 template files

#### Test Template Updates
- **Test Templates with Metadata** - All test templates in `tests/` folder updated with metadata fields:
  - `enterattacktrees` (.tml, .json, .yaml) - Open Safe attack tree with styling
  - `enterattacktrees_nostyle` (.tml, .json, .yaml) - Open Safe attack tree minimal
  - `thiefexample` (.tml, .json, .yaml) - Castle heist attack tree
  - `webapp_threatmodel` (.tml, .json, .yaml) - Three-tier web application threat model
  - `test_attacktree` (.json, .yaml) - Simple attack tree for format testing
- Total: 14 test template files with metadata

#### Metadata API & UI Support
- **Library Support** - Full metadata parsing in core visualization classes:
  - `TemplateMetadata` dataclass in `results.py` with `from_dict()`, `to_dict()`, `has_metadata()` methods
  - `get_metadata()` method added to `VisualizationBase` class
  - `_get_metadata_root_key()` method for subclass customization (tree/graph/model)
  - Exported via `__init__.py` for public API access
- **API Support** - Metadata fields in analyze endpoints:
  - `TemplateMetadata` Pydantic schema added to `schemas.py`
  - `TreeStats`, `GraphStats`, `ModelStats` schemas updated with optional `metadata` field
  - `/analyze/attack-tree`, `/analyze/attack-graph`, `/analyze/threat-model` endpoints return metadata
- **UI Support** - Visual metadata display in all panels:
  - New `TemplateMetadata.vue` component with collapsible metadata section
  - Displays: name, description, type, version, engineversion, author, email, url, dates
  - Integrated into AttackTreePanel, AttackGraphPanel, ThreatModelPanel
  - Automatic author linking to URL, email mailto links

### Changed
- App.vue refactored to use dynamic `<component :is>` pattern instead of `v-if` conditionals
- Frontend version updated to 0.2.5
- All existing templates updated with new metadata fields

---

## [0.2.6] - 2025-12-26

### Added

#### Binary Visualization Configuration System
- **User-Configurable Visualization Parameters** - Binary visualizations can now be customized via TOML configuration files, separate from style presets:
  - **Entropy Analysis**: `window_size`, `step`, `dpi`, `show_thresholds`, custom `thresholds[]`, `fill_alpha`, `show_grid`, `grid_alpha`
  - **Byte Distribution**: `bar_width`, `bar_alpha`, `dpi`, `show_regions`, custom `regions[]` with start/end byte ranges
  - **Wind Rose**: `bar_alpha`, `dpi`, `rticks[]`, `rlabel_position`
  - **Heatmap**: `block_size`, `dpi`, `interpolation`, `aspect`, `show_colorbar`, `colorbar_label`

#### Core Library Updates (`binvis.py`)
- `configfile` parameter added to `BinVis.__init__()` for loading user configuration
- `_default_config()` method - Returns default configuration for all visualization types
- `loadconfig()` method - Loads and parses user TOML config file
- `_merge_config()` method - Merges user config with defaults (user values override)
- `visualize_entropy()` - Now uses config for window_size, step, thresholds, grid settings
- `visualize_distribution()` - Now uses config for bar_width, bar_alpha, regions
- `visualize_windrose()` - Now uses config for bar_alpha, rticks, rlabel_position
- `visualize_heatmap()` - Now uses config for block_size, interpolation, aspect, colorbar
- Method parameters override config values when explicitly provided

#### CLI Updates (`usecvis.py`)
- `-C, --config <file>` argument for binary visualization mode (mode 2)
- Config file validation before visualization
- Updated help text with config usage example

#### API Updates
- **New Pydantic Schemas** (`api/schemas.py`):
  - `EntropyThreshold` - Threshold line configuration
  - `EntropyConfig` - Entropy analysis settings with validation
  - `DistributionRegion` - Byte region highlight configuration
  - `ByteDistributionConfig` - Byte distribution settings
  - `WindRoseConfig` - Wind rose settings
  - `HeatmapConfig` - Heatmap settings
  - `BinVisConfig` - Complete configuration container
- `BinaryVisRequest` schema updated with optional `config` field
- `/visualize/binary` endpoint accepts `config_json` form field (JSON string)
- `apply_binvis_config()` helper function to apply API config to BinVis instance

#### Frontend Updates (`BinaryVisPanel.vue`)
- **Advanced Configuration Section** - Collapsible UI for configuration:
  - "Load Config TOML" button to upload configuration file
  - Configuration textarea editor with TOML syntax
  - Real-time TOML validation with error display
  - "Custom" badge indicator when config is active
  - Clear button to reset configuration
- **Quick Presets** - One-click configuration presets:
  - "High Detail" - Smaller windows, higher DPI for detailed analysis
  - "Fast" - Larger windows, lower DPI for quick overview
  - "Malware Analysis" - Custom thresholds for packed/encrypted detection
- TOML to JSON conversion using `smol-toml` parser
- `visualizeBinary()` API function updated to accept `configJson` parameter

#### Template Configuration File
- `templates/binvis_config.toml` - Comprehensive example configuration with all options documented

#### Unit Tests (11 new tests in `test_binvis.py`)
- `TestBinVisConfig` test class:
  - `test_default_config` - Verifies default config sections exist
  - `test_default_config_values` - Verifies default values
  - `test_load_config_from_file` - Tests TOML config loading
  - `test_config_merge_preserves_defaults` - Tests config merging
  - `test_config_file_not_found_uses_defaults` - Tests fallback behavior
  - `test_loadconfig_with_custom_thresholds` - Tests custom entropy thresholds
  - `test_loadconfig_with_custom_regions` - Tests custom distribution regions
  - `test_visualize_entropy_uses_config` - Tests entropy uses config values
  - `test_visualize_heatmap_uses_config_block_size` - Tests heatmap uses config
  - `test_explicit_params_override_config` - Tests parameter override behavior
  - `test_init_with_configfile_param` - Tests constructor parameter
- Total binvis tests: 37 (26 existing + 11 new)

### Changed
- Library version updated to 0.2.6
- API version updated to 0.2.6
- Frontend version updated to 0.2.6

---

## [0.2.8] - 2025-12-26

### Added

#### Navigation Redesign

**Reorganized Navigation Structure**
- Primary tabs reduced from 11 to 4 main visualization types
- Tools dropdown menu consolidates 5 utility features
- Documentation and Settings moved to header as icon buttons

**Primary Tabs** (Main Visualizations):
- Attack Trees
- Attack Graphs
- Threat Modeling
- Binary Analysis

**Tools Dropdown Menu**:
- CVSS Calculator
- Format Converter
- Batch Processing
- Data Export
- File Compare

**Header Actions**:
- Documentation icon button
- Settings icon button
- Clean/Reset button

**Responsive Design Improvements**:
- Mobile-friendly navigation with icons-only mode
- Click-outside-to-close dropdown behavior
- Proper responsive breakpoints for tablets and phones

#### CVSS Display Settings

**Settings Module (`src/usecvislib/settings.py`)**
- `DisplaySettings` class - Centralized management of visualization display settings
- Singleton pattern for consistent settings across all modules
- `get_cvss_display()` - Get all CVSS display settings
- `set_cvss_display()` - Update CVSS display settings
- `is_cvss_enabled()` - Check if CVSS is enabled (globally or per-type)
- `set_cvss_enabled()` - Enable/disable CVSS for specific visualization types
- `enable_cvss_all()` - Enable CVSS for all visualization types
- `disable_cvss_all()` - Disable CVSS for all visualization types
- `reset()` - Reset settings to defaults
- `to_dict()` / `from_dict()` - Export/import settings

**Constants Updates (`src/usecvislib/constants.py`)**
- `VisualizationType` enum - Attack Tree, Attack Graph, Threat Model, BinVis
- `DEFAULT_CVSS_DISPLAY` - Default CVSS display settings dictionary

**API Endpoints (`api/main.py`)**
- `GET /settings` - Get current display settings
- `PUT /settings` - Update display settings
- `POST /settings/cvss/enable-all` - Enable CVSS for all types
- `POST /settings/cvss/disable-all` - Disable CVSS for all types
- `POST /settings/reset` - Reset settings to defaults

**API Schemas (`api/schemas.py`)**
- `CVSSDisplaySettings` - CVSS display toggle settings model
- `DisplaySettingsRequest` - Request model for updating settings
- `DisplaySettingsResponse` - Response model for settings

**Frontend Updates**
- `SettingsPanel.vue` - Added CVSS Display Settings section
- Global CVSS toggle - Master on/off switch
- Per-type toggles for Attack Trees, Attack Graphs, Threat Models
- Enable All / Disable All / Reset to Defaults buttons
- `api.js` - Added settings API functions:
  - `getDisplaySettings()` - Fetch current settings
  - `updateDisplaySettings()` - Update settings
  - `enableCvssAll()` - Enable all CVSS
  - `disableCvssAll()` - Disable all CVSS
  - `resetDisplaySettings()` - Reset to defaults

**Visualization Module Updates**
- `attacktrees.py` - Checks `is_cvss_enabled("attack_tree")` before applying CVSS styling
- `attackgraphs.py` - Checks `is_cvss_enabled("attack_graph")` before applying CVSS styling
- `threatmodeling.py` - Checks `is_cvss_enabled("threat_model")` before including CVSS in reports

#### Testing
- `tests/test_settings.py` - 18 unit tests for settings module
  - Singleton pattern verification
  - Default settings validation
  - CVSS enable/disable functionality
  - Global vs per-type toggle behavior
  - Settings import/export
  - Integration with visualization modules

### Changed
- Library version updated to 0.2.8

---

## [0.2.7] - 2025-12-26

### Added

#### CVSS 3.x Support (Full Implementation)

**Core CVSS Module (`src/usecvislib/cvss.py`)**
- `CVSSVersion` enum - Support for CVSS 3.0 and 3.1
- `AttackVector` enum - Network, Adjacent, Local, Physical
- `AttackComplexity` enum - Low, High
- `PrivilegesRequired` enum - None, Low, High (with scope-dependent weights)
- `UserInteraction` enum - None, Required
- `Scope` enum - Unchanged, Changed
- `Impact` enum - None, Low, High (for C/I/A metrics)
- `CVSSVector` dataclass - Parsed vector with all components and base score
- `parse_cvss_vector()` - Parse CVSS 3.x vector strings with validation
- `calculate_cvss_from_vector()` - Full CVSS 3.x score calculation algorithm
- `validate_cvss_vector()` - Vector string format validation
- `get_cvss_score()` - Resolve score from numeric value or vector string
- `CVSS_EXAMPLES` - Reference vectors for common scenarios

**CVSS Helper Functions (`src/usecvislib/constants.py`)**
- `cvss_to_color()` - Map CVSS scores to severity colors (Critical: #8b0000, High: #e74c3c, Medium: #f39c12, Low: #27ae60, None: #3498db)
- `cvss_to_severity_label()` - Map scores to labels (Critical/High/Medium/Low/None)
- `cvss_to_risk_level()` - Map scores to RiskLevel enum
- `validate_cvss_score()` - Validate numeric CVSS scores (0.0-10.0)
- `CVSS_SEVERITY_LABELS` - Severity label mapping dictionary

**Attack Graphs CVSS Integration (`src/usecvislib/attackgraphs.py`)**
- Vulnerability nodes support both `cvss` (numeric) and `cvss_vector` (string)
- Automatic severity color coding based on CVSS score
- Node labels include CVSS score and severity (asterisk for vector-calculated)
- CVSS validation in `_validate_impl()`
- Statistics include `average_cvss` and `critical_vulnerabilities` count
- `find_weighted_shortest_path()` uses CVSS as edge weights (inverted: 10 - score)

**Attack Trees CVSS Integration (`src/usecvislib/attacktrees.py`)**
- Tree nodes support `cvss` and `cvss_vector` attributes
- Automatic fillcolor based on CVSS severity (overrides template color)
- Node labels enhanced with CVSS score and severity badge
- CVSS validation for both numeric and vector formats
- Statistics: `nodes_with_cvss`, `average_cvss`, `max_cvss`, `critical_nodes`, `high_risk_nodes`

**Threat Modeling CVSS Integration (`src/usecvislib/threatmodeling.py`)**
- Custom threats section `[threats]` with CVSS scoring
- STRIDE analysis includes estimated CVSS scores based on threat severity
- Custom threats support both `cvss` and `cvss_vector` attributes
- Statistics: `total_threats`, `threats_with_cvss`, `average_cvss`, `max_cvss`, `critical_threats`, `high_threats`

**API Schema Updates (`api/schemas.py`)**
- `CVSSSeverity` enum - Critical, High, Medium, Low, None
- `VulnerabilityInput` model with CVSS validation (0.0-10.0 range)
- `TreeStats` - Added `nodes_with_cvss`, `average_cvss`, `max_cvss`, `critical_nodes`, `high_risk_nodes`
- `ModelStats` - Added `total_threats`, `threats_with_cvss`, `average_cvss`, `max_cvss`, `critical_threats`, `high_threats`
- `StrideCategory` - Added `cvss` and `severity` fields for threat scoring

**API Endpoint Updates (`api/main.py`)**
- STRIDE analysis endpoint returns CVSS scores and severity labels for each threat
- `convert_threat()` helper maps threat CVSS to severity labels

**Frontend CVSS Calculator**
- `CVSSCalculator.vue` - Interactive CVSS 3.1 calculator component:
  - All base metrics: Attack Vector, Attack Complexity, Privileges Required, User Interaction, Scope
  - Impact metrics: Confidentiality, Integrity, Availability
  - Real-time score calculation with CVSS 3.1 algorithm
  - Vector string generation
  - Copy to clipboard functionality
  - Visual severity indicator with color coding
- `CVSSCalculatorPanel.vue` - Full panel wrapper:
  - Severity ranges reference table
  - Usage examples for Attack Graph, Attack Tree, and Threat Model templates
  - Calculation history with recent entries
- New "CVSS Calculator" tab in App.vue with 🎯 icon

**Frontend Panel Updates**
- `AttackGraphPanel.vue` - CVSS severity badges and statistics display
- `AttackTreePanel.vue` - CVSS stats: nodes_with_cvss, average_cvss, critical_nodes, high_risk_nodes
- `ThreatModelPanel.vue` - CVSS stats and threat severity display with color-coded badges
- CSS classes for CVSS severity: `.cvss-critical`, `.cvss-high`, `.cvss-medium`, `.cvss-low`, `.cvss-none`

**Unit Tests (`tests/test_cvss.py` - 33 tests)**
- `TestCVSSVectorParsing` - Vector parsing for CVSS 3.0/3.1, case insensitivity, invalid formats
- `TestCVSSScoreCalculation` - Score calculation for critical, high, medium, low, zero impact scenarios
- `TestCVSSValidation` - Vector and numeric score validation
- `TestGetCVSSScore` - Score resolution from numeric values and vectors
- `TestCVSSColorAndLabels` - Color mapping and severity label tests
- `TestCVSSVectorMethods` - CVSSVector.to_dict() and raw_string preservation
- `TestCVSSEdgeCases` - Physical attack vectors, changed scope, score rounding

**Template Updates (All formats: TOML, JSON, YAML)**
- **Attack Graphs** - All vulnerabilities have `cvss` or `cvss_vector`:
  - `cloud_infrastructure` - 7 vulnerabilities with CVSS vectors
  - `corporate_network` - 8 vulnerabilities with CVSS
  - `simple_network` - 3 vulnerabilities with CVSS vectors
- **Attack Trees** - Leaf nodes have CVSS for risk assessment:
  - `web_application_attack` - 11 nodes with CVSS
  - `ransomware_attack` - 10 nodes with CVSS
  - `insider_threat` - 10 nodes with CVSS (data exfil, privilege abuse, sabotage)
- **Threat Models** - Custom threats with CVSS:
  - `banking_api` - 8 threats with CVSS
  - `microservices_architecture` - 6 threats with CVSS
  - `cicd_pipeline` - 6 supply chain threats with CVSS
  - `cloud_infrastructure` - 5 cloud security threats with CVSS
  - `ecommerce_platform` - 5 e-commerce threats with CVSS
  - `healthcare_system` - 5 healthcare/HIPAA threats with CVSS
  - `iot_system` - 5 IoT security threats with CVSS
  - `saas_multitenant` - 5 multi-tenant threats with CVSS
- **Test Templates** - All test templates updated with CVSS:
  - `enterattacktrees` - 9 CVSS entries
  - `enterattacktrees_nostyle` - 9 CVSS entries
  - `thiefexample` - 8 CVSS entries
  - `webapp_threatmodel` - 4 threat entries with CVSS
  - `test_attacktree` - 3 CVSS entries

### Changed
- Library version updated to 0.2.7
- Total test count: 475 passed, 11 skipped
- Templates follow consistent rule: `cvss` OR `cvss_vector` (not both) on same element
- Category/root/goal nodes have no CVSS (only leaf attack techniques)

---

## [0.2.9] - 2025-12-27

### Added

#### NetworkX Integration for Attack Graphs
- **Backend** (`src/usecvislib/attackgraphs.py`):
  - Integrated NetworkX library for advanced graph analysis
  - New centrality algorithms: `betweenness_centrality()`, `closeness_centrality()`, `pagerank()`
  - New path algorithms: `k_shortest_paths()`, `all_paths_between()`
  - New graph structure analysis: `find_cycles()`, `strongly_connected_components()`, `diameter()`, `graph_density()`
  - New security analysis: `find_chokepoints()`, `find_attack_surfaces()`, `vulnerability_impact_score()`
  - New comprehensive method: `get_graph_metrics()`

- **API Endpoints** (`api/main.py`):
  - `POST /analyze/centrality` - Calculate betweenness, closeness, and PageRank centrality
  - `POST /analyze/graph-metrics` - Get comprehensive graph metrics (density, diameter, cycles, SCCs)
  - `POST /analyze/chokepoints` - Identify critical network bottlenecks
  - `POST /analyze/attack-surface` - Find attack entry points and reachable nodes
  - `POST /analyze/vulnerability-impact` - Calculate impact score for specific vulnerability

- **API Schemas** (`api/schemas.py`):
  - `CentralityNode`, `CentralityResponse`
  - `GraphMetricsResponse`
  - `ChokepointNode`, `ChokepointsResponse`
  - `AttackSurfaceNode`, `AttackSurfaceResponse`
  - `VulnerabilityImpactResponse`

- **Frontend API** (`frontend/src/services/api.js`):
  - `analyzeCentralityFromContent()`
  - `analyzeGraphMetricsFromContent()`
  - `analyzeChokepointsFromContent()`
  - `analyzeAttackSurfaceFromContent()`
  - `analyzeVulnerabilityImpactFromContent()`

- **Frontend UI** (`frontend/src/components/AttackGraphPanel.vue`):
  - New "Advanced Graph Analysis" section with action buttons
  - Vulnerability impact analysis with ID input field
  - Graph Metrics display (density, diameter, cycles, SCCs, DAG status, clustering)
  - Centrality Rankings display (betweenness, closeness, PageRank scores)
  - Chokepoints display with critical node highlighting
  - Attack Surface entry points display with reachability stats
  - Vulnerability Impact display with severity coloring

- **Tests** (`tests/test_attackgraphs.py`):
  - `TestNetworkXCentrality` - 3 tests for centrality algorithms
  - `TestNetworkXPaths` - 3 tests for path algorithms
  - `TestNetworkXGraphStructure` - 5 tests for graph structure analysis
  - `TestNetworkXSecurityAnalysis` - 4 tests for security analysis

- **Dependencies**: Added `networkx>=3.0` to `requirements.txt`

- **Documentation**: Created `devnotes/NETWORKX_UI_INTEGRATION.md` action plan

---

## [0.3.0] - 2025-12-29

### Added

#### Mermaid Diagram Export Support
- **Mermaid Generator Module** (`src/usecvislib/mermaid.py`):
  - `serialize_to_mermaid()` - Convert configuration data to Mermaid diagram syntax
  - `detect_visualization_type()` - Auto-detect visualization type from configuration structure
  - Support for all visualization types: attack trees, threat models, attack graphs
  - Future-ready support for: kill chains, timelines, access graphs, vulnerability trees
  - `MermaidDiagramType` enum - Flowchart, Sequence, Gantt
  - `MermaidDirection` enum - Top-down, Bottom-up, Left-right, Right-left
  - `sanitize_node_id()` - Mermaid-compatible ID sanitization
  - `escape_label()` - Label escaping for special characters
  - Size limits for complex graphs (max_nodes parameter)

- **CLI Format Conversion** (`src/usecvislib/usecvis.py`):
  - `--convert <format>` option supporting: toml, json, yaml, mermaid
  - Auto-detection of input format from file extension
  - Auto-detection of visualization type for Mermaid output
  - Output saved as `.mmd` file for Mermaid format
  - Examples:
    ```bash
    usecvis -i attack.toml -o output --convert mermaid
    usecvis -i threat.yaml -o diagram --convert json
    ```

- **API Mermaid Support** (`api/main.py`, `api/schemas.py`):
  - `ConfigFormat.MERMAID` enum value added
  - `/convert` endpoint now accepts `mermaid` as target format
  - Mermaid files use `.mmd` extension

- **Frontend Mermaid Export** (`frontend/src/components/ConvertPanel.vue`):
  - Mermaid added to "Convert To" dropdown (output-only format)
  - Pink/magenta styling for Mermaid format badge
  - Updated description to include Mermaid

- **Library Exports** (`src/usecvislib/__init__.py`):
  - `serialize_to_mermaid` function
  - `detect_visualization_type` function
  - `MermaidDiagramType` enum
  - `MermaidDirection` enum
  - `MERMAID_FILE_EXTENSION` constant

#### Mermaid Output Features
- **Attack Trees**: Flowchart with root node styling, edge connections
- **Threat Models**: DFD-style flowchart with process circles, datastore cylinders, external rectangles
- **Attack Graphs**: Network diagram with hosts, vulnerabilities (diamond), privileges (hexagon), services
- **Styling**: Color-coded nodes based on type and severity
- **Comments**: Diagram title included as Mermaid comment

### Changed
- `utils.py` - Added mermaid to ConfigFormat Literal and SUPPORTED_EXTENSIONS
- `constants.py` - Added MERMAID to ConfigFormat enum
- Format conversion utilities updated to handle Mermaid as output-only format
- Library version updated to 0.3.0
- API version updated to 0.3.0
- CLI version updated to 0.3.0
- Frontend version updated to 0.3.0
- setup.py version updated to 0.3.0

### Notes
- Mermaid is an **output-only** format - cannot be used as input for conversion
- Mermaid syntax can be rendered in GitHub, GitLab, VS Code, and documentation tools
- `.mmd` files are plain text and can be edited manually

---

## [0.3.1] - 2025-12-29

### Added

#### Custom Diagrams Module (Mode 4)
- **New `CustomDiagrams` class** (`src/usecvislib/custom_diagrams.py`) for creating arbitrary user-defined diagrams:
  - Schema-driven configuration with reusable node and edge type definitions
  - Support for 55+ Graphviz shapes organized by category
  - Template-based label formatting with placeholders (e.g., `{name}\n{ip}`)
  - TOML, JSON, and YAML configuration support
  - Built-in validation with descriptive error messages

- **Core Methods**:
  - `load(filepath)` - Load configuration from TOML/JSON/YAML file
  - `load_from_dict(data)` - Load from Python dictionary
  - `load_template(template_name)` - Load built-in template
  - `BuildCustomDiagram(output, format)` - Generate visualization
  - `validate()` - Validate configuration against schema
  - `get_diagram_stats()` - Get diagram statistics

- **Schema Definition System**:
  - `[schema.nodes.<type>]` - Define custom node types with shape, style, required_fields
  - `[schema.edges.<type>]` - Define custom edge types with style, arrowhead, color
  - `label_template` - Dynamic labels using field placeholders
  - `optional_fields` - Additional optional attributes
  - Style inheritance from parent type definitions

- **Shape Gallery (55+ shapes)**:
  - Basic: box, ellipse, circle, diamond, triangle, parallelogram
  - 3D: box3d, cylinder, folder
  - Arrows: rarrow, larrow, rpromoter, lpromoter
  - Special: star, note, tab, component, cds, signature
  - Records: record, Mrecord for structured data
  - Network: cloud, firewall, server, database, laptop

- **Layout Options**:
  - `hierarchical` (TB, BT, LR, RL directions)
  - `circular`
  - `radial`
  - `force` (fdp, neato, sfdp algorithms)

- **Styles (6 presets)**:
  - `cd_default` - Clean professional look
  - `cd_dark` - Dark theme with light text
  - `cd_corporate` - Professional enterprise style
  - `cd_neon` - Cyberpunk neon style
  - `cd_blueprint` - Technical blueprint style
  - `cd_pastel` - Soft pastel colors

- **Built-in Templates (6)**:
  - `simple_flowchart` - Basic process flow with start/end/decision nodes
  - `network_topology` - Three-tier network architecture
  - `process_flow` - Business process diagram
  - `org_chart` - Organizational hierarchy
  - `er_diagram` - Entity-relationship model
  - `state_machine` - State transition diagram

#### CLI Mode 4
- `usecvis -m 4` - Custom Diagrams mode
- `-i <file>` - Input configuration (TOML/JSON/YAML)
- `-o <output>` - Output file path
- `-f <format>` - Output format (png, svg, pdf)
- `-s <style>` - Style preset
- `-t <template>` - Load built-in template
- `--list-templates` - Show available templates
- `--list-shapes` - Show available shapes

#### API Endpoints (5 new)
- `POST /custom-diagrams/visualize` - Generate diagram from configuration
- `POST /custom-diagrams/validate` - Validate configuration
- `POST /custom-diagrams/from-template` - Generate from built-in template
- `POST /custom-diagrams/import` - Generate from uploaded file
- `GET /custom-diagrams/templates` - List available templates
- `GET /custom-diagrams/shapes` - Get shape gallery organized by category

#### Frontend CustomDiagramPanel.vue
- **Three sub-tabs**: Templates, Import, Editor
- **Templates Tab**: Browse and select from 6 built-in templates with category icons
- **Import Tab**: Drag-and-drop file upload with format auto-detection
- **Editor Tab**: Live TOML editor with syntax highlighting and validation
- **Shape Gallery**: Visual browser for all 55+ shapes with click-to-copy ID
- **Options**: Style selector, output format, layout algorithm, direction
- **Real-time validation**: Syntax and schema validation with error display
- App.vue - Added Custom Diagrams tab with 📊 icon

#### Example Templates
- `docs/examples/custom-diagrams/simple-flowchart.toml` - Login process flowchart
- `docs/examples/custom-diagrams/network-topology.toml` - Three-tier network architecture
- `templates/custom-diagrams/` - All 6 built-in templates in TOML, JSON, and YAML formats

#### Documentation
- `docs/CUSTOM_DIAGRAMS_GUIDE.md` - Comprehensive 26KB user guide:
  - Configuration format reference
  - Schema definition guide
  - Shape gallery with all 55+ shapes
  - Template usage and customization
  - Layout and style options
  - Python API examples
  - REST API reference
  - CLI usage examples

#### Unit Tests (20+ new tests)
- `tests/test_custom_diagrams.py`:
  - Configuration loading tests
  - Schema validation tests
  - Template loading tests
  - Rendering tests
  - Statistics tests
  - Multi-format support tests

#### Batch Processing Support
- Added Custom Diagrams mode to Batch Processing feature
- Updated `VisualizationMode` enum with `CUSTOM_DIAGRAM` option
- Added `cd_` style prefix for Custom Diagrams in BatchPanel.vue
- Full statistics collection support via `get_stats()` method

### Changed
- Updated `README.md` with Custom Diagrams module information
- Updated `docs/CLI_GUIDE.md` with Mode 4 documentation
- Updated `docs/PYTHON_API.md` with CustomDiagrams class reference
- Updated `docs/UI_GUIDE.md` with Custom Diagrams panel documentation
- Library version updated to 0.3.1
- API version updated to 0.3.1
- Frontend version updated to 0.3.1

### Fixed
- **Custom Diagrams dark theme styling** - Fixed CSS variables to match app theme
- **HTML entity rendering** - Fixed shape icons using `v-html` directive
- **API method calls** - Fixed endpoints to use correct `BuildCustomDiagram()` method
- **Batch processing for Custom Diagrams** - Fixed stats method call to use `get_stats()` instead of `get_diagram_stats()`

---

## [0.3.2] - 2026-01-01

### Added

#### Save Template Button
- **Template Download Feature** - New "Save Template" button in all editor panels:
  - Attack Tree Panel
  - Attack Graph Panel
  - Threat Model Panel
  - Custom Diagram Panel
- Downloads current editor content with timestamped filename (e.g., `my_template_20260101_143025.toml`)
- Preserves original file extension (TOML, JSON, YAML)
- Uses existing `downloadTextFile()` utility from `api.js`

#### Template Type Mismatch Detection
- **New `template-detector.js` utility** (`frontend/src/utils/template-detector.js`):
  - `detectTemplateType(content)` - Analyzes configuration content to determine template type
  - `validateTemplateType(content, expectedType)` - Validates if template matches expected panel
  - `TemplateType` enum - ATTACK_TREE, ATTACK_GRAPH, THREAT_MODEL, CUSTOM_DIAGRAM, UNKNOWN
  - `TemplateTypeNames` - Human-readable names for template types
  - `TemplateTypePanels` - Maps template types to panel names
- **Detection Logic**:
  - Attack Tree: Detects `[tree]` + `root`, or `[nodes]` + `[edges]` structure
  - Attack Graph: Detects `[graph]` + `[[hosts]]` / `[[vulnerabilities]]` structure
  - Threat Model: Detects `[model]`, `[processes]`, `[externals]`, `[dataflows]` structure
  - Custom Diagram: Detects `[diagram]` + `[schema]` structure
- **Warning Banner UI** - Yellow warning banner shown when template type doesn't match panel:
  - Displays detected template type and suggested panel
  - "Dismiss" button to continue anyway (for edge cases like conversion)
  - Integrated into AttackTreePanel, AttackGraphPanel, ThreatModelPanel
- **Automatic Validation** - Template type checked immediately on file load

#### API Authentication System
- **New `api/auth.py` module** for API key-based authentication:
  - Single API key support via `USECVISLIB_API_KEY` environment variable
  - Multiple API keys support via `USECVISLIB_API_KEYS` (comma-separated)
  - Auth toggle via `USECVISLIB_AUTH_ENABLED` (default: true)
  - Fail-fast startup validation with helpful error messages
  - Secure key generation utility (`generate_example_key()`)
  - Constant-time key comparison to prevent timing attacks

- **Authentication Features**:
  - `verify_api_key()` - FastAPI dependency for protected routes
  - `validate_auth_config()` - Startup configuration validation
  - `get_configured_keys()` - Retrieve all configured API keys
  - Path exclusions for `/docs`, `/redoc`, `/openapi.json`
  - Custom `X-API-Key` header (configurable via `USECVISLIB_API_KEY_HEADER`)

- **API Integration** (`api/main.py`):
  - Global authentication dependency on all endpoints
  - Updated CORS to allow `X-API-Key` header
  - OpenAPI security scheme with `ApiKeyAuth`
  - 401 response documentation
  - Updated API description with auth instructions

- **Frontend Authentication** (`frontend/src/services/api.js`):
  - `getApiKey()` - Retrieve stored API key from localStorage
  - `setApiKey(key)` - Save API key to localStorage
  - `clearApiKey()` - Remove stored API key
  - `hasApiKey()` - Check if key is configured
  - Axios request interceptor to add `X-API-Key` header
  - Axios response interceptor for 401 error handling
  - Custom event dispatch (`usecvislib:auth-error`) for auth failures

- **Settings Panel UI** (`frontend/src/components/SettingsPanel.vue`):
  - New "API Authentication" section at top of settings
  - Password-style input with show/hide toggle
  - API key status indicator (configured/not configured)
  - Save and Clear buttons
  - Success/error message display
  - Auth error event listener for real-time feedback

- **Docker Configuration**:
  - `docker-compose.yml` - Added auth environment variables
  - `.env.example` - New configuration template with all auth options

- **Documentation**:
  - `devnotes/API_AUTHENTICATION.md` - Complete implementation guide with quick-start

#### Unit Tests (30 new tests)
- `tests/test_api_auth.py`:
  - `TestAuthConfiguration` (6 tests) - Key management and generation
  - `TestStartupValidation` (3 tests) - Fail-fast behavior
  - `TestAuthDisabled` (3 tests) - Auth disabled mode
  - `TestAuthEnabled` (7 tests) - Auth enabled with keys
  - `TestMultipleKeys` (4 tests) - Multiple API keys support
  - `TestSecurityFeatures` (4 tests) - Security behaviors
  - `TestOpenAPISchema` (3 tests) - OpenAPI security scheme

#### Node Icon/Image Support
- **Bundled Icons** - 3000+ bundled icons in `assets/icons/` organized by provider:
  - **AWS Icons** - Full AWS architecture icon set (EC2, S3, Lambda, RDS, VPC, etc.)
  - **Azure Icons** - Microsoft Azure service icons
  - **Bootstrap Icons** - General purpose icons for UI elements
  - Categories include: compute, storage, database, networking, security, containers, serverless, and more
- **Icon Resolution** - Automatic icon path resolution using `@icon:` prefix (e.g., `image = "@icon:server"`)
- **Custom Images** - Support for custom images via absolute or relative file paths
- **Node Styling** - Nodes with icons automatically use `shape="none"` with image below label
- **`process_node_image()` Utility** - Helper function in `utils.py` for icon/image processing
- **Template Updates** - New icon-enabled templates for all visualization types:
  - `network_infrastructure_with_icons.tml` - Network topology with device icons
  - `aws_cloud_security.tml` - AWS architecture with service icons
  - Additional templates renamed with `_with_icons` suffix for clarity

### Changed
- `api/schemas.py` - Added `AuthErrorResponse` schema
- Frontend build updated with auth components
- API responses now include 401 status for auth failures

### Security

#### API Authentication Hardening
- API keys never logged (only presence/validity status)
- Constant-time comparison prevents timing attacks
- 401 responses don't reveal valid keys
- WWW-Authenticate header included in auth failures
- Empty and whitespace-only keys rejected

#### Security Audit Fixes (API Authentication)
- **Timing attack fix** - Replaced `any()` with constant-time loop that checks ALL keys to prevent timing leaks from short-circuit evaluation
- **Auth bypass removed** - Removed `/health` and `/icons/*` from excluded paths; all endpoints now require authentication when enabled
- **Per-key audit logging** - Added `key_id` to log entries for tracking API key usage patterns
- **Rate limiting on /health** - Added rate limiting to `/health` endpoint to prevent DoS attacks
- **Dynamic auth check** - Added `is_auth_enabled()` function for runtime auth checking (improves testability)

#### Security Audit Fixes (Image/Icon Support)
- **Symlink attack prevention** - Added `_validate_path_within_directory()` that rejects symlinks and uses `Path.relative_to()` for secure directory confinement
- **DOT injection prevention** - Escaped `resolved_path` with `_escape_html()` before embedding in Graphviz HTML labels
- **Cache directory race condition fix** - Added pre/post symlink checks for SVG-to-PNG cache directory creation (TOCTOU protection)
- **Path traversal hardening** - Added detection for URL-encoded path traversal attempts (`%2e`, `%2f`, `%5c`)
- **Backslash traversal** - Added check for Windows-style path traversal using backslashes

### Fixed
- Test isolation issue with auth module caching across test files

#### Font Color Readability Improvements
- **Default Style Fix** - Changed default node fontcolor from "blue" to "white" in `config_attacktrees.tml` for better readability on colored backgrounds
- **CVSS-Colored Nodes** - Automatically sets `fontcolor="white"` when CVSS severity colors are applied to nodes (attack trees and attack graphs)
- **Icon Nodes** - Automatically sets `fontcolor="black"` for nodes with icons (shape=none) since they appear on white/transparent backgrounds
- Applies to all visualization modules: `attacktrees.py`, `attackgraphs.py`, `threatmodeling.py`
- Users can still override fontcolor by explicitly setting it in templates

#### Icon Shape Preservation
- **Fixed icon rendering order** - Corrected order of operations in `attackgraphs.py` to call `merge_dicts()` before `process_node_image()`, preventing default styles from overwriting icon settings
- **Optional shape with icons** - Added `preserve_shape` parameter to `process_node_image()` in `utils.py` allowing users to explicitly set a `shape` attribute for nodes with icons
- **User control** - When a user explicitly sets `shape` in their configuration file (e.g., `shape = "box"`), the node will display both the icon and the background shape
- **Default behavior unchanged** - By default, nodes with icons continue to render cleanly with `shape="none"` (no background)
- Applies to all visualization modules: `attacktrees.py`, `attackgraphs.py`, `threatmodeling.py`

#### Icon Gallery Authentication Fix
- **Fixed icon endpoints auth** - Re-added `/icons`, `/icons/categories`, and `/icons/` prefix to auth exclusion list
- **Reason**: `<img>` tags cannot pass authentication headers, so icon file serving must be excluded from auth for the gallery to work
- Icon list and category endpoints also excluded to support the icon gallery UI

#### Icon Rendering Improvements (2025-12-31)
- **Fixed icon size scaling** - Large icons (512x512 AWS PNGs) are now automatically resized to 48x48 thumbnails using PIL for consistent display
- **Fixed label positioning** - Icon labels now consistently appear below icons using HTML TABLE layout instead of unpredictable `xlabel` positioning
- **Removed unwanted backgrounds** - Icons no longer display background boxes/shapes by default, regardless of template `style` or `fillcolor` settings
- **Simplified icon processing** - Unified `process_node_image()` function now handles all icon rendering consistently:
  - Uses HTML TABLE with image in first row and label in second row
  - Clears all inherited style attributes for clean rendering
  - PIL-based thumbnail generation for images larger than 64 pixels
  - Fallback to original image if PIL is unavailable
- **Detection logic improved** - Updated style preservation checks in `attacktrees.py`, `attackgraphs.py`, and `threatmodeling.py` to properly detect when users want styled backgrounds vs clean icons
- **Test updates** - Updated `test_image_support.py` to validate new HTML TABLE-based icon rendering

#### Branding Updates (2026-01-03)
- **New Logo** - Added custom USecVisLib logo to the web UI header replacing the shield emoji
- **Settings About Logo** - Updated Settings panel About section with the logo image
- **Favicon** - New custom favicon.ico replacing the default SVG favicon
- **README Logo** - Added centered logo with text at the top of README.md

---

## [0.3.3] - 2026-01-09

### Security

#### Comprehensive Security Audit & Fixes
- **Complete security code review** performed across entire codebase
- **38 security vulnerabilities identified and fixed** (7 Critical, 6 High, 12 Medium, 13 Low)
- All 1058 tests passing after security hardening

#### Critical Fixes (7)
- **Path Traversal in `find_template_file()`** - Added `validate_path_component()` and `validate_path_within_directory()` helper functions to prevent directory escape via `../` sequences
- **Path Traversal in Custom Diagram Templates** - Added path validation for template file loading
- **Image ID Prefix Matching Vulnerability** - Added `validate_uuid_format()` with strict RFC 4122 UUID regex pattern to prevent ID injection attacks
- **XSS in HTML Report Generation** - Added `html.escape()` to all user-controlled content in `generate_html_report()` (threatmodeling.py)
- **Graphviz DOT Injection** - Enhanced `_escape_dot_string()` to escape `{`, `}`, `|`, `;`, `&` characters that could break graph structure
- **Bypassable Path Traversal in Icons Endpoint** - Added URL-encoded path traversal detection (`%2e`, `%2f`, `%5c`) and null byte checks
- **YAML Serialization without SafeDumper** - Added `Dumper=yaml.SafeDumper` to prevent arbitrary Python object serialization in `utils.py` and `exporters.py`

#### High Fixes (6)
- **Missing HSTS Header** - Added `Strict-Transport-Security: max-age=31536000; includeSubDomains` to SecurityHeadersMiddleware
- **SVG Path Traversal in Custom Shapes** - Added symlink rejection and `is_relative_to()` validation in `shapes/custom.py`
- **Exception Detail Exposure** - Replaced 30+ instances of `detail=str(e)` with generic error messages to prevent stack trace leakage
- **Markdown Table Injection** - Added `_escape_markdown_cell()` function in `exporters.py` to escape pipe characters and prevent table breakout
- **Dependency CVE Fixes**:
  - `fastapi >= 0.115.0` (from 0.109.0) - security fixes
  - `uvicorn >= 0.32.0` (from 0.27.0) - CVE-2020-7694
  - `python-multipart >= 0.0.18` (from 0.0.6) - CVE-2024-53981
  - `axios >= 1.7.9` (from 1.6.0) - CVE fixes

#### Medium Fixes (12)
- **CORS Origin Validation** - Added `_validate_cors_origin()` function with URL parsing, wildcard rejection, and scheme validation
- **Hardcoded `/tmp` Paths** - Replaced `/tmp/unused` with `os.path.join(TEMP_DIR, "pytm_output")` for secure temp file handling
- **Filename Log Injection Prevention** - Added `sanitize_filename_for_log()` function to remove control characters, limit length, and escape format specifiers
- **Uvicorn Timeout/Limit Configuration** - Added server hardening with:
  - `timeout_keep_alive=5` - Prevent slow-read DoS attacks
  - `limit_concurrency=100` - Prevent resource exhaustion
  - `limit_max_requests=10000` - Prevent memory leaks
  - All configurable via environment variables
- **Missing Output Encoding in Logs** - 8 filename log statements now use sanitization function
- **Per-User Image Isolation** - Added API key hash-based namespace isolation for uploaded images to prevent cross-user access
- **Generic Error Messages** - Fixed vulnerability impact endpoint to return generic error messages preventing internal path disclosure
- **Dict Field Size Validators** - Added `@field_validator` with size limits to Dict fields in Pydantic schemas (nodes, styles, edges) preventing DoS via oversized payloads
- **Temp File Cleanup** - Added `__del__` destructors to AttackTrees, AttackGraphs, and ThreatModeling classes for automatic temp file cleanup
- **Sensitive Paths Whitelist Expansion** - Expanded SENSITIVE_PATHS list with macOS-specific paths and refined to allow temp directories while blocking system directories
- **SVG Validation Enhancements** - Added 20+ dangerous pattern checks including `<embed>`, `<object>`, `<link>`, `<meta>`, `<feImage>`, `<style>`, style injection via `url()`, XML entity attacks, and external xlink:href
- **Output Path Validation in Exporters** - Added `validate_output_path()` checks to all export methods (to_json, to_csv, to_yaml, to_markdown_table, etc.)

#### Low Fixes (13)
- **Per-Request Timeouts** - Added configurable request timeouts to all visualization endpoints using `asyncio.wait_for()`:
  - `REQUEST_TIMEOUT_VISUALIZE=120` - Individual visualization requests
  - `REQUEST_TIMEOUT_ANALYZE=60` - Analysis operations
  - `REQUEST_TIMEOUT_BATCH=300` - Batch operations
  - Returns HTTP 504 on timeout with generic error message
- **String Length Constraints** - Added `max_length` to 15+ Pydantic schema string fields to prevent memory exhaustion:
  - `VulnerabilityInput`: id (256), label (512), description (4096), cwe (32)
  - `TemplateMetadata`: name (256), description (2048), author (256), email (320), url (2048)
  - `DiagramNode/Edge/Cluster/Settings`: id (256), type (64), name/label (512)
- **Security Function Docstrings** - Added CWE references to security helper functions:
  - `validate_path_within_directory`: CWE-22 (Path Traversal)
  - `is_safe_symlink`: CWE-59 (Symlink Attack)
  - `is_valid_image`: File type spoofing prevention
  - `_parse_allowed_origins`: CORS misconfiguration prevention
- **Conditional Debug Logging** - 29 instances of `exc_info=True` now conditional on `LOG_LEVEL=DEBUG` to prevent stack trace leakage in production
- **Version Information Disclosure** - Version and path information only logged in DEBUG mode; generic startup message in production

### Changed
- `api/main.py` - Added comprehensive security helper functions, input validation, per-request timeouts, and per-user image isolation
- `api/schemas.py` - Added `max_length` constraints to string fields and Dict field size validators
- `src/usecvislib/exporters.py` - Added markdown injection prevention, YAML SafeDumper, and output path validation
- `src/usecvislib/shapes/custom.py` - Added path traversal prevention, symlink attack prevention, and 20+ SVG dangerous pattern checks
- `src/usecvislib/threatmodeling.py` - Added HTML escaping, enhanced DOT string escaping, and temp file cleanup
- `src/usecvislib/attacktrees.py` - Added temp file cleanup in destructor
- `src/usecvislib/attackgraphs.py` - Added temp file cleanup in destructor
- `src/usecvislib/utils.py` - Added YAML SafeDumper and refined sensitive paths list
- `src/usecvislib/constants.py` - Expanded SENSITIVE_PATHS with macOS-specific paths
- `requirements.txt` - Updated vulnerable dependencies
- `frontend/package.json` - Updated axios to fix CVEs

---

## [Unreleased]

### Planned
- User sessions and history
