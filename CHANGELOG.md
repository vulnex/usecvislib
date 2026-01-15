# Changelog

All notable changes to USecVisLib will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
