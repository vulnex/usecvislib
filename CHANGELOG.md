# Changelog

All notable changes to USecVisLib will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Mermaid Diagrams Module** (Work in Progress)
  - New `MermaidDiagrams` class for rendering Mermaid syntax to images via mermaid-cli
  - Support for all Mermaid diagram types: flowcharts, sequence, class, state, ER, Gantt, etc.
  - Template system with categories (flowcharts, sequence, class, state, etc.)
  - API endpoint `/mermaid/template/{category}/{name}` for loading template content
  - Frontend panel `MermaidDiagramPanel.vue` with editor and template browser
  - Docker support with Chromium and puppeteer configuration for sandbox environments

- **Cloud Diagrams Module** (Work in Progress)
  - New `CloudDiagrams` class for cloud architecture visualization
  - Support for AWS, Azure, GCP, and generic cloud icons
  - Template system for common cloud patterns
  - Frontend panel `CloudDiagramPanel.vue` with editor and template browser

### Fixed

- **Consistent Style Application Across All Modules**
  - Fixed Custom Diagrams API endpoint not applying the style parameter - styles now correctly override schema-defined colors when a non-default style is selected
  - Fixed Attack Trees leaf nodes ignoring selected style - CVSS-based colors no longer override the selected style (CVSS info still shown in labels)
  - Fixed Attack Graphs vulnerability nodes ignoring selected style - same CVSS color fix as Attack Trees

### Changed

- **Custom Diagrams Style System Overhaul**
  - Custom Diagrams now loads style configuration from `config_customdiagrams.tml` instead of using hardcoded values
  - Added `_strip_style_attrs()` method to strip schema-defined style attributes when non-default style is selected
  - Node colors, edge colors, and cluster styling now respect the selected style preset
  - Style presets (dark, neon, monochrome, etc.) now fully apply to all diagram elements

### Behavior Changes

- **Default Style**: Template/schema-defined colors are preserved (backward compatible)
- **Non-Default Styles**: Style colors take full precedence over template/schema colors
- CVSS severity information is still displayed in node labels regardless of style selection

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
