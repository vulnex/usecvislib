# Security Policy

USecVisLib is a security visualization library, shipped with the `usecvis` CLI, a REST API server, a web frontend and a Docker setup; vulnerability reports against it are handled through the coordinated-disclosure process below.

## Supported Versions

Security fixes land on the latest released minor version. Older versions do not receive backports.

| Version | Supported |
|---------|-----------|
| 0.6.x   | Yes       |
| < 0.6   | No        |

## Reporting a Vulnerability

**Do not open a public issue for security vulnerabilities.** Use one of the private channels below.

**Preferred — GitHub Private Security Advisory:**
[github.com/vulnex/usecvislib/security/advisories/new](https://github.com/vulnex/usecvislib/security/advisories/new)

**Alternative — Email:** security@vulnex.com

Please include:

- A description of the issue and its impact
- Steps to reproduce (proof-of-concept welcome; a minimal input file helps)
- The USecVisLib version affected (`python -c "import usecvislib; print(usecvislib.__version__)"` or `pip show usecvislib`)
- Your platform and Python version
- The affected component: library, `usecvis` CLI, API server, web frontend, or Docker image / `docker-compose.yml` setup
- Whether you intend to disclose publicly, and on what timeline

## What to Expect

- **Acknowledgement** within 3 business days of report.
- **Initial assessment** (severity, scope, fix path) within 7 business days.
- **Fix and release** target: 30 days for critical/high, 90 days for medium/low. We will keep you informed if a fix needs longer.
- **Disclosure** is coordinated — we credit the reporter in the release notes unless you ask otherwise, and we will not publish details until a patched release is available.

We do not run a paid bug bounty program at this time.

## Scope

In scope:

- Code execution through crafted input files (TOML / JSON / YAML / Mermaid) in the library, CLI or API server
- DOT/Graphviz injection: labels or node IDs that escape label escaping or node-ID sanitization
- Path traversal or unsafe file operations: escaping input/output path validation, symlink rejection, the sensitive-path blocklist for output files, or the bundled-icon and uploaded-image directories
- File upload validation bypass in the API: magic-byte content checks, SVG uploads carrying DTD/entity declarations (XXE)
- Authentication and authorization bypass in the API server: API key validation, job tokens for progress streams, the unauthenticated path list
- Rate-limiting, request-size, timeout, or graph-complexity bypasses that lead to denial of service
- Security header or CORS misconfiguration in the API server as shipped
- Docker image and `docker-compose.yml` weaknesses in the shipped configuration (non-root execution, resource limits, default port bindings)
- Cross-site scripting or similar injection in the web frontend or in generated SVG/HTML output when rendering attacker-controlled input

Out of scope:

- Vulnerabilities in Graphviz, mermaid-cli, Chromium, the `diagrams` package, or other external renderers themselves — report those upstream to their maintainers.
- Deployments that change the shipped security settings (for example exposing the API beyond loopback with authentication disabled, adding wildcard CORS origins, or removing resource limits).
- Issues that require an attacker to already have write access to the host, the user's files, or the deployment's environment configuration.
- Rendering bugs that are not security issues (wrong layout, colors, missing elements) — please open a regular issue.
- Social-engineering attacks against USecVisLib maintainers.

## Hardening Stance

USecVisLib is built defense-first:

- **Input files are parsed as data.** TOML and JSON use standard parsers and YAML is loaded with `yaml.safe_load`; parsed configs are subject to a nesting-depth limit, and config uploads to the API are capped at 1 MB.
- **No outbound network calls from USecVisLib's own code.** The library, CLI and API server render locally (Graphviz, matplotlib, the built-in SVG engine, and locally installed mermaid-cli and `diagrams`); there are no update checks, telemetry or remote fetches.
- **DOT output is escaped.** Labels pass through `escape_dot_label()` (quotes, backslashes, control characters and record/HTML-like characters escaped, length capped) and node IDs through `sanitize_node_id()` (alphanumerics, `_` and `-` only).
- **Path checks on file access.** Input paths reject null bytes and symlinks; output paths are refused under system locations (`/etc`, `/usr`, `/proc`, …), checked on both the resolved and the lexical path; bundled icons and uploaded images are confined to their directories.
- **Upload validation.** Image uploads are checked by magic bytes rather than the claimed type, capped at 5 MB, and SVG uploads containing a DOCTYPE or entity declaration are rejected.
- **API authentication is opt-in and fails closed when enabled.** It is off by default (`USECVISLIB_AUTH_ENABLED=false`); when enabled, the server refuses to start without an API key, and keys are compared as SHA-256 digests with `secrets.compare_digest`. Only documentation, `/health` and icon endpoints are unauthenticated.
- **API rate limiting and resource bounds.** Endpoints are rate-limited per client (defaults 30/min general, 10/min visualize, 20/min analyze), request bodies are size-limited, requests have timeouts, and graphs are subject to node/edge complexity limits.
- **Security headers and strict CORS.** The API sets HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, a Referrer-Policy and a Content-Security-Policy; CORS allows only explicitly listed origins and rejects wildcards.
- **Hardened containers.** The API image runs as a non-root `appuser` and the frontend nginx image as the `nginx` user; `docker-compose.yml` sets memory/CPU limits on every service and binds the API to loopback by default.

If a contribution would weaken any of the above, expect it to be declined regardless of feature value.
