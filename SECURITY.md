# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.3.x   | :white_check_mark: |
| < 0.3   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability in USecVisLib, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please send an email to **security@vulnex.com** with:

- A description of the vulnerability
- Steps to reproduce the issue
- The potential impact
- Any suggested fixes (optional)

## Response Timeline

- **Acknowledgment**: Within 48 hours of receiving your report
- **Initial assessment**: Within 5 business days
- **Fix and disclosure**: We aim to release a fix within 30 days for confirmed vulnerabilities

## Scope

This policy covers the USecVisLib library, API server, and web frontend, including:

- Authentication and authorization mechanisms (API key validation, constant-time comparison)
- Input validation and sanitization (configuration files, graph data, image uploads)
- Path traversal and file access controls (symlink rejection, sensitive path blocklist)
- DOT/Graphviz injection prevention (label escaping, node ID sanitization)
- Rate limiting and resource management (request throttling, graph complexity limits)
- Security headers and CORS configuration
- Docker container security (non-root execution, resource limits)
- File upload validation (magic bytes detection, SVG XXE prevention)

## Acknowledgments

We appreciate responsible disclosure and will credit reporters in the CHANGELOG (unless you prefer to remain anonymous).
