/**
 * VULNEX -Universal Security Visualization Library-
 *
 * File: config-validator.js
 * Author: Simon Roses Femerling
 * Created: 2025-01-01
 * Last Modified: 2025-12-23
 * Version: 0.3.1
 * License: Apache-2.0
 * Copyright (c) 2025 VULNEX. All rights reserved.
 * https://www.vulnex.com
 *
 * Configuration file validation utility
 * Supports TOML, JSON, and YAML formats with live validation
 */

import { parse as parseToml } from 'smol-toml'
import yaml from 'js-yaml'

/**
 * Detect configuration format from content
 * @param {string} content - Configuration content
 * @param {string} filename - Optional filename for extension-based detection
 * @returns {'toml' | 'json' | 'yaml'}
 */
export function detectFormat(content, filename = '') {
  // First try extension-based detection
  if (filename) {
    const ext = filename.toLowerCase().split('.').pop()
    if (ext === 'json') return 'json'
    if (ext === 'yaml' || ext === 'yml') return 'yaml'
    if (ext === 'toml' || ext === 'tml') return 'toml'
  }

  // Content-based detection
  const trimmed = content.trim()

  // JSON starts with { or [
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    try {
      JSON.parse(content)
      return 'json'
    } catch (e) {
      // Not valid JSON, continue checking
    }
  }

  // TOML has distinct patterns: [sections], key = value
  if (/^\s*\[[\w.-]+\]/m.test(content) || /^\s*[\w.-]+\s*=/m.test(content)) {
    try {
      parseToml(content)
      return 'toml'
    } catch (e) {
      // Not valid TOML, try YAML
    }
  }

  // Default to YAML (most permissive)
  return 'yaml'
}

/**
 * Parse content based on format
 * @param {string} content - Configuration content
 * @param {'toml' | 'json' | 'yaml'} format - Format to parse as
 * @returns {{data: object|null, error: {message: string, line?: number, column?: number}|null}}
 */
export function parseContent(content, format) {
  if (!content || !content.trim()) {
    return { data: {}, error: null }
  }

  try {
    let data
    switch (format) {
      case 'json':
        data = JSON.parse(content)
        break
      case 'yaml':
        data = yaml.load(content) || {}
        break
      case 'toml':
      default:
        data = parseToml(content)
        break
    }
    return { data, error: null }
  } catch (error) {
    return {
      data: null,
      error: {
        message: error.message || 'Invalid syntax',
        line: error.line || error.mark?.line + 1 || 1,
        column: error.column || error.mark?.column + 1 || 1,
      }
    }
  }
}

/**
 * Validate configuration content and return diagnostics
 * @param {string} content - Content to validate
 * @param {'toml' | 'json' | 'yaml'} format - Format of content
 * @returns {Array<{from: number, to: number, severity: string, message: string}>}
 */
export function validateConfig(content, format) {
  const diagnostics = []

  if (!content || !content.trim()) {
    return diagnostics
  }

  const { error } = parseContent(content, format)

  if (error) {
    const line = error.line || 1
    const column = error.column || 1
    const message = error.message

    // Calculate character position from line/column
    const lines = content.split('\n')
    let from = 0
    for (let i = 0; i < line - 1 && i < lines.length; i++) {
      from += lines[i].length + 1
    }
    from += Math.min(column - 1, (lines[line - 1] || '').length)

    // Highlight to end of line or reasonable span
    const lineContent = lines[line - 1] || ''
    const to = from + Math.max(1, lineContent.length - column + 1)

    diagnostics.push({
      from,
      to: Math.min(to, content.length),
      severity: 'error',
      message: `Line ${line}: ${message}`,
    })
  }

  return diagnostics
}

/**
 * Validate attack tree structure
 * @param {string} content - Configuration content
 * @param {'toml' | 'json' | 'yaml'} format - Format of content
 * @returns {Array<{from: number, to: number, severity: string, message: string}>}
 */
export function validateAttackTreeStructure(content, format = 'toml') {
  const diagnostics = validateConfig(content, format)

  if (diagnostics.length > 0) {
    return diagnostics
  }

  const { data } = parseContent(content, format)
  if (!data) return diagnostics

  // Check for required sections
  if (!data.tree) {
    diagnostics.push({
      from: 0,
      to: 1,
      severity: 'warning',
      message: 'Missing "tree" section - required for attack tree visualization',
    })
  } else {
    if (!data.tree.name) {
      diagnostics.push({
        from: 0,
        to: 1,
        severity: 'warning',
        message: 'Missing "name" in "tree" section',
      })
    }
    if (!data.tree.root) {
      diagnostics.push({
        from: 0,
        to: 1,
        severity: 'warning',
        message: 'Missing "root" in "tree" section',
      })
    }
  }

  if (!data.nodes || Object.keys(data.nodes).length === 0) {
    diagnostics.push({
      from: 0,
      to: 1,
      severity: 'warning',
      message: 'Missing or empty "nodes" section',
    })
  }

  if (!data.edges) {
    diagnostics.push({
      from: 0,
      to: 1,
      severity: 'warning',
      message: 'Missing "edges" section',
    })
  }

  return diagnostics
}

/**
 * Validate threat model structure
 * @param {string} content - Configuration content
 * @param {'toml' | 'json' | 'yaml'} format - Format of content
 * @returns {Array<{from: number, to: number, severity: string, message: string}>}
 */
export function validateThreatModelStructure(content, format = 'toml') {
  const diagnostics = validateConfig(content, format)

  if (diagnostics.length > 0) {
    return diagnostics
  }

  const { data } = parseContent(content, format)
  if (!data) return diagnostics

  if (!data.model) {
    diagnostics.push({
      from: 0,
      to: 1,
      severity: 'warning',
      message: 'Missing "model" section - required for threat model visualization',
    })
  } else if (!data.model.name) {
    diagnostics.push({
      from: 0,
      to: 1,
      severity: 'warning',
      message: 'Missing "name" in "model" section',
    })
  }

  const hasProcesses = data.processes && Object.keys(data.processes).length > 0
  const hasExternals = data.externals && Object.keys(data.externals).length > 0
  const hasDatastores = data.datastores && Object.keys(data.datastores).length > 0

  if (!hasProcesses && !hasExternals && !hasDatastores) {
    diagnostics.push({
      from: 0,
      to: 1,
      severity: 'warning',
      message: 'Threat model should have at least one of: "externals", "processes", "datastores"',
    })
  }

  if (!data.dataflows || Object.keys(data.dataflows).length === 0) {
    diagnostics.push({
      from: 0,
      to: 1,
      severity: 'warning',
      message: 'Missing or empty "dataflows" section - required for DFD visualization',
    })
  }

  return diagnostics
}

// Re-export for backwards compatibility
export { validateConfig as validateToml }
