/**
 * VULNEX -Universal Security Visualization Library-
 *
 * File: toml-validator.js
 * Author: Simon Roses Femerling
 * Created: 2025-01-01
 * Last Modified: 2025-12-23
 * Version: 0.3.1
 * License: Apache-2.0
 * Copyright (c) 2025 VULNEX. All rights reserved.
 * https://www.vulnex.com
 *
 * TOML Validation utility using smol-toml
 * Provides live validation with detailed error messages
 */

import { parse } from 'smol-toml'

/**
 * Validate TOML content and return diagnostics
 * @param {string} content - TOML content to validate
 * @returns {Array<{from: number, to: number, severity: string, message: string}>}
 */
export function validateToml(content) {
  const diagnostics = []

  if (!content || !content.trim()) {
    return diagnostics
  }

  try {
    parse(content)
  } catch (error) {
    // smol-toml provides line/column information
    const line = error.line || 1
    const column = error.column || 1
    const message = error.message || 'Invalid TOML syntax'

    // Calculate character position from line/column
    const lines = content.split('\n')
    let from = 0
    for (let i = 0; i < line - 1 && i < lines.length; i++) {
      from += lines[i].length + 1  // +1 for newline
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
 * Validate TOML for attack tree specific structure
 * @param {string} content - TOML content
 * @returns {Array<{from: number, to: number, severity: string, message: string}>}
 */
export function validateAttackTreeStructure(content) {
  const diagnostics = validateToml(content)

  if (diagnostics.length > 0) {
    return diagnostics  // Return syntax errors first
  }

  try {
    const data = parse(content)

    // Check for required sections
    if (!data.tree) {
      diagnostics.push({
        from: 0,
        to: 1,
        severity: 'warning',
        message: 'Missing [tree] section - required for attack tree visualization',
      })
    } else {
      if (!data.tree.name) {
        diagnostics.push({
          from: 0,
          to: 1,
          severity: 'warning',
          message: 'Missing "name" in [tree] section',
        })
      }
      if (!data.tree.root) {
        diagnostics.push({
          from: 0,
          to: 1,
          severity: 'warning',
          message: 'Missing "root" in [tree] section',
        })
      }
    }

    if (!data.nodes || Object.keys(data.nodes).length === 0) {
      diagnostics.push({
        from: 0,
        to: 1,
        severity: 'warning',
        message: 'Missing or empty [nodes] section',
      })
    }

    if (!data.edges) {
      diagnostics.push({
        from: 0,
        to: 1,
        severity: 'warning',
        message: 'Missing [edges] section',
      })
    }
  } catch (e) {
    // Parsing error already handled
  }

  return diagnostics
}

/**
 * Validate TOML for threat model specific structure
 * @param {string} content - TOML content
 * @returns {Array<{from: number, to: number, severity: string, message: string}>}
 */
export function validateThreatModelStructure(content) {
  const diagnostics = validateToml(content)

  if (diagnostics.length > 0) {
    return diagnostics
  }

  try {
    const data = parse(content)

    if (!data.model) {
      diagnostics.push({
        from: 0,
        to: 1,
        severity: 'warning',
        message: 'Missing [model] section - required for threat model visualization',
      })
    } else if (!data.model.name) {
      diagnostics.push({
        from: 0,
        to: 1,
        severity: 'warning',
        message: 'Missing "name" in [model] section',
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
        message: 'Threat model should have at least one of: [externals], [processes], [datastores]',
      })
    }

    if (!data.dataflows || Object.keys(data.dataflows).length === 0) {
      diagnostics.push({
        from: 0,
        to: 1,
        severity: 'warning',
        message: 'Missing or empty [dataflows] section - required for DFD visualization',
      })
    }
  } catch (e) {
    // Parsing error already handled
  }

  return diagnostics
}
