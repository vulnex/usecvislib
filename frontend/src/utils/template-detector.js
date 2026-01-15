/**
 * VULNEX -Universal Security Visualization Library-
 *
 * File: template-detector.js
 * Author: Claude Code
 * Created: 2026-01-01
 * Version: 0.3.3
 * License: Apache-2.0
 * Copyright (c) 2025 VULNEX. All rights reserved.
 * https://www.vulnex.com
 *
 * Template type detection utility
 * Detects whether a configuration file is for Attack Trees, Attack Graphs, or Threat Models
 */

import { parse as parseToml } from 'smol-toml'
import yaml from 'js-yaml'

/**
 * Template types
 */
export const TemplateType = {
  ATTACK_TREE: 'attack-tree',
  ATTACK_GRAPH: 'attack-graph',
  THREAT_MODEL: 'threat-model',
  CUSTOM_DIAGRAM: 'custom-diagram',
  UNKNOWN: 'unknown'
}

/**
 * Human-readable names for template types
 */
export const TemplateTypeNames = {
  [TemplateType.ATTACK_TREE]: 'Attack Tree',
  [TemplateType.ATTACK_GRAPH]: 'Attack Graph',
  [TemplateType.THREAT_MODEL]: 'Threat Model',
  [TemplateType.CUSTOM_DIAGRAM]: 'Custom Diagram',
  [TemplateType.UNKNOWN]: 'Unknown'
}

/**
 * Panel names that correspond to each template type
 */
export const TemplateTypePanels = {
  [TemplateType.ATTACK_TREE]: 'Attack Trees',
  [TemplateType.ATTACK_GRAPH]: 'Attack Graphs',
  [TemplateType.THREAT_MODEL]: 'Threat Models',
  [TemplateType.CUSTOM_DIAGRAM]: 'Custom Diagrams',
  [TemplateType.UNKNOWN]: null
}

/**
 * Parse content based on format
 * @param {string} content - Raw content string
 * @param {string} format - Format: 'toml', 'json', or 'yaml'
 * @returns {object|null} Parsed object or null if parsing fails
 */
function parseContent(content, format) {
  try {
    switch (format) {
      case 'json':
        return JSON.parse(content)
      case 'yaml':
        return yaml.load(content)
      case 'toml':
      default:
        return parseToml(content)
    }
  } catch (e) {
    return null
  }
}

/**
 * Detect format from content
 * @param {string} content - Raw content string
 * @returns {'toml' | 'json' | 'yaml'}
 */
function detectFormat(content) {
  const trimmed = content.trim()

  // JSON starts with { or [
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    try {
      JSON.parse(content)
      return 'json'
    } catch (e) {
      // Not valid JSON
    }
  }

  // Check for YAML indicators (but not TOML)
  if (trimmed.startsWith('---') || /^[\w]+:\s*$/m.test(content)) {
    try {
      yaml.load(content)
      return 'yaml'
    } catch (e) {
      // Not valid YAML
    }
  }

  // Default to TOML
  return 'toml'
}

/**
 * Check if object has Attack Tree structure
 * Attack Trees have: [tree] with root, [nodes], [edges]
 * @param {object} obj - Parsed configuration object
 * @returns {boolean}
 */
function isAttackTree(obj) {
  // Must have tree section with root
  if (obj.tree && obj.tree.root) {
    return true
  }

  // Or have nodes and edges at root level with tree-like structure
  if (obj.nodes && obj.edges && !obj.graph && !obj.model && !obj.diagram) {
    return true
  }

  return false
}

/**
 * Check if object has Attack Graph structure
 * Attack Graphs have: [graph], [[hosts]], [[vulnerabilities]], [[exploits]]
 * @param {object} obj - Parsed configuration object
 * @returns {boolean}
 */
function isAttackGraph(obj) {
  // Must have graph section
  if (obj.graph) {
    // And typically has hosts, vulnerabilities, or exploits
    if (obj.hosts || obj.vulnerabilities || obj.exploits) {
      return true
    }
    // Or graph section with network-related fields
    if (obj.graph.name || obj.graph.title) {
      // Check for host/vulnerability arrays
      if (Array.isArray(obj.hosts) || Array.isArray(obj.vulnerabilities)) {
        return true
      }
    }
  }

  // Check for hosts array with zone/type fields (attack graph specific)
  if (Array.isArray(obj.hosts)) {
    const hasHostFields = obj.hosts.some(h => h.zone || h.host_type || h.services)
    if (hasHostFields) {
      return true
    }
  }

  return false
}

/**
 * Check if object has Threat Model structure
 * Threat Models have: [model], [processes.*], [externals.*], [datastores.*], [dataflows.*]
 * @param {object} obj - Parsed configuration object
 * @returns {boolean}
 */
function isThreatModel(obj) {
  // Must have model section
  if (obj.model) {
    return true
  }

  // Or have DFD-specific sections
  if (obj.processes || obj.externals || obj.datastores || obj.dataflows) {
    return true
  }

  // Check for boundaries (trust boundaries)
  if (obj.boundaries) {
    return true
  }

  return false
}

/**
 * Check if object has Custom Diagram structure
 * Custom Diagrams have: [diagram], [schema]
 * @param {object} obj - Parsed configuration object
 * @returns {boolean}
 */
function isCustomDiagram(obj) {
  // Must have diagram section
  if (obj.diagram) {
    // And typically has schema or nodes with custom shapes
    if (obj.schema || obj.diagram.layout || obj.diagram.style) {
      return true
    }
  }

  return false
}

/**
 * Detect template type from content
 * @param {string} content - Raw configuration content (TOML, JSON, or YAML)
 * @param {string} [format] - Optional format hint ('toml', 'json', 'yaml')
 * @returns {{type: string, confidence: 'high' | 'medium' | 'low', detectedFormat: string}}
 */
export function detectTemplateType(content, format = null) {
  if (!content || typeof content !== 'string') {
    return { type: TemplateType.UNKNOWN, confidence: 'low', detectedFormat: 'unknown' }
  }

  // Detect format if not provided
  const detectedFormat = format || detectFormat(content)

  // Parse the content
  const obj = parseContent(content, detectedFormat)

  if (!obj) {
    return { type: TemplateType.UNKNOWN, confidence: 'low', detectedFormat }
  }

  // Check each type in order of specificity
  // Attack Graph is most specific (has unique fields like hosts, vulnerabilities)
  if (isAttackGraph(obj)) {
    return { type: TemplateType.ATTACK_GRAPH, confidence: 'high', detectedFormat }
  }

  // Threat Model is next (has model, processes, dataflows)
  if (isThreatModel(obj)) {
    return { type: TemplateType.THREAT_MODEL, confidence: 'high', detectedFormat }
  }

  // Custom Diagram (has diagram with schema)
  if (isCustomDiagram(obj)) {
    return { type: TemplateType.CUSTOM_DIAGRAM, confidence: 'high', detectedFormat }
  }

  // Attack Tree is most generic (tree with nodes/edges)
  if (isAttackTree(obj)) {
    return { type: TemplateType.ATTACK_TREE, confidence: 'high', detectedFormat }
  }

  // Unknown type
  return { type: TemplateType.UNKNOWN, confidence: 'low', detectedFormat }
}

/**
 * Check if template type matches expected type for a panel
 * @param {string} content - Raw configuration content
 * @param {string} expectedType - Expected template type (from TemplateType)
 * @param {string} [format] - Optional format hint
 * @returns {{matches: boolean, detectedType: string, detectedTypeName: string, expectedTypeName: string, suggestedPanel: string|null}}
 */
export function validateTemplateType(content, expectedType, format = null) {
  const detection = detectTemplateType(content, format)

  return {
    matches: detection.type === expectedType || detection.type === TemplateType.UNKNOWN,
    detectedType: detection.type,
    detectedTypeName: TemplateTypeNames[detection.type],
    expectedTypeName: TemplateTypeNames[expectedType],
    suggestedPanel: TemplateTypePanels[detection.type],
    confidence: detection.confidence
  }
}
