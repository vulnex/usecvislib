/**
 * VULNEX -Universal Security Visualization Library-
 *
 * File: api.js
 * Author: Simon Roses Femerling
 * Created: 2025-01-01
 * Last Modified: 2025-12-30
 * Version: 0.3.1
 * License: Apache-2.0
 * Copyright (c) 2025 VULNEX. All rights reserved.
 * https://www.vulnex.com
 *
 * API Service - Handles all communication with the backend API
 */

import axios from 'axios'

// API base URL - uses proxy in development
const API_BASE = '/api'

// =============================================================================
// API Key Management
// =============================================================================

const API_KEY_STORAGE_KEY = 'usecvislib_api_key'

/**
 * Get the stored API key
 * @returns {string} The API key or empty string if not set
 */
export function getApiKey() {
  try {
    return localStorage.getItem(API_KEY_STORAGE_KEY) || ''
  } catch (e) {
    // localStorage may not be available in some contexts
    console.warn('localStorage not available:', e)
    return ''
  }
}

/**
 * Set the API key
 * @param {string} key - The API key to store
 */
export function setApiKey(key) {
  try {
    if (key) {
      localStorage.setItem(API_KEY_STORAGE_KEY, key)
    } else {
      localStorage.removeItem(API_KEY_STORAGE_KEY)
    }
  } catch (e) {
    console.warn('localStorage not available:', e)
  }
}

/**
 * Clear the stored API key
 */
export function clearApiKey() {
  setApiKey('')
}

/**
 * Check if an API key is configured
 * @returns {boolean} True if API key is set
 */
export function hasApiKey() {
  return getApiKey().length > 0
}

// =============================================================================
// Axios Instance with Authentication
// =============================================================================

// Create axios instance with defaults
const api = axios.create({
  baseURL: API_BASE,
  timeout: 60000, // 60 seconds for large file processing
})

// Request interceptor - add API key to all requests
api.interceptors.request.use(
  (config) => {
    const apiKey = getApiKey()
    if (apiKey) {
      config.headers['X-API-Key'] = apiKey
    }
    return config
  },
  (error) => {
    return Promise.reject(error)
  }
)

// Response interceptor - handle authentication errors
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      // Dispatch custom event for auth failure
      const event = new CustomEvent('usecvislib:auth-error', {
        detail: {
          message: error.response?.data?.detail || 'Authentication failed',
          status: 401
        }
      })
      window.dispatchEvent(event)
    }
    return Promise.reject(error)
  }
)

/**
 * Health check
 */
export async function checkHealth() {
  const response = await api.get('/health')
  return response.data
}

/**
 * Get available styles
 */
export async function getStyles() {
  const response = await api.get('/styles')
  return response.data
}

/**
 * Get supported formats
 */
export async function getFormats() {
  const response = await api.get('/formats')
  return response.data
}

/**
 * Get available threat modeling engines
 */
export async function getEngines() {
  const response = await api.get('/engines')
  return response.data
}

/**
 * Generate attack tree visualization
 */
export async function visualizeAttackTree(file, format = 'png', style = 'at_default') {
  const formData = new FormData()
  formData.append('file', file)

  const response = await api.post(
    `/visualize/attack-tree?format=${format}&style=${style}`,
    formData,
    {
      responseType: 'blob',
      headers: { 'Content-Type': 'multipart/form-data' }
    }
  )
  return response.data
}

/**
 * Analyze attack tree
 */
export async function analyzeAttackTree(file) {
  const formData = new FormData()
  formData.append('file', file)

  const response = await api.post('/analyze/attack-tree', formData, {
    headers: { 'Content-Type': 'multipart/form-data' }
  })
  return response.data
}

/**
 * Validate attack tree
 */
export async function validateAttackTree(file) {
  const formData = new FormData()
  formData.append('file', file)

  const response = await api.post('/validate/attack-tree', formData, {
    headers: { 'Content-Type': 'multipart/form-data' }
  })
  return response.data
}

/**
 * Generate threat model visualization
 */
export async function visualizeThreatModel(file, format = 'png', style = 'tm_default', engine = 'usecvislib') {
  const formData = new FormData()
  formData.append('file', file)

  const response = await api.post(
    `/visualize/threat-model?format=${format}&style=${style}&engine=${engine}`,
    formData,
    {
      responseType: 'blob',
      headers: { 'Content-Type': 'multipart/form-data' }
    }
  )
  return response.data
}

/**
 * Analyze threat model
 */
export async function analyzeThreatModel(file) {
  const formData = new FormData()
  formData.append('file', file)

  const response = await api.post('/analyze/threat-model', formData, {
    headers: { 'Content-Type': 'multipart/form-data' }
  })
  return response.data
}

/**
 * Perform STRIDE analysis
 */
export async function analyzeStride(file) {
  const formData = new FormData()
  formData.append('file', file)

  const response = await api.post('/analyze/stride', formData, {
    headers: { 'Content-Type': 'multipart/form-data' }
  })
  return response.data
}

/**
 * Generate binary visualization
 * @param {File} file - Binary file to visualize
 * @param {string} format - Output format (png, svg, pdf)
 * @param {string} style - Style preset (bv_default, etc.)
 * @param {string} visType - Visualization type (entropy, distribution, windrose, heatmap)
 * @param {string|null} configJson - Optional JSON string with visualization config
 */
export async function visualizeBinary(file, format = 'png', style = 'bv_default', visType = 'entropy', configJson = null) {
  const formData = new FormData()
  formData.append('file', file)

  // Add config JSON if provided
  if (configJson) {
    formData.append('config_json', configJson)
  }

  const response = await api.post(
    `/visualize/binary?format=${format}&style=${style}&visualization_type=${visType}`,
    formData,
    {
      responseType: 'blob',
      headers: { 'Content-Type': 'multipart/form-data' }
    }
  )
  return response.data
}

/**
 * Analyze binary file
 */
export async function analyzeBinary(file) {
  const formData = new FormData()
  formData.append('file', file)

  const response = await api.post('/analyze/binary', formData, {
    headers: { 'Content-Type': 'multipart/form-data' }
  })
  return response.data
}

/**
 * Create object URL from blob for display
 */
export function createImageUrl(blob) {
  return URL.createObjectURL(blob)
}

/**
 * Generate timestamp string for filenames (YYYYMMDD_HHMMSS)
 */
export function getTimestamp() {
  const now = new Date()
  const year = now.getFullYear()
  const month = String(now.getMonth() + 1).padStart(2, '0')
  const day = String(now.getDate()).padStart(2, '0')
  const hours = String(now.getHours()).padStart(2, '0')
  const minutes = String(now.getMinutes()).padStart(2, '0')
  const seconds = String(now.getSeconds()).padStart(2, '0')
  return `${year}${month}${day}_${hours}${minutes}${seconds}`
}

/**
 * Download blob as file
 */
export function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
}

/**
 * Get file extension from config format
 * @param {string} configFormat - 'toml', 'json', or 'yaml'
 */
function getExtensionFromFormat(configFormat) {
  const extensions = {
    'toml': '.tml',
    'json': '.json',
    'yaml': '.yaml',
  }
  return extensions[configFormat] || '.tml'
}

/**
 * Helper to create a File from text content
 * @param {string} content - File content
 * @param {string} baseName - Base filename without extension
 * @param {string} configFormat - 'toml', 'json', or 'yaml'
 */
function createFileFromContent(content, baseName = 'input', configFormat = 'toml') {
  const extension = getExtensionFromFormat(configFormat)
  const filename = `${baseName}${extension}`
  const blob = new Blob([content], { type: 'text/plain' })
  return new File([blob], filename, { type: 'text/plain' })
}

/**
 * Generate attack tree visualization from text content
 * @param {string} content - Configuration content
 * @param {string} outputFormat - Output format (png, svg, pdf)
 * @param {string} style - Style preset
 * @param {string} configFormat - Configuration format (toml, json, yaml)
 */
export async function visualizeAttackTreeFromContent(content, outputFormat = 'png', style = 'at_default', configFormat = 'toml') {
  const file = createFileFromContent(content, 'attack_tree', configFormat)
  return visualizeAttackTree(file, outputFormat, style)
}

/**
 * Analyze attack tree from text content
 * @param {string} content - Configuration content
 * @param {string} configFormat - Configuration format (toml, json, yaml)
 */
export async function analyzeAttackTreeFromContent(content, configFormat = 'toml') {
  const file = createFileFromContent(content, 'attack_tree', configFormat)
  return analyzeAttackTree(file)
}

/**
 * Validate attack tree from text content
 * @param {string} content - Configuration content
 * @param {string} configFormat - Configuration format (toml, json, yaml)
 */
export async function validateAttackTreeFromContent(content, configFormat = 'toml') {
  const file = createFileFromContent(content, 'attack_tree', configFormat)
  return validateAttackTree(file)
}

/**
 * Generate threat model visualization from text content
 * @param {string} content - Configuration content
 * @param {string} outputFormat - Output format (png, svg, pdf)
 * @param {string} style - Style preset
 * @param {string} engine - Engine (usecvislib, pytm)
 * @param {string} configFormat - Configuration format (toml, json, yaml)
 */
export async function visualizeThreatModelFromContent(content, outputFormat = 'png', style = 'tm_default', engine = 'usecvislib', configFormat = 'toml') {
  const file = createFileFromContent(content, 'threat_model', configFormat)
  return visualizeThreatModel(file, outputFormat, style, engine)
}

/**
 * Analyze threat model from text content
 * @param {string} content - Configuration content
 * @param {string} configFormat - Configuration format (toml, json, yaml)
 */
export async function analyzeThreatModelFromContent(content, configFormat = 'toml') {
  const file = createFileFromContent(content, 'threat_model', configFormat)
  return analyzeThreatModel(file)
}

/**
 * Perform STRIDE analysis from text content
 * @param {string} content - Configuration content
 * @param {string} configFormat - Configuration format (toml, json, yaml)
 */
export async function analyzeStrideFromContent(content, configFormat = 'toml') {
  const file = createFileFromContent(content, 'threat_model', configFormat)
  return analyzeStride(file)
}

/**
 * Convert configuration file to another format
 * @param {File} file - Configuration file to convert
 * @param {string} targetFormat - Target format ('toml', 'json', or 'yaml')
 * @returns {Promise<{content: string, source_format: string, target_format: string, filename: string}>}
 */
export async function convertFormat(file, targetFormat) {
  const formData = new FormData()
  formData.append('file', file)

  const response = await api.post(
    `/convert?target_format=${targetFormat}`,
    formData,
    {
      headers: { 'Content-Type': 'multipart/form-data' }
    }
  )
  return response.data
}

/**
 * Convert configuration content to another format
 * @param {string} content - Configuration content
 * @param {string} sourceFormat - Source format ('toml', 'json', or 'yaml')
 * @param {string} targetFormat - Target format ('toml', 'json', or 'yaml')
 * @returns {Promise<{content: string, source_format: string, target_format: string, filename: string}>}
 */
export async function convertFormatFromContent(content, sourceFormat, targetFormat) {
  const file = createFileFromContent(content, 'config', sourceFormat)
  return convertFormat(file, targetFormat)
}

/**
 * Download text content as a file
 * @param {string} content - Text content to download
 * @param {string} filename - Filename for download
 */
export function downloadTextFile(content, filename) {
  const blob = new Blob([content], { type: 'text/plain' })
  downloadBlob(blob, filename)
}

/**
 * Generate threat model report
 * @param {File} file - Threat model configuration file
 * @param {string} format - Report format ('markdown' or 'html')
 * @returns {Promise<{content: string, format: string, filename: string}>}
 */
export async function generateReport(file, format = 'markdown') {
  const formData = new FormData()
  formData.append('file', file)

  const response = await api.post(
    `/report/threat-model?format=${format}`,
    formData,
    {
      headers: { 'Content-Type': 'multipart/form-data' }
    }
  )
  return response.data
}

/**
 * Generate threat model report from content
 * @param {string} content - Configuration content
 * @param {string} configFormat - Configuration format (toml, json, yaml)
 * @param {string} reportFormat - Report format ('markdown' or 'html')
 * @returns {Promise<{content: string, format: string, filename: string}>}
 */
export async function generateReportFromContent(content, configFormat = 'toml', reportFormat = 'markdown') {
  const file = createFileFromContent(content, 'threat_model', configFormat)
  return generateReport(file, reportFormat)
}

/**
 * Get threat library
 * @param {string|null} elementType - Optional element type filter
 * @param {number} limit - Maximum threats to return
 * @param {number} offset - Pagination offset
 * @returns {Promise<{total: number, threats: Array, pytm_available: boolean}>}
 */
export async function getThreatLibrary(elementType = null, limit = 100, offset = 0) {
  let url = `/threats/library?limit=${limit}&offset=${offset}`
  if (elementType) {
    url += `&element_type=${elementType}`
  }
  const response = await api.get(url)
  return response.data
}

/**
 * Get available element types for threat filtering
 * @returns {Promise<{element_types: string[]}>}
 */
export async function getThreatElementTypes() {
  const response = await api.get('/threats/element-types')
  return response.data
}

// =============================================================================
// Attack Graph Functions
// =============================================================================

/**
 * Generate attack graph visualization
 * @param {File} file - Attack graph configuration file
 * @param {string} format - Output format (png, svg, pdf)
 * @param {string} style - Style preset
 */
export async function visualizeAttackGraph(file, format = 'png', style = 'ag_default') {
  const formData = new FormData()
  formData.append('file', file)

  const response = await api.post(
    `/visualize/attack-graph?format=${format}&style=${style}`,
    formData,
    {
      responseType: 'blob',
      headers: { 'Content-Type': 'multipart/form-data' }
    }
  )
  return response.data
}

/**
 * Generate attack graph visualization from text content
 * @param {string} content - Configuration content
 * @param {string} outputFormat - Output format (png, svg, pdf)
 * @param {string} style - Style preset
 * @param {string} configFormat - Configuration format (toml, json, yaml)
 */
export async function visualizeAttackGraphFromContent(content, outputFormat = 'png', style = 'ag_default', configFormat = 'toml') {
  const file = createFileFromContent(content, 'attack_graph', configFormat)
  return visualizeAttackGraph(file, outputFormat, style)
}

/**
 * Analyze attack graph
 * @param {File} file - Attack graph configuration file
 */
export async function analyzeAttackGraph(file) {
  const formData = new FormData()
  formData.append('file', file)

  const response = await api.post('/analyze/attack-graph', formData, {
    headers: { 'Content-Type': 'multipart/form-data' }
  })
  return response.data
}

/**
 * Analyze attack graph from text content
 * @param {string} content - Configuration content
 * @param {string} configFormat - Configuration format (toml, json, yaml)
 */
export async function analyzeAttackGraphFromContent(content, configFormat = 'toml') {
  const file = createFileFromContent(content, 'attack_graph', configFormat)
  return analyzeAttackGraph(file)
}

/**
 * Find attack paths in graph
 * @param {File} file - Attack graph configuration file
 * @param {string} source - Source node ID
 * @param {string} target - Target node ID
 * @param {number} maxPaths - Maximum paths to return
 */
export async function findAttackPaths(file, source, target, maxPaths = 10) {
  const formData = new FormData()
  formData.append('file', file)

  const response = await api.post(
    `/analyze/attack-paths?source=${encodeURIComponent(source)}&target=${encodeURIComponent(target)}&max_paths=${maxPaths}`,
    formData,
    {
      headers: { 'Content-Type': 'multipart/form-data' }
    }
  )
  return response.data
}

/**
 * Find attack paths from text content
 * @param {string} content - Configuration content
 * @param {string} source - Source node ID
 * @param {string} target - Target node ID
 * @param {string} configFormat - Configuration format (toml, json, yaml)
 * @param {number} maxPaths - Maximum paths to return
 */
export async function findAttackPathsFromContent(content, source, target, configFormat = 'toml', maxPaths = 10) {
  const file = createFileFromContent(content, 'attack_graph', configFormat)
  return findAttackPaths(file, source, target, maxPaths)
}

/**
 * Analyze critical nodes in attack graph
 * @param {File} file - Attack graph configuration file
 * @param {number} topN - Number of top critical nodes to return
 */
export async function analyzeCriticalNodes(file, topN = 10) {
  const formData = new FormData()
  formData.append('file', file)

  const response = await api.post(
    `/analyze/critical-nodes?top_n=${topN}`,
    formData,
    {
      headers: { 'Content-Type': 'multipart/form-data' }
    }
  )
  return response.data
}

/**
 * Analyze critical nodes from text content
 * @param {string} content - Configuration content
 * @param {string} configFormat - Configuration format (toml, json, yaml)
 * @param {number} topN - Number of top critical nodes to return
 */
export async function analyzeCriticalNodesFromContent(content, configFormat = 'toml', topN = 10) {
  const file = createFileFromContent(content, 'attack_graph', configFormat)
  return analyzeCriticalNodes(file, topN)
}

/**
 * Validate attack graph
 * @param {File} file - Attack graph configuration file
 */
export async function validateAttackGraph(file) {
  const formData = new FormData()
  formData.append('file', file)

  const response = await api.post('/validate/attack-graph', formData, {
    headers: { 'Content-Type': 'multipart/form-data' }
  })
  return response.data
}

/**
 * Validate attack graph from text content
 * @param {string} content - Configuration content
 * @param {string} configFormat - Configuration format (toml, json, yaml)
 */
export async function validateAttackGraphFromContent(content, configFormat = 'toml') {
  const file = createFileFromContent(content, 'attack_graph', configFormat)
  return validateAttackGraph(file)
}

// =============================================================================
// NetworkX Advanced Graph Analysis Functions
// =============================================================================

/**
 * Analyze centrality metrics (betweenness, closeness, pagerank)
 * @param {string} content - Configuration content
 * @param {string} algorithm - Algorithm: 'all', 'betweenness', 'closeness', 'pagerank'
 * @param {number} limit - Number of top nodes to return
 * @param {string} configFormat - Configuration format (toml, json, yaml)
 */
export async function analyzeCentralityFromContent(content, algorithm = 'all', limit = 10, configFormat = 'toml') {
  const file = createFileFromContent(content, 'attack_graph', configFormat)
  const formData = new FormData()
  formData.append('file', file)

  const response = await api.post(
    `/analyze/centrality?algorithm=${algorithm}&limit=${limit}`,
    formData,
    {
      headers: { 'Content-Type': 'multipart/form-data' }
    }
  )
  return response.data
}

/**
 * Get comprehensive graph metrics (density, diameter, cycles, SCCs)
 * @param {string} content - Configuration content
 * @param {string} configFormat - Configuration format (toml, json, yaml)
 */
export async function analyzeGraphMetricsFromContent(content, configFormat = 'toml') {
  const file = createFileFromContent(content, 'attack_graph', configFormat)
  const formData = new FormData()
  formData.append('file', file)

  const response = await api.post('/analyze/graph-metrics', formData, {
    headers: { 'Content-Type': 'multipart/form-data' }
  })
  return response.data
}

/**
 * Find network chokepoints (critical bottleneck nodes)
 * @param {string} content - Configuration content
 * @param {number} limit - Number of top chokepoints to return
 * @param {string} configFormat - Configuration format (toml, json, yaml)
 */
export async function analyzeChokepointsFromContent(content, limit = 10, configFormat = 'toml') {
  const file = createFileFromContent(content, 'attack_graph', configFormat)
  const formData = new FormData()
  formData.append('file', file)

  const response = await api.post(
    `/analyze/chokepoints?limit=${limit}`,
    formData,
    {
      headers: { 'Content-Type': 'multipart/form-data' }
    }
  )
  return response.data
}

/**
 * Analyze attack surface (entry points and reachable nodes)
 * @param {string} content - Configuration content
 * @param {string} configFormat - Configuration format (toml, json, yaml)
 */
export async function analyzeAttackSurfaceFromContent(content, configFormat = 'toml') {
  const file = createFileFromContent(content, 'attack_graph', configFormat)
  const formData = new FormData()
  formData.append('file', file)

  const response = await api.post('/analyze/attack-surface', formData, {
    headers: { 'Content-Type': 'multipart/form-data' }
  })
  return response.data
}

/**
 * Calculate vulnerability impact score
 * @param {string} content - Configuration content
 * @param {string} vulnId - Vulnerability ID to analyze
 * @param {string} configFormat - Configuration format (toml, json, yaml)
 */
export async function analyzeVulnerabilityImpactFromContent(content, vulnId, configFormat = 'toml') {
  const file = createFileFromContent(content, 'attack_graph', configFormat)
  const formData = new FormData()
  formData.append('file', file)

  const response = await api.post(
    `/analyze/vulnerability-impact?vulnerability_id=${encodeURIComponent(vulnId)}`,
    formData,
    {
      headers: { 'Content-Type': 'multipart/form-data' }
    }
  )
  return response.data
}

// =============================================================================
// Batch Processing Functions
// =============================================================================

/**
 * Batch process multiple files
 * @param {string} mode - Visualization mode (attack_tree, attack_graph, threat_model, binary)
 * @param {File[]} files - Array of files to process
 * @param {string} format - Output format (png, svg, pdf)
 * @param {string} style - Style preset
 * @param {boolean} collectStats - Whether to collect statistics
 * @param {Function} onProgress - Progress callback (filename, success, error)
 * @returns {Promise<{total: number, success_count: number, failure_count: number, success_rate: number, results: Array}>}
 */
export async function batchVisualize(mode, files, format = 'png', style = null, collectStats = false, onProgress = null) {
  const formData = new FormData()
  files.forEach(file => formData.append('files', file))

  let url = `/batch/visualize?mode=${mode}&format=${format}&collect_stats=${collectStats}`
  if (style) {
    url += `&style=${style}`
  }

  const response = await api.post(url, formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
    timeout: 300000, // 5 minutes for batch processing
  })

  // Call progress callback for each result if provided
  if (onProgress && response.data.results) {
    response.data.results.forEach(result => {
      onProgress(result.filename, result.success, result.error)
    })
  }

  return response.data
}

/**
 * Download batch results as a ZIP file
 * @param {Array} results - Array of result objects with output_file paths
 * @returns {Promise<Blob>}
 */
export async function downloadBatchResults(results) {
  const successfulFiles = results.filter(r => r.success && r.output_file)
  if (successfulFiles.length === 0) {
    throw new Error('No successful files to download')
  }

  // For now, return the results - actual ZIP download would need server-side support
  return successfulFiles
}

// =============================================================================
// Export Functions
// =============================================================================

/**
 * Export data from a configuration file
 * @param {File} file - Configuration file
 * @param {string} exportFormat - Export format (json, csv, yaml, markdown)
 * @param {string|null} section - Optional section to export (for CSV/markdown)
 * @param {boolean} includeStats - Include statistics in export
 * @returns {Promise<{content: string, format: string, filename: string, rows?: number}>}
 */
export async function exportData(file, exportFormat = 'json', section = null, includeStats = true) {
  const formData = new FormData()
  formData.append('file', file)

  let url = `/export/data?format=${exportFormat}&include_stats=${includeStats}`
  if (section) {
    url += `&section=${encodeURIComponent(section)}`
  }

  const response = await api.post(url, formData, {
    headers: { 'Content-Type': 'multipart/form-data' }
  })
  return response.data
}

/**
 * Export data from content
 * @param {string} content - Configuration content
 * @param {string} configFormat - Configuration format (toml, json, yaml)
 * @param {string} exportFormat - Export format (json, csv, yaml, markdown)
 * @param {string|null} section - Optional section to export
 * @param {boolean} includeStats - Include statistics
 * @returns {Promise<{content: string, format: string, filename: string, rows?: number}>}
 */
export async function exportDataFromContent(content, configFormat = 'toml', exportFormat = 'json', section = null, includeStats = true) {
  const file = createFileFromContent(content, 'config', configFormat)
  return exportData(file, exportFormat, section, includeStats)
}

/**
 * Get exportable sections from a configuration file
 * @param {File} file - Configuration file
 * @returns {Promise<{sections: string[]}>}
 */
export async function getExportSections(file) {
  const formData = new FormData()
  formData.append('file', file)

  const response = await api.post('/export/sections', formData, {
    headers: { 'Content-Type': 'multipart/form-data' }
  })
  return response.data
}

/**
 * Get exportable sections from content
 * @param {string} content - Configuration content
 * @param {string} configFormat - Configuration format (toml, json, yaml)
 * @returns {Promise<{sections: string[]}>}
 */
export async function getExportSectionsFromContent(content, configFormat = 'toml') {
  const file = createFileFromContent(content, 'config', configFormat)
  return getExportSections(file)
}

// =============================================================================
// Settings Functions
// =============================================================================

/**
 * Get current display settings
 * @returns {Promise<{cvss_display: {enabled: boolean, attack_tree: boolean, attack_graph: boolean, threat_model: boolean}}>}
 */
export async function getDisplaySettings() {
  const response = await api.get('/settings')
  return response.data
}

/**
 * Update display settings
 * @param {Object} settings - Settings to update
 * @param {Object} settings.cvss_display - CVSS display settings
 * @returns {Promise<{cvss_display: Object}>}
 */
export async function updateDisplaySettings(settings) {
  const response = await api.put('/settings', settings)
  return response.data
}

/**
 * Enable CVSS display for all visualization types
 * @returns {Promise<{cvss_display: Object}>}
 */
export async function enableCvssAll() {
  const response = await api.post('/settings/cvss/enable-all')
  return response.data
}

/**
 * Disable CVSS display for all visualization types
 * @returns {Promise<{cvss_display: Object}>}
 */
export async function disableCvssAll() {
  const response = await api.post('/settings/cvss/disable-all')
  return response.data
}

/**
 * Reset all display settings to defaults
 * @returns {Promise<{cvss_display: Object}>}
 */
export async function resetDisplaySettings() {
  const response = await api.post('/settings/reset')
  return response.data
}

// =============================================================================
// Custom Diagrams Functions
// =============================================================================

/**
 * Get available shapes for custom diagrams
 * @param {string|null} category - Optional category filter
 * @returns {Promise<{shapes: Array, total: number, categories: string[]}>}
 */
export async function getCustomDiagramShapes(category = null) {
  let url = '/custom-diagrams/shapes'
  if (category) {
    url += `?category=${encodeURIComponent(category)}`
  }
  const response = await api.get(url)
  return response.data
}

/**
 * Get shape details by ID
 * @param {string} shapeId - Shape identifier
 * @returns {Promise<{id: string, name: string, category: string, ...}>}
 */
export async function getCustomDiagramShape(shapeId) {
  const response = await api.get(`/custom-diagrams/shapes/${encodeURIComponent(shapeId)}`)
  return response.data
}

/**
 * Get available custom diagram templates
 * @param {string|null} category - Optional category filter
 * @returns {Promise<{templates: Array, total: number, categories: string[]}>}
 */
export async function getCustomDiagramTemplates(category = null) {
  let url = '/custom-diagrams/templates'
  if (category) {
    url += `?category=${encodeURIComponent(category)}`
  }
  const response = await api.get(url)
  return response.data
}

/**
 * Get template content by ID
 * @param {string} templateId - Template ID (category/name format)
 * @returns {Promise<{id: string, content: string, format: string}>}
 */
export async function getCustomDiagramTemplate(templateId) {
  const response = await api.get(`/custom-diagrams/templates/${templateId}`)
  return response.data
}

/**
 * Get available custom diagram styles
 * @returns {Promise<{styles: string[], default: string, descriptions: object}>}
 */
export async function getCustomDiagramStyles() {
  const response = await api.get('/custom-diagrams/styles')
  return response.data
}

/**
 * Get available layout algorithms
 * @returns {Promise<{layouts: string[], default: string, descriptions: object}>}
 */
export async function getCustomDiagramLayouts() {
  const response = await api.get('/custom-diagrams/layouts')
  return response.data
}

/**
 * Visualize custom diagram from file
 * @param {File} file - TOML/JSON/YAML file with diagram definition
 * @param {string} format - Output format (png, svg, pdf)
 * @param {string} style - Style preset
 * @returns {Promise<Blob>}
 */
export async function visualizeCustomDiagram(file, format = 'png', style = 'cd_default') {
  const formData = new FormData()
  formData.append('file', file)

  const response = await api.post(
    `/custom-diagrams/visualize?format=${format}&style=${style}`,
    formData,
    {
      responseType: 'blob',
      headers: { 'Content-Type': 'multipart/form-data' }
    }
  )
  return response.data
}

/**
 * Visualize custom diagram from content
 * @param {string} content - Configuration content
 * @param {string} outputFormat - Output format (png, svg, pdf)
 * @param {string} style - Style preset
 * @param {string} configFormat - Configuration format (toml, json, yaml)
 * @returns {Promise<Blob>}
 */
export async function visualizeCustomDiagramFromContent(content, outputFormat = 'png', style = 'cd_default', configFormat = 'toml') {
  const file = createFileFromContent(content, 'custom_diagram', configFormat)
  return visualizeCustomDiagram(file, outputFormat, style)
}

/**
 * Validate custom diagram configuration
 * @param {File} file - Configuration file
 * @returns {Promise<{valid: boolean, errors: string[], warnings: string[], node_count: number, edge_count: number}>}
 */
export async function validateCustomDiagram(file) {
  const formData = new FormData()
  formData.append('file', file)

  const response = await api.post('/custom-diagrams/validate', formData, {
    headers: { 'Content-Type': 'multipart/form-data' }
  })
  return response.data
}

/**
 * Validate custom diagram from content
 * @param {string} content - Configuration content
 * @param {string} configFormat - Configuration format (toml, json, yaml)
 * @returns {Promise<{valid: boolean, errors: string[], warnings: string[], node_count: number, edge_count: number}>}
 */
export async function validateCustomDiagramFromContent(content, configFormat = 'toml') {
  const file = createFileFromContent(content, 'custom_diagram', configFormat)
  return validateCustomDiagram(file)
}

/**
 * Get custom diagram statistics
 * @param {File} file - Configuration file
 * @returns {Promise<{total_nodes: number, total_edges: number, node_types: object, edge_types: object}>}
 */
export async function getCustomDiagramStats(file) {
  const formData = new FormData()
  formData.append('file', file)

  const response = await api.post('/custom-diagrams/stats', formData, {
    headers: { 'Content-Type': 'multipart/form-data' }
  })
  return response.data
}

/**
 * Get custom diagram statistics from content
 * @param {string} content - Configuration content
 * @param {string} configFormat - Configuration format (toml, json, yaml)
 * @returns {Promise<{total_nodes: number, total_edges: number, node_types: object, edge_types: object}>}
 */
export async function getCustomDiagramStatsFromContent(content, configFormat = 'toml') {
  const file = createFileFromContent(content, 'custom_diagram', configFormat)
  return getCustomDiagramStats(file)
}

/**
 * Generate custom diagram from template
 * @param {string} templateId - Template ID (category/name)
 * @param {string} format - Output format (png, svg, pdf)
 * @param {string} style - Style preset
 * @returns {Promise<Blob>}
 */
export async function visualizeCustomDiagramFromTemplate(templateId, format = 'png', style = 'cd_default') {
  const response = await api.post(
    `/custom-diagrams/from-template?template_id=${encodeURIComponent(templateId)}&format=${format}&style=${style}`,
    {},
    { responseType: 'blob' }
  )
  return response.data
}

// =============================================================================
// Mermaid Diagrams Functions
// =============================================================================

/**
 * Generate Mermaid diagram visualization
 * @param {File} file - Mermaid source file (.mmd, .toml, .json, .yaml)
 * @param {string} format - Output format (png, svg, pdf)
 * @param {string} theme - Mermaid theme (default, dark, forest, neutral, base)
 * @param {string} background - Background color
 * @param {number} width - Output width in pixels
 * @param {number} height - Output height in pixels
 * @returns {Promise<Blob>}
 */
export async function visualizeMermaid(file, format = 'png', theme = 'default', background = 'white', width = 800, height = 600) {
  const formData = new FormData()
  formData.append('file', file)

  const response = await api.post(
    `/visualize/mermaid?format=${format}&theme=${theme}&background=${encodeURIComponent(background)}&width=${width}&height=${height}`,
    formData,
    {
      headers: { 'Content-Type': 'multipart/form-data' },
      responseType: 'blob'
    }
  )
  return response.data
}

/**
 * Generate Mermaid diagram from text content
 * @param {string} content - Mermaid or config content
 * @param {string} outputFormat - Output format (png, svg, pdf)
 * @param {string} theme - Mermaid theme
 * @param {string} background - Background color (white, transparent, or hex)
 * @param {string} configFormat - Configuration format (mermaid, toml, json, yaml)
 * @returns {Promise<Blob>}
 */
export async function visualizeMermaidFromContent(content, outputFormat = 'png', theme = 'default', background = 'white', configFormat = 'toml') {
  // For raw mermaid syntax, use .mmd extension
  const extension = configFormat === 'mermaid' ? '.mmd' : getExtensionFromFormat(configFormat)
  const filename = `mermaid_diagram${extension}`
  const blob = new Blob([content], { type: 'text/plain' })
  const file = new File([blob], filename, { type: 'text/plain' })
  return visualizeMermaid(file, outputFormat, theme, background)
}

/**
 * Validate Mermaid diagram
 * @param {File} file - Mermaid source file
 * @returns {Promise<{valid: boolean, errors: string[], diagram_type: string, stats: object}>}
 */
export async function validateMermaid(file) {
  const formData = new FormData()
  formData.append('file', file)

  const response = await api.post('/analyze/mermaid', formData, {
    headers: { 'Content-Type': 'multipart/form-data' }
  })
  return response.data
}

/**
 * Validate Mermaid diagram from content
 * @param {string} content - Mermaid or config content
 * @param {string} configFormat - Configuration format (mermaid, toml, json, yaml)
 * @returns {Promise<{valid: boolean, errors: string[], diagram_type: string, stats: object}>}
 */
export async function validateMermaidFromContent(content, configFormat = 'toml') {
  const extension = configFormat === 'mermaid' ? '.mmd' : getExtensionFromFormat(configFormat)
  const filename = `mermaid_diagram${extension}`
  const blob = new Blob([content], { type: 'text/plain' })
  const file = new File([blob], filename, { type: 'text/plain' })
  return validateMermaid(file)
}

/**
 * Get available Mermaid templates
 * @param {string} category - Optional category filter
 * @returns {Promise<{templates: Array, categories: string[], total: number}>}
 */
export async function getMermaidTemplates(category = null) {
  const url = category ? `/mermaid/templates?category=${encodeURIComponent(category)}` : '/mermaid/templates'
  const response = await api.get(url)
  return response.data
}

/**
 * Get Mermaid template content
 * @param {string} category - Template category
 * @param {string} name - Template name
 * @returns {Promise<{id: string, name: string, category: string, content: string, diagram_type: string, filename: string}>}
 */
export async function getMermaidTemplate(category, name) {
  const response = await api.get(`/mermaid/template/${encodeURIComponent(category)}/${encodeURIComponent(name)}`)
  return response.data
}

/**
 * Get available Mermaid themes
 * @returns {Promise<{themes: string[], default: string}>}
 */
export async function getMermaidThemes() {
  const response = await api.get('/mermaid/themes')
  return response.data
}

/**
 * Get supported Mermaid diagram types
 * @returns {Promise<{types: string[], descriptions: object}>}
 */
export async function getMermaidTypes() {
  const response = await api.get('/mermaid/types')
  return response.data
}

// =============================================================================
// Cloud Diagrams Functions
// =============================================================================

/**
 * Generate cloud architecture diagram
 * @param {File} file - Cloud diagram config file (.toml, .json, .yaml)
 * @param {string} format - Output format (png, svg, pdf, jpg)
 * @param {string} direction - Layout direction (TB, BT, LR, RL)
 * @param {boolean} showLegend - Show diagram legend
 * @returns {Promise<Blob>}
 */
export async function visualizeCloud(file, format = 'png', direction = 'TB', showLegend = false) {
  const formData = new FormData()
  formData.append('file', file)

  const response = await api.post(
    `/visualize/cloud?format=${format}&direction=${direction}&show_legend=${showLegend}`,
    formData,
    {
      headers: { 'Content-Type': 'multipart/form-data' },
      responseType: 'blob'
    }
  )
  return response.data
}

/**
 * Generate cloud diagram from text content
 * @param {string} content - Configuration content
 * @param {string} outputFormat - Output format (png, svg, pdf, jpg)
 * @param {string} direction - Layout direction
 * @param {string} configFormat - Configuration format (toml, json, yaml)
 * @returns {Promise<Blob>}
 */
export async function visualizeCloudFromContent(content, outputFormat = 'png', direction = 'TB', configFormat = 'toml') {
  const file = createFileFromContent(content, 'cloud_diagram', configFormat)
  return visualizeCloud(file, outputFormat, direction)
}

/**
 * Validate cloud diagram configuration
 * @param {File} file - Cloud diagram config file
 * @returns {Promise<{valid: boolean, errors: string[], stats: object}>}
 */
export async function validateCloud(file) {
  const formData = new FormData()
  formData.append('file', file)

  const response = await api.post('/analyze/cloud', formData, {
    headers: { 'Content-Type': 'multipart/form-data' }
  })
  return response.data
}

/**
 * Validate cloud diagram from content
 * @param {string} content - Configuration content
 * @param {string} configFormat - Configuration format (toml, json, yaml)
 * @returns {Promise<{valid: boolean, errors: string[], stats: object}>}
 */
export async function validateCloudFromContent(content, configFormat = 'toml') {
  const file = createFileFromContent(content, 'cloud_diagram', configFormat)
  return validateCloud(file)
}

/**
 * Get available cloud providers
 * @returns {Promise<{providers: Array}>}
 */
export async function getCloudProviders() {
  const response = await api.get('/cloud/providers')
  return response.data
}

/**
 * Get cloud diagram icons for a provider
 * @param {string} provider - Cloud provider (aws, azure, gcp, k8s, etc.)
 * @param {string} category - Optional category filter (compute, database, network, etc.)
 * @returns {Promise<{icons: Array, provider: string, category: string, total: number}>}
 */
export async function getCloudIcons(provider, category = null) {
  let url = `/cloud/icons?provider=${encodeURIComponent(provider)}`
  if (category) {
    url += `&category=${encodeURIComponent(category)}`
  }
  const response = await api.get(url)
  return response.data
}

/**
 * Get available cloud diagram templates
 * @param {string} category - Optional category filter (aws, kubernetes, security)
 * @returns {Promise<{templates: Array, categories: string[], total: number}>}
 */
export async function getCloudTemplates(category = null) {
  const url = category ? `/cloud/templates?category=${encodeURIComponent(category)}` : '/cloud/templates'
  const response = await api.get(url)
  return response.data
}

/**
 * Get a specific cloud diagram template content
 * @param {string} category - Template category (aws, kubernetes, security)
 * @param {string} name - Template name
 * @returns {Promise<{id: string, name: string, category: string, content: string, filename: string, providers: string[]}>}
 */
export async function getCloudTemplate(category, name) {
  const response = await api.get(`/cloud/template/${encodeURIComponent(category)}/${encodeURIComponent(name)}`)
  return response.data
}

/**
 * Generate Python code from cloud diagram config
 * @param {File} file - Cloud diagram config file
 * @returns {Promise<{code: string, filename: string}>}
 */
export async function generateCloudCode(file) {
  const formData = new FormData()
  formData.append('file', file)

  const response = await api.post('/cloud/generate-code', formData, {
    headers: { 'Content-Type': 'multipart/form-data' }
  })
  return response.data
}

/**
 * Generate Python code from cloud diagram content
 * @param {string} content - Configuration content
 * @param {string} configFormat - Configuration format (toml, json, yaml)
 * @returns {Promise<{code: string, filename: string}>}
 */
export async function generateCloudCodeFromContent(content, configFormat = 'toml') {
  const file = createFileFromContent(content, 'cloud_diagram', configFormat)
  return generateCloudCode(file)
}

// =============================================================================
// Diff/Comparison Functions
// =============================================================================

/**
 * Compare two configuration files
 * @param {File} oldFile - Original file
 * @param {File} newFile - Modified file
 * @param {string[]} ignorePaths - Paths to ignore in comparison
 * @param {boolean} generateReport - Generate markdown report
 * @returns {Promise<{has_changes: boolean, summary: object, changes: Array, report?: string}>}
 */
export async function compareFiles(oldFile, newFile, ignorePaths = [], generateReport = false) {
  const formData = new FormData()
  formData.append('old_file', oldFile)
  formData.append('new_file', newFile)

  let url = `/diff/compare?generate_report=${generateReport}`
  if (ignorePaths.length > 0) {
    ignorePaths.forEach(path => {
      url += `&ignore_paths=${encodeURIComponent(path)}`
    })
  }

  const response = await api.post(url, formData, {
    headers: { 'Content-Type': 'multipart/form-data' }
  })
  return response.data
}

/**
 * Compare two configuration contents
 * @param {string} oldContent - Original content
 * @param {string} newContent - Modified content
 * @param {string} configFormat - Configuration format (toml, json, yaml)
 * @param {string[]} ignorePaths - Paths to ignore
 * @param {boolean} generateReport - Generate markdown report
 * @returns {Promise<{has_changes: boolean, summary: object, changes: Array, report?: string}>}
 */
export async function compareContents(oldContent, newContent, configFormat = 'toml', ignorePaths = [], generateReport = false) {
  const oldFile = createFileFromContent(oldContent, 'old_config', configFormat)
  const newFile = createFileFromContent(newContent, 'new_config', configFormat)
  return compareFiles(oldFile, newFile, ignorePaths, generateReport)
}

/**
 * Get a summary of changes between two files
 * @param {File} oldFile - Original file
 * @param {File} newFile - Modified file
 * @returns {Promise<{added: number, removed: number, modified: number, total: number}>}
 */
export async function getDiffSummary(oldFile, newFile) {
  const result = await compareFiles(oldFile, newFile, [], false)
  return result.summary
}

// =============================================================================
// Image Upload Functions
// =============================================================================

/**
 * Upload an image for use in visualizations
 * @param {File} file - Image file (PNG, JPEG, GIF, SVG, BMP)
 * @returns {Promise<{image_id: string, filename: string, size: number, content_type: string}>}
 */
export async function uploadImage(file) {
  const formData = new FormData()
  formData.append('file', file)

  const response = await api.post('/images/upload', formData, {
    headers: { 'Content-Type': 'multipart/form-data' }
  })
  return response.data
}

/**
 * Get information about an uploaded image
 * @param {string} imageId - Image UUID
 * @returns {Promise<{image_id: string, exists: boolean, size: number, content_type: string, created_at: string}>}
 */
export async function getImageInfo(imageId) {
  const response = await api.get(`/images/${imageId}`)
  return response.data
}

/**
 * Download an uploaded image
 * @param {string} imageId - Image UUID
 * @returns {Promise<Blob>}
 */
export async function downloadImage(imageId) {
  const response = await api.get(`/images/${imageId}/download`, {
    responseType: 'blob'
  })
  return response.data
}

/**
 * Delete an uploaded image
 * @param {string} imageId - Image UUID
 * @returns {Promise<{deleted: boolean, image_id: string}>}
 */
export async function deleteImage(imageId) {
  const response = await api.delete(`/images/${imageId}`)
  return response.data
}

/**
 * List all uploaded images
 * @returns {Promise<{images: Array, total: number}>}
 */
export async function listImages() {
  const response = await api.get('/images')
  return response.data
}

/**
 * Get image thumbnail URL (for display)
 * @param {string} imageId - Image UUID
 * @returns {string} URL to fetch the image
 */
export function getImageUrl(imageId) {
  const apiKey = getApiKey()
  const baseUrl = `${API_BASE}/images/${imageId}/download`
  // Note: For authenticated requests, the image would need to be fetched via the api instance
  return baseUrl
}


// =============================================================================
// Bundled Icons API
// =============================================================================

/**
 * List bundled icons with pagination and filtering
 * @param {Object} options - Query options
 * @param {string} [options.category] - Filter by category (azure, aws, bootstrap)
 * @param {string} [options.subcategory] - Filter by subcategory
 * @param {string} [options.search] - Search by icon name
 * @param {number} [options.page=1] - Page number
 * @param {number} [options.pageSize=50] - Icons per page (10-200)
 * @returns {Promise<{icons: Array, categories: Array, subcategories: Array, total: number, page: number, page_size: number, total_pages: number, has_more: boolean}>}
 */
export async function listBundledIcons(options = {}) {
  const params = {}
  if (options.category) params.category = options.category
  if (options.subcategory) params.subcategory = options.subcategory
  if (options.search) params.search = options.search
  if (options.page) params.page = options.page
  if (options.pageSize) params.page_size = options.pageSize
  const response = await api.get('/icons', { params })
  return response.data
}

/**
 * Get bundled icon categories with counts
 * @returns {Promise<{categories: Array, counts: Object}>}
 */
export async function getBundledIconCategories() {
  const response = await api.get('/icons/categories')
  return response.data
}

/**
 * Get URL for a bundled icon
 * @param {string} category - Icon category (azure, aws, bootstrap)
 * @param {string} name - Icon name (without extension)
 * @returns {string} URL to fetch the icon
 */
export function getBundledIconUrl(category, name) {
  return `${API_BASE}/icons/${category}/${name}`
}

/**
 * Get URL for a bundled icon by ID
 * @param {string} iconId - Icon ID in format "category/name"
 * @returns {string} URL to fetch the icon
 */
export function getBundledIconUrlById(iconId) {
  return `${API_BASE}/icons/${iconId}`
}

export default {
  // Authentication
  getApiKey,
  setApiKey,
  clearApiKey,
  hasApiKey,
  // Health & Info
  checkHealth,
  getStyles,
  getFormats,
  getEngines,
  visualizeAttackTree,
  analyzeAttackTree,
  validateAttackTree,
  visualizeThreatModel,
  analyzeThreatModel,
  analyzeStride,
  visualizeBinary,
  analyzeBinary,
  createImageUrl,
  getTimestamp,
  downloadBlob,
  downloadTextFile,
  visualizeAttackTreeFromContent,
  analyzeAttackTreeFromContent,
  validateAttackTreeFromContent,
  visualizeThreatModelFromContent,
  analyzeThreatModelFromContent,
  analyzeStrideFromContent,
  convertFormat,
  convertFormatFromContent,
  generateReport,
  generateReportFromContent,
  getThreatLibrary,
  getThreatElementTypes,
  visualizeAttackGraph,
  visualizeAttackGraphFromContent,
  analyzeAttackGraph,
  analyzeAttackGraphFromContent,
  findAttackPaths,
  findAttackPathsFromContent,
  analyzeCriticalNodes,
  analyzeCriticalNodesFromContent,
  validateAttackGraph,
  validateAttackGraphFromContent,
  // Batch processing
  batchVisualize,
  downloadBatchResults,
  // Export
  exportData,
  exportDataFromContent,
  getExportSections,
  getExportSectionsFromContent,
  // Diff/Comparison
  compareFiles,
  compareContents,
  getDiffSummary,
  // Settings
  getDisplaySettings,
  updateDisplaySettings,
  enableCvssAll,
  disableCvssAll,
  resetDisplaySettings,
  // NetworkX Advanced Analysis
  analyzeCentralityFromContent,
  analyzeGraphMetricsFromContent,
  analyzeChokepointsFromContent,
  analyzeAttackSurfaceFromContent,
  analyzeVulnerabilityImpactFromContent,
  // Custom Diagrams
  getCustomDiagramShapes,
  getCustomDiagramShape,
  getCustomDiagramTemplates,
  getCustomDiagramTemplate,
  getCustomDiagramStyles,
  getCustomDiagramLayouts,
  visualizeCustomDiagram,
  visualizeCustomDiagramFromContent,
  validateCustomDiagram,
  validateCustomDiagramFromContent,
  getCustomDiagramStats,
  getCustomDiagramStatsFromContent,
  visualizeCustomDiagramFromTemplate,
  // Mermaid Diagrams
  visualizeMermaid,
  visualizeMermaidFromContent,
  validateMermaid,
  validateMermaidFromContent,
  getMermaidTemplates,
  getMermaidTemplate,
  getMermaidThemes,
  getMermaidTypes,
  // Cloud Diagrams
  visualizeCloud,
  visualizeCloudFromContent,
  validateCloud,
  validateCloudFromContent,
  getCloudProviders,
  getCloudIcons,
  getCloudTemplates,
  getCloudTemplate,
  generateCloudCode,
  generateCloudCodeFromContent,
}
