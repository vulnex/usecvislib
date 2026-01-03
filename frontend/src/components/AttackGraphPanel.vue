<!--
  VULNEX -Universal Security Visualization Library-

  File: AttackGraphPanel.vue
  Author: Simon Roses Femerling
  Created: 2025-01-01
  Last Modified: 2026-01-01
  Version: 0.3.1
  License: Apache-2.0
  Copyright (c) 2025 VULNEX. All rights reserved.
  https://www.vulnex.com
-->
<template>
  <div class="panel">
    <div class="panel-header">
      <h2>Attack Graph Visualization</h2>
      <p>Upload a configuration file (TOML, JSON, or YAML) defining your network attack graph</p>
    </div>

    <div class="panel-body">
      <div class="form-section">
        <!-- Upload area - only shown when no content -->
        <div
          v-if="!editorContent"
          class="upload-area"
          :class="{ dragover: isDragging }"
          @dragover.prevent="isDragging = true"
          @dragleave="isDragging = false"
          @drop.prevent="handleDrop"
        >
          <input type="file" ref="fileInput" accept=".tml,.toml,.json,.yaml,.yml" @change="handleFileSelect" class="file-input" />
          <div class="upload-content" @click="$refs.fileInput.click()">
            <span class="upload-icon">&#x1F4C1;</span>
            <p>Drop config file here or click to browse</p>
            <span class="file-types">Supports: TOML, JSON, YAML</span>
          </div>
        </div>

        <!-- Config Editor - shown after file upload -->
        <ConfigEditor
          v-if="editorContent"
          v-model="editorContent"
          :fileName="fileName"
          title="Attack Graph Definition"
          validationType="attack-graph"
          minHeight="250px"
          maxHeight="400px"
          @validation-change="handleValidationChange"
          @format-detected="handleFormatDetected"
          ref="configEditor"
        />

        <!-- Change file button when editor is shown -->
        <div v-if="editorContent" class="file-actions">
          <button class="btn btn-small btn-secondary" @click="changeFile">
            Change File
          </button>
          <button class="btn btn-small btn-secondary" @click="saveTemplate">
            Save Template
          </button>
        </div>

        <!-- Template type mismatch warning -->
        <div v-if="templateMismatch" class="template-warning">
          <div class="warning-content">
            <span class="warning-icon">&#x26A0;</span>
            <div class="warning-text">
              <strong>Template type mismatch:</strong> This appears to be a <strong>{{ templateMismatch.detectedTypeName }}</strong> template.
              You're in the Attack Graphs panel.
              <span v-if="templateMismatch.suggestedPanel">Consider switching to <strong>{{ templateMismatch.suggestedPanel }}</strong>.</span>
            </div>
          </div>
          <button class="btn btn-small btn-warning-dismiss" @click="dismissMismatchWarning">Dismiss</button>
        </div>

        <!-- Node Images Section -->
        <div v-if="editorContent" class="images-section">
          <div class="section-header" @click="showImageUploader = !showImageUploader">
            <span class="toggle-icon">{{ showImageUploader ? '▼' : '▶' }}</span>
            <span class="section-title">Node Images</span>
            <span class="section-hint">(optional)</span>
          </div>
          <div v-show="showImageUploader" class="section-content">
            <p class="images-help">
              Upload images for host nodes. Copy the image_id and add <code>image_id = "..."</code> to
              the host definition in your configuration.
            </p>
            <ImageUploader
              ref="imageUploader"
              title="Upload Host Image"
              @image-selected="handleImageSelected"
            />
          </div>
        </div>

        <div class="options-row">
          <div class="option-group">
            <label>Output Format</label>
            <select v-model="format">
              <option v-for="f in formats" :key="f" :value="f">{{ f.toUpperCase() }}</option>
            </select>
          </div>
          <div class="option-group">
            <label>Style</label>
            <select v-model="style">
              <option v-for="s in styles" :key="s" :value="s">{{ formatStyleName(s) }}</option>
            </select>
          </div>
        </div>

        <div class="actions">
          <button class="btn btn-primary" @click="generateVisualization" :disabled="!canGenerate || loading">
            <span v-if="loading" class="spinner"></span>
            {{ loading ? 'Generating...' : 'Generate Visualization' }}
          </button>
          <button class="btn btn-secondary" @click="analyzeGraph" :disabled="!canGenerate || loading">
            Analyze Structure
          </button>
          <button class="btn btn-secondary" @click="validateGraph" :disabled="!canGenerate || loading">
            Validate
          </button>
        </div>

        <!-- Path Finding Section -->
        <div v-if="editorContent" class="path-section">
          <h4>Attack Path Analysis</h4>
          <div class="path-inputs">
            <div class="option-group">
              <label>Source Node</label>
              <input type="text" v-model="pathSource" placeholder="e.g., attacker" />
            </div>
            <div class="option-group">
              <label>Target Node</label>
              <input type="text" v-model="pathTarget" placeholder="e.g., database" />
            </div>
            <button class="btn btn-secondary" @click="findPaths" :disabled="!canFindPaths || loading">
              Find Paths
            </button>
          </div>
          <button class="btn btn-secondary" @click="analyzeCritical" :disabled="!canGenerate || loading">
            Analyze Critical Nodes
          </button>
        </div>

        <!-- Advanced Analysis Section (NetworkX) -->
        <div v-if="editorContent" class="advanced-analysis-section">
          <h4>Advanced Graph Analysis</h4>
          <div class="analysis-buttons">
            <button class="btn btn-secondary" @click="analyzeMetrics" :disabled="!canGenerate || loading">
              Graph Metrics
            </button>
            <button class="btn btn-secondary" @click="analyzeCentrality" :disabled="!canGenerate || loading">
              Centrality Analysis
            </button>
            <button class="btn btn-secondary" @click="analyzeChokepoints" :disabled="!canGenerate || loading">
              Find Chokepoints
            </button>
            <button class="btn btn-secondary" @click="analyzeAttackSurface" :disabled="!canGenerate || loading">
              Attack Surface
            </button>
          </div>
          <!-- Vulnerability Impact Analysis -->
          <div class="vuln-impact-row">
            <div class="option-group">
              <label>Vulnerability ID</label>
              <input type="text" v-model="selectedVuln" placeholder="e.g., CVE-2024-1234" />
            </div>
            <button class="btn btn-secondary" @click="analyzeVulnImpact" :disabled="!canGenerate || !selectedVuln.trim() || loading">
              Analyze Impact
            </button>
          </div>
        </div>
      </div>

      <div v-if="error" class="error-message">
        <span class="error-icon">&#x26A0;</span>
        {{ error }}
      </div>

      <div v-if="imageUrl || imageBlob" class="result-section">
        <div class="result-header">
          <h3>Generated Visualization</h3>
          <button class="btn btn-small" @click="downloadImage">
            Download
          </button>
        </div>
        <!-- PDF cannot be previewed in img tag -->
        <div v-if="format === 'pdf'" class="pdf-notice">
          <div class="pdf-icon">&#x1F4C4;</div>
          <p>PDF generated successfully</p>
          <p class="pdf-hint">Click "Download" to save the PDF file</p>
        </div>
        <ZoomableImage v-else :src="imageUrl" alt="Attack Graph Visualization" />
      </div>

      <div v-if="stats" class="stats-section">
        <h3>Graph Statistics</h3>
        <div class="stats-grid">
          <div class="stat-item">
            <span class="stat-value">{{ stats.total_hosts }}</span>
            <span class="stat-label">Hosts</span>
          </div>
          <div class="stat-item">
            <span class="stat-value">{{ stats.total_vulnerabilities }}</span>
            <span class="stat-label">Vulnerabilities</span>
          </div>
          <div class="stat-item">
            <span class="stat-value">{{ stats.total_privileges }}</span>
            <span class="stat-label">Privileges</span>
          </div>
          <div class="stat-item">
            <span class="stat-value">{{ stats.total_services }}</span>
            <span class="stat-label">Services</span>
          </div>
          <div class="stat-item">
            <span class="stat-value">{{ stats.total_exploits }}</span>
            <span class="stat-label">Exploits</span>
          </div>
          <div class="stat-item">
            <span class="stat-value">{{ stats.total_nodes }}</span>
            <span class="stat-label">Total Nodes</span>
          </div>
          <div class="stat-item">
            <span class="stat-value">{{ stats.total_edges }}</span>
            <span class="stat-label">Total Edges</span>
          </div>
          <div v-if="stats.average_cvss > 0" class="stat-item" :class="getCvssSeverityClass(stats.average_cvss)">
            <span class="stat-value">{{ stats.average_cvss.toFixed(1) }}</span>
            <span class="stat-label">Avg CVSS</span>
            <span class="cvss-badge" :class="getCvssSeverityClass(stats.average_cvss)">
              {{ getCvssSeverityLabel(stats.average_cvss) }}
            </span>
          </div>
          <div v-if="stats.critical_vulnerabilities > 0" class="stat-item cvss-critical">
            <span class="stat-value">{{ stats.critical_vulnerabilities }}</span>
            <span class="stat-label">Critical Vulns</span>
          </div>
        </div>
        <TemplateMetadata v-if="stats.metadata" :metadata="stats.metadata" />
      </div>

      <div v-if="paths" class="paths-section">
        <h3>Attack Paths: {{ paths.source }} &#x2192; {{ paths.target }}</h3>
        <p class="paths-summary">Found {{ paths.total_paths }} path(s)
          <span v-if="paths.shortest_path_length">, shortest: {{ paths.shortest_path_length }} steps</span>
        </p>
        <div v-if="paths.paths.length" class="paths-list">
          <div v-for="(path, i) in paths.paths" :key="i" class="path-item">
            <span class="path-number">{{ i + 1 }}.</span>
            <span class="path-nodes">{{ path.path.join(' &#x2192; ') }}</span>
            <span class="path-length">({{ path.length }} steps)</span>
          </div>
        </div>
        <p v-else class="no-paths">No paths found between these nodes</p>
      </div>

      <div v-if="criticalNodes && criticalNodes.length" class="critical-section">
        <h3>Critical Nodes (by Degree Centrality)</h3>
        <div class="critical-list">
          <div v-for="(node, i) in criticalNodes" :key="node.id" class="critical-item">
            <span class="critical-rank">{{ i + 1 }}</span>
            <div class="critical-info">
              <span class="critical-label">{{ node.label }}</span>
              <span class="critical-type">({{ node.type }})</span>
            </div>
            <div class="critical-stats">
              <span>In: {{ node.in_degree }}</span>
              <span>Out: {{ node.out_degree }}</span>
              <span class="criticality-score">Score: {{ node.criticality_score }}</span>
            </div>
          </div>
        </div>
      </div>

      <div v-if="validation" class="validation-section">
        <h3>Validation Result</h3>
        <div :class="['validation-result', validation.valid ? 'valid' : 'invalid']">
          <span class="validation-icon">{{ validation.valid ? '&#x2705;' : '&#x274C;' }}</span>
          {{ validation.valid ? 'Valid attack graph structure' : 'Validation errors found' }}
        </div>
        <ul v-if="validation.errors && validation.errors.length" class="error-list">
          <li v-for="(err, i) in validation.errors" :key="i">{{ err }}</li>
        </ul>
      </div>

      <!-- Graph Metrics Section -->
      <div v-if="graphMetrics" class="metrics-section">
        <h3>Graph Metrics</h3>
        <div class="metrics-grid">
          <div class="metric-item">
            <span class="metric-value">{{ graphMetrics.density?.toFixed(4) || 'N/A' }}</span>
            <span class="metric-label">Density</span>
          </div>
          <div class="metric-item">
            <span class="metric-value">{{ graphMetrics.diameter ?? 'N/A' }}</span>
            <span class="metric-label">Diameter</span>
          </div>
          <div class="metric-item">
            <span class="metric-value">{{ graphMetrics.num_cycles ?? 0 }}</span>
            <span class="metric-label">Cycles</span>
          </div>
          <div class="metric-item">
            <span class="metric-value">{{ graphMetrics.num_strongly_connected_components ?? 0 }}</span>
            <span class="metric-label">SCCs</span>
          </div>
          <div class="metric-item">
            <span class="metric-value">{{ graphMetrics.is_dag ? 'Yes' : 'No' }}</span>
            <span class="metric-label">Is DAG</span>
          </div>
          <div class="metric-item">
            <span class="metric-value">{{ graphMetrics.average_clustering?.toFixed(4) || 'N/A' }}</span>
            <span class="metric-label">Avg Clustering</span>
          </div>
        </div>
      </div>

      <!-- Centrality Section -->
      <div v-if="centrality && centrality.nodes" class="centrality-section">
        <h3>Node Centrality Rankings</h3>
        <div class="centrality-list">
          <div v-for="(node, i) in centrality.nodes" :key="node.id" class="centrality-item">
            <span class="rank">{{ i + 1 }}</span>
            <div class="node-info">
              <span class="node-label">{{ node.label }}</span>
              <span class="node-type">({{ node.type }})</span>
            </div>
            <div class="scores">
              <span v-if="node.betweenness_centrality != null" class="score">
                B: {{ node.betweenness_centrality.toFixed(4) }}
              </span>
              <span v-if="node.closeness_centrality != null" class="score">
                C: {{ node.closeness_centrality.toFixed(4) }}
              </span>
              <span v-if="node.pagerank != null" class="score">
                PR: {{ node.pagerank.toFixed(4) }}
              </span>
            </div>
          </div>
        </div>
      </div>

      <!-- Chokepoints Section -->
      <div v-if="chokepoints && chokepoints.chokepoints" class="chokepoints-section">
        <h3>Network Chokepoints</h3>
        <p class="section-description">Critical nodes that many attack paths traverse. Securing these disrupts multiple attack vectors.</p>
        <div class="chokepoints-list">
          <div v-for="cp in chokepoints.chokepoints" :key="cp.id"
               class="chokepoint-item" :class="{ critical: cp.is_critical }">
            <div class="cp-info">
              <span class="cp-label">{{ cp.label }}</span>
              <span class="cp-type">({{ cp.type }})</span>
            </div>
            <div class="cp-stats">
              <span class="betweenness">Score: {{ cp.betweenness_score?.toFixed(4) || 'N/A' }}</span>
              <span class="degrees">In: {{ cp.in_degree }} / Out: {{ cp.out_degree }}</span>
              <span v-if="cp.is_critical" class="critical-badge">CRITICAL</span>
            </div>
          </div>
        </div>
      </div>

      <!-- Attack Surface Section -->
      <div v-if="attackSurface && attackSurface.entry_points" class="attack-surface-section">
        <h3>Attack Surface Entry Points</h3>
        <p class="section-description">Network entry points sorted by number of reachable nodes.</p>
        <div class="surface-list">
          <div v-for="ep in attackSurface.entry_points" :key="ep.id" class="entry-point">
            <div class="ep-info">
              <span class="ep-label">{{ ep.label }}</span>
              <span class="ep-type">({{ ep.type }})</span>
            </div>
            <div class="ep-stats">
              <span class="reachable">{{ ep.reachable_nodes }} nodes reachable</span>
              <span class="out-degree">{{ ep.out_degree }} direct connections</span>
            </div>
          </div>
        </div>
      </div>

      <!-- Vulnerability Impact Section -->
      <div v-if="vulnImpact" class="vuln-impact-section">
        <h3>Vulnerability Impact: {{ vulnImpact.vulnerability_id }}</h3>
        <div class="impact-grid">
          <div class="impact-item" :class="getImpactClass(vulnImpact.impact_score)">
            <span class="impact-value">{{ vulnImpact.impact_score?.toFixed(2) || 'N/A' }}</span>
            <span class="impact-label">Impact Score</span>
          </div>
          <div class="impact-item">
            <span class="impact-value">{{ vulnImpact.reachable_nodes ?? 0 }}</span>
            <span class="impact-label">Reachable Nodes</span>
          </div>
          <div class="impact-item">
            <span class="impact-value">{{ vulnImpact.affected_hosts ?? 0 }}</span>
            <span class="impact-label">Affected Hosts</span>
          </div>
          <div class="impact-item">
            <span class="impact-value">{{ vulnImpact.paths_through ?? 0 }}</span>
            <span class="impact-label">Paths Through</span>
          </div>
        </div>
        <div v-if="vulnImpact.cvss_score" class="impact-cvss">
          <span class="cvss-label">CVSS:</span>
          <span class="cvss-value" :class="getCvssSeverityClass(vulnImpact.cvss_score)">
            {{ vulnImpact.cvss_score.toFixed(1) }}
          </span>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, inject, watch, computed } from 'vue'
import ConfigEditor from './ConfigEditor.vue'
import ZoomableImage from './ZoomableImage.vue'
import TemplateMetadata from './TemplateMetadata.vue'
import ImageUploader from './ImageUploader.vue'
import {
  visualizeAttackGraphFromContent,
  analyzeAttackGraphFromContent,
  validateAttackGraphFromContent,
  findAttackPathsFromContent,
  analyzeCriticalNodesFromContent,
  analyzeCentralityFromContent,
  analyzeGraphMetricsFromContent,
  analyzeChokepointsFromContent,
  analyzeAttackSurfaceFromContent,
  analyzeVulnerabilityImpactFromContent,
  createImageUrl,
  getTimestamp,
  downloadBlob,
  downloadTextFile
} from '../services/api.js'
import { validateTemplateType, TemplateType } from '../utils/template-detector.js'

const props = defineProps({
  styles: { type: Array, default: () => [] },
  formats: { type: Array, default: () => ['png'] }
})

// Watch for clean trigger from parent
const cleanTrigger = inject('cleanTrigger')
watch(cleanTrigger, () => {
  resetPanel()
})

// State
const editorContent = ref(null)
const fileName = ref('')
const fileFormat = ref('toml')
const format = ref('png')
const style = ref('ag_default')
const loading = ref(false)
const error = ref(null)
const imageUrl = ref(null)
const imageBlob = ref(null)
const stats = ref(null)
const validation = ref(null)
const paths = ref(null)
const criticalNodes = ref(null)
const pathSource = ref('')
const pathTarget = ref('')
const isDragging = ref(false)
const fileInput = ref(null)
const configEditor = ref(null)
const isConfigValid = ref(false)
const showImageUploader = ref(false)
const imageUploader = ref(null)
const selectedImageId = ref(null)
const templateMismatch = ref(null)  // { detectedTypeName, suggestedPanel }

// NetworkX Advanced Analysis State
const graphMetrics = ref(null)
const centrality = ref(null)
const chokepoints = ref(null)
const attackSurface = ref(null)
const vulnImpact = ref(null)
const selectedVuln = ref('')

// Computed
const canGenerate = computed(() => {
  return editorContent.value && editorContent.value.trim() && isConfigValid.value
})

const canFindPaths = computed(() => {
  return canGenerate.value && pathSource.value.trim() && pathTarget.value.trim()
})

// Methods
function formatStyleName(s) {
  return s.replace('ag_', '').replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())
}

async function handleFileSelect(event) {
  const files = event.target.files
  if (files.length > 0) {
    await loadFileContent(files[0])
  }
}

async function handleDrop(event) {
  isDragging.value = false
  const files = event.dataTransfer.files
  if (files.length > 0) {
    await loadFileContent(files[0])
  }
}

async function loadFileContent(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onload = (e) => {
      editorContent.value = e.target.result
      fileName.value = file.name
      clearResults()
      checkTemplateType(e.target.result)
      resolve()
    }
    reader.onerror = () => {
      error.value = 'Failed to read file'
      reject(new Error('Failed to read file'))
    }
    reader.readAsText(file)
  })
}

function checkTemplateType(content) {
  const result = validateTemplateType(content, TemplateType.ATTACK_GRAPH)
  if (!result.matches && result.detectedType !== TemplateType.UNKNOWN) {
    templateMismatch.value = {
      detectedTypeName: result.detectedTypeName,
      suggestedPanel: result.suggestedPanel
    }
  } else {
    templateMismatch.value = null
  }
}

function changeFile() {
  editorContent.value = null
  fileName.value = ''
  fileFormat.value = 'toml'
  isConfigValid.value = false
  templateMismatch.value = null
  clearResults()
  if (fileInput.value) {
    fileInput.value.value = ''
  }
}

function handleValidationChange({ valid, errors }) {
  isConfigValid.value = !errors.some(e => e.severity === 'error')
}

function handleFormatDetected(format) {
  fileFormat.value = format
}

function clearResults() {
  error.value = null
  imageUrl.value = null
  imageBlob.value = null
  stats.value = null
  validation.value = null
  paths.value = null
  criticalNodes.value = null
  // NetworkX results
  graphMetrics.value = null
  centrality.value = null
  chokepoints.value = null
  attackSurface.value = null
  vulnImpact.value = null
}

function resetPanel() {
  editorContent.value = null
  fileName.value = ''
  fileFormat.value = 'toml'
  format.value = 'png'
  style.value = 'ag_default'
  pathSource.value = ''
  pathTarget.value = ''
  selectedVuln.value = ''
  isConfigValid.value = false
  showImageUploader.value = false
  selectedImageId.value = null
  templateMismatch.value = null
  clearResults()
}

function dismissMismatchWarning() {
  templateMismatch.value = null
}

function handleImageSelected(image) {
  selectedImageId.value = image?.image_id || null
}

async function generateVisualization() {
  if (!editorContent.value) return

  loading.value = true
  error.value = null
  stats.value = null
  validation.value = null
  paths.value = null
  criticalNodes.value = null

  try {
    const blob = await visualizeAttackGraphFromContent(editorContent.value, format.value, style.value, fileFormat.value)
    imageBlob.value = blob
    imageUrl.value = createImageUrl(blob)
  } catch (err) {
    error.value = err.response?.data?.detail || err.message || 'Failed to generate visualization'
  } finally {
    loading.value = false
  }
}

async function analyzeGraph() {
  if (!editorContent.value) return

  loading.value = true
  error.value = null
  validation.value = null
  paths.value = null
  criticalNodes.value = null

  try {
    stats.value = await analyzeAttackGraphFromContent(editorContent.value, fileFormat.value)
  } catch (err) {
    error.value = err.response?.data?.detail || err.message || 'Failed to analyze graph'
  } finally {
    loading.value = false
  }
}

async function validateGraph() {
  if (!editorContent.value) return

  loading.value = true
  error.value = null
  stats.value = null
  paths.value = null
  criticalNodes.value = null

  try {
    validation.value = await validateAttackGraphFromContent(editorContent.value, fileFormat.value)
  } catch (err) {
    error.value = err.response?.data?.detail || err.message || 'Failed to validate graph'
  } finally {
    loading.value = false
  }
}

async function findPaths() {
  if (!editorContent.value || !pathSource.value || !pathTarget.value) return

  loading.value = true
  error.value = null
  paths.value = null

  try {
    paths.value = await findAttackPathsFromContent(
      editorContent.value,
      pathSource.value.trim(),
      pathTarget.value.trim(),
      fileFormat.value
    )
  } catch (err) {
    error.value = err.response?.data?.detail || err.message || 'Failed to find paths'
  } finally {
    loading.value = false
  }
}

async function analyzeCritical() {
  if (!editorContent.value) return

  loading.value = true
  error.value = null
  criticalNodes.value = null

  try {
    const result = await analyzeCriticalNodesFromContent(editorContent.value, fileFormat.value)
    criticalNodes.value = result.critical_nodes
  } catch (err) {
    error.value = err.response?.data?.detail || err.message || 'Failed to analyze critical nodes'
  } finally {
    loading.value = false
  }
}

function downloadImage() {
  if (imageBlob.value) {
    downloadBlob(imageBlob.value, `attack_graph_${getTimestamp()}.${format.value}`)
  }
}

function saveTemplate() {
  if (!editorContent.value) return

  // Extract base name and extension from original filename
  const name = fileName.value || 'template.toml'
  const lastDot = name.lastIndexOf('.')
  const baseName = lastDot > 0 ? name.substring(0, lastDot) : name
  const extension = lastDot > 0 ? name.substring(lastDot) : '.toml'

  // Generate filename with timestamp
  const saveFilename = `${baseName}_${getTimestamp()}${extension}`
  downloadTextFile(editorContent.value, saveFilename)
}

// CVSS severity helpers
function getCvssSeverityClass(cvss) {
  if (cvss >= 9.0) return 'cvss-critical'
  if (cvss >= 7.0) return 'cvss-high'
  if (cvss >= 4.0) return 'cvss-medium'
  if (cvss >= 0.1) return 'cvss-low'
  return 'cvss-none'
}

function getCvssSeverityLabel(cvss) {
  if (cvss >= 9.0) return 'Critical'
  if (cvss >= 7.0) return 'High'
  if (cvss >= 4.0) return 'Medium'
  if (cvss >= 0.1) return 'Low'
  return 'None'
}

// Impact score class helper
function getImpactClass(score) {
  if (score >= 8.0) return 'impact-critical'
  if (score >= 6.0) return 'impact-high'
  if (score >= 4.0) return 'impact-medium'
  if (score >= 2.0) return 'impact-low'
  return 'impact-minimal'
}

// NetworkX Advanced Analysis Handlers
async function analyzeMetrics() {
  if (!editorContent.value) return

  loading.value = true
  error.value = null
  graphMetrics.value = null

  try {
    graphMetrics.value = await analyzeGraphMetricsFromContent(editorContent.value, fileFormat.value)
  } catch (err) {
    error.value = err.response?.data?.detail || err.message || 'Failed to analyze graph metrics'
  } finally {
    loading.value = false
  }
}

async function analyzeCentrality() {
  if (!editorContent.value) return

  loading.value = true
  error.value = null
  centrality.value = null

  try {
    centrality.value = await analyzeCentralityFromContent(editorContent.value, 'all', 10, fileFormat.value)
  } catch (err) {
    error.value = err.response?.data?.detail || err.message || 'Failed to analyze centrality'
  } finally {
    loading.value = false
  }
}

async function analyzeChokepoints() {
  if (!editorContent.value) return

  loading.value = true
  error.value = null
  chokepoints.value = null

  try {
    chokepoints.value = await analyzeChokepointsFromContent(editorContent.value, 10, fileFormat.value)
  } catch (err) {
    error.value = err.response?.data?.detail || err.message || 'Failed to find chokepoints'
  } finally {
    loading.value = false
  }
}

async function analyzeAttackSurface() {
  if (!editorContent.value) return

  loading.value = true
  error.value = null
  attackSurface.value = null

  try {
    attackSurface.value = await analyzeAttackSurfaceFromContent(editorContent.value, fileFormat.value)
  } catch (err) {
    error.value = err.response?.data?.detail || err.message || 'Failed to analyze attack surface'
  } finally {
    loading.value = false
  }
}

async function analyzeVulnImpact() {
  if (!editorContent.value || !selectedVuln.value.trim()) return

  loading.value = true
  error.value = null
  vulnImpact.value = null

  try {
    vulnImpact.value = await analyzeVulnerabilityImpactFromContent(
      editorContent.value,
      selectedVuln.value.trim(),
      fileFormat.value
    )
  } catch (err) {
    error.value = err.response?.data?.detail || err.message || 'Failed to analyze vulnerability impact'
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.file-actions {
  display: flex;
  gap: 0.5rem;
  margin: 0.75rem 0 1rem;
}

/* Template mismatch warning */
.template-warning {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1rem;
  padding: 0.75rem 1rem;
  margin: 0.75rem 0;
  background: #fef3c7;
  border: 1px solid #f59e0b;
  border-radius: 8px;
  color: #92400e;
}

.warning-content {
  display: flex;
  align-items: flex-start;
  gap: 0.75rem;
}

.warning-icon {
  font-size: 1.25rem;
  flex-shrink: 0;
}

.warning-text {
  font-size: 0.9rem;
  line-height: 1.5;
}

.warning-text strong {
  color: #78350f;
}

.btn-warning-dismiss {
  flex-shrink: 0;
  background: transparent;
  border: 1px solid #d97706;
  color: #92400e;
  font-size: 0.8rem;
  padding: 0.25rem 0.75rem;
}

.btn-warning-dismiss:hover {
  background: #fde68a;
}

.file-types {
  display: block;
  margin-top: 0.5rem;
  font-size: 0.75rem;
  color: var(--text-tertiary);
}

.path-section {
  margin-top: 1.5rem;
  padding-top: 1rem;
  border-top: 1px solid var(--border-color);
}

.path-section h4 {
  margin: 0 0 0.75rem;
  font-size: 0.9rem;
  color: var(--text-secondary);
}

.path-inputs {
  display: flex;
  gap: 1rem;
  align-items: flex-end;
  flex-wrap: wrap;
  margin-bottom: 0.75rem;
}

.path-inputs .option-group {
  flex: 1;
  min-width: 120px;
}

.path-inputs input {
  width: 100%;
  padding: 0.5rem;
  border: 1px solid var(--border-color);
  border-radius: 4px;
  font-size: 0.875rem;
}

.paths-section {
  margin-top: 1.5rem;
  padding: 1rem;
  background: var(--bg-secondary);
  border-radius: 8px;
}

.paths-section h3 {
  margin: 0 0 0.5rem;
}

.paths-summary {
  margin: 0 0 1rem;
  color: var(--text-secondary);
  font-size: 0.875rem;
}

.paths-list {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.path-item {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.5rem;
  background: var(--bg-primary);
  border-radius: 4px;
  font-family: monospace;
  font-size: 0.85rem;
}

.path-number {
  font-weight: bold;
  color: var(--accent-color);
  min-width: 1.5rem;
}

.path-nodes {
  flex: 1;
  word-break: break-word;
}

.path-length {
  color: var(--text-tertiary);
  font-size: 0.75rem;
}

.no-paths {
  color: var(--text-tertiary);
  font-style: italic;
}

.critical-section {
  margin-top: 1.5rem;
  padding: 1rem;
  background: var(--bg-secondary);
  border-radius: 8px;
}

.critical-section h3 {
  margin: 0 0 1rem;
}

.critical-list {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.critical-item {
  display: flex;
  align-items: center;
  gap: 1rem;
  padding: 0.75rem;
  background: var(--bg-primary);
  border-radius: 4px;
}

.critical-rank {
  font-weight: bold;
  font-size: 1.1rem;
  color: var(--accent-color);
  min-width: 1.5rem;
}

.critical-info {
  flex: 1;
}

.critical-label {
  font-weight: 500;
}

.critical-type {
  color: var(--text-tertiary);
  font-size: 0.85rem;
  margin-left: 0.25rem;
}

.critical-stats {
  display: flex;
  gap: 0.75rem;
  font-size: 0.8rem;
  color: var(--text-secondary);
}

.criticality-score {
  font-weight: 600;
  color: var(--warning-color, #f39c12);
}

/* CVSS Severity Color Classes */
.cvss-critical .stat-value,
.cvss-critical .stat-label {
  color: #8b0000;
}

.cvss-high .stat-value,
.cvss-high .stat-label {
  color: #e74c3c;
}

.cvss-medium .stat-value,
.cvss-medium .stat-label {
  color: #f39c12;
}

.cvss-low .stat-value,
.cvss-low .stat-label {
  color: #27ae60;
}

.cvss-none .stat-value,
.cvss-none .stat-label {
  color: #3498db;
}

/* CVSS Badge */
.cvss-badge {
  display: inline-block;
  padding: 0.15rem 0.4rem;
  border-radius: 4px;
  font-size: 0.65rem;
  font-weight: 600;
  text-transform: uppercase;
  margin-top: 0.25rem;
}

.cvss-badge.cvss-critical {
  background: #8b0000;
  color: white;
}

.cvss-badge.cvss-high {
  background: #e74c3c;
  color: white;
}

.cvss-badge.cvss-medium {
  background: #f39c12;
  color: white;
}

.cvss-badge.cvss-low {
  background: #27ae60;
  color: white;
}

.cvss-badge.cvss-none {
  background: #3498db;
  color: white;
}

/* Advanced Analysis Section */
.advanced-analysis-section {
  margin-top: 1.5rem;
  padding-top: 1rem;
  border-top: 1px solid var(--border-color);
}

.advanced-analysis-section h4 {
  margin: 0 0 0.75rem;
  font-size: 0.9rem;
  color: var(--text-secondary);
}

.analysis-buttons {
  display: flex;
  gap: 0.5rem;
  flex-wrap: wrap;
  margin-bottom: 0.75rem;
}

.vuln-impact-row {
  display: flex;
  gap: 1rem;
  align-items: flex-end;
  flex-wrap: wrap;
  margin-top: 0.75rem;
}

.vuln-impact-row .option-group {
  flex: 1;
  min-width: 150px;
}

.vuln-impact-row input {
  width: 100%;
  padding: 0.5rem;
  border: 1px solid var(--border-color);
  border-radius: 4px;
  font-size: 0.875rem;
}

/* Graph Metrics Grid */
.metrics-section {
  margin-top: 1.5rem;
  padding: 1rem;
  background: var(--bg-secondary);
  border-radius: 8px;
}

.metrics-section h3 {
  margin: 0 0 1rem;
}

.metrics-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(100px, 1fr));
  gap: 1rem;
}

.metric-item {
  text-align: center;
  padding: 0.75rem;
  background: var(--bg-primary);
  border-radius: 8px;
}

.metric-value {
  display: block;
  font-size: 1.5rem;
  font-weight: 600;
  color: var(--accent-color);
}

.metric-label {
  font-size: 0.75rem;
  color: var(--text-tertiary);
}

/* Centrality Section */
.centrality-section {
  margin-top: 1.5rem;
  padding: 1rem;
  background: var(--bg-secondary);
  border-radius: 8px;
}

.centrality-section h3 {
  margin: 0 0 1rem;
}

.centrality-list {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.centrality-item {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  padding: 0.5rem 0.75rem;
  background: var(--bg-primary);
  border-radius: 4px;
}

.centrality-item .rank {
  font-weight: bold;
  font-size: 1rem;
  color: var(--accent-color);
  min-width: 1.5rem;
}

.centrality-item .node-info {
  flex: 1;
}

.centrality-item .node-label {
  font-weight: 500;
}

.centrality-item .node-type {
  color: var(--text-tertiary);
  font-size: 0.85rem;
  margin-left: 0.25rem;
}

.centrality-item .scores {
  display: flex;
  gap: 0.75rem;
  font-size: 0.8rem;
  font-family: monospace;
}

.centrality-item .score {
  color: var(--text-secondary);
}

/* Chokepoints Section */
.chokepoints-section {
  margin-top: 1.5rem;
  padding: 1rem;
  background: var(--bg-secondary);
  border-radius: 8px;
}

.chokepoints-section h3 {
  margin: 0 0 0.5rem;
}

.section-description {
  margin: 0 0 1rem;
  font-size: 0.85rem;
  color: var(--text-secondary);
}

.chokepoints-list {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.chokepoint-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 0.75rem;
  background: var(--bg-primary);
  border-radius: 4px;
  border-left: 3px solid transparent;
}

.chokepoint-item.critical {
  border-left-color: #e74c3c;
}

.cp-info {
  flex: 1;
}

.cp-label {
  font-weight: 500;
}

.cp-type {
  color: var(--text-tertiary);
  font-size: 0.85rem;
  margin-left: 0.25rem;
}

.cp-stats {
  display: flex;
  gap: 0.75rem;
  font-size: 0.8rem;
  color: var(--text-secondary);
}

.critical-badge {
  background: #e74c3c;
  color: white;
  padding: 0.15rem 0.4rem;
  border-radius: 4px;
  font-size: 0.65rem;
  font-weight: 600;
}

/* Attack Surface Section */
.attack-surface-section {
  margin-top: 1.5rem;
  padding: 1rem;
  background: var(--bg-secondary);
  border-radius: 8px;
}

.attack-surface-section h3 {
  margin: 0 0 0.5rem;
}

.surface-list {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.entry-point {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 0.75rem;
  background: var(--bg-primary);
  border-radius: 4px;
}

.ep-info {
  flex: 1;
}

.ep-label {
  font-weight: 500;
}

.ep-type {
  color: var(--text-tertiary);
  font-size: 0.85rem;
  margin-left: 0.25rem;
}

.ep-stats {
  display: flex;
  gap: 0.75rem;
  font-size: 0.8rem;
  color: var(--text-secondary);
}

.ep-stats .reachable {
  color: var(--accent-color);
  font-weight: 500;
}

/* Vulnerability Impact Section */
.vuln-impact-section {
  margin-top: 1.5rem;
  padding: 1rem;
  background: var(--bg-secondary);
  border-radius: 8px;
}

.vuln-impact-section h3 {
  margin: 0 0 1rem;
}

.impact-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
  gap: 1rem;
  margin-bottom: 1rem;
}

.impact-item {
  text-align: center;
  padding: 0.75rem;
  background: var(--bg-primary);
  border-radius: 8px;
}

.impact-value {
  display: block;
  font-size: 1.5rem;
  font-weight: 600;
  color: var(--accent-color);
}

.impact-label {
  font-size: 0.75rem;
  color: var(--text-tertiary);
}

/* Impact severity classes */
.impact-critical .impact-value {
  color: #8b0000;
}

.impact-high .impact-value {
  color: #e74c3c;
}

.impact-medium .impact-value {
  color: #f39c12;
}

.impact-low .impact-value {
  color: #27ae60;
}

.impact-minimal .impact-value {
  color: #3498db;
}

.impact-cvss {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-size: 0.9rem;
}

.cvss-label {
  color: var(--text-secondary);
}

.cvss-value {
  font-weight: 600;
  padding: 0.25rem 0.5rem;
  border-radius: 4px;
}

.cvss-value.cvss-critical {
  background: #8b0000;
  color: white;
}

.cvss-value.cvss-high {
  background: #e74c3c;
  color: white;
}

.cvss-value.cvss-medium {
  background: #f39c12;
  color: white;
}

.cvss-value.cvss-low {
  background: #27ae60;
  color: white;
}

.cvss-value.cvss-none {
  background: #3498db;
  color: white;
}

/* PDF Notice */
.pdf-notice {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 3rem 2rem;
  background: var(--bg-secondary);
  border: 2px dashed var(--border-color);
  border-radius: 8px;
  text-align: center;
}

.pdf-notice .pdf-icon {
  font-size: 4rem;
  margin-bottom: 1rem;
  opacity: 0.8;
}

.pdf-notice p {
  margin: 0.25rem 0;
  color: var(--text-primary);
  font-size: 1.1rem;
}

.pdf-notice .pdf-hint {
  color: var(--text-secondary);
  font-size: 0.9rem;
}

/* Images Section */
.images-section {
  margin: 1rem 0;
  border: 1px solid var(--border-color);
  border-radius: 8px;
  overflow: hidden;
}

.images-section .section-header {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.75rem 1rem;
  background: var(--bg-tertiary);
  cursor: pointer;
  user-select: none;
  transition: background 0.2s;
}

.images-section .section-header:hover {
  background: var(--bg-secondary);
}

.toggle-icon {
  font-size: 0.7rem;
  color: var(--text-tertiary);
}

.section-title {
  font-weight: 500;
  color: var(--text-primary);
}

.section-hint {
  font-size: 0.8rem;
  color: var(--text-tertiary);
}

.section-content {
  padding: 1rem;
  background: var(--bg-secondary);
  border-top: 1px solid var(--border-color);
}

.images-help {
  margin: 0 0 1rem;
  font-size: 0.85rem;
  color: var(--text-secondary);
  line-height: 1.5;
}

.images-help code {
  background: var(--bg-tertiary);
  padding: 0.15rem 0.4rem;
  border-radius: 4px;
  font-size: 0.8rem;
  color: var(--primary);
}
</style>
