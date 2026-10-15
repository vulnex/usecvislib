<!--
  VULNEX -Universal Security Visualization Library-

  File: BatchPanel.vue
  Author: Simon Roses Femerling
  Created: 2025-12-25
  Last Modified: 2025-12-25
  Version: 0.3.1
  License: Apache-2.0
  Copyright (c) 2025 VULNEX. All rights reserved.
  https://www.vulnex.com
-->
<template>
  <div class="panel">
    <div class="panel-header">
      <h2>Batch Processing</h2>
      <p>Process multiple files at once with any file-based module: attack trees and graphs, threat models, architecture diagrams, kill chains, timelines, vulnerability trees, MAESTRO, custom diagrams, or binary analysis.</p>
    </div>

    <div class="panel-body">
      <div class="form-section">
        <!-- Upload area for multiple files -->
        <div
          class="upload-area"
          :class="{ dragover: isDragging }"
          @dragover.prevent="isDragging = true"
          @dragleave="isDragging = false"
          @drop.prevent="handleDrop"
        >
          <input
            type="file"
            ref="fileInput"
            :accept="mode === 'binary' ? '' : '.tml,.toml,.json,.yaml,.yml'"
            @change="handleFileSelect"
            class="file-input"
            multiple
          />
          <div class="upload-content" @click="$refs.fileInput.click()">
            <span class="upload-icon">&#x1F4C2;</span>
            <p>Drop multiple config files here or click to browse</p>
            <span class="file-types">Supports: TOML, JSON, YAML (for visualizations) or any file (Binary Analysis)</span>
          </div>
        </div>

        <!-- File list -->
        <div v-if="files.length > 0" class="file-list">
          <div class="file-list-header">
            <h3>Selected Files ({{ files.length }})</h3>
            <button class="btn btn-small btn-secondary" @click="clearFiles">Clear All</button>
          </div>
          <ul class="files">
            <li v-for="(file, index) in files" :key="index" class="file-item">
              <span class="file-name">{{ file.name }}</span>
              <span class="file-size">{{ formatFileSize(file.size) }}</span>
              <button class="btn-remove" @click="removeFile(index)">&#x2715;</button>
            </li>
          </ul>
        </div>

        <!-- Options -->
        <div class="options-row">
          <div class="option-group">
            <label>Visualization Mode</label>
            <select v-model="mode">
              <option v-for="m in modes" :key="m.value" :value="m.value">{{ m.label }}</option>
            </select>
          </div>
          <div v-if="mode === 'binary'" class="option-group">
            <label>Chart</label>
            <select v-model="binaryChart">
              <option v-for="c in binaryCharts" :key="c.value" :value="c.value">{{ c.label }}</option>
            </select>
          </div>
          <div class="option-group">
            <label>Output Format</label>
            <select v-model="format">
              <option v-for="f in formats" :key="f" :value="f">{{ f.toUpperCase() }}</option>
            </select>
          </div>
          <div class="option-group">
            <label>Style</label>
            <select v-model="style">
              <option v-for="s in currentStyles" :key="s" :value="s">{{ formatStyleName(s) }}</option>
            </select>
          </div>
        </div>

        <div class="options-row">
          <div class="option-group checkbox-group">
            <label>
              <input type="checkbox" v-model="collectStats" />
              Collect Statistics
            </label>
          </div>
        </div>

        <div class="actions">
          <button
            class="btn btn-primary"
            @click="processBatch"
            :disabled="files.length === 0 || processing"
          >
            <span v-if="processing" class="spinner"></span>
            {{ processing ? `Processing (${progress.current}/${progress.total})...` : 'Process All Files' }}
          </button>
        </div>
      </div>

      <div v-if="error" class="error-message">
        <span class="error-icon">&#x26A0;</span>
        {{ error }}
      </div>

      <!-- Progress bar -->
      <div v-if="processing" class="progress-section">
        <div class="progress-bar">
          <div
            class="progress-fill"
            :style="{ width: (progress.current / progress.total * 100) + '%' }"
          ></div>
        </div>
        <p class="progress-text">Processing {{ progress.current }} of {{ progress.total }} files...</p>
      </div>

      <!-- Results -->
      <div v-if="results" class="results-section">
        <div class="results-header">
          <h3>Batch Results</h3>
          <div class="results-summary">
            <span class="success">{{ results.success_count }} succeeded</span>
            <span class="failure" v-if="results.failure_count > 0">{{ results.failure_count }} failed</span>
            <span class="rate">({{ (results.success_rate * 100).toFixed(0) }}% success rate)</span>
          </div>
        </div>

        <div class="results-list">
          <div
            v-for="(result, index) in results.results"
            :key="index"
            :class="['result-item', result.success ? 'success' : 'failure']"
          >
            <span class="result-icon">{{ result.success ? '&#x2705;' : '&#x274C;' }}</span>
            <span class="result-filename">{{ result.filename }}</span>
            <template v-if="result.success">
              <button
                v-if="result.image_data"
                class="btn btn-small btn-download"
                @click="downloadResult(result)"
              >
                Download {{ result.output_file }}
              </button>
              <span v-else class="result-output">{{ result.output_file }}</span>
            </template>
            <span v-else class="result-error">{{ result.error }}</span>
          </div>
        </div>

        <!-- Download All button -->
        <div v-if="successfulResults.length > 1" class="download-all">
          <button class="btn btn-secondary" @click="downloadAll">
            Download All ({{ successfulResults.length }} files)
          </button>
        </div>

        <!-- Aggregate stats -->
        <div v-if="results.aggregate_stats" class="aggregate-stats">
          <h4>Aggregate Statistics</h4>
          <div class="stats-grid">
            <div v-for="(value, key) in results.aggregate_stats" :key="key" class="stat-item">
              <span class="stat-value">{{ formatStatValue(value) }}</span>
              <span class="stat-label">{{ formatStatKey(key) }}</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, inject, watch, computed } from 'vue'
import { batchVisualize } from '../services/api.js'

const props = defineProps({
  styles: { type: Object, default: () => ({}) },
  formats: { type: Array, default: () => ['png'] }
})

// Watch for clean trigger from parent
const cleanTrigger = inject('cleanTrigger')
watch(cleanTrigger, () => {
  resetPanel()
})

// State
const files = ref([])
const mode = ref('attack_tree')
const format = ref('png')
const style = ref('at_default')
const collectStats = ref(true)
const binaryChart = ref('entropy')
const processing = ref(false)
const error = ref(null)
const results = ref(null)
const isDragging = ref(false)
const fileInput = ref(null)
const progress = ref({ current: 0, total: 0 })

// Batch modes: API mode value, label, key in the /styles response, style prefix
const modes = [
  { value: 'attack_tree', label: 'Attack Tree', stylesKey: 'attack_tree', prefix: 'at_' },
  { value: 'attack_graph', label: 'Attack Graph', stylesKey: 'attack_graph', prefix: 'ag_' },
  { value: 'threat_model', label: 'Threat Model', stylesKey: 'threat_model', prefix: 'tm_' },
  { value: 'privilege_gradient', label: 'Privilege Gradient', stylesKey: 'privilege_gradient', prefix: 'pg_' },
  { value: 'component_diagram', label: 'Component Diagram', stylesKey: 'component_diagram', prefix: 'cd_' },
  { value: 'dependency_graph', label: 'Dependency Graph', stylesKey: 'dependency_graph', prefix: 'dg_' },
  { value: 'kill_chain', label: 'Kill Chain', stylesKey: 'kill_chain', prefix: 'kc_' },
  { value: 'incident_timeline', label: 'Incident Timeline', stylesKey: 'timeline', prefix: 'tl_' },
  { value: 'vuln_tree', label: 'Vulnerability Tree', stylesKey: 'vuln_tree', prefix: 'vt_' },
  { value: 'maestro', label: 'MAESTRO', stylesKey: 'maestro', prefix: 'ma_' },
  { value: 'custom_diagram', label: 'Custom Diagram', stylesKey: 'custom_diagram', prefix: 'cd_' },
  { value: 'binary', label: 'Binary Analysis', stylesKey: 'binary_visualization', prefix: 'bv_' }
]

// One chart per file in binary mode
const binaryCharts = [
  { value: 'entropy', label: 'Entropy' },
  { value: 'distribution', label: 'Byte Distribution' },
  { value: 'windrose', label: 'Wind Rose' },
  { value: 'heatmap', label: 'Heatmap' },
  { value: 'digraph', label: 'Byte-Pair Digraph' }
]

const currentMode = computed(() => modes.find(m => m.value === mode.value) || modes[0])

// Computed
const currentStyles = computed(() => props.styles[currentMode.value.stylesKey] || [])

const successfulResults = computed(() => {
  if (!results.value?.results) return []
  return results.value.results.filter(r => r.success && r.image_data)
})

// Watch mode changes to reset style
watch(mode, () => {
  style.value = currentMode.value.prefix + 'default'
})

// Methods
function formatStyleName(s) {
  // Remove prefix and format
  // SVG-engine presets (sv_*) sit beside the module's own: keep them apart
  if (s.startsWith('sv_')) {
    return 'SVG ' + formatStyleName(s.substring(3))
  }
  const prefixes = [...new Set(modes.map(m => m.prefix))]
  let name = s
  for (const p of prefixes) {
    if (name.startsWith(p)) {
      name = name.substring(p.length)
      break
    }
  }
  return name.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())
}

function formatFileSize(bytes) {
  if (bytes < 1024) return bytes + ' B'
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB'
  return (bytes / (1024 * 1024)).toFixed(1) + ' MB'
}

function formatStatKey(key) {
  return key.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())
}

function formatStatValue(value) {
  if (typeof value === 'number') {
    return Number.isInteger(value) ? value : value.toFixed(2)
  }
  return value
}

async function handleFileSelect(event) {
  const selectedFiles = Array.from(event.target.files)
  addFiles(selectedFiles)
}

async function handleDrop(event) {
  isDragging.value = false
  const droppedFiles = Array.from(event.dataTransfer.files)
  addFiles(droppedFiles)
}

function addFiles(newFiles) {
  files.value = [...files.value, ...newFiles]
  error.value = null
  results.value = null
}

function removeFile(index) {
  files.value.splice(index, 1)
}

function clearFiles() {
  files.value = []
  results.value = null
  error.value = null
  if (fileInput.value) {
    fileInput.value.value = ''
  }
}

function resetPanel() {
  files.value = []
  mode.value = 'attack_tree'
  format.value = 'png'
  style.value = 'at_default'
  collectStats.value = true
  binaryChart.value = 'entropy'
  processing.value = false
  error.value = null
  results.value = null
  progress.value = { current: 0, total: 0 }
}

async function processBatch() {
  if (files.value.length === 0) return

  processing.value = true
  error.value = null
  results.value = null
  progress.value = { current: 0, total: files.value.length }

  try {
    const onProgress = (filename, success, err) => {
      progress.value.current++
    }

    results.value = await batchVisualize(
      mode.value,
      files.value,
      format.value,
      style.value,
      collectStats.value,
      onProgress,
      mode.value === 'binary' ? binaryChart.value : null
    )
  } catch (err) {
    error.value = err.response?.data?.detail || err.message || 'Failed to process batch'
  } finally {
    processing.value = false
  }
}

function downloadResult(result) {
  if (!result.image_data) return

  // Convert base64 to blob
  const byteCharacters = atob(result.image_data)
  const byteNumbers = new Array(byteCharacters.length)
  for (let i = 0; i < byteCharacters.length; i++) {
    byteNumbers[i] = byteCharacters.charCodeAt(i)
  }
  const byteArray = new Uint8Array(byteNumbers)

  // Determine MIME type
  const mimeTypes = {
    png: 'image/png',
    svg: 'image/svg+xml',
    pdf: 'application/pdf'
  }
  const ext = result.output_file.split('.').pop().toLowerCase()
  const mimeType = mimeTypes[ext] || 'application/octet-stream'

  const blob = new Blob([byteArray], { type: mimeType })
  const url = URL.createObjectURL(blob)

  const a = document.createElement('a')
  a.href = url
  a.download = result.output_file
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
}

function downloadAll() {
  // Download each successful result with a small delay to avoid browser issues
  successfulResults.value.forEach((result, index) => {
    setTimeout(() => downloadResult(result), index * 300)
  })
}
</script>

<style scoped>
.file-list {
  margin: 1rem 0;
  border: 1px solid var(--border-color);
  border-radius: 8px;
  overflow: hidden;
}

.file-list-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 0.75rem 1rem;
  background: var(--bg-secondary);
  border-bottom: 1px solid var(--border-color);
}

.file-list-header h3 {
  margin: 0;
  font-size: 0.9rem;
}

.files {
  list-style: none;
  padding: 0;
  margin: 0;
  max-height: 200px;
  overflow-y: auto;
}

.file-item {
  display: flex;
  align-items: center;
  padding: 0.5rem 1rem;
  border-bottom: 1px solid var(--border-color);
  gap: 1rem;
}

.file-item:last-child {
  border-bottom: none;
}

.file-name {
  flex: 1;
  font-family: monospace;
  font-size: 0.85rem;
}

.file-size {
  color: var(--text-tertiary);
  font-size: 0.8rem;
}

.btn-remove {
  background: none;
  border: none;
  color: var(--text-tertiary);
  cursor: pointer;
  padding: 0.25rem;
  font-size: 0.9rem;
}

.btn-remove:hover {
  color: var(--error-color);
}

.checkbox-group label {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  cursor: pointer;
}

.progress-section {
  margin: 1rem 0;
}

.progress-bar {
  height: 8px;
  background: var(--bg-secondary);
  border-radius: 4px;
  overflow: hidden;
}

.progress-fill {
  height: 100%;
  background: var(--primary-color);
  transition: width 0.3s ease;
}

.progress-text {
  text-align: center;
  margin-top: 0.5rem;
  color: var(--text-secondary);
  font-size: 0.85rem;
}

.results-section {
  margin-top: 1.5rem;
  border: 1px solid var(--border-color);
  border-radius: 8px;
  overflow: hidden;
}

.results-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 1rem;
  background: var(--bg-secondary);
  border-bottom: 1px solid var(--border-color);
}

.results-header h3 {
  margin: 0;
}

.results-summary {
  display: flex;
  gap: 1rem;
  font-size: 0.85rem;
}

.results-summary .success {
  color: var(--success-color);
}

.results-summary .failure {
  color: var(--error-color);
}

.results-summary .rate {
  color: var(--text-tertiary);
}

.results-list {
  max-height: 300px;
  overflow-y: auto;
}

.result-item {
  display: flex;
  align-items: center;
  padding: 0.75rem 1rem;
  border-bottom: 1px solid var(--border-color);
  gap: 0.75rem;
}

.result-item:last-child {
  border-bottom: none;
}

.result-item.success {
  background: rgba(var(--success-rgb), 0.05);
}

.result-item.failure {
  background: rgba(var(--error-rgb), 0.05);
}

.result-icon {
  font-size: 1rem;
}

.result-filename {
  font-family: monospace;
  font-size: 0.85rem;
  flex: 1;
}

.result-output {
  color: var(--success-color);
  font-size: 0.8rem;
}

.result-error {
  color: var(--error-color);
  font-size: 0.8rem;
  max-width: 300px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.aggregate-stats {
  padding: 1rem;
  background: var(--bg-secondary);
  border-top: 1px solid var(--border-color);
}

.aggregate-stats h4 {
  margin: 0 0 1rem 0;
  font-size: 0.9rem;
}

.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(100px, 1fr));
  gap: 1rem;
}

.stat-item {
  text-align: center;
}

.stat-value {
  display: block;
  font-size: 1.5rem;
  font-weight: 600;
  color: var(--primary-color);
}

.stat-label {
  font-size: 0.75rem;
  color: var(--text-tertiary);
  text-transform: uppercase;
}

.file-types {
  display: block;
  margin-top: 0.5rem;
  font-size: 0.75rem;
  color: var(--text-tertiary);
}

.btn-download {
  margin-left: auto;
  background: var(--primary-color);
  color: white;
  border: none;
  padding: 0.25rem 0.75rem;
  border-radius: 4px;
  cursor: pointer;
  font-size: 0.8rem;
}

.btn-download:hover {
  background: var(--primary-hover);
}

.download-all {
  padding: 1rem;
  border-top: 1px solid var(--border-color);
  text-align: center;
}
</style>
