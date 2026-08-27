<!--
  VULNEX -Universal Security Visualization Library-

  File: VulnTreePanel.vue
  Author: Simon Roses Femerling
  Created: 2026-08-27
  Last Modified: 2026-08-27
  Version: 0.4.1
  License: Apache-2.0
  Copyright (c) 2026 VULNEX. All rights reserved.
  https://www.vulnex.com
-->
<template>
  <div class="panel">
    <div class="panel-header">
      <h2>Vulnerability Dependency Tree</h2>
      <p>Upload a configuration file (TOML, JSON, or YAML) describing software dependencies and their CVEs for supply-chain analysis</p>
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
          title="Vulnerability Tree Definition"
          validationType="vuln-tree"
          minHeight="250px"
          maxHeight="400px"
          @validation-change="handleValidationChange"
          @format-detected="handleFormatDetected"
          ref="configEditor"
        />

        <div v-if="editorContent" class="file-actions">
          <button class="btn btn-small btn-secondary" @click="changeFile">Change File</button>
          <button class="btn btn-small btn-secondary" @click="saveTemplate">Save Template</button>
        </div>

        <!-- Template type mismatch warning -->
        <div v-if="templateMismatch" class="template-warning">
          <div class="warning-content">
            <span class="warning-icon">&#x26A0;</span>
            <div class="warning-text">
              <strong>Template type mismatch:</strong> This appears to be a <strong>{{ templateMismatch.detectedTypeName }}</strong> template.
              You're in the Vulnerability Tree panel.
              <span v-if="templateMismatch.suggestedPanel">Consider switching to <strong>{{ templateMismatch.suggestedPanel }}</strong>.</span>
            </div>
          </div>
          <button class="btn btn-small btn-warning-dismiss" @click="dismissMismatchWarning">Dismiss</button>
        </div>

        <div class="options-row">
          <div class="option-group">
            <label>Output Format</label>
            <select v-model="format">
              <option v-for="f in formats" :key="f" :value="f">{{ f.toUpperCase() }}</option>
            </select>
          </div>
          <div class="option-group">
            <label>Mode</label>
            <select v-model="mode">
              <option value="tree">Full Tree</option>
              <option value="vulnerable_only">Vulnerable Only</option>
              <option value="critical_path">Critical Path</option>
            </select>
          </div>
          <div class="option-group">
            <label>Style</label>
            <select v-model="style">
              <option v-for="s in availableStyles" :key="s" :value="s">{{ formatStyleName(s) }}</option>
            </select>
          </div>
        </div>

        <div class="actions">
          <button class="btn btn-primary" @click="generateVisualization" :disabled="!canGenerate || loading">
            <span v-if="loading" class="spinner"></span>
            {{ loading ? 'Generating...' : 'Generate Visualization' }}
          </button>
          <button class="btn btn-secondary" @click="analyzeTree" :disabled="!canGenerate || loading">
            Analyze
          </button>
          <button class="btn btn-secondary" @click="validateTree" :disabled="!canGenerate || loading">
            Validate
          </button>
        </div>
      </div>

      <div v-if="error" class="error-message">
        <span class="error-icon">&#x26A0;</span>
        {{ error }}
      </div>

      <div v-if="imageUrl || imageBlob" class="result-section">
        <div class="result-header">
          <h3>Generated Visualization</h3>
          <button class="btn btn-small" @click="downloadImage">Download</button>
        </div>
        <div v-if="format === 'pdf'" class="pdf-notice">
          <div class="pdf-icon">&#x1F4C4;</div>
          <p>PDF generated successfully</p>
          <p class="pdf-hint">Click "Download" to save the PDF file</p>
        </div>
        <InteractiveSvg v-else-if="svgText" :svg-text="svgText" />
        <ZoomableImage v-else :src="imageUrl" alt="Vulnerability Dependency Tree" />
      </div>

      <div v-if="stats" class="stats-section">
        <h3>Supply Chain Statistics</h3>
        <div class="stats-grid">
          <div class="stat-item">
            <span class="stat-value">{{ stats.total_dependencies }}</span>
            <span class="stat-label">Dependencies</span>
            <span class="coverage-sub">{{ stats.direct_dependencies }} direct / {{ stats.transitive_dependencies }} transitive</span>
          </div>
          <div class="stat-item" :class="riskClass">
            <span class="stat-value">{{ stats.vulnerable_dependencies }}</span>
            <span class="stat-label">Vulnerable</span>
          </div>
          <div class="stat-item">
            <span class="stat-value">{{ stats.total_vulnerabilities }}</span>
            <span class="stat-label">CVEs</span>
          </div>
          <div class="stat-item" :class="{ 'cov-gap': stats.exploited_vulnerabilities > 0 }">
            <span class="stat-value">{{ stats.exploited_vulnerabilities }}</span>
            <span class="stat-label">Exploited</span>
          </div>
          <div class="stat-item" :class="cvssClass(stats.max_cvss)">
            <span class="stat-value">{{ stats.max_cvss.toFixed(1) }}</span>
            <span class="stat-label">Max CVSS</span>
          </div>
          <div class="stat-item">
            <span class="stat-value">{{ stats.remediation_available }}</span>
            <span class="stat-label">Fixable</span>
          </div>
        </div>

        <div v-if="severityBreakdown.length" class="severity-breakdown">
          <h4>Severity Distribution</h4>
          <div class="severity-bars">
            <div v-for="s in severityBreakdown" :key="s.name" class="severity-bar-row">
              <span class="severity-name" :style="{ color: s.color }">{{ s.name }}</span>
              <div class="severity-bar-track">
                <div class="severity-bar-fill" :style="{ width: s.pct + '%', background: s.color }"></div>
              </div>
              <span class="severity-count">{{ s.count }}</span>
            </div>
          </div>
        </div>

        <div v-if="stats.impacted_roots && stats.impacted_roots.length" class="impacted-roots">
          <h4>Impacted Root Packages</h4>
          <div class="chip-row">
            <span v-for="r in stats.impacted_roots" :key="r" class="root-chip">{{ r }}</span>
          </div>
        </div>

        <div v-if="stats.warnings && stats.warnings.length" class="warnings-list">
          <h4>Warnings</h4>
          <ul>
            <li v-for="(w, i) in stats.warnings" :key="i">{{ w }}</li>
          </ul>
        </div>

        <TemplateMetadata v-if="stats.metadata" :metadata="stats.metadata" />
      </div>

      <div v-if="validation" class="validation-section">
        <h3>Validation Result</h3>
        <div :class="['validation-result', validation.valid ? 'valid' : 'invalid']">
          <span class="validation-icon">{{ validation.valid ? '&#x2705;' : '&#x274C;' }}</span>
          {{ validation.valid ? 'Valid dependency tree structure' : 'Validation issues found' }}
        </div>
        <ul v-if="validation.errors && validation.errors.length" class="error-list">
          <li v-for="(err, i) in validation.errors" :key="i">{{ err }}</li>
        </ul>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, inject, watch, computed } from 'vue'
import ConfigEditor from './ConfigEditor.vue'
import InteractiveSvg from './InteractiveSvg.vue'
import ZoomableImage from './ZoomableImage.vue'
import TemplateMetadata from './TemplateMetadata.vue'
import {
  visualizeVulnTreeFromContent,
  analyzeVulnTreeFromContent,
  validateVulnTreeFromContent,
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

const cleanTrigger = inject('cleanTrigger')
watch(cleanTrigger, () => resetPanel())

const editorContent = ref(null)
const fileName = ref('')
const fileFormat = ref('toml')
const format = ref('png')
const style = ref('vt_default')
const mode = ref('tree')
const loading = ref(false)
const error = ref(null)
const imageUrl = ref(null)
const imageBlob = ref(null)
const svgText = ref(null)
const stats = ref(null)
const validation = ref(null)
const isDragging = ref(false)
const fileInput = ref(null)
const configEditor = ref(null)
const isConfigValid = ref(false)
const templateMismatch = ref(null)

const VULNTREE_STYLES = ['vt_default', 'vt_dark', 'vt_security', 'vt_corporate', 'vt_minimal']
const SEVERITY_COLORS = {
  critical: '#7b1fa2',
  high: '#c62828',
  medium: '#ef6c00',
  low: '#fbc02d',
  none: '#4caf50'
}

const availableStyles = computed(() => {
  const fromProps = (props.styles || []).filter((s) => s.startsWith('vt_'))
  return fromProps.length ? fromProps : VULNTREE_STYLES
})

const canGenerate = computed(() => editorContent.value && editorContent.value.trim() && isConfigValid.value)

const severityBreakdown = computed(() => {
  if (!stats.value || !stats.value.severity_distribution) return []
  const order = ['critical', 'high', 'medium', 'low', 'none']
  const dist = stats.value.severity_distribution
  const entries = order.filter((k) => (dist[k] || 0) > 0).map((k) => [k, dist[k]])
  const max = Math.max(1, ...entries.map(([, c]) => c))
  return entries.map(([name, count]) => ({
    name,
    count,
    pct: Math.round((count / max) * 100),
    color: SEVERITY_COLORS[name] || '#64748b'
  }))
})

const riskClass = computed(() => {
  if (!stats.value) return ''
  return stats.value.vulnerable_dependencies > 0 ? 'cov-gap' : 'cov-good'
})

function cvssClass(v) {
  if (v >= 9.0) return 'cov-gap'
  if (v >= 7.0) return 'cov-partial'
  return v > 0 ? '' : 'cov-good'
}

function formatStyleName(s) {
  return s.replace(/^vt_/, '').replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase())
}

async function handleFileSelect(event) {
  const files = event.target.files
  if (files.length > 0) await loadFileContent(files[0])
}

async function handleDrop(event) {
  isDragging.value = false
  const files = event.dataTransfer.files
  if (files.length > 0) await loadFileContent(files[0])
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
  const result = validateTemplateType(content, TemplateType.VULN_TREE)
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
  if (fileInput.value) fileInput.value.value = ''
}

function handleValidationChange({ errors }) {
  isConfigValid.value = !errors.some((e) => e.severity === 'error')
}

function handleFormatDetected(detectedFormat) {
  fileFormat.value = detectedFormat
}

function clearResults() {
  error.value = null
  imageUrl.value = null
  imageBlob.value = null
  svgText.value = null
  stats.value = null
  validation.value = null
}

function resetPanel() {
  editorContent.value = null
  fileName.value = ''
  fileFormat.value = 'toml'
  format.value = 'png'
  style.value = 'vt_default'
  mode.value = 'tree'
  isConfigValid.value = false
  templateMismatch.value = null
  clearResults()
}

function dismissMismatchWarning() {
  templateMismatch.value = null
}

async function generateVisualization() {
  if (!editorContent.value) return
  loading.value = true
  error.value = null
  stats.value = null
  validation.value = null
  try {
    const blob = await visualizeVulnTreeFromContent(
      editorContent.value,
      format.value,
      style.value,
      fileFormat.value,
      mode.value
    )
    imageBlob.value = blob
    imageUrl.value = createImageUrl(blob)
    svgText.value = format.value === 'svg' ? await blob.text() : null
  } catch (err) {
    error.value = err.response?.data?.detail || err.message || 'Failed to generate visualization'
  } finally {
    loading.value = false
  }
}

async function analyzeTree() {
  if (!editorContent.value) return
  loading.value = true
  error.value = null
  validation.value = null
  try {
    stats.value = await analyzeVulnTreeFromContent(editorContent.value, fileFormat.value)
  } catch (err) {
    error.value = err.response?.data?.detail || err.message || 'Failed to analyze vulnerability tree'
  } finally {
    loading.value = false
  }
}

async function validateTree() {
  if (!editorContent.value) return
  loading.value = true
  error.value = null
  stats.value = null
  try {
    validation.value = await validateVulnTreeFromContent(editorContent.value, fileFormat.value)
  } catch (err) {
    error.value = err.response?.data?.detail || err.message || 'Failed to validate vulnerability tree'
  } finally {
    loading.value = false
  }
}

function downloadImage() {
  if (imageBlob.value) downloadBlob(imageBlob.value, `vuln_tree_${getTimestamp()}.${format.value}`)
}

function saveTemplate() {
  if (!editorContent.value) return
  const name = fileName.value || 'template.toml'
  const lastDot = name.lastIndexOf('.')
  const baseName = lastDot > 0 ? name.substring(0, lastDot) : name
  const extension = lastDot > 0 ? name.substring(lastDot) : '.toml'
  downloadTextFile(editorContent.value, `${baseName}_${getTimestamp()}${extension}`)
}
</script>

<style scoped>
.file-actions {
  display: flex;
  gap: 0.5rem;
  margin: 0.75rem 0 1rem;
}

.file-types {
  display: block;
  margin-top: 0.5rem;
  font-size: 0.75rem;
  color: var(--text-tertiary);
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

/* Risk coloring on stat cards */
.cov-good .stat-value {
  color: #27ae60;
}

.cov-partial .stat-value {
  color: #e0a53f;
}

.cov-gap .stat-value {
  color: #e74c3c;
}

.coverage-sub {
  display: block;
  margin-top: 0.15rem;
  font-size: 0.7rem;
  color: var(--text-tertiary);
}

/* Severity breakdown */
.severity-breakdown {
  margin-top: 1.5rem;
}

.severity-breakdown h4,
.impacted-roots h4,
.warnings-list h4 {
  margin: 0 0 0.75rem;
  font-size: 0.95rem;
  color: var(--text-primary);
}

.severity-bars {
  display: flex;
  flex-direction: column;
  gap: 0.4rem;
}

.severity-bar-row {
  display: grid;
  grid-template-columns: 90px 1fr 2rem;
  align-items: center;
  gap: 0.75rem;
}

.severity-name {
  font-size: 0.8rem;
  text-transform: capitalize;
  text-align: right;
  font-weight: 600;
}

.severity-bar-track {
  height: 14px;
  background: var(--bg-tertiary);
  border-radius: 7px;
  overflow: hidden;
}

.severity-bar-fill {
  height: 100%;
  border-radius: 7px;
  transition: width 0.3s ease;
}

.severity-count {
  font-size: 0.8rem;
  font-weight: 600;
  color: var(--text-primary);
  text-align: center;
}

/* Impacted roots */
.impacted-roots {
  margin-top: 1.5rem;
}

.chip-row {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
}

.root-chip {
  padding: 0.3rem 0.75rem;
  background: var(--bg-secondary);
  border: 1px solid var(--border-color);
  border-radius: 999px;
  font-size: 0.8rem;
  color: var(--text-primary);
  font-family: monospace;
}

/* Warnings list */
.warnings-list {
  margin-top: 1.25rem;
}

.warnings-list ul {
  margin: 0;
  padding-left: 1.25rem;
}

.warnings-list li {
  font-size: 0.85rem;
  color: #92400e;
  line-height: 1.5;
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
</style>
