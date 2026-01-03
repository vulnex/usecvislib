<!--
  VULNEX -Universal Security Visualization Library-

  File: ThreatModelPanel.vue
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
      <h2>Threat Model Visualization</h2>
      <p>Upload a configuration file (TOML, JSON, or YAML) defining your system's data flow diagram</p>
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
          title="Threat Model Definition"
          validationType="threat-model"
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
              You're in the Threat Models panel.
              <span v-if="templateMismatch.suggestedPanel">Consider switching to <strong>{{ templateMismatch.suggestedPanel }}</strong>.</span>
            </div>
          </div>
          <button class="btn btn-small btn-warning-dismiss" @click="dismissMismatchWarning">Dismiss</button>
        </div>

        <!-- Node Images Section -->
        <div v-if="editorContent" class="images-section">
          <div class="section-header" @click="showImageUploader = !showImageUploader">
            <span class="toggle-icon">{{ showImageUploader ? '▼' : '▶' }}</span>
            <span class="section-title">Element Images</span>
            <span class="section-hint">(optional)</span>
          </div>
          <div v-show="showImageUploader" class="section-content">
            <p class="images-help">
              Upload images for DFD elements. Copy the image_id and add <code>image_id = "..."</code>
              to processes, datastores, or external entities in your configuration.
            </p>
            <ImageUploader
              ref="imageUploader"
              title="Upload Element Image"
              @image-selected="handleImageSelected"
            />
          </div>
        </div>

        <div class="options-row">
          <div class="option-group">
            <label>Engine</label>
            <select v-model="engine">
              <option v-for="e in engines" :key="e.value" :value="e.value" :disabled="!e.available">
                {{ e.label }}{{ !e.available ? ' (not installed)' : '' }}
              </option>
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
            <select v-model="style" :disabled="engine === 'pytm'">
              <option v-for="s in styles" :key="s" :value="s">{{ formatStyleName(s) }}</option>
            </select>
          </div>
        </div>

        <div v-if="engine === 'pytm'" class="engine-info">
          <span class="info-icon">&#x2139;</span>
          Using OWASP PyTM engine. Custom styles are not available with this engine.
        </div>

        <div class="actions">
          <button class="btn btn-primary" @click="generateVisualization" :disabled="!canGenerate || loading">
            <span v-if="loading" class="spinner"></span>
            {{ loading ? 'Generating...' : 'Generate DFD' }}
          </button>
          <button class="btn btn-secondary" @click="analyzeModel" :disabled="!canGenerate || loading">
            Analyze Model
          </button>
          <button class="btn btn-accent" @click="runStrideAnalysis" :disabled="!canGenerate || loading">
            STRIDE Analysis
          </button>
        </div>

        <div class="report-section">
          <div class="report-options">
            <label>Report Format</label>
            <select v-model="reportFormat">
              <option value="markdown">Markdown</option>
              <option value="html">HTML</option>
            </select>
          </div>
          <button class="btn btn-outline" @click="generateReport" :disabled="!canGenerate || loading">
            <span v-if="loading" class="spinner"></span>
            {{ loading ? 'Generating...' : 'Generate Report' }}
          </button>
        </div>
      </div>

      <div v-if="error" class="error-message">
        <span class="error-icon">&#x26A0;</span>
        {{ error }}
      </div>

      <div v-if="imageUrl || imageBlob" class="result-section">
        <div class="result-header">
          <h3>Data Flow Diagram</h3>
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
        <ZoomableImage v-else :src="imageUrl" alt="Threat Model DFD" />
      </div>

      <div v-if="stats" class="stats-section">
        <h3>Model Statistics</h3>
        <div class="stats-grid">
          <div class="stat-item">
            <span class="stat-value">{{ stats.total_processes }}</span>
            <span class="stat-label">Processes</span>
          </div>
          <div class="stat-item">
            <span class="stat-value">{{ stats.total_datastores }}</span>
            <span class="stat-label">Data Stores</span>
          </div>
          <div class="stat-item">
            <span class="stat-value">{{ stats.total_externals }}</span>
            <span class="stat-label">External Entities</span>
          </div>
          <div class="stat-item">
            <span class="stat-value">{{ stats.total_dataflows }}</span>
            <span class="stat-label">Data Flows</span>
          </div>
          <div class="stat-item">
            <span class="stat-value">{{ stats.total_boundaries }}</span>
            <span class="stat-label">Trust Boundaries</span>
          </div>
          <div class="stat-item highlight">
            <span class="stat-value">{{ stats.flows_crossing_boundaries }}</span>
            <span class="stat-label">Boundary Crossings</span>
          </div>
          <div v-if="stats.total_threats > 0" class="stat-item">
            <span class="stat-value">{{ stats.total_threats }}</span>
            <span class="stat-label">Total Threats</span>
          </div>
          <div v-if="stats.average_cvss > 0" class="stat-item" :class="getCvssSeverityClass(stats.average_cvss)">
            <span class="stat-value">{{ stats.average_cvss.toFixed(1) }}</span>
            <span class="stat-label">Avg CVSS</span>
            <span class="cvss-badge" :class="getCvssSeverityClass(stats.average_cvss)">
              {{ getCvssSeverityLabel(stats.average_cvss) }}
            </span>
          </div>
          <div v-if="stats.critical_threats > 0" class="stat-item cvss-critical">
            <span class="stat-value">{{ stats.critical_threats }}</span>
            <span class="stat-label">Critical Threats</span>
          </div>
          <div v-if="stats.high_threats > 0" class="stat-item cvss-high">
            <span class="stat-value">{{ stats.high_threats }}</span>
            <span class="stat-label">High Threats</span>
          </div>
        </div>
        <TemplateMetadata v-if="stats.metadata" :metadata="stats.metadata" />
      </div>

      <div v-if="strideReport" class="stride-section">
        <h3>STRIDE Threat Analysis</h3>
        <p class="stride-model">Model: {{ strideReport.model_name }}</p>

        <div class="stride-categories">
          <div class="stride-category" v-for="(category, key) in strideCategories" :key="key">
            <div class="category-header" @click="toggleCategory(key)">
              <span class="category-icon">{{ category.icon }}</span>
              <span class="category-name">{{ category.name }}</span>
              <span class="category-count">{{ getThreats(key).length }}</span>
              <span class="expand-icon">{{ expandedCategories[key] ? '▼' : '▶' }}</span>
            </div>
            <div v-if="expandedCategories[key]" class="category-threats">
              <div v-if="getThreats(key).length === 0" class="no-threats">
                No threats identified
              </div>
              <div v-for="(threat, i) in getThreats(key)" :key="i" class="threat-item" :class="threat.cvss ? getCvssSeverityClass(threat.cvss) : ''">
                <div class="threat-header">
                  <div class="threat-element">{{ threat.element }}</div>
                  <div v-if="threat.cvss" class="threat-cvss">
                    <span class="cvss-score">{{ threat.cvss.toFixed(1) }}</span>
                    <span class="cvss-badge" :class="getCvssSeverityClass(threat.cvss)">
                      {{ getCvssSeverityLabel(threat.cvss) }}
                    </span>
                  </div>
                </div>
                <div class="threat-description">{{ threat.threat }}</div>
                <div class="threat-mitigation">
                  <span class="mitigation-label">Mitigation:</span>
                  {{ threat.mitigation }}
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, reactive, inject, watch, computed } from 'vue'
import ConfigEditor from './ConfigEditor.vue'
import ZoomableImage from './ZoomableImage.vue'
import TemplateMetadata from './TemplateMetadata.vue'
import ImageUploader from './ImageUploader.vue'
import {
  visualizeThreatModelFromContent,
  analyzeThreatModelFromContent,
  analyzeStrideFromContent,
  generateReportFromContent,
  createImageUrl,
  getTimestamp,
  downloadBlob,
  downloadTextFile
} from '../services/api.js'
import { validateTemplateType, TemplateType } from '../utils/template-detector.js'

const props = defineProps({
  styles: { type: Array, default: () => [] },
  formats: { type: Array, default: () => ['png'] },
  engines: {
    type: Array,
    default: () => [
      { value: 'usecvislib', label: 'USecVisLib', available: true },
      { value: 'pytm', label: 'OWASP PyTM', available: true }
    ]
  }
})

// Watch for clean trigger from parent
const cleanTrigger = inject('cleanTrigger')
watch(cleanTrigger, () => {
  resetPanel()
})

// State
const editorContent = ref(null)  // null = no file, string = content
const fileName = ref('')
const fileFormat = ref('toml')  // Detected file format: toml, json, yaml
const format = ref('png')
const style = ref('tm_default')
const engine = ref('usecvislib')
const loading = ref(false)
const error = ref(null)
const imageUrl = ref(null)
const imageBlob = ref(null)
const stats = ref(null)
const strideReport = ref(null)
const isDragging = ref(false)
const fileInput = ref(null)
const configEditor = ref(null)
const isConfigValid = ref(false)
const reportFormat = ref('markdown')
const showImageUploader = ref(false)
const imageUploader = ref(null)
const selectedImageId = ref(null)
const templateMismatch = ref(null)  // { detectedTypeName, suggestedPanel }

const expandedCategories = reactive({
  spoofing: false,
  tampering: false,
  repudiation: false,
  information_disclosure: false,
  denial_of_service: false,
  elevation_of_privilege: false
})

const strideCategories = {
  spoofing: { name: 'Spoofing', icon: '🎭' },
  tampering: { name: 'Tampering', icon: '✏️' },
  repudiation: { name: 'Repudiation', icon: '🚫' },
  information_disclosure: { name: 'Information Disclosure', icon: '🔓' },
  denial_of_service: { name: 'Denial of Service', icon: '💥' },
  elevation_of_privilege: { name: 'Elevation of Privilege', icon: '⬆️' }
}

// Computed
const canGenerate = computed(() => {
  return editorContent.value && editorContent.value.trim() && isConfigValid.value
})

// Methods
function formatStyleName(s) {
  return s.replace('tm_', '').replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())
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
  const result = validateTemplateType(content, TemplateType.THREAT_MODEL)
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
  // Reset the file input
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
  strideReport.value = null
}

function resetPanel() {
  editorContent.value = null
  fileName.value = ''
  fileFormat.value = 'toml'
  format.value = 'png'
  style.value = 'tm_default'
  engine.value = 'usecvislib'
  isConfigValid.value = false
  showImageUploader.value = false
  selectedImageId.value = null
  templateMismatch.value = null
  // Reset expanded categories
  Object.keys(expandedCategories).forEach(key => {
    expandedCategories[key] = false
  })
  clearResults()
}

function dismissMismatchWarning() {
  templateMismatch.value = null
}

function handleImageSelected(image) {
  selectedImageId.value = image?.image_id || null
}

function toggleCategory(key) {
  expandedCategories[key] = !expandedCategories[key]
}

function getThreats(key) {
  return strideReport.value?.[key] || []
}

async function generateVisualization() {
  if (!editorContent.value) return

  loading.value = true
  error.value = null
  stats.value = null
  strideReport.value = null

  try {
    const blob = await visualizeThreatModelFromContent(editorContent.value, format.value, style.value, engine.value, fileFormat.value)
    imageBlob.value = blob
    imageUrl.value = createImageUrl(blob)
  } catch (err) {
    error.value = err.response?.data?.detail || err.message || 'Failed to generate visualization'
  } finally {
    loading.value = false
  }
}

async function analyzeModel() {
  if (!editorContent.value) return

  loading.value = true
  error.value = null
  strideReport.value = null

  try {
    stats.value = await analyzeThreatModelFromContent(editorContent.value, fileFormat.value)
  } catch (err) {
    error.value = err.response?.data?.detail || err.message || 'Failed to analyze model'
  } finally {
    loading.value = false
  }
}

async function runStrideAnalysis() {
  if (!editorContent.value) return

  loading.value = true
  error.value = null
  stats.value = null

  try {
    strideReport.value = await analyzeStrideFromContent(editorContent.value, fileFormat.value)
    // Expand first category with threats
    for (const key of Object.keys(strideCategories)) {
      if (getThreats(key).length > 0) {
        expandedCategories[key] = true
        break
      }
    }
  } catch (err) {
    error.value = err.response?.data?.detail || err.message || 'Failed to run STRIDE analysis'
  } finally {
    loading.value = false
  }
}

async function generateReport() {
  if (!editorContent.value) return

  loading.value = true
  error.value = null

  try {
    const result = await generateReportFromContent(editorContent.value, fileFormat.value, reportFormat.value)
    downloadTextFile(result.content, result.filename)
  } catch (err) {
    error.value = err.response?.data?.detail || err.message || 'Failed to generate report'
  } finally {
    loading.value = false
  }
}

function downloadImage() {
  if (imageBlob.value) {
    downloadBlob(imageBlob.value, `threat_model_${getTimestamp()}.${format.value}`)
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

.report-section {
  display: flex;
  align-items: center;
  gap: 1rem;
  margin-top: 1rem;
  padding-top: 1rem;
  border-top: 1px solid var(--border-color);
}

.report-options {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.report-options label {
  font-size: 0.875rem;
  color: var(--text-secondary);
}

.report-options select {
  padding: 0.375rem 0.75rem;
  border-radius: 4px;
  border: 1px solid var(--border-color);
  background: var(--bg-secondary);
  color: var(--text-primary);
  font-size: 0.875rem;
}

.btn-outline {
  background: transparent;
  border: 1px solid var(--accent-color);
  color: var(--accent-color);
}

.btn-outline:hover:not(:disabled) {
  background: var(--accent-color);
  color: white;
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

/* Threat CVSS display */
.threat-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.threat-cvss {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.cvss-score {
  font-weight: 600;
  font-size: 0.9rem;
}

.threat-item.cvss-critical {
  border-left: 3px solid #8b0000;
}

.threat-item.cvss-high {
  border-left: 3px solid #e74c3c;
}

.threat-item.cvss-medium {
  border-left: 3px solid #f39c12;
}

.threat-item.cvss-low {
  border-left: 3px solid #27ae60;
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

.section-header {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.75rem 1rem;
  background: var(--bg-tertiary);
  cursor: pointer;
  user-select: none;
  transition: background 0.2s;
}

.section-header:hover {
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
