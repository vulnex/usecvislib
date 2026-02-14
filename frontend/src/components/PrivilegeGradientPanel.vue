<!--
  VULNEX -Universal Security Visualization Library-

  File: PrivilegeGradientPanel.vue
  License: Apache-2.0
  Copyright (c) 2025 VULNEX. All rights reserved.
-->
<template>
  <div class="panel">
    <div class="panel-header">
      <h2>Privilege Gradient Visualization</h2>
      <p>Upload a configuration file (TOML, JSON, or YAML) defining your privilege gradient</p>
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
          title="Privilege Gradient Definition"
          validationType="privilege-gradient"
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
              You're in the Privilege Gradients panel.
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
          <button class="btn btn-secondary" @click="analyzeStructure" :disabled="!canGenerate || loading">
            Analyze Structure
          </button>
          <button class="btn btn-secondary" @click="detectInversions" :disabled="!canGenerate || loading">
            Detect Inversions
          </button>
          <button class="btn btn-secondary" @click="validateGradient" :disabled="!canGenerate || loading">
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
        <ZoomableImage v-else :src="imageUrl" alt="Privilege Gradient Visualization" />
      </div>

      <div v-if="stats" class="stats-section">
        <h3>Gradient Statistics</h3>
        <div class="stats-grid">
          <div class="stat-item">
            <span class="stat-value">{{ stats.total_zones }}</span>
            <span class="stat-label">Zones</span>
          </div>
          <div class="stat-item">
            <span class="stat-value">{{ stats.total_components }}</span>
            <span class="stat-label">Components</span>
          </div>
          <div class="stat-item">
            <span class="stat-value">{{ stats.total_influences }}</span>
            <span class="stat-label">Influences</span>
          </div>
          <div class="stat-item">
            <span class="stat-value">{{ stats.total_inversions }}</span>
            <span class="stat-label">Inversions</span>
          </div>
          <div v-if="stats.max_trust_gap > 0" class="stat-item severity-critical">
            <span class="stat-value">{{ stats.max_trust_gap }}</span>
            <span class="stat-label">Max Trust Gap</span>
          </div>
        </div>
        <TemplateMetadata v-if="stats.metadata" :metadata="stats.metadata" />

        <div v-if="stats && stats.components_per_zone" class="zone-breakdown">
          <h4>Components per Zone</h4>
          <div class="zone-bars">
            <div v-for="(count, zone) in stats.components_per_zone" :key="zone" class="zone-bar-item">
              <span class="zone-label">{{ zone }}</span>
              <div class="zone-bar" :style="{ width: (count / maxZoneCount * 100) + '%' }"></div>
              <span class="zone-count">{{ count }}</span>
            </div>
          </div>
        </div>
      </div>

      <div v-if="inversions" class="inversions-section">
        <h3>Privilege Inversions</h3>
        <div class="inversions-summary">
          <span>Total: {{ inversions.total }}</span>
          <span v-if="inversions.by_severity.critical" class="severity-badge critical">Critical: {{ inversions.by_severity.critical }}</span>
          <span v-if="inversions.by_severity.high" class="severity-badge high">High: {{ inversions.by_severity.high }}</span>
          <span v-if="inversions.by_severity.medium" class="severity-badge medium">Medium: {{ inversions.by_severity.medium }}</span>
        </div>
        <div class="inversions-list">
          <div v-for="inv in inversions.inversions" :key="inv.from + inv.to" class="inversion-item" :class="'severity-' + inv.severity">
            <div class="inv-flow">
              <span class="inv-component">{{ inv.from }}</span>
              <span class="inv-arrow">&rarr;</span>
              <span class="inv-component">{{ inv.to }}</span>
            </div>
            <div class="inv-details">
              <span class="inv-zones">{{ inv.from_zone }} &rarr; {{ inv.to_zone }}</span>
              <span class="inv-gap">Gap: {{ inv.trust_gap }}</span>
              <span class="severity-badge" :class="inv.severity">{{ inv.severity.toUpperCase() }}</span>
            </div>
          </div>
        </div>
      </div>

      <div v-if="validation" class="validation-section">
        <h3>Validation Result</h3>
        <div :class="['validation-result', validation.valid ? 'valid' : 'invalid']">
          <span class="validation-icon">{{ validation.valid ? '&#x2705;' : '&#x274C;' }}</span>
          {{ validation.valid ? 'Valid privilege gradient structure' : 'Validation errors found' }}
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
import ZoomableImage from './ZoomableImage.vue'
import TemplateMetadata from './TemplateMetadata.vue'
import {
  visualizePrivilegeGradientFromContent,
  analyzePrivilegeGradientFromContent,
  analyzeInversionsFromContent,
  validatePrivilegeGradientFromContent,
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
const style = ref('pg_default')
const loading = ref(false)
const error = ref(null)
const imageUrl = ref(null)
const imageBlob = ref(null)
const stats = ref(null)
const inversions = ref(null)
const validation = ref(null)
const isDragging = ref(false)
const fileInput = ref(null)
const configEditor = ref(null)
const isConfigValid = ref(false)
const templateMismatch = ref(null)  // { detectedTypeName, suggestedPanel }

// Computed
const canGenerate = computed(() => {
  return editorContent.value && editorContent.value.trim() && isConfigValid.value
})

const maxZoneCount = computed(() => {
  if (!stats.value || !stats.value.components_per_zone) return 1
  return Math.max(...Object.values(stats.value.components_per_zone), 1)
})

// Methods
function formatStyleName(s) {
  return s.replace('pg_', '').replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())
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
  const result = validateTemplateType(content, TemplateType.PRIVILEGE_GRADIENT || 'privilege-gradient')
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
  inversions.value = null
  validation.value = null
}

function resetPanel() {
  editorContent.value = null
  fileName.value = ''
  fileFormat.value = 'toml'
  format.value = 'png'
  style.value = 'pg_default'
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
  inversions.value = null
  validation.value = null

  try {
    const blob = await visualizePrivilegeGradientFromContent(editorContent.value, format.value, style.value, fileFormat.value)
    imageBlob.value = blob
    imageUrl.value = createImageUrl(blob)
  } catch (err) {
    error.value = err.response?.data?.detail || err.message || 'Failed to generate visualization'
  } finally {
    loading.value = false
  }
}

async function analyzeStructure() {
  if (!editorContent.value) return

  loading.value = true
  error.value = null
  inversions.value = null
  validation.value = null

  try {
    stats.value = await analyzePrivilegeGradientFromContent(editorContent.value, fileFormat.value)
  } catch (err) {
    error.value = err.response?.data?.detail || err.message || 'Failed to analyze structure'
  } finally {
    loading.value = false
  }
}

async function detectInversions() {
  if (!editorContent.value) return

  loading.value = true
  error.value = null
  stats.value = null
  validation.value = null

  try {
    inversions.value = await analyzeInversionsFromContent(editorContent.value, fileFormat.value)
  } catch (err) {
    error.value = err.response?.data?.detail || err.message || 'Failed to detect inversions'
  } finally {
    loading.value = false
  }
}

async function validateGradient() {
  if (!editorContent.value) return

  loading.value = true
  error.value = null
  stats.value = null
  inversions.value = null

  try {
    validation.value = await validatePrivilegeGradientFromContent(editorContent.value, fileFormat.value)
  } catch (err) {
    error.value = err.response?.data?.detail || err.message || 'Failed to validate gradient'
  } finally {
    loading.value = false
  }
}

function downloadImage() {
  if (imageBlob.value) {
    downloadBlob(imageBlob.value, `privilege_gradient_${getTimestamp()}.${format.value}`)
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

/* Inversions Section */
.inversions-section {
  margin-top: 1.5rem;
  padding: 1rem;
  background: var(--bg-secondary);
  border-radius: 8px;
}

.inversions-section h3 {
  margin: 0 0 1rem;
}

.inversions-summary {
  display: flex;
  align-items: center;
  gap: 1rem;
  margin-bottom: 1rem;
  font-size: 0.9rem;
  color: var(--text-secondary);
}

.inversions-list {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.inversion-item {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  padding: 0.75rem;
  background: var(--bg-primary);
  border-radius: 4px;
  border-left: 3px solid transparent;
}

.inversion-item.severity-critical {
  border-left-color: #8b0000;
}

.inversion-item.severity-high {
  border-left-color: #e74c3c;
}

.inversion-item.severity-medium {
  border-left-color: #f39c12;
}

.inversion-item.severity-low {
  border-left-color: #27ae60;
}

.inv-flow {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-family: monospace;
  font-size: 0.9rem;
}

.inv-component {
  font-weight: 600;
  color: var(--text-primary);
}

.inv-arrow {
  color: var(--text-tertiary);
}

.inv-details {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  font-size: 0.8rem;
  color: var(--text-secondary);
}

.inv-zones {
  font-style: italic;
}

.inv-gap {
  font-weight: 500;
}

/* Severity Badges */
.severity-badge {
  display: inline-block;
  padding: 0.15rem 0.4rem;
  border-radius: 4px;
  font-size: 0.7rem;
  font-weight: 600;
  text-transform: uppercase;
  color: white;
}

.severity-badge.critical {
  background: #8b0000;
}

.severity-badge.high {
  background: #e74c3c;
}

.severity-badge.medium {
  background: #f39c12;
}

.severity-badge.low {
  background: #27ae60;
}

/* Severity critical stat value */
.severity-critical .stat-value {
  color: #e74c3c;
}

.severity-critical .stat-label {
  color: #e74c3c;
}

/* Zone Breakdown */
.zone-breakdown {
  margin-top: 1.5rem;
  padding-top: 1rem;
  border-top: 1px solid var(--border-color);
}

.zone-breakdown h4 {
  margin: 0 0 0.75rem;
  font-size: 0.9rem;
  color: var(--text-secondary);
}

.zone-bars {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.zone-bar-item {
  display: flex;
  align-items: center;
  gap: 0.75rem;
}

.zone-label {
  min-width: 120px;
  font-size: 0.85rem;
  font-weight: 500;
  color: var(--text-primary);
  text-align: right;
}

.zone-bar {
  height: 20px;
  background: var(--accent-color);
  border-radius: 4px;
  min-width: 4px;
  transition: width 0.3s ease;
}

.zone-count {
  min-width: 30px;
  font-size: 0.8rem;
  font-weight: 600;
  color: var(--text-secondary);
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
