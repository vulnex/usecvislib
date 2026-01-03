<!--
  VULNEX -Universal Security Visualization Library-

  File: AttackTreePanel.vue
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
      <h2>Attack Tree Visualization</h2>
      <p>Upload a configuration file (TOML, JSON, or YAML) defining your attack tree structure</p>
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
          title="Attack Tree Definition"
          validationType="attack-tree"
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
              You're in the Attack Trees panel.
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
              Upload images to use in your attack tree nodes. After uploading, copy the image_id
              and add <code>image_id = "..."</code> to the node in your configuration.
            </p>
            <ImageUploader
              ref="imageUploader"
              title="Upload Node Image"
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
          <button class="btn btn-secondary" @click="analyzeTree" :disabled="!canGenerate || loading">
            Analyze Structure
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
        <ZoomableImage v-else :src="imageUrl" alt="Attack Tree Visualization" />
      </div>

      <div v-if="stats" class="stats-section">
        <h3>Tree Statistics</h3>
        <div class="stats-grid">
          <div class="stat-item">
            <span class="stat-value">{{ stats.total_nodes }}</span>
            <span class="stat-label">Nodes</span>
          </div>
          <div class="stat-item">
            <span class="stat-value">{{ stats.total_edges }}</span>
            <span class="stat-label">Edges</span>
          </div>
          <div class="stat-item">
            <span class="stat-value">{{ stats.leaf_nodes }}</span>
            <span class="stat-label">Leaf Nodes</span>
          </div>
          <div class="stat-item">
            <span class="stat-value">{{ stats.internal_nodes }}</span>
            <span class="stat-label">Internal Nodes</span>
          </div>
          <div v-if="stats.nodes_with_cvss > 0" class="stat-item">
            <span class="stat-value">{{ stats.nodes_with_cvss }}</span>
            <span class="stat-label">Nodes w/ CVSS</span>
          </div>
          <div v-if="stats.average_cvss > 0" class="stat-item" :class="getCvssSeverityClass(stats.average_cvss)">
            <span class="stat-value">{{ stats.average_cvss.toFixed(1) }}</span>
            <span class="stat-label">Avg CVSS</span>
            <span class="cvss-badge" :class="getCvssSeverityClass(stats.average_cvss)">
              {{ getCvssSeverityLabel(stats.average_cvss) }}
            </span>
          </div>
          <div v-if="stats.critical_nodes > 0" class="stat-item cvss-critical">
            <span class="stat-value">{{ stats.critical_nodes }}</span>
            <span class="stat-label">Critical Nodes</span>
          </div>
          <div v-if="stats.high_risk_nodes > 0" class="stat-item cvss-high">
            <span class="stat-value">{{ stats.high_risk_nodes }}</span>
            <span class="stat-label">High Risk Nodes</span>
          </div>
        </div>
        <TemplateMetadata v-if="stats.metadata" :metadata="stats.metadata" />
      </div>

      <div v-if="validation" class="validation-section">
        <h3>Validation Result</h3>
        <div :class="['validation-result', validation.valid ? 'valid' : 'invalid']">
          <span class="validation-icon">{{ validation.valid ? '&#x2705;' : '&#x274C;' }}</span>
          {{ validation.valid ? 'Valid attack tree structure' : 'Validation errors found' }}
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
import ImageUploader from './ImageUploader.vue'
import {
  visualizeAttackTreeFromContent,
  analyzeAttackTreeFromContent,
  validateAttackTreeFromContent,
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
const editorContent = ref(null)  // null = no file, string = content
const fileName = ref('')
const fileFormat = ref('toml')  // Detected file format: toml, json, yaml
const format = ref('png')
const style = ref('at_default')
const loading = ref(false)
const error = ref(null)
const imageUrl = ref(null)
const imageBlob = ref(null)
const stats = ref(null)
const validation = ref(null)
const isDragging = ref(false)
const fileInput = ref(null)
const configEditor = ref(null)
const isConfigValid = ref(false)
const showImageUploader = ref(false)
const imageUploader = ref(null)
const selectedImageId = ref(null)
const templateMismatch = ref(null)  // { detectedTypeName, suggestedPanel }

// Computed
const canGenerate = computed(() => {
  return editorContent.value && editorContent.value.trim() && isConfigValid.value
})

// Methods
function formatStyleName(s) {
  return s.replace('at_', '').replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())
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
  const result = validateTemplateType(content, TemplateType.ATTACK_TREE)
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
  validation.value = null
}

function resetPanel() {
  editorContent.value = null
  fileName.value = ''
  fileFormat.value = 'toml'
  format.value = 'png'
  style.value = 'at_default'
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

  try {
    const blob = await visualizeAttackTreeFromContent(editorContent.value, format.value, style.value, fileFormat.value)
    imageBlob.value = blob
    imageUrl.value = createImageUrl(blob)
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
    stats.value = await analyzeAttackTreeFromContent(editorContent.value, fileFormat.value)
  } catch (err) {
    error.value = err.response?.data?.detail || err.message || 'Failed to analyze tree'
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
    validation.value = await validateAttackTreeFromContent(editorContent.value, fileFormat.value)
  } catch (err) {
    error.value = err.response?.data?.detail || err.message || 'Failed to validate tree'
  } finally {
    loading.value = false
  }
}

function downloadImage() {
  if (imageBlob.value) {
    downloadBlob(imageBlob.value, `attack_tree_${getTimestamp()}.${format.value}`)
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
