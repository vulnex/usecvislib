<!--
  VULNEX -Universal Security Visualization Library-

  File: ArchitecturePanel.vue
  License: Apache-2.0
  Copyright (c) 2025 VULNEX. All rights reserved.
-->
<template>
  <div class="panel">
    <div class="panel-header">
      <h2>Architecture Diagram Visualization</h2>
      <p>Upload a configuration file (TOML, JSON, or YAML) defining your architecture diagram</p>
    </div>

    <div class="panel-body">
      <div class="form-section">
        <!-- Diagram Type Toggle -->
        <div class="diagram-type-toggle">
          <button
            :class="['toggle-btn', { active: diagramType === 'component-diagram' }]"
            @click="switchDiagramType('component-diagram')"
          >
            Component Diagram
          </button>
          <button
            :class="['toggle-btn', { active: diagramType === 'dependency-graph' }]"
            @click="switchDiagramType('dependency-graph')"
          >
            Dependency Graph
          </button>
        </div>

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
          :title="diagramType === 'component-diagram' ? 'Component Diagram Definition' : 'Dependency Graph Definition'"
          :validationType="diagramType"
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
              You're in the Architecture panel.
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
              <option v-for="s in currentStyles" :key="s" :value="s">{{ formatStyleName(s) }}</option>
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
          <button class="btn btn-secondary" @click="validateDiagram" :disabled="!canGenerate || loading">
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
        <ZoomableImage v-else :src="imageUrl" alt="Architecture Diagram Visualization" />
      </div>

      <div v-if="stats" class="stats-section">
        <h3>{{ diagramType === 'component-diagram' ? 'Component Diagram' : 'Dependency Graph' }} Statistics</h3>
        <div class="stats-grid" v-if="diagramType === 'component-diagram'">
          <div class="stat-item">
            <span class="stat-value">{{ stats.total_layers }}</span>
            <span class="stat-label">Layers</span>
          </div>
          <div class="stat-item">
            <span class="stat-value">{{ stats.total_components }}</span>
            <span class="stat-label">Components</span>
          </div>
          <div class="stat-item">
            <span class="stat-value">{{ stats.total_connections }}</span>
            <span class="stat-label">Connections</span>
          </div>
        </div>
        <div class="stats-grid" v-else>
          <div class="stat-item">
            <span class="stat-value">{{ stats.total_modules }}</span>
            <span class="stat-label">Modules</span>
          </div>
          <div class="stat-item">
            <span class="stat-value">{{ stats.total_dependencies }}</span>
            <span class="stat-label">Dependencies</span>
          </div>
          <div class="stat-item" :class="{ 'severity-critical': stats.total_circular > 0 }">
            <span class="stat-value">{{ stats.total_circular }}</span>
            <span class="stat-label">Circular</span>
          </div>
          <div class="stat-item">
            <span class="stat-value">{{ stats.internal_count }}</span>
            <span class="stat-label">Internal</span>
          </div>
          <div class="stat-item">
            <span class="stat-value">{{ stats.external_count }}</span>
            <span class="stat-label">External</span>
          </div>
        </div>
        <TemplateMetadata v-if="stats.metadata" :metadata="stats.metadata" />

        <!-- Components per Layer breakdown (Component Diagram) -->
        <div v-if="diagramType === 'component-diagram' && stats.components_per_layer" class="layer-breakdown">
          <h4>Components per Layer</h4>
          <div class="layer-bars">
            <div v-for="(count, layer) in stats.components_per_layer" :key="layer" class="layer-bar-item">
              <span class="layer-label">{{ layer }}</span>
              <div class="layer-bar-track">
                <div class="layer-bar" :style="{ width: (count / maxLayerCount * 100) + '%' }"></div>
              </div>
              <span class="layer-count">{{ count }}</span>
            </div>
          </div>
        </div>

        <!-- Groups breakdown (Dependency Graph) -->
        <div v-if="diagramType === 'dependency-graph' && stats.groups && stats.groups.length" class="groups-breakdown">
          <h4>Module Groups</h4>
          <div class="groups-list">
            <span v-for="group in stats.groups" :key="group" class="group-badge">{{ group }}</span>
          </div>
        </div>
      </div>

      <div v-if="validation" class="validation-section">
        <h3>Validation Result</h3>
        <div :class="['validation-result', validation.valid ? 'valid' : 'invalid']">
          <span class="validation-icon">{{ validation.valid ? '&#x2705;' : '&#x274C;' }}</span>
          {{ validation.valid ? 'Valid diagram structure' : 'Validation errors found' }}
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
  visualizeComponentDiagramFromContent,
  visualizeDependencyGraphFromContent,
  analyzeComponentDiagramFromContent,
  analyzeDependencyGraphFromContent,
  validateComponentDiagramFromContent,
  validateDependencyGraphFromContent,
  createImageUrl,
  getTimestamp,
  downloadBlob,
  downloadTextFile
} from '../services/api.js'
import { validateTemplateType, TemplateType } from '../utils/template-detector.js'

const props = defineProps({
  formats: { type: Array, default: () => ['png'] }
})

// Watch for clean trigger from parent
const cleanTrigger = inject('cleanTrigger')
watch(cleanTrigger, () => {
  resetPanel()
})

// State
const diagramType = ref('component-diagram')
const editorContent = ref(null)
const fileName = ref('')
const fileFormat = ref('toml')
const format = ref('png')
const style = ref('cd_default')
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
const templateMismatch = ref(null)

// Style options per diagram type
const componentDiagramStyles = ['cd_default', 'cd_blueprint', 'cd_minimal', 'cd_dark']
const dependencyGraphStyles = ['dg_default', 'dg_dark', 'dg_minimal', 'dg_coupling']

// Computed
const currentStyles = computed(() => {
  return diagramType.value === 'component-diagram' ? componentDiagramStyles : dependencyGraphStyles
})

const canGenerate = computed(() => {
  return editorContent.value && editorContent.value.trim() && isConfigValid.value
})

const maxLayerCount = computed(() => {
  if (!stats.value || !stats.value.components_per_layer) return 1
  return Math.max(...Object.values(stats.value.components_per_layer), 1)
})

// Methods
function formatStyleName(s) {
  return s.replace(/^(cd_|dg_)/, '').replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())
}

function switchDiagramType(type) {
  if (diagramType.value === type) return
  diagramType.value = type
  style.value = type === 'component-diagram' ? 'cd_default' : 'dg_default'
  clearResults()
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
  const expectedType = diagramType.value === 'component-diagram'
    ? TemplateType.COMPONENT_DIAGRAM
    : TemplateType.DEPENDENCY_GRAPH
  const result = validateTemplateType(content, expectedType)
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
}

function resetPanel() {
  editorContent.value = null
  fileName.value = ''
  fileFormat.value = 'toml'
  format.value = 'png'
  style.value = diagramType.value === 'component-diagram' ? 'cd_default' : 'dg_default'
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
    const visualizeFn = diagramType.value === 'component-diagram'
      ? visualizeComponentDiagramFromContent
      : visualizeDependencyGraphFromContent
    const blob = await visualizeFn(editorContent.value, format.value, style.value, fileFormat.value)
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
  validation.value = null

  try {
    const analyzeFn = diagramType.value === 'component-diagram'
      ? analyzeComponentDiagramFromContent
      : analyzeDependencyGraphFromContent
    stats.value = await analyzeFn(editorContent.value, fileFormat.value)
  } catch (err) {
    error.value = err.response?.data?.detail || err.message || 'Failed to analyze structure'
  } finally {
    loading.value = false
  }
}

async function validateDiagram() {
  if (!editorContent.value) return

  loading.value = true
  error.value = null
  stats.value = null

  try {
    const validateFn = diagramType.value === 'component-diagram'
      ? validateComponentDiagramFromContent
      : validateDependencyGraphFromContent
    validation.value = await validateFn(editorContent.value, fileFormat.value)
  } catch (err) {
    error.value = err.response?.data?.detail || err.message || 'Failed to validate diagram'
  } finally {
    loading.value = false
  }
}

function downloadImage() {
  if (imageBlob.value) {
    const prefix = diagramType.value === 'component-diagram' ? 'component_diagram' : 'dependency_graph'
    downloadBlob(imageBlob.value, `${prefix}_${getTimestamp()}.${format.value}`)
  }
}

function saveTemplate() {
  if (!editorContent.value) return

  const name = fileName.value || 'template.toml'
  const lastDot = name.lastIndexOf('.')
  const baseName = lastDot > 0 ? name.substring(0, lastDot) : name
  const extension = lastDot > 0 ? name.substring(lastDot) : '.toml'

  const saveFilename = `${baseName}_${getTimestamp()}${extension}`
  downloadTextFile(editorContent.value, saveFilename)
}
</script>

<style scoped>
/* Diagram Type Toggle */
.diagram-type-toggle {
  display: flex;
  gap: 0;
  margin-bottom: 1rem;
  border: 1px solid var(--border-color);
  border-radius: 8px;
  overflow: hidden;
}

.toggle-btn {
  flex: 1;
  padding: 0.6rem 1rem;
  border: none;
  background: var(--bg-secondary);
  color: var(--text-secondary);
  font-size: 0.9rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s ease;
}

.toggle-btn:first-child {
  border-right: 1px solid var(--border-color);
}

.toggle-btn.active {
  background: var(--accent-color);
  color: white;
}

.toggle-btn:hover:not(.active) {
  background: var(--bg-tertiary, #e5e7eb);
}

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

/* Severity critical stat value */
.severity-critical .stat-value {
  color: #e74c3c;
}

.severity-critical .stat-label {
  color: #e74c3c;
}

/* Layer Breakdown */
.layer-breakdown {
  margin-top: 1.5rem;
  padding-top: 1rem;
  border-top: 1px solid var(--border-color);
}

.layer-breakdown h4 {
  margin: 0 0 0.75rem;
  font-size: 0.9rem;
  color: var(--text-secondary);
}

.layer-bars {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.layer-bar-item {
  display: flex;
  align-items: center;
  gap: 0.75rem;
}

.layer-label {
  min-width: 120px;
  font-size: 0.85rem;
  font-weight: 500;
  color: var(--text-primary);
  text-align: right;
}

.layer-bar-track {
  flex: 1;
}

.layer-bar {
  height: 20px;
  background: var(--accent-color);
  border-radius: 4px;
  min-width: 4px;
  transition: width 0.3s ease;
}

.layer-count {
  min-width: 30px;
  font-size: 0.8rem;
  font-weight: 600;
  color: var(--text-secondary);
}

/* Groups Breakdown */
.groups-breakdown {
  margin-top: 1.5rem;
  padding-top: 1rem;
  border-top: 1px solid var(--border-color);
}

.groups-breakdown h4 {
  margin: 0 0 0.75rem;
  font-size: 0.9rem;
  color: var(--text-secondary);
}

.groups-list {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
}

.group-badge {
  display: inline-block;
  padding: 0.25rem 0.75rem;
  background: var(--bg-secondary);
  border: 1px solid var(--border-color);
  border-radius: 16px;
  font-size: 0.8rem;
  font-weight: 500;
  color: var(--text-primary);
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
