<!--
  VULNEX -Universal Security Visualization Library-

  File: CustomDiagramPanel.vue
  Author: Claude Code
  Created: 2025-12-29
  Last Modified: 2026-01-01
  Version: 0.3.1
  License: Apache-2.0
  Copyright (c) 2025 VULNEX. All rights reserved.
  https://www.vulnex.com
-->
<template>
  <div class="panel custom-diagram-panel">
    <div class="panel-header">
      <h2>Custom Diagrams</h2>
      <p>Create flexible, schema-driven visualizations with custom node types and styles</p>
    </div>

    <div class="panel-body">
      <!-- Tab Navigation -->
      <div class="sub-tabs">
        <button
          :class="['sub-tab', { active: activeSubTab === 'editor' }]"
          @click="activeSubTab = 'editor'"
        >
          Editor
        </button>
        <button
          :class="['sub-tab', { active: activeSubTab === 'templates' }]"
          @click="activeSubTab = 'templates'"
        >
          Templates
        </button>
        <button
          :class="['sub-tab', { active: activeSubTab === 'shapes' }]"
          @click="activeSubTab = 'shapes'"
        >
          Shape Gallery
        </button>
      </div>

      <!-- Editor Tab -->
      <div v-if="activeSubTab === 'editor'" class="form-section">
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
            <span class="upload-icon">&#x1F3A8;</span>
            <p>Drop config file here or click to browse</p>
            <span class="file-types">Supports: TOML, JSON, YAML</span>
          </div>
        </div>

        <!-- Config Editor - shown after file upload -->
        <ConfigEditor
          v-if="editorContent"
          v-model="editorContent"
          :fileName="fileName"
          title="Custom Diagram Definition"
          validationType="custom-diagram"
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
          <button class="btn btn-small btn-secondary" @click="clearAll">
            Clear
          </button>
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
              Upload images to use in diagram nodes. Copy the image_id and add
              <code>image_id = "..."</code> to nodes in your configuration.
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
            <select v-model="selectedStyle">
              <option v-for="s in availableStyles" :key="s.value" :value="s.value">
                {{ s.label }}
              </option>
            </select>
          </div>
        </div>

        <div class="actions">
          <button class="btn btn-primary" @click="generateVisualization" :disabled="!canGenerate || loading">
            <span v-if="loading" class="spinner"></span>
            {{ loading ? 'Generating...' : 'Generate Visualization' }}
          </button>
          <button class="btn btn-secondary" @click="validateDiagram" :disabled="!canGenerate || loading">
            Validate
          </button>
          <button class="btn btn-secondary" @click="getDiagramStats" :disabled="!canGenerate || loading">
            Statistics
          </button>
        </div>
      </div>

      <!-- Templates Tab -->
      <div v-if="activeSubTab === 'templates'" class="templates-section">
        <div class="templates-header">
          <div class="option-group">
            <label>Category</label>
            <select v-model="selectedTemplateCategory" @change="loadTemplates">
              <option value="">All Categories</option>
              <option v-for="cat in templateCategories" :key="cat" :value="cat">
                {{ formatCategoryName(cat) }}
              </option>
            </select>
          </div>
        </div>

        <div v-if="loadingTemplates" class="loading-spinner">
          <span class="spinner"></span> Loading templates...
        </div>

        <div v-else class="templates-grid">
          <div
            v-for="template in templates"
            :key="template.id"
            class="template-card"
            @click="selectTemplate(template)"
          >
            <div class="template-icon" v-html="getCategoryIcon(template.category)"></div>
            <div class="template-info">
              <h4>{{ template.name }}</h4>
              <span class="template-category">{{ formatCategoryName(template.category) }}</span>
              <div class="template-meta">
                <span>{{ template.node_count }} nodes</span>
                <span>{{ template.edge_count }} edges</span>
              </div>
            </div>
          </div>
        </div>

        <div v-if="!loadingTemplates && templates.length === 0" class="empty-state">
          <p>No templates found</p>
        </div>
      </div>

      <!-- Shape Gallery Tab -->
      <div v-if="activeSubTab === 'shapes'" class="shapes-section">
        <div class="shapes-header">
          <div class="option-group">
            <label>Category</label>
            <select v-model="selectedShapeCategory" @change="loadShapes">
              <option value="">All Categories</option>
              <option v-for="cat in shapeCategories" :key="cat" :value="cat">
                {{ formatCategoryName(cat) }}
              </option>
            </select>
          </div>
        </div>

        <div v-if="loadingShapes" class="loading-spinner">
          <span class="spinner"></span> Loading shapes...
        </div>

        <div v-else class="shapes-grid">
          <div
            v-for="shape in shapes"
            :key="shape.id"
            class="shape-card"
            :style="getShapeStyle(shape)"
            @click="copyShapeId(shape)"
          >
            <div class="shape-preview" :style="getShapePreviewStyle(shape)" v-html="getShapeIcon(shape)">
            </div>
            <div class="shape-info">
              <h5>{{ shape.name }}</h5>
              <span class="shape-id">{{ shape.id }}</span>
            </div>
          </div>
        </div>

        <div v-if="!loadingShapes && shapes.length === 0" class="empty-state">
          <p>No shapes found</p>
        </div>
      </div>

      <!-- Error Display -->
      <div v-if="error" class="error-message">
        <span class="error-icon">&#x26A0;</span>
        {{ error }}
      </div>

      <!-- Validation Results -->
      <div v-if="validationResult" class="validation-section">
        <h3>Validation Result</h3>
        <div :class="['validation-status', validationResult.valid ? 'valid' : 'invalid']">
          {{ validationResult.valid ? 'Valid' : 'Invalid' }}
        </div>
        <div v-if="validationResult.errors && validationResult.errors.length > 0" class="validation-errors">
          <h4>Errors</h4>
          <ul>
            <li v-for="(err, idx) in validationResult.errors" :key="idx" class="error-item">
              {{ err }}
            </li>
          </ul>
        </div>
        <div v-if="validationResult.warnings && validationResult.warnings.length > 0" class="validation-warnings">
          <h4>Warnings</h4>
          <ul>
            <li v-for="(warn, idx) in validationResult.warnings" :key="idx" class="warning-item">
              {{ warn }}
            </li>
          </ul>
        </div>
        <div class="validation-stats">
          <span>Nodes: {{ validationResult.node_count }}</span>
          <span>Edges: {{ validationResult.edge_count }}</span>
        </div>
      </div>

      <!-- Result Section -->
      <div v-if="imageUrl || imageBlob" class="result-section">
        <div class="result-header">
          <h3>Generated Visualization</h3>
          <button class="btn btn-small" @click="downloadImage">
            Download
          </button>
        </div>
        <div v-if="format === 'pdf'" class="pdf-notice">
          <div class="pdf-icon">&#x1F4C4;</div>
          <p>PDF generated successfully</p>
          <p class="pdf-hint">Click "Download" to save the PDF file</p>
        </div>
        <ZoomableImage v-else :src="imageUrl" alt="Custom Diagram Visualization" />
      </div>

      <!-- Statistics Section -->
      <div v-if="stats" class="stats-section">
        <h3>Diagram Statistics</h3>
        <div class="stats-grid">
          <div class="stat-item">
            <span class="stat-value">{{ stats.total_nodes }}</span>
            <span class="stat-label">Nodes</span>
          </div>
          <div class="stat-item">
            <span class="stat-value">{{ stats.total_edges }}</span>
            <span class="stat-label">Edges</span>
          </div>
          <div v-if="stats.total_clusters > 0" class="stat-item">
            <span class="stat-value">{{ stats.total_clusters }}</span>
            <span class="stat-label">Clusters</span>
          </div>
        </div>

        <div v-if="stats.node_types && Object.keys(stats.node_types).length > 0" class="type-breakdown">
          <h4>Node Types</h4>
          <div class="type-list">
            <span v-for="(count, type) in stats.node_types" :key="type" class="type-tag">
              {{ type }}: {{ count }}
            </span>
          </div>
        </div>

        <div v-if="stats.edge_types && Object.keys(stats.edge_types).length > 0" class="type-breakdown">
          <h4>Edge Types</h4>
          <div class="type-list">
            <span v-for="(count, type) in stats.edge_types" :key="type" class="type-tag">
              {{ type }}: {{ count }}
            </span>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, watch, inject } from 'vue'
import {
  getCustomDiagramShapes,
  getCustomDiagramTemplates,
  getCustomDiagramTemplate,
  getCustomDiagramStyles,
  visualizeCustomDiagramFromContent,
  validateCustomDiagramFromContent,
  getCustomDiagramStatsFromContent,
  visualizeCustomDiagramFromTemplate,
  createImageUrl,
  downloadBlob,
  downloadTextFile,
  getTimestamp
} from '../services/api.js'
import ConfigEditor from './ConfigEditor.vue'
import ZoomableImage from './ZoomableImage.vue'
import ImageUploader from './ImageUploader.vue'

// Props
const props = defineProps({
  apiConnected: Boolean,
  apiVersion: String,
  modules: Object,
  formats: {
    type: Array,
    default: () => ['png', 'svg', 'pdf']
  }
})

// Clean trigger from parent
const cleanTrigger = inject('cleanTrigger', ref(0))

// Watch for clean trigger changes
watch(cleanTrigger, () => {
  resetState()
})

// State
const activeSubTab = ref('editor')
const editorContent = ref('')
const fileName = ref('')
const configFormat = ref('toml')
const format = ref('png')
const selectedStyle = ref('cd_default')
const loading = ref(false)
const error = ref(null)
const isDragging = ref(false)
const showImageUploader = ref(false)
const imageUploader = ref(null)
const selectedImageId = ref(null)

// Result state
const imageUrl = ref(null)
const imageBlob = ref(null)
const stats = ref(null)
const validationResult = ref(null)

// Templates state
const templates = ref([])
const templateCategories = ref([])
const selectedTemplateCategory = ref('')
const loadingTemplates = ref(false)

// Shapes state
const shapes = ref([])
const shapeCategories = ref([])
const selectedShapeCategory = ref('')
const loadingShapes = ref(false)

// Styles state
const availableStyles = ref([
  { value: 'cd_default', label: 'Default' },
  { value: 'cd_dark', label: 'Dark Mode' },
  { value: 'cd_blueprint', label: 'Blueprint' },
  { value: 'cd_minimal', label: 'Minimal' },
  { value: 'cd_neon', label: 'Neon' },
  { value: 'cd_corporate', label: 'Corporate' }
])

// Computed
const canGenerate = computed(() => {
  return editorContent.value && editorContent.value.trim().length > 0
})

// Methods
function resetState() {
  editorContent.value = ''
  fileName.value = ''
  error.value = null
  imageUrl.value = null
  imageBlob.value = null
  stats.value = null
  validationResult.value = null
  showImageUploader.value = false
  selectedImageId.value = null
}

function handleImageSelected(image) {
  selectedImageId.value = image?.image_id || null
}

function handleFileSelect(event) {
  const file = event.target.files[0]
  if (file) {
    loadFile(file)
  }
}

function handleDrop(event) {
  isDragging.value = false
  const file = event.dataTransfer.files[0]
  if (file) {
    loadFile(file)
  }
}

function loadFile(file) {
  fileName.value = file.name
  const reader = new FileReader()
  reader.onload = (e) => {
    editorContent.value = e.target.result
    detectFormat(file.name)
  }
  reader.readAsText(file)
}

function detectFormat(name) {
  if (name.endsWith('.json')) {
    configFormat.value = 'json'
  } else if (name.endsWith('.yaml') || name.endsWith('.yml')) {
    configFormat.value = 'yaml'
  } else {
    configFormat.value = 'toml'
  }
}

function handleFormatDetected(detectedFormat) {
  configFormat.value = detectedFormat
}

function handleValidationChange(isValid) {
  // Optional: handle validation state changes
}

function changeFile() {
  editorContent.value = ''
  fileName.value = ''
  error.value = null
  validationResult.value = null
}

function clearAll() {
  resetState()
}

async function generateVisualization() {
  if (!canGenerate.value) return

  loading.value = true
  error.value = null
  imageUrl.value = null
  imageBlob.value = null

  try {
    const blob = await visualizeCustomDiagramFromContent(
      editorContent.value,
      format.value,
      selectedStyle.value,
      configFormat.value
    )

    imageBlob.value = blob
    if (format.value !== 'pdf') {
      imageUrl.value = createImageUrl(blob)
    }
  } catch (err) {
    console.error('Visualization error:', err)
    error.value = err.response?.data?.detail || err.message || 'Failed to generate visualization'
  } finally {
    loading.value = false
  }
}

async function validateDiagram() {
  if (!canGenerate.value) return

  loading.value = true
  error.value = null
  validationResult.value = null

  try {
    validationResult.value = await validateCustomDiagramFromContent(
      editorContent.value,
      configFormat.value
    )
  } catch (err) {
    console.error('Validation error:', err)
    error.value = err.response?.data?.detail || err.message || 'Failed to validate diagram'
  } finally {
    loading.value = false
  }
}

async function getDiagramStats() {
  if (!canGenerate.value) return

  loading.value = true
  error.value = null
  stats.value = null

  try {
    stats.value = await getCustomDiagramStatsFromContent(
      editorContent.value,
      configFormat.value
    )
  } catch (err) {
    console.error('Stats error:', err)
    error.value = err.response?.data?.detail || err.message || 'Failed to get statistics'
  } finally {
    loading.value = false
  }
}

function downloadImage() {
  if (!imageBlob.value) return

  const timestamp = getTimestamp()
  const ext = format.value
  const baseName = fileName.value ? fileName.value.replace(/\.[^.]+$/, '') : 'custom_diagram'
  downloadBlob(imageBlob.value, `${baseName}_${timestamp}.${ext}`)
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

// Template methods
async function loadTemplates() {
  loadingTemplates.value = true
  try {
    const data = await getCustomDiagramTemplates(selectedTemplateCategory.value || null)
    templates.value = data.templates || []
    if (!templateCategories.value.length) {
      templateCategories.value = data.categories || []
    }
  } catch (err) {
    console.error('Failed to load templates:', err)
    error.value = 'Failed to load templates'
  } finally {
    loadingTemplates.value = false
  }
}

async function selectTemplate(template) {
  try {
    const data = await getCustomDiagramTemplate(template.id)
    editorContent.value = data.content
    fileName.value = template.filename
    detectFormat(template.filename)
    activeSubTab.value = 'editor'
  } catch (err) {
    console.error('Failed to load template:', err)
    error.value = 'Failed to load template content'
  }
}

// Shape methods
async function loadShapes() {
  loadingShapes.value = true
  try {
    const data = await getCustomDiagramShapes(selectedShapeCategory.value || null)
    shapes.value = data.shapes || []
    if (!shapeCategories.value.length) {
      shapeCategories.value = data.categories || []
    }
  } catch (err) {
    console.error('Failed to load shapes:', err)
    error.value = 'Failed to load shapes'
  } finally {
    loadingShapes.value = false
  }
}

function copyShapeId(shape) {
  navigator.clipboard.writeText(shape.id)
  // Could add a toast notification here
}

// Utility methods
function formatCategoryName(category) {
  if (!category) return ''
  return category.charAt(0).toUpperCase() + category.slice(1).replace(/_/g, ' ')
}

function getCategoryIcon(category) {
  const icons = {
    general: '&#x1F4CA;',
    software: '&#x1F4BB;',
    network: '&#x1F310;',
    security: '&#x1F512;',
    business: '&#x1F4BC;'
  }
  return icons[category] || '&#x1F4C4;'
}

function getShapeIcon(shape) {
  const shapeIcons = {
    box: '&#x25A1;',
    ellipse: '&#x25EF;',
    diamond: '&#x25C7;',
    circle: '&#x25CB;',
    cylinder: '&#x2395;',
    hexagon: '&#x2B21;',
    triangle: '&#x25B3;',
    star: '&#x2605;'
  }
  return shapeIcons[shape.shape] || '&#x25A1;'
}

function getShapeStyle(shape) {
  return {
    borderColor: shape.bordercolor || '#ccc',
  }
}

function getShapePreviewStyle(shape) {
  return {
    backgroundColor: shape.fillcolor || '#f5f5f5',
    color: shape.fontcolor || '#333'
  }
}

// Load initial data
async function loadStyles() {
  try {
    const data = await getCustomDiagramStyles()
    availableStyles.value = data.styles.map(s => ({
      value: s,
      label: data.descriptions[s] || formatCategoryName(s.replace('cd_', ''))
    }))
  } catch (err) {
    console.error('Failed to load styles:', err)
  }
}

// Initialize
onMounted(async () => {
  await Promise.all([
    loadTemplates(),
    loadShapes(),
    loadStyles()
  ])
})
</script>

<style scoped>
.custom-diagram-panel {
  height: 100%;
  overflow-y: auto;
}

.sub-tabs {
  display: flex;
  gap: 4px;
  margin-bottom: 16px;
  padding: 4px;
  background: var(--bg-tertiary);
  border-radius: 8px;
}

.sub-tab {
  flex: 1;
  padding: 8px 16px;
  border: none;
  background: transparent;
  color: var(--text-secondary);
  font-size: 14px;
  font-weight: 500;
  cursor: pointer;
  border-radius: 6px;
  transition: all 0.2s ease;
}

.sub-tab:hover {
  background: rgba(255, 255, 255, 0.05);
  color: var(--text-primary);
}

.sub-tab.active {
  background: var(--primary);
  color: white;
}

/* Templates Grid */
.templates-section,
.shapes-section {
  padding: 0;
}

.templates-header,
.shapes-header {
  margin-bottom: 16px;
}

.templates-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
  gap: 12px;
}

.template-card {
  padding: 16px;
  background: var(--bg-tertiary);
  border: 1px solid var(--border-color);
  border-radius: 8px;
  cursor: pointer;
  transition: all 0.2s ease;
}

.template-card:hover {
  border-color: var(--primary);
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
}

.template-icon {
  font-size: 24px;
  margin-bottom: 8px;
}

.template-info h4 {
  margin: 0 0 4px 0;
  font-size: 14px;
  font-weight: 600;
  color: var(--text-primary);
}

.template-category {
  display: block;
  font-size: 12px;
  color: var(--text-secondary);
  margin-bottom: 8px;
}

.template-meta {
  display: flex;
  gap: 8px;
  font-size: 11px;
  color: var(--text-muted);
}

/* Shapes Grid */
.shapes-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(120px, 1fr));
  gap: 8px;
}

.shape-card {
  padding: 12px;
  background: var(--bg-tertiary);
  border: 1px solid var(--border-color);
  border-radius: 8px;
  cursor: pointer;
  text-align: center;
  transition: all 0.2s ease;
}

.shape-card:hover {
  border-color: var(--primary);
  transform: scale(1.02);
}

.shape-preview {
  width: 48px;
  height: 48px;
  margin: 0 auto 8px;
  border-radius: 4px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 24px;
}

.shape-info h5 {
  margin: 0 0 4px 0;
  font-size: 12px;
  font-weight: 600;
  color: var(--text-primary);
}

.shape-id {
  font-size: 10px;
  color: var(--text-muted);
  font-family: monospace;
}

/* Validation Section */
.validation-section {
  margin-top: 16px;
  padding: 16px;
  background: var(--bg-tertiary);
  border-radius: 8px;
}

.validation-status {
  display: inline-block;
  padding: 4px 12px;
  border-radius: 4px;
  font-weight: 600;
  font-size: 14px;
  margin-bottom: 12px;
}

.validation-status.valid {
  background: rgba(16, 185, 129, 0.2);
  color: var(--success);
}

.validation-status.invalid {
  background: rgba(239, 68, 68, 0.2);
  color: var(--danger);
}

.validation-errors,
.validation-warnings {
  margin-top: 12px;
}

.validation-errors h4,
.validation-warnings h4 {
  margin: 0 0 8px 0;
  font-size: 13px;
  font-weight: 600;
  color: var(--text-primary);
}

.validation-errors ul,
.validation-warnings ul {
  margin: 0;
  padding-left: 20px;
}

.error-item {
  color: var(--danger);
  font-size: 13px;
  margin-bottom: 4px;
}

.warning-item {
  color: var(--warning);
  font-size: 13px;
  margin-bottom: 4px;
}

.validation-stats {
  margin-top: 12px;
  display: flex;
  gap: 16px;
  font-size: 13px;
  color: var(--text-secondary);
}

/* Stats Section */
.stats-section {
  margin-top: 16px;
  padding: 16px;
  background: var(--bg-tertiary);
  border-radius: 8px;
}

.stats-section h3 {
  margin: 0 0 16px 0;
  font-size: 16px;
  color: var(--text-primary);
}

.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(80px, 1fr));
  gap: 12px;
  margin-bottom: 16px;
}

.stat-item {
  text-align: center;
  padding: 12px;
  background: var(--bg-secondary);
  border-radius: 8px;
  border: 1px solid var(--border-color);
}

.stat-value {
  display: block;
  font-size: 24px;
  font-weight: 700;
  color: var(--primary);
}

.stat-label {
  display: block;
  font-size: 11px;
  color: var(--text-secondary);
  margin-top: 4px;
}

.type-breakdown {
  margin-top: 12px;
}

.type-breakdown h4 {
  margin: 0 0 8px 0;
  font-size: 13px;
  font-weight: 600;
  color: var(--text-primary);
}

.type-list {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.type-tag {
  display: inline-block;
  padding: 4px 8px;
  background: rgba(99, 102, 241, 0.2);
  color: var(--primary);
  border-radius: 4px;
  font-size: 12px;
}

/* Loading & Empty States */
.loading-spinner {
  text-align: center;
  padding: 24px;
  color: var(--text-secondary);
}

.empty-state {
  text-align: center;
  padding: 32px;
  color: var(--text-secondary);
}

/* File types hint */
.file-types {
  font-size: 12px;
  color: var(--text-muted);
}

.file-actions {
  display: flex;
  gap: 8px;
}

.options-row {
  display: flex;
  gap: 16px;
  flex-wrap: wrap;
}

.option-group {
  flex: 1;
  min-width: 120px;
}

.option-group label {
  display: block;
  font-size: 13px;
  font-weight: 500;
  margin-bottom: 6px;
  color: var(--text-primary);
}

.option-group select {
  width: 100%;
  padding: 8px 12px;
  border: 1px solid var(--border-color);
  border-radius: 6px;
  font-size: 14px;
  background: var(--bg-tertiary);
  color: var(--text-primary);
}

.option-group select:focus {
  outline: none;
  border-color: var(--primary);
}

.spinner {
  display: inline-block;
  width: 16px;
  height: 16px;
  border: 2px solid currentColor;
  border-right-color: transparent;
  border-radius: 50%;
  animation: spin 0.75s linear infinite;
  margin-right: 8px;
}

@keyframes spin {
  to { transform: rotate(360deg); }
}

.error-message {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 12px 16px;
  background: rgba(239, 68, 68, 0.15);
  border: 1px solid rgba(239, 68, 68, 0.3);
  border-radius: 6px;
  color: var(--danger);
}

.error-icon {
  font-size: 18px;
}

.result-section {
  margin-top: 16px;
}

.result-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 12px;
}

.result-header h3 {
  margin: 0;
  font-size: 16px;
  color: var(--text-primary);
}

.pdf-notice {
  text-align: center;
  padding: 32px;
  background: var(--bg-tertiary);
  border-radius: 8px;
}

.pdf-icon {
  font-size: 48px;
  margin-bottom: 12px;
}

.pdf-hint {
  font-size: 13px;
  color: var(--text-secondary);
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
