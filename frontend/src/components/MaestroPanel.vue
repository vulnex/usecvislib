<!--
  VULNEX -Universal Security Visualization Library-

  File: MaestroPanel.vue
  License: Apache-2.0
  Copyright (c) 2026 VULNEX. All rights reserved.
-->
<template>
  <div class="panel">
    <div class="panel-header">
      <h2>MAESTRO Agentic Threat Model</h2>
      <p>
        Threat modeling for agentic AI systems across 7 layers: Foundation Models, Data Operations,
        Agent Frameworks, Infrastructure, Observability, Security, and Agent Ecosystem.
      </p>
    </div>

    <div class="panel-body">
      <div class="form-section">
        <!-- Upload area when no content -->
        <div
          v-if="!editorContent"
          class="upload-area"
          :class="{ dragover: isDragging }"
          @dragover.prevent="isDragging = true"
          @dragleave="isDragging = false"
          @drop.prevent="handleDrop"
        >
          <input
            type="file"
            ref="fileInput"
            accept=".tml,.toml,.json,.yaml,.yml"
            @change="handleFileSelect"
            class="file-input"
          />
          <div class="upload-content" @click="$refs.fileInput.click()">
            <span class="upload-icon">&#x1F4C1;</span>
            <p>Drop MAESTRO config here or click to browse</p>
            <span class="file-types">Supports: TOML, JSON, YAML</span>
          </div>
        </div>

        <!-- Config Editor after upload -->
        <ConfigEditor
          v-if="editorContent"
          v-model="editorContent"
          :fileName="fileName"
          title="MAESTRO Threat Model Definition"
          minHeight="280px"
          maxHeight="450px"
          @validation-change="handleValidationChange"
          @format-detected="handleFormatDetected"
          ref="configEditor"
        />

        <div v-if="editorContent" class="file-actions">
          <button class="btn btn-small btn-secondary" @click="changeFile">Change File</button>
          <button class="btn btn-small btn-secondary" @click="saveTemplate">Save Template</button>
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
              <option value="ma_default">Default</option>
            </select>
          </div>
        </div>

        <div class="actions">
          <button class="btn btn-primary" @click="generateVisualization" :disabled="!canGenerate || loading">
            <span v-if="loading" class="spinner"></span>
            {{ loading ? 'Generating...' : 'Generate Visualization' }}
          </button>
          <button class="btn btn-secondary" @click="analyzeModel" :disabled="!canGenerate || loading">
            Analyze
          </button>
          <button class="btn btn-secondary" @click="validateModel" :disabled="!canGenerate || loading">
            Validate
          </button>
          <button class="btn btn-secondary" @click="toggleCatalog">
            {{ catalogOpen ? 'Hide Catalog' : 'Browse Threat Catalog' }}
          </button>
        </div>
      </div>

      <div v-if="error" class="error-message">
        <span class="error-icon">&#x26A0;</span>
        {{ error }}
      </div>

      <!-- Visualization output -->
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
        <ZoomableImage v-else :src="imageUrl" alt="MAESTRO Threat Model" />
      </div>

      <!-- Stats -->
      <div v-if="stats" class="stats-section">
        <h3>MAESTRO Statistics</h3>
        <div class="stats-grid">
          <div class="stat-item">
            <span class="stat-value">{{ stats.total_agents }}</span>
            <span class="stat-label">Agents</span>
          </div>
          <div class="stat-item">
            <span class="stat-value">{{ stats.total_assets }}</span>
            <span class="stat-label">Assets</span>
          </div>
          <div class="stat-item">
            <span class="stat-value">{{ stats.total_threats }}</span>
            <span class="stat-label">Threats</span>
          </div>
          <div class="stat-item" :class="{ 'severity-critical': stats.unmitigated_threats > 0 }">
            <span class="stat-value">{{ stats.unmitigated_threats }}</span>
            <span class="stat-label">Unmitigated</span>
          </div>
          <div class="stat-item">
            <span class="stat-value">{{ stats.total_cross_layer_threats }}</span>
            <span class="stat-label">Cross-Layer</span>
          </div>
          <div class="stat-item">
            <span class="stat-value">{{ stats.total_mitigations }}</span>
            <span class="stat-label">Mitigations</span>
          </div>
        </div>

        <TemplateMetadata v-if="stats.metadata" :metadata="stats.metadata" />

        <div v-if="stats.patterns && stats.patterns.length" class="patterns-row">
          <h4>Architecture Patterns</h4>
          <div class="patterns-list">
            <span v-for="p in stats.patterns" :key="p" class="pattern-badge">{{ p }}</span>
          </div>
        </div>

        <div v-if="stats.threats_by_severity && Object.keys(stats.threats_by_severity).length" class="severity-breakdown">
          <h4>Threats by Severity</h4>
          <div class="severity-grid">
            <div
              v-for="(count, sev) in stats.threats_by_severity"
              :key="sev"
              :class="['severity-cell', `severity-${sev}`]"
            >
              <span class="severity-count">{{ count }}</span>
              <span class="severity-label">{{ sev }}</span>
            </div>
          </div>
        </div>

        <div v-if="stats.threats_by_layer && Object.keys(stats.threats_by_layer).length" class="layer-breakdown">
          <h4>Threats by Layer</h4>
          <div class="layer-bars">
            <div v-for="(count, layer) in stats.threats_by_layer" :key="layer" class="layer-bar-item">
              <span class="layer-label">{{ layer }}</span>
              <div class="layer-bar-track">
                <div class="layer-bar" :style="{ width: (count / maxLayerCount * 100) + '%' }"></div>
              </div>
              <span class="layer-count">{{ count }}</span>
            </div>
          </div>
        </div>

        <div v-if="stats.warnings && stats.warnings.length" class="warnings-section">
          <h4>Warnings</h4>
          <ul class="warning-list">
            <li v-for="(w, i) in stats.warnings" :key="i">{{ w }}</li>
          </ul>
        </div>
      </div>

      <!-- Validation result -->
      <div v-if="validation" class="validation-section">
        <h3>Validation Result</h3>
        <div :class="['validation-result', validation.valid ? 'valid' : 'invalid']">
          <span class="validation-icon">{{ validation.valid ? '&#x2705;' : '&#x274C;' }}</span>
          {{ validation.valid ? 'Valid MAESTRO model' : 'Validation errors found' }}
        </div>
        <ul v-if="validation.errors && validation.errors.length" class="error-list">
          <li v-for="(err, i) in validation.errors" :key="i">{{ err }}</li>
        </ul>
        <div v-if="validation.warnings && validation.warnings.length" class="warnings-section">
          <h4>Warnings</h4>
          <ul class="warning-list">
            <li v-for="(w, i) in validation.warnings" :key="i">{{ w }}</li>
          </ul>
        </div>
      </div>

      <!-- Catalog browser -->
      <div v-if="catalogOpen" class="catalog-section">
        <h3>MAESTRO Threat Catalog</h3>
        <div v-if="!catalog" class="catalog-loading">Loading catalog...</div>
        <div v-else>
          <p class="catalog-meta">
            Version <strong>{{ catalog.catalog_version }}</strong> &middot;
            {{ catalog.framework_version }} &middot;
            {{ catalog.threats.length }} threats &middot;
            {{ catalog.cross_layer_threats.length }} cross-layer &middot;
            {{ catalog.mitigations.length }} mitigations
          </p>
          <div class="catalog-layer-filter">
            <button
              v-for="layerKey in Object.keys(catalog.layers)"
              :key="layerKey"
              :class="['layer-chip', { active: activeCatalogLayer === layerKey }]"
              @click="activeCatalogLayer = layerKey"
            >
              L{{ catalog.layers[layerKey].id }} {{ catalog.layers[layerKey].name }}
            </button>
            <button
              :class="['layer-chip', { active: activeCatalogLayer === null }]"
              @click="activeCatalogLayer = null"
            >
              All
            </button>
          </div>
          <div class="catalog-threats">
            <div v-for="t in filteredCatalogThreats" :key="t.id" class="catalog-threat-card">
              <div class="threat-header">
                <span class="threat-id">{{ t.id }}</span>
                <span :class="['threat-severity', `severity-${t.default_severity}`]">
                  {{ t.default_severity }}
                </span>
              </div>
              <strong>{{ t.name }}</strong>
              <p class="threat-desc">{{ t.description }}</p>
              <div v-if="t.stride_category" class="threat-stride">
                STRIDE: {{ t.stride_category }} ({{ t.stride_mapping }})
              </div>
            </div>
          </div>
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
import {
  visualizeMaestroFromContent,
  analyzeMaestroFromContent,
  validateMaestroFromContent,
  getMaestroCatalog,
  createImageUrl,
  getTimestamp,
  downloadBlob,
  downloadTextFile
} from '../services/api.js'

defineProps({
  formats: { type: Array, default: () => ['png'] }
})

// Reset on global clean trigger
const cleanTrigger = inject('cleanTrigger')
watch(cleanTrigger, () => {
  resetPanel()
})

// State
const editorContent = ref(null)
const fileName = ref('')
const fileFormat = ref('toml')
const format = ref('png')
const style = ref('ma_default')
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
const catalogOpen = ref(false)
const catalog = ref(null)
const activeCatalogLayer = ref(null)

// Computed
const canGenerate = computed(() => {
  return editorContent.value && editorContent.value.trim() && isConfigValid.value
})

const maxLayerCount = computed(() => {
  if (!stats.value || !stats.value.threats_by_layer) return 1
  return Math.max(...Object.values(stats.value.threats_by_layer), 1)
})

const filteredCatalogThreats = computed(() => {
  if (!catalog.value) return []
  if (!activeCatalogLayer.value) return catalog.value.threats
  return catalog.value.threats.filter(t => t.layer === activeCatalogLayer.value)
})

// Methods
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
      resolve()
    }
    reader.onerror = () => {
      error.value = 'Failed to read file'
      reject(new Error('Failed to read file'))
    }
    reader.readAsText(file)
  })
}

function changeFile() {
  editorContent.value = null
  fileName.value = ''
  fileFormat.value = 'toml'
  isConfigValid.value = false
  clearResults()
  if (fileInput.value) fileInput.value.value = ''
}

function handleValidationChange({ errors }) {
  isConfigValid.value = !errors.some(e => e.severity === 'error')
}

function handleFormatDetected(fmt) {
  fileFormat.value = fmt
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
  style.value = 'ma_default'
  isConfigValid.value = false
  catalogOpen.value = false
  clearResults()
}

async function generateVisualization() {
  if (!editorContent.value) return
  loading.value = true
  error.value = null
  stats.value = null
  validation.value = null

  try {
    const blob = await visualizeMaestroFromContent(
      editorContent.value, format.value, style.value, fileFormat.value
    )
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
  validation.value = null

  try {
    stats.value = await analyzeMaestroFromContent(editorContent.value, fileFormat.value)
  } catch (err) {
    error.value = err.response?.data?.detail || err.message || 'Failed to analyze model'
  } finally {
    loading.value = false
  }
}

async function validateModel() {
  if (!editorContent.value) return
  loading.value = true
  error.value = null
  stats.value = null

  try {
    validation.value = await validateMaestroFromContent(editorContent.value, fileFormat.value)
  } catch (err) {
    error.value = err.response?.data?.detail || err.message || 'Failed to validate model'
  } finally {
    loading.value = false
  }
}

async function toggleCatalog() {
  catalogOpen.value = !catalogOpen.value
  if (catalogOpen.value && !catalog.value) {
    try {
      catalog.value = await getMaestroCatalog()
    } catch (err) {
      error.value = err.response?.data?.detail || err.message || 'Failed to load catalog'
      catalogOpen.value = false
    }
  }
}

function downloadImage() {
  if (imageBlob.value) {
    downloadBlob(imageBlob.value, `maestro_threat_model_${getTimestamp()}.${format.value}`)
  }
}

function saveTemplate() {
  if (!editorContent.value) return
  const name = fileName.value || 'maestro.toml'
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

.severity-critical .stat-value,
.severity-critical .stat-label {
  color: #e74c3c;
}

.patterns-row {
  margin-top: 1.5rem;
  padding-top: 1rem;
  border-top: 1px solid var(--border-color);
}

.patterns-row h4,
.severity-breakdown h4,
.layer-breakdown h4,
.warnings-section h4 {
  margin: 0 0 0.75rem;
  font-size: 0.9rem;
  color: var(--text-secondary);
}

.patterns-list {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
}

.pattern-badge {
  display: inline-block;
  padding: 0.25rem 0.75rem;
  background: var(--bg-secondary);
  border: 1px solid var(--border-color);
  border-radius: 16px;
  font-size: 0.8rem;
  font-weight: 500;
  color: var(--text-primary);
}

.severity-breakdown,
.layer-breakdown {
  margin-top: 1.5rem;
  padding-top: 1rem;
  border-top: 1px solid var(--border-color);
}

.severity-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
  gap: 0.5rem;
}

.severity-cell {
  display: flex;
  flex-direction: column;
  align-items: center;
  padding: 0.75rem;
  border-radius: 8px;
  border: 1px solid var(--border-color);
}

.severity-cell .severity-count {
  font-size: 1.5rem;
  font-weight: 600;
}

.severity-cell .severity-label {
  font-size: 0.8rem;
  text-transform: capitalize;
  color: var(--text-secondary);
}

.severity-low { background: rgba(76, 175, 80, 0.1); border-color: #4caf50; }
.severity-medium { background: rgba(255, 179, 0, 0.1); border-color: #ffb300; }
.severity-high { background: rgba(251, 140, 0, 0.1); border-color: #fb8c00; }
.severity-critical { background: rgba(229, 57, 53, 0.1); border-color: #e53935; }

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
  min-width: 160px;
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

.warnings-section {
  margin-top: 1.5rem;
  padding-top: 1rem;
  border-top: 1px solid var(--border-color);
}

.warning-list {
  margin: 0;
  padding-left: 1.25rem;
  font-size: 0.9rem;
  color: #92400e;
}

.warning-list li {
  margin-bottom: 0.25rem;
}

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

/* Catalog browser */
.catalog-section {
  margin-top: 2rem;
  padding-top: 1rem;
  border-top: 1px solid var(--border-color);
}

.catalog-loading {
  padding: 1rem;
  text-align: center;
  color: var(--text-secondary);
}

.catalog-meta {
  font-size: 0.85rem;
  color: var(--text-secondary);
}

.catalog-layer-filter {
  display: flex;
  flex-wrap: wrap;
  gap: 0.4rem;
  margin: 0.75rem 0 1rem;
}

.layer-chip {
  padding: 0.3rem 0.7rem;
  border-radius: 16px;
  border: 1px solid var(--border-color);
  background: var(--bg-secondary);
  color: var(--text-primary);
  font-size: 0.8rem;
  cursor: pointer;
}

.layer-chip.active {
  background: var(--accent-color);
  color: white;
  border-color: var(--accent-color);
}

.catalog-threats {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 0.75rem;
  max-height: 480px;
  overflow-y: auto;
}

.catalog-threat-card {
  padding: 0.75rem;
  border: 1px solid var(--border-color);
  border-radius: 8px;
  background: var(--bg-secondary);
  font-size: 0.85rem;
}

.threat-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 0.4rem;
}

.threat-id {
  font-family: monospace;
  font-size: 0.75rem;
  color: var(--text-secondary);
}

.threat-severity {
  padding: 0.1rem 0.5rem;
  border-radius: 12px;
  font-size: 0.7rem;
  text-transform: uppercase;
  font-weight: 600;
  color: white;
}

.threat-severity.severity-low { background: #4caf50; }
.threat-severity.severity-medium { background: #ffb300; }
.threat-severity.severity-high { background: #fb8c00; }
.threat-severity.severity-critical { background: #e53935; }

.threat-desc {
  margin: 0.4rem 0;
  font-size: 0.8rem;
  color: var(--text-secondary);
  line-height: 1.4;
}

.threat-stride {
  font-size: 0.75rem;
  color: var(--text-tertiary);
  font-style: italic;
}
</style>
