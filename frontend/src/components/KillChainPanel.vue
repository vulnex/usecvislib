<!--
  VULNEX -Universal Security Visualization Library-

  File: KillChainPanel.vue
  Author: Simon Roses Femerling
  Created: 2026-08-09
  Last Modified: 2026-08-09
  Version: 0.4.1
  License: Apache-2.0
  Copyright (c) 2026 VULNEX. All rights reserved.
  https://www.vulnex.com
-->
<template>
  <div class="panel">
    <div class="panel-header">
      <h2>Kill Chain / MITRE ATT&amp;CK</h2>
      <p>Upload a configuration file (TOML, JSON, or YAML) mapping techniques to kill-chain phases or ATT&amp;CK tactics</p>
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
          title="Kill Chain Definition"
          validationType="kill-chain"
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
              You're in the Kill Chain panel.
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
            <label>Engine</label>
            <select v-model="renderEngine">
              <option value="graphviz">Graphviz</option>
              <option value="svg">SVG (modern)</option>
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
          <button class="btn btn-secondary" @click="analyzeChain" :disabled="!canGenerate || loading">
            Analyze Coverage
          </button>
          <button class="btn btn-secondary" @click="validateChain" :disabled="!canGenerate || loading">
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
        <ZoomableImage v-else :src="imageUrl" alt="Kill Chain Visualization" />
      </div>

      <div v-if="stats" class="stats-section">
        <h3>Coverage Statistics</h3>
        <div class="stats-grid">
          <div class="stat-item">
            <span class="stat-value">{{ stats.total_techniques }}</span>
            <span class="stat-label">Techniques</span>
          </div>
          <div class="stat-item">
            <span class="stat-value">{{ formatFramework(stats.framework) }}</span>
            <span class="stat-label">Framework</span>
          </div>
          <div class="stat-item">
            <span class="stat-value">{{ stats.active_phases.length }}</span>
            <span class="stat-label">Active Phases</span>
          </div>
          <div class="stat-item">
            <span class="stat-value">{{ stats.total_incidents }}</span>
            <span class="stat-label">Incidents</span>
          </div>
          <div class="stat-item" :class="coverageClass(stats.detection_coverage)">
            <span class="stat-value">{{ formatPct(stats.detection_coverage) }}</span>
            <span class="stat-label">Detection</span>
            <span class="coverage-sub">{{ stats.detected_techniques }}/{{ stats.total_techniques }}</span>
          </div>
          <div class="stat-item" :class="coverageClass(stats.mitigation_coverage)">
            <span class="stat-value">{{ formatPct(stats.mitigation_coverage) }}</span>
            <span class="stat-label">Mitigation</span>
            <span class="coverage-sub">{{ stats.mitigated_techniques }}/{{ stats.total_techniques }}</span>
          </div>
        </div>

        <div v-if="phaseBreakdown.length" class="phase-breakdown">
          <h4>Techniques per Phase</h4>
          <div class="phase-bars">
            <div v-for="p in phaseBreakdown" :key="p.name" class="phase-bar-row">
              <span class="phase-name">{{ p.name }}</span>
              <div class="phase-bar-track">
                <div class="phase-bar-fill" :style="{ width: p.pct + '%' }"></div>
              </div>
              <span class="phase-count">{{ p.count }}</span>
            </div>
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
          {{ validation.valid ? 'Valid kill chain structure' : 'Validation issues found' }}
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
  visualizeKillChainFromContent,
  analyzeKillChainFromContent,
  validateKillChainFromContent,
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
const style = ref('kc_default')
const renderEngine = ref('graphviz')
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

const SVG_ENGINE_STYLES = ['sv_default', 'sv_dark', 'sv_neon', 'sv_corporate', 'sv_minimal']
const GRAPHVIZ_STYLES = ['kc_default', 'kc_light', 'kc_coverage']

// SVG-engine presets (sv_*) and Graphviz presets (kc_*) are not interchangeable
const availableStyles = computed(() => {
  if (renderEngine.value === 'svg') return SVG_ENGINE_STYLES
  const fromProps = (props.styles || []).filter((s) => s.startsWith('kc_'))
  return fromProps.length ? fromProps : GRAPHVIZ_STYLES
})

watch(renderEngine, (engine) => {
  style.value = engine === 'svg' ? 'sv_default' : 'kc_default'
})

const canGenerate = computed(() => editorContent.value && editorContent.value.trim() && isConfigValid.value)

const phaseBreakdown = computed(() => {
  if (!stats.value || !stats.value.techniques_per_phase) return []
  const entries = Object.entries(stats.value.techniques_per_phase).filter(([, c]) => c > 0)
  const max = Math.max(1, ...entries.map(([, c]) => c))
  return entries.map(([name, count]) => ({ name, count, pct: Math.round((count / max) * 100) }))
})

function formatStyleName(s) {
  return s.replace(/^(kc_|sv_)/, '').replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase())
}

function formatFramework(f) {
  if (f === 'attack') return 'ATT&CK'
  if (f === 'kill_chain') return 'Kill Chain'
  return 'Custom'
}

function formatPct(v) {
  return `${Math.round((v || 0) * 100)}%`
}

function coverageClass(v) {
  if (v >= 0.75) return 'cov-good'
  if (v >= 0.4) return 'cov-partial'
  return 'cov-gap'
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
  const result = validateTemplateType(content, TemplateType.KILL_CHAIN)
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
  style.value = 'kc_default'
  renderEngine.value = 'graphviz'
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
    const blob = await visualizeKillChainFromContent(
      editorContent.value,
      format.value,
      style.value,
      fileFormat.value,
      renderEngine.value
    )
    imageBlob.value = blob
    imageUrl.value = createImageUrl(blob)
    svgText.value = renderEngine.value === 'svg' && format.value === 'svg' ? await blob.text() : null
  } catch (err) {
    error.value = err.response?.data?.detail || err.message || 'Failed to generate visualization'
  } finally {
    loading.value = false
  }
}

async function analyzeChain() {
  if (!editorContent.value) return
  loading.value = true
  error.value = null
  validation.value = null
  try {
    stats.value = await analyzeKillChainFromContent(editorContent.value, fileFormat.value)
  } catch (err) {
    error.value = err.response?.data?.detail || err.message || 'Failed to analyze kill chain'
  } finally {
    loading.value = false
  }
}

async function validateChain() {
  if (!editorContent.value) return
  loading.value = true
  error.value = null
  stats.value = null
  try {
    validation.value = await validateKillChainFromContent(editorContent.value, fileFormat.value)
  } catch (err) {
    error.value = err.response?.data?.detail || err.message || 'Failed to validate kill chain'
  } finally {
    loading.value = false
  }
}

function downloadImage() {
  if (imageBlob.value) downloadBlob(imageBlob.value, `kill_chain_${getTimestamp()}.${format.value}`)
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

/* Coverage severity colors */
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

/* Phase breakdown */
.phase-breakdown {
  margin-top: 1.5rem;
}

.phase-breakdown h4,
.warnings-list h4 {
  margin: 0 0 0.75rem;
  font-size: 0.95rem;
  color: var(--text-primary);
}

.phase-bars {
  display: flex;
  flex-direction: column;
  gap: 0.4rem;
}

.phase-bar-row {
  display: grid;
  grid-template-columns: 160px 1fr 2rem;
  align-items: center;
  gap: 0.75rem;
}

.phase-name {
  font-size: 0.8rem;
  color: var(--text-secondary);
  text-align: right;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.phase-bar-track {
  height: 14px;
  background: var(--bg-tertiary);
  border-radius: 7px;
  overflow: hidden;
}

.phase-bar-fill {
  height: 100%;
  background: linear-gradient(90deg, #3498db, #1e3a5f);
  border-radius: 7px;
  transition: width 0.3s ease;
}

.phase-count {
  font-size: 0.8rem;
  font-weight: 600;
  color: var(--text-primary);
  text-align: center;
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
