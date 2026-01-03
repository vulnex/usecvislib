<!--
  VULNEX -Universal Security Visualization Library-

  File: BinaryVisPanel.vue
  Author: Simon Roses Femerling
  Created: 2025-01-01
  Last Modified: 2025-12-23
  Version: 0.3.1
  License: Apache-2.0
  Copyright (c) 2025 VULNEX. All rights reserved.
  https://www.vulnex.com
-->
<template>
  <div class="panel">
    <div class="panel-header">
      <h2>Binary File Visualization</h2>
      <p>Upload any binary file for entropy and pattern analysis</p>
    </div>

    <div class="panel-body">
      <div class="form-section">
        <div class="upload-area" :class="{ dragover: isDragging }" @dragover.prevent="isDragging = true"
          @dragleave="isDragging = false" @drop.prevent="handleDrop">
          <input type="file" ref="fileInput" @change="handleFileSelect" class="file-input" />
          <div class="upload-content" @click="$refs.fileInput.click()">
            <span class="upload-icon">📁</span>
            <p v-if="!file">Drop any binary file here or click to browse</p>
            <p v-else class="file-name">{{ file.name }} ({{ formatFileSize(file.size) }})</p>
          </div>
        </div>

        <div class="options-row">
          <div class="option-group">
            <label>Visualization Type</label>
            <select v-model="visType">
              <option v-for="v in visTypes" :key="v.value" :value="v.value">
                {{ v.icon }} {{ v.label }}
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
            <select v-model="style">
              <option v-for="s in styles" :key="s" :value="s">{{ formatStyleName(s) }}</option>
            </select>
          </div>
        </div>

        <!-- Advanced Configuration Section -->
        <div class="config-section">
          <div class="config-header" @click="showConfig = !showConfig">
            <span class="config-toggle">{{ showConfig ? '▼' : '▶' }}</span>
            <span>Advanced Configuration</span>
            <span v-if="hasConfig" class="config-badge">Custom</span>
          </div>

          <div v-if="showConfig" class="config-body">
            <div class="config-upload">
              <input type="file" ref="configInput" @change="handleConfigSelect" accept=".toml,.tml" class="file-input" />
              <button class="btn btn-small" @click="$refs.configInput.click()">
                📄 Load Config TOML
              </button>
              <button v-if="configContent" class="btn btn-small btn-secondary" @click="clearConfig">
                Clear
              </button>
              <span v-if="configFileName" class="config-file-name">{{ configFileName }}</span>
            </div>

            <div class="config-editor">
              <label>Configuration (TOML format)</label>
              <textarea
                v-model="configContent"
                placeholder="# Paste TOML config or load from file
# Example:
[entropy_analysis]
window_size = 512
step = 128

[heatmap]
block_size = 128"
                rows="10"
                spellcheck="false"
              ></textarea>
              <div v-if="configError" class="config-error">{{ configError }}</div>
            </div>

            <div class="config-presets">
              <label>Quick Presets</label>
              <div class="preset-buttons">
                <button class="btn btn-tiny" @click="applyPreset('high-detail')">High Detail</button>
                <button class="btn btn-tiny" @click="applyPreset('fast')">Fast</button>
                <button class="btn btn-tiny" @click="applyPreset('malware')">Malware Analysis</button>
              </div>
            </div>
          </div>
        </div>

        <div class="actions">
          <button class="btn btn-primary" @click="generateVisualization" :disabled="!file || loading">
            <span v-if="loading" class="spinner"></span>
            {{ loading ? 'Generating...' : 'Generate Visualization' }}
          </button>
          <button class="btn btn-secondary" @click="analyzeFile" :disabled="!file || loading">
            📈 Analyze File
          </button>
        </div>
      </div>

      <div v-if="error" class="error-message">
        <span class="error-icon">⚠️</span>
        {{ error }}
      </div>

      <div v-if="stats" class="stats-section">
        <h3>File Analysis</h3>
        <div class="stats-grid">
          <div class="stat-item">
            <span class="stat-value">{{ formatFileSize(stats.file_size) }}</span>
            <span class="stat-label">File Size</span>
          </div>
          <div class="stat-item" :class="getEntropyClass(stats.entropy)">
            <span class="stat-value">{{ stats.entropy.toFixed(3) }}</span>
            <span class="stat-label">Entropy (0-8)</span>
          </div>
          <div class="stat-item">
            <span class="stat-value">{{ stats.unique_bytes }}/256</span>
            <span class="stat-label">Unique Bytes</span>
          </div>
          <div class="stat-item">
            <span class="stat-value">{{ stats.null_percentage.toFixed(1) }}%</span>
            <span class="stat-label">Null Bytes</span>
          </div>
          <div class="stat-item">
            <span class="stat-value">{{ stats.printable_percentage.toFixed(1) }}%</span>
            <span class="stat-label">Printable ASCII</span>
          </div>
          <div class="stat-item">
            <span class="stat-value">{{ stats.high_byte_percentage.toFixed(1) }}%</span>
            <span class="stat-label">High Bytes (128-255)</span>
          </div>
        </div>

        <div class="entropy-indicator">
          <div class="entropy-bar">
            <div class="entropy-fill" :style="{ width: (stats.entropy / 8 * 100) + '%' }"
              :class="getEntropyClass(stats.entropy)"></div>
          </div>
          <div class="entropy-labels">
            <span>Low (text/sparse)</span>
            <span>Medium (code)</span>
            <span>High (compressed/encrypted)</span>
          </div>
        </div>
      </div>

      <div v-if="imageUrl" class="result-section">
        <div class="result-header">
          <h3>{{ getVisLabel(visType) }} Visualization</h3>
          <button class="btn btn-small" @click="downloadImage">
            ⬇️ Download
          </button>
        </div>
        <div class="image-container">
          <img :src="imageUrl" :alt="getVisLabel(visType) + ' Visualization'" />
        </div>
      </div>

      <div class="vis-type-info">
        <h4>Visualization Types</h4>
        <div class="info-grid">
          <div class="info-item">
            <span class="info-icon">📈</span>
            <div>
              <strong>Entropy</strong>
              <p>Shows entropy distribution across the file. High entropy indicates compressed or encrypted data.</p>
            </div>
          </div>
          <div class="info-item">
            <span class="info-icon">📊</span>
            <div>
              <strong>Distribution</strong>
              <p>Histogram of byte value frequencies. Useful for identifying file types and patterns.</p>
            </div>
          </div>
          <div class="info-item">
            <span class="info-icon">🌀</span>
            <div>
              <strong>Wind Rose</strong>
              <p>Polar visualization of byte pair patterns. Reveals repeating structures.</p>
            </div>
          </div>
          <div class="info-item">
            <span class="info-icon">🗺️</span>
            <div>
              <strong>Heatmap</strong>
              <p>2D view of the file structure. Each row represents a block of bytes.</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, inject, watch, computed } from 'vue'
import {
  visualizeBinary,
  analyzeBinary,
  createImageUrl,
  getTimestamp,
  downloadBlob
} from '../services/api.js'
import { parse as parseToml } from 'smol-toml'

const props = defineProps({
  styles: { type: Array, default: () => [] },
  formats: { type: Array, default: () => ['png'] }
})

// Watch for clean trigger from parent
const cleanTrigger = inject('cleanTrigger')
watch(cleanTrigger, () => {
  resetPanel()
})

const file = ref(null)
const format = ref('png')
const style = ref('bv_default')
const visType = ref('entropy')
const loading = ref(false)
const error = ref(null)
const imageUrl = ref(null)
const imageBlob = ref(null)
const stats = ref(null)
const isDragging = ref(false)
const fileInput = ref(null)

// Configuration state
const showConfig = ref(false)
const configContent = ref('')
const configFileName = ref('')
const configError = ref('')
const configInput = ref(null)

const hasConfig = computed(() => configContent.value.trim().length > 0)

const visTypes = [
  { value: 'entropy', label: 'Entropy Analysis', icon: '📈' },
  { value: 'distribution', label: 'Byte Distribution', icon: '📊' },
  { value: 'windrose', label: 'Wind Rose', icon: '🌀' },
  { value: 'heatmap', label: 'Heatmap', icon: '🗺️' }
]

function formatStyleName(s) {
  return s.replace('bv_', '').replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())
}

function formatFileSize(bytes) {
  if (bytes < 1024) return bytes + ' B'
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB'
  if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + ' MB'
  return (bytes / (1024 * 1024 * 1024)).toFixed(1) + ' GB'
}

function getEntropyClass(entropy) {
  if (entropy < 3) return 'entropy-low'
  if (entropy < 6) return 'entropy-medium'
  return 'entropy-high'
}

function getVisLabel(type) {
  const vis = visTypes.find(v => v.value === type)
  return vis ? vis.label : type
}

function handleFileSelect(event) {
  const files = event.target.files
  if (files.length > 0) {
    file.value = files[0]
    clearResults()
  }
}

function handleDrop(event) {
  isDragging.value = false
  const files = event.dataTransfer.files
  if (files.length > 0) {
    file.value = files[0]
    clearResults()
  }
}

function clearResults() {
  error.value = null
  imageUrl.value = null
  imageBlob.value = null
  stats.value = null
}

function resetPanel() {
  file.value = null
  format.value = 'png'
  style.value = 'bv_default'
  visType.value = 'entropy'
  clearResults()
  clearConfig()
}

// Configuration handling functions
function handleConfigSelect(event) {
  const files = event.target.files
  if (files.length > 0) {
    const configFile = files[0]
    configFileName.value = configFile.name
    const reader = new FileReader()
    reader.onload = (e) => {
      configContent.value = e.target.result
      validateConfig()
    }
    reader.readAsText(configFile)
  }
}

function clearConfig() {
  configContent.value = ''
  configFileName.value = ''
  configError.value = ''
}

function validateConfig() {
  configError.value = ''
  if (!configContent.value.trim()) return true

  try {
    parseToml(configContent.value)
    return true
  } catch (err) {
    configError.value = `Invalid TOML: ${err.message}`
    return false
  }
}

function getConfigJson() {
  if (!configContent.value.trim()) return null

  try {
    const parsed = parseToml(configContent.value)
    return JSON.stringify(parsed)
  } catch (err) {
    configError.value = `Invalid TOML: ${err.message}`
    return null
  }
}

function applyPreset(preset) {
  const presets = {
    'high-detail': `# High Detail Configuration
[entropy_analysis]
window_size = 128
step = 32
dpi = 200

[heatmap]
block_size = 128
dpi = 200

[byte_distribution]
dpi = 200
`,
    'fast': `# Fast Processing Configuration
[entropy_analysis]
window_size = 512
step = 256
dpi = 100

[heatmap]
block_size = 512
dpi = 100
`,
    'malware': `# Malware Analysis Configuration
[entropy_analysis]
window_size = 256
step = 64
show_thresholds = true

[[entropy_analysis.thresholds]]
value = 7.0
color = "red"
style = "--"
alpha = 0.7
label = "Packed/Encrypted sections"

[[entropy_analysis.thresholds]]
value = 5.5
color = "orange"
style = "--"
alpha = 0.5
label = "Obfuscated code"

[heatmap]
block_size = 256
show_colorbar = true
`
  }

  configContent.value = presets[preset] || ''
  validateConfig()
}

async function generateVisualization() {
  if (!file.value) return

  loading.value = true
  error.value = null

  // Validate config if present
  if (configContent.value.trim() && !validateConfig()) {
    loading.value = false
    return
  }

  try {
    const configJson = getConfigJson()
    const blob = await visualizeBinary(file.value, format.value, style.value, visType.value, configJson)
    imageBlob.value = blob
    imageUrl.value = createImageUrl(blob)
  } catch (err) {
    error.value = err.response?.data?.detail || err.message || 'Failed to generate visualization'
  } finally {
    loading.value = false
  }
}

async function analyzeFile() {
  if (!file.value) return

  loading.value = true
  error.value = null

  try {
    stats.value = await analyzeBinary(file.value)
  } catch (err) {
    error.value = err.response?.data?.detail || err.message || 'Failed to analyze file'
  } finally {
    loading.value = false
  }
}

function downloadImage() {
  if (imageBlob.value) {
    downloadBlob(imageBlob.value, `binary_${visType.value}_${getTimestamp()}.${format.value}`)
  }
}
</script>

<style scoped>
/* Advanced Configuration Section */
.config-section {
  margin-top: 1rem;
  border: 1px solid var(--border-color, #3a3a3a);
  border-radius: 6px;
  overflow: hidden;
}

.config-header {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.75rem 1rem;
  background: var(--bg-secondary, #2a2a2a);
  cursor: pointer;
  user-select: none;
}

.config-header:hover {
  background: var(--bg-hover, #333);
}

.config-toggle {
  font-size: 0.75rem;
  color: var(--text-muted, #888);
}

.config-badge {
  margin-left: auto;
  font-size: 0.7rem;
  padding: 0.15rem 0.5rem;
  background: var(--accent-color, #4a9eff);
  color: white;
  border-radius: 10px;
}

.config-body {
  padding: 1rem;
  background: var(--bg-primary, #1a1a1a);
  border-top: 1px solid var(--border-color, #3a3a3a);
}

.config-upload {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  margin-bottom: 1rem;
}

.config-file-name {
  font-size: 0.85rem;
  color: var(--text-muted, #888);
  font-style: italic;
}

.config-editor {
  margin-bottom: 1rem;
}

.config-editor label {
  display: block;
  margin-bottom: 0.5rem;
  font-size: 0.85rem;
  color: var(--text-muted, #888);
}

.config-editor textarea {
  width: 100%;
  padding: 0.75rem;
  font-family: 'Monaco', 'Menlo', 'Consolas', monospace;
  font-size: 0.85rem;
  background: var(--bg-tertiary, #222);
  color: var(--text-primary, #fff);
  border: 1px solid var(--border-color, #3a3a3a);
  border-radius: 4px;
  resize: vertical;
}

.config-editor textarea:focus {
  outline: none;
  border-color: var(--accent-color, #4a9eff);
}

.config-error {
  margin-top: 0.5rem;
  padding: 0.5rem;
  font-size: 0.8rem;
  color: #ff6b6b;
  background: rgba(255, 107, 107, 0.1);
  border-radius: 4px;
}

.config-presets {
  padding-top: 0.5rem;
  border-top: 1px solid var(--border-color, #3a3a3a);
}

.config-presets label {
  display: block;
  margin-bottom: 0.5rem;
  font-size: 0.85rem;
  color: var(--text-muted, #888);
}

.preset-buttons {
  display: flex;
  gap: 0.5rem;
  flex-wrap: wrap;
}

.btn-tiny {
  padding: 0.25rem 0.5rem;
  font-size: 0.75rem;
}

.btn-small {
  padding: 0.35rem 0.75rem;
  font-size: 0.85rem;
}
</style>
