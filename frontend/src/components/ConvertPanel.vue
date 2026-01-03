<!--
  VULNEX -Universal Security Visualization Library-

  File: ConvertPanel.vue
  Author: Simon Roses Femerling
  Created: 2025-01-01
  Last Modified: 2025-12-29
  Version: 0.3.1
  License: Apache-2.0
  Copyright (c) 2025 VULNEX. All rights reserved.
  https://www.vulnex.com
-->
<template>
  <div class="panel">
    <div class="panel-header">
      <h2>Format Conversion</h2>
      <p>Convert configuration files between TOML, JSON, YAML, and Mermaid formats</p>
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
            <span class="upload-icon">&#x1F504;</span>
            <p>Drop config file here or click to browse</p>
            <span class="file-types">Supports: TOML, JSON, YAML</span>
          </div>
        </div>

        <!-- Source content display -->
        <div v-if="editorContent" class="source-section">
          <div class="source-header">
            <h3>Source File</h3>
            <div class="source-info">
              <span class="format-badge" :class="sourceFormat">{{ sourceFormat.toUpperCase() }}</span>
              <span class="file-name">{{ fileName }}</span>
            </div>
          </div>
          <div class="source-preview">
            <pre><code>{{ truncatedContent }}</code></pre>
          </div>
          <button class="btn btn-small btn-secondary" @click="changeFile">
            Change File
          </button>
        </div>

        <!-- Target format selection -->
        <div v-if="editorContent" class="options-row">
          <div class="option-group">
            <label>Convert To</label>
            <select v-model="targetFormat">
              <option v-for="f in availableTargetFormats" :key="f" :value="f">{{ f.toUpperCase() }}</option>
            </select>
          </div>
        </div>

        <div v-if="editorContent" class="actions">
          <button class="btn btn-primary" @click="convertFile" :disabled="!canConvert || loading">
            <span v-if="loading" class="spinner"></span>
            {{ loading ? 'Converting...' : 'Convert' }}
          </button>
        </div>
      </div>

      <div v-if="error" class="error-message">
        <span class="error-icon">&#x26A0;</span>
        {{ error }}
      </div>

      <div v-if="result" class="result-section">
        <div class="result-header">
          <h3>Converted Content</h3>
          <div class="result-actions">
            <span class="format-badge" :class="result.target_format">{{ result.target_format.toUpperCase() }}</span>
            <button class="btn btn-small btn-primary" @click="downloadResult">
              Download
            </button>
            <button class="btn btn-small btn-secondary" @click="copyToClipboard">
              {{ copied ? 'Copied!' : 'Copy' }}
            </button>
          </div>
        </div>
        <div class="result-preview">
          <pre><code>{{ result.content }}</code></pre>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, inject, watch, computed } from 'vue'
import {
  convertFormatFromContent,
  downloadTextFile,
  getTimestamp
} from '../services/api.js'

// Watch for clean trigger from parent
const cleanTrigger = inject('cleanTrigger')
watch(cleanTrigger, () => {
  resetPanel()
})

// State
const editorContent = ref(null)
const fileName = ref('')
const sourceFormat = ref('toml')
const targetFormat = ref('json')
const loading = ref(false)
const error = ref(null)
const result = ref(null)
const isDragging = ref(false)
const fileInput = ref(null)
const copied = ref(false)

// Available formats (mermaid is output-only)
const allFormats = ['toml', 'json', 'yaml']
const outputOnlyFormats = ['mermaid']
const allTargetFormats = [...allFormats, ...outputOnlyFormats]

// Computed
const availableTargetFormats = computed(() => {
  // Include all formats except the source format
  // Mermaid is output-only so it's always available as a target
  return allTargetFormats.filter(f => f !== sourceFormat.value)
})

const canConvert = computed(() => {
  return editorContent.value &&
         editorContent.value.trim() &&
         targetFormat.value !== sourceFormat.value
})

const truncatedContent = computed(() => {
  if (!editorContent.value) return ''
  const lines = editorContent.value.split('\n')
  if (lines.length > 15) {
    return lines.slice(0, 15).join('\n') + '\n...'
  }
  return editorContent.value
})

// Methods
function detectFormat(filename) {
  const ext = filename.toLowerCase().split('.').pop()
  if (ext === 'json') return 'json'
  if (ext === 'yaml' || ext === 'yml') return 'yaml'
  return 'toml'
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
      sourceFormat.value = detectFormat(file.name)
      // Set default target format to something different
      targetFormat.value = availableTargetFormats.value[0]
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
  sourceFormat.value = 'toml'
  targetFormat.value = 'json'
  clearResults()
  if (fileInput.value) {
    fileInput.value.value = ''
  }
}

function clearResults() {
  error.value = null
  result.value = null
  copied.value = false
}

function resetPanel() {
  editorContent.value = null
  fileName.value = ''
  sourceFormat.value = 'toml'
  targetFormat.value = 'json'
  clearResults()
}

async function convertFile() {
  if (!editorContent.value) return

  loading.value = true
  error.value = null
  result.value = null
  copied.value = false

  try {
    result.value = await convertFormatFromContent(
      editorContent.value,
      sourceFormat.value,
      targetFormat.value
    )
  } catch (err) {
    error.value = err.response?.data?.detail || err.message || 'Failed to convert file'
  } finally {
    loading.value = false
  }
}

function downloadResult() {
  if (result.value) {
    downloadTextFile(result.value.content, result.value.filename)
  }
}

async function copyToClipboard() {
  if (result.value) {
    try {
      await navigator.clipboard.writeText(result.value.content)
      copied.value = true
      setTimeout(() => { copied.value = false }, 2000)
    } catch (err) {
      error.value = 'Failed to copy to clipboard'
    }
  }
}
</script>

<style scoped>
.file-types {
  display: block;
  margin-top: 0.5rem;
  font-size: 0.75rem;
  color: var(--text-tertiary);
}

.source-section {
  background: var(--bg-tertiary);
  border-radius: var(--border-radius);
  padding: 1rem;
  margin-bottom: 1rem;
}

.source-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 0.75rem;
}

.source-header h3 {
  margin: 0;
  font-size: 1rem;
}

.source-info {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.file-name {
  font-size: 0.875rem;
  color: var(--text-secondary);
}

.format-badge {
  padding: 0.25rem 0.5rem;
  border-radius: 4px;
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: uppercase;
}

.format-badge.toml {
  background: rgba(99, 102, 241, 0.2);
  color: #818cf8;
}

.format-badge.json {
  background: rgba(16, 185, 129, 0.2);
  color: #34d399;
}

.format-badge.yaml {
  background: rgba(245, 158, 11, 0.2);
  color: #fbbf24;
}

.format-badge.mermaid {
  background: rgba(236, 72, 153, 0.2);
  color: #f472b6;
}

.source-preview,
.result-preview {
  background: var(--bg-primary);
  border-radius: var(--border-radius);
  padding: 0.75rem;
  overflow: auto;
  max-height: 300px;
  margin-bottom: 0.75rem;
}

.source-preview pre,
.result-preview pre {
  margin: 0;
  font-family: 'Fira Code', 'Consolas', monospace;
  font-size: 0.8rem;
  line-height: 1.5;
  white-space: pre-wrap;
  word-break: break-word;
}

.result-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 0.75rem;
}

.result-header h3 {
  margin: 0;
}

.result-actions {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.options-row {
  margin: 1rem 0;
}

.option-group label {
  display: block;
  margin-bottom: 0.5rem;
  font-weight: 500;
  color: var(--text-secondary);
}

.option-group select {
  width: 100%;
  max-width: 200px;
  padding: 0.6rem 0.8rem;
  background: var(--bg-tertiary);
  border: 1px solid var(--border-color);
  border-radius: var(--border-radius);
  color: var(--text-primary);
  font-size: 0.9rem;
}

.actions {
  margin-top: 1rem;
}
</style>
