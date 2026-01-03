<!--
  VULNEX -Universal Security Visualization Library-

  File: ExportPanel.vue
  Author: Simon Roses Femerling
  Created: 2025-12-25
  Last Modified: 2025-12-29
  Version: 0.3.1
  License: Apache-2.0
  Copyright (c) 2025 VULNEX. All rights reserved.
  https://www.vulnex.com
-->
<template>
  <div class="panel">
    <div class="panel-header">
      <h2>Export Data</h2>
      <p>Export configuration data to various formats (JSON, CSV, YAML, Markdown, Mermaid).</p>
    </div>

    <div class="panel-body">
      <div class="form-section">
        <!-- Upload area -->
        <div
          v-if="!content"
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
            <p>Drop config file here or click to browse</p>
            <span class="file-types">Supports: TOML, JSON, YAML</span>
          </div>
        </div>

        <!-- File loaded indicator -->
        <div v-else class="file-loaded-section">
          <div class="file-loaded">
            <span class="file-icon">&#x1F4C4;</span>
            <span class="file-name">{{ fileName }}</span>
            <button class="btn btn-small btn-secondary" @click="changeFile">Change File</button>
          </div>

          <!-- Available sections -->
          <div v-if="sections.length > 0" class="sections-info">
            <h4>Available Sections</h4>
            <div class="section-tags">
              <span v-for="section in sections" :key="section" class="section-tag">
                {{ section }}
              </span>
            </div>
          </div>
        </div>

        <!-- Export options -->
        <div class="options-row">
          <div class="option-group">
            <label>Export Format</label>
            <select v-model="exportFormat">
              <option value="json">JSON</option>
              <option value="csv">CSV</option>
              <option value="yaml">YAML</option>
              <option value="markdown">Markdown</option>
              <option value="mermaid">Mermaid (.mmd)</option>
            </select>
          </div>
          <div class="option-group" v-if="exportFormat === 'csv' || exportFormat === 'markdown'">
            <label>Section (for CSV/Markdown)</label>
            <select v-model="selectedSection">
              <option value="">All sections</option>
              <option v-for="section in sections" :key="section" :value="section">
                {{ section }}
              </option>
            </select>
          </div>
        </div>

        <div class="options-row">
          <div class="option-group checkbox-group">
            <label>
              <input type="checkbox" v-model="includeStats" />
              Include Statistics
            </label>
          </div>
        </div>

        <div class="actions">
          <button
            class="btn btn-primary"
            @click="exportData"
            :disabled="!content || loading"
          >
            <span v-if="loading" class="spinner"></span>
            {{ loading ? 'Exporting...' : 'Export Data' }}
          </button>
        </div>
      </div>

      <div v-if="error" class="error-message">
        <span class="error-icon">&#x26A0;</span>
        {{ error }}
      </div>

      <!-- Export result -->
      <div v-if="exportResult" class="export-section">
        <div class="export-header">
          <h3>Exported Data</h3>
          <div class="export-meta">
            <span>Format: {{ exportResult.format.toUpperCase() }}</span>
            <span v-if="exportResult.rows">Rows: {{ exportResult.rows }}</span>
          </div>
          <button class="btn btn-small" @click="downloadExport">
            Download {{ exportResult.filename }}
          </button>
        </div>
        <pre class="export-content">{{ exportResult.content }}</pre>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, inject, watch } from 'vue'
import {
  exportDataFromContent,
  getExportSectionsFromContent,
  downloadTextFile,
  getTimestamp
} from '../services/api.js'

// Watch for clean trigger from parent
const cleanTrigger = inject('cleanTrigger')
watch(cleanTrigger, () => {
  resetPanel()
})

// State
const content = ref(null)
const fileName = ref('')
const configFormat = ref('toml')
const exportFormat = ref('json')
const selectedSection = ref('')
const includeStats = ref(true)
const sections = ref([])
const loading = ref(false)
const error = ref(null)
const exportResult = ref(null)
const isDragging = ref(false)
const fileInput = ref(null)

// Methods
function detectFormat(filename) {
  if (filename.endsWith('.json')) return 'json'
  if (filename.endsWith('.yaml') || filename.endsWith('.yml')) return 'yaml'
  return 'toml'
}

async function loadFile(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onload = (e) => resolve(e.target.result)
    reader.onerror = () => reject(new Error('Failed to read file'))
    reader.readAsText(file)
  })
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
  try {
    content.value = await loadFile(file)
    fileName.value = file.name
    configFormat.value = detectFormat(file.name)
    error.value = null
    exportResult.value = null

    // Get available sections
    try {
      const result = await getExportSectionsFromContent(content.value, configFormat.value)
      sections.value = result.sections || []
    } catch (err) {
      sections.value = []
    }
  } catch (err) {
    error.value = 'Failed to read file'
  }
}

function changeFile() {
  content.value = null
  fileName.value = ''
  configFormat.value = 'toml'
  sections.value = []
  exportResult.value = null
  error.value = null
  if (fileInput.value) {
    fileInput.value.value = ''
  }
}

function resetPanel() {
  content.value = null
  fileName.value = ''
  configFormat.value = 'toml'
  exportFormat.value = 'json'
  selectedSection.value = ''
  includeStats.value = true
  sections.value = []
  loading.value = false
  error.value = null
  exportResult.value = null
}

async function exportData() {
  if (!content.value) return

  loading.value = true
  error.value = null
  exportResult.value = null

  try {
    exportResult.value = await exportDataFromContent(
      content.value,
      configFormat.value,
      exportFormat.value,
      selectedSection.value || null,
      includeStats.value
    )
  } catch (err) {
    error.value = err.response?.data?.detail || err.message || 'Failed to export data'
  } finally {
    loading.value = false
  }
}

function downloadExport() {
  if (exportResult.value) {
    downloadTextFile(exportResult.value.content, exportResult.value.filename)
  }
}
</script>

<style scoped>
.file-loaded-section {
  margin-bottom: 1rem;
}

.file-loaded {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  padding: 1rem;
  background: var(--bg-secondary);
  border: 1px solid var(--border-color);
  border-radius: 8px;
}

.file-loaded .file-icon {
  font-size: 1.5rem;
}

.file-loaded .file-name {
  flex: 1;
  font-family: monospace;
  font-size: 0.9rem;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.sections-info {
  margin-top: 1rem;
}

.sections-info h4 {
  margin: 0 0 0.5rem 0;
  font-size: 0.85rem;
  color: var(--text-secondary);
}

.section-tags {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
}

.section-tag {
  padding: 0.25rem 0.5rem;
  background: var(--bg-tertiary);
  border-radius: 4px;
  font-size: 0.8rem;
  font-family: monospace;
  color: var(--text-secondary);
}

.checkbox-group label {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  cursor: pointer;
}

.export-section {
  margin-top: 1.5rem;
  border: 1px solid var(--border-color);
  border-radius: 8px;
  overflow: hidden;
}

.export-header {
  display: flex;
  align-items: center;
  gap: 1rem;
  padding: 1rem;
  background: var(--bg-secondary);
  border-bottom: 1px solid var(--border-color);
}

.export-header h3 {
  margin: 0;
  flex: 1;
}

.export-meta {
  display: flex;
  gap: 1rem;
  font-size: 0.85rem;
  color: var(--text-secondary);
}

.export-content {
  margin: 0;
  padding: 1rem;
  background: var(--bg-tertiary);
  font-family: monospace;
  font-size: 0.8rem;
  overflow-x: auto;
  max-height: 400px;
  overflow-y: auto;
  white-space: pre-wrap;
}

.file-types {
  display: block;
  margin-top: 0.5rem;
  font-size: 0.75rem;
  color: var(--text-tertiary);
}
</style>
