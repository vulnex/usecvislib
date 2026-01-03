<!--
  VULNEX -Universal Security Visualization Library-

  File: ComparePanel.vue
  Author: Simon Roses Femerling
  Created: 2025-12-25
  Last Modified: 2025-12-25
  Version: 0.3.1
  License: Apache-2.0
  Copyright (c) 2025 VULNEX. All rights reserved.
  https://www.vulnex.com
-->
<template>
  <div class="panel">
    <div class="panel-header">
      <h2>Compare Configurations</h2>
      <p>Compare two configuration files to see what changed between versions.</p>
    </div>

    <div class="panel-body">
      <div class="form-section">
        <div class="compare-uploads">
          <!-- Old file upload -->
          <div class="upload-column">
            <h3>Original File</h3>
            <div
              v-if="!oldContent"
              class="upload-area small"
              :class="{ dragover: isDraggingOld }"
              @dragover.prevent="isDraggingOld = true"
              @dragleave="isDraggingOld = false"
              @drop.prevent="handleDropOld"
            >
              <input
                type="file"
                ref="oldFileInput"
                accept=".tml,.toml,.json,.yaml,.yml"
                @change="handleOldFileSelect"
                class="file-input"
              />
              <div class="upload-content" @click="$refs.oldFileInput.click()">
                <span class="upload-icon">&#x1F4C4;</span>
                <p>Drop original file here</p>
              </div>
            </div>
            <div v-else class="file-loaded">
              <span class="file-icon">&#x1F4C4;</span>
              <span class="file-name">{{ oldFileName }}</span>
              <button class="btn-remove" @click="clearOldFile">&#x2715;</button>
            </div>
          </div>

          <!-- Arrow -->
          <div class="compare-arrow">
            <span>&#x27A1;</span>
          </div>

          <!-- New file upload -->
          <div class="upload-column">
            <h3>Modified File</h3>
            <div
              v-if="!newContent"
              class="upload-area small"
              :class="{ dragover: isDraggingNew }"
              @dragover.prevent="isDraggingNew = true"
              @dragleave="isDraggingNew = false"
              @drop.prevent="handleDropNew"
            >
              <input
                type="file"
                ref="newFileInput"
                accept=".tml,.toml,.json,.yaml,.yml"
                @change="handleNewFileSelect"
                class="file-input"
              />
              <div class="upload-content" @click="$refs.newFileInput.click()">
                <span class="upload-icon">&#x1F4C4;</span>
                <p>Drop modified file here</p>
              </div>
            </div>
            <div v-else class="file-loaded">
              <span class="file-icon">&#x1F4C4;</span>
              <span class="file-name">{{ newFileName }}</span>
              <button class="btn-remove" @click="clearNewFile">&#x2715;</button>
            </div>
          </div>
        </div>

        <div class="options-row">
          <div class="option-group checkbox-group">
            <label>
              <input type="checkbox" v-model="generateReport" />
              Generate Markdown Report
            </label>
          </div>
        </div>

        <div class="actions">
          <button
            class="btn btn-primary"
            @click="compareConfigs"
            :disabled="!canCompare || loading"
          >
            <span v-if="loading" class="spinner"></span>
            {{ loading ? 'Comparing...' : 'Compare Files' }}
          </button>
        </div>
      </div>

      <div v-if="error" class="error-message">
        <span class="error-icon">&#x26A0;</span>
        {{ error }}
      </div>

      <!-- Diff Results -->
      <div v-if="diffResult" class="diff-section">
        <!-- Summary -->
        <div class="diff-summary">
          <h3>
            {{ diffResult.has_changes ? 'Changes Detected' : 'No Changes' }}
          </h3>
          <div v-if="diffResult.has_changes" class="summary-stats">
            <span class="stat added">+{{ diffResult.summary.added }} added</span>
            <span class="stat removed">-{{ diffResult.summary.removed }} removed</span>
            <span class="stat modified">~{{ diffResult.summary.modified }} modified</span>
            <span class="stat total">{{ diffResult.summary.total }} total changes</span>
          </div>
        </div>

        <!-- Changes list -->
        <div v-if="diffResult.has_changes" class="changes-list">
          <h4>Changes</h4>

          <!-- Additions -->
          <div v-if="addedChanges.length > 0" class="change-group">
            <h5 class="change-type added">Added ({{ addedChanges.length }})</h5>
            <div v-for="(change, index) in addedChanges" :key="'added-' + index" class="change-item added">
              <span class="change-icon">+</span>
              <span class="change-path">{{ change.path }}</span>
              <span class="change-value" v-if="change.new_value">{{ formatValue(change.new_value) }}</span>
            </div>
          </div>

          <!-- Removals -->
          <div v-if="removedChanges.length > 0" class="change-group">
            <h5 class="change-type removed">Removed ({{ removedChanges.length }})</h5>
            <div v-for="(change, index) in removedChanges" :key="'removed-' + index" class="change-item removed">
              <span class="change-icon">-</span>
              <span class="change-path">{{ change.path }}</span>
              <span class="change-value" v-if="change.old_value">{{ formatValue(change.old_value) }}</span>
            </div>
          </div>

          <!-- Modifications -->
          <div v-if="modifiedChanges.length > 0" class="change-group">
            <h5 class="change-type modified">Modified ({{ modifiedChanges.length }})</h5>
            <div v-for="(change, index) in modifiedChanges" :key="'modified-' + index" class="change-item modified">
              <span class="change-icon">~</span>
              <span class="change-path">{{ change.path }}</span>
              <div class="change-values">
                <span class="old-value">{{ formatValue(change.old_value) }}</span>
                <span class="arrow">&#x2192;</span>
                <span class="new-value">{{ formatValue(change.new_value) }}</span>
              </div>
            </div>
          </div>
        </div>

        <!-- Markdown report -->
        <div v-if="diffResult.report" class="report-section">
          <div class="report-header">
            <h4>Markdown Report</h4>
            <button class="btn btn-small" @click="downloadReport">Download Report</button>
          </div>
          <pre class="report-content">{{ diffResult.report }}</pre>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, inject, watch, computed } from 'vue'
import { compareContents, downloadTextFile, getTimestamp } from '../services/api.js'

// Watch for clean trigger from parent
const cleanTrigger = inject('cleanTrigger')
watch(cleanTrigger, () => {
  resetPanel()
})

// State
const oldContent = ref(null)
const oldFileName = ref('')
const oldFormat = ref('toml')
const newContent = ref(null)
const newFileName = ref('')
const newFormat = ref('toml')
const generateReport = ref(true)
const loading = ref(false)
const error = ref(null)
const diffResult = ref(null)
const isDraggingOld = ref(false)
const isDraggingNew = ref(false)
const oldFileInput = ref(null)
const newFileInput = ref(null)

// Computed
const canCompare = computed(() => {
  return oldContent.value && newContent.value
})

const addedChanges = computed(() => {
  if (!diffResult.value?.changes) return []
  return diffResult.value.changes.filter(c => c.change_type === 'added')
})

const removedChanges = computed(() => {
  if (!diffResult.value?.changes) return []
  return diffResult.value.changes.filter(c => c.change_type === 'removed')
})

const modifiedChanges = computed(() => {
  if (!diffResult.value?.changes) return []
  return diffResult.value.changes.filter(c => c.change_type === 'modified')
})

// Methods
function detectFormat(filename) {
  if (filename.endsWith('.json')) return 'json'
  if (filename.endsWith('.yaml') || filename.endsWith('.yml')) return 'yaml'
  return 'toml'
}

function formatValue(value) {
  if (value === null || value === undefined) return 'null'
  if (typeof value === 'object') {
    return JSON.stringify(value, null, 2).substring(0, 100)
  }
  return String(value).substring(0, 100)
}

async function loadFile(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onload = (e) => resolve(e.target.result)
    reader.onerror = () => reject(new Error('Failed to read file'))
    reader.readAsText(file)
  })
}

async function handleOldFileSelect(event) {
  const files = event.target.files
  if (files.length > 0) {
    try {
      oldContent.value = await loadFile(files[0])
      oldFileName.value = files[0].name
      oldFormat.value = detectFormat(files[0].name)
      error.value = null
      diffResult.value = null
    } catch (err) {
      error.value = 'Failed to read original file'
    }
  }
}

async function handleNewFileSelect(event) {
  const files = event.target.files
  if (files.length > 0) {
    try {
      newContent.value = await loadFile(files[0])
      newFileName.value = files[0].name
      newFormat.value = detectFormat(files[0].name)
      error.value = null
      diffResult.value = null
    } catch (err) {
      error.value = 'Failed to read modified file'
    }
  }
}

async function handleDropOld(event) {
  isDraggingOld.value = false
  const files = event.dataTransfer.files
  if (files.length > 0) {
    try {
      oldContent.value = await loadFile(files[0])
      oldFileName.value = files[0].name
      oldFormat.value = detectFormat(files[0].name)
      error.value = null
      diffResult.value = null
    } catch (err) {
      error.value = 'Failed to read original file'
    }
  }
}

async function handleDropNew(event) {
  isDraggingNew.value = false
  const files = event.dataTransfer.files
  if (files.length > 0) {
    try {
      newContent.value = await loadFile(files[0])
      newFileName.value = files[0].name
      newFormat.value = detectFormat(files[0].name)
      error.value = null
      diffResult.value = null
    } catch (err) {
      error.value = 'Failed to read modified file'
    }
  }
}

function clearOldFile() {
  oldContent.value = null
  oldFileName.value = ''
  oldFormat.value = 'toml'
  diffResult.value = null
  if (oldFileInput.value) {
    oldFileInput.value.value = ''
  }
}

function clearNewFile() {
  newContent.value = null
  newFileName.value = ''
  newFormat.value = 'toml'
  diffResult.value = null
  if (newFileInput.value) {
    newFileInput.value.value = ''
  }
}

function resetPanel() {
  oldContent.value = null
  oldFileName.value = ''
  oldFormat.value = 'toml'
  newContent.value = null
  newFileName.value = ''
  newFormat.value = 'toml'
  generateReport.value = true
  loading.value = false
  error.value = null
  diffResult.value = null
}

async function compareConfigs() {
  if (!canCompare.value) return

  loading.value = true
  error.value = null
  diffResult.value = null

  try {
    // Use the format of the original file
    diffResult.value = await compareContents(
      oldContent.value,
      newContent.value,
      oldFormat.value,
      [],
      generateReport.value
    )
  } catch (err) {
    error.value = err.response?.data?.detail || err.message || 'Failed to compare files'
  } finally {
    loading.value = false
  }
}

function downloadReport() {
  if (diffResult.value?.report) {
    downloadTextFile(diffResult.value.report, `diff_report_${getTimestamp()}.md`)
  }
}
</script>

<style scoped>
.compare-uploads {
  display: flex;
  gap: 1rem;
  align-items: flex-start;
  margin-bottom: 1.5rem;
}

.upload-column {
  flex: 1;
}

.upload-column h3 {
  margin: 0 0 0.75rem 0;
  font-size: 0.9rem;
  color: var(--text-secondary);
}

.upload-area.small {
  min-height: 100px;
  padding: 1rem;
}

.upload-area.small .upload-icon {
  font-size: 1.5rem;
}

.upload-area.small p {
  font-size: 0.85rem;
  margin: 0.5rem 0 0 0;
}

.compare-arrow {
  display: flex;
  align-items: center;
  justify-content: center;
  padding-top: 2rem;
  font-size: 1.5rem;
  color: var(--text-tertiary);
}

.file-loaded {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 1rem;
  background: var(--bg-secondary);
  border: 1px solid var(--border-color);
  border-radius: 8px;
}

.file-loaded .file-icon {
  font-size: 1.25rem;
}

.file-loaded .file-name {
  flex: 1;
  font-family: monospace;
  font-size: 0.85rem;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.btn-remove {
  background: none;
  border: none;
  color: var(--text-tertiary);
  cursor: pointer;
  padding: 0.25rem;
  font-size: 0.9rem;
}

.btn-remove:hover {
  color: var(--error-color);
}

.checkbox-group label {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  cursor: pointer;
}

.diff-section {
  margin-top: 1.5rem;
  border: 1px solid var(--border-color);
  border-radius: 8px;
  overflow: hidden;
}

.diff-summary {
  padding: 1rem;
  background: var(--bg-secondary);
  border-bottom: 1px solid var(--border-color);
}

.diff-summary h3 {
  margin: 0 0 0.5rem 0;
}

.summary-stats {
  display: flex;
  gap: 1rem;
  flex-wrap: wrap;
}

.summary-stats .stat {
  font-size: 0.85rem;
  padding: 0.25rem 0.5rem;
  border-radius: 4px;
}

.summary-stats .stat.added {
  background: rgba(var(--success-rgb), 0.1);
  color: var(--success-color);
}

.summary-stats .stat.removed {
  background: rgba(var(--error-rgb), 0.1);
  color: var(--error-color);
}

.summary-stats .stat.modified {
  background: rgba(var(--warning-rgb), 0.1);
  color: var(--warning-color);
}

.summary-stats .stat.total {
  background: var(--bg-tertiary);
  color: var(--text-secondary);
}

.changes-list {
  padding: 1rem;
}

.changes-list h4 {
  margin: 0 0 1rem 0;
}

.change-group {
  margin-bottom: 1.5rem;
}

.change-group:last-child {
  margin-bottom: 0;
}

.change-type {
  margin: 0 0 0.5rem 0;
  font-size: 0.85rem;
  font-weight: 600;
}

.change-type.added {
  color: var(--success-color);
}

.change-type.removed {
  color: var(--error-color);
}

.change-type.modified {
  color: var(--warning-color);
}

.change-item {
  display: flex;
  align-items: flex-start;
  gap: 0.5rem;
  padding: 0.5rem;
  margin-bottom: 0.25rem;
  border-radius: 4px;
  font-family: monospace;
  font-size: 0.85rem;
}

.change-item.added {
  background: rgba(var(--success-rgb), 0.05);
}

.change-item.removed {
  background: rgba(var(--error-rgb), 0.05);
}

.change-item.modified {
  background: rgba(var(--warning-rgb), 0.05);
}

.change-icon {
  font-weight: bold;
  width: 1rem;
  text-align: center;
}

.change-item.added .change-icon {
  color: var(--success-color);
}

.change-item.removed .change-icon {
  color: var(--error-color);
}

.change-item.modified .change-icon {
  color: var(--warning-color);
}

.change-path {
  font-weight: 500;
  color: var(--text-primary);
}

.change-value {
  color: var(--text-secondary);
  margin-left: auto;
  max-width: 200px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.change-values {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  margin-left: auto;
  font-size: 0.8rem;
}

.old-value {
  color: var(--error-color);
  text-decoration: line-through;
}

.new-value {
  color: var(--success-color);
}

.arrow {
  color: var(--text-tertiary);
}

.report-section {
  border-top: 1px solid var(--border-color);
}

.report-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 0.75rem 1rem;
  background: var(--bg-secondary);
  border-bottom: 1px solid var(--border-color);
}

.report-header h4 {
  margin: 0;
  font-size: 0.9rem;
}

.report-content {
  margin: 0;
  padding: 1rem;
  background: var(--bg-tertiary);
  font-family: monospace;
  font-size: 0.8rem;
  overflow-x: auto;
  max-height: 300px;
  overflow-y: auto;
  white-space: pre-wrap;
}
</style>
