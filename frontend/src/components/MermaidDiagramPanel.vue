<!--
  VULNEX -Universal Security Visualization Library-

  File: MermaidDiagramPanel.vue
  Author: Claude Code
  Created: 2026-01-14
  Last Modified: 2026-01-14
  Version: 0.3.2
  License: Apache-2.0
  Copyright (c) 2025 VULNEX. All rights reserved.
  https://www.vulnex.com
-->
<template>
  <div class="panel mermaid-panel">
    <div class="panel-header">
      <h2>Mermaid Diagrams</h2>
      <p>Create diagrams using Mermaid syntax - flowcharts, sequence diagrams, ER diagrams, and more</p>
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
          :class="['sub-tab', { active: activeSubTab === 'reference' }]"
          @click="activeSubTab = 'reference'"
        >
          Reference
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
          <input type="file" ref="fileInput" accept=".mmd,.tml,.toml,.json,.yaml,.yml" @change="handleFileSelect" class="file-input" />
          <div class="upload-content" @click="$refs.fileInput.click()">
            <span class="upload-icon">🧜</span>
            <p>Drop Mermaid file here or click to browse</p>
            <span class="file-types">Supports: .mmd, TOML, JSON, YAML</span>
          </div>
        </div>

        <!-- Mermaid Editor - shown after file upload or new diagram -->
        <div v-if="editorContent" class="editor-wrapper">
          <div class="editor-header">
            <span class="editor-title">{{ fileName || 'Mermaid Diagram' }}</span>
            <span v-if="detectedType" class="detected-type">Type: {{ detectedType }}</span>
          </div>
          <textarea
            v-model="editorContent"
            class="code-editor"
            spellcheck="false"
            placeholder="Enter Mermaid syntax here..."
          ></textarea>
        </div>

        <!-- Quick start button when empty -->
        <div v-if="!editorContent" class="quick-start">
          <button class="btn btn-secondary" @click="startNewDiagram('flowchart')">
            New Flowchart
          </button>
          <button class="btn btn-secondary" @click="startNewDiagram('sequence')">
            New Sequence Diagram
          </button>
          <button class="btn btn-secondary" @click="startNewDiagram('class')">
            New Class Diagram
          </button>
        </div>

        <!-- Change file button when editor is shown -->
        <div v-if="editorContent" class="file-actions">
          <button class="btn btn-small btn-secondary" @click="changeFile">
            Change File
          </button>
          <button class="btn btn-small btn-secondary" @click="clearAll">
            Clear
          </button>
        </div>

        <div class="options-row">
          <div class="option-group">
            <label>Output Format</label>
            <select v-model="format">
              <option v-for="f in formats" :key="f" :value="f">{{ f.toUpperCase() }}</option>
            </select>
          </div>
          <div class="option-group">
            <label>Theme</label>
            <select v-model="selectedTheme">
              <option v-for="t in themes" :key="t" :value="t">{{ t }}</option>
            </select>
          </div>
          <div class="option-group">
            <label>Background</label>
            <select v-model="background">
              <option value="white">White</option>
              <option value="transparent">Transparent</option>
              <option value="#1a1a2e">Dark</option>
            </select>
          </div>
        </div>

        <div class="actions">
          <button class="btn btn-primary" @click="generateVisualization" :disabled="!canGenerate || loading">
            <span v-if="loading" class="spinner"></span>
            {{ loading ? 'Generating...' : 'Generate Diagram' }}
          </button>
          <button class="btn btn-secondary" @click="validateDiagram" :disabled="!canGenerate || loading">
            Validate
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
            :key="template.path"
            class="template-card"
            @click="selectTemplate(template)"
          >
            <div class="template-icon">{{ getTypeIcon(template.diagram_type) }}</div>
            <div class="template-info">
              <h4>{{ template.name }}</h4>
              <span class="template-category">{{ formatCategoryName(template.category) }}</span>
              <span v-if="template.diagram_type" class="template-type">{{ template.diagram_type }}</span>
            </div>
          </div>
        </div>

        <div v-if="!loadingTemplates && templates.length === 0" class="empty-state">
          <p>No templates found</p>
        </div>
      </div>

      <!-- Reference Tab -->
      <div v-if="activeSubTab === 'reference'" class="reference-section">
        <h3>Supported Diagram Types</h3>
        <div class="reference-grid">
          <div v-for="(desc, type) in diagramTypes" :key="type" class="reference-card">
            <div class="reference-icon">{{ getTypeIcon(type) }}</div>
            <h4>{{ type }}</h4>
            <p>{{ desc }}</p>
          </div>
        </div>

        <h3>Quick Examples</h3>
        <div class="examples-list">
          <div class="example-item">
            <h4>Flowchart</h4>
            <pre>flowchart TD
    A[Start] --> B{Decision}
    B -->|Yes| C[End]
    B -->|No| D[Retry]</pre>
            <button class="btn btn-small" @click="useExample('flowchart')">Use This</button>
          </div>
          <div class="example-item">
            <h4>Sequence Diagram</h4>
            <pre>sequenceDiagram
    Alice->>Bob: Hello Bob
    Bob-->>Alice: Hi Alice</pre>
            <button class="btn btn-small" @click="useExample('sequence')">Use This</button>
          </div>
          <div class="example-item">
            <h4>ER Diagram</h4>
            <pre>erDiagram
    USER ||--o{ ORDER : places
    ORDER ||--|{ ITEM : contains</pre>
            <button class="btn btn-small" @click="useExample('er')">Use This</button>
          </div>
        </div>
      </div>

      <!-- Result Display -->
      <div v-if="resultImage" class="result-section">
        <div class="result-header">
          <h3>Generated Diagram</h3>
          <div class="result-actions">
            <button class="btn btn-small" @click="downloadResult">Download</button>
            <button class="btn btn-small btn-secondary" @click="clearResult">Clear</button>
          </div>
        </div>
        <div class="result-image">
          <img :src="resultImage" alt="Generated Mermaid Diagram" />
        </div>
      </div>

      <!-- Validation/Error Messages -->
      <div v-if="error" class="error-message">
        <span class="error-icon">⚠</span>
        {{ error }}
      </div>
      <div v-if="validationResult" class="validation-section">
        <h3>Validation Result</h3>
        <div :class="['validation-status', validationResult.valid ? 'valid' : 'invalid']">
          {{ validationResult.valid ? 'Valid' : 'Invalid' }}
        </div>
        <p v-if="validationResult.diagram_type">Detected type: {{ validationResult.diagram_type }}</p>
        <div v-if="validationResult.errors && validationResult.errors.length > 0" class="validation-errors">
          <h4>Errors</h4>
          <ul>
            <li v-for="(err, idx) in validationResult.errors" :key="idx" class="error-item">{{ err }}</li>
          </ul>
        </div>
        <div v-if="validationResult.stats" class="validation-stats">
          <span>Lines: {{ validationResult.stats.line_count }}</span>
          <span>Characters: {{ validationResult.stats.char_count }}</span>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, watch, inject } from 'vue'
import {
  visualizeMermaidFromContent,
  validateMermaidFromContent,
  getMermaidTemplates,
  getMermaidTemplate,
  getMermaidThemes,
  getMermaidTypes
} from '../services/api.js'

const props = defineProps({
  apiConnected: Boolean,
  formats: Array
})

// Clean trigger from parent
const cleanTrigger = inject('cleanTrigger', ref(0))

// State
const activeSubTab = ref('editor')
const editorContent = ref('')
const fileName = ref('')
const format = ref('png')
const selectedTheme = ref('default')
const background = ref('white')
const detectedType = ref('')
const isDragging = ref(false)
const loading = ref(false)
const error = ref('')
const resultImage = ref(null)
const validationResult = ref(null)

// Templates
const templates = ref([])
const templateCategories = ref([])
const selectedTemplateCategory = ref('')
const loadingTemplates = ref(false)

// Reference data
const themes = ref(['default', 'dark', 'forest', 'neutral', 'base'])
const diagramTypes = ref({})

// Computed
const canGenerate = computed(() => {
  return editorContent.value.trim().length > 0 && props.apiConnected
})

// Methods
async function generateVisualization() {
  if (!canGenerate.value) return

  loading.value = true
  error.value = ''
  resultImage.value = null

  try {
    // Determine config format based on content
    const configFormat = detectFormat(editorContent.value)

    const blob = await visualizeMermaidFromContent(
      editorContent.value,
      format.value,
      selectedTheme.value,
      configFormat
    )

    resultImage.value = URL.createObjectURL(blob)
  } catch (err) {
    error.value = err.response?.data?.detail || err.message || 'Failed to generate diagram'
  } finally {
    loading.value = false
  }
}

async function validateDiagram() {
  if (!canGenerate.value) return

  loading.value = true
  error.value = ''
  validationResult.value = null

  try {
    const configFormat = detectFormat(editorContent.value)
    validationResult.value = await validateMermaidFromContent(editorContent.value, configFormat)
    if (validationResult.value.diagram_type) {
      detectedType.value = validationResult.value.diagram_type
    }
  } catch (err) {
    error.value = err.response?.data?.detail || err.message || 'Validation failed'
  } finally {
    loading.value = false
  }
}

function detectFormat(content) {
  const trimmed = content.trim()
  // Check for Mermaid syntax keywords at start
  const mermaidKeywords = ['flowchart', 'graph', 'sequenceDiagram', 'classDiagram', 'stateDiagram',
    'erDiagram', 'gantt', 'pie', 'mindmap', 'timeline', 'gitGraph']
  for (const kw of mermaidKeywords) {
    if (trimmed.startsWith(kw)) return 'mermaid'
  }
  // Check for TOML
  if (trimmed.startsWith('[')) return 'toml'
  // Check for JSON
  if (trimmed.startsWith('{')) return 'json'
  // Default to mermaid (raw syntax)
  return 'mermaid'
}

function handleFileSelect(event) {
  const file = event.target.files[0]
  if (file) loadFile(file)
}

function handleDrop(event) {
  isDragging.value = false
  const file = event.dataTransfer.files[0]
  if (file) loadFile(file)
}

function loadFile(file) {
  fileName.value = file.name
  const reader = new FileReader()
  reader.onload = (e) => {
    editorContent.value = e.target.result
    detectDiagramType()
  }
  reader.readAsText(file)
}

function detectDiagramType() {
  const content = editorContent.value.trim()
  const types = ['flowchart', 'graph', 'sequenceDiagram', 'classDiagram', 'stateDiagram',
    'erDiagram', 'gantt', 'pie', 'mindmap', 'timeline', 'gitGraph']
  for (const t of types) {
    if (content.startsWith(t)) {
      detectedType.value = t
      return
    }
  }
  detectedType.value = ''
}

function changeFile() {
  editorContent.value = ''
  fileName.value = ''
  detectedType.value = ''
  resultImage.value = null
  validationResult.value = null
  error.value = ''
}

function clearAll() {
  changeFile()
}

function clearResult() {
  resultImage.value = null
}

function downloadResult() {
  if (!resultImage.value) return
  const link = document.createElement('a')
  link.href = resultImage.value
  link.download = `mermaid_diagram.${format.value}`
  link.click()
}

function startNewDiagram(type) {
  const diagramTemplates = {
    flowchart: `flowchart TD
    A[Start] --> B{Decision}
    B -->|Yes| C[Process]
    B -->|No| D[End]
    C --> D`,
    sequence: `sequenceDiagram
    participant A as Alice
    participant B as Bob
    A->>B: Hello Bob
    B-->>A: Hi Alice
    A->>B: How are you?
    B-->>A: Great!`,
    class: `classDiagram
    class Animal {
        +String name
        +int age
        +makeSound()
    }
    class Dog {
        +String breed
        +bark()
    }
    Animal <|-- Dog`
  }
  editorContent.value = diagramTemplates[type] || ''
  fileName.value = `new_${type}.mmd`
  detectDiagramType()
}

function useExample(type) {
  const examples = {
    flowchart: `flowchart TD
    A[Start] --> B{Decision}
    B -->|Yes| C[End]
    B -->|No| D[Retry]`,
    sequence: `sequenceDiagram
    Alice->>Bob: Hello Bob
    Bob-->>Alice: Hi Alice`,
    er: `erDiagram
    USER ||--o{ ORDER : places
    ORDER ||--|{ ITEM : contains`
  }
  editorContent.value = examples[type] || ''
  activeSubTab.value = 'editor'
  detectDiagramType()
}

async function loadTemplates() {
  loadingTemplates.value = true
  try {
    const data = await getMermaidTemplates(selectedTemplateCategory.value || null)
    templates.value = data.templates || []
    templateCategories.value = data.categories || []
  } catch (err) {
    console.error('Failed to load templates:', err)
    templates.value = []
  } finally {
    loadingTemplates.value = false
  }
}

async function selectTemplate(template) {
  loading.value = true
  error.value = ''

  try {
    // Extract category and name from template
    // Template name is already formatted (e.g., "Basic Flow"), need to convert back to ID format
    const templateName = template.name.toLowerCase().replace(/\s+/g, '-')
    const data = await getMermaidTemplate(template.category, templateName)

    editorContent.value = data.content
    fileName.value = data.filename
    detectedType.value = data.diagram_type || ''
    activeSubTab.value = 'editor'
  } catch (err) {
    console.error('Failed to load template:', err)
    error.value = err.response?.data?.detail || 'Failed to load template'
  } finally {
    loading.value = false
  }
}

function formatCategoryName(name) {
  if (!name) return ''
  return name.replace(/-/g, ' ').replace(/\b\w/g, c => c.toUpperCase())
}

function getTypeIcon(type) {
  const icons = {
    flowchart: '📊',
    graph: '📊',
    sequenceDiagram: '↔️',
    classDiagram: '📦',
    stateDiagram: '🔄',
    erDiagram: '🗄️',
    gantt: '📅',
    pie: '🥧',
    mindmap: '🧠',
    timeline: '📜',
    gitGraph: '🌳'
  }
  return icons[type] || '📋'
}

// Load initial data
onMounted(async () => {
  try {
    const typesData = await getMermaidTypes()
    diagramTypes.value = typesData.descriptions || {}

    const themesData = await getMermaidThemes()
    themes.value = themesData.themes || ['default', 'dark', 'forest', 'neutral', 'base']
  } catch (err) {
    console.error('Failed to load Mermaid config:', err)
  }

  loadTemplates()
})

// Watch for clean trigger
watch(cleanTrigger, () => {
  clearAll()
})
</script>

<style scoped>
.mermaid-panel {
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

.upload-area {
  border: 2px dashed var(--border-color);
  border-radius: 8px;
  padding: 48px;
  text-align: center;
  cursor: pointer;
  transition: all 0.3s;
  margin-bottom: 16px;
  background: var(--bg-tertiary);
}

.upload-area:hover,
.upload-area.dragover {
  border-color: var(--primary);
  background: rgba(99, 102, 241, 0.1);
}

.upload-icon {
  font-size: 48px;
  display: block;
  margin-bottom: 16px;
}

.upload-content p {
  margin: 0 0 8px;
  color: var(--text-primary);
}

.file-input {
  display: none;
}

.file-types {
  font-size: 12px;
  color: var(--text-muted);
}

.editor-wrapper {
  border: 1px solid var(--border-color);
  border-radius: 8px;
  overflow: hidden;
  margin-bottom: 16px;
}

.editor-header {
  background: var(--bg-tertiary);
  padding: 8px 16px;
  border-bottom: 1px solid var(--border-color);
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.editor-title {
  font-weight: 500;
  color: var(--text-primary);
}

.detected-type {
  font-size: 12px;
  color: var(--text-secondary);
  background: var(--bg-secondary);
  padding: 4px 8px;
  border-radius: 4px;
}

.code-editor {
  width: 100%;
  min-height: 300px;
  padding: 16px;
  font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
  font-size: 14px;
  border: none;
  resize: vertical;
  line-height: 1.5;
  background: var(--bg-secondary);
  color: var(--text-primary);
}

.code-editor:focus {
  outline: none;
}

.quick-start {
  display: flex;
  gap: 8px;
  justify-content: center;
  margin-bottom: 16px;
}

.file-actions {
  display: flex;
  gap: 8px;
  margin-bottom: 16px;
}

.options-row {
  display: flex;
  gap: 16px;
  margin-bottom: 16px;
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

.actions {
  display: flex;
  gap: 8px;
}

.btn {
  padding: 10px 20px;
  border: none;
  border-radius: 6px;
  cursor: pointer;
  font-weight: 500;
  font-size: 14px;
  transition: all 0.2s;
}

.btn-primary {
  background: var(--primary);
  color: white;
}

.btn-primary:hover:not(:disabled) {
  background: var(--primary-hover);
}

.btn-secondary {
  background: var(--bg-tertiary);
  color: var(--text-primary);
  border: 1px solid var(--border-color);
}

.btn-secondary:hover:not(:disabled) {
  background: var(--bg-secondary);
}

.btn-small {
  padding: 6px 12px;
  font-size: 13px;
}

.btn:disabled {
  opacity: 0.6;
  cursor: not-allowed;
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

.templates-section {
  padding: 0;
}

.templates-header {
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

.template-category,
.template-type {
  display: block;
  font-size: 12px;
  color: var(--text-secondary);
}

.reference-section h3 {
  margin: 0 0 16px;
  font-size: 16px;
  color: var(--text-primary);
}

.reference-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
  gap: 12px;
  margin-bottom: 24px;
}

.reference-card {
  padding: 16px;
  background: var(--bg-tertiary);
  border: 1px solid var(--border-color);
  border-radius: 8px;
  text-align: center;
}

.reference-icon {
  font-size: 24px;
  margin-bottom: 8px;
}

.reference-card h4 {
  margin: 0 0 4px 0;
  font-size: 13px;
  font-weight: 600;
  color: var(--text-primary);
}

.reference-card p {
  margin: 0;
  font-size: 11px;
  color: var(--text-secondary);
}

.examples-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.example-item {
  padding: 16px;
  background: var(--bg-tertiary);
  border: 1px solid var(--border-color);
  border-radius: 8px;
}

.example-item h4 {
  margin: 0 0 8px 0;
  font-size: 14px;
  color: var(--text-primary);
}

.example-item pre {
  background: var(--bg-secondary);
  padding: 12px;
  border-radius: 6px;
  overflow-x: auto;
  font-size: 13px;
  margin: 8px 0;
  color: var(--text-primary);
}

.result-section {
  margin-top: 16px;
  border: 1px solid var(--border-color);
  border-radius: 8px;
  overflow: hidden;
}

.result-header {
  background: var(--bg-tertiary);
  padding: 12px 16px;
  display: flex;
  justify-content: space-between;
  align-items: center;
  border-bottom: 1px solid var(--border-color);
}

.result-header h3 {
  margin: 0;
  font-size: 14px;
  color: var(--text-primary);
}

.result-actions {
  display: flex;
  gap: 8px;
}

.result-image {
  padding: 16px;
  text-align: center;
  background: var(--bg-secondary);
}

.result-image img {
  max-width: 100%;
  height: auto;
  border-radius: 4px;
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
  margin-top: 16px;
}

.error-icon {
  font-size: 18px;
}

.validation-section {
  margin-top: 16px;
  padding: 16px;
  background: var(--bg-tertiary);
  border-radius: 8px;
}

.validation-section h3 {
  margin: 0 0 12px;
  font-size: 16px;
  color: var(--text-primary);
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

.validation-errors h4 {
  margin: 12px 0 8px;
  font-size: 13px;
  font-weight: 600;
  color: var(--text-primary);
}

.validation-errors ul {
  margin: 0;
  padding-left: 20px;
}

.error-item {
  color: var(--danger);
  font-size: 13px;
  margin-bottom: 4px;
}

.validation-stats {
  display: flex;
  gap: 16px;
  margin-top: 12px;
  font-size: 13px;
  color: var(--text-secondary);
}

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
</style>
