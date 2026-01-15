<!--
  VULNEX -Universal Security Visualization Library-

  File: CloudDiagramPanel.vue
  Author: Claude Code
  Created: 2026-01-14
  Last Modified: 2026-01-14
  Version: 0.3.3
  License: Apache-2.0
  Copyright (c) 2025 VULNEX. All rights reserved.
  https://www.vulnex.com
-->
<template>
  <div class="panel cloud-panel">
    <div class="panel-header">
      <h2>Cloud Architecture Diagrams</h2>
      <p>Create cloud architecture diagrams using the Python Diagrams library - supports AWS, Azure, GCP, Kubernetes, and more</p>
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
          Providers & Icons
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
            <span class="upload-icon">☁️</span>
            <p>Drop cloud diagram config file here or click to browse</p>
            <span class="file-types">Supports: TOML, JSON, YAML</span>
          </div>
        </div>

        <!-- Config Editor - shown after file upload or new diagram -->
        <div v-if="editorContent" class="editor-wrapper">
          <div class="editor-header">
            <span class="editor-title">{{ fileName || 'Cloud Diagram' }}</span>
            <span v-if="detectedProvider" class="detected-type">Provider: {{ detectedProvider }}</span>
          </div>
          <textarea
            v-model="editorContent"
            class="code-editor"
            spellcheck="false"
            placeholder="Enter cloud diagram configuration (TOML/JSON/YAML)..."
          ></textarea>
        </div>

        <!-- Quick start button when empty -->
        <div v-if="!editorContent" class="quick-start">
          <button class="btn btn-secondary" @click="startNewDiagram('aws')">
            New AWS Diagram
          </button>
          <button class="btn btn-secondary" @click="startNewDiagram('azure')">
            New Azure Diagram
          </button>
          <button class="btn btn-secondary" @click="startNewDiagram('gcp')">
            New GCP Diagram
          </button>
          <button class="btn btn-secondary" @click="startNewDiagram('k8s')">
            New K8s Diagram
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
            <label>Direction</label>
            <select v-model="direction">
              <option value="TB">Top to Bottom</option>
              <option value="BT">Bottom to Top</option>
              <option value="LR">Left to Right</option>
              <option value="RL">Right to Left</option>
            </select>
          </div>
          <div class="option-group">
            <label>Show Legend</label>
            <select v-model="showLegend">
              <option :value="false">No</option>
              <option :value="true">Yes</option>
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
          <button class="btn btn-secondary" @click="generatePythonCode" :disabled="!canGenerate || loading">
            Generate Python Code
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
            <div class="template-icon">{{ getProviderIcon(template.category) }}</div>
            <div class="template-info">
              <h4>{{ template.name }}</h4>
              <span class="template-category">{{ formatCategoryName(template.category) }}</span>
            </div>
          </div>
        </div>

        <div v-if="!loadingTemplates && templates.length === 0" class="empty-state">
          <p>No templates found</p>
        </div>
      </div>

      <!-- Reference Tab -->
      <div v-if="activeSubTab === 'reference'" class="reference-section">
        <h3>Cloud Providers</h3>
        <div class="providers-grid">
          <div
            v-for="provider in providers"
            :key="provider.id"
            class="provider-card"
            :class="{ selected: selectedProvider === provider.id }"
            @click="selectProvider(provider.id)"
          >
            <div class="provider-icon">{{ getProviderIcon(provider.id) }}</div>
            <h4>{{ provider.name }}</h4>
            <p v-if="provider.description">{{ provider.description }}</p>
          </div>
        </div>

        <div v-if="selectedProvider" class="icons-section">
          <h3>{{ formatCategoryName(selectedProvider) }} Icons</h3>

          <div class="icons-filter">
            <div class="option-group">
              <label>Category</label>
              <select v-model="selectedIconCategory" @change="loadIcons">
                <option value="">All Categories</option>
                <option v-for="cat in iconCategories" :key="cat" :value="cat">
                  {{ formatCategoryName(cat) }}
                </option>
              </select>
            </div>
          </div>

          <div v-if="loadingIcons" class="loading-spinner">
            <span class="spinner"></span> Loading icons...
          </div>

          <div v-else class="icons-grid">
            <div v-for="icon in icons" :key="icon.id" class="icon-item" :title="icon.name" @click="copyIconId(icon)">
              <span class="icon-name">{{ icon.name }}</span>
              <code class="icon-id">{{ icon.id }}</code>
            </div>
          </div>

          <div v-if="!loadingIcons && icons.length === 0" class="empty-state">
            <p>No icons found</p>
          </div>
        </div>

        <h3>Configuration Example</h3>
        <div class="example-item">
          <pre>[cloud]
title = "My Architecture"
provider = "aws"  # aws, azure, gcp, k8s, etc.
direction = "TB"  # TB, BT, LR, RL

[[cloud.nodes]]
id = "web"
label = "Web Server"
icon = "aws.compute.EC2"

[[cloud.nodes]]
id = "db"
label = "Database"
icon = "aws.database.RDS"

[[cloud.edges]]
from = "web"
to = "db"
label = "Query"</pre>
          <button class="btn btn-small" @click="useExample">Use This Example</button>
        </div>
      </div>

      <!-- Python Code Output -->
      <div v-if="pythonCode" class="code-section">
        <div class="code-header">
          <h3>Generated Python Code</h3>
          <div class="code-actions">
            <button class="btn btn-small" @click="copyCode">Copy</button>
            <button class="btn btn-small" @click="downloadCode">Download</button>
            <button class="btn btn-small btn-secondary" @click="pythonCode = ''">Close</button>
          </div>
        </div>
        <pre class="python-code">{{ pythonCode }}</pre>
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
          <ZoomableImage :src="resultImage" alt="Generated Cloud Diagram" />
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
        <div v-if="validationResult.errors && validationResult.errors.length > 0" class="validation-errors">
          <h4>Errors</h4>
          <ul>
            <li v-for="(err, idx) in validationResult.errors" :key="idx" class="error-item">{{ err }}</li>
          </ul>
        </div>
        <div v-if="validationResult.stats" class="validation-stats">
          <span>Nodes: {{ validationResult.stats.node_count || 0 }}</span>
          <span>Edges: {{ validationResult.stats.edge_count || 0 }}</span>
          <span>Groups: {{ validationResult.stats.group_count || 0 }}</span>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, watch, inject } from 'vue'
import ZoomableImage from './ZoomableImage.vue'
import {
  visualizeCloudFromContent,
  validateCloudFromContent,
  getCloudProviders,
  getCloudIcons,
  getCloudTemplates,
  getCloudTemplate,
  generateCloudCodeFromContent
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
const direction = ref('TB')
const showLegend = ref(false)
const detectedProvider = ref('')
const isDragging = ref(false)
const loading = ref(false)
const error = ref('')
const resultImage = ref(null)
const validationResult = ref(null)
const pythonCode = ref('')

// Templates
const templates = ref([])
const templateCategories = ref([])
const selectedTemplateCategory = ref('')
const loadingTemplates = ref(false)

// Providers and Icons
const providers = ref([])
const selectedProvider = ref('')
const icons = ref([])
const iconCategories = ref([])
const selectedIconCategory = ref('')
const loadingIcons = ref(false)

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
    const configFormat = detectFormat(editorContent.value)

    const blob = await visualizeCloudFromContent(
      editorContent.value,
      format.value,
      direction.value,
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
    validationResult.value = await validateCloudFromContent(editorContent.value, configFormat)
  } catch (err) {
    error.value = err.response?.data?.detail || err.message || 'Validation failed'
  } finally {
    loading.value = false
  }
}

async function generatePythonCode() {
  if (!canGenerate.value) return

  loading.value = true
  error.value = ''
  pythonCode.value = ''

  try {
    const configFormat = detectFormat(editorContent.value)
    const result = await generateCloudCodeFromContent(editorContent.value, configFormat)
    pythonCode.value = result.code
  } catch (err) {
    error.value = err.response?.data?.detail || err.message || 'Failed to generate code'
  } finally {
    loading.value = false
  }
}

function detectFormat(content) {
  const trimmed = content.trim()
  if (trimmed.startsWith('[')) return 'toml'
  if (trimmed.startsWith('{')) return 'json'
  return 'toml'
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
    detectProvider()
  }
  reader.readAsText(file)
}

function detectProvider() {
  const content = editorContent.value.toLowerCase()
  const providerPatterns = {
    'aws': /provider\s*=\s*["']?aws/,
    'azure': /provider\s*=\s*["']?azure/,
    'gcp': /provider\s*=\s*["']?gcp/,
    'k8s': /provider\s*=\s*["']?k8s|kubernetes/,
  }

  for (const [provider, pattern] of Object.entries(providerPatterns)) {
    if (pattern.test(content)) {
      detectedProvider.value = provider.toUpperCase()
      return
    }
  }
  detectedProvider.value = ''
}

function changeFile() {
  editorContent.value = ''
  fileName.value = ''
  detectedProvider.value = ''
  resultImage.value = null
  validationResult.value = null
  pythonCode.value = ''
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
  link.download = `cloud_diagram.${format.value}`
  link.click()
}

function copyCode() {
  navigator.clipboard.writeText(pythonCode.value)
}

function downloadCode() {
  const blob = new Blob([pythonCode.value], { type: 'text/plain' })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = 'cloud_diagram.py'
  link.click()
  URL.revokeObjectURL(url)
}

function copyIconId(icon) {
  navigator.clipboard.writeText(icon.id)
}

function startNewDiagram(provider) {
  const diagramTemplates = {
    aws: `[cloud]
title = "AWS Architecture"
provider = "aws"
direction = "TB"

[[cloud.nodes]]
id = "users"
label = "Users"
icon = "aws.general.Users"

[[cloud.nodes]]
id = "alb"
label = "Load Balancer"
icon = "aws.network.ELB"

[[cloud.nodes]]
id = "ec2"
label = "Web Servers"
icon = "aws.compute.EC2"

[[cloud.nodes]]
id = "rds"
label = "Database"
icon = "aws.database.RDS"

[[cloud.edges]]
from = "users"
to = "alb"

[[cloud.edges]]
from = "alb"
to = "ec2"

[[cloud.edges]]
from = "ec2"
to = "rds"`,
    azure: `[cloud]
title = "Azure Architecture"
provider = "azure"
direction = "TB"

[[cloud.nodes]]
id = "users"
label = "Users"
icon = "azure.general.Usericon"

[[cloud.nodes]]
id = "appgw"
label = "App Gateway"
icon = "azure.network.ApplicationGateway"

[[cloud.nodes]]
id = "vm"
label = "Virtual Machines"
icon = "azure.compute.VM"

[[cloud.nodes]]
id = "sql"
label = "SQL Database"
icon = "azure.database.SQLDatabases"

[[cloud.edges]]
from = "users"
to = "appgw"

[[cloud.edges]]
from = "appgw"
to = "vm"

[[cloud.edges]]
from = "vm"
to = "sql"`,
    gcp: `[cloud]
title = "GCP Architecture"
provider = "gcp"
direction = "TB"

[[cloud.nodes]]
id = "users"
label = "Users"
icon = "gcp.compute.GCE"

[[cloud.nodes]]
id = "lb"
label = "Load Balancer"
icon = "gcp.network.LoadBalancing"

[[cloud.nodes]]
id = "gce"
label = "Compute Engine"
icon = "gcp.compute.GCE"

[[cloud.nodes]]
id = "sql"
label = "Cloud SQL"
icon = "gcp.database.SQL"

[[cloud.edges]]
from = "users"
to = "lb"

[[cloud.edges]]
from = "lb"
to = "gce"

[[cloud.edges]]
from = "gce"
to = "sql"`,
    k8s: `[cloud]
title = "Kubernetes Architecture"
provider = "k8s"
direction = "LR"

[[cloud.groups]]
id = "cluster"
label = "K8s Cluster"

[[cloud.nodes]]
id = "ingress"
label = "Ingress"
icon = "k8s.network.Ing"
group = "cluster"

[[cloud.nodes]]
id = "svc"
label = "Service"
icon = "k8s.network.SVC"
group = "cluster"

[[cloud.nodes]]
id = "deploy"
label = "Deployment"
icon = "k8s.compute.Deploy"
group = "cluster"

[[cloud.nodes]]
id = "pod"
label = "Pods"
icon = "k8s.compute.Pod"
group = "cluster"

[[cloud.edges]]
from = "ingress"
to = "svc"

[[cloud.edges]]
from = "svc"
to = "deploy"

[[cloud.edges]]
from = "deploy"
to = "pod"`
  }
  editorContent.value = diagramTemplates[provider] || diagramTemplates.aws
  fileName.value = `new_${provider}_diagram.tml`
  detectProvider()
}

function useExample() {
  editorContent.value = `[cloud]
title = "My Architecture"
provider = "aws"
direction = "TB"

[[cloud.nodes]]
id = "web"
label = "Web Server"
icon = "aws.compute.EC2"

[[cloud.nodes]]
id = "db"
label = "Database"
icon = "aws.database.RDS"

[[cloud.edges]]
from = "web"
to = "db"
label = "Query"`
  activeSubTab.value = 'editor'
  detectProvider()
}

async function loadTemplates() {
  loadingTemplates.value = true
  try {
    const data = await getCloudTemplates(selectedTemplateCategory.value || null)
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
  try {
    // Extract the actual filename from the path (e.g., "/app/templates/cloud/aws/web-application.toml" -> "web-application")
    const pathParts = template.path.split('/')
    const filenameWithExt = pathParts[pathParts.length - 1]
    const templateName = filenameWithExt.replace(/\.(toml|yaml|yml|json)$/, '')

    // Fetch the template content from the API
    const data = await getCloudTemplate(template.category, templateName)

    // Load the content into the editor
    editorContent.value = data.content
    fileName.value = data.filename || filenameWithExt
    detectedProvider.value = template.category?.toUpperCase() || ''

    // Switch to editor tab
    activeSubTab.value = 'editor'

    // Clear previous results
    resultImage.value = null
    validationResult.value = null
    error.value = ''
  } catch (err) {
    console.error('Failed to load template:', err)
    error.value = 'Failed to load template: ' + (err.response?.data?.detail || err.message)
  }
}

async function loadProviders() {
  try {
    const data = await getCloudProviders()
    providers.value = data.providers || []
  } catch (err) {
    console.error('Failed to load providers:', err)
    providers.value = [
      { id: 'aws', name: 'Amazon Web Services' },
      { id: 'azure', name: 'Microsoft Azure' },
      { id: 'gcp', name: 'Google Cloud Platform' },
      { id: 'k8s', name: 'Kubernetes' },
      { id: 'onprem', name: 'On-Premises' },
      { id: 'saas', name: 'SaaS Applications' },
      { id: 'generic', name: 'Generic Icons' },
      { id: 'programming', name: 'Programming Languages' },
      { id: 'firebase', name: 'Firebase' },
      { id: 'digitalocean', name: 'DigitalOcean' },
      { id: 'alibabacloud', name: 'Alibaba Cloud' },
      { id: 'oci', name: 'Oracle Cloud Infrastructure' },
      { id: 'openstack', name: 'OpenStack' },
      { id: 'outscale', name: 'Outscale' }
    ]
  }
}

async function selectProvider(providerId) {
  selectedProvider.value = providerId
  selectedIconCategory.value = ''
  await loadIcons()
}

async function loadIcons() {
  if (!selectedProvider.value) return

  loadingIcons.value = true
  try {
    const data = await getCloudIcons(selectedProvider.value, selectedIconCategory.value || null)
    icons.value = data.icons || []
    const cats = new Set(data.icons?.map(i => i.category).filter(Boolean) || [])
    iconCategories.value = Array.from(cats).sort()
  } catch (err) {
    console.error('Failed to load icons:', err)
    icons.value = []
  } finally {
    loadingIcons.value = false
  }
}

function formatCategoryName(name) {
  if (!name) return ''
  return name.replace(/-/g, ' ').replace(/\b\w/g, c => c.toUpperCase())
}

function getProviderIcon(provider) {
  const icons = {
    aws: '🖥️',
    azure: '☁️',
    gcp: '🌐',
    k8s: '⚙️',
    kubernetes: '⚙️',
    onprem: '🏢',
    generic: '📦',
    saas: '📱',
    outscale: '🖥️',
    alibabacloud: '☁️',
    oci: '🖥️',
    openstack: '🌐',
    firebase: '🔥',
    digitalocean: '💧',
    elastic: '🔍',
    programming: '💻'
  }
  return icons[provider?.toLowerCase()] || '☁️'
}

// Load initial data
onMounted(async () => {
  await loadProviders()
  loadTemplates()
})

// Watch for clean trigger
watch(cleanTrigger, () => {
  clearAll()
})
</script>

<style scoped>
.cloud-panel {
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
  flex-wrap: wrap;
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
  flex-wrap: wrap;
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

.template-category {
  display: block;
  font-size: 12px;
  color: var(--text-secondary);
}

.reference-section h3 {
  margin: 0 0 16px;
  font-size: 16px;
  color: var(--text-primary);
}

.providers-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(140px, 1fr));
  gap: 12px;
  margin-bottom: 24px;
}

.provider-card {
  padding: 16px;
  background: var(--bg-tertiary);
  border: 1px solid var(--border-color);
  border-radius: 8px;
  text-align: center;
  cursor: pointer;
  transition: all 0.2s ease;
}

.provider-card:hover {
  border-color: var(--primary);
  background: rgba(99, 102, 241, 0.1);
}

.provider-card.selected {
  border-color: var(--primary);
  background: rgba(99, 102, 241, 0.2);
}

.provider-icon {
  font-size: 28px;
  margin-bottom: 8px;
}

.provider-card h4 {
  margin: 0 0 4px 0;
  font-size: 12px;
  font-weight: 600;
  color: var(--text-primary);
}

.provider-card p {
  margin: 0;
  font-size: 10px;
  color: var(--text-secondary);
}

.icons-section {
  margin-top: 24px;
}

.icons-filter {
  margin-bottom: 16px;
}

.icons-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
  gap: 8px;
  max-height: 400px;
  overflow-y: auto;
}

.icon-item {
  padding: 8px 12px;
  background: var(--bg-tertiary);
  border: 1px solid var(--border-color);
  border-radius: 6px;
  cursor: pointer;
  transition: all 0.2s;
}

.icon-item:hover {
  border-color: var(--primary);
  background: rgba(99, 102, 241, 0.1);
}

.icon-name {
  display: block;
  font-size: 12px;
  font-weight: 500;
  color: var(--text-primary);
  margin-bottom: 4px;
}

.icon-id {
  display: block;
  font-size: 10px;
  color: var(--text-muted);
  background: var(--bg-secondary);
  padding: 2px 4px;
  border-radius: 3px;
}

.example-item {
  padding: 16px;
  background: var(--bg-tertiary);
  border: 1px solid var(--border-color);
  border-radius: 8px;
  margin-top: 16px;
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

.code-section {
  margin-top: 16px;
  border: 1px solid var(--border-color);
  border-radius: 8px;
  overflow: hidden;
}

.code-header {
  background: var(--bg-tertiary);
  padding: 12px 16px;
  display: flex;
  justify-content: space-between;
  align-items: center;
  border-bottom: 1px solid var(--border-color);
}

.code-header h3 {
  margin: 0;
  font-size: 14px;
  color: var(--text-primary);
}

.code-actions {
  display: flex;
  gap: 8px;
}

.python-code {
  background: #1e1e1e;
  color: #d4d4d4;
  padding: 16px;
  margin: 0;
  overflow-x: auto;
  font-size: 13px;
  max-height: 400px;
  overflow-y: auto;
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
