<!--
  VULNEX -Universal Security Visualization Library-

  File: SettingsPanel.vue
  Author: Simon Roses Femerling
  Created: 2025-01-01
  Last Modified: 2025-12-30
  Version: 0.3.3
  License: Apache-2.0
  Copyright (c) 2025 VULNEX. All rights reserved.
  https://www.vulnex.com
-->
<template>
  <div class="panel settings-panel">
    <div class="panel-header">
      <h2>Settings</h2>
      <p>Configure application preferences and view system status</p>
    </div>

    <div class="panel-body">
      <!-- API Authentication Section -->
      <div class="settings-section">
        <h3>API Authentication</h3>
        <p class="section-description">Configure your API key for authenticated access</p>
        <div class="auth-card">
          <div class="form-group">
            <label for="apiKey">API Key</label>
            <div class="api-key-input-group">
              <input
                :type="showApiKey ? 'text' : 'password'"
                id="apiKey"
                v-model="apiKeyInput"
                placeholder="Enter your API key (e.g., usecvis_xxx...)"
                class="api-key-input"
                @keyup.enter="saveApiKey"
              />
              <button
                class="btn btn-icon"
                @click="showApiKey = !showApiKey"
                :title="showApiKey ? 'Hide API key' : 'Show API key'"
              >
                {{ showApiKey ? '🙈' : '👁️' }}
              </button>
            </div>
            <span class="input-hint">Required when API authentication is enabled on the server</span>
          </div>
          <div class="auth-status" :class="{ 'has-key': hasStoredApiKey }">
            <span class="auth-status-dot"></span>
            <span class="auth-status-text">
              {{ hasStoredApiKey ? 'API key configured' : 'No API key configured' }}
            </span>
          </div>
          <div class="auth-actions">
            <button class="btn btn-primary" @click="saveApiKey" :disabled="!apiKeyInput">
              Save API Key
            </button>
            <button class="btn btn-secondary" @click="clearStoredApiKey" :disabled="!hasStoredApiKey">
              Clear API Key
            </button>
          </div>
          <div v-if="authError" class="auth-error">
            {{ authError }}
          </div>
          <div v-if="authSuccess" class="auth-success">
            {{ authSuccess }}
          </div>
        </div>
      </div>

      <!-- API Status Section -->
      <div class="settings-section">
        <h3>API Connection</h3>
        <div class="status-card" :class="{ connected: apiConnected, disconnected: !apiConnected }">
          <div class="status-indicator">
            <span class="status-dot"></span>
            <span class="status-text">{{ apiConnected ? 'Connected' : 'Disconnected' }}</span>
          </div>
          <div class="status-details" v-if="apiConnected">
            <div class="detail-row">
              <span class="detail-label">API URL:</span>
              <span class="detail-value">{{ apiUrl }}</span>
            </div>
            <div class="detail-row">
              <span class="detail-label">Version:</span>
              <span class="detail-value">{{ apiVersion }}</span>
            </div>
          </div>
          <div class="status-error" v-else>
            <p>Unable to connect to the API server. Please ensure the backend is running.</p>
          </div>
          <button class="btn btn-secondary" @click="testConnection" :disabled="testing">
            {{ testing ? 'Testing...' : 'Test Connection' }}
          </button>
        </div>
      </div>

      <!-- Modules Status -->
      <div class="settings-section" v-if="apiConnected">
        <h3>Available Modules</h3>
        <div class="modules-grid">
          <div class="module-card" :class="{ active: modules.attack_trees }">
            <span class="module-icon">🌳</span>
            <span class="module-name">Attack Trees</span>
            <span class="module-status">{{ modules.attack_trees ? 'Active' : 'Inactive' }}</span>
          </div>
          <div class="module-card" :class="{ active: modules.attack_graphs }">
            <span class="module-icon">🕸️</span>
            <span class="module-name">Attack Graphs</span>
            <span class="module-status">{{ modules.attack_graphs ? 'Active' : 'Inactive' }}</span>
          </div>
          <div class="module-card" :class="{ active: modules.threat_modeling }">
            <span class="module-icon">🔍</span>
            <span class="module-name">Threat Modeling</span>
            <span class="module-status">{{ modules.threat_modeling ? 'Active' : 'Inactive' }}</span>
          </div>
          <div class="module-card" :class="{ active: modules.binary_visualization }">
            <span class="module-icon">📊</span>
            <span class="module-name">Binary Analysis</span>
            <span class="module-status">{{ modules.binary_visualization ? 'Active' : 'Inactive' }}</span>
          </div>
          <div class="module-card" :class="{ active: modules.custom_diagrams }">
            <span class="module-icon">🎨</span>
            <span class="module-name">Custom Diagrams</span>
            <span class="module-status">{{ modules.custom_diagrams ? 'Active' : 'Inactive' }}</span>
          </div>
        </div>
      </div>

      <!-- Display Settings -->
      <div class="settings-section">
        <h3>Display Settings</h3>
        <div class="settings-form">
          <div class="form-group">
            <label for="defaultFormat">Default Output Format</label>
            <select id="defaultFormat" v-model="settings.defaultFormat">
              <option value="png">PNG</option>
              <option value="svg">SVG</option>
              <option value="pdf">PDF</option>
            </select>
          </div>
          <div class="form-group">
            <label for="theme">Theme</label>
            <select id="theme" v-model="settings.theme" @change="applyTheme">
              <option value="dark">Dark</option>
              <option value="light">Light (Coming Soon)</option>
            </select>
          </div>
        </div>
      </div>

      <!-- CVSS Display Settings -->
      <div class="settings-section" v-if="apiConnected">
        <h3>CVSS Display Settings</h3>
        <p class="section-description">Control how CVSS scores are displayed in visualizations</p>
        <div class="cvss-settings">
          <div class="cvss-toggle global-toggle">
            <label class="toggle-label">
              <input
                type="checkbox"
                v-model="cvssSettings.enabled"
                @change="updateCvssSettings"
              />
              <span class="toggle-text">Enable CVSS Display (Global)</span>
            </label>
            <span class="toggle-description">Master toggle for all CVSS display</span>
          </div>

          <div class="cvss-toggles" :class="{ disabled: !cvssSettings.enabled }">
            <div class="cvss-toggle">
              <label class="toggle-label">
                <input
                  type="checkbox"
                  v-model="cvssSettings.attack_tree"
                  @change="updateCvssSettings"
                  :disabled="!cvssSettings.enabled"
                />
                <span class="toggle-text">Attack Trees</span>
              </label>
              <span class="toggle-description">Show CVSS scores and severity colors</span>
            </div>

            <div class="cvss-toggle">
              <label class="toggle-label">
                <input
                  type="checkbox"
                  v-model="cvssSettings.attack_graph"
                  @change="updateCvssSettings"
                  :disabled="!cvssSettings.enabled"
                />
                <span class="toggle-text">Attack Graphs</span>
              </label>
              <span class="toggle-description">Show CVSS on vulnerability nodes</span>
            </div>

            <div class="cvss-toggle">
              <label class="toggle-label">
                <input
                  type="checkbox"
                  v-model="cvssSettings.threat_model"
                  @change="updateCvssSettings"
                  :disabled="!cvssSettings.enabled"
                />
                <span class="toggle-text">Threat Models</span>
              </label>
              <span class="toggle-description">Show CVSS in STRIDE reports</span>
            </div>
          </div>

          <div class="cvss-actions">
            <button class="btn btn-secondary btn-sm" @click="enableAllCvss" :disabled="cvssLoading">
              Enable All
            </button>
            <button class="btn btn-secondary btn-sm" @click="disableAllCvss" :disabled="cvssLoading">
              Disable All
            </button>
            <button class="btn btn-secondary btn-sm" @click="resetCvssSettings" :disabled="cvssLoading">
              Reset to Defaults
            </button>
          </div>
        </div>
      </div>

      <!-- Image Management Section -->
      <div class="settings-section" v-if="apiConnected">
        <h3>Image Management</h3>
        <p class="section-description">Manage uploaded images used in visualizations</p>
        <div class="image-management-card">
          <div class="image-management-header">
            <span class="image-count">{{ images.length }} image{{ images.length !== 1 ? 's' : '' }} uploaded</span>
            <button class="btn btn-secondary btn-sm" @click="loadImages" :disabled="imagesLoading">
              {{ imagesLoading ? 'Loading...' : 'Refresh' }}
            </button>
          </div>

          <div v-if="imagesLoading" class="images-loading">
            Loading images...
          </div>

          <div v-else-if="images.length === 0" class="images-empty">
            No images uploaded yet. Upload images from visualization panels.
          </div>

          <div v-else class="images-grid">
            <div v-for="image in images" :key="image.image_id" class="image-card">
              <div class="image-preview">
                <img :src="getImagePreviewUrl(image.image_id)" :alt="image.filename" @error="handleImageError" />
              </div>
              <div class="image-details">
                <span class="image-filename" :title="image.filename">{{ truncateFilename(image.filename) }}</span>
                <span class="image-size">{{ formatFileSize(image.size) }}</span>
                <span class="image-id-label">ID: <code @click="copyToClipboard(image.image_id)">{{ truncateId(image.image_id) }}</code></span>
              </div>
              <div class="image-actions">
                <button class="btn btn-icon btn-copy" @click="copyToClipboard(image.image_id)" title="Copy image ID">
                  📋
                </button>
                <button class="btn btn-icon btn-delete" @click="confirmDeleteImage(image)" title="Delete image">
                  🗑️
                </button>
              </div>
            </div>
          </div>

          <div v-if="imageDeleteError" class="image-error">
            {{ imageDeleteError }}
          </div>
        </div>

        <!-- Delete Confirmation Modal -->
        <div v-if="imageToDelete" class="modal-overlay" @click.self="imageToDelete = null">
          <div class="modal-content">
            <h4>Delete Image?</h4>
            <p>Are you sure you want to delete "{{ imageToDelete.filename }}"?</p>
            <p class="modal-warning">This action cannot be undone. Visualizations using this image will no longer display it.</p>
            <div class="modal-actions">
              <button class="btn btn-secondary" @click="imageToDelete = null">Cancel</button>
              <button class="btn btn-danger" @click="deleteSelectedImage" :disabled="deletingImage">
                {{ deletingImage ? 'Deleting...' : 'Delete' }}
              </button>
            </div>
          </div>
        </div>
      </div>

      <!-- About Section -->
      <div class="settings-section">
        <h3>About</h3>
        <div class="about-card">
          <div class="about-logo"><img src="/usecvislib_logo.png" alt="USecVisLib" class="about-logo-image" /></div>
          <div class="about-info">
            <h4>USecVisLib</h4>
            <p>Universal Security Visualization Library</p>
            <p class="version">Frontend v0.3.3</p>
          </div>
        </div>
        <div class="about-links">
          <a href="http://localhost:8000/docs" target="_blank" class="about-link">
            <span class="link-icon">📖</span>
            API Documentation
          </a>
          <a href="https://github.com/vulnex/usecvislib" target="_blank" class="about-link">
            <span class="link-icon">💻</span>
            GitHub Repository
          </a>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted, onUnmounted, watch } from 'vue'
import {
  checkHealth,
  getDisplaySettings,
  updateDisplaySettings,
  enableCvssAll,
  disableCvssAll,
  resetDisplaySettings,
  getApiKey,
  setApiKey,
  clearApiKey,
  hasApiKey,
  listImages,
  deleteImage,
  getImageUrl
} from '../services/api.js'

const props = defineProps({
  apiConnected: { type: Boolean, default: false },
  apiVersion: { type: String, default: 'Unknown' },
  modules: {
    type: Object,
    default: () => ({
      attack_trees: false,
      attack_graphs: false,
      threat_modeling: false,
      binary_visualization: false,
      custom_diagrams: false
    })
  }
})

const emit = defineEmits(['connection-change'])

const apiUrl = window.location.origin + '/api'
const testing = ref(false)
const cvssLoading = ref(false)

// API Key state
const apiKeyInput = ref('')
const showApiKey = ref(false)
const hasStoredApiKey = ref(false)
const authError = ref('')
const authSuccess = ref('')

const settings = reactive({
  defaultFormat: localStorage.getItem('defaultFormat') || 'png',
  theme: localStorage.getItem('theme') || 'dark'
})

const cvssSettings = reactive({
  enabled: true,
  attack_tree: true,
  attack_graph: true,
  threat_model: true
})

// Image Management state
const images = ref([])
const imagesLoading = ref(false)
const imageToDelete = ref(null)
const deletingImage = ref(false)
const imageDeleteError = ref('')

// API Key functions
function loadApiKeyStatus() {
  hasStoredApiKey.value = hasApiKey()
  // Don't load the actual key into the input for security
  apiKeyInput.value = ''
}

function saveApiKeyHandler() {
  if (!apiKeyInput.value) return

  setApiKey(apiKeyInput.value)
  hasStoredApiKey.value = true
  authSuccess.value = 'API key saved successfully'
  authError.value = ''

  // Clear success message after 3 seconds
  setTimeout(() => {
    authSuccess.value = ''
  }, 3000)

  // Clear input after saving
  apiKeyInput.value = ''

  // Test connection with new key
  testConnection()
}

// Alias for template
const saveApiKey = saveApiKeyHandler

function clearStoredApiKey() {
  clearApiKey()
  hasStoredApiKey.value = false
  apiKeyInput.value = ''
  authSuccess.value = 'API key cleared'
  authError.value = ''

  setTimeout(() => {
    authSuccess.value = ''
  }, 3000)
}

// Listen for auth errors from API interceptor
function handleAuthError(event) {
  authError.value = event.detail.message
  authSuccess.value = ''
}

// Image Management functions
async function loadImages() {
  imagesLoading.value = true
  imageDeleteError.value = ''
  try {
    const response = await listImages()
    images.value = response.images || []
  } catch (error) {
    console.error('Failed to load images:', error)
    imageDeleteError.value = 'Failed to load images'
  } finally {
    imagesLoading.value = false
  }
}

function getImagePreviewUrl(imageId) {
  return getImageUrl(imageId)
}

function handleImageError(event) {
  event.target.src = 'data:image/svg+xml,' + encodeURIComponent(
    '<svg xmlns="http://www.w3.org/2000/svg" width="60" height="60" viewBox="0 0 60 60">' +
    '<rect fill="#333" width="60" height="60"/>' +
    '<text fill="#666" font-size="10" x="30" y="35" text-anchor="middle">No Preview</text>' +
    '</svg>'
  )
}

function truncateFilename(filename, maxLength = 20) {
  if (!filename || filename.length <= maxLength) return filename
  const ext = filename.split('.').pop()
  const name = filename.slice(0, filename.lastIndexOf('.'))
  const truncatedName = name.slice(0, maxLength - ext.length - 4)
  return `${truncatedName}...${ext}`
}

function truncateId(id, length = 8) {
  if (!id) return ''
  return id.slice(0, length) + '...'
}

function formatFileSize(bytes) {
  if (!bytes) return '0 B'
  const units = ['B', 'KB', 'MB']
  let i = 0
  while (bytes >= 1024 && i < units.length - 1) {
    bytes /= 1024
    i++
  }
  return `${bytes.toFixed(i > 0 ? 1 : 0)} ${units[i]}`
}

async function copyToClipboard(text) {
  try {
    await navigator.clipboard.writeText(text)
  } catch (e) {
    console.error('Failed to copy:', e)
  }
}

function confirmDeleteImage(image) {
  imageToDelete.value = image
}

async function deleteSelectedImage() {
  if (!imageToDelete.value) return

  deletingImage.value = true
  imageDeleteError.value = ''

  try {
    await deleteImage(imageToDelete.value.image_id)
    images.value = images.value.filter(img => img.image_id !== imageToDelete.value.image_id)
    imageToDelete.value = null
  } catch (error) {
    console.error('Failed to delete image:', error)
    imageDeleteError.value = 'Failed to delete image'
  } finally {
    deletingImage.value = false
  }
}

onMounted(() => {
  loadApiKeyStatus()
  window.addEventListener('usecvislib:auth-error', handleAuthError)
  if (props.apiConnected) {
    loadCvssSettings()
    loadImages()
  }
})

onUnmounted(() => {
  window.removeEventListener('usecvislib:auth-error', handleAuthError)
})

async function testConnection() {
  testing.value = true
  try {
    const health = await checkHealth()
    emit('connection-change', {
      connected: true,
      version: health.version,
      modules: health.modules
    })
    // Load CVSS settings after successful connection
    await loadCvssSettings()
  } catch (error) {
    emit('connection-change', { connected: false })
  } finally {
    testing.value = false
  }
}

async function loadCvssSettings() {
  try {
    const response = await getDisplaySettings()
    if (response.cvss_display) {
      Object.assign(cvssSettings, response.cvss_display)
    }
  } catch (error) {
    console.error('Failed to load CVSS settings:', error)
  }
}

async function updateCvssSettings() {
  cvssLoading.value = true
  try {
    await updateDisplaySettings({
      cvss_display: {
        enabled: cvssSettings.enabled,
        attack_tree: cvssSettings.attack_tree,
        attack_graph: cvssSettings.attack_graph,
        threat_model: cvssSettings.threat_model
      }
    })
  } catch (error) {
    console.error('Failed to update CVSS settings:', error)
  } finally {
    cvssLoading.value = false
  }
}

async function enableAllCvss() {
  cvssLoading.value = true
  try {
    const response = await enableCvssAll()
    if (response.cvss_display) {
      Object.assign(cvssSettings, response.cvss_display)
    }
  } catch (error) {
    console.error('Failed to enable all CVSS:', error)
  } finally {
    cvssLoading.value = false
  }
}

async function disableAllCvss() {
  cvssLoading.value = true
  try {
    const response = await disableCvssAll()
    if (response.cvss_display) {
      Object.assign(cvssSettings, response.cvss_display)
    }
  } catch (error) {
    console.error('Failed to disable all CVSS:', error)
  } finally {
    cvssLoading.value = false
  }
}

async function resetCvssSettings() {
  cvssLoading.value = true
  try {
    const response = await resetDisplaySettings()
    if (response.cvss_display) {
      Object.assign(cvssSettings, response.cvss_display)
    }
  } catch (error) {
    console.error('Failed to reset CVSS settings:', error)
  } finally {
    cvssLoading.value = false
  }
}

function applyTheme() {
  localStorage.setItem('theme', settings.theme)
  // Theme switching logic would go here
}

// Watch for settings changes and save to localStorage
function saveSettings() {
  localStorage.setItem('defaultFormat', settings.defaultFormat)
}

// Load CVSS settings and images when API is connected
watch(() => props.apiConnected, (connected) => {
  if (connected) {
    loadCvssSettings()
    loadImages()
  }
})
</script>

<style scoped>
.settings-panel {
  max-width: 800px;
  margin: 0 auto;
}

.settings-section {
  margin-bottom: 2rem;
  padding-bottom: 2rem;
  border-bottom: 1px solid var(--border-color);
}

.settings-section:last-child {
  border-bottom: none;
}

.settings-section h3 {
  color: var(--primary-color);
  margin-bottom: 1rem;
  font-size: 1.2rem;
}

/* Auth Card */
.auth-card {
  background: var(--bg-tertiary);
  border-radius: 12px;
  padding: 1.5rem;
  border: 1px solid var(--border-color);
}

.api-key-input-group {
  display: flex;
  gap: 0.5rem;
  align-items: center;
}

.api-key-input {
  flex: 1;
  padding: 0.75rem;
  background: var(--bg-secondary);
  border: 1px solid var(--border-color);
  border-radius: 6px;
  color: var(--text-color);
  font-family: monospace;
  font-size: 0.95rem;
}

.api-key-input:focus {
  outline: none;
  border-color: var(--primary-color);
}

.api-key-input::placeholder {
  color: var(--text-muted);
  font-family: inherit;
}

.btn-icon {
  padding: 0.5rem 0.75rem;
  background: var(--bg-secondary);
  border: 1px solid var(--border-color);
  border-radius: 6px;
  cursor: pointer;
  font-size: 1.1rem;
  transition: all 0.2s;
}

.btn-icon:hover {
  background: var(--bg-tertiary);
  border-color: var(--primary-color);
}

.input-hint {
  display: block;
  font-size: 0.8rem;
  color: var(--text-muted);
  margin-top: 0.5rem;
}

.auth-status {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  margin: 1rem 0;
  padding: 0.75rem;
  background: var(--bg-secondary);
  border-radius: 6px;
}

.auth-status-dot {
  width: 10px;
  height: 10px;
  border-radius: 50%;
  background: var(--text-muted);
}

.auth-status.has-key .auth-status-dot {
  background: var(--success-color);
  box-shadow: 0 0 6px var(--success-color);
}

.auth-status-text {
  font-size: 0.9rem;
  color: var(--text-muted);
}

.auth-status.has-key .auth-status-text {
  color: var(--success-color);
}

.auth-actions {
  display: flex;
  gap: 0.75rem;
  margin-top: 1rem;
}

.auth-error {
  margin-top: 1rem;
  padding: 0.75rem;
  background: rgba(239, 68, 68, 0.1);
  border: 1px solid var(--error-color);
  border-radius: 6px;
  color: var(--error-color);
  font-size: 0.9rem;
}

.auth-success {
  margin-top: 1rem;
  padding: 0.75rem;
  background: rgba(34, 197, 94, 0.1);
  border: 1px solid var(--success-color);
  border-radius: 6px;
  color: var(--success-color);
  font-size: 0.9rem;
}

/* Status Card */
.status-card {
  background: var(--bg-tertiary);
  border-radius: 12px;
  padding: 1.5rem;
  border: 2px solid var(--border-color);
}

.status-card.connected {
  border-color: var(--success-color);
}

.status-card.disconnected {
  border-color: var(--error-color);
}

.status-indicator {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  margin-bottom: 1rem;
}

.status-dot {
  width: 12px;
  height: 12px;
  border-radius: 50%;
  background: var(--error-color);
}

.connected .status-dot {
  background: var(--success-color);
  box-shadow: 0 0 8px var(--success-color);
}

.status-text {
  font-size: 1.1rem;
  font-weight: 600;
}

.status-details {
  margin-bottom: 1rem;
}

.detail-row {
  display: flex;
  gap: 0.5rem;
  margin-bottom: 0.5rem;
}

.detail-label {
  color: var(--text-muted);
}

.detail-value {
  color: var(--text-color);
  font-family: monospace;
}

.status-error {
  color: var(--error-color);
  margin-bottom: 1rem;
}

/* Modules Grid */
.modules-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 1rem;
}

.module-card {
  background: var(--bg-tertiary);
  border: 1px solid var(--border-color);
  border-radius: 8px;
  padding: 1rem;
  display: flex;
  flex-direction: column;
  align-items: center;
  text-align: center;
  gap: 0.5rem;
  opacity: 0.5;
}

.module-card.active {
  opacity: 1;
  border-color: var(--success-color);
}

.module-icon {
  font-size: 2rem;
}

.module-name {
  font-weight: 600;
}

.module-status {
  font-size: 0.85rem;
  color: var(--text-muted);
}

.module-card.active .module-status {
  color: var(--success-color);
}

/* Settings Form */
.settings-form {
  display: grid;
  gap: 1rem;
}

.form-group {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.form-group label {
  font-weight: 500;
  color: var(--text-muted);
}

.form-group select {
  padding: 0.75rem;
  background: var(--bg-tertiary);
  border: 1px solid var(--border-color);
  border-radius: 6px;
  color: var(--text-color);
  font-size: 1rem;
  max-width: 300px;
}

/* About Section */
.about-card {
  display: flex;
  align-items: center;
  gap: 1.5rem;
  background: var(--bg-tertiary);
  border-radius: 12px;
  padding: 1.5rem;
  margin-bottom: 1rem;
}

.about-logo {
  font-size: 3rem;
}

.about-logo-image {
  height: 64px;
  width: auto;
  object-fit: contain;
}

.about-info h4 {
  font-size: 1.3rem;
  margin-bottom: 0.25rem;
}

.about-info p {
  color: var(--text-muted);
  margin-bottom: 0.25rem;
}

.about-info .version {
  font-family: monospace;
  font-size: 0.9rem;
}

.about-links {
  display: flex;
  gap: 1rem;
  flex-wrap: wrap;
}

.about-link {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.75rem 1rem;
  background: var(--bg-tertiary);
  border: 1px solid var(--border-color);
  border-radius: 8px;
  color: var(--text-color);
  text-decoration: none;
  transition: all 0.2s;
}

.about-link:hover {
  border-color: var(--primary-color);
  background: var(--bg-secondary);
}

.link-icon {
  font-size: 1.2rem;
}

/* CVSS Settings */
.section-description {
  color: var(--text-muted);
  font-size: 0.9rem;
  margin-bottom: 1rem;
}

.cvss-settings {
  background: var(--bg-tertiary);
  border-radius: 12px;
  padding: 1.5rem;
}

.cvss-toggle {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
  padding: 0.75rem 0;
  border-bottom: 1px solid var(--border-color);
}

.cvss-toggle:last-child {
  border-bottom: none;
}

.cvss-toggle.global-toggle {
  padding-bottom: 1rem;
  margin-bottom: 0.5rem;
  border-bottom: 2px solid var(--primary-color);
}

.toggle-label {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  cursor: pointer;
}

.toggle-label input[type="checkbox"] {
  width: 18px;
  height: 18px;
  cursor: pointer;
  accent-color: var(--primary-color);
}

.toggle-text {
  font-weight: 500;
  color: var(--text-color);
}

.toggle-description {
  font-size: 0.85rem;
  color: var(--text-muted);
  margin-left: 1.75rem;
}

.cvss-toggles.disabled {
  opacity: 0.5;
}

.cvss-toggles.disabled .toggle-label {
  cursor: not-allowed;
}

.cvss-actions {
  display: flex;
  gap: 0.75rem;
  margin-top: 1.25rem;
  padding-top: 1rem;
  border-top: 1px solid var(--border-color);
}

.btn-sm {
  padding: 0.5rem 1rem;
  font-size: 0.875rem;
}

/* Image Management */
.image-management-card {
  background: var(--bg-tertiary);
  border-radius: 12px;
  padding: 1.5rem;
}

.image-management-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 1rem;
}

.image-count {
  font-size: 0.9rem;
  color: var(--text-secondary);
}

.images-loading,
.images-empty {
  text-align: center;
  padding: 2rem;
  color: var(--text-muted);
  font-size: 0.9rem;
}

.images-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
  gap: 1rem;
  max-height: 400px;
  overflow-y: auto;
}

.image-card {
  background: var(--bg-secondary);
  border: 1px solid var(--border-color);
  border-radius: 8px;
  padding: 0.75rem;
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.image-card:hover {
  border-color: var(--primary-color);
}

.image-preview {
  width: 100%;
  height: 80px;
  display: flex;
  align-items: center;
  justify-content: center;
  background: var(--bg-primary);
  border-radius: 4px;
  overflow: hidden;
}

.image-preview img {
  max-width: 100%;
  max-height: 100%;
  object-fit: contain;
}

.image-details {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
}

.image-filename {
  font-size: 0.8rem;
  color: var(--text-color);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.image-size {
  font-size: 0.7rem;
  color: var(--text-muted);
}

.image-id-label {
  font-size: 0.7rem;
  color: var(--text-muted);
}

.image-id-label code {
  background: var(--bg-tertiary);
  padding: 0.1rem 0.3rem;
  border-radius: 3px;
  cursor: pointer;
  font-size: 0.65rem;
}

.image-id-label code:hover {
  background: var(--primary-color);
  color: white;
}

.image-actions {
  display: flex;
  justify-content: flex-end;
  gap: 0.5rem;
}

.btn-copy,
.btn-delete {
  padding: 0.25rem 0.5rem;
  font-size: 0.8rem;
  background: transparent;
  border: none;
  cursor: pointer;
  opacity: 0.7;
  transition: opacity 0.2s;
}

.btn-copy:hover,
.btn-delete:hover {
  opacity: 1;
}

.image-error {
  margin-top: 1rem;
  padding: 0.75rem;
  background: rgba(239, 68, 68, 0.1);
  border: 1px solid var(--error-color);
  border-radius: 6px;
  color: var(--error-color);
  font-size: 0.9rem;
}

/* Modal */
.modal-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(0, 0, 0, 0.7);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
}

.modal-content {
  background: var(--bg-secondary);
  border: 1px solid var(--border-color);
  border-radius: 12px;
  padding: 1.5rem;
  max-width: 400px;
  width: 90%;
}

.modal-content h4 {
  margin: 0 0 0.75rem;
  color: var(--text-color);
}

.modal-content p {
  margin: 0 0 0.75rem;
  color: var(--text-secondary);
  font-size: 0.9rem;
}

.modal-warning {
  color: var(--error-color);
  font-size: 0.85rem;
}

.modal-actions {
  display: flex;
  justify-content: flex-end;
  gap: 0.75rem;
  margin-top: 1.5rem;
}

.btn-danger {
  background: var(--error-color);
  color: white;
  border: none;
  padding: 0.5rem 1rem;
  border-radius: 6px;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-danger:hover:not(:disabled) {
  background: #dc2626;
}

.btn-danger:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}
</style>
