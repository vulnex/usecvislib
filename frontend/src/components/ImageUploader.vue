<!--
  VULNEX -Universal Security Visualization Library-

  File: ImageUploader.vue
  Author: Claude Code
  Created: 2025-12-30
  Version: 0.3.1
  License: Apache-2.0
  Copyright (c) 2025 VULNEX. All rights reserved.
  https://www.vulnex.com
-->
<template>
  <div class="image-uploader">
    <div class="uploader-header">
      <h4>{{ title }}</h4>
      <button
        v-if="selectedImageId"
        class="btn btn-small btn-clear"
        @click="clearSelection"
        title="Clear image selection"
      >
        Clear Selection
      </button>
    </div>

    <!-- Tab Navigation -->
    <div class="tab-nav">
      <button
        class="tab-btn"
        :class="{ active: activeTab === 'upload' }"
        @click="activeTab = 'upload'"
      >
        Upload
      </button>
      <button
        class="tab-btn"
        :class="{ active: activeTab === 'bundled' }"
        @click="activeTab = 'bundled'"
      >
        Bundled Icons
      </button>
    </div>

    <!-- Upload Tab -->
    <div v-show="activeTab === 'upload'" class="tab-content">
    <!-- Drop Zone -->
    <div
      class="drop-zone"
      :class="{ 'drag-over': isDragging, 'has-error': uploadError }"
      @dragenter.prevent="handleDragEnter"
      @dragover.prevent="handleDragOver"
      @dragleave.prevent="handleDragLeave"
      @drop.prevent="handleDrop"
      @click="triggerFileInput"
    >
      <input
        ref="fileInput"
        type="file"
        accept="image/png,image/jpeg,image/gif,image/svg+xml,image/bmp"
        @change="handleFileSelect"
        hidden
      />
      <div class="drop-zone-content">
        <span class="drop-icon">{{ isDragging ? '📥' : '🖼️' }}</span>
        <span class="drop-text">
          {{ isDragging ? 'Drop image here' : 'Click or drag image to upload' }}
        </span>
        <span class="drop-hint">PNG, JPEG, GIF, SVG, BMP (max 5MB)</span>
      </div>
    </div>

    <!-- Upload Progress -->
    <div v-if="isUploading" class="upload-progress">
      <div class="progress-bar">
        <div class="progress-fill" :style="{ width: uploadProgress + '%' }"></div>
      </div>
      <span class="progress-text">Uploading...</span>
    </div>

    <!-- Upload Error -->
    <div v-if="uploadError" class="upload-error">
      <span class="error-icon">⚠️</span>
      <span class="error-text">{{ uploadError }}</span>
      <button class="btn-dismiss" @click="uploadError = ''">×</button>
    </div>

    <!-- Image List -->
    <div class="image-list" v-if="images.length > 0">
      <div class="image-list-header">
        <span>Available Images ({{ images.length }})</span>
        <button
          class="btn btn-small btn-refresh"
          @click="loadImages"
          :disabled="isLoading"
          title="Refresh image list"
        >
          {{ isLoading ? '...' : '↻' }}
        </button>
      </div>
      <div class="image-grid">
        <div
          v-for="image in images"
          :key="image.image_id"
          class="image-item"
          :class="{ selected: selectedImageId === image.image_id }"
          @click="selectImage(image)"
        >
          <div class="image-preview">
            <img
              :src="getImagePreviewUrl(image.image_id)"
              :alt="image.filename || 'Image'"
              @error="handleImageError($event, image)"
            />
          </div>
          <div class="image-info">
            <span class="image-name" :title="image.filename">
              {{ truncateFilename(image.filename || image.image_id) }}
            </span>
            <span class="image-size">{{ formatSize(image.size) }}</span>
          </div>
          <div class="image-actions">
            <button
              class="btn-icon btn-select"
              :class="{ active: selectedImageId === image.image_id }"
              @click.stop="selectImage(image)"
              title="Select this image"
            >
              {{ selectedImageId === image.image_id ? '✓' : '○' }}
            </button>
            <button
              class="btn-icon btn-delete"
              @click.stop="confirmDelete(image)"
              title="Delete image"
            >
              🗑️
            </button>
          </div>
        </div>
      </div>
    </div>

    <!-- Empty State -->
    <div v-else-if="!isLoading" class="empty-state">
      <span class="empty-icon">📷</span>
      <span class="empty-text">No images uploaded yet</span>
    </div>

    <!-- Loading State -->
    <div v-if="isLoading && images.length === 0" class="loading-state">
      <span class="loading-spinner">⏳</span>
      <span class="loading-text">Loading images...</span>
    </div>
    </div><!-- End Upload Tab -->

    <!-- Bundled Icons Tab -->
    <div v-show="activeTab === 'bundled'" class="tab-content">
      <IconBrowser
        @select="handleBundledIconSelect"
        @close="activeTab = 'upload'"
      />
    </div>

    <!-- Delete Confirmation Modal -->
    <div v-if="deleteConfirm" class="modal-overlay" @click.self="deleteConfirm = null">
      <div class="modal-content">
        <h4>Delete Image?</h4>
        <p>Are you sure you want to delete "{{ deleteConfirm.filename || deleteConfirm.image_id }}"?</p>
        <div class="modal-actions">
          <button class="btn btn-secondary" @click="deleteConfirm = null">Cancel</button>
          <button class="btn btn-danger" @click="deleteImage(deleteConfirm)">Delete</button>
        </div>
      </div>
    </div>

    <!-- Selected Image Display -->
    <div v-if="selectedImageId" class="selected-image-display">
      <span class="selected-label">Selected:</span>
      <span class="selected-source" :class="selectedImageSource">
        {{ selectedImageSource === 'bundled' ? 'Bundled' : 'Uploaded' }}
      </span>
      <span class="selected-id">{{ selectedImageId }}</span>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted, watch } from 'vue'
import {
  uploadImage,
  getImageInfo,
  deleteImage as apiDeleteImage,
  listImages,
  getImageUrl,
  getBundledIconUrlById
} from '../services/api.js'
import IconBrowser from './IconBrowser.vue'

const props = defineProps({
  title: { type: String, default: 'Node Image' },
  modelValue: { type: String, default: '' },
  autoLoad: { type: Boolean, default: true }
})

const emit = defineEmits(['update:modelValue', 'image-selected', 'image-uploaded', 'image-deleted'])

// State
const fileInput = ref(null)
const images = ref([])
const selectedImageId = ref(props.modelValue)
const selectedImageSource = ref('') // 'uploaded' or 'bundled'
const isLoading = ref(false)
const isUploading = ref(false)
const uploadProgress = ref(0)
const uploadError = ref('')
const isDragging = ref(false)
const deleteConfirm = ref(null)
const activeTab = ref('upload')
let dragCounter = 0

// Watch for external modelValue changes
watch(() => props.modelValue, (newValue) => {
  selectedImageId.value = newValue
})

// Load images on mount
onMounted(() => {
  if (props.autoLoad) {
    loadImages()
  }
})

// Load image list from API
async function loadImages() {
  isLoading.value = true
  try {
    const response = await listImages()
    images.value = response.images || []
  } catch (error) {
    console.error('Failed to load images:', error)
    uploadError.value = 'Failed to load images'
  } finally {
    isLoading.value = false
  }
}

// Trigger file input click
function triggerFileInput() {
  fileInput.value?.click()
}

// Handle file selection from input
function handleFileSelect(event) {
  const file = event.target.files?.[0]
  if (file) {
    uploadFile(file)
  }
  // Reset input so same file can be selected again
  event.target.value = ''
}

// Drag and drop handlers
function handleDragEnter(event) {
  dragCounter++
  isDragging.value = true
}

function handleDragOver(event) {
  event.dataTransfer.dropEffect = 'copy'
}

function handleDragLeave(event) {
  dragCounter--
  if (dragCounter === 0) {
    isDragging.value = false
  }
}

function handleDrop(event) {
  dragCounter = 0
  isDragging.value = false

  const file = event.dataTransfer.files?.[0]
  if (file) {
    // Validate file type
    const validTypes = ['image/png', 'image/jpeg', 'image/gif', 'image/svg+xml', 'image/bmp']
    if (!validTypes.includes(file.type)) {
      uploadError.value = 'Invalid file type. Please upload PNG, JPEG, GIF, SVG, or BMP.'
      return
    }
    uploadFile(file)
  }
}

// Upload file to API
async function uploadFile(file) {
  // Validate size (5MB max)
  if (file.size > 5 * 1024 * 1024) {
    uploadError.value = 'File too large. Maximum size is 5MB.'
    return
  }

  uploadError.value = ''
  isUploading.value = true
  uploadProgress.value = 0

  // Simulate progress (actual progress would need XMLHttpRequest)
  const progressInterval = setInterval(() => {
    if (uploadProgress.value < 90) {
      uploadProgress.value += 10
    }
  }, 100)

  try {
    const response = await uploadImage(file)
    uploadProgress.value = 100

    // Add to images list
    images.value.unshift({
      image_id: response.image_id,
      filename: response.filename,
      size: response.size,
      content_type: response.content_type
    })

    // Auto-select uploaded image
    selectImage({ image_id: response.image_id })

    emit('image-uploaded', response)
  } catch (error) {
    console.error('Upload failed:', error)
    uploadError.value = error.response?.data?.detail || 'Upload failed'
  } finally {
    clearInterval(progressInterval)
    isUploading.value = false
    uploadProgress.value = 0
  }
}

// Select an uploaded image
function selectImage(image) {
  selectedImageId.value = image.image_id
  selectedImageSource.value = 'uploaded'
  emit('update:modelValue', image.image_id)
  emit('image-selected', { ...image, source: 'uploaded' })
}

// Handle bundled icon selection
function handleBundledIconSelect(icon) {
  selectedImageId.value = icon.id
  selectedImageSource.value = 'bundled'
  emit('update:modelValue', icon.id)
  emit('image-selected', {
    image_id: icon.id,
    filename: icon.name,
    source: 'bundled',
    icon_url: getBundledIconUrlById(icon.id)
  })
}

// Clear selection
function clearSelection() {
  selectedImageId.value = ''
  selectedImageSource.value = ''
  emit('update:modelValue', '')
  emit('image-selected', null)
}

// Confirm delete
function confirmDelete(image) {
  deleteConfirm.value = image
}

// Delete image
async function deleteImage(image) {
  try {
    await apiDeleteImage(image.image_id)

    // Remove from list
    images.value = images.value.filter(img => img.image_id !== image.image_id)

    // Clear selection if deleted image was selected
    if (selectedImageId.value === image.image_id) {
      clearSelection()
    }

    emit('image-deleted', image)
  } catch (error) {
    console.error('Delete failed:', error)
    uploadError.value = 'Failed to delete image'
  } finally {
    deleteConfirm.value = null
  }
}

// Get preview URL for image
function getImagePreviewUrl(imageId) {
  return getImageUrl(imageId)
}

// Handle image load error
function handleImageError(event, image) {
  // Set a placeholder
  event.target.src = 'data:image/svg+xml,' + encodeURIComponent(
    '<svg xmlns="http://www.w3.org/2000/svg" width="60" height="60" viewBox="0 0 60 60">' +
    '<rect fill="#333" width="60" height="60"/>' +
    '<text fill="#666" font-size="12" x="30" y="35" text-anchor="middle">No Preview</text>' +
    '</svg>'
  )
}

// Utility: Truncate filename
function truncateFilename(filename, maxLength = 20) {
  if (filename.length <= maxLength) return filename
  const ext = filename.split('.').pop()
  const name = filename.slice(0, filename.lastIndexOf('.'))
  const truncatedName = name.slice(0, maxLength - ext.length - 4)
  return `${truncatedName}...${ext}`
}

// Utility: Format file size
function formatSize(bytes) {
  if (!bytes) return '0 B'
  const units = ['B', 'KB', 'MB']
  let i = 0
  while (bytes >= 1024 && i < units.length - 1) {
    bytes /= 1024
    i++
  }
  return `${bytes.toFixed(i > 0 ? 1 : 0)} ${units[i]}`
}

// Expose methods for parent components
defineExpose({
  loadImages,
  selectImage,
  clearSelection,
  getSelectedImageId: () => selectedImageId.value
})
</script>

<style scoped>
.image-uploader {
  background: var(--bg-secondary);
  border: 1px solid var(--border-color);
  border-radius: 8px;
  padding: 1rem;
}

.uploader-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 0.75rem;
}

.uploader-header h4 {
  margin: 0;
  font-size: 0.95rem;
  color: var(--text-primary);
}

.btn-clear {
  font-size: 0.75rem;
  padding: 0.25rem 0.5rem;
}

/* Tab Navigation */
.tab-nav {
  display: flex;
  border-bottom: 1px solid var(--border-color);
  margin-bottom: 0.75rem;
}

.tab-btn {
  flex: 1;
  padding: 0.5rem 1rem;
  background: none;
  border: none;
  border-bottom: 2px solid transparent;
  color: var(--text-secondary);
  font-size: 0.85rem;
  cursor: pointer;
  transition: all 0.2s;
}

.tab-btn:hover {
  color: var(--text-primary);
  background: var(--bg-tertiary);
}

.tab-btn.active {
  color: var(--primary);
  border-bottom-color: var(--primary);
  font-weight: 500;
}

.tab-content {
  /* Tab content wrapper */
}

/* Drop Zone */
.drop-zone {
  border: 2px dashed var(--border-color);
  border-radius: 8px;
  padding: 1.5rem;
  text-align: center;
  cursor: pointer;
  transition: all 0.2s;
  background: var(--bg-tertiary);
}

.drop-zone:hover {
  border-color: var(--primary);
  background: rgba(var(--primary-rgb), 0.05);
}

.drop-zone.drag-over {
  border-color: var(--primary);
  background: rgba(var(--primary-rgb), 0.1);
  transform: scale(1.01);
}

.drop-zone.has-error {
  border-color: var(--danger);
}

.drop-zone-content {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 0.5rem;
}

.drop-icon {
  font-size: 2rem;
}

.drop-text {
  font-size: 0.9rem;
  color: var(--text-primary);
}

.drop-hint {
  font-size: 0.75rem;
  color: var(--text-tertiary);
}

/* Upload Progress */
.upload-progress {
  margin-top: 0.75rem;
}

.progress-bar {
  height: 4px;
  background: var(--bg-tertiary);
  border-radius: 2px;
  overflow: hidden;
}

.progress-fill {
  height: 100%;
  background: var(--primary);
  transition: width 0.1s ease;
}

.progress-text {
  display: block;
  font-size: 0.75rem;
  color: var(--text-tertiary);
  margin-top: 0.25rem;
}

/* Upload Error */
.upload-error {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  margin-top: 0.75rem;
  padding: 0.5rem 0.75rem;
  background: rgba(239, 68, 68, 0.1);
  border: 1px solid var(--danger);
  border-radius: 6px;
  color: var(--danger);
  font-size: 0.85rem;
}

.error-icon {
  flex-shrink: 0;
}

.error-text {
  flex: 1;
}

.btn-dismiss {
  background: none;
  border: none;
  color: var(--danger);
  font-size: 1.2rem;
  cursor: pointer;
  padding: 0;
  line-height: 1;
}

/* Image List */
.image-list {
  margin-top: 1rem;
}

.image-list-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 0.5rem;
  font-size: 0.85rem;
  color: var(--text-secondary);
}

.btn-refresh {
  padding: 0.25rem 0.5rem;
  font-size: 0.85rem;
  min-width: 28px;
}

.image-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(140px, 1fr));
  gap: 0.75rem;
  max-height: 300px;
  overflow-y: auto;
}

.image-item {
  background: var(--bg-tertiary);
  border: 2px solid var(--border-color);
  border-radius: 8px;
  padding: 0.5rem;
  cursor: pointer;
  transition: all 0.2s;
}

.image-item:hover {
  border-color: var(--primary);
}

.image-item.selected {
  border-color: var(--success);
  background: rgba(16, 185, 129, 0.1);
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
  margin-bottom: 0.5rem;
}

.image-preview img {
  max-width: 100%;
  max-height: 100%;
  object-fit: contain;
}

.image-info {
  display: flex;
  flex-direction: column;
  gap: 0.15rem;
  margin-bottom: 0.5rem;
}

.image-name {
  font-size: 0.75rem;
  color: var(--text-primary);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.image-size {
  font-size: 0.7rem;
  color: var(--text-tertiary);
}

.image-actions {
  display: flex;
  justify-content: space-between;
  gap: 0.5rem;
}

.btn-icon {
  background: none;
  border: none;
  cursor: pointer;
  padding: 0.25rem;
  font-size: 0.9rem;
  border-radius: 4px;
  transition: all 0.2s;
}

.btn-select {
  color: var(--text-tertiary);
}

.btn-select:hover,
.btn-select.active {
  color: var(--success);
}

.btn-delete {
  opacity: 0.6;
}

.btn-delete:hover {
  opacity: 1;
}

/* Empty State */
.empty-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 0.5rem;
  padding: 2rem 1rem;
  color: var(--text-tertiary);
}

.empty-icon {
  font-size: 2rem;
  opacity: 0.5;
}

.empty-text {
  font-size: 0.9rem;
}

/* Loading State */
.loading-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 0.5rem;
  padding: 2rem 1rem;
  color: var(--text-tertiary);
}

.loading-spinner {
  font-size: 1.5rem;
  animation: spin 1s linear infinite;
}

@keyframes spin {
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
}

.loading-text {
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
  color: var(--text-primary);
}

.modal-content p {
  margin: 0 0 1.5rem;
  color: var(--text-secondary);
  font-size: 0.9rem;
}

.modal-actions {
  display: flex;
  justify-content: flex-end;
  gap: 0.75rem;
}

/* Selected Image Display */
.selected-image-display {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  margin-top: 0.75rem;
  padding: 0.5rem 0.75rem;
  background: rgba(16, 185, 129, 0.1);
  border: 1px solid var(--success);
  border-radius: 6px;
  font-size: 0.8rem;
}

.selected-label {
  color: var(--success);
  font-weight: 500;
}

.selected-source {
  font-size: 0.7rem;
  padding: 0.1rem 0.4rem;
  border-radius: 3px;
  font-weight: 500;
}

.selected-source.uploaded {
  background: rgba(59, 130, 246, 0.2);
  color: #3b82f6;
}

.selected-source.bundled {
  background: rgba(168, 85, 247, 0.2);
  color: #a855f7;
}

.selected-id {
  color: var(--text-secondary);
  font-family: monospace;
  font-size: 0.75rem;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  flex: 1;
}

/* Button styles */
.btn {
  padding: 0.5rem 1rem;
  border-radius: 6px;
  font-size: 0.9rem;
  cursor: pointer;
  transition: all 0.2s;
  border: 1px solid transparent;
}

.btn-small {
  padding: 0.35rem 0.65rem;
  font-size: 0.8rem;
}

.btn-secondary {
  background: var(--bg-tertiary);
  color: var(--text-primary);
  border-color: var(--border-color);
}

.btn-secondary:hover:not(:disabled) {
  background: var(--bg-primary);
  border-color: var(--primary);
}

.btn-danger {
  background: var(--danger);
  color: white;
}

.btn-danger:hover:not(:disabled) {
  background: #dc2626;
}

.btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}
</style>
