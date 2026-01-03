<!--
  VULNEX -Universal Security Visualization Library-

  File: IconBrowser.vue
  Author: Claude Code
  Created: 2025-12-30
  Version: 0.3.1
  License: Apache-2.0
  Copyright (c) 2025 VULNEX. All rights reserved.
  https://www.vulnex.com

  Icon Browser - Browse and select bundled icons with virtual scrolling
-->
<template>
  <div class="icon-browser" :class="{ 'browser-expanded': isExpanded }">
    <div class="browser-header">
      <h4>Bundled Icons</h4>
      <div class="header-actions">
        <button
          class="btn-icon btn-expand"
          @click="toggleExpand"
          :title="isExpanded ? 'Collapse' : 'Expand'"
        >
          {{ isExpanded ? '⊟' : '⊞' }}
        </button>
        <button
          class="btn-icon btn-close"
          @click="$emit('close')"
          title="Close"
        >
          ×
        </button>
      </div>
    </div>

    <!-- Search Bar -->
    <div class="search-bar">
      <input
        v-model="searchQuery"
        type="text"
        placeholder="Search icons..."
        class="search-input"
        @input="debouncedSearch"
      />
      <span v-if="searchQuery" class="search-clear" @click="clearSearch">×</span>
      <span class="search-icon">🔍</span>
    </div>

    <div class="browser-content">
      <!-- Categories Sidebar -->
      <div class="categories-sidebar">
        <div class="category-header">Categories</div>
        <div
          class="category-item"
          :class="{ active: !selectedCategory }"
          @click="selectCategory(null)"
        >
          <span class="category-name">All Icons</span>
          <span class="category-count">{{ totalIcons }}</span>
        </div>
        <div
          v-for="cat in categories"
          :key="cat.name"
          class="category-item"
          :class="{ active: selectedCategory === cat.name }"
          @click="selectCategory(cat.name)"
        >
          <span class="category-icon">{{ getCategoryIcon(cat.name) }}</span>
          <span class="category-name">{{ formatCategoryName(cat.name) }}</span>
          <span class="category-count">{{ cat.count }}</span>
        </div>

        <!-- Subcategories -->
        <div v-if="subcategories.length > 0" class="subcategory-section">
          <div class="category-header">Subcategories</div>
          <div
            class="category-item subcategory"
            :class="{ active: !selectedSubcategory }"
            @click="selectSubcategory(null)"
          >
            <span class="category-name">All</span>
          </div>
          <div
            v-for="sub in subcategories.slice(0, showAllSubcategories ? subcategories.length : 10)"
            :key="sub"
            class="category-item subcategory"
            :class="{ active: selectedSubcategory === sub }"
            @click="selectSubcategory(sub)"
            :title="sub"
          >
            <span class="category-name">{{ truncateSubcategory(sub) }}</span>
          </div>
          <button
            v-if="subcategories.length > 10"
            class="show-more-btn"
            @click="showAllSubcategories = !showAllSubcategories"
          >
            {{ showAllSubcategories ? 'Show Less' : `Show ${subcategories.length - 10} More` }}
          </button>
        </div>
      </div>

      <!-- Icons Grid -->
      <div class="icons-container">
        <!-- Results Info -->
        <div class="results-info">
          <span>{{ filteredTotal }} icons</span>
          <span v-if="searchQuery" class="search-tag">
            Search: "{{ searchQuery }}"
            <button class="tag-clear" @click="clearSearch">×</button>
          </span>
        </div>

        <!-- Loading State -->
        <div v-if="isLoading && icons.length === 0" class="loading-state">
          <span class="loading-spinner">⏳</span>
          <span>Loading icons...</span>
        </div>

        <!-- Icons Grid with Virtual Scroll -->
        <div
          ref="gridContainer"
          class="icons-grid-container"
          @scroll="handleScroll"
        >
          <div class="icons-grid">
            <div
              v-for="icon in icons"
              :key="icon.id"
              class="icon-item"
              :class="{ selected: selectedIcon?.id === icon.id }"
              @click="selectIcon(icon)"
              @dblclick="confirmSelection(icon)"
              :title="`${icon.name}\n${icon.category}${icon.subcategory ? '/' + icon.subcategory : ''}`"
            >
              <div class="icon-preview">
                <img
                  :src="getIconUrl(icon)"
                  :alt="icon.name"
                  loading="lazy"
                  @error="handleIconError($event)"
                />
              </div>
              <div class="icon-name">{{ truncateName(icon.name) }}</div>
            </div>
          </div>

          <!-- Load More Indicator -->
          <div v-if="hasMore" ref="loadMoreTrigger" class="load-more">
            <span v-if="isLoadingMore" class="loading-spinner">⏳</span>
            <span v-else>Scroll for more...</span>
          </div>

          <!-- No Results -->
          <div v-if="!isLoading && icons.length === 0" class="no-results">
            <span class="no-results-icon">🔍</span>
            <span>No icons found</span>
            <button v-if="searchQuery || selectedCategory" class="btn-reset" @click="resetFilters">
              Reset Filters
            </button>
          </div>
        </div>
      </div>

      <!-- Preview Panel -->
      <div class="preview-panel" v-if="selectedIcon">
        <div class="preview-header">Preview</div>
        <div class="preview-image">
          <img :src="getIconUrl(selectedIcon)" :alt="selectedIcon.name" />
        </div>
        <div class="preview-info">
          <div class="preview-row">
            <span class="preview-label">Name:</span>
            <span class="preview-value">{{ selectedIcon.name }}</span>
          </div>
          <div class="preview-row">
            <span class="preview-label">Category:</span>
            <span class="preview-value">{{ selectedIcon.category }}</span>
          </div>
          <div v-if="selectedIcon.subcategory" class="preview-row">
            <span class="preview-label">Subcategory:</span>
            <span class="preview-value">{{ selectedIcon.subcategory }}</span>
          </div>
          <div class="preview-row">
            <span class="preview-label">Format:</span>
            <span class="preview-value">{{ selectedIcon.format.toUpperCase() }}</span>
          </div>
          <div class="preview-row">
            <span class="preview-label">Size:</span>
            <span class="preview-value">{{ formatSize(selectedIcon.size) }}</span>
          </div>
          <div class="preview-row">
            <span class="preview-label">ID:</span>
            <span class="preview-value id-value" :title="selectedIcon.id">{{ selectedIcon.id }}</span>
          </div>
        </div>
        <div class="preview-actions">
          <button class="btn btn-primary" @click="confirmSelection(selectedIcon)">
            Select Icon
          </button>
          <button class="btn btn-secondary" @click="copyIconId(selectedIcon)">
            Copy ID
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, onUnmounted, watch, nextTick } from 'vue'
import { listBundledIcons, getBundledIconCategories, getBundledIconUrlById } from '../services/api.js'

const props = defineProps({
  initialCategory: { type: String, default: null }
})

const emit = defineEmits(['select', 'close'])

// State
const isExpanded = ref(false)
const isLoading = ref(false)
const isLoadingMore = ref(false)
const searchQuery = ref('')
const selectedCategory = ref(props.initialCategory)
const selectedSubcategory = ref(null)
const selectedIcon = ref(null)
const showAllSubcategories = ref(false)

// Data
const icons = ref([])
const categories = ref([])
const subcategories = ref([])
const totalIcons = ref(0)
const filteredTotal = ref(0)
const currentPage = ref(1)
const hasMore = ref(false)
const pageSize = 60

// Refs
const gridContainer = ref(null)
const loadMoreTrigger = ref(null)
let intersectionObserver = null
let searchTimeout = null

// Load categories on mount
onMounted(async () => {
  await loadCategories()
  await loadIcons()
  setupIntersectionObserver()
})

onUnmounted(() => {
  if (intersectionObserver) {
    intersectionObserver.disconnect()
  }
  if (searchTimeout) {
    clearTimeout(searchTimeout)
  }
})

// Watch for category changes
watch(selectedCategory, () => {
  selectedSubcategory.value = null
  showAllSubcategories.value = false
  resetAndLoad()
})

watch(selectedSubcategory, () => {
  resetAndLoad()
})

// Setup intersection observer for infinite scroll
function setupIntersectionObserver() {
  if (!('IntersectionObserver' in window)) return

  intersectionObserver = new IntersectionObserver(
    (entries) => {
      const entry = entries[0]
      if (entry.isIntersecting && hasMore.value && !isLoadingMore.value) {
        loadMore()
      }
    },
    { rootMargin: '100px' }
  )

  nextTick(() => {
    if (loadMoreTrigger.value) {
      intersectionObserver.observe(loadMoreTrigger.value)
    }
  })
}

// Load categories
async function loadCategories() {
  try {
    const response = await getBundledIconCategories()
    categories.value = response.categories.map(cat => ({
      name: cat,
      count: response.counts[cat] || 0
    }))
    totalIcons.value = Object.values(response.counts).reduce((a, b) => a + b, 0)
  } catch (error) {
    console.error('Failed to load categories:', error)
  }
}

// Load icons with current filters
async function loadIcons(append = false) {
  if (!append) {
    isLoading.value = true
    currentPage.value = 1
  } else {
    isLoadingMore.value = true
  }

  try {
    const response = await listBundledIcons({
      category: selectedCategory.value,
      subcategory: selectedSubcategory.value,
      search: searchQuery.value || null,
      page: currentPage.value,
      pageSize: pageSize
    })

    if (append) {
      icons.value = [...icons.value, ...response.icons]
    } else {
      icons.value = response.icons
      subcategories.value = response.subcategories || []
    }

    filteredTotal.value = response.total
    hasMore.value = response.has_more

    // Re-observe load more trigger
    nextTick(() => {
      if (loadMoreTrigger.value && intersectionObserver) {
        intersectionObserver.disconnect()
        intersectionObserver.observe(loadMoreTrigger.value)
      }
    })
  } catch (error) {
    console.error('Failed to load icons:', error)
  } finally {
    isLoading.value = false
    isLoadingMore.value = false
  }
}

// Load more icons (pagination)
async function loadMore() {
  if (isLoadingMore.value || !hasMore.value) return
  currentPage.value++
  await loadIcons(true)
}

// Reset and reload icons
function resetAndLoad() {
  icons.value = []
  currentPage.value = 1
  hasMore.value = false
  loadIcons()
}

// Debounced search
function debouncedSearch() {
  if (searchTimeout) {
    clearTimeout(searchTimeout)
  }
  searchTimeout = setTimeout(() => {
    resetAndLoad()
  }, 300)
}

// Clear search
function clearSearch() {
  searchQuery.value = ''
  resetAndLoad()
}

// Select category
function selectCategory(category) {
  selectedCategory.value = category
}

// Select subcategory
function selectSubcategory(subcategory) {
  selectedSubcategory.value = subcategory
}

// Select icon
function selectIcon(icon) {
  selectedIcon.value = icon
}

// Confirm selection and emit
function confirmSelection(icon) {
  emit('select', icon)
}

// Copy icon ID to clipboard
async function copyIconId(icon) {
  try {
    await navigator.clipboard.writeText(icon.id)
    // Could show a toast notification here
  } catch (error) {
    console.error('Failed to copy:', error)
  }
}

// Reset all filters
function resetFilters() {
  searchQuery.value = ''
  selectedCategory.value = null
  selectedSubcategory.value = null
  resetAndLoad()
}

// Toggle expanded mode
function toggleExpand() {
  isExpanded.value = !isExpanded.value
}

// Handle scroll (fallback for intersection observer)
function handleScroll(event) {
  const container = event.target
  const scrollBottom = container.scrollHeight - container.scrollTop - container.clientHeight
  if (scrollBottom < 200 && hasMore.value && !isLoadingMore.value) {
    loadMore()
  }
}

// Get icon URL
function getIconUrl(icon) {
  return getBundledIconUrlById(icon.id)
}

// Handle icon load error
function handleIconError(event) {
  event.target.src = 'data:image/svg+xml,' + encodeURIComponent(
    '<svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 48 48">' +
    '<rect fill="#2d2d2d" width="48" height="48" rx="4"/>' +
    '<text fill="#666" font-size="10" x="24" y="28" text-anchor="middle">?</text>' +
    '</svg>'
  )
}

// Utility functions
function getCategoryIcon(category) {
  const icons = {
    azure: '☁️',
    aws: '🔶',
    bootstrap: '🅱️'
  }
  return icons[category] || '📁'
}

function formatCategoryName(name) {
  return name.charAt(0).toUpperCase() + name.slice(1)
}

function truncateName(name, maxLength = 12) {
  if (name.length <= maxLength) return name
  return name.slice(0, maxLength - 2) + '...'
}

function truncateSubcategory(sub, maxLength = 20) {
  if (sub.length <= maxLength) return sub
  return sub.slice(0, maxLength - 2) + '...'
}

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
</script>

<style scoped>
.icon-browser {
  display: flex;
  flex-direction: column;
  background: var(--bg-secondary);
  border: 1px solid var(--border-color);
  border-radius: 8px;
  height: 400px;
  transition: height 0.3s ease;
}

.icon-browser.browser-expanded {
  height: 600px;
}

.browser-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 0.75rem 1rem;
  border-bottom: 1px solid var(--border-color);
}

.browser-header h4 {
  margin: 0;
  font-size: 0.95rem;
  color: var(--text-primary);
}

.header-actions {
  display: flex;
  gap: 0.5rem;
}

.btn-icon {
  background: none;
  border: none;
  cursor: pointer;
  font-size: 1.2rem;
  color: var(--text-tertiary);
  padding: 0.25rem;
  line-height: 1;
  border-radius: 4px;
  transition: all 0.2s;
}

.btn-icon:hover {
  color: var(--text-primary);
  background: var(--bg-tertiary);
}

/* Search Bar */
.search-bar {
  position: relative;
  padding: 0.5rem 1rem;
  border-bottom: 1px solid var(--border-color);
}

.search-input {
  width: 100%;
  padding: 0.5rem 2rem 0.5rem 2rem;
  border: 1px solid var(--border-color);
  border-radius: 6px;
  background: var(--bg-tertiary);
  color: var(--text-primary);
  font-size: 0.85rem;
}

.search-input:focus {
  outline: none;
  border-color: var(--primary);
}

.search-icon {
  position: absolute;
  left: 1.5rem;
  top: 50%;
  transform: translateY(-50%);
  font-size: 0.9rem;
  opacity: 0.5;
}

.search-clear {
  position: absolute;
  right: 1.5rem;
  top: 50%;
  transform: translateY(-50%);
  cursor: pointer;
  font-size: 1rem;
  color: var(--text-tertiary);
}

.search-clear:hover {
  color: var(--text-primary);
}

/* Browser Content Layout */
.browser-content {
  display: flex;
  flex: 1;
  overflow: hidden;
}

/* Categories Sidebar */
.categories-sidebar {
  width: 160px;
  border-right: 1px solid var(--border-color);
  overflow-y: auto;
  flex-shrink: 0;
}

.category-header {
  padding: 0.5rem 0.75rem;
  font-size: 0.7rem;
  font-weight: 600;
  text-transform: uppercase;
  color: var(--text-tertiary);
  letter-spacing: 0.05em;
}

.category-item {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.5rem 0.75rem;
  cursor: pointer;
  font-size: 0.8rem;
  color: var(--text-secondary);
  transition: all 0.15s;
}

.category-item:hover {
  background: var(--bg-tertiary);
  color: var(--text-primary);
}

.category-item.active {
  background: rgba(var(--primary-rgb), 0.15);
  color: var(--primary);
  font-weight: 500;
}

.category-icon {
  font-size: 0.9rem;
}

.category-name {
  flex: 1;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.category-count {
  font-size: 0.7rem;
  background: var(--bg-tertiary);
  padding: 0.1rem 0.4rem;
  border-radius: 10px;
  color: var(--text-tertiary);
}

.subcategory-section {
  border-top: 1px solid var(--border-color);
  margin-top: 0.5rem;
}

.category-item.subcategory {
  padding-left: 1rem;
  font-size: 0.75rem;
}

.show-more-btn {
  width: 100%;
  padding: 0.5rem;
  font-size: 0.7rem;
  color: var(--primary);
  background: none;
  border: none;
  cursor: pointer;
  text-align: left;
  padding-left: 1rem;
}

.show-more-btn:hover {
  text-decoration: underline;
}

/* Icons Container */
.icons-container {
  flex: 1;
  display: flex;
  flex-direction: column;
  overflow: hidden;
}

.results-info {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.5rem 0.75rem;
  font-size: 0.75rem;
  color: var(--text-tertiary);
  border-bottom: 1px solid var(--border-color);
}

.search-tag {
  display: flex;
  align-items: center;
  gap: 0.25rem;
  background: rgba(var(--primary-rgb), 0.15);
  color: var(--primary);
  padding: 0.15rem 0.5rem;
  border-radius: 4px;
}

.tag-clear {
  background: none;
  border: none;
  cursor: pointer;
  color: var(--primary);
  font-size: 0.9rem;
  line-height: 1;
  padding: 0;
}

.icons-grid-container {
  flex: 1;
  overflow-y: auto;
  padding: 0.5rem;
}

.icons-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(70px, 1fr));
  gap: 0.5rem;
}

.icon-item {
  display: flex;
  flex-direction: column;
  align-items: center;
  padding: 0.5rem;
  background: var(--bg-tertiary);
  border: 2px solid transparent;
  border-radius: 6px;
  cursor: pointer;
  transition: all 0.15s;
}

.icon-item:hover {
  border-color: var(--border-color);
  background: var(--bg-primary);
}

.icon-item.selected {
  border-color: var(--primary);
  background: rgba(var(--primary-rgb), 0.1);
}

.icon-preview {
  width: 48px;
  height: 48px;
  display: flex;
  align-items: center;
  justify-content: center;
}

.icon-preview img {
  max-width: 100%;
  max-height: 100%;
  object-fit: contain;
}

.icon-name {
  font-size: 0.65rem;
  color: var(--text-tertiary);
  text-align: center;
  margin-top: 0.25rem;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  width: 100%;
}

/* Load More */
.load-more {
  display: flex;
  justify-content: center;
  align-items: center;
  padding: 1rem;
  font-size: 0.8rem;
  color: var(--text-tertiary);
}

/* Loading State */
.loading-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 0.5rem;
  padding: 2rem;
  color: var(--text-tertiary);
}

.loading-spinner {
  animation: spin 1s linear infinite;
}

@keyframes spin {
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
}

/* No Results */
.no-results {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 0.5rem;
  padding: 2rem;
  color: var(--text-tertiary);
}

.no-results-icon {
  font-size: 2rem;
  opacity: 0.5;
}

.btn-reset {
  margin-top: 0.5rem;
  padding: 0.35rem 0.75rem;
  font-size: 0.8rem;
  background: var(--bg-tertiary);
  border: 1px solid var(--border-color);
  border-radius: 4px;
  color: var(--text-primary);
  cursor: pointer;
}

.btn-reset:hover {
  border-color: var(--primary);
}

/* Preview Panel */
.preview-panel {
  width: 180px;
  border-left: 1px solid var(--border-color);
  display: flex;
  flex-direction: column;
  flex-shrink: 0;
}

.preview-header {
  padding: 0.5rem 0.75rem;
  font-size: 0.7rem;
  font-weight: 600;
  text-transform: uppercase;
  color: var(--text-tertiary);
  letter-spacing: 0.05em;
  border-bottom: 1px solid var(--border-color);
}

.preview-image {
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 1rem;
  background: var(--bg-tertiary);
  min-height: 100px;
}

.preview-image img {
  max-width: 80px;
  max-height: 80px;
  object-fit: contain;
}

.preview-info {
  padding: 0.75rem;
  flex: 1;
  overflow-y: auto;
}

.preview-row {
  display: flex;
  flex-direction: column;
  margin-bottom: 0.5rem;
}

.preview-label {
  font-size: 0.65rem;
  color: var(--text-tertiary);
  text-transform: uppercase;
  margin-bottom: 0.1rem;
}

.preview-value {
  font-size: 0.8rem;
  color: var(--text-primary);
  word-break: break-word;
}

.preview-value.id-value {
  font-family: monospace;
  font-size: 0.7rem;
  background: var(--bg-tertiary);
  padding: 0.25rem;
  border-radius: 3px;
}

.preview-actions {
  padding: 0.75rem;
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  border-top: 1px solid var(--border-color);
}

.btn {
  padding: 0.5rem 0.75rem;
  border-radius: 6px;
  font-size: 0.8rem;
  cursor: pointer;
  transition: all 0.2s;
  border: 1px solid transparent;
  text-align: center;
}

.btn-primary {
  background: var(--primary);
  color: white;
}

.btn-primary:hover {
  opacity: 0.9;
}

.btn-secondary {
  background: var(--bg-tertiary);
  color: var(--text-primary);
  border-color: var(--border-color);
}

.btn-secondary:hover {
  border-color: var(--primary);
}

/* Responsive adjustments */
@media (max-width: 768px) {
  .categories-sidebar {
    width: 120px;
  }

  .preview-panel {
    display: none;
  }

  .icons-grid {
    grid-template-columns: repeat(auto-fill, minmax(60px, 1fr));
  }
}
</style>
