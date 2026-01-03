<!--
  VULNEX -Universal Security Visualization Library-

  File: TemplateMetadata.vue
  Author: Simon Roses Femerling
  Created: 2025-12-25
  Last Modified: 2025-12-25
  Version: 0.3.1
  License: Apache-2.0
  Copyright (c) 2025 VULNEX. All rights reserved.
  https://www.vulnex.com
-->
<template>
  <div v-if="hasMetadata" class="metadata-section">
    <div class="metadata-header" @click="isExpanded = !isExpanded">
      <h4>
        <span class="metadata-icon">&#x1F4CB;</span>
        Template Metadata
        <span class="expand-icon">{{ isExpanded ? '&#x25BC;' : '&#x25B6;' }}</span>
      </h4>
    </div>
    <div v-show="isExpanded" class="metadata-content">
      <div class="metadata-grid">
        <div v-if="metadata.name" class="metadata-item">
          <span class="metadata-label">Name</span>
          <span class="metadata-value">{{ metadata.name }}</span>
        </div>
        <div v-if="metadata.description" class="metadata-item full-width">
          <span class="metadata-label">Description</span>
          <span class="metadata-value">{{ metadata.description }}</span>
        </div>
        <div v-if="metadata.type" class="metadata-item">
          <span class="metadata-label">Type</span>
          <span class="metadata-value type-badge">{{ metadata.type }}</span>
        </div>
        <div v-if="metadata.version" class="metadata-item">
          <span class="metadata-label">Template Version</span>
          <span class="metadata-value">{{ metadata.version }}</span>
        </div>
        <div v-if="metadata.engineversion" class="metadata-item">
          <span class="metadata-label">Engine Version</span>
          <span class="metadata-value">{{ metadata.engineversion }}</span>
        </div>
        <div v-if="metadata.author" class="metadata-item">
          <span class="metadata-label">Author</span>
          <span class="metadata-value">
            <a v-if="metadata.url" :href="metadata.url" target="_blank" rel="noopener">
              {{ metadata.author }}
            </a>
            <span v-else>{{ metadata.author }}</span>
          </span>
        </div>
        <div v-if="metadata.email" class="metadata-item">
          <span class="metadata-label">Email</span>
          <span class="metadata-value">
            <a :href="'mailto:' + metadata.email">{{ metadata.email }}</a>
          </span>
        </div>
        <div v-if="metadata.date" class="metadata-item">
          <span class="metadata-label">Created</span>
          <span class="metadata-value">{{ metadata.date }}</span>
        </div>
        <div v-if="metadata.last_modified" class="metadata-item">
          <span class="metadata-label">Last Modified</span>
          <span class="metadata-value">{{ metadata.last_modified }}</span>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed } from 'vue'

const props = defineProps({
  metadata: {
    type: Object,
    default: () => ({})
  }
})

const isExpanded = ref(true)

const hasMetadata = computed(() => {
  if (!props.metadata) return false
  return props.metadata.engineversion ||
         props.metadata.version ||
         props.metadata.type ||
         props.metadata.author ||
         props.metadata.date
})
</script>

<style scoped>
.metadata-section {
  margin-top: 1.5rem;
  border: 1px solid var(--border-color);
  border-radius: var(--border-radius);
  background: var(--bg-secondary);
  overflow: hidden;
}

.metadata-header {
  padding: 0.75rem 1rem;
  background: var(--bg-tertiary);
  cursor: pointer;
  user-select: none;
  transition: var(--transition);
}

.metadata-header:hover {
  background: var(--bg-secondary);
}

.metadata-header h4 {
  margin: 0;
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-size: 0.95rem;
  color: var(--text-primary);
}

.metadata-icon {
  font-size: 1.1rem;
}

.expand-icon {
  margin-left: auto;
  font-size: 0.7rem;
  color: var(--text-secondary);
}

.metadata-content {
  padding: 1rem;
}

.metadata-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
  gap: 1rem;
}

.metadata-item {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
}

.metadata-item.full-width {
  grid-column: 1 / -1;
}

.metadata-label {
  font-size: 0.75rem;
  color: var(--text-tertiary);
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.metadata-value {
  font-size: 0.9rem;
  color: var(--text-primary);
}

.metadata-value a {
  color: var(--primary);
  text-decoration: none;
}

.metadata-value a:hover {
  text-decoration: underline;
}

.type-badge {
  display: inline-block;
  padding: 0.15rem 0.5rem;
  background: rgba(59, 130, 246, 0.2);
  color: #93c5fd;
  border-radius: 4px;
  font-size: 0.8rem;
  font-weight: 500;
}
</style>
