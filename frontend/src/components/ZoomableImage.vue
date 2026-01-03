<!--
  VULNEX -Universal Security Visualization Library-

  File: ZoomableImage.vue
  Author: Simon Roses Femerling
  Created: 2025-01-01
  Last Modified: 2025-12-23
  Version: 0.3.1
  License: Apache-2.0
  Copyright (c) 2025 VULNEX. All rights reserved.
  https://www.vulnex.com
-->
<template>
  <div class="zoomable-image-wrapper">
    <div class="zoom-controls">
      <button class="zoom-btn" @click="zoomOut" :disabled="zoom <= minZoom" title="Zoom Out">
        <span>−</span>
      </button>
      <span class="zoom-level">{{ Math.round(zoom * 100) }}%</span>
      <button class="zoom-btn" @click="zoomIn" :disabled="zoom >= maxZoom" title="Zoom In">
        <span>+</span>
      </button>
      <button class="zoom-btn reset-btn" @click="resetZoom" :disabled="zoom === 1 && !isPanned" title="Reset">
        <span>⟲</span>
      </button>
      <button class="zoom-btn fit-btn" @click="fitToContainer" title="Fit to View">
        <span>⊡</span>
      </button>
    </div>
    <div
      class="image-viewport"
      ref="viewport"
      @wheel.prevent="handleWheel"
      @mousedown="startDrag"
      @mousemove="drag"
      @mouseup="endDrag"
      @mouseleave="endDrag"
      :class="{ dragging: isDragging, 'can-drag': zoom > 1 }"
    >
      <img
        ref="image"
        :src="src"
        :alt="alt"
        :style="imageStyle"
        @load="onImageLoad"
        draggable="false"
      />
    </div>
  </div>
</template>

<script setup>
import { ref, computed, watch } from 'vue'

const props = defineProps({
  src: { type: String, required: true },
  alt: { type: String, default: 'Visualization' }
})

// Zoom state
const zoom = ref(1)
const minZoom = 0.25
const maxZoom = 5
const zoomStep = 0.25

// Pan state
const panX = ref(0)
const panY = ref(0)
const isDragging = ref(false)
const dragStart = ref({ x: 0, y: 0 })
const panStart = ref({ x: 0, y: 0 })

// Refs
const viewport = ref(null)
const image = ref(null)
const imageNaturalSize = ref({ width: 0, height: 0 })

// Computed
const isPanned = computed(() => panX.value !== 0 || panY.value !== 0)

const imageStyle = computed(() => ({
  transform: `scale(${zoom.value}) translate(${panX.value / zoom.value}px, ${panY.value / zoom.value}px)`,
  transformOrigin: 'center center',
  cursor: zoom.value > 1 ? (isDragging.value ? 'grabbing' : 'grab') : 'default'
}))

// Methods
function zoomIn() {
  const newZoom = Math.min(zoom.value + zoomStep, maxZoom)
  zoom.value = Math.round(newZoom * 100) / 100
}

function zoomOut() {
  const newZoom = Math.max(zoom.value - zoomStep, minZoom)
  zoom.value = Math.round(newZoom * 100) / 100
  constrainPan()
}

function resetZoom() {
  zoom.value = 1
  panX.value = 0
  panY.value = 0
}

function fitToContainer() {
  if (!viewport.value || !imageNaturalSize.value.width) return

  const containerWidth = viewport.value.clientWidth - 32 // padding
  const containerHeight = viewport.value.clientHeight - 32

  const scaleX = containerWidth / imageNaturalSize.value.width
  const scaleY = containerHeight / imageNaturalSize.value.height

  zoom.value = Math.min(Math.max(Math.min(scaleX, scaleY), minZoom), maxZoom)
  zoom.value = Math.round(zoom.value * 100) / 100
  panX.value = 0
  panY.value = 0
}

function handleWheel(event) {
  const delta = event.deltaY > 0 ? -zoomStep : zoomStep
  const newZoom = Math.max(minZoom, Math.min(maxZoom, zoom.value + delta))
  zoom.value = Math.round(newZoom * 100) / 100

  if (zoom.value <= 1) {
    panX.value = 0
    panY.value = 0
  } else {
    constrainPan()
  }
}

function startDrag(event) {
  if (zoom.value <= 1) return

  isDragging.value = true
  dragStart.value = { x: event.clientX, y: event.clientY }
  panStart.value = { x: panX.value, y: panY.value }
}

function drag(event) {
  if (!isDragging.value) return

  const dx = event.clientX - dragStart.value.x
  const dy = event.clientY - dragStart.value.y

  panX.value = panStart.value.x + dx
  panY.value = panStart.value.y + dy

  constrainPan()
}

function endDrag() {
  isDragging.value = false
}

function constrainPan() {
  if (!viewport.value || !image.value) return

  const viewportRect = viewport.value.getBoundingClientRect()
  const scaledWidth = imageNaturalSize.value.width * zoom.value
  const scaledHeight = imageNaturalSize.value.height * zoom.value

  const maxPanX = Math.max(0, (scaledWidth - viewportRect.width) / 2)
  const maxPanY = Math.max(0, (scaledHeight - viewportRect.height) / 2)

  panX.value = Math.max(-maxPanX, Math.min(maxPanX, panX.value))
  panY.value = Math.max(-maxPanY, Math.min(maxPanY, panY.value))
}

function onImageLoad() {
  if (image.value) {
    imageNaturalSize.value = {
      width: image.value.naturalWidth,
      height: image.value.naturalHeight
    }
  }
}

// Reset when src changes
watch(() => props.src, () => {
  resetZoom()
})
</script>

<style scoped>
.zoomable-image-wrapper {
  background: white;
  border-radius: var(--border-radius);
  overflow: hidden;
}

.zoom-controls {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.5rem 1rem;
  background: #f5f5f5;
  border-bottom: 1px solid #e0e0e0;
}

.zoom-btn {
  width: 28px;
  height: 28px;
  border: 1px solid #ccc;
  border-radius: 4px;
  background: white;
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 16px;
  font-weight: bold;
  color: #333;
  transition: all 0.15s ease;
}

.zoom-btn:hover:not(:disabled) {
  background: #e8e8e8;
  border-color: #999;
}

.zoom-btn:disabled {
  opacity: 0.4;
  cursor: not-allowed;
}

.zoom-btn span {
  line-height: 1;
}

.reset-btn span,
.fit-btn span {
  font-size: 14px;
}

.zoom-level {
  min-width: 50px;
  text-align: center;
  font-size: 0.85rem;
  font-weight: 500;
  color: #555;
  font-family: monospace;
}

.image-viewport {
  padding: 1rem;
  overflow: hidden;
  max-height: 550px;
  min-height: 200px;
  display: flex;
  align-items: center;
  justify-content: center;
  background: white;
}

.image-viewport.can-drag {
  cursor: grab;
}

.image-viewport.dragging {
  cursor: grabbing;
}

.image-viewport img {
  max-width: 100%;
  max-height: 100%;
  height: auto;
  user-select: none;
  transition: transform 0.1s ease-out;
}

.image-viewport.dragging img {
  transition: none;
}
</style>
