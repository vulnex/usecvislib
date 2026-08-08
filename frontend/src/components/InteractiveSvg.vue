<!--
  VULNEX -Universal Security Visualization Library-

  File: InteractiveSvg.vue
  Author: Simon Roses Femerling
  Created: 2026-08-08
  Last Modified: 2026-08-08
  Version: 0.4.1
  License: Apache-2.0
  Copyright (c) 2026 VULNEX. All rights reserved.
  https://www.vulnex.com
-->
<!--
  Inline renderer for SVG-engine output (render_engine=svg).

  Sanitizes the SVG text with DOMPurify (defense in depth - the engine
  already guarantees no active content) before injecting it into the DOM,
  then adds zoom/pan and node hover/click interaction via the engine's
  interactivity contract (.usv-node groups with data-node-id attributes).
  Raster formats and Graphviz-engine SVG keep using ZoomableImage.
-->
<template>
  <div class="interactive-svg-wrapper">
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
      <span v-if="selectedNode" class="selected-node" :title="selectedNode">
        Selected: <code>{{ selectedNode }}</code>
      </span>
    </div>
    <div
      class="svg-viewport"
      ref="viewport"
      @wheel.prevent="handleWheel"
      @mousedown="startDrag"
      @mousemove="drag"
      @mouseup="endDrag"
      @mouseleave="endDrag"
      @click="handleClick"
      :class="{ dragging: isDragging, 'can-drag': zoom > 1 }"
    >
      <div class="svg-stage" :style="stageStyle" v-html="sanitizedSvg"></div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, watch } from 'vue'
import DOMPurify from 'dompurify'

const props = defineProps({
  svgText: { type: String, required: true }
})

const emit = defineEmits(['node-click'])

// Zoom/pan state (same model as ZoomableImage)
const zoom = ref(1)
const minZoom = 0.25
const maxZoom = 5
const zoomStep = 0.25
const panX = ref(0)
const panY = ref(0)
const isDragging = ref(false)
const dragStart = ref({ x: 0, y: 0 })
const panStart = ref({ x: 0, y: 0 })
const viewport = ref(null)
const selectedNode = ref(null)

const isPanned = computed(() => panX.value !== 0 || panY.value !== 0)

const sanitizedSvg = computed(() =>
  DOMPurify.sanitize(props.svgText, {
    USE_PROFILES: { svg: true, svgFilters: true },
    ADD_TAGS: ['style'],
    FORBID_TAGS: ['script', 'foreignObject'],
    FORBID_ATTR: ['onerror', 'onload', 'onclick']
  })
)

const stageStyle = computed(() => ({
  transform: `scale(${zoom.value}) translate(${panX.value / zoom.value}px, ${panY.value / zoom.value}px)`,
  transformOrigin: 'center center',
  cursor: zoom.value > 1 ? (isDragging.value ? 'grabbing' : 'grab') : 'default'
}))

function zoomIn() {
  zoom.value = Math.round(Math.min(zoom.value + zoomStep, maxZoom) * 100) / 100
}

function zoomOut() {
  zoom.value = Math.round(Math.max(zoom.value - zoomStep, minZoom) * 100) / 100
}

function resetZoom() {
  zoom.value = 1
  panX.value = 0
  panY.value = 0
}

function handleWheel(event) {
  const delta = event.deltaY > 0 ? -zoomStep : zoomStep
  zoom.value = Math.round(Math.max(minZoom, Math.min(maxZoom, zoom.value + delta)) * 100) / 100
  if (zoom.value <= 1) {
    panX.value = 0
    panY.value = 0
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
  panX.value = panStart.value.x + (event.clientX - dragStart.value.x)
  panY.value = panStart.value.y + (event.clientY - dragStart.value.y)
}

function endDrag() {
  isDragging.value = false
}

function handleClick(event) {
  const nodeGroup = event.target.closest('g.usv-node')
  if (!viewport.value) return
  viewport.value.querySelectorAll('.usv-selected').forEach((el) => el.classList.remove('usv-selected'))
  if (nodeGroup) {
    nodeGroup.classList.add('usv-selected')
    selectedNode.value = nodeGroup.getAttribute('data-node-id')
    emit('node-click', {
      nodeId: nodeGroup.getAttribute('data-node-id'),
      label: nodeGroup.getAttribute('data-label'),
      cvss: nodeGroup.getAttribute('data-cvss')
    })
  } else {
    selectedNode.value = null
  }
}

watch(
  () => props.svgText,
  () => {
    resetZoom()
    selectedNode.value = null
  }
)
</script>

<style scoped>
.interactive-svg-wrapper {
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

.reset-btn span {
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

.selected-node {
  margin-left: auto;
  font-size: 0.85rem;
  color: #555;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  max-width: 50%;
}

.selected-node code {
  background: #eef2f7;
  padding: 0.1rem 0.4rem;
  border-radius: 4px;
  font-size: 0.8rem;
}

.svg-viewport {
  padding: 1rem;
  overflow: hidden;
  max-height: 550px;
  min-height: 200px;
  display: flex;
  align-items: center;
  justify-content: center;
  background: white;
}

.svg-viewport.can-drag {
  cursor: grab;
}

.svg-viewport.dragging {
  cursor: grabbing;
}

.svg-stage {
  transition: transform 0.1s ease-out;
  max-width: 100%;
}

.svg-viewport.dragging .svg-stage {
  transition: none;
}

.svg-stage :deep(svg) {
  max-width: 100%;
  height: auto;
  display: block;
}

.svg-stage :deep(g.usv-node) {
  cursor: pointer;
}

.svg-stage :deep(g.usv-node.usv-selected rect),
.svg-stage :deep(g.usv-node.usv-selected polygon) {
  stroke: #2563eb;
  stroke-width: 2.5;
}
</style>
