<!--
  VULNEX -Universal Security Visualization Library-

  File: App.vue
  Author: Simon Roses Femerling
  Created: 2025-01-01
  Last Modified: 2025-12-29
  Version: 0.3.1
  License: Apache-2.0
  Copyright (c) 2025 VULNEX. All rights reserved.
  https://www.vulnex.com
-->
<template>
  <div class="app">
    <header class="header">
      <div class="header-content">
        <h1 class="logo">
          <img src="/usecvislib_logo.png" alt="USecVisLib" class="logo-image" />
          USecVisLib
        </h1>
        <p class="tagline">Universal Security Visualization Library</p>
      </div>
      <div class="header-actions">
        <button class="btn btn-icon" @click="activeTab = 'docs'" :class="{ active: activeTab === 'docs' }" title="Documentation">
          📖
        </button>
        <button class="btn btn-icon" @click="activeTab = 'settings'" :class="{ active: activeTab === 'settings' }" title="Settings">
          ⚙️
        </button>
        <button class="btn btn-clean" @click="cleanAllTabs" title="Reset all visualizations">
          🗑️ Clean
        </button>
      </div>
    </header>

    <main class="main">
      <nav class="tabs-container">
        <!-- Primary Tabs -->
        <div class="tabs tabs-primary">
          <button
            v-for="tab in primaryTabs"
            :key="tab.id"
            :class="['tab', { active: activeTab === tab.id }]"
            @click="activeTab = tab.id"
          >
            <span class="tab-icon">{{ tab.icon }}</span>
            <span class="tab-name">{{ tab.name }}</span>
          </button>
        </div>

        <!-- Tools Dropdown -->
        <div class="tools-dropdown" :class="{ open: toolsDropdownOpen }">
          <button class="tab tab-dropdown" @click="toggleToolsDropdown" :class="{ active: isToolActive }">
            <span class="tab-icon">🔧</span>
            <span class="tab-name">Tools</span>
            <span class="dropdown-arrow">{{ toolsDropdownOpen ? '▲' : '▼' }}</span>
          </button>
          <div class="dropdown-menu" v-if="toolsDropdownOpen">
            <button
              v-for="tab in toolTabs"
              :key="tab.id"
              :class="['dropdown-item', { active: activeTab === tab.id }]"
              @click="selectTool(tab.id)"
            >
              <span class="dropdown-icon">{{ tab.icon }}</span>
              <span class="dropdown-text">{{ tab.name }}</span>
            </button>
          </div>
        </div>
      </nav>

      <div class="content">
        <keep-alive>
          <component
            :is="currentComponent"
            :key="activeTab"
            v-bind="currentProps"
            @connection-change="handleConnectionChange"
          />
        </keep-alive>
      </div>
    </main>

    <footer class="footer">
      <p>USecVisLib v0.3.2 |
        <a href="http://localhost:8000/docs" target="_blank">API Docs</a> |
        <a href="https://github.com/vulnex/usecvislib" target="_blank">GitHub</a>
      </p>
    </footer>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, onUnmounted, provide } from 'vue'
import { checkHealth, getStyles, getFormats, getEngines } from './services/api.js'
import AttackTreePanel from './components/AttackTreePanel.vue'
import AttackGraphPanel from './components/AttackGraphPanel.vue'
import ThreatModelPanel from './components/ThreatModelPanel.vue'
import BinaryVisPanel from './components/BinaryVisPanel.vue'
import ConvertPanel from './components/ConvertPanel.vue'
import BatchPanel from './components/BatchPanel.vue'
import ExportPanel from './components/ExportPanel.vue'
import ComparePanel from './components/ComparePanel.vue'
import CVSSCalculatorPanel from './components/CVSSCalculatorPanel.vue'
import CustomDiagramPanel from './components/CustomDiagramPanel.vue'
import DocumentationPanel from './components/DocumentationPanel.vue'
import SettingsPanel from './components/SettingsPanel.vue'

const apiConnected = ref(false)
const apiVersion = ref('Unknown')
const modules = ref({
  attack_trees: false,
  attack_graphs: false,
  threat_modeling: false,
  binary_visualization: false
})
const activeTab = ref('attack-tree')
const styles = ref({
  attack_tree: [],
  attack_graph: [],
  threat_model: [],
  custom_diagram: [],
  binary_visualization: []
})
const formats = ref([])
const engines = ref([
  { value: 'usecvislib', label: 'USecVisLib', available: true },
  { value: 'pytm', label: 'OWASP PyTM', available: true }
])

// Clean trigger - increment to signal child components to reset
const cleanTrigger = ref(0)
provide('cleanTrigger', cleanTrigger)

// Primary visualization tabs
const primaryTabs = [
  { id: 'attack-tree', name: 'Attack Trees', icon: '🌳' },
  { id: 'attack-graph', name: 'Attack Graphs', icon: '🕸️' },
  { id: 'threat-model', name: 'Threat Modeling', icon: '🔍' },
  { id: 'custom-diagram', name: 'Custom Diagrams', icon: '🎨' },
  { id: 'binary', name: 'Binary Analysis', icon: '📊' }
]

// Tool tabs (shown in dropdown)
const toolTabs = [
  { id: 'cvss', name: 'CVSS Calculator', icon: '🎯' },
  { id: 'convert', name: 'Format Converter', icon: '🔄' },
  { id: 'batch', name: 'Batch Processing', icon: '📦' },
  { id: 'export', name: 'Data Export', icon: '📤' },
  { id: 'compare', name: 'File Compare', icon: '🔀' }
]

// Tools dropdown state
const toolsDropdownOpen = ref(false)

// Check if any tool tab is active
const isToolActive = computed(() => {
  return toolTabs.some(t => t.id === activeTab.value)
})

function toggleToolsDropdown() {
  toolsDropdownOpen.value = !toolsDropdownOpen.value
}

function selectTool(tabId) {
  activeTab.value = tabId
  toolsDropdownOpen.value = false
}

// Close dropdown when clicking outside
function handleClickOutside(event) {
  const dropdown = document.querySelector('.tools-dropdown')
  if (dropdown && !dropdown.contains(event.target)) {
    toolsDropdownOpen.value = false
  }
}

// Component mapping for dynamic component rendering with keep-alive
const componentMap = {
  'attack-tree': AttackTreePanel,
  'attack-graph': AttackGraphPanel,
  'threat-model': ThreatModelPanel,
  'custom-diagram': CustomDiagramPanel,
  'binary': BinaryVisPanel,
  'cvss': CVSSCalculatorPanel,
  'convert': ConvertPanel,
  'batch': BatchPanel,
  'export': ExportPanel,
  'compare': ComparePanel,
  'docs': DocumentationPanel,
  'settings': SettingsPanel
}

// Current component based on active tab
const currentComponent = computed(() => {
  return componentMap[activeTab.value] || AttackTreePanel
})

// Props for the current component
const currentProps = computed(() => {
  const baseProps = {
    apiConnected: apiConnected.value,
    apiVersion: apiVersion.value,
    modules: modules.value
  }

  switch (activeTab.value) {
    case 'attack-tree':
      return {
        ...baseProps,
        styles: styles.value.attack_tree || [],
        formats: formats.value
      }
    case 'attack-graph':
      return {
        ...baseProps,
        styles: styles.value.attack_graph || [],
        formats: formats.value
      }
    case 'threat-model':
      return {
        ...baseProps,
        styles: styles.value.threat_model || [],
        formats: formats.value,
        engines: engines.value
      }
    case 'custom-diagram':
      return {
        ...baseProps,
        formats: formats.value
      }
    case 'binary':
      return {
        ...baseProps,
        styles: styles.value.binary_visualization || [],
        formats: formats.value
      }
    case 'convert':
    case 'export':
    case 'compare':
      return {
        ...baseProps,
        formats: formats.value
      }
    case 'batch':
      return {
        ...baseProps,
        styles: styles.value,
        formats: formats.value
      }
    case 'docs':
    case 'settings':
    default:
      return baseProps
  }
})

function cleanAllTabs() {
  cleanTrigger.value++
}

function handleConnectionChange(data) {
  apiConnected.value = data.connected
  if (data.connected) {
    apiVersion.value = data.version || 'Unknown'
    modules.value = data.modules || {}
  }
}

onMounted(async () => {
  // Add click outside listener for dropdown
  document.addEventListener('click', handleClickOutside)

  try {
    const health = await checkHealth()
    apiConnected.value = true
    apiVersion.value = health.version || 'Unknown'
    modules.value = health.modules || {}

    const [stylesData, formatsData, enginesData] = await Promise.all([
      getStyles(),
      getFormats(),
      getEngines()
    ])

    styles.value = stylesData
    formats.value = formatsData.formats

    // Transform engines data for the dropdown
    engines.value = enginesData.engines.map(e => ({
      value: e,
      label: e === 'usecvislib' ? 'USecVisLib' : 'OWASP PyTM',
      available: e === 'usecvislib' || enginesData.pytm_available
    }))
  } catch (error) {
    console.error('Failed to connect to API:', error)
    apiConnected.value = false
  }
})

onUnmounted(() => {
  document.removeEventListener('click', handleClickOutside)
})
</script>
