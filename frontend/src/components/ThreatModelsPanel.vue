<!--
  VULNEX -Universal Security Visualization Library-

  File: ThreatModelsPanel.vue
  Description: Wrapper that groups the classical STRIDE/PyTM threat model
               panel and the MAESTRO agentic threat model panel under a
               single top-level tab with a sub-tab toggle. Mirrors the
               ArchitecturePanel toggle pattern.
  License: Apache-2.0
  Copyright (c) 2026 VULNEX. All rights reserved.
-->
<template>
  <div class="panel">
    <div class="panel-header">
      <h2>Threat Models</h2>
      <p>
        Choose a threat modeling approach: classical STRIDE / PyTM data-flow
        diagrams, or MAESTRO for agentic AI systems.
      </p>
    </div>

    <div class="panel-body">
      <!-- Sub-tab toggle -->
      <div class="diagram-type-toggle">
        <button
          :class="['toggle-btn', { active: activeView === 'classical' }]"
          @click="activeView = 'classical'"
        >
          Classical (STRIDE / PyTM)
        </button>
        <button
          :class="['toggle-btn', { active: activeView === 'maestro' }]"
          @click="activeView = 'maestro'"
        >
          Agentic AI (MAESTRO)
        </button>
      </div>

      <!-- Active sub-panel.
           keep-alive preserves each child's local state so switching back
           does not lose an in-progress edit. -->
      <keep-alive>
        <component
          :is="currentComponent"
          :key="activeView"
          v-bind="currentChildProps"
        />
      </keep-alive>
    </div>
  </div>
</template>

<script setup>
import { ref, computed } from 'vue'
import ThreatModelPanel from './ThreatModelPanel.vue'
import MaestroPanel from './MaestroPanel.vue'

const props = defineProps({
  // Shared
  apiConnected: { type: Boolean, default: false },
  apiVersion: { type: String, default: 'Unknown' },
  modules: { type: Object, default: () => ({}) },
  formats: { type: Array, default: () => ['png'] },
  // Classical panel
  styles: { type: Array, default: () => [] },
  engines: { type: Array, default: () => [] },
})

const activeView = ref('classical')

const currentComponent = computed(() =>
  activeView.value === 'maestro' ? MaestroPanel : ThreatModelPanel
)

// Each child has its own prop expectations; route only what it needs to
// keep Vue from warning about unused / missing required props.
const currentChildProps = computed(() => {
  const shared = {
    apiConnected: props.apiConnected,
    apiVersion: props.apiVersion,
    modules: props.modules,
  }
  if (activeView.value === 'maestro') {
    return { ...shared, formats: props.formats }
  }
  return {
    ...shared,
    styles: props.styles,
    formats: props.formats,
    engines: props.engines,
  }
})
</script>

<style scoped>
/* Toggle styling matches the ArchitecturePanel convention so users find a
   consistent sub-tab pattern across the app. */
.diagram-type-toggle {
  display: flex;
  gap: 0;
  margin-bottom: 1.25rem;
  border: 1px solid var(--border-color);
  border-radius: 8px;
  overflow: hidden;
}

.toggle-btn {
  flex: 1;
  padding: 0.7rem 1rem;
  border: none;
  background: var(--bg-secondary);
  color: var(--text-secondary);
  font-size: 0.95rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s ease;
}

.toggle-btn:first-child {
  border-right: 1px solid var(--border-color);
}

.toggle-btn.active {
  background: var(--accent-color);
  color: white;
}

.toggle-btn:hover:not(.active) {
  background: var(--bg-tertiary, #e5e7eb);
}
</style>
