<!--
  VULNEX -Universal Security Visualization Library-

  File: CVSSCalculatorPanel.vue
  Author: Simon Roses Femerling
  Created: 2025-12-26
  Last Modified: 2025-12-26
  Version: 0.3.1
  License: Apache-2.0
  Copyright (c) 2025 VULNEX. All rights reserved.
  https://www.vulnex.com
-->
<template>
  <div class="panel">
    <div class="panel-header">
      <h2>CVSS Calculator</h2>
      <p>Calculate CVSS scores and generate vector strings for use in your security visualizations</p>
    </div>

    <div class="panel-body">
      <CVSSCalculator
        @apply="handleApply"
        @update:score="currentScore = $event"
        @update:vector="currentVector = $event"
      />

      <!-- Quick Reference -->
      <div class="reference-section">
        <h3>CVSS Severity Ranges</h3>
        <div class="severity-reference">
          <div class="severity-item critical">
            <span class="range">9.0 - 10.0</span>
            <span class="label">Critical</span>
          </div>
          <div class="severity-item high">
            <span class="range">7.0 - 8.9</span>
            <span class="label">High</span>
          </div>
          <div class="severity-item medium">
            <span class="range">4.0 - 6.9</span>
            <span class="label">Medium</span>
          </div>
          <div class="severity-item low">
            <span class="range">0.1 - 3.9</span>
            <span class="label">Low</span>
          </div>
          <div class="severity-item none">
            <span class="range">0.0</span>
            <span class="label">None</span>
          </div>
        </div>
      </div>

      <!-- Usage Examples -->
      <div class="examples-section">
        <h3>Using CVSS in Templates</h3>
        <div class="example-code">
          <h4>Attack Graph (vulnerability with CVSS vector):</h4>
          <pre><code>[vulnerabilities.sql_injection]
label = "SQL Injection"
host = "webserver"
cvss_vector = "{{ currentVector }}"</code></pre>
        </div>
        <div class="example-code">
          <h4>Attack Tree (node with numeric CVSS):</h4>
          <pre><code>[nodes]
"SQL Injection" = {style="filled", shape="rectangle", cvss={{ currentScore }}}</code></pre>
        </div>
        <div class="example-code">
          <h4>Threat Model (custom threat with CVSS):</h4>
          <pre><code>[threats.sql_injection]
element = "database"
threat = "SQL Injection in query parameters"
mitigation = "Use parameterized queries"
cvss = {{ currentScore }}</code></pre>
        </div>
      </div>

      <!-- History -->
      <div v-if="history.length > 0" class="history-section">
        <h3>Recent Calculations</h3>
        <div class="history-list">
          <div v-for="(item, index) in history" :key="index" class="history-item" :class="getSeverityClass(item.score)">
            <span class="history-score">{{ item.score }}</span>
            <span class="history-vector">{{ item.vector }}</span>
            <button class="btn btn-small" @click="copyHistoryVector(item.vector)">Copy</button>
          </div>
        </div>
        <button class="btn btn-secondary btn-small" @click="clearHistory">Clear History</button>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, inject, watch } from 'vue'
import CVSSCalculator from './CVSSCalculator.vue'

// Watch for clean trigger from parent
const cleanTrigger = inject('cleanTrigger')
watch(cleanTrigger, () => {
  clearHistory()
})

const currentScore = ref(9.8)
const currentVector = ref('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')
const history = ref([])

function handleApply({ score, vector }) {
  // Add to history
  history.value.unshift({ score, vector, timestamp: new Date() })
  // Keep only last 10 entries
  if (history.value.length > 10) {
    history.value = history.value.slice(0, 10)
  }
}

function getSeverityClass(score) {
  if (score >= 9.0) return 'severity-critical'
  if (score >= 7.0) return 'severity-high'
  if (score >= 4.0) return 'severity-medium'
  if (score >= 0.1) return 'severity-low'
  return 'severity-none'
}

async function copyHistoryVector(vector) {
  try {
    await navigator.clipboard.writeText(vector)
  } catch (err) {
    console.error('Failed to copy:', err)
  }
}

function clearHistory() {
  history.value = []
}
</script>

<style scoped>
.reference-section {
  margin-top: 2rem;
  padding: 1.5rem;
  background: var(--bg-secondary);
  border-radius: 8px;
}

.reference-section h3 {
  margin: 0 0 1rem;
  font-size: 1rem;
}

.severity-reference {
  display: flex;
  flex-wrap: wrap;
  gap: 0.75rem;
}

.severity-item {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.5rem 1rem;
  border-radius: 6px;
  color: white;
  font-size: 0.875rem;
}

.severity-item .range {
  font-weight: bold;
}

.severity-item .label {
  opacity: 0.9;
}

.severity-item.critical {
  background: #8b0000;
}

.severity-item.high {
  background: #e74c3c;
}

.severity-item.medium {
  background: #f39c12;
}

.severity-item.low {
  background: #27ae60;
}

.severity-item.none {
  background: #3498db;
}

.examples-section {
  margin-top: 2rem;
  padding: 1.5rem;
  background: var(--bg-secondary);
  border-radius: 8px;
}

.examples-section h3 {
  margin: 0 0 1rem;
  font-size: 1rem;
}

.example-code {
  margin-bottom: 1.5rem;
}

.example-code:last-child {
  margin-bottom: 0;
}

.example-code h4 {
  font-size: 0.875rem;
  color: var(--text-secondary);
  margin: 0 0 0.5rem;
}

.example-code pre {
  background: var(--bg-primary);
  padding: 1rem;
  border-radius: 6px;
  overflow-x: auto;
  margin: 0;
}

.example-code code {
  font-family: 'SF Mono', Monaco, 'Courier New', monospace;
  font-size: 0.8125rem;
  color: var(--text-primary);
}

.history-section {
  margin-top: 2rem;
  padding: 1.5rem;
  background: var(--bg-secondary);
  border-radius: 8px;
}

.history-section h3 {
  margin: 0 0 1rem;
  font-size: 1rem;
}

.history-list {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  margin-bottom: 1rem;
}

.history-item {
  display: flex;
  align-items: center;
  gap: 1rem;
  padding: 0.5rem 0.75rem;
  background: var(--bg-primary);
  border-radius: 6px;
  border-left: 4px solid;
}

.history-item.severity-critical {
  border-color: #8b0000;
}

.history-item.severity-high {
  border-color: #e74c3c;
}

.history-item.severity-medium {
  border-color: #f39c12;
}

.history-item.severity-low {
  border-color: #27ae60;
}

.history-item.severity-none {
  border-color: #3498db;
}

.history-score {
  font-weight: bold;
  font-size: 1rem;
  min-width: 40px;
}

.history-vector {
  flex: 1;
  font-family: monospace;
  font-size: 0.8125rem;
  color: var(--text-secondary);
}

.btn {
  padding: 0.5rem 1rem;
  border-radius: 4px;
  font-size: 0.875rem;
  cursor: pointer;
  border: none;
  transition: background 0.2s;
}

.btn-small {
  padding: 0.35rem 0.75rem;
  font-size: 0.8125rem;
}

.btn-secondary {
  background: var(--bg-tertiary);
  color: var(--text-primary);
}

.btn-secondary:hover {
  background: var(--border-color);
}
</style>
