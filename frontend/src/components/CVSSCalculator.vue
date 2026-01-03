<!--
  VULNEX -Universal Security Visualization Library-

  File: CVSSCalculator.vue
  Author: Simon Roses Femerling
  Created: 2025-12-26
  Last Modified: 2025-12-26
  Version: 0.3.1
  License: Apache-2.0
  Copyright (c) 2025 VULNEX. All rights reserved.
  https://www.vulnex.com
-->
<template>
  <div class="cvss-calculator">
    <div class="calculator-header">
      <h3>CVSS 3.1 Calculator</h3>
      <p class="subtitle">Calculate and generate CVSS vector strings for vulnerabilities</p>
    </div>

    <div class="calculator-body">
      <!-- Base Metrics -->
      <div class="metrics-section">
        <h4>Base Metrics</h4>

        <div class="metrics-grid">
          <!-- Attack Vector -->
          <div class="metric-group">
            <label>
              Attack Vector (AV)
              <span class="info-icon" :data-tooltip="metricDescriptions.attackVector">ⓘ</span>
            </label>
            <div class="radio-group">
              <label class="radio-option" v-for="opt in attackVectorOptions" :key="opt.value">
                <input type="radio" v-model="metrics.attackVector" :value="opt.value" />
                <span class="radio-label">{{ opt.label }}</span>
                <span class="radio-desc">{{ opt.description }}</span>
              </label>
            </div>
          </div>

          <!-- Attack Complexity -->
          <div class="metric-group">
            <label>
              Attack Complexity (AC)
              <span class="info-icon" :data-tooltip="metricDescriptions.attackComplexity">ⓘ</span>
            </label>
            <div class="radio-group">
              <label class="radio-option" v-for="opt in attackComplexityOptions" :key="opt.value">
                <input type="radio" v-model="metrics.attackComplexity" :value="opt.value" />
                <span class="radio-label">{{ opt.label }}</span>
                <span class="radio-desc">{{ opt.description }}</span>
              </label>
            </div>
          </div>

          <!-- Privileges Required -->
          <div class="metric-group">
            <label>
              Privileges Required (PR)
              <span class="info-icon" :data-tooltip="metricDescriptions.privilegesRequired">ⓘ</span>
            </label>
            <div class="radio-group">
              <label class="radio-option" v-for="opt in privilegesRequiredOptions" :key="opt.value">
                <input type="radio" v-model="metrics.privilegesRequired" :value="opt.value" />
                <span class="radio-label">{{ opt.label }}</span>
                <span class="radio-desc">{{ opt.description }}</span>
              </label>
            </div>
          </div>

          <!-- User Interaction -->
          <div class="metric-group">
            <label>
              User Interaction (UI)
              <span class="info-icon" :data-tooltip="metricDescriptions.userInteraction">ⓘ</span>
            </label>
            <div class="radio-group">
              <label class="radio-option" v-for="opt in userInteractionOptions" :key="opt.value">
                <input type="radio" v-model="metrics.userInteraction" :value="opt.value" />
                <span class="radio-label">{{ opt.label }}</span>
                <span class="radio-desc">{{ opt.description }}</span>
              </label>
            </div>
          </div>

          <!-- Scope -->
          <div class="metric-group">
            <label>
              Scope (S)
              <span class="info-icon" :data-tooltip="metricDescriptions.scope">ⓘ</span>
            </label>
            <div class="radio-group">
              <label class="radio-option" v-for="opt in scopeOptions" :key="opt.value">
                <input type="radio" v-model="metrics.scope" :value="opt.value" />
                <span class="radio-label">{{ opt.label }}</span>
                <span class="radio-desc">{{ opt.description }}</span>
              </label>
            </div>
          </div>
        </div>

        <h4 class="impact-header">Impact Metrics</h4>

        <div class="metrics-grid">
          <!-- Confidentiality Impact -->
          <div class="metric-group">
            <label>
              Confidentiality Impact (C)
              <span class="info-icon" :data-tooltip="metricDescriptions.confidentiality">ⓘ</span>
            </label>
            <div class="radio-group">
              <label class="radio-option" v-for="opt in impactOptions" :key="opt.value">
                <input type="radio" v-model="metrics.confidentiality" :value="opt.value" />
                <span class="radio-label">{{ opt.label }}</span>
                <span class="radio-desc">{{ opt.description }}</span>
              </label>
            </div>
          </div>

          <!-- Integrity Impact -->
          <div class="metric-group">
            <label>
              Integrity Impact (I)
              <span class="info-icon" :data-tooltip="metricDescriptions.integrity">ⓘ</span>
            </label>
            <div class="radio-group">
              <label class="radio-option" v-for="opt in impactOptions" :key="opt.value">
                <input type="radio" v-model="metrics.integrity" :value="opt.value" />
                <span class="radio-label">{{ opt.label }}</span>
                <span class="radio-desc">{{ opt.description }}</span>
              </label>
            </div>
          </div>

          <!-- Availability Impact -->
          <div class="metric-group">
            <label>
              Availability Impact (A)
              <span class="info-icon" :data-tooltip="metricDescriptions.availability">ⓘ</span>
            </label>
            <div class="radio-group">
              <label class="radio-option" v-for="opt in impactOptions" :key="opt.value">
                <input type="radio" v-model="metrics.availability" :value="opt.value" />
                <span class="radio-label">{{ opt.label }}</span>
                <span class="radio-desc">{{ opt.description }}</span>
              </label>
            </div>
          </div>
        </div>
      </div>

      <!-- Results -->
      <div class="results-section">
        <div class="score-display" :class="severityClass">
          <div class="score-value">{{ calculatedScore }}</div>
          <div class="severity-label">{{ severityLabel }}</div>
        </div>

        <div class="vector-display">
          <label>CVSS Vector String</label>
          <div class="vector-string">
            <input type="text" :value="vectorString" readonly />
            <button class="btn btn-small" @click="copyVector" :title="copied ? 'Copied!' : 'Copy to clipboard'">
              {{ copied ? 'Copied!' : 'Copy' }}
            </button>
            <button class="btn btn-secondary btn-small" @click="resetMetrics">Reset</button>
            <button class="btn btn-primary btn-small" @click="$emit('apply', { score: calculatedScore, vector: vectorString })">
              Apply to Template
            </button>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, watch } from 'vue'

const emit = defineEmits(['apply', 'update:score', 'update:vector'])

// CVSS 3.1 Metric Values and Weights
const AV_WEIGHTS = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }
const AC_WEIGHTS = { L: 0.77, H: 0.44 }
const PR_WEIGHTS_UNCHANGED = { N: 0.85, L: 0.62, H: 0.27 }
const PR_WEIGHTS_CHANGED = { N: 0.85, L: 0.68, H: 0.50 }
const UI_WEIGHTS = { N: 0.85, R: 0.62 }
const IMPACT_WEIGHTS = { N: 0, L: 0.22, H: 0.56 }

// Metric options
const attackVectorOptions = [
  { value: 'N', label: 'Network', description: 'Exploitable from the network' },
  { value: 'A', label: 'Adjacent', description: 'Requires adjacent network access' },
  { value: 'L', label: 'Local', description: 'Requires local access' },
  { value: 'P', label: 'Physical', description: 'Requires physical access' }
]

const attackComplexityOptions = [
  { value: 'L', label: 'Low', description: 'No specialized conditions' },
  { value: 'H', label: 'High', description: 'Specialized conditions required' }
]

const privilegesRequiredOptions = [
  { value: 'N', label: 'None', description: 'No privileges required' },
  { value: 'L', label: 'Low', description: 'Low privileges required' },
  { value: 'H', label: 'High', description: 'High privileges required' }
]

const userInteractionOptions = [
  { value: 'N', label: 'None', description: 'No user interaction required' },
  { value: 'R', label: 'Required', description: 'User must take action' }
]

const scopeOptions = [
  { value: 'U', label: 'Unchanged', description: 'Impact limited to vulnerable component' },
  { value: 'C', label: 'Changed', description: 'Can affect resources beyond vulnerable component' }
]

const impactOptions = [
  { value: 'N', label: 'None', description: 'No impact' },
  { value: 'L', label: 'Low', description: 'Limited impact' },
  { value: 'H', label: 'High', description: 'Complete impact' }
]

// Metric descriptions for tooltips
const metricDescriptions = {
  attackVector: 'Attack Vector (AV) reflects how the vulnerability can be exploited. Network means remotely exploitable over the internet; Adjacent requires the attacker to be on the same network segment; Local requires local access to the system; Physical requires physical access to the device.',
  attackComplexity: 'Attack Complexity (AC) describes the conditions beyond the attacker\'s control that must exist to exploit the vulnerability. Low means no special access conditions or extenuating circumstances; High means specific conditions must be met for the attack to succeed.',
  privilegesRequired: 'Privileges Required (PR) describes the level of privileges an attacker must possess before exploiting the vulnerability. None means no prior authentication is required; Low means basic user privileges are sufficient; High means administrative privileges are required.',
  userInteraction: 'User Interaction (UI) captures whether the attack requires a user to perform some action. None means the vulnerability can be exploited without any user involvement; Required means a user must take some action for exploitation to succeed.',
  scope: 'Scope (S) captures whether a vulnerability in one component impacts resources beyond its security scope. Unchanged means the impact is limited to the vulnerable component; Changed means the vulnerability can affect resources beyond the vulnerable component\'s security authority.',
  confidentiality: 'Confidentiality Impact (C) measures the impact on the confidentiality of information. None means no loss of confidentiality; Low means some restricted information is disclosed; High means all information is disclosed or critical information is directly stolen.',
  integrity: 'Integrity Impact (I) measures the impact on data trustworthiness. None means no loss of integrity; Low means data can be modified with limited consequences; High means complete loss of integrity, data can be freely modified with serious consequences.',
  availability: 'Availability Impact (A) measures the impact on accessibility of resources. None means no impact on availability; Low means reduced performance or interruptions in availability; High means complete loss of availability or the attacker can fully deny access to resources.'
}

// State
const metrics = ref({
  attackVector: 'N',
  attackComplexity: 'L',
  privilegesRequired: 'N',
  userInteraction: 'N',
  scope: 'U',
  confidentiality: 'H',
  integrity: 'H',
  availability: 'H'
})

const copied = ref(false)

// Computed values
const vectorString = computed(() => {
  const m = metrics.value
  return `CVSS:3.1/AV:${m.attackVector}/AC:${m.attackComplexity}/PR:${m.privilegesRequired}/UI:${m.userInteraction}/S:${m.scope}/C:${m.confidentiality}/I:${m.integrity}/A:${m.availability}`
})

const calculatedScore = computed(() => {
  const m = metrics.value

  // Get weights
  const avWeight = AV_WEIGHTS[m.attackVector]
  const acWeight = AC_WEIGHTS[m.attackComplexity]
  const prWeights = m.scope === 'C' ? PR_WEIGHTS_CHANGED : PR_WEIGHTS_UNCHANGED
  const prWeight = prWeights[m.privilegesRequired]
  const uiWeight = UI_WEIGHTS[m.userInteraction]

  const cWeight = IMPACT_WEIGHTS[m.confidentiality]
  const iWeight = IMPACT_WEIGHTS[m.integrity]
  const aWeight = IMPACT_WEIGHTS[m.availability]

  // Calculate ISS (Impact Sub-Score)
  const iss = 1 - ((1 - cWeight) * (1 - iWeight) * (1 - aWeight))

  // If no impact, score is 0
  if (iss <= 0) {
    return 0.0
  }

  // Calculate Impact
  let impact
  if (m.scope === 'U') {
    impact = 6.42 * iss
  } else {
    impact = 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15)
  }

  // Calculate Exploitability
  const exploitability = 8.22 * avWeight * acWeight * prWeight * uiWeight

  // Calculate Base Score
  let baseScore
  if (impact <= 0) {
    baseScore = 0
  } else if (m.scope === 'U') {
    baseScore = Math.min(impact + exploitability, 10)
  } else {
    baseScore = Math.min(1.08 * (impact + exploitability), 10)
  }

  // Round up to 1 decimal place (CVSS spec)
  return Math.ceil(baseScore * 10) / 10
})

const severityLabel = computed(() => {
  const score = calculatedScore.value
  if (score >= 9.0) return 'Critical'
  if (score >= 7.0) return 'High'
  if (score >= 4.0) return 'Medium'
  if (score >= 0.1) return 'Low'
  return 'None'
})

const severityClass = computed(() => {
  const score = calculatedScore.value
  if (score >= 9.0) return 'severity-critical'
  if (score >= 7.0) return 'severity-high'
  if (score >= 4.0) return 'severity-medium'
  if (score >= 0.1) return 'severity-low'
  return 'severity-none'
})

// Watchers
watch([calculatedScore, vectorString], ([score, vector]) => {
  emit('update:score', score)
  emit('update:vector', vector)
})

// Methods
function resetMetrics() {
  metrics.value = {
    attackVector: 'N',
    attackComplexity: 'L',
    privilegesRequired: 'N',
    userInteraction: 'N',
    scope: 'U',
    confidentiality: 'H',
    integrity: 'H',
    availability: 'H'
  }
}

async function copyVector() {
  try {
    await navigator.clipboard.writeText(vectorString.value)
    copied.value = true
    setTimeout(() => { copied.value = false }, 2000)
  } catch (err) {
    console.error('Failed to copy:', err)
  }
}
</script>

<style scoped>
.cvss-calculator {
  background: var(--bg-secondary);
  border-radius: 8px;
  padding: 1.5rem;
  margin: 1rem 0;
}

.calculator-header {
  margin-bottom: 1.5rem;
}

.calculator-header h3 {
  margin: 0 0 0.25rem;
  color: var(--text-primary);
}

.subtitle {
  color: var(--text-secondary);
  font-size: 0.875rem;
  margin: 0;
}

.metrics-section h4 {
  margin: 0 0 1rem;
  color: var(--text-primary);
  font-size: 1rem;
}

.impact-header {
  margin-top: 1.5rem !important;
}

.metrics-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 1.25rem;
}

.metric-group {
  background: var(--bg-primary);
  padding: 1rem;
  border-radius: 6px;
}

.metric-group > label {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-weight: 600;
  font-size: 0.875rem;
  margin-bottom: 0.75rem;
  color: var(--text-primary);
}

.info-icon {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 16px;
  height: 16px;
  font-size: 12px;
  color: var(--text-tertiary);
  cursor: help;
  position: relative;
  transition: color 0.2s;
}

.info-icon:hover {
  color: var(--accent-color);
}

.info-icon::after {
  content: attr(data-tooltip);
  position: absolute;
  bottom: calc(100% + 8px);
  left: 50%;
  transform: translateX(-50%);
  padding: 0.75rem 1rem;
  background: var(--bg-primary);
  border: 1px solid var(--border-color);
  border-radius: 6px;
  font-size: 0.75rem;
  font-weight: 400;
  line-height: 1.5;
  color: var(--text-secondary);
  white-space: normal;
  width: 280px;
  max-width: 90vw;
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
  z-index: 1000;
  opacity: 0;
  visibility: hidden;
  transition: opacity 0.2s, visibility 0.2s;
  pointer-events: none;
}

.info-icon:hover::after {
  opacity: 1;
  visibility: visible;
}

.info-icon::before {
  content: '';
  position: absolute;
  bottom: calc(100% + 2px);
  left: 50%;
  transform: translateX(-50%);
  border: 6px solid transparent;
  border-top-color: var(--border-color);
  z-index: 1001;
  opacity: 0;
  visibility: hidden;
  transition: opacity 0.2s, visibility 0.2s;
}

.info-icon:hover::before {
  opacity: 1;
  visibility: visible;
}

.radio-group {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.radio-option {
  display: flex;
  align-items: flex-start;
  gap: 0.5rem;
  cursor: pointer;
  padding: 0.35rem 0;
}

.radio-option input[type="radio"] {
  margin-top: 0.15rem;
}

.radio-label {
  font-weight: 500;
  font-size: 0.875rem;
  color: var(--text-primary);
}

.radio-desc {
  font-size: 0.75rem;
  color: var(--text-tertiary);
  margin-left: 0.25rem;
}

.results-section {
  margin-top: 2rem;
  padding-top: 1.5rem;
  border-top: 1px solid var(--border-color);
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 1.5rem;
}

.score-display {
  text-align: center;
  padding: 1rem 1.5rem;
  border-radius: 8px;
  min-width: 100px;
}

.score-value {
  font-size: 2rem;
  font-weight: bold;
  color: white;
}

.severity-label {
  font-size: 0.875rem;
  font-weight: 600;
  color: white;
  text-transform: uppercase;
}

.severity-critical {
  background: #8b0000;
}

.severity-high {
  background: #e74c3c;
}

.severity-medium {
  background: #f39c12;
}

.severity-low {
  background: #27ae60;
}

.severity-none {
  background: #3498db;
}

.vector-display {
  flex: 1;
  min-width: 300px;
}

.vector-display > label {
  display: block;
  font-size: 0.75rem;
  color: var(--text-secondary);
  margin-bottom: 0.25rem;
}

.vector-string {
  display: flex;
  gap: 0.5rem;
}

.vector-string input {
  flex: 1;
  padding: 0.5rem 0.75rem;
  font-family: monospace;
  font-size: 0.875rem;
  background: var(--bg-primary);
  border: 1px solid var(--border-color);
  border-radius: 4px;
  color: var(--text-primary);
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
  padding: 0.5rem 0.75rem;
}

.btn-primary {
  background: var(--accent-color);
  color: white;
}

.btn-primary:hover {
  background: var(--accent-hover);
}

.btn-secondary {
  background: var(--bg-tertiary);
  color: var(--text-primary);
}

.btn-secondary:hover {
  background: var(--border-color);
}
</style>
