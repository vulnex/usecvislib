<!--
  VULNEX -Universal Security Visualization Library-

  File: CVSSCalculator.vue
  Author: Simon Roses Femerling
  Created: 2025-12-26
  Last Modified: 2025-01-15
  Version: 0.4.0
  License: Apache-2.0
  Copyright (c) 2025 VULNEX. All rights reserved.
  https://www.vulnex.com
-->
<template>
  <div class="cvss-calculator">
    <div class="calculator-header">
      <h3>CVSS Calculator</h3>
      <p class="subtitle">Calculate and generate CVSS vector strings for vulnerabilities</p>
    </div>

    <div class="calculator-body">
      <!-- Version Toggle -->
      <div class="version-toggle">
        <button
          class="version-btn"
          :class="{ active: selectedVersion === '3.1' }"
          @click="selectedVersion = '3.1'"
        >
          CVSS 3.1
        </button>
        <button
          class="version-btn"
          :class="{ active: selectedVersion === '4.0' }"
          @click="selectedVersion = '4.0'"
        >
          CVSS 4.0
        </button>
      </div>

      <!-- Vector Import Section -->
      <div class="vector-import-section">
        <label>Import Vector String</label>
        <div class="vector-import-row">
          <input
            type="text"
            v-model="importVector"
            :placeholder="selectedVersion === '4.0' ? 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N' : 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'"
            @keyup.enter="parseImportedVector"
            :class="{ 'input-error': importError, 'input-success': importSuccess }"
          />
          <button class="btn btn-primary btn-small" @click="parseImportedVector">Parse</button>
        </div>
        <div v-if="importError" class="import-message error">{{ importError }}</div>
        <div v-if="importSuccess" class="import-message success">{{ importSuccess }}</div>
      </div>

      <!-- CVSS 3.1 Metrics -->
      <div v-if="selectedVersion === '3.1'" class="metrics-section">
        <h4>Base Metrics</h4>

        <div class="metrics-grid">
          <!-- Attack Vector -->
          <div class="metric-group">
            <label>
              Attack Vector (AV)
              <span class="info-icon" :data-tooltip="metricDescriptions31.attackVector">ⓘ</span>
            </label>
            <div class="radio-group">
              <label class="radio-option" v-for="opt in attackVectorOptions31" :key="opt.value">
                <input type="radio" v-model="metrics31.attackVector" :value="opt.value" />
                <span class="radio-label">{{ opt.label }}</span>
                <span class="radio-desc">{{ opt.description }}</span>
              </label>
            </div>
          </div>

          <!-- Attack Complexity -->
          <div class="metric-group">
            <label>
              Attack Complexity (AC)
              <span class="info-icon" :data-tooltip="metricDescriptions31.attackComplexity">ⓘ</span>
            </label>
            <div class="radio-group">
              <label class="radio-option" v-for="opt in attackComplexityOptions31" :key="opt.value">
                <input type="radio" v-model="metrics31.attackComplexity" :value="opt.value" />
                <span class="radio-label">{{ opt.label }}</span>
                <span class="radio-desc">{{ opt.description }}</span>
              </label>
            </div>
          </div>

          <!-- Privileges Required -->
          <div class="metric-group">
            <label>
              Privileges Required (PR)
              <span class="info-icon" :data-tooltip="metricDescriptions31.privilegesRequired">ⓘ</span>
            </label>
            <div class="radio-group">
              <label class="radio-option" v-for="opt in privilegesRequiredOptions31" :key="opt.value">
                <input type="radio" v-model="metrics31.privilegesRequired" :value="opt.value" />
                <span class="radio-label">{{ opt.label }}</span>
                <span class="radio-desc">{{ opt.description }}</span>
              </label>
            </div>
          </div>

          <!-- User Interaction -->
          <div class="metric-group">
            <label>
              User Interaction (UI)
              <span class="info-icon" :data-tooltip="metricDescriptions31.userInteraction">ⓘ</span>
            </label>
            <div class="radio-group">
              <label class="radio-option" v-for="opt in userInteractionOptions31" :key="opt.value">
                <input type="radio" v-model="metrics31.userInteraction" :value="opt.value" />
                <span class="radio-label">{{ opt.label }}</span>
                <span class="radio-desc">{{ opt.description }}</span>
              </label>
            </div>
          </div>

          <!-- Scope -->
          <div class="metric-group">
            <label>
              Scope (S)
              <span class="info-icon" :data-tooltip="metricDescriptions31.scope">ⓘ</span>
            </label>
            <div class="radio-group">
              <label class="radio-option" v-for="opt in scopeOptions31" :key="opt.value">
                <input type="radio" v-model="metrics31.scope" :value="opt.value" />
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
              <span class="info-icon" :data-tooltip="metricDescriptions31.confidentiality">ⓘ</span>
            </label>
            <div class="radio-group">
              <label class="radio-option" v-for="opt in impactOptions31" :key="opt.value">
                <input type="radio" v-model="metrics31.confidentiality" :value="opt.value" />
                <span class="radio-label">{{ opt.label }}</span>
                <span class="radio-desc">{{ opt.description }}</span>
              </label>
            </div>
          </div>

          <!-- Integrity Impact -->
          <div class="metric-group">
            <label>
              Integrity Impact (I)
              <span class="info-icon" :data-tooltip="metricDescriptions31.integrity">ⓘ</span>
            </label>
            <div class="radio-group">
              <label class="radio-option" v-for="opt in impactOptions31" :key="opt.value">
                <input type="radio" v-model="metrics31.integrity" :value="opt.value" />
                <span class="radio-label">{{ opt.label }}</span>
                <span class="radio-desc">{{ opt.description }}</span>
              </label>
            </div>
          </div>

          <!-- Availability Impact -->
          <div class="metric-group">
            <label>
              Availability Impact (A)
              <span class="info-icon" :data-tooltip="metricDescriptions31.availability">ⓘ</span>
            </label>
            <div class="radio-group">
              <label class="radio-option" v-for="opt in impactOptions31" :key="opt.value">
                <input type="radio" v-model="metrics31.availability" :value="opt.value" />
                <span class="radio-label">{{ opt.label }}</span>
                <span class="radio-desc">{{ opt.description }}</span>
              </label>
            </div>
          </div>
        </div>
      </div>

      <!-- CVSS 4.0 Metrics -->
      <div v-if="selectedVersion === '4.0'" class="metrics-section">
        <h4>Exploitability Metrics</h4>

        <div class="metrics-grid">
          <!-- Attack Vector -->
          <div class="metric-group">
            <label>
              Attack Vector (AV)
              <span class="info-icon" :data-tooltip="metricDescriptions40.attackVector">ⓘ</span>
            </label>
            <div class="radio-group">
              <label class="radio-option" v-for="opt in attackVectorOptions40" :key="opt.value">
                <input type="radio" v-model="metrics40.attackVector" :value="opt.value" />
                <span class="radio-label">{{ opt.label }}</span>
                <span class="radio-desc">{{ opt.description }}</span>
              </label>
            </div>
          </div>

          <!-- Attack Complexity -->
          <div class="metric-group">
            <label>
              Attack Complexity (AC)
              <span class="info-icon" :data-tooltip="metricDescriptions40.attackComplexity">ⓘ</span>
            </label>
            <div class="radio-group">
              <label class="radio-option" v-for="opt in attackComplexityOptions40" :key="opt.value">
                <input type="radio" v-model="metrics40.attackComplexity" :value="opt.value" />
                <span class="radio-label">{{ opt.label }}</span>
                <span class="radio-desc">{{ opt.description }}</span>
              </label>
            </div>
          </div>

          <!-- Attack Requirements (NEW in 4.0) -->
          <div class="metric-group">
            <label>
              Attack Requirements (AT)
              <span class="info-icon" :data-tooltip="metricDescriptions40.attackRequirements">ⓘ</span>
            </label>
            <div class="radio-group">
              <label class="radio-option" v-for="opt in attackRequirementsOptions40" :key="opt.value">
                <input type="radio" v-model="metrics40.attackRequirements" :value="opt.value" />
                <span class="radio-label">{{ opt.label }}</span>
                <span class="radio-desc">{{ opt.description }}</span>
              </label>
            </div>
          </div>

          <!-- Privileges Required -->
          <div class="metric-group">
            <label>
              Privileges Required (PR)
              <span class="info-icon" :data-tooltip="metricDescriptions40.privilegesRequired">ⓘ</span>
            </label>
            <div class="radio-group">
              <label class="radio-option" v-for="opt in privilegesRequiredOptions40" :key="opt.value">
                <input type="radio" v-model="metrics40.privilegesRequired" :value="opt.value" />
                <span class="radio-label">{{ opt.label }}</span>
                <span class="radio-desc">{{ opt.description }}</span>
              </label>
            </div>
          </div>

          <!-- User Interaction (expanded in 4.0) -->
          <div class="metric-group">
            <label>
              User Interaction (UI)
              <span class="info-icon" :data-tooltip="metricDescriptions40.userInteraction">ⓘ</span>
            </label>
            <div class="radio-group">
              <label class="radio-option" v-for="opt in userInteractionOptions40" :key="opt.value">
                <input type="radio" v-model="metrics40.userInteraction" :value="opt.value" />
                <span class="radio-label">{{ opt.label }}</span>
                <span class="radio-desc">{{ opt.description }}</span>
              </label>
            </div>
          </div>
        </div>

        <h4 class="impact-header">Vulnerable System Impact</h4>

        <div class="metrics-grid">
          <!-- Vulnerable Confidentiality -->
          <div class="metric-group">
            <label>
              Confidentiality (VC)
              <span class="info-icon" :data-tooltip="metricDescriptions40.vulnConfidentiality">ⓘ</span>
            </label>
            <div class="radio-group">
              <label class="radio-option" v-for="opt in impactOptions40" :key="opt.value">
                <input type="radio" v-model="metrics40.vulnConfidentiality" :value="opt.value" />
                <span class="radio-label">{{ opt.label }}</span>
                <span class="radio-desc">{{ opt.description }}</span>
              </label>
            </div>
          </div>

          <!-- Vulnerable Integrity -->
          <div class="metric-group">
            <label>
              Integrity (VI)
              <span class="info-icon" :data-tooltip="metricDescriptions40.vulnIntegrity">ⓘ</span>
            </label>
            <div class="radio-group">
              <label class="radio-option" v-for="opt in impactOptions40" :key="opt.value">
                <input type="radio" v-model="metrics40.vulnIntegrity" :value="opt.value" />
                <span class="radio-label">{{ opt.label }}</span>
                <span class="radio-desc">{{ opt.description }}</span>
              </label>
            </div>
          </div>

          <!-- Vulnerable Availability -->
          <div class="metric-group">
            <label>
              Availability (VA)
              <span class="info-icon" :data-tooltip="metricDescriptions40.vulnAvailability">ⓘ</span>
            </label>
            <div class="radio-group">
              <label class="radio-option" v-for="opt in impactOptions40" :key="opt.value">
                <input type="radio" v-model="metrics40.vulnAvailability" :value="opt.value" />
                <span class="radio-label">{{ opt.label }}</span>
                <span class="radio-desc">{{ opt.description }}</span>
              </label>
            </div>
          </div>
        </div>

        <h4 class="impact-header">Subsequent System Impact</h4>

        <div class="metrics-grid">
          <!-- Subsequent Confidentiality -->
          <div class="metric-group">
            <label>
              Confidentiality (SC)
              <span class="info-icon" :data-tooltip="metricDescriptions40.subseqConfidentiality">ⓘ</span>
            </label>
            <div class="radio-group">
              <label class="radio-option" v-for="opt in impactOptions40" :key="opt.value">
                <input type="radio" v-model="metrics40.subseqConfidentiality" :value="opt.value" />
                <span class="radio-label">{{ opt.label }}</span>
                <span class="radio-desc">{{ opt.description }}</span>
              </label>
            </div>
          </div>

          <!-- Subsequent Integrity -->
          <div class="metric-group">
            <label>
              Integrity (SI)
              <span class="info-icon" :data-tooltip="metricDescriptions40.subseqIntegrity">ⓘ</span>
            </label>
            <div class="radio-group">
              <label class="radio-option" v-for="opt in impactOptions40" :key="opt.value">
                <input type="radio" v-model="metrics40.subseqIntegrity" :value="opt.value" />
                <span class="radio-label">{{ opt.label }}</span>
                <span class="radio-desc">{{ opt.description }}</span>
              </label>
            </div>
          </div>

          <!-- Subsequent Availability -->
          <div class="metric-group">
            <label>
              Availability (SA)
              <span class="info-icon" :data-tooltip="metricDescriptions40.subseqAvailability">ⓘ</span>
            </label>
            <div class="radio-group">
              <label class="radio-option" v-for="opt in impactOptions40" :key="opt.value">
                <input type="radio" v-model="metrics40.subseqAvailability" :value="opt.value" />
                <span class="radio-label">{{ opt.label }}</span>
                <span class="radio-desc">{{ opt.description }}</span>
              </label>
            </div>
          </div>
        </div>

        <!-- Threat Metrics (collapsible) -->
        <div class="collapsible-section">
          <button class="collapsible-header" @click="showThreatMetrics = !showThreatMetrics">
            <span>Threat Metrics (Optional)</span>
            <span class="chevron" :class="{ rotated: showThreatMetrics }">&#9660;</span>
          </button>
          <div v-if="showThreatMetrics" class="collapsible-content">
            <div class="metrics-grid">
              <!-- Exploit Maturity -->
              <div class="metric-group">
                <label>
                  Exploit Maturity (E)
                  <span class="info-icon" :data-tooltip="metricDescriptions40.exploitMaturity">ⓘ</span>
                </label>
                <div class="radio-group">
                  <label class="radio-option" v-for="opt in exploitMaturityOptions40" :key="opt.value">
                    <input type="radio" v-model="metrics40.exploitMaturity" :value="opt.value" />
                    <span class="radio-label">{{ opt.label }}</span>
                    <span class="radio-desc">{{ opt.description }}</span>
                  </label>
                </div>
              </div>
            </div>
          </div>
        </div>

        <!-- Environmental Metrics (collapsible) -->
        <div class="collapsible-section">
          <button class="collapsible-header" @click="showEnvironmentalMetrics = !showEnvironmentalMetrics">
            <span>Environmental Metrics (Optional)</span>
            <span class="chevron" :class="{ rotated: showEnvironmentalMetrics }">&#9660;</span>
          </button>
          <div v-if="showEnvironmentalMetrics" class="collapsible-content">
            <div class="metrics-grid">
              <!-- Confidentiality Requirement -->
              <div class="metric-group">
                <label>
                  Confidentiality Req. (CR)
                  <span class="info-icon" :data-tooltip="metricDescriptions40.confRequirement">ⓘ</span>
                </label>
                <div class="radio-group">
                  <label class="radio-option" v-for="opt in requirementOptions40" :key="opt.value">
                    <input type="radio" v-model="metrics40.confRequirement" :value="opt.value" />
                    <span class="radio-label">{{ opt.label }}</span>
                    <span class="radio-desc">{{ opt.description }}</span>
                  </label>
                </div>
              </div>

              <!-- Integrity Requirement -->
              <div class="metric-group">
                <label>
                  Integrity Req. (IR)
                  <span class="info-icon" :data-tooltip="metricDescriptions40.integRequirement">ⓘ</span>
                </label>
                <div class="radio-group">
                  <label class="radio-option" v-for="opt in requirementOptions40" :key="opt.value">
                    <input type="radio" v-model="metrics40.integRequirement" :value="opt.value" />
                    <span class="radio-label">{{ opt.label }}</span>
                    <span class="radio-desc">{{ opt.description }}</span>
                  </label>
                </div>
              </div>

              <!-- Availability Requirement -->
              <div class="metric-group">
                <label>
                  Availability Req. (AR)
                  <span class="info-icon" :data-tooltip="metricDescriptions40.availRequirement">ⓘ</span>
                </label>
                <div class="radio-group">
                  <label class="radio-option" v-for="opt in requirementOptions40" :key="opt.value">
                    <input type="radio" v-model="metrics40.availRequirement" :value="opt.value" />
                    <span class="radio-label">{{ opt.label }}</span>
                    <span class="radio-desc">{{ opt.description }}</span>
                  </label>
                </div>
              </div>
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

// =============================================================================
// Version Selection (4.0 is default)
// =============================================================================
const selectedVersion = ref('4.0')

// =============================================================================
// CVSS 3.1 Configuration
// =============================================================================
const AV_WEIGHTS_31 = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }
const AC_WEIGHTS_31 = { L: 0.77, H: 0.44 }
const PR_WEIGHTS_UNCHANGED_31 = { N: 0.85, L: 0.62, H: 0.27 }
const PR_WEIGHTS_CHANGED_31 = { N: 0.85, L: 0.68, H: 0.50 }
const UI_WEIGHTS_31 = { N: 0.85, R: 0.62 }
const IMPACT_WEIGHTS_31 = { N: 0, L: 0.22, H: 0.56 }

const attackVectorOptions31 = [
  { value: 'N', label: 'Network', description: 'Exploitable from the network' },
  { value: 'A', label: 'Adjacent', description: 'Requires adjacent network access' },
  { value: 'L', label: 'Local', description: 'Requires local access' },
  { value: 'P', label: 'Physical', description: 'Requires physical access' }
]

const attackComplexityOptions31 = [
  { value: 'L', label: 'Low', description: 'No specialized conditions' },
  { value: 'H', label: 'High', description: 'Specialized conditions required' }
]

const privilegesRequiredOptions31 = [
  { value: 'N', label: 'None', description: 'No privileges required' },
  { value: 'L', label: 'Low', description: 'Low privileges required' },
  { value: 'H', label: 'High', description: 'High privileges required' }
]

const userInteractionOptions31 = [
  { value: 'N', label: 'None', description: 'No user interaction required' },
  { value: 'R', label: 'Required', description: 'User must take action' }
]

const scopeOptions31 = [
  { value: 'U', label: 'Unchanged', description: 'Impact limited to vulnerable component' },
  { value: 'C', label: 'Changed', description: 'Can affect resources beyond vulnerable component' }
]

const impactOptions31 = [
  { value: 'N', label: 'None', description: 'No impact' },
  { value: 'L', label: 'Low', description: 'Limited impact' },
  { value: 'H', label: 'High', description: 'Complete impact' }
]

const metricDescriptions31 = {
  attackVector: 'Attack Vector (AV) reflects how the vulnerability can be exploited. Network means remotely exploitable; Adjacent requires same network; Local requires local access; Physical requires physical access.',
  attackComplexity: 'Attack Complexity (AC) describes conditions beyond the attacker\'s control. Low means no special conditions; High means specific conditions must be met.',
  privilegesRequired: 'Privileges Required (PR) describes privileges needed before exploitation. None means no authentication; Low means basic user; High means admin.',
  userInteraction: 'User Interaction (UI) captures if attack requires user action. None means no user involvement; Required means user must take action.',
  scope: 'Scope (S) captures if vulnerability impacts resources beyond its security scope. Unchanged means limited to vulnerable component; Changed means can affect other resources.',
  confidentiality: 'Confidentiality Impact (C) measures impact on information confidentiality. None means no loss; Low means some disclosure; High means all disclosed.',
  integrity: 'Integrity Impact (I) measures impact on data trustworthiness. None means no loss; Low means limited modification; High means complete loss.',
  availability: 'Availability Impact (A) measures impact on resource accessibility. None means no impact; Low means reduced performance; High means complete denial.'
}

const metrics31 = ref({
  attackVector: 'N',
  attackComplexity: 'L',
  privilegesRequired: 'N',
  userInteraction: 'N',
  scope: 'U',
  confidentiality: 'H',
  integrity: 'H',
  availability: 'H'
})

// =============================================================================
// CVSS 4.0 Configuration
// =============================================================================
const attackVectorOptions40 = [
  { value: 'N', label: 'Network', description: 'Exploitable from the network' },
  { value: 'A', label: 'Adjacent', description: 'Requires adjacent network access' },
  { value: 'L', label: 'Local', description: 'Requires local access' },
  { value: 'P', label: 'Physical', description: 'Requires physical access' }
]

const attackComplexityOptions40 = [
  { value: 'L', label: 'Low', description: 'No specialized conditions' },
  { value: 'H', label: 'High', description: 'Specialized conditions required' }
]

const attackRequirementsOptions40 = [
  { value: 'N', label: 'None', description: 'No deployment/execution conditions' },
  { value: 'P', label: 'Present', description: 'Conditions exist (race condition, man-in-middle)' }
]

const privilegesRequiredOptions40 = [
  { value: 'N', label: 'None', description: 'No privileges required' },
  { value: 'L', label: 'Low', description: 'Low privileges required' },
  { value: 'H', label: 'High', description: 'High privileges required' }
]

const userInteractionOptions40 = [
  { value: 'N', label: 'None', description: 'No user interaction required' },
  { value: 'P', label: 'Passive', description: 'User involuntarily triggers exploit' },
  { value: 'A', label: 'Active', description: 'User must actively interact' }
]

const impactOptions40 = [
  { value: 'H', label: 'High', description: 'Complete impact' },
  { value: 'L', label: 'Low', description: 'Limited impact' },
  { value: 'N', label: 'None', description: 'No impact' }
]

const exploitMaturityOptions40 = [
  { value: 'X', label: 'Not Defined', description: 'Insufficient info to choose value' },
  { value: 'A', label: 'Attacked', description: 'Attacks observed in the wild' },
  { value: 'P', label: 'PoC', description: 'Proof-of-concept exists' },
  { value: 'U', label: 'Unreported', description: 'No public exploit available' }
]

const requirementOptions40 = [
  { value: 'X', label: 'Not Defined', description: 'Assume High' },
  { value: 'H', label: 'High', description: 'Critical importance' },
  { value: 'M', label: 'Medium', description: 'Moderate importance' },
  { value: 'L', label: 'Low', description: 'Limited importance' }
]

const metricDescriptions40 = {
  attackVector: 'Attack Vector (AV) reflects context by which vulnerability exploitation is possible. Network (N) means remotely exploitable without physical or local access.',
  attackComplexity: 'Attack Complexity (AC) describes conditions beyond attacker control. Low means no specialized access conditions needed.',
  attackRequirements: 'Attack Requirements (AT) captures conditions specific to the vulnerable system. None means no special deployment/execution conditions. Present means conditions like race conditions or man-in-middle position required.',
  privilegesRequired: 'Privileges Required (PR) describes privileges an attacker must have before exploitation.',
  userInteraction: 'User Interaction (UI) captures if user must participate. None means no involvement; Passive means involuntary participation; Active means user must interact.',
  vulnConfidentiality: 'Confidentiality impact on the VULNERABLE system. Measures information disclosure.',
  vulnIntegrity: 'Integrity impact on the VULNERABLE system. Measures ability to modify data.',
  vulnAvailability: 'Availability impact on the VULNERABLE system. Measures ability to deny access.',
  subseqConfidentiality: 'Confidentiality impact on SUBSEQUENT systems that may be affected.',
  subseqIntegrity: 'Integrity impact on SUBSEQUENT systems that may be affected.',
  subseqAvailability: 'Availability impact on SUBSEQUENT systems that may be affected.',
  exploitMaturity: 'Exploit Maturity (E) measures likelihood of attack based on current exploit status.',
  confRequirement: 'Confidentiality Requirement (CR) represents importance of confidentiality for the target.',
  integRequirement: 'Integrity Requirement (IR) represents importance of integrity for the target.',
  availRequirement: 'Availability Requirement (AR) represents importance of availability for the target.'
}

const metrics40 = ref({
  // Base - Exploitability
  attackVector: 'N',
  attackComplexity: 'L',
  attackRequirements: 'N',
  privilegesRequired: 'N',
  userInteraction: 'N',
  // Base - Vulnerable System Impact
  vulnConfidentiality: 'H',
  vulnIntegrity: 'H',
  vulnAvailability: 'H',
  // Base - Subsequent System Impact
  subseqConfidentiality: 'N',
  subseqIntegrity: 'N',
  subseqAvailability: 'N',
  // Threat
  exploitMaturity: 'X',
  // Environmental
  confRequirement: 'X',
  integRequirement: 'X',
  availRequirement: 'X'
})

// Collapsible sections state
const showThreatMetrics = ref(false)
const showEnvironmentalMetrics = ref(false)

// =============================================================================
// CVSS 4.0 MacroVector Lookup Table
// =============================================================================
const MACROVECTOR_LOOKUP = {
  "000000": 10.0, "000001": 9.9, "000010": 9.8, "000011": 9.5,
  "000020": 9.5, "000021": 9.2, "000100": 10.0, "000101": 9.6,
  "000110": 9.3, "000111": 8.7, "000120": 9.1, "000121": 8.1,
  "000200": 9.3, "000201": 9.0, "000210": 8.9, "000211": 8.0,
  "000220": 8.1, "000221": 6.8, "001000": 9.8, "001001": 9.5,
  "001010": 9.5, "001011": 9.2, "001020": 9.0, "001021": 8.4,
  "001100": 9.3, "001101": 9.2, "001110": 8.9, "001111": 8.1,
  "001120": 8.1, "001121": 6.5, "001200": 8.8, "001201": 8.0,
  "001210": 7.8, "001211": 7.0, "001220": 6.9, "001221": 4.8,
  "002001": 9.2, "002011": 8.2, "002021": 7.2, "002101": 7.9,
  "002111": 6.9, "002121": 5.0, "002201": 6.9, "002211": 5.5,
  "002221": 2.7, "010000": 9.9, "010001": 9.7, "010010": 9.5,
  "010011": 9.2, "010020": 9.2, "010021": 8.5, "010100": 9.5,
  "010101": 9.1, "010110": 9.0, "010111": 8.3, "010120": 8.4,
  "010121": 7.1, "010200": 9.2, "010201": 8.1, "010210": 8.2,
  "010211": 7.1, "010220": 7.2, "010221": 5.3, "011000": 9.5,
  "011001": 9.3, "011010": 9.2, "011011": 8.5, "011020": 8.5,
  "011021": 7.3, "011100": 9.2, "011101": 8.2, "011110": 8.0,
  "011111": 7.2, "011120": 7.0, "011121": 5.9, "011200": 8.4,
  "011201": 7.0, "011210": 7.1, "011211": 5.2, "011220": 5.0,
  "011221": 3.0, "012001": 8.6, "012011": 7.5, "012021": 5.2,
  "012101": 7.1, "012111": 5.2, "012121": 2.9, "012201": 6.3,
  "012211": 2.9, "012221": 1.7, "100000": 9.8, "100001": 9.5,
  "100010": 9.4, "100011": 8.7, "100020": 9.1, "100021": 8.1,
  "100100": 9.4, "100101": 8.9, "100110": 8.6, "100111": 7.4,
  "100120": 7.7, "100121": 6.4, "100200": 8.7, "100201": 7.5,
  "100210": 7.4, "100211": 6.3, "100220": 6.3, "100221": 4.9,
  "101000": 9.4, "101001": 8.9, "101010": 8.8, "101011": 7.7,
  "101020": 7.6, "101021": 6.7, "101100": 8.6, "101101": 7.6,
  "101110": 7.4, "101111": 5.8, "101120": 5.9, "101121": 5.0,
  "101200": 7.2, "101201": 5.7, "101210": 5.7, "101211": 5.2,
  "101220": 5.2, "101221": 2.5, "102001": 8.3, "102011": 7.0,
  "102021": 5.4, "102101": 6.5, "102111": 5.8, "102121": 2.6,
  "102201": 5.3, "102211": 2.1, "102221": 1.3, "110000": 9.5,
  "110001": 9.0, "110010": 8.8, "110011": 7.6, "110020": 7.6,
  "110021": 7.0, "110100": 9.0, "110101": 7.7, "110110": 7.5,
  "110111": 6.2, "110120": 6.1, "110121": 5.3, "110200": 7.7,
  "110201": 6.6, "110210": 6.8, "110211": 5.9, "110220": 5.2,
  "110221": 3.0, "111000": 8.9, "111001": 7.8, "111010": 7.6,
  "111011": 6.7, "111020": 6.2, "111021": 5.8, "111100": 7.4,
  "111101": 5.9, "111110": 5.7, "111111": 5.7, "111120": 4.7,
  "111121": 2.3, "111200": 6.1, "111201": 5.2, "111210": 5.7,
  "111211": 2.9, "111220": 2.4, "111221": 1.6, "112001": 7.1,
  "112011": 5.9, "112021": 3.0, "112101": 5.8, "112111": 2.6,
  "112121": 1.5, "112201": 2.3, "112211": 1.6, "112221": 0.6,
  "200000": 9.3, "200001": 8.7, "200010": 8.6, "200011": 7.2,
  "200020": 7.5, "200021": 5.8, "200100": 8.6, "200101": 7.4,
  "200110": 7.4, "200111": 6.1, "200120": 5.6, "200121": 3.4,
  "200200": 7.0, "200201": 5.4, "200210": 5.2, "200211": 4.0,
  "200220": 4.0, "200221": 2.2, "201000": 8.5, "201001": 7.5,
  "201010": 7.4, "201011": 5.5, "201020": 6.2, "201021": 5.1,
  "201100": 7.2, "201101": 5.7, "201110": 5.5, "201111": 4.1,
  "201120": 4.6, "201121": 1.9, "201200": 5.3, "201201": 3.6,
  "201210": 3.4, "201211": 1.9, "201220": 1.9, "201221": 0.8,
  "202001": 6.4, "202011": 5.1, "202021": 2.0, "202101": 4.7,
  "202111": 2.1, "202121": 1.1, "202201": 2.4, "202211": 0.9,
  "202221": 0.4, "210000": 8.8, "210001": 7.5, "210010": 7.3,
  "210011": 5.3, "210020": 6.0, "210021": 5.0, "210100": 7.3,
  "210101": 5.5, "210110": 5.9, "210111": 4.0, "210120": 4.1,
  "210121": 2.0, "210200": 5.4, "210201": 4.3, "210210": 4.5,
  "210211": 2.2, "210220": 2.0, "210221": 1.1, "211000": 7.5,
  "211001": 5.5, "211010": 5.8, "211011": 4.5, "211020": 4.0,
  "211021": 2.1, "211100": 6.1, "211101": 5.1, "211110": 4.8,
  "211111": 1.8, "211120": 2.0, "211121": 0.9, "211200": 4.6,
  "211201": 1.8, "211210": 1.7, "211211": 0.7, "211220": 0.8,
  "211221": 0.2, "212001": 5.3, "212011": 2.4, "212021": 1.4,
  "212101": 2.4, "212111": 1.2, "212121": 0.5, "212201": 1.0,
  "212211": 0.3, "212221": 0.1,
}

// =============================================================================
// Shared State
// =============================================================================
const copied = ref(false)
const importVector = ref('')
const importError = ref('')
const importSuccess = ref('')

// Vector patterns
const CVSS31_PATTERN = /^CVSS:3\.[01]\/AV:([NALP])\/AC:([LH])\/PR:([NLH])\/UI:([NR])\/S:([UC])\/C:([NLH])\/I:([NLH])\/A:([NLH])$/i
const CVSS40_BASE_PATTERN = /^CVSS:4\.0\/AV:([NALP])\/AC:([LH])\/AT:([NP])\/PR:([NLH])\/UI:([NPA])\/VC:([HLN])\/VI:([HLN])\/VA:([HLN])\/SC:([HLN])\/SI:([HLN])\/SA:([HLN])/i

// =============================================================================
// Computed Values
// =============================================================================
const vectorString = computed(() => {
  if (selectedVersion.value === '3.1') {
    const m = metrics31.value
    return `CVSS:3.1/AV:${m.attackVector}/AC:${m.attackComplexity}/PR:${m.privilegesRequired}/UI:${m.userInteraction}/S:${m.scope}/C:${m.confidentiality}/I:${m.integrity}/A:${m.availability}`
  } else {
    const m = metrics40.value
    let vector = `CVSS:4.0/AV:${m.attackVector}/AC:${m.attackComplexity}/AT:${m.attackRequirements}/PR:${m.privilegesRequired}/UI:${m.userInteraction}/VC:${m.vulnConfidentiality}/VI:${m.vulnIntegrity}/VA:${m.vulnAvailability}/SC:${m.subseqConfidentiality}/SI:${m.subseqIntegrity}/SA:${m.subseqAvailability}`

    // Add optional metrics if defined
    if (m.exploitMaturity !== 'X') {
      vector += `/E:${m.exploitMaturity}`
    }
    if (m.confRequirement !== 'X') {
      vector += `/CR:${m.confRequirement}`
    }
    if (m.integRequirement !== 'X') {
      vector += `/IR:${m.integRequirement}`
    }
    if (m.availRequirement !== 'X') {
      vector += `/AR:${m.availRequirement}`
    }
    return vector
  }
})

const calculatedScore = computed(() => {
  if (selectedVersion.value === '3.1') {
    return calculateScore31()
  } else {
    return calculateScore40()
  }
})

function calculateScore31() {
  const m = metrics31.value

  const avWeight = AV_WEIGHTS_31[m.attackVector]
  const acWeight = AC_WEIGHTS_31[m.attackComplexity]
  const prWeights = m.scope === 'C' ? PR_WEIGHTS_CHANGED_31 : PR_WEIGHTS_UNCHANGED_31
  const prWeight = prWeights[m.privilegesRequired]
  const uiWeight = UI_WEIGHTS_31[m.userInteraction]

  const cWeight = IMPACT_WEIGHTS_31[m.confidentiality]
  const iWeight = IMPACT_WEIGHTS_31[m.integrity]
  const aWeight = IMPACT_WEIGHTS_31[m.availability]

  const iss = 1 - ((1 - cWeight) * (1 - iWeight) * (1 - aWeight))

  if (iss <= 0) return 0.0

  let impact
  if (m.scope === 'U') {
    impact = 6.42 * iss
  } else {
    impact = 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15)
  }

  const exploitability = 8.22 * avWeight * acWeight * prWeight * uiWeight

  let baseScore
  if (impact <= 0) {
    baseScore = 0
  } else if (m.scope === 'U') {
    baseScore = Math.min(impact + exploitability, 10)
  } else {
    baseScore = Math.min(1.08 * (impact + exploitability), 10)
  }

  return Math.ceil(baseScore * 10) / 10
}

function calculateScore40() {
  const m = metrics40.value

  // Derive MacroVector (EQ1-EQ6)
  const av = m.attackVector
  const ac = m.attackComplexity
  const at = m.attackRequirements
  const pr = m.privilegesRequired
  const ui = m.userInteraction
  const vc = m.vulnConfidentiality
  const vi = m.vulnIntegrity
  const va = m.vulnAvailability
  const sc = m.subseqConfidentiality
  const si = m.subseqIntegrity
  const sa = m.subseqAvailability
  const e = m.exploitMaturity === 'X' ? 'A' : m.exploitMaturity
  const cr = m.confRequirement === 'X' ? 'H' : m.confRequirement
  const ir = m.integRequirement === 'X' ? 'H' : m.integRequirement
  const ar = m.availRequirement === 'X' ? 'H' : m.availRequirement

  // EQ1: AV/PR/UI
  let eq1
  if (av === 'N' && pr === 'N' && ui === 'N') {
    eq1 = 0
  } else if ((av === 'N' || pr === 'N' || ui === 'N') && !(av === 'N' && pr === 'N' && ui === 'N')) {
    eq1 = 1
  } else {
    eq1 = 2
  }

  // EQ2: AC/AT
  const eq2 = (ac === 'L' && at === 'N') ? 0 : 1

  // EQ3: VC/VI/VA
  let eq3
  if (vc === 'H' && vi === 'H') {
    eq3 = 0
  } else if (vc === 'H' || vi === 'H' || va === 'H') {
    eq3 = 1
  } else {
    eq3 = 2
  }

  // EQ4: SC/SI/SA
  let eq4
  if (sc === 'H' || si === 'H' || sa === 'H') {
    eq4 = 1
  } else {
    eq4 = 2
  }

  // EQ5: Exploit Maturity
  let eq5
  if (e === 'A') {
    eq5 = 0
  } else if (e === 'P') {
    eq5 = 1
  } else {
    eq5 = 2
  }

  // EQ6: Requirements
  const crHvcH = (cr === 'H' && vc === 'H')
  const irHviH = (ir === 'H' && vi === 'H')
  const arHvaH = (ar === 'H' && va === 'H')
  const eq6 = (crHvcH || irHviH || arHvaH) ? 0 : 1

  const macroVector = `${eq1}${eq2}${eq3}${eq4}${eq5}${eq6}`

  // Lookup score
  const baseScore = MACROVECTOR_LOOKUP[macroVector]
  if (baseScore === undefined) {
    return 0.0
  }

  // Apply simple interpolation adjustment
  let adjustment = 0
  if (eq1 === 1) {
    if (av !== 'N') adjustment += 0.1
    if (pr !== 'N') adjustment += 0.1
    if (ui !== 'N') adjustment += 0.1
  }
  if (eq2 === 1) {
    if (ac === 'H') adjustment += 0.1
    if (at === 'P') adjustment += 0.1
  }

  const finalScore = Math.max(0.0, baseScore - Math.min(adjustment, 1.0))
  return Math.round(finalScore * 10) / 10
}

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

// =============================================================================
// Watchers
// =============================================================================
watch([calculatedScore, vectorString], ([score, vector]) => {
  emit('update:score', score)
  emit('update:vector', vector)
})

// =============================================================================
// Methods
// =============================================================================
function resetMetrics() {
  if (selectedVersion.value === '3.1') {
    metrics31.value = {
      attackVector: 'N',
      attackComplexity: 'L',
      privilegesRequired: 'N',
      userInteraction: 'N',
      scope: 'U',
      confidentiality: 'H',
      integrity: 'H',
      availability: 'H'
    }
  } else {
    metrics40.value = {
      attackVector: 'N',
      attackComplexity: 'L',
      attackRequirements: 'N',
      privilegesRequired: 'N',
      userInteraction: 'N',
      vulnConfidentiality: 'H',
      vulnIntegrity: 'H',
      vulnAvailability: 'H',
      subseqConfidentiality: 'N',
      subseqIntegrity: 'N',
      subseqAvailability: 'N',
      exploitMaturity: 'X',
      confRequirement: 'X',
      integRequirement: 'X',
      availRequirement: 'X'
    }
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

function parseImportedVector() {
  importError.value = ''
  importSuccess.value = ''

  const input = importVector.value.trim()
  if (!input) {
    importError.value = 'Please enter a CVSS vector string'
    return
  }

  const upperInput = input.toUpperCase()

  // Try CVSS 4.0 first
  if (upperInput.startsWith('CVSS:4.0/')) {
    const match = upperInput.match(CVSS40_BASE_PATTERN)
    if (!match) {
      importError.value = 'Invalid CVSS 4.0 vector format'
      return
    }

    selectedVersion.value = '4.0'
    metrics40.value = {
      attackVector: match[1],
      attackComplexity: match[2],
      attackRequirements: match[3],
      privilegesRequired: match[4],
      userInteraction: match[5],
      vulnConfidentiality: match[6],
      vulnIntegrity: match[7],
      vulnAvailability: match[8],
      subseqConfidentiality: match[9],
      subseqIntegrity: match[10],
      subseqAvailability: match[11],
      exploitMaturity: 'X',
      confRequirement: 'X',
      integRequirement: 'X',
      availRequirement: 'X'
    }

    // Parse optional metrics
    const eMatch = upperInput.match(/\/E:([XAPU])/i)
    if (eMatch) metrics40.value.exploitMaturity = eMatch[1]

    const crMatch = upperInput.match(/\/CR:([XHML])/i)
    if (crMatch) metrics40.value.confRequirement = crMatch[1]

    const irMatch = upperInput.match(/\/IR:([XHML])/i)
    if (irMatch) metrics40.value.integRequirement = irMatch[1]

    const arMatch = upperInput.match(/\/AR:([XHML])/i)
    if (arMatch) metrics40.value.availRequirement = arMatch[1]

    importSuccess.value = `CVSS 4.0 vector parsed (Score: ${calculatedScore.value})`
    setTimeout(() => { importSuccess.value = '' }, 3000)
    return
  }

  // Try CVSS 3.x
  if (upperInput.startsWith('CVSS:3.')) {
    const match = upperInput.match(CVSS31_PATTERN)
    if (!match) {
      importError.value = 'Invalid CVSS 3.x vector format'
      return
    }

    selectedVersion.value = '3.1'
    metrics31.value = {
      attackVector: match[1],
      attackComplexity: match[2],
      privilegesRequired: match[3],
      userInteraction: match[4],
      scope: match[5],
      confidentiality: match[6],
      integrity: match[7],
      availability: match[8]
    }

    importSuccess.value = `CVSS 3.1 vector parsed (Score: ${calculatedScore.value})`
    setTimeout(() => { importSuccess.value = '' }, 3000)
    return
  }

  importError.value = 'Unrecognized CVSS version. Expected CVSS:3.1/... or CVSS:4.0/...'
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

/* Version Toggle */
.version-toggle {
  display: flex;
  gap: 0.5rem;
  margin-bottom: 1.5rem;
}

.version-btn {
  flex: 1;
  padding: 0.75rem 1rem;
  border: 2px solid var(--border-color);
  background: var(--bg-primary);
  color: var(--text-secondary);
  border-radius: 6px;
  font-weight: 600;
  font-size: 0.875rem;
  cursor: pointer;
  transition: all 0.2s;
}

.version-btn:hover {
  border-color: var(--accent-color);
  color: var(--text-primary);
}

.version-btn.active {
  border-color: var(--accent-color);
  background: var(--accent-color);
  color: white;
}

/* Metrics Section */
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

/* Collapsible Sections */
.collapsible-section {
  margin-top: 1.5rem;
  border: 1px solid var(--border-color);
  border-radius: 6px;
  overflow: hidden;
}

.collapsible-header {
  width: 100%;
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 1rem;
  background: var(--bg-primary);
  border: none;
  cursor: pointer;
  font-weight: 600;
  font-size: 0.875rem;
  color: var(--text-primary);
  transition: background 0.2s;
}

.collapsible-header:hover {
  background: var(--bg-tertiary);
}

.chevron {
  font-size: 0.75rem;
  transition: transform 0.2s;
}

.chevron.rotated {
  transform: rotate(180deg);
}

.collapsible-content {
  padding: 1rem;
  background: var(--bg-secondary);
}

/* Results Section */
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

.severity-critical { background: #8b0000; }
.severity-high { background: #e74c3c; }
.severity-medium { background: #f39c12; }
.severity-low { background: #27ae60; }
.severity-none { background: #3498db; }

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
  flex-wrap: wrap;
}

.vector-string input {
  flex: 1;
  min-width: 250px;
  padding: 0.5rem 0.75rem;
  font-family: monospace;
  font-size: 0.875rem;
  background: var(--bg-primary);
  border: 1px solid var(--border-color);
  border-radius: 4px;
  color: var(--text-primary);
}

/* Buttons */
.btn {
  padding: 0.5rem 1rem;
  border-radius: 4px;
  font-size: 0.875rem;
  cursor: pointer;
  border: none;
  transition: background 0.2s;
}

.btn-small { padding: 0.5rem 0.75rem; }

.btn-primary {
  background: var(--accent-color);
  color: white;
}

.btn-primary:hover { background: var(--accent-hover); }

.btn-secondary {
  background: var(--bg-tertiary);
  color: var(--text-primary);
}

.btn-secondary:hover { background: var(--border-color); }

/* Vector Import Section */
.vector-import-section {
  background: var(--bg-primary);
  padding: 1rem;
  border-radius: 6px;
  margin-bottom: 1.5rem;
}

.vector-import-section > label {
  display: block;
  font-weight: 600;
  font-size: 0.875rem;
  margin-bottom: 0.5rem;
  color: var(--text-primary);
}

.vector-import-row {
  display: flex;
  gap: 0.5rem;
}

.vector-import-row input {
  flex: 1;
  padding: 0.5rem 0.75rem;
  font-family: monospace;
  font-size: 0.875rem;
  background: var(--bg-secondary);
  border: 1px solid var(--border-color);
  border-radius: 4px;
  color: var(--text-primary);
  transition: border-color 0.2s;
}

.vector-import-row input:focus {
  outline: none;
  border-color: var(--accent-color);
}

.vector-import-row input.input-error { border-color: #e74c3c; }
.vector-import-row input.input-success { border-color: #27ae60; }

.import-message {
  font-size: 0.75rem;
  margin-top: 0.5rem;
  padding: 0.25rem 0;
}

.import-message.error { color: #e74c3c; }
.import-message.success { color: #27ae60; }
</style>
