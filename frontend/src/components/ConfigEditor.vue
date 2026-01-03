<template>
  <div class="config-editor-container" :class="{ collapsed: isCollapsed }">
    <div class="editor-header" @click="isCollapsed && toggleCollapse()">
      <div class="editor-title">
        <button
          class="btn-collapse"
          @click.stop="toggleCollapse"
          :title="isCollapsed ? 'Expand editor' : 'Collapse editor'"
        >
          <span class="collapse-icon">{{ isCollapsed ? '&#x25B6;' : '&#x25BC;' }}</span>
        </button>
        <span class="editor-icon">&#x1F4DD;</span>
        <span>{{ title || 'Configuration Editor' }}</span>
        <span v-if="fileName" class="file-name">- {{ fileName }}</span>
        <span v-if="detectedFormat" class="format-badge" :class="detectedFormat">
          {{ detectedFormat.toUpperCase() }}
        </span>
        <span v-if="isCollapsed" class="collapsed-hint">(click to expand)</span>
      </div>
      <div class="editor-actions">
        <button
          class="btn btn-small"
          @click="copyContent"
          title="Copy to clipboard"
        >
          Copy
        </button>
        <button
          class="btn btn-small btn-danger"
          @click="clearEditor"
          title="Clear editor"
        >
          Clear
        </button>
      </div>
    </div>

    <div v-show="!isCollapsed" ref="editorContainer" class="editor-wrapper"></div>

    <div v-if="!isCollapsed && validationErrors.length > 0" class="validation-summary">
      <div class="validation-header">
        <span class="error-icon">&#x26A0;</span>
        <span>{{ validationErrors.length }} issue{{ validationErrors.length > 1 ? 's' : '' }} found</span>
      </div>
      <ul class="error-list">
        <li v-for="(error, i) in validationErrors" :key="i" :class="error.severity">
          {{ error.message }}
        </li>
      </ul>
    </div>

    <div v-else-if="!isCollapsed && content && content.trim()" class="validation-success">
      <span class="success-icon">&#x2705;</span>
      Valid {{ detectedFormat ? detectedFormat.toUpperCase() : 'configuration' }} syntax
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted, watch, computed } from 'vue'
import { EditorState } from '@codemirror/state'
import { EditorView, keymap, lineNumbers, highlightActiveLine, highlightActiveLineGutter } from '@codemirror/view'
import { defaultKeymap, history, historyKeymap } from '@codemirror/commands'
import { searchKeymap, highlightSelectionMatches } from '@codemirror/search'
import { linter, lintGutter } from '@codemirror/lint'
import { json } from '@codemirror/lang-json'
import { yaml } from '@codemirror/lang-yaml'
import { toml } from '../utils/toml-language.js'
import { darkTheme } from '../utils/editor-theme.js'
import {
  detectFormat,
  validateConfig,
  validateAttackTreeStructure,
  validateThreatModelStructure
} from '../utils/config-validator.js'

const props = defineProps({
  modelValue: { type: String, default: '' },
  title: { type: String, default: '' },
  fileName: { type: String, default: '' },
  format: {
    type: String,
    default: '',
    validator: (v) => ['', 'toml', 'json', 'yaml'].includes(v)
  },
  validationType: {
    type: String,
    default: 'syntax',
    validator: (v) => ['syntax', 'attack-tree', 'threat-model'].includes(v)
  },
  readOnly: { type: Boolean, default: false },
  minHeight: { type: String, default: '300px' },
  maxHeight: { type: String, default: '500px' },
})

const emit = defineEmits(['update:modelValue', 'validation-change', 'format-detected'])

const editorContainer = ref(null)
const content = ref(props.modelValue)
const validationErrors = ref([])
const detectedFormat = ref(props.format || 'toml')
const isCollapsed = ref(false)
let editorView = null

// Toggle collapse state
function toggleCollapse() {
  isCollapsed.value = !isCollapsed.value
}

// Computed property for checking errors
const hasErrors = computed(() => {
  return validationErrors.value.some(e => e.severity === 'error')
})

// Detect format from content or filename
function updateDetectedFormat() {
  if (props.format) {
    detectedFormat.value = props.format
  } else {
    detectedFormat.value = detectFormat(content.value, props.fileName)
  }
  emit('format-detected', detectedFormat.value)
}

// Get language extension based on format
function getLanguageExtension() {
  switch (detectedFormat.value) {
    case 'json':
      return json()
    case 'yaml':
      return yaml()
    case 'toml':
    default:
      return toml()
  }
}

// Create linter based on validation type and format
function createLinter() {
  return linter((view) => {
    const text = view.state.doc.toString()
    let diagnostics = []
    const format = detectedFormat.value

    switch (props.validationType) {
      case 'attack-tree':
        diagnostics = validateAttackTreeStructure(text, format)
        break
      case 'threat-model':
        diagnostics = validateThreatModelStructure(text, format)
        break
      default:
        diagnostics = validateConfig(text, format)
    }

    validationErrors.value = diagnostics
    emit('validation-change', { valid: diagnostics.length === 0, errors: diagnostics, format })

    return diagnostics
  }, { delay: 300 })
}

// Create update listener to emit changes
function createUpdateListener() {
  return EditorView.updateListener.of((update) => {
    if (update.docChanged) {
      const newContent = update.state.doc.toString()
      content.value = newContent
      emit('update:modelValue', newContent)

      // Re-detect format if not explicitly set
      if (!props.format) {
        const newFormat = detectFormat(newContent, props.fileName)
        if (newFormat !== detectedFormat.value) {
          detectedFormat.value = newFormat
          emit('format-detected', newFormat)
          // Reinitialize editor with new language
          initEditor()
        }
      }
    }
  })
}

// Initialize editor
function initEditor() {
  if (!editorContainer.value) return

  // Clean up existing editor
  if (editorView) {
    editorView.destroy()
  }

  const extensions = [
    // Basic editor setup
    lineNumbers(),
    highlightActiveLine(),
    highlightActiveLineGutter(),
    history(),
    highlightSelectionMatches(),

    // Keymaps
    keymap.of([
      ...defaultKeymap,
      ...historyKeymap,
      ...searchKeymap,
    ]),

    // Language mode based on format
    getLanguageExtension(),

    // Dark theme
    ...darkTheme,

    // Linting
    lintGutter(),
    createLinter(),

    // Update listener
    createUpdateListener(),

    // Read-only mode
    EditorState.readOnly.of(props.readOnly),

    // Editor dimensions
    EditorView.theme({
      '&': {
        minHeight: props.minHeight,
        maxHeight: props.maxHeight,
      },
      '.cm-scroller': {
        overflow: 'auto',
      },
    }),
  ]

  const startState = EditorState.create({
    doc: props.modelValue,
    extensions,
  })

  editorView = new EditorView({
    state: startState,
    parent: editorContainer.value,
  })
}

// Update editor content programmatically
function setContent(newContent) {
  if (editorView) {
    const transaction = editorView.state.update({
      changes: {
        from: 0,
        to: editorView.state.doc.length,
        insert: newContent,
      },
    })
    editorView.dispatch(transaction)
  }
}

// Copy content to clipboard
async function copyContent() {
  try {
    await navigator.clipboard.writeText(content.value)
  } catch (e) {
    console.error('Failed to copy:', e)
  }
}

// Clear editor
function clearEditor() {
  setContent('')
  emit('update:modelValue', '')
}

// Watch for external modelValue changes
watch(() => props.modelValue, (newValue) => {
  if (editorView && newValue !== editorView.state.doc.toString()) {
    setContent(newValue)
  }
})

// Watch for fileName changes to update format detection
watch(() => props.fileName, () => {
  updateDetectedFormat()
  initEditor()
})

// Watch for format prop changes
watch(() => props.format, (newFormat) => {
  if (newFormat) {
    detectedFormat.value = newFormat
    initEditor()
  }
})

// Watch for validation type changes
watch(() => props.validationType, () => {
  initEditor()
})

onMounted(() => {
  updateDetectedFormat()
  initEditor()
})

onUnmounted(() => {
  if (editorView) {
    editorView.destroy()
  }
})

// Expose methods for parent component
defineExpose({
  setContent,
  getContent: () => content.value,
  getFormat: () => detectedFormat.value,
  hasErrors,
  getErrors: () => validationErrors.value,
})
</script>

<style scoped>
.config-editor-container {
  background: var(--bg-secondary);
  border: 1px solid var(--border-color);
  border-radius: var(--border-radius);
  overflow: hidden;
}

.editor-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 0.75rem 1rem;
  background: var(--bg-tertiary);
  border-bottom: 1px solid var(--border-color);
}

.editor-title {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-weight: 500;
  color: var(--text-primary);
}

.btn-collapse {
  background: none;
  border: none;
  padding: 0.25rem;
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  color: var(--text-secondary);
  transition: var(--transition);
  border-radius: 4px;
}

.btn-collapse:hover {
  background: var(--bg-secondary);
  color: var(--text-primary);
}

.collapse-icon {
  font-size: 0.7rem;
  line-height: 1;
}

.collapsed-hint {
  font-size: 0.75rem;
  color: var(--text-tertiary);
  font-weight: 400;
  font-style: italic;
}

.config-editor-container.collapsed .editor-header {
  cursor: pointer;
}

.config-editor-container.collapsed .editor-header:hover {
  background: var(--bg-secondary);
}

.editor-icon {
  font-size: 1.1rem;
}

.file-name {
  color: var(--text-secondary);
  font-weight: 400;
}

.format-badge {
  padding: 0.15rem 0.4rem;
  font-size: 0.65rem;
  font-weight: 600;
  border-radius: 3px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.format-badge.toml {
  background: rgba(147, 51, 234, 0.2);
  color: #c4b5fd;
}

.format-badge.json {
  background: rgba(59, 130, 246, 0.2);
  color: #93c5fd;
}

.format-badge.yaml {
  background: rgba(16, 185, 129, 0.2);
  color: #6ee7b7;
}

.editor-actions {
  display: flex;
  gap: 0.5rem;
}

.btn-small {
  padding: 0.35rem 0.65rem;
  font-size: 0.8rem;
  background: var(--bg-secondary);
  color: var(--text-primary);
  border: 1px solid var(--border-color);
  border-radius: var(--border-radius);
  cursor: pointer;
  transition: var(--transition);
}

.btn-small:hover:not(:disabled) {
  background: var(--bg-primary);
  border-color: var(--primary);
}

.btn-small:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.btn-small.btn-danger:hover:not(:disabled) {
  background: rgba(239, 68, 68, 0.15);
  border-color: var(--danger);
  color: var(--danger);
}

.editor-wrapper {
  width: 100%;
}

.editor-wrapper :deep(.cm-editor) {
  outline: none;
}

.validation-summary {
  padding: 0.75rem 1rem;
  background: rgba(239, 68, 68, 0.1);
  border-top: 1px solid var(--border-color);
}

.validation-header {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-weight: 500;
  color: var(--danger);
  margin-bottom: 0.5rem;
}

.error-icon {
  font-size: 1rem;
}

.error-list {
  list-style: none;
  padding: 0;
  margin: 0;
}

.error-list li {
  padding: 0.25rem 0;
  font-size: 0.85rem;
  color: #fca5a5;
}

.error-list li.warning {
  color: var(--accent);
}

.validation-success {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.75rem 1rem;
  background: rgba(16, 185, 129, 0.1);
  border-top: 1px solid var(--border-color);
  color: var(--success);
  font-size: 0.9rem;
}

.success-icon {
  font-size: 1rem;
}
</style>
