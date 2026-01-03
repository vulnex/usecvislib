/**
 * VULNEX -Universal Security Visualization Library-
 *
 * File: editor-theme.js
 * Author: Simon Roses Femerling
 * Created: 2025-01-01
 * Last Modified: 2025-12-23
 * Version: 0.3.1
 * License: Apache-2.0
 * Copyright (c) 2025 VULNEX. All rights reserved.
 * https://www.vulnex.com
 *
 * Dark theme for CodeMirror 6 matching USecVisLib UI
 */

import { EditorView } from '@codemirror/view'
import { HighlightStyle, syntaxHighlighting } from '@codemirror/language'
import { tags as t } from '@lezer/highlight'

// Theme colors matching styles.css CSS variables
const colors = {
  bgPrimary: '#0f172a',
  bgSecondary: '#1e293b',
  bgTertiary: '#334155',
  textPrimary: '#f8fafc',
  textSecondary: '#94a3b8',
  textMuted: '#64748b',
  primary: '#6366f1',
  accent: '#f59e0b',
  success: '#10b981',
  danger: '#ef4444',
  border: '#334155',
}

// Editor base theme
export const editorTheme = EditorView.theme({
  '&': {
    backgroundColor: colors.bgTertiary,
    color: colors.textPrimary,
    fontSize: '14px',
    fontFamily: 'ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace',
  },
  '.cm-content': {
    caretColor: colors.primary,
    padding: '12px 0',
  },
  '.cm-cursor, .cm-dropCursor': {
    borderLeftColor: colors.primary,
    borderLeftWidth: '2px',
  },
  '&.cm-focused .cm-cursor': {
    borderLeftColor: colors.primary,
  },
  '.cm-selectionBackground, ::selection': {
    backgroundColor: `${colors.primary}40`,
  },
  '&.cm-focused .cm-selectionBackground, &.cm-focused ::selection': {
    backgroundColor: `${colors.primary}50`,
  },
  '.cm-gutters': {
    backgroundColor: colors.bgSecondary,
    color: colors.textMuted,
    border: 'none',
    borderRight: `1px solid ${colors.border}`,
  },
  '.cm-lineNumbers .cm-gutterElement': {
    padding: '0 12px 0 8px',
    minWidth: '40px',
  },
  '.cm-activeLineGutter': {
    backgroundColor: colors.bgTertiary,
    color: colors.textSecondary,
  },
  '.cm-activeLine': {
    backgroundColor: `${colors.bgSecondary}80`,
  },
  '.cm-foldPlaceholder': {
    backgroundColor: colors.bgTertiary,
    color: colors.textSecondary,
    border: 'none',
  },
  '.cm-tooltip': {
    backgroundColor: colors.bgSecondary,
    border: `1px solid ${colors.border}`,
    borderRadius: '6px',
  },
  // Lint gutter and diagnostics
  '.cm-lintGutter': {
    width: '16px',
  },
  '.cm-diagnostic': {
    padding: '8px 12px',
    borderRadius: '4px',
    marginTop: '4px',
  },
  '.cm-diagnostic-error': {
    backgroundColor: `${colors.danger}20`,
    borderLeft: `3px solid ${colors.danger}`,
  },
  '.cm-diagnostic-warning': {
    backgroundColor: `${colors.accent}20`,
    borderLeft: `3px solid ${colors.accent}`,
  },
  // Scrollbar styling
  '.cm-scroller': {
    overflow: 'auto',
  },
  '.cm-scroller::-webkit-scrollbar': {
    width: '8px',
    height: '8px',
  },
  '.cm-scroller::-webkit-scrollbar-track': {
    backgroundColor: colors.bgSecondary,
  },
  '.cm-scroller::-webkit-scrollbar-thumb': {
    backgroundColor: colors.border,
    borderRadius: '4px',
  },
  '.cm-scroller::-webkit-scrollbar-thumb:hover': {
    backgroundColor: colors.textMuted,
  },
}, { dark: true })

// Syntax highlighting
export const highlightStyle = HighlightStyle.define([
  { tag: t.comment, color: colors.textMuted, fontStyle: 'italic' },
  { tag: t.string, color: colors.success },
  { tag: t.number, color: colors.accent },
  { tag: t.bool, color: colors.accent },
  { tag: t.atom, color: '#a78bfa' },  // Purple for dates
  { tag: t.keyword, color: colors.primary },
  { tag: t.propertyName, color: '#93c5fd' },  // Light blue for keys
  { tag: t.variableName, color: colors.textPrimary },
  { tag: t.namespace, color: colors.primary, fontWeight: 'bold' },
  { tag: t.meta, color: colors.primary },
  { tag: t.punctuation, color: colors.textSecondary },
  { tag: t.bracket, color: colors.textSecondary },
  { tag: t.invalid, color: colors.danger },
])

// Combined theme extension
export const darkTheme = [
  editorTheme,
  syntaxHighlighting(highlightStyle),
]
