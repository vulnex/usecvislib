/**
 * VULNEX -Universal Security Visualization Library-
 *
 * File: toml-language.js
 * Author: Simon Roses Femerling
 * Created: 2025-01-01
 * Last Modified: 2025-12-23
 * Version: 0.3.1
 * License: Apache-2.0
 * Copyright (c) 2025 VULNEX. All rights reserved.
 * https://www.vulnex.com
 *
 * TOML Language Support for CodeMirror 6
 * Provides syntax highlighting for TOML files using StreamLanguage.
 */

import { StreamLanguage } from '@codemirror/language'

const tomlParser = {
  token(stream, state) {
    // Skip whitespace
    if (stream.eatSpace()) return null

    // Comments
    if (stream.match('#')) {
      stream.skipToEnd()
      return 'comment'
    }

    // Table headers [table] or [[array.of.tables]]
    if (stream.match(/^\[\[?/)) {
      state.inHeader = true
      return 'meta'
    }
    if (state.inHeader && stream.match(/\]\]?/)) {
      state.inHeader = false
      return 'meta'
    }
    if (state.inHeader) {
      stream.match(/[^\]]+/)
      return 'namespace'
    }

    // Multiline basic strings """
    if (stream.match(/"""/)) {
      state.inMultilineString = 'basic'
      return 'string'
    }
    // Multiline literal strings '''
    if (stream.match(/'''/)) {
      state.inMultilineString = 'literal'
      return 'string'
    }
    if (state.inMultilineString === 'basic') {
      if (stream.match(/"""/)) {
        state.inMultilineString = null
        return 'string'
      }
      stream.next()
      return 'string'
    }
    if (state.inMultilineString === 'literal') {
      if (stream.match(/'''/)) {
        state.inMultilineString = null
        return 'string'
      }
      stream.next()
      return 'string'
    }

    // Basic strings "..."
    if (stream.match(/"(?:[^"\\]|\\.)*"/)) return 'string'
    // Literal strings '...'
    if (stream.match(/'[^']*'/)) return 'string'

    // Booleans
    if (stream.match(/\b(true|false)\b/)) return 'bool'

    // Numbers (hex, octal, binary)
    if (stream.match(/0x[0-9a-fA-F_]+/)) return 'number'
    if (stream.match(/0o[0-7_]+/)) return 'number'
    if (stream.match(/0b[01_]+/)) return 'number'
    // Special floats
    if (stream.match(/[+-]?(inf|nan)/)) return 'number'
    // Regular numbers (integers and floats)
    if (stream.match(/[+-]?\d[\d_]*(\.\d[\d_]*)?([eE][+-]?\d[\d_]*)?/)) return 'number'

    // Dates and times
    if (stream.match(/\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?)?/)) {
      return 'atom'
    }
    if (stream.match(/\d{2}:\d{2}:\d{2}(\.\d+)?/)) return 'atom'

    // Keys (identifiers before =)
    if (stream.match(/[a-zA-Z_][a-zA-Z0-9_-]*/)) {
      if (stream.peek() === '=' || stream.match(/\s*=/, false)) {
        return 'propertyName'
      }
      return 'variableName'
    }

    // Operators and punctuation
    if (stream.match(/[=,\[\]{}]/)) return 'punctuation'

    // Skip unknown characters
    stream.next()
    return null
  },

  startState() {
    return { inHeader: false, inMultilineString: null }
  }
}

// Create the language
export const tomlLanguage = StreamLanguage.define(tomlParser)

// Export convenience function
export function toml() {
  return tomlLanguage
}
