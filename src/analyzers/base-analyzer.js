const fs = require('fs');
const path = require('path');
const acorn = require('acorn');
const { parse: parseTypeScript } = require('@typescript-eslint/typescript-estree');

// File extensions parsed with typescript-estree (handles TS syntax + JSX).
// Plain JS extensions go through Acorn, preserving the parser pipeline
// described in §4.3 of the IWSPA '26 paper. The hybrid resolves the
// limitation noted in §7.3 (Acorn-only parsing failed on TS files) without
// abandoning Acorn for the JS path.
const TS_OR_JSX_EXTENSIONS = new Set(['.ts', '.tsx', '.mts', '.cts', '.jsx']);

const TRAVERSAL_SKIP_KEYS = new Set([
  'comments',
  'loc',
  'parent',
  'range',
  'tokens'
]);

class BaseAnalyzer {
  constructor(name, options = {}) {
    this.name = name;
    this.enabled = options.enabled !== false;
    this.severity = options.severity || 'warning';
  }

  analyze(filePath, content) {
    throw new Error('analyze method must be implemented');
  }

  analyzeFile(filePath) {
    if (!fs.existsSync(filePath)) {
      return [];
    }

    const content = fs.readFileSync(filePath, 'utf8');
    return this.analyze(filePath, content);
  }

  createFinding(file, line, column, message, ruleId = null, severity = null) {
    return {
      ruleId: ruleId || this.name,
      level: severity || this.severity,
      message: message,
      location: {
        file: file,
        line: line,
        column: column
      }
    };
  }

  parseAST(content, filePath = 'file.js') {
    const ext = path.extname(filePath).toLowerCase();

    if (TS_OR_JSX_EXTENSIONS.has(ext)) {
      try {
        return parseTypeScript(content, {
          comment: false,
          errorOnTypeScriptSyntacticAndSemanticIssues: false,
          filePath,
          jsx: true,
          loc: true,
          range: true,
          sourceType: 'module',
          tokens: false
        });
      } catch (error) {
        return null;
      }
    }

    try {
      return acorn.parse(content, {
        ecmaVersion: 2022,
        sourceType: 'module',
        locations: true,
        ranges: true,
        allowHashBang: true
      });
    } catch (error) {
      return null;
    }
  }

  walkAST(ast, visitors, state = null) {
    if (!ast) return;
    this.traverseAST(ast, state, visitors, false);
  }

  walkRecursiveAST(ast, state, visitors) {
    if (!ast) return;
    this.traverseAST(ast, state, visitors, true);
  }

  traverseAST(node, state, visitors, visitorControlsChildren) {
    if (!this.isASTNode(node)) return;

    const visitor = visitors[node.type];
    const visitChild = child => this.traverseAST(child, state, visitors, visitorControlsChildren);

    if (visitor) {
      visitor(node, state, visitChild);
      if (visitorControlsChildren) return;
    }

    this.traverseChildren(node, state, visitors, visitorControlsChildren);
  }

  traverseChildren(node, state, visitors, visitorControlsChildren) {
    Object.keys(node).forEach(key => {
      if (TRAVERSAL_SKIP_KEYS.has(key)) return;

      const value = node[key];
      if (Array.isArray(value)) {
        value.forEach(child => this.traverseAST(child, state, visitors, visitorControlsChildren));
      } else {
        this.traverseAST(value, state, visitors, visitorControlsChildren);
      }
    });
  }

  isASTNode(value) {
    return value && typeof value.type === 'string';
  }
}

module.exports = BaseAnalyzer;
