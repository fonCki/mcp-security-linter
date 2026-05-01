const fs = require('fs');
const { parse } = require('@typescript-eslint/typescript-estree');

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
    try {
      return parse(content, {
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
