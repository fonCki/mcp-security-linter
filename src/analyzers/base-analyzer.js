const fs = require('fs');
const path = require('path');
const acorn = require('acorn');
const walk = require('acorn-walk');

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

  parseAST(content) {
    try {
      return acorn.parse(content, {
        ecmaVersion: 2022,
        sourceType: 'module',
        locations: true,
        ranges: true,
        allowHashBang: true  // Handle #!/usr/bin/env node shebangs
      });
    } catch (error) {
      // Fallback or silence error for non-JS files or syntax errors
      return null;
    }
  }

  walkAST(ast, visitors) {
    if (!ast) return;
    walk.simple(ast, visitors);
  }
}

module.exports = BaseAnalyzer;