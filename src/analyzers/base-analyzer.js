const fs = require('fs');
const path = require('path');

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

  createFinding(file, line, column, message, ruleId = null) {
    return {
      ruleId: ruleId || this.name,
      level: this.severity,
      message: message,
      location: {
        file: file,
        line: line,
        column: column
      }
    };
  }
}

module.exports = BaseAnalyzer;