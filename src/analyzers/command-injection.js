const BaseAnalyzer = require('./base-analyzer');

class CommandInjectionAnalyzer extends BaseAnalyzer {
  constructor(options = {}) {
    super('command-injection', options);
  }

  analyze(filePath, content) {
    const findings = [];

    return findings;
  }
}

module.exports = CommandInjectionAnalyzer;