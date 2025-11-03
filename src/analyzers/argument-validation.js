const BaseAnalyzer = require('./base-analyzer');

class ArgumentValidationAnalyzer extends BaseAnalyzer {
  constructor(options = {}) {
    super('argument-validation', options);
  }

  analyze(filePath, content) {
    const findings = [];

    return findings;
  }
}

module.exports = ArgumentValidationAnalyzer;