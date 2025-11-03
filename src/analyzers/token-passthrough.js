const BaseAnalyzer = require('./base-analyzer');

class TokenPassthroughAnalyzer extends BaseAnalyzer {
  constructor(options = {}) {
    super('token-passthrough', options);
  }

  analyze(filePath, content) {
    const findings = [];

    return findings;
  }
}

module.exports = TokenPassthroughAnalyzer;