const BaseAnalyzer = require('./base-analyzer');

class OAuthHygieneAnalyzer extends BaseAnalyzer {
  constructor(options = {}) {
    super('oauth-hygiene', options);
  }

  analyze(filePath, content) {
    const findings = [];

    return findings;
  }
}

module.exports = OAuthHygieneAnalyzer;