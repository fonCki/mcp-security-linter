const BaseAnalyzer = require('./base-analyzer');

class UnauthenticatedEndpointsAnalyzer extends BaseAnalyzer {
  constructor(options = {}) {
    super('unauthenticated-endpoints', options);
  }

  analyze(filePath, content) {
    const findings = [];

    return findings;
  }
}

module.exports = UnauthenticatedEndpointsAnalyzer;