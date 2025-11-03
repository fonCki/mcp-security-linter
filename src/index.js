const fs = require('fs');
const path = require('path');
const glob = require('glob');

class MCPSecurityLinter {
  constructor(config = {}) {
    this.analyzers = [];
    this.config = config;
    this.loadAnalyzers();
  }

  loadAnalyzers() {
    const analyzerFiles = [
      'ai-detector',
      'command-injection',
      'token-passthrough',
      'unauthenticated-endpoints',
      'oauth-hygiene',
      'argument-validation'
    ];

    analyzerFiles.forEach(file => {
      const AnalyzerClass = require(`./analyzers/${file}`);
      const analyzer = new AnalyzerClass(this.config[file] || {});
      if (analyzer.enabled !== false) {
        this.analyzers.push(analyzer);
      }
    });
  }

  async analyze(targetPath) {
    const findings = [];
    const files = this.getFiles(targetPath);

    for (const file of files) {
      const content = fs.readFileSync(file, 'utf8');

      for (const analyzer of this.analyzers) {
        try {
          const results = analyzer.analyze(file, content);
          if (results && results.length > 0) {
            findings.push(...results);
          }
        } catch (error) {
          console.error(`Error in ${analyzer.name} analyzer:`, error);
        }
      }
    }

    return findings;
  }

  getFiles(targetPath) {
    const stats = fs.statSync(targetPath);

    if (stats.isFile()) {
      return [targetPath];
    }

    const pattern = path.join(targetPath, '**/*.{js,ts,jsx,tsx,py,java,go,rb}');
    return glob.sync(pattern, {
      ignore: ['**/node_modules/**', '**/dist/**', '**/.git/**']
    });
  }
}

module.exports = MCPSecurityLinter;