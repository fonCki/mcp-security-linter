const fs = require('fs');
const path = require('path');
const glob = require('glob');

const DEFAULT_CONFIG = require('../defaults.json');

class MCPSecurityLinter {
  constructor(config = {}) {
    this.analyzers = [];
    this.config = this.mergeConfig(config);
    this.loadAnalyzers();
  }

  mergeConfig(userConfig) {
    const merged = JSON.parse(JSON.stringify(DEFAULT_CONFIG));

    if (userConfig.global) {
      merged.global = { ...merged.global, ...userConfig.global };
    }

    if (userConfig.analyzers) {
      Object.keys(userConfig.analyzers).forEach(key => {
        if (merged.analyzers[key]) {
          merged.analyzers[key] = { ...merged.analyzers[key], ...userConfig.analyzers[key] };
        } else {
          merged.analyzers[key] = userConfig.analyzers[key];
        }
      });
    }

    Object.keys(DEFAULT_CONFIG.analyzers).forEach(analyzerKey => {
      if (userConfig[analyzerKey]) {
        merged.analyzers[analyzerKey] = {
          ...merged.analyzers[analyzerKey],
          ...userConfig[analyzerKey]
        };
      }
    });

    if (userConfig.output) {
      merged.output = { ...merged.output, ...userConfig.output };
    }

    return merged;
  }

  loadAnalyzers() {
    const analyzerDir = path.join(__dirname, 'analyzers');
    const analyzerFiles = fs.readdirSync(analyzerDir)
      .filter(file => file.endsWith('.js') && file !== 'base-analyzer.js')
      .map(file => file.replace('.js', ''));

    analyzerFiles.forEach(file => {
      try {
        const AnalyzerClass = require(`./analyzers/${file}`);
        const analyzerConfig = this.config.analyzers[file] || {};
        const globalConfig = this.config.global || {};
        const analyzer = new AnalyzerClass({
          ...analyzerConfig,
          globalConfig
        });
        if (analyzer.enabled !== false) {
          this.analyzers.push(analyzer);
        }
      } catch (error) {
        console.warn(`Warning: Could not load analyzer ${file}:`, error.message);
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

    const globOptions = {
      ignore: this.config.global.excludePatterns,
      dot: true  // Include dotfiles like .env
    };

    let files = [];

    // Match files with extensions
    const extensions = this.config.global.fileExtensions
      .filter(ext => ext.startsWith('.') && ext.length > 1)
      .map(ext => ext.replace('.', ''))
      .join(',');

    if (extensions) {
      const extPattern = path.join(targetPath, `**/*.{${extensions}}`);
      files = files.concat(glob.sync(extPattern, globOptions));
    }

    // Match specific filenames without extensions or with dot prefix
    const specialFiles = [
      'Dockerfile', 'dockerfile',
      '.env', '.env.local', '.env.production', '.env.development', '.env.test',
      '.gitignore', '.dockerignore',
      'mcp-config.json', '.mcp-config.json'
    ];

    specialFiles.forEach(filename => {
      const filePattern = path.join(targetPath, `**/${filename}`);
      files = files.concat(glob.sync(filePattern, globOptions));
    });

    // Remove duplicates and return
    return [...new Set(files)];
  }
}

module.exports = MCPSecurityLinter;
