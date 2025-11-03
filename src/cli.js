#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const minimist = require('minimist');
const MCPSecurityLinter = require('./index');
const { formatOutput } = require('./formatters');

const argv = minimist(process.argv.slice(2), {
  alias: {
    c: 'config',
    f: 'format',
    o: 'output',
    h: 'help'
  },
  default: {
    format: 'console',
    config: '.mcp-lint.json'
  }
});

if (argv.help) {
  console.log(`
MCP Security Linter

Usage: mcp-lint [path] [options]

Options:
  -c, --config   Configuration file path (default: .mcp-lint.json)
  -f, --format   Output format: console, json, sarif (default: console)
  -o, --output   Output file path
  -h, --help     Show this help message

Examples:
  mcp-lint .
  mcp-lint src/ --format sarif --output results.sarif
  mcp-lint --config custom-config.json
`);
  process.exit(0);
}

async function main() {
  const targetPath = argv._[0] || '.';
  let config = {};

  if (fs.existsSync(argv.config)) {
    const configContent = fs.readFileSync(argv.config, 'utf8');
    config = JSON.parse(configContent);
  }

  const linter = new MCPSecurityLinter(config);
  const findings = await linter.analyze(targetPath);

  const output = formatOutput(findings, argv.format);

  if (argv.output) {
    fs.writeFileSync(argv.output, output);
    console.log(`Results written to ${argv.output}`);
  } else {
    console.log(output);
  }

  if (findings.length > 0 && argv.format === 'console') {
    console.log(`\nFound ${findings.length} security issue(s)`);
    process.exit(1);
  }
}

main().catch(error => {
  console.error('Error:', error);
  process.exit(1);
});