#!/usr/bin/env node

const MCPSecurityLinter = require('./src/index');
const { formatOutput } = require('./src/formatters');

async function runDemo() {
  console.log('MCP Security Linter - Demo\n');
  console.log('Analyzing test fixtures for AI-generated content...\n');

  const linter = new MCPSecurityLinter({
    'ai-detector': { enabled: true, severity: 'warning' }
  });

  const vulnerableFile = './tests/fixtures/sample-vulnerable.js';
  console.log(`Scanning: ${vulnerableFile}\n`);

  const findings = await linter.analyze(vulnerableFile);

  if (findings.length > 0) {
    console.log('Security Issues Found:');
    console.log('='.repeat(50));
    console.log(formatOutput(findings, 'console'));
    console.log('='.repeat(50));
    console.log(`\nTotal issues: ${findings.length}`);
  } else {
    console.log('No issues found!');
  }
}

runDemo().catch(console.error);