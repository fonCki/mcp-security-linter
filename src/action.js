const core = require('@actions/core');
const github = require('@actions/github');
const fs = require('fs');
const MCPSecurityLinter = require('./index');
const { formatOutput } = require('./formatters');

async function run() {
  try {
    const path = process.env.INPUT_PATH || core.getInput('path') || '.';
    const configPath = process.env.INPUT_CONFIG || core.getInput('config') || '.mcp-lint.json';
    const failOnWarnings = (process.env['INPUT_FAIL-ON-WARNINGS'] || core.getInput('fail-on-warnings')) === 'true';
    const outputFormat = process.env['INPUT_OUTPUT-FORMAT'] || core.getInput('output-format') || 'sarif';

    let config = {};
    if (fs.existsSync(configPath)) {
      const configContent = fs.readFileSync(configPath, 'utf8');
      config = JSON.parse(configContent);
    }

    const linter = new MCPSecurityLinter(config);
    const findings = await linter.analyze(path);

    const sarifOutput = formatOutput(findings, 'sarif');
    const sarifFile = 'mcp-security-results.sarif';
    fs.writeFileSync(sarifFile, sarifOutput);

    core.setOutput('findings-count', findings.length);
    core.setOutput('sarif-file', sarifFile);

    if (findings.length > 0) {
      findings.forEach(finding => {
        const annotation = {
          path: finding.location.file,
          start_line: finding.location.line,
          end_line: finding.location.line,
          annotation_level: finding.level === 'error' ? 'failure' : 'warning',
          message: finding.message,
          title: finding.ruleId
        };

        if (finding.level === 'error') {
          core.error(finding.message, annotation);
        } else {
          core.warning(finding.message, annotation);
        }
      });

      const hasErrors = findings.some(f => f.level === 'error');
      if (hasErrors || failOnWarnings) {
        core.setFailed(`Found ${findings.length} security issue(s)`);
      }
    } else {
      core.info('No security issues found');
    }
  } catch (error) {
    core.setFailed(error.message);
  }
}

run();