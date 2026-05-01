const fs = require('fs');
const os = require('os');
const MCPSecurityLinter = require('./index');
const { formatOutput } = require('./formatters');

const VALID_OUTPUT_FORMATS = new Set(['sarif', 'json', 'console']);

function getInput(name, defaultValue = '') {
  const normalizedName = name.replace(/[- ]/g, '_').toUpperCase();
  const legacyName = name.replace(/ /g, '_').toUpperCase();

  return process.env[`INPUT_${normalizedName}`] ||
    process.env[`INPUT_${legacyName}`] ||
    defaultValue;
}

function setOutput(name, value) {
  const outputFile = process.env.GITHUB_OUTPUT;
  if (outputFile) {
    fs.appendFileSync(outputFile, `${name}=${value}${os.EOL}`);
  } else {
    console.log(`::set-output name=${escapeProperty(name)}::${escapeData(String(value))}`);
  }
}

function info(message) {
  console.log(message);
}

function setFailed(message) {
  console.error(message);
  process.exitCode = 1;
}

function annotation(level, message, metadata) {
  const props = [
    ['file', metadata.path],
    ['line', metadata.start_line],
    ['endLine', metadata.end_line],
    ['title', metadata.title]
  ]
    .filter(([, value]) => value !== undefined && value !== null)
    .map(([key, value]) => `${key}=${escapeProperty(String(value))}`)
    .join(',');

  console.log(`::${level} ${props}::${escapeData(message)}`);
}

function escapeData(value) {
  return value
    .replace(/%/g, '%25')
    .replace(/\r/g, '%0D')
    .replace(/\n/g, '%0A');
}

function escapeProperty(value) {
  return escapeData(value)
    .replace(/:/g, '%3A')
    .replace(/,/g, '%2C');
}

async function run() {
  try {
    const path = getInput('path', '.');
    const configPath = getInput('config', '.mcp-lint.json');
    const failOnWarnings = getInput('fail-on-warnings', 'false') === 'true';
    const outputFormat = getInput('output-format', 'sarif');

    if (!VALID_OUTPUT_FORMATS.has(outputFormat)) {
      throw new Error(`Unsupported output format '${outputFormat}'. Expected one of: sarif, json, console.`);
    }

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

    const resultsFile = outputFormat === 'sarif' ? sarifFile : `mcp-security-results.${outputFormat}`;
    if (outputFormat !== 'sarif') {
      fs.writeFileSync(resultsFile, formatOutput(findings, outputFormat));
    }

    setOutput('findings-count', findings.length);
    setOutput('sarif-file', sarifFile);
    setOutput('results-file', resultsFile);

    if (findings.length > 0) {
      findings.forEach(finding => {
        const metadata = {
          path: finding.location.file,
          start_line: finding.location.line,
          end_line: finding.location.line,
          annotation_level: finding.level === 'error' ? 'failure' : 'warning',
          message: finding.message,
          title: finding.ruleId
        };

        if (finding.level === 'error') {
          annotation('error', finding.message, metadata);
        } else {
          annotation('warning', finding.message, metadata);
        }
      });

      const hasErrors = findings.some(f => f.level === 'error');
      if (hasErrors || failOnWarnings) {
        setFailed(`Found ${findings.length} security issue(s)`);
      }
    } else {
      info('No security issues found');
    }
  } catch (error) {
    setFailed(error.message);
  }
}

run();
