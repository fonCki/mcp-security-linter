// ANSI color codes
const colors = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',

  // Text colors
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  gray: '\x1b[90m',

  // Background colors
  bgRed: '\x1b[41m',
  bgYellow: '\x1b[43m'
};

// Check if colors should be disabled (CI environments, piped output)
const supportsColor = process.stdout.isTTY && process.env.TERM !== 'dumb';

function colorize(text, color) {
  if (!supportsColor) return text;
  return `${color}${text}${colors.reset}`;
}

function format(findings) {
  if (findings.length === 0) {
    const successMsg = colorize('✓', colors.green) + ' No security issues found';
    return '\n' + successMsg + '\n';
  }

  let output = '';
  const groupedByFile = {};
  let errorCount = 0;
  let warningCount = 0;

  // Group findings by file
  findings.forEach(finding => {
    const file = finding.location.file;
    if (!groupedByFile[file]) {
      groupedByFile[file] = [];
    }
    groupedByFile[file].push(finding);

    if (finding.level === 'error') errorCount++;
    else if (finding.level === 'warning') warningCount++;
  });

  // Output findings grouped by file
  Object.keys(groupedByFile).forEach(file => {
    output += '\n' + colorize(file, colors.cyan) + '\n';

    groupedByFile[file].forEach(finding => {
      const level = finding.level.toUpperCase();
      const position = colorize(`${finding.location.line}:${finding.location.column}`, colors.dim);
      const ruleId = colorize(`[${finding.ruleId}]`, colors.gray);

      let levelFormatted;
      if (finding.level === 'error') {
        levelFormatted = colorize('✖ ERROR  ', colors.red + colors.bold);
      } else if (finding.level === 'warning') {
        levelFormatted = colorize('⚠ WARNING', colors.yellow + colors.bold);
      } else {
        levelFormatted = colorize('ℹ NOTE   ', colors.blue + colors.bold);
      }

      output += `  ${position} ${levelFormatted} ${finding.message} ${ruleId}\n`;
    });
  });

  // Summary section
  output += '\n';
  output += colorize('─'.repeat(60), colors.gray) + '\n';

  const problemsText = errorCount + warningCount === 1 ? 'problem' : 'problems';
  const summary = `✖ ${errorCount + warningCount} ${problemsText} `;

  const errorText = errorCount > 0
    ? colorize(`${errorCount} error${errorCount !== 1 ? 's' : ''}`, colors.red + colors.bold)
    : colorize('0 errors', colors.dim);

  const warningText = warningCount > 0
    ? colorize(`${warningCount} warning${warningCount !== 1 ? 's' : ''}`, colors.yellow + colors.bold)
    : colorize('0 warnings', colors.dim);

  output += summary + `(${errorText}, ${warningText})\n`;

  return output;
}

module.exports = { format };