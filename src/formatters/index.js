const sarifFormatter = require('./sarif');
const jsonFormatter = require('./json');
const consoleFormatter = require('./console');

function formatOutput(findings, format) {
  switch (format) {
    case 'sarif':
      return sarifFormatter.format(findings);
    case 'json':
      return jsonFormatter.format(findings);
    case 'console':
    default:
      return consoleFormatter.format(findings);
  }
}

module.exports = { formatOutput };