function format(findings) {
  if (findings.length === 0) {
    return 'No security issues found';
  }

  let output = '';
  const groupedByFile = {};

  findings.forEach(finding => {
    const file = finding.location.file;
    if (!groupedByFile[file]) {
      groupedByFile[file] = [];
    }
    groupedByFile[file].push(finding);
  });

  Object.keys(groupedByFile).forEach(file => {
    output += `\n${file}\n`;
    groupedByFile[file].forEach(finding => {
      const level = finding.level.toUpperCase();
      const position = `${finding.location.line}:${finding.location.column}`;
      output += `  ${position} ${level} ${finding.message} [${finding.ruleId}]\n`;
    });
  });

  return output;
}

module.exports = { format };