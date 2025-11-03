function format(findings) {
  const sarif = {
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'MCP Security Linter',
            version: '0.1.0',
            informationUri: 'https://github.com/alfonsoridao/mcp-security-linter',
            rules: getRules(findings)
          }
        },
        results: findings.map(finding => ({
          ruleId: finding.ruleId,
          level: mapLevel(finding.level),
          message: {
            text: finding.message
          },
          locations: [
            {
              physicalLocation: {
                artifactLocation: {
                  uri: finding.location.file
                },
                region: {
                  startLine: finding.location.line,
                  startColumn: finding.location.column
                }
              }
            }
          ]
        }))
      }
    ]
  };

  return JSON.stringify(sarif, null, 2);
}

function getRules(findings) {
  const rules = {};

  findings.forEach(finding => {
    if (!rules[finding.ruleId]) {
      rules[finding.ruleId] = {
        id: finding.ruleId,
        name: finding.ruleId,
        shortDescription: {
          text: finding.ruleId.replace(/-/g, ' ')
        },
        defaultConfiguration: {
          level: mapLevel(finding.level)
        }
      };
    }
  });

  return Object.values(rules);
}

function mapLevel(level) {
  switch (level) {
    case 'error':
      return 'error';
    case 'warning':
      return 'warning';
    case 'info':
      return 'note';
    default:
      return 'warning';
  }
}

module.exports = { format };