const packageJson = require('../../package.json');
const defaultConfig = require('../../defaults.json');

function format(findings) {
  const sarif = {
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: defaultConfig.output.sarif.toolName,
            version: packageJson.version,
            informationUri: defaultConfig.output.sarif.informationUri,
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
                  startLine: Math.max(1, finding.location.line || 1),
                  startColumn: Math.max(1, finding.location.column || 1)
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
