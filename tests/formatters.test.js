const { formatOutput } = require('../src/formatters');

const finding = {
  ruleId: 'command-exec',
  level: 'error',
  message: 'Dangerous command execution detected.',
  location: {
    file: 'server.ts',
    line: 3,
    column: 10
  }
};

describe('formatters', () => {
  test('formats JSON output with summary counts', () => {
    const output = JSON.parse(formatOutput([finding], 'json'));

    expect(output.summary).toEqual({
      total: 1,
      errors: 1,
      warnings: 0,
      info: 0
    });
    expect(output.findings[0]).toEqual(finding);
  });

  test('formats SARIF output with rules and locations', () => {
    const output = JSON.parse(formatOutput([finding], 'sarif'));

    expect(output.version).toBe('2.1.0');
    expect(output.runs[0].tool.driver.rules[0].id).toBe('command-exec');
    expect(output.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri).toBe('server.ts');
    expect(output.runs[0].results[0].locations[0].physicalLocation.region.startLine).toBe(3);
  });

  test('formats empty console output', () => {
    expect(formatOutput([], 'console')).toContain('No security issues found');
  });
});
