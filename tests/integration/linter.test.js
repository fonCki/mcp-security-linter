const MCPSecurityLinter = require('../../src/index');
const path = require('path');

describe('MCPSecurityLinter Integration', () => {
  let linter;

  beforeEach(() => {
    linter = new MCPSecurityLinter({
      'ai-detector': { enabled: true }
    });
  });

  test('analyzes directory with mixed files', async () => {
    const testDir = path.join(__dirname, '../fixtures/ai-content');
    const findings = await linter.analyze(testDir);

    expect(findings).toBeDefined();
    expect(Array.isArray(findings)).toBe(true);
    expect(findings.length).toBeGreaterThan(0);
  });

  test('returns proper finding structure', async () => {
    const testDir = path.join(__dirname, '../fixtures/ai-content');
    const findings = await linter.analyze(testDir);

    if (findings.length > 0) {
      const finding = findings[0];
      expect(finding).toHaveProperty('ruleId');
      expect(finding).toHaveProperty('level');
      expect(finding).toHaveProperty('message');
      expect(finding).toHaveProperty('location');
      expect(finding.location).toHaveProperty('file');
      expect(finding.location).toHaveProperty('line');
      expect(finding.location).toHaveProperty('column');
    }
  });

  test('respects analyzer configuration', async () => {
    const disabledLinter = new MCPSecurityLinter({
      'ai-detector': { enabled: false }
    });

    const testDir = path.join(__dirname, '../fixtures/ai-content');
    const findings = await disabledLinter.analyze(testDir);

    expect(findings.length).toBe(0);
  });
});