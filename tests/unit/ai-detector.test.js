const AIDetector = require('../../src/analyzers/ai-detector');
const fs = require('fs');
const path = require('path');

describe('AIDetector', () => {
  let detector;
  const testDir = path.join(__dirname, '../fixtures/ai-content');

  beforeEach(() => {
    detector = new AIDetector();
  });

  test('detects ChatGPT mentions', () => {
    const testFile = path.join(testDir, 'chatgpt.js');
    const content = fs.readFileSync(testFile, 'utf8');
    const findings = detector.analyze(testFile, content);

    expect(findings).toBeDefined();
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].ruleId).toBe('ai-generated-content');
    expect(findings[0].message).toContain('ChatGPT');
  });

  test('detects OpenAI references', () => {
    const testFile = path.join(testDir, 'openai.js');
    const content = fs.readFileSync(testFile, 'utf8');
    const findings = detector.analyze(testFile, content);

    expect(findings).toBeDefined();
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].message).toMatch(/openai/i);
  });

  test('detects Claude mentions', () => {
    const testFile = path.join(testDir, 'claude.js');
    const content = fs.readFileSync(testFile, 'utf8');
    const findings = detector.analyze(testFile, content);

    expect(findings).toBeDefined();
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].message).toMatch(/claude/i);
  });

  test('returns empty array for clean files', () => {
    const testFile = path.join(testDir, 'clean.js');
    const content = fs.readFileSync(testFile, 'utf8');
    const findings = detector.analyze(testFile, content);

    expect(findings).toBeDefined();
    expect(findings.length).toBe(0);
  });

  test('detects multiple AI references in one file', () => {
    const testFile = path.join(testDir, 'mixed.js');
    const content = fs.readFileSync(testFile, 'utf8');
    const findings = detector.analyze(testFile, content);

    expect(findings.length).toBeGreaterThan(1);
  });
});