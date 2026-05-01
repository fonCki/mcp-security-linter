const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const cliPath = path.join(__dirname, '..', 'src', 'cli.js');

describe('CLI', () => {
  let tempDir;
  let vulnerableFile;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-cli-'));
    vulnerableFile = path.join(tempDir, 'vulnerable.js');
    fs.writeFileSync(
      vulnerableFile,
      "const { exec } = require('child_process'); const cmd = process.env.CMD; exec(cmd);"
    );
  });

  afterEach(() => {
    if (tempDir && fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  test('exits with failure for console findings', () => {
    const result = runCli([vulnerableFile, '--format', 'console']);

    expect(result.status).toBe(1);
    expect(result.stdout).toContain('Found 1 security issue');
  });

  test('exits with failure for JSON findings', () => {
    const result = runCli([vulnerableFile, '--format', 'json']);
    const output = JSON.parse(result.stdout);

    expect(result.status).toBe(1);
    expect(output.summary.total).toBe(1);
  });

  test('exits with failure for SARIF findings', () => {
    const result = runCli([vulnerableFile, '--format', 'sarif']);
    const output = JSON.parse(result.stdout);

    expect(result.status).toBe(1);
    expect(output.version).toBe('2.1.0');
    expect(output.runs[0].results).toHaveLength(1);
  });

  test('exits with success when there are no findings', () => {
    const safeFile = path.join(tempDir, 'safe.js');
    fs.writeFileSync(safeFile, "const command = 'ls -la';");

    const result = runCli([safeFile, '--format', 'json']);
    const output = JSON.parse(result.stdout);

    expect(result.status).toBe(0);
    expect(output.summary.total).toBe(0);
  });
});

function runCli(args) {
  return spawnSync(process.execPath, [cliPath, ...args], {
    encoding: 'utf8'
  });
}
