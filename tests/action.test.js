const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const actionPath = path.join(__dirname, '..', 'src', 'action.js');

describe('GitHub Action entrypoint', () => {
  let tempDir;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-action-'));
  });

  afterEach(() => {
    if (tempDir && fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  test('writes SARIF plus requested JSON output and fails on error findings', () => {
    const vulnerableFile = path.join(tempDir, 'vulnerable.js');
    const outputFile = path.join(tempDir, 'github-output.txt');
    fs.writeFileSync(
      vulnerableFile,
      "const { exec } = require('child_process'); const cmd = process.env.CMD; exec(cmd);"
    );

    const result = spawnSync(process.execPath, [actionPath], {
      cwd: tempDir,
      encoding: 'utf8',
      env: {
        ...process.env,
        GITHUB_OUTPUT: outputFile,
        INPUT_PATH: vulnerableFile,
        INPUT_OUTPUT_FORMAT: 'json'
      }
    });

    expect(result.status).toBe(1);
    expect(fs.existsSync(path.join(tempDir, 'mcp-security-results.sarif'))).toBe(true);
    expect(fs.existsSync(path.join(tempDir, 'mcp-security-results.json'))).toBe(true);
    expect(fs.readFileSync(outputFile, 'utf8')).toContain('results-file=mcp-security-results.json');
    expect(result.stdout).toContain('::error');
  });
});
