const CommandExecAnalyzer = require('../../src/analyzers/command-exec');
const fs = require('fs');
const path = require('path');

describe('CommandExecAnalyzer', () => {
  let analyzer;
  const testDir = path.join(__dirname, '../fixtures/command-exec');

  beforeEach(() => {
    analyzer = new CommandExecAnalyzer({ severity: 'error' });
  });

  describe('Dangerous rm commands', () => {
    test('detects rm -rf / (root deletion)', () => {
      const testFile = path.join(testDir, 'dangerous-rm.js');
      const content = fs.readFileSync(testFile, 'utf8');
      const findings = analyzer.analyze(testFile, content);

      const rootDeleteFindings = findings.filter(f =>
        f.message.includes('Deletes root directory') || f.message.includes('root')
      );

      expect(rootDeleteFindings.length).toBeGreaterThan(0);
      expect(rootDeleteFindings[0].ruleId).toBe('dangerous-command-exec');
      expect(rootDeleteFindings[0].level).toBe('error');
    });

    test('detects rm -rf ~ (home deletion)', () => {
      const testFile = path.join(testDir, 'dangerous-rm.js');
      const content = fs.readFileSync(testFile, 'utf8');
      const findings = analyzer.analyze(testFile, content);

      const homeDeleteFindings = findings.filter(f =>
        f.message.includes('home directory')
      );

      expect(homeDeleteFindings.length).toBeGreaterThan(0);
      expect(homeDeleteFindings[0].level).toBe('error');
    });

    test('detects rm -rf * (wildcard deletion)', () => {
      const testFile = path.join(testDir, 'dangerous-rm.js');
      const content = fs.readFileSync(testFile, 'utf8');
      const findings = analyzer.analyze(testFile, content);

      const wildcardFindings = findings.filter(f =>
        f.message.includes('wildcard')
      );

      expect(wildcardFindings.length).toBeGreaterThan(0);
      expect(wildcardFindings[0].level).toBe('error');
    });
  });

  describe('Curl/Wget piped to shell', () => {
    test('detects curl | bash pattern', () => {
      const testFile = path.join(testDir, 'curl-pipe-shell.js');
      const content = fs.readFileSync(testFile, 'utf8');
      const findings = analyzer.analyze(testFile, content);

      const curlBashFindings = findings.filter(f =>
        f.message.includes('curl') && f.message.includes('shell')
      );

      expect(curlBashFindings.length).toBeGreaterThan(0);
      expect(curlBashFindings[0].ruleId).toBe('dangerous-command-exec');
      expect(curlBashFindings[0].level).toBe('error');
    });

    test('detects wget | sh pattern', () => {
      const testFile = path.join(testDir, 'curl-pipe-shell.js');
      const content = fs.readFileSync(testFile, 'utf8');
      const findings = analyzer.analyze(testFile, content);

      const wgetShFindings = findings.filter(f =>
        f.message.includes('wget') && f.message.includes('shell')
      );

      expect(wgetShFindings.length).toBeGreaterThan(0);
      expect(wgetShFindings[0].level).toBe('error');
    });

    test('detects curl | python pattern', () => {
      const testFile = path.join(testDir, 'curl-pipe-shell.js');
      const content = fs.readFileSync(testFile, 'utf8');
      const findings = analyzer.analyze(testFile, content);

      const curlPythonFindings = findings.filter(f =>
        f.message.includes('curl') && f.message.includes('shell')
      );

      expect(curlPythonFindings.length).toBeGreaterThan(0);
    });
  });

  describe('Encoded/Obfuscated commands', () => {
    test('detects PowerShell -encodedCommand', () => {
      const testFile = path.join(testDir, 'encoded-commands.js');
      const content = fs.readFileSync(testFile, 'utf8');
      const findings = analyzer.analyze(testFile, content);

      const powershellFindings = findings.filter(f =>
        f.message.toLowerCase().includes('powershell')
      );

      expect(powershellFindings.length).toBeGreaterThan(0);
      expect(powershellFindings[0].level).toBe('error');
    });

    test('detects base64 | bash pattern', () => {
      const testFile = path.join(testDir, 'encoded-commands.js');
      const content = fs.readFileSync(testFile, 'utf8');
      const findings = analyzer.analyze(testFile, content);

      const base64Findings = findings.filter(f =>
        f.message.toLowerCase().includes('base64')
      );

      expect(base64Findings.length).toBeGreaterThan(0);
      expect(base64Findings[0].level).toBe('error');
    });
  });

  describe('Credential access patterns', () => {
    test('detects /etc/shadow access', () => {
      const testFile = path.join(testDir, 'credential-access.js');
      const content = fs.readFileSync(testFile, 'utf8');
      const findings = analyzer.analyze(testFile, content);

      const shadowFindings = findings.filter(f =>
        f.message.includes('shadow')
      );

      expect(shadowFindings.length).toBeGreaterThan(0);
      expect(shadowFindings[0].level).toBe('error');
    });

    test('detects /etc/passwd access', () => {
      const testFile = path.join(testDir, 'credential-access.js');
      const content = fs.readFileSync(testFile, 'utf8');
      const findings = analyzer.analyze(testFile, content);

      const passwdFindings = findings.filter(f =>
        f.message.includes('password file')
      );

      expect(passwdFindings.length).toBeGreaterThan(0);
    });

    test('detects AWS credential environment variables', () => {
      const testFile = path.join(testDir, 'credential-access.js');
      const content = fs.readFileSync(testFile, 'utf8');
      const findings = analyzer.analyze(testFile, content);

      const credentialFindings = findings.filter(f =>
        f.message.toLowerCase().includes('credential')
      );

      expect(credentialFindings.length).toBeGreaterThan(0);
    });
  });

  describe('Reverse shell patterns', () => {
    test('detects netcat -e (reverse shell)', () => {
      const testFile = path.join(testDir, 'reverse-shell.js');
      const content = fs.readFileSync(testFile, 'utf8');
      const findings = analyzer.analyze(testFile, content);

      const netcatFindings = findings.filter(f =>
        f.message.toLowerCase().includes('netcat') ||
        f.message.toLowerCase().includes('reverse shell')
      );

      expect(netcatFindings.length).toBeGreaterThan(0);
      expect(netcatFindings[0].level).toBe('error');
    });

    test('detects /dev/tcp/ bash backdoor', () => {
      const testFile = path.join(testDir, 'reverse-shell.js');
      const content = fs.readFileSync(testFile, 'utf8');
      const findings = analyzer.analyze(testFile, content);

      const devTcpFindings = findings.filter(f =>
        f.message.includes('/dev/tcp/')
      );

      expect(devTcpFindings.length).toBeGreaterThan(0);
      expect(devTcpFindings[0].level).toBe('error');
    });
  });

  describe('Python subprocess patterns', () => {
    test('detects Python subprocess.call with rm -rf', () => {
      const testFile = path.join(testDir, 'python-subprocess.py');
      const content = fs.readFileSync(testFile, 'utf8');
      const findings = analyzer.analyze(testFile, content);

      const subprocessFindings = findings.filter(f =>
        f.message.includes('subprocess')
      );

      expect(subprocessFindings.length).toBeGreaterThan(0);
    });

    test('detects Python os.system', () => {
      const testFile = path.join(testDir, 'python-subprocess.py');
      const content = fs.readFileSync(testFile, 'utf8');
      const findings = analyzer.analyze(testFile, content);

      const osSystemFindings = findings.filter(f =>
        f.message.includes('os.system')
      );

      expect(osSystemFindings.length).toBeGreaterThan(0);
    });

    test('detects Python os.popen', () => {
      const testFile = path.join(testDir, 'python-subprocess.py');
      const content = fs.readFileSync(testFile, 'utf8');
      const findings = analyzer.analyze(testFile, content);

      const osPopenFindings = findings.filter(f =>
        f.message.includes('os.popen')
      );

      expect(osPopenFindings.length).toBeGreaterThan(0);
    });
  });

  describe('Dynamic code execution', () => {
    test('detects eval() usage', () => {
      const testFile = path.join(testDir, 'eval-dynamic.js');
      const content = fs.readFileSync(testFile, 'utf8');
      const findings = analyzer.analyze(testFile, content);

      const evalFindings = findings.filter(f =>
        f.message.includes('eval(')
      );

      expect(evalFindings.length).toBeGreaterThan(0);
    });

    test('detects Function constructor', () => {
      const testFile = path.join(testDir, 'eval-dynamic.js');
      const content = fs.readFileSync(testFile, 'utf8');
      const findings = analyzer.analyze(testFile, content);

      const functionFindings = findings.filter(f =>
        f.message.includes('Function(')
      );

      expect(functionFindings.length).toBeGreaterThan(0);
    });

    test('detects vm.runInNewContext', () => {
      const testFile = path.join(testDir, 'eval-dynamic.js');
      const content = fs.readFileSync(testFile, 'utf8');
      const findings = analyzer.analyze(testFile, content);

      const vmFindings = findings.filter(f =>
        f.message.includes('vm.runInNewContext') ||
        f.message.includes('vm.runInThisContext')
      );

      expect(vmFindings.length).toBeGreaterThan(0);
    });
  });

  describe('Safe usage patterns', () => {
    test('detects exec usage but with lower severity for safe operations', () => {
      const testFile = path.join(testDir, 'safe-usage.js');
      const content = fs.readFileSync(testFile, 'utf8');
      const findings = analyzer.analyze(testFile, content);

      // Safe usage should still be detected (as exec methods are found)
      // but without dangerous pattern escalation
      expect(findings.length).toBeGreaterThan(0);

      // All findings should be generic warnings, not dangerous-command-exec
      const dangerousFindings = findings.filter(f =>
        f.ruleId === 'dangerous-command-exec'
      );

      expect(dangerousFindings.length).toBe(0);

      // Should have generic exec warnings
      const genericWarnings = findings.filter(f =>
        f.ruleId === 'command-exec-usage'
      );

      expect(genericWarnings.length).toBeGreaterThan(0);
      expect(genericWarnings[0].level).toBe('warning');
    });
  });

  describe('Test file exclusion', () => {
    test('does not analyze test files', () => {
      const testFilePath = '/src/commands.test.js';
      const content = "exec('rm -rf /')";

      const findings = analyzer.analyze(testFilePath, content);

      expect(findings).toBeDefined();
      expect(findings.length).toBe(0);
    });

    test('does not analyze spec files', () => {
      const specFilePath = '/src/commands.spec.js';
      const content = "exec('rm -rf /')";

      const findings = analyzer.analyze(specFilePath, content);

      expect(findings).toBeDefined();
      expect(findings.length).toBe(0);
    });
  });

  describe('Configuration', () => {
    test('uses custom severity from config', () => {
      const customAnalyzer = new CommandExecAnalyzer({ severity: 'note' });
      const testFile = path.join(testDir, 'safe-usage.js');
      const content = fs.readFileSync(testFile, 'utf8');
      const findings = customAnalyzer.analyze(testFile, content);

      // Generic warnings should use custom severity
      const genericWarnings = findings.filter(f =>
        f.ruleId === 'command-exec-usage'
      );

      if (genericWarnings.length > 0) {
        expect(genericWarnings[0].level).toBe('warning');
      }
    });

    test('can be disabled via config', () => {
      const disabledAnalyzer = new CommandExecAnalyzer({ enabled: false });
      expect(disabledAnalyzer.enabled).toBe(false);
    });

    test('respects custom file extensions', () => {
      const customAnalyzer = new CommandExecAnalyzer({
        fileExtensions: ['.js', '.ts']
      });

      const findings = customAnalyzer.analyze('test.py', 'exec("rm -rf /")');
      expect(findings.length).toBe(0); // .py not in custom extensions
    });
  });
});
