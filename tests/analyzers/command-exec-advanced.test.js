const CommandExecAnalyzer = require('../../src/analyzers/command-exec');

describe('CommandExecAnalyzer (Advanced)', () => {
    let analyzer;

    beforeEach(() => {
        analyzer = new CommandExecAnalyzer();
    });

    test('should detect indirect execution via variable reassignment', () => {
        const code = `
      const { exec } = require('child_process');
      const userInput = process.env.INPUT;
      const cmd = userInput;
      exec(cmd);
    `;
        const findings = analyzer.analyze('test.js', code);
        expect(findings).toHaveLength(1);
        expect(findings[0].message).toContain("Dangerous command execution detected");
    });

    test('should detect execution via concatenation', () => {
        const code = `
      const exec = require('child_process').exec;
      const input = process.env.USER_INPUT;
      exec('ls ' + input);
    `;
        const findings = analyzer.analyze('test.js', code);
        expect(findings).toHaveLength(1);
    });

    test('should detect execution via template literals', () => {
        const code = `
      const cp = require('child_process');
      const file = process.env.FILE;
      cp.exec(\`cat \${file}\`);
    `;
        const findings = analyzer.analyze('test.js', code);
        expect(findings).toHaveLength(1);
    });

    test('should detect execution passed to helper function', () => {
        const code = `
      const { exec } = require('child_process');
      
      function runCommand(c) {
        exec(c);
      }
      
      const input = process.env.CMD;
      runCommand(input);
    `;
        const findings = analyzer.analyze('test.js', code);
        expect(findings).toHaveLength(1);
    });

    test('should detect vm.runInContext with tainted input', () => {
        const code = `
      const vm = require('vm');
      const code = process.env.UNTRUSTED_CODE;
      vm.runInContext(code, sandbox);
    `;
        const findings = analyzer.analyze('test.js', code);
        expect(findings).toHaveLength(1);
    });

    test('should NOT flag safe hardcoded commands', () => {
        const code = `
      const { exec } = require('child_process');
      exec('ls -la');
      exec('echo "hello"');
    `;
        const findings = analyzer.analyze('test.js', code);
        expect(findings).toHaveLength(0);
    });

    test('should NOT flag safe template literals', () => {
        const code = `
      const { exec } = require('child_process');
      const dir = 'safe_dir';
      exec(\`ls \${dir}\`); // This is technically safe if dir is safe.
      // But our analyzer might flag it if it doesn't know 'dir' is safe.
      // Let's assume 'dir' is defined as a literal string in the same scope.
    `;
        // If our analyzer is smart, it sees 'dir' comes from literal 'safe_dir'.
        const findings = analyzer.analyze('test.js', code);
        expect(findings).toHaveLength(0);
    });
});
