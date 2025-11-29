const CommandExecAnalyzer = require('../../src/analyzers/command-exec');

describe('CommandExecAnalyzer - MCP Patterns', () => {
  let analyzer;

  beforeEach(() => {
    analyzer = new CommandExecAnalyzer();
  });

  describe('MCP Tool Arguments (args.*)', () => {
    test('should detect args.command flowing to exec', () => {
      const code = `
        const { Server } = require("@modelcontextprotocol/sdk/server/index.js");
        const { exec } = require("child_process");

        server.setRequestHandler("tools/call", async (request) => {
          const { command } = request.params.arguments;
          exec(command);
        });
      `;
      const findings = analyzer.analyze('test.js', code);
      expect(findings.length).toBeGreaterThan(0);
      expect(findings[0].message).toContain('MCP');
    });

    test('should detect direct args.command pattern', () => {
      const code = `
        const { Server } = require("@modelcontextprotocol/sdk/server/index.js");
        const { exec } = require("child_process");

        async function handleTool(args) {
          exec(args.command);
        }
      `;
      const findings = analyzer.analyze('test.js', code);
      expect(findings.length).toBeGreaterThan(0);
      expect(findings[0].message).toContain('args.command');
    });

    test('should detect args variable stored then executed', () => {
      const code = `
        const { Server } = require("@modelcontextprotocol/sdk/server/index.js");
        const { exec } = require("child_process");

        function handleRequest(args) {
          const cmd = args.command;
          exec(cmd);
        }
      `;
      const findings = analyzer.analyze('test.js', code);
      expect(findings.length).toBeGreaterThan(0);
    });

    test('should detect destructured command from args', () => {
      const code = `
        const { Server } = require("@modelcontextprotocol/sdk/server/index.js");
        const { exec } = require("child_process");

        server.handle(({ command, workingDirectory }) => {
          exec(command);
        });
      `;
      const findings = analyzer.analyze('test.js', code);
      expect(findings.length).toBeGreaterThan(0);
      expect(findings[0].message).toContain('command');
    });
  });

  describe('MCP Handler Patterns', () => {
    test('should detect fallbackRequestHandler with exec', () => {
      const code = `
        const { Server } = require("@modelcontextprotocol/sdk/server/index.js");
        const { exec } = require("child_process");

        server.fallbackRequestHandler = async (request) => {
          const { command } = request.params.arguments;
          exec(command);
        };
      `;
      const findings = analyzer.analyze('test.js', code);
      expect(findings.length).toBeGreaterThan(0);
    });

    test('should detect setRequestHandler pattern', () => {
      const code = `
        const { Server } = require("@modelcontextprotocol/sdk/server/index.js");
        const { execSync } = require("child_process");

        server.setRequestHandler(CallToolRequestSchema, async ({ params }) => {
          const { command } = params.arguments;
          execSync(command);
        });
      `;
      const findings = analyzer.analyze('test.js', code);
      expect(findings.length).toBeGreaterThan(0);
    });
  });

  describe('execa Library Support', () => {
    test('should detect execa with tainted input', () => {
      const code = `
        import { Server } from '@modelcontextprotocol/sdk/server/index.js';
        import { execa } from 'execa';

        server.handle(async (args) => {
          await execa(args.command);
        });
      `;
      const findings = analyzer.analyze('test.js', code);
      expect(findings.length).toBeGreaterThan(0);
      expect(findings[0].message).toContain('execa');
    });

    test('should detect execa with shell option and env', () => {
      const code = `
        import { execa } from 'execa';

        async function run(command) {
          await execa(command, [], {
            shell: true,
            env: process.env,
          });
        }
      `;
      const findings = analyzer.analyze('test.js', code);
      // Should detect the env: process.env pattern
      expect(findings.some(f => f.ruleId === 'command-exec-env')).toBe(true);
    });
  });

  describe('Environment Pollution (env: process.env)', () => {
    test('should detect env: process.env in exec options', () => {
      const code = `
        const { exec } = require('child_process');
        exec('ls', { env: process.env });
      `;
      const findings = analyzer.analyze('test.js', code);
      expect(findings.some(f => f.ruleId === 'command-exec-env')).toBe(true);
    });

    test('should flag higher severity when shell: true with env: process.env', () => {
      const code = `
        const { spawn } = require('child_process');
        spawn('bash', ['-c', 'echo hello'], { shell: true, env: process.env });
      `;
      const findings = analyzer.analyze('test.js', code);
      const envFinding = findings.find(f => f.ruleId === 'command-exec-env');
      expect(envFinding).toBeDefined();
      expect(envFinding.level).toBe('error');
    });

    test('should detect env: process.env in execa options', () => {
      const code = `
        import { execa } from 'execa';
        await execa('command', [], { env: process.env });
      `;
      const findings = analyzer.analyze('test.js', code);
      expect(findings.some(f => f.ruleId === 'command-exec-env')).toBe(true);
    });
  });

  describe('Real-World MCP Server Patterns (from experiment)', () => {
    test('should detect CommandExecution pattern (ryaker/CommandExecution)', () => {
      // Simplified version of the vulnerable pattern
      const code = `
        const { Server } = require("@modelcontextprotocol/sdk/server/index.js");
        const { exec } = require("child_process");
        const { promisify } = require("util");
        const execPromise = promisify(exec);

        server.fallbackRequestHandler = async (request) => {
          const { method, params } = request;
          if (method === "tools/call") {
            const { name, arguments: args = {} } = params || {};
            if (name === "execute-command") {
              const { command, workingDirectory } = args;
              return await execPromise(command, { cwd: workingDirectory });
            }
          }
        };
      `;
      const findings = analyzer.analyze('test.js', code);
      expect(findings.length).toBeGreaterThan(0);
      // Should detect args flowing to execPromise
      expect(findings.some(f => f.message.includes('command'))).toBe(true);
    });

    test('should detect hdresearch/mcp-shell pattern (execa with env)', () => {
      const code = `
        import { Server } from '@modelcontextprotocol/sdk/server/index.js';
        import { execa } from 'execa';

        server.setRequestHandler(CallToolRequestSchema, async (request) => {
          const { command } = request.params.arguments;
          const { stdout, stderr } = await execa(command, [], {
            shell: true,
            env: process.env,
          });
          return { content: [{ type: 'text', text: stdout || stderr }] };
        });
      `;
      const findings = analyzer.analyze('test.js', code);
      expect(findings.length).toBeGreaterThan(0);
      // Should detect both the tainted command AND the env pattern
      expect(findings.some(f => f.ruleId === 'command-exec')).toBe(true);
      expect(findings.some(f => f.ruleId === 'command-exec-env')).toBe(true);
    });
  });

  describe('False Positive Prevention', () => {
    test('should NOT flag hardcoded commands in MCP servers', () => {
      const code = `
        const { Server } = require("@modelcontextprotocol/sdk/server/index.js");
        const { exec } = require("child_process");

        server.handle(async (request) => {
          exec('ls -la');  // Safe: hardcoded
          exec('echo "Hello World"');  // Safe: hardcoded
        });
      `;
      const findings = analyzer.analyze('test.js', code);
      // Should not have command-exec findings for hardcoded commands
      const commandExecFindings = findings.filter(f => f.ruleId === 'command-exec');
      expect(commandExecFindings).toHaveLength(0);
    });

    test('should NOT flag safe internal function calls', () => {
      const code = `
        const { exec } = require("child_process");

        function getSafeCommand() {
          return 'ls -la';
        }

        exec(getSafeCommand());
      `;
      const findings = analyzer.analyze('test.js', code);
      expect(findings).toHaveLength(0);
    });
  });

  describe('Backward Compatibility (process.env)', () => {
    test('should still detect process.env flowing to exec', () => {
      const code = `
        const { exec } = require('child_process');
        const cmd = process.env.COMMAND;
        exec(cmd);
      `;
      const findings = analyzer.analyze('test.js', code);
      expect(findings.length).toBeGreaterThan(0);
      expect(findings[0].message).toContain('process.env');
    });

    test('should detect process.env in template literal', () => {
      const code = `
        const { exec } = require('child_process');
        const file = process.env.FILE;
        exec(\`cat \${file}\`);
      `;
      const findings = analyzer.analyze('test.js', code);
      expect(findings.length).toBeGreaterThan(0);
    });
  });
});
