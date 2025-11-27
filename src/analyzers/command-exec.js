const BaseAnalyzer = require('./base-analyzer');
const path = require('path');

const NAME = 'command-exec';

// Dangerous command execution patterns
const EXEC_METHODS = [
  // Node.js child_process methods
  /\bexec\s*\(/gi,
  /\bexecSync\s*\(/gi,
  /\bspawn\s*\(/gi,
  /\bspawnSync\s*\(/gi,
  /\bexecFile\s*\(/gi,
  /\bexecFileSync\s*\(/gi,
  /\bfork\s*\(/gi,

  // Python subprocess methods
  /subprocess\.call\s*\(/gi,
  /subprocess\.run\s*\(/gi,
  /subprocess\.Popen\s*\(/gi,
  /os\.system\s*\(/gi,
  /os\.popen\s*\(/gi,

  // Dynamic code execution
  /\beval\s*\(/gi,
  /new\s+Function\s*\(/gi,
  /vm\.runInNewContext\s*\(/gi,
  /vm\.runInThisContext\s*\(/gi
];

// Dangerous command patterns (high severity)
const DANGEROUS_COMMANDS = [
  // Destructive operations (order matters - check specific patterns before generic ones)
  { pattern: /rm\s+-rf\s+\/(?:\s|$|'|"|;|\))/, description: 'Deletes root directory', severity: 'error' },
  { pattern: /rm\s+-rf\s+~(?:\s|$|'|"|;|\))/, description: 'Deletes home directory', severity: 'error' },
  { pattern: /rm\s+-rf\s+\*(?:\s|$|'|"|;|\))/, description: 'Recursive deletion with wildcard', severity: 'error' },
  { pattern: /rm\s+-rf\s+\/\w+\/\*/, description: 'Recursive deletion in directory', severity: 'warning' },
  { pattern: /\bdd\s+if=.*of=\/dev\//, description: 'Potentially destructive disk operation', severity: 'error' },
  { pattern: /\bmkfs\b/, description: 'Format filesystem operation', severity: 'error' },

  // Network/credential exfiltration
  { pattern: /curl\s+.*\|\s*(?:bash|sh|python)/i, description: 'Pipe curl output to shell', severity: 'error' },
  { pattern: /wget\s+.*\|\s*(?:bash|sh|python)/i, description: 'Pipe wget output to shell', severity: 'error' },
  { pattern: /\bnc\s+-e/i, description: 'Netcat with execute flag (reverse shell)', severity: 'error' },
  { pattern: /\bnetcat\s+-e/i, description: 'Netcat with execute flag (reverse shell)', severity: 'error' },

  // Encoded/obfuscated commands
  { pattern: /powershell.*-enc(?:oded)?(?:command)?/i, description: 'Encoded PowerShell command', severity: 'error' },
  { pattern: /powershell.*-e\s+[A-Za-z0-9+\/=]{20,}/i, description: 'Base64-encoded PowerShell', severity: 'error' },
  { pattern: /base64\s+-d.*(?:bash|sh)/i, description: 'Base64-decoded shell command', severity: 'error' },
  { pattern: /echo.*base64.*bash/i, description: 'Base64-decoded shell command', severity: 'error' },

  // Credential access
  { pattern: /\/etc\/shadow/, description: 'Access to shadow password file', severity: 'error' },
  { pattern: /\/etc\/passwd/, description: 'Access to password file', severity: 'warning' },
  { pattern: /\$(?:AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|GITHUB_TOKEN|OPENAI_API_KEY)/, description: 'Credential environment variable access', severity: 'warning' },

  // Suspicious shell operations
  { pattern: /chmod\s+777/i, description: 'Setting overly permissive file permissions', severity: 'warning' },
  { pattern: /\/dev\/tcp\//i, description: 'Bash /dev/tcp/ network redirection (potential backdoor)', severity: 'error' },
  { pattern: />\s*\/dev\/null\s+2>&1/i, description: 'Suppressing all output (potential stealth)', severity: 'warning' }
];

class CommandExecAnalyzer extends BaseAnalyzer {
  constructor(options = {}) {
    super(NAME, options);

    const globalConfig = options.globalConfig || {};
    this.extensions = options.fileExtensions || globalConfig.fileExtensions || ['.js', '.ts', '.jsx', '.tsx', '.py', '.java', '.json'];
    this.testPatterns = options.testFilePatterns || globalConfig.testFilePatterns || ['.test.', '.spec.', '__tests__'];

    // Allow custom patterns to be added
    this.execPatterns = options.customExecPatterns ?
      [...EXEC_METHODS, ...options.customExecPatterns] :
      EXEC_METHODS;

    this.dangerousCommands = options.customDangerousCommands ?
      [...DANGEROUS_COMMANDS, ...options.customDangerousCommands] :
      DANGEROUS_COMMANDS;
  }

  analyze(filePath, content) {
    const findings = [];

    if (!this.shouldAnalyze(filePath)) {
      return findings;
    }

    // Shell scripts (.sh, .bash, .zsh) - scan for dangerous patterns directly
    const ext = path.extname(filePath);
    if (['.sh', '.bash', '.zsh'].includes(ext)) {
      return this.analyzeShellScript(filePath, content);
    }

    // Try AST analysis first for JS/TS files
    const ast = this.parseAST(content);
    if (ast) {
      try {
        return this.analyzeAST(ast, filePath, content);
      } catch (err) {
        console.warn(`AST analysis failed for ${filePath}, falling back to regex:`, err.message);
      }
    }

    // Fallback to Regex (original implementation)
    return this.analyzeRegex(filePath, content);
  }

  analyzeAST(ast, filePath, content) {
    const findings = [];
    const self = this;

    this.walkAST(ast, {
      CallExpression(node) {
        self.handleNode(node, filePath, findings, content);
      },
      NewExpression(node) {
        self.handleNode(node, filePath, findings, content);
      }
    });

    return findings;
  }

  handleNode(node, filePath, findings, content) {
    // Identify the function name being called
    let functionName = '';
    let fullMethodName = '';

    if (node.callee.type === 'Identifier') {
      functionName = node.callee.name; // e.g., exec()
      fullMethodName = functionName;
    } else if (node.callee.type === 'MemberExpression') {
      functionName = node.callee.property.name; // e.g., exec()
      // Construct full name like "child_process.exec" or "vm.runInNewContext"
      if (node.callee.object.type === 'Identifier') {
        fullMethodName = `${node.callee.object.name}.${functionName}`;
      } else {
        fullMethodName = functionName;
      }
    }

    // Check if it's a dangerous execution method
    const dangerousFuncs = [
      'exec', 'execSync', 'spawn', 'spawnSync',
      'execFile', 'execFileSync', 'fork',
      'eval', 'Function',
      'runInNewContext', 'runInThisContext', 'createContext'
    ];

    if (dangerousFuncs.includes(functionName)) {
      this.analyzeDangerousCall(node, filePath, findings, content, fullMethodName);
    }
  }

  analyzeDangerousCall(node, filePath, findings, content, functionName) {
    if (!node.arguments || node.arguments.length === 0) return;

    let dangerousPattern = null;
    let isDynamic = false;
    const argsContent = [];

    // Check all arguments for dangerous patterns
    for (const arg of node.arguments) {
      const argContent = content.substring(arg.start, arg.end);
      argsContent.push(argContent);

      // Strip quotes for cleaner regex matching
      const cleanArg = argContent.replace(/^['"`]|['"`]$/g, '');

      // Check for specific dangerous commands within this argument
      for (const cmd of this.dangerousCommands) {
        if (cmd.pattern.test(cleanArg) || cmd.pattern.test(argContent)) {
          dangerousPattern = cmd;
          break;
        }
      }
      if (dangerousPattern) break;

      // Check for dynamic nature
      if (arg.type === 'TemplateLiteral' && arg.expressions.length > 0) {
        isDynamic = true;
      } else if (arg.type === 'BinaryExpression') {
        isDynamic = true;
      } else if (arg.type === 'Identifier') {
        isDynamic = true;
      }
    }

    const location = { line: node.loc.start.line, column: node.loc.start.column };
    const joinedArgs = argsContent.join(' ').replace(/\s+/g, ' '); // Normalize whitespace (handle newlines)

    // Check joined arguments for dangerous patterns (handles split command/args like spawn('powershell', ['-enc', ...]))
    if (!dangerousPattern) {
      for (const cmd of this.dangerousCommands) {
        if (cmd.pattern.test(joinedArgs)) {
          dangerousPattern = cmd;
          break;
        }
      }
    }

    if (dangerousPattern) {
      findings.push(this.createFinding(
        filePath,
        location.line,
        location.column,
        `Dangerous command execution detected: ${dangerousPattern.description} using ${functionName}`,
        'dangerous-command-exec',
        dangerousPattern.severity === 'error' ? 'error' : this.severity
      ));
    } else if (isDynamic) {
      // Generic warning for dynamic execution
      // Format: "via eval(userInput)" to satisfy tests looking for "eval("
      findings.push(this.createFinding(
        filePath,
        location.line,
        location.column,
        `Dynamic command execution detected via ${functionName}(${joinedArgs}). Ensure user input is properly validated.`,
        'command-exec-usage',
        'warning'
      ));
    } else {
      // Generic warning for static/safe execution
      findings.push(this.createFinding(
        filePath,
        location.line,
        location.column,
        `Command execution method detected: ${functionName}(${joinedArgs}). Ensure user input is properly validated.`,
        'command-exec-usage',
        'warning'
      ));
    }
  }

  analyzeRegex(filePath, content) {
    const findings = [];
    // First pass: Detect execution method usage
    this.execPatterns.forEach((pattern) => {
      const matches = content.matchAll(pattern);
      for (const match of matches) {
        const location = this.getLocation(content, match.index);

        // Extract the statement containing this match
        // Find the start of the current line
        let lineStart = match.index;
        while (lineStart > 0 && content[lineStart - 1] !== '\n') {
          lineStart--;
        }

        // Find the end of the statement (next semicolon, closing paren + semicolon, or several newlines)
        let statementEnd = match.index;
        let parenDepth = 0;
        let braceDepth = 0;

        while (statementEnd < content.length) {
          const char = content[statementEnd];

          if (char === '(') parenDepth++;
          if (char === ')') parenDepth--;
          if (char === '{') braceDepth++;
          if (char === '}') braceDepth--;

          // End of statement: semicolon at depth 0, or closing all parens/braces
          if (char === ';' && parenDepth === 0) {
            statementEnd++;
            break;
          }

          // For spawn/exec calls, we want to include the full call with arguments
          if (char === ')' && parenDepth === 0 && statementEnd > match.index + 10) {
            statementEnd += 50; // Grab a bit more to ensure we get string args
            break;
          }

          statementEnd++;

          // Safety limit
          if (statementEnd - match.index > 500) break;
        }

        const context = content.substring(lineStart, statementEnd);

        // Check if this execution contains dangerous patterns
        let dangerousPattern = null;
        let maxSeverity = this.severity;

        for (const cmd of this.dangerousCommands) {
          if (cmd.pattern.test(context)) {
            dangerousPattern = cmd;
            // Upgrade severity if dangerous command found
            if (cmd.severity === 'error') {
              maxSeverity = 'error';
            }
            break;
          }
        }

        if (dangerousPattern) {
          findings.push(this.createFinding(
            filePath,
            location.line,
            location.column,
            `Dangerous command execution detected: ${dangerousPattern.description} using "${match[0].trim()}"`,
            'dangerous-command-exec',
            maxSeverity
          ));
        } else {
          // Generic execution method warning (lower severity)
          findings.push(this.createFinding(
            filePath,
            location.line,
            location.column,
            `Command execution method detected: "${match[0].trim()}". Ensure user input is properly validated and sanitized.`,
            'command-exec-usage',
            'warning'
          ));
        }
      }
    });

    return findings;
  }

  analyzeShellScript(filePath, content) {
    const findings = [];
    const lines = content.split('\n');

    lines.forEach((line, index) => {
      const lineNumber = index + 1;
      const trimmedLine = line.trim();

      // Skip comments and empty lines
      if (trimmedLine.startsWith('#') || trimmedLine.length === 0) {
        return;
      }

      // Check for dangerous command patterns in each line
      for (const cmd of this.dangerousCommands) {
        if (cmd.pattern.test(line)) {
          findings.push(this.createFinding(
            filePath,
            lineNumber,
            1,
            `Dangerous shell command detected: ${cmd.description}`,
            'dangerous-shell-command',
            cmd.severity
          ));
          break; // Only report first match per line
        }
      }
    });

    return findings;
  }

  shouldAnalyze(filePath) {
    const ext = path.extname(filePath);

    // Skip test files
    if (this.testPatterns.some(pattern => filePath.includes(pattern))) {
      return false;
    }

    return this.extensions.includes(ext);
  }

  getLocation(content, index) {
    const lines = content.substring(0, index).split('\n');
    const line = lines.length;
    const column = lines[lines.length - 1].length + 1;
    return { line, column };
  }

  createFinding(file, line, column, message, ruleId = null, severity = null) {
    return {
      ruleId: ruleId || this.name,
      level: severity || this.severity,
      message: message,
      location: {
        file: file,
        line: line,
        column: column
      }
    };
  }
}

module.exports = CommandExecAnalyzer;
