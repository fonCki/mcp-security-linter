const BaseAnalyzer = require('./base-analyzer');
const path = require('path');
const walk = require('acorn-walk');

const NAME = 'command-exec';

/**
 * MCP-Aware Command Execution Analyzer
 *
 * Detects dangerous command execution patterns in MCP servers, including:
 * - process.env → exec/spawn (original behavior)
 * - MCP tool arguments → exec/spawn (NEW: args.command, destructured params)
 * - env: process.env in exec options (NEW: environment pollution)
 * - execa library support (NEW)
 *
 * @version 2.0.0
 */
class CommandExecAnalyzer extends BaseAnalyzer {
  constructor(options = {}) {
    super(NAME, options);

    const globalConfig = options.globalConfig || {};
    this.extensions = options.fileExtensions || globalConfig.fileExtensions || ['.js', '.ts', '.jsx', '.tsx'];
    this.testPatterns = options.testFilePatterns || globalConfig.testFilePatterns || ['.test.', '.spec.', '__tests__'];

    // Execution sinks - functions that execute commands
    this.execSinks = new Set([
      'exec', 'execSync', 'spawn', 'spawnSync', 'execFile', 'execFileSync', 'fork',
      'eval', 'Function',
      'execa', 'execaSync', 'execaCommand', 'execaCommandSync', '$'  // execa library
    ]);

    // Member expression sinks (object.method patterns)
    this.memberExecSinks = new Set([
      'child_process.exec', 'child_process.execSync',
      'child_process.spawn', 'child_process.spawnSync',
      'child_process.execFile', 'child_process.execFileSync',
      'child_process.fork',
      'cp.exec', 'cp.execSync', 'cp.spawn', 'cp.spawnSync',
      'vm.runInContext', 'vm.runInNewContext', 'vm.runInThisContext',
      'util.promisify'  // promisify(exec) pattern
    ]);

    // MCP handler method names that receive untrusted input
    this.mcpHandlerMethods = new Set([
      'setRequestHandler', 'fallbackRequestHandler',
      'handle', 'handleToolCall', 'handleRequest',
      'call', 'invoke'
    ]);

    // MCP parameter names that are always tainted
    this.mcpTaintedParams = new Set([
      'args', 'arguments', 'params', 'parameters',
      'request', 'req', 'input', 'payload'
    ]);

    // Common MCP argument properties that flow to commands
    this.mcpCommandProps = new Set([
      'command', 'cmd', 'script', 'shell', 'exec',
      'query', 'sql', 'code', 'expression'
    ]);
  }

  analyze(filePath, content) {
    if (!this.shouldAnalyze(filePath)) {
      return [];
    }

    const ast = this.parseAST(content);
    if (!ast) {
      return [];
    }

    try {
      let findings = [];
      let functionTaints = new Map();
      let changed = true;
      let iterations = 0;
      const MAX_ITERATIONS = 10;

      // Pre-analyze to detect MCP handler patterns
      const mcpContext = this.detectMCPPatterns(ast);

      while (changed && iterations < MAX_ITERATIONS) {
        changed = false;
        iterations++;
        findings = [];

        const result = this.analyzePass(ast, filePath, content, functionTaints, mcpContext);
        findings = result.findings;

        for (const [funcName, paramMap] of result.newFunctionTaints) {
          if (!functionTaints.has(funcName)) {
            functionTaints.set(funcName, new Map());
          }

          const currentTaints = functionTaints.get(funcName);
          for (const [paramIndex, origin] of paramMap) {
            if (!currentTaints.has(paramIndex) || currentTaints.get(paramIndex) !== origin) {
              currentTaints.set(paramIndex, origin);
              changed = true;
            }
          }
        }
      }

      return findings;
    } catch (err) {
      console.warn(`AST analysis failed for ${filePath}:`, err.message);
      return [];
    }
  }

  /**
   * Pre-analyze to detect MCP-specific patterns
   * Identifies handler functions, tool definitions, etc.
   */
  detectMCPPatterns(ast) {
    const context = {
      isMCPServer: false,
      handlerFunctions: new Set(),
      toolHandlerParams: new Map()  // Maps param names to their origin
    };

    const self = this;

    walk.simple(ast, {
      // Detect MCP SDK imports
      ImportDeclaration(node) {
        if (node.source.value && node.source.value.includes('@modelcontextprotocol')) {
          context.isMCPServer = true;
        }
      },

      // Detect require('@modelcontextprotocol/...')
      CallExpression(node) {
        if (node.callee.name === 'require' && node.arguments[0]?.value?.includes('@modelcontextprotocol')) {
          context.isMCPServer = true;
        }

        // Detect handler registrations: server.setRequestHandler(...)
        if (node.callee.type === 'MemberExpression') {
          const methodName = node.callee.property?.name;
          if (self.mcpHandlerMethods.has(methodName)) {
            context.isMCPServer = true;

            // Find the handler function argument
            for (const arg of node.arguments) {
              if (arg.type === 'ArrowFunctionExpression' || arg.type === 'FunctionExpression') {
                // Mark all params of the handler as tainted
                arg.params.forEach((param, idx) => {
                  if (param.type === 'Identifier') {
                    context.toolHandlerParams.set(param.name, `mcp-handler-param-${idx}`);
                  } else if (param.type === 'ObjectPattern') {
                    // Destructured params like ({ args, name }) => ...
                    param.properties.forEach(prop => {
                      if (prop.key?.name) {
                        context.toolHandlerParams.set(prop.key.name, `mcp-handler-destructured`);
                      }
                    });
                  }
                });
              }
            }
          }
        }
      },

      // Detect fallbackRequestHandler = async (request) => ...
      AssignmentExpression(node) {
        if (node.left.type === 'MemberExpression') {
          const propName = node.left.property?.name;
          if (self.mcpHandlerMethods.has(propName)) {
            context.isMCPServer = true;

            if (node.right.type === 'ArrowFunctionExpression' || node.right.type === 'FunctionExpression') {
              node.right.params.forEach((param, idx) => {
                if (param.type === 'Identifier') {
                  context.toolHandlerParams.set(param.name, `mcp-fallback-param-${idx}`);
                }
              });
            }
          }
        }
      }
    });

    return context;
  }

  analyzePass(ast, filePath, content, existingFunctionTaints, mcpContext) {
    const self = this;
    const findings = [];
    const newFunctionTaints = new Map();

    // Track variables that are aliases for exec functions (e.g., execPromise = promisify(exec))
    const execAliases = new Set();

    const state = {
      scopeStack: [new Map()],
      mcpContext,
      execAliases,

      getCurrentScope() {
        return this.scopeStack[this.scopeStack.length - 1];
      },

      isTainted(name) {
        // Check local scopes first
        for (let i = this.scopeStack.length - 1; i >= 0; i--) {
          if (this.scopeStack[i].has(name)) {
            return this.scopeStack[i].get(name);
          }
        }

        // Check MCP handler params (always tainted in MCP context)
        if (this.mcpContext.toolHandlerParams.has(name)) {
          return this.mcpContext.toolHandlerParams.get(name);
        }

        // Check if it's a known MCP tainted parameter name
        if (this.mcpContext.isMCPServer && self.mcpTaintedParams.has(name)) {
          return `mcp-param:${name}`;
        }

        return null;
      },

      taint(name, origin) {
        this.getCurrentScope().set(name, origin);
      },

      pushScope() {
        this.scopeStack.push(new Map());
      },

      popScope() {
        this.scopeStack.pop();
      }
    };

    const visitors = {
      FunctionDeclaration(node, st, c) {
        st.pushScope();
        const funcName = node.id?.name;

        // Check if params match MCP tainted names
        node.params.forEach((param, index) => {
          if (param.type === 'Identifier') {
            // Check if this function received taint from a previous pass
            if (existingFunctionTaints.has(funcName)) {
              const taintedParams = existingFunctionTaints.get(funcName);
              if (taintedParams.has(index)) {
                st.taint(param.name, taintedParams.get(index));
              }
            }

            // Mark MCP param names as tainted
            if (st.mcpContext.isMCPServer && self.mcpTaintedParams.has(param.name)) {
              st.taint(param.name, `mcp-param:${param.name}`);
            }
          } else if (param.type === 'ObjectPattern') {
            // Handle destructured params: function foo({ command, args }) { ... }
            self.handleDestructuredParam(param, st);
          }
        });

        c(node.body, st);
        st.popScope();
      },

      ArrowFunctionExpression(node, st, c) {
        st.pushScope();

        // Mark handler params as tainted
        node.params.forEach((param, index) => {
          if (param.type === 'Identifier') {
            if (st.mcpContext.isMCPServer && self.mcpTaintedParams.has(param.name)) {
              st.taint(param.name, `mcp-param:${param.name}`);
            }
          } else if (param.type === 'ObjectPattern') {
            self.handleDestructuredParam(param, st);
          }
        });

        c(node.body, st);
        st.popScope();
      },

      FunctionExpression(node, st, c) {
        st.pushScope();

        node.params.forEach((param, index) => {
          if (param.type === 'Identifier') {
            if (st.mcpContext.isMCPServer && self.mcpTaintedParams.has(param.name)) {
              st.taint(param.name, `mcp-param:${param.name}`);
            }
          } else if (param.type === 'ObjectPattern') {
            self.handleDestructuredParam(param, st);
          }
        });

        c(node.body, st);
        st.popScope();
      },

      VariableDeclarator(node, st, c) {
        if (node.id.type === 'Identifier') {
          const varName = node.id.name;
          if (node.init) {
            // Check for promisify(exec) pattern - creates an exec alias
            if (self.isPromisifiedExec(node.init)) {
              st.execAliases.add(varName);
            }
            // Check for process.env
            else if (self.isProcessEnv(node.init)) {
              st.taint(varName, 'process.env');
            }
            // Check for MCP arg access: args.command, params.query
            else if (self.isMCPArgAccess(node.init)) {
              const origin = self.getMCPArgOrigin(node.init);
              st.taint(varName, origin);
            }
            // Check regular taint propagation
            else {
              const result = self.getTaintOrigin(node.init, st.isTainted.bind(st));
              if (result) st.taint(varName, result.origin);
            }
          }
        } else if (node.id.type === 'ObjectPattern' && node.init) {
          // Destructuring: const { command, args } = something
          const initTaint = self.getTaintOrigin(node.init, st.isTainted.bind(st));
          const isMCPInit = self.isMCPArgAccess(node.init);

          // Handle each destructured property
          self.handleDestructuredDeclarator(node.id, node.init, st, initTaint, isMCPInit);
        }

        if (node.init) c(node.init, st);
      },

      AssignmentExpression(node, st, c) {
        if (node.left.type === 'Identifier') {
          const varName = node.left.name;
          if (self.isProcessEnv(node.right)) {
            st.taint(varName, 'process.env');
          } else if (self.isMCPArgAccess(node.right)) {
            st.taint(varName, self.getMCPArgOrigin(node.right));
          } else {
            const result = self.getTaintOrigin(node.right, st.isTainted.bind(st));
            if (result) st.taint(varName, result.origin);
          }
        }
        c(node.right, st);
      },

      CallExpression(node, st, c) {
        // Check for dangerous execution patterns
        self.checkCallExpression(node, st.isTainted.bind(st), filePath, findings, content, st.mcpContext, st.execAliases);

        // Check for env option in exec calls
        self.checkExecOptions(node, filePath, findings, st.mcpContext);

        // Track taint flow through function calls
        if (node.callee.type === 'Identifier') {
          const funcName = node.callee.name;
          node.arguments.forEach((arg, index) => {
            const result = self.getTaintOrigin(arg, st.isTainted.bind(st));
            if (result) {
              if (!newFunctionTaints.has(funcName)) {
                newFunctionTaints.set(funcName, new Map());
              }
              newFunctionTaints.get(funcName).set(index, result.origin);
            }
          });
        }

        node.arguments.forEach(arg => c(arg, st));
        c(node.callee, st);
      }
    };

    walk.recursive(ast, state, visitors);

    return { findings, newFunctionTaints };
  }

  /**
   * Handle destructured parameters like { command, args }
   * Marks relevant properties as tainted
   */
  handleDestructuredParam(pattern, st) {
    if (pattern.type !== 'ObjectPattern') return;

    for (const prop of pattern.properties) {
      if (prop.type === 'Property') {
        const keyName = prop.key?.name;
        const valueName = prop.value?.type === 'Identifier' ? prop.value.name : keyName;

        // Mark MCP command properties as high-priority taint
        if (this.mcpCommandProps.has(keyName)) {
          st.taint(valueName, `mcp-arg:${keyName}`);
        }
        // Mark general MCP params as tainted
        else if (this.mcpTaintedParams.has(keyName)) {
          st.taint(valueName, `mcp-param:${keyName}`);
        }
        // In MCP context, be more aggressive with destructured params
        else if (st.mcpContext.isMCPServer) {
          st.taint(valueName, `mcp-destructured:${keyName}`);
        }
      }
    }
  }

  /**
   * Handle destructuring in variable declarations
   * Handles complex patterns like: { name, arguments: args = {} } = params
   */
  handleDestructuredDeclarator(pattern, init, st, initTaint, isMCPInit) {
    if (pattern.type !== 'ObjectPattern') return;

    // If destructuring from a tainted source, taint all extracted values
    const sourceIsTainted = initTaint || isMCPInit;

    for (const prop of pattern.properties) {
      if (prop.type === 'Property') {
        const keyName = prop.key?.name;
        let valueName = keyName;

        // Handle renamed destructuring: { arguments: args }
        if (prop.value?.type === 'Identifier') {
          valueName = prop.value.name;
        }
        // Handle destructuring with default: { arguments: args = {} }
        else if (prop.value?.type === 'AssignmentPattern') {
          if (prop.value.left?.type === 'Identifier') {
            valueName = prop.value.left.name;
          }
        }

        // Mark as tainted based on context
        if (this.mcpCommandProps.has(keyName)) {
          st.taint(valueName, `mcp-arg:${keyName}`);
        } else if (this.mcpTaintedParams.has(keyName) || keyName === 'arguments') {
          // 'arguments' is commonly used in MCP for tool arguments
          st.taint(valueName, `mcp-param:${keyName}`);
        } else if (sourceIsTainted) {
          st.taint(valueName, initTaint?.origin || `mcp-destructured:${keyName}`);
        } else if (st.mcpContext.isMCPServer) {
          st.taint(valueName, `mcp-destructured:${keyName}`);
        }
      }
    }
  }

  /**
   * Check if node is accessing MCP arguments (args.command, params.query)
   */
  isMCPArgAccess(node) {
    if (node.type !== 'MemberExpression') return false;

    const objName = node.object?.name;
    const propName = node.property?.name;

    // args.command, args.query, etc.
    if (this.mcpTaintedParams.has(objName)) {
      return true;
    }

    // params.args.command (nested)
    if (node.object?.type === 'MemberExpression') {
      return this.isMCPArgAccess(node.object);
    }

    return false;
  }

  /**
   * Get origin description for MCP arg access
   */
  getMCPArgOrigin(node) {
    if (node.type !== 'MemberExpression') return null;

    const parts = [];
    let current = node;

    while (current.type === 'MemberExpression') {
      if (current.property?.name) {
        parts.unshift(current.property.name);
      }
      current = current.object;
    }

    if (current.type === 'Identifier') {
      parts.unshift(current.name);
    }

    return `mcp-arg:${parts.join('.')}`;
  }

  isProcessEnv(node) {
    if (node.type === 'MemberExpression') {
      // process.env.X
      if (node.object.type === 'MemberExpression' &&
        node.object.object?.name === 'process' &&
        node.object.property?.name === 'env') {
        return true;
      }
      // Direct process.env
      if (node.object?.name === 'process' && node.property?.name === 'env') {
        return true;
      }
    }
    return false;
  }

  getTaintOrigin(node, isTainted) {
    if (!node) return null;

    if (node.type === 'Identifier') {
      const origin = isTainted(node.name);
      if (origin) return { origin, source: node };
      return null;
    }

    if (node.type === 'Literal') return null;

    // Check MCP arg access
    if (this.isMCPArgAccess(node)) {
      return { origin: this.getMCPArgOrigin(node), source: node };
    }

    if (node.type === 'ConditionalExpression') {
      return this.getTaintOrigin(node.consequent, isTainted) || this.getTaintOrigin(node.alternate, isTainted);
    }

    if (node.type === 'BinaryExpression') {
      return this.getTaintOrigin(node.left, isTainted) || this.getTaintOrigin(node.right, isTainted);
    }

    // Handle params || {} pattern (LogicalExpression)
    if (node.type === 'LogicalExpression') {
      return this.getTaintOrigin(node.left, isTainted) || this.getTaintOrigin(node.right, isTainted);
    }

    if (node.type === 'TemplateLiteral') {
      for (const expr of node.expressions) {
        const result = this.getTaintOrigin(expr, isTainted);
        if (result) return result;
      }
    }

    if (node.type === 'ObjectExpression') {
      for (const prop of node.properties) {
        if (prop.type === 'Property') {
          const result = this.getTaintOrigin(prop.value, isTainted);
          if (result) return result;
        }
      }
    }

    if (node.type === 'ArrayExpression') {
      for (const el of node.elements) {
        if (el) {
          const result = this.getTaintOrigin(el, isTainted);
          if (result) return result;
        }
      }
    }

    if (node.type === 'MemberExpression') {
      // Check for tainted object access
      const objTaint = this.getTaintOrigin(node.object, isTainted);
      if (objTaint) return objTaint;
    }

    if (this.isProcessEnv(node)) return { origin: 'process.env', source: node };

    return null;
  }

  checkCallExpression(node, isTainted, filePath, findings, content, mcpContext, execAliases = new Set()) {
    let functionName = '';
    let isExecSink = false;

    if (node.callee.type === 'Identifier') {
      functionName = node.callee.name;
      isExecSink = this.execSinks.has(functionName) || execAliases.has(functionName);
    } else if (node.callee.type === 'MemberExpression') {
      const prop = node.callee.property?.name;
      const obj = node.callee.object?.name;
      functionName = obj ? `${obj}.${prop}` : prop;

      isExecSink = this.memberExecSinks.has(functionName) ||
        this.execSinks.has(prop) ||
        execAliases.has(prop) ||
        /^(exec|execSync|spawn|spawnSync|eval)$/.test(prop);
    }

    // Also check for promisified exec patterns
    if (node.callee.type === 'CallExpression') {
      // promisify(exec)(cmd) pattern
      if (node.callee.callee?.name === 'promisify' || functionName.includes('promisify')) {
        isExecSink = true;
        functionName = 'promisified-exec';
      }
    }

    if (isExecSink) {
      node.arguments.forEach((arg, index) => {
        const result = this.getTaintOrigin(arg, isTainted);
        if (result) {
          this.reportFinding(filePath, arg, functionName, result.origin, findings, mcpContext);
        }
      });
    }
  }

  /**
   * Check for dangerous patterns in exec options
   * Specifically: { env: process.env, shell: true }
   */
  checkExecOptions(node, filePath, findings, mcpContext) {
    let functionName = '';
    let isExecCall = false;

    if (node.callee.type === 'Identifier') {
      functionName = node.callee.name;
      isExecCall = this.execSinks.has(functionName);
    } else if (node.callee.type === 'MemberExpression') {
      const prop = node.callee.property?.name;
      functionName = prop;
      isExecCall = this.execSinks.has(prop) || this.memberExecSinks.has(`${node.callee.object?.name}.${prop}`);
    }

    if (!isExecCall) return;

    // Look for options object in arguments
    for (const arg of node.arguments) {
      if (arg.type === 'ObjectExpression') {
        let hasEnvProcessEnv = false;
        let hasShellTrue = false;
        let envNode = null;

        for (const prop of arg.properties) {
          if (prop.type !== 'Property') continue;

          const keyName = prop.key?.name;

          // Check for env: process.env
          if (keyName === 'env') {
            if (this.isProcessEnvDirect(prop.value)) {
              hasEnvProcessEnv = true;
              envNode = prop;
            }
          }

          // Check for shell: true
          if (keyName === 'shell' && prop.value?.value === true) {
            hasShellTrue = true;
          }
        }

        // Report if env: process.env is passed (environment pollution risk)
        if (hasEnvProcessEnv) {
          const severity = hasShellTrue ? 'error' : 'warning';
          const message = hasShellTrue
            ? `Dangerous execution: '${functionName}' with shell: true and env: process.env exposes all environment variables to shell execution`
            : `Environment pollution risk: '${functionName}' called with env: process.env passes all environment variables`;

          findings.push(this.createFinding(
            filePath,
            envNode?.loc?.start?.line || node.loc?.start?.line || 0,
            envNode?.loc?.start?.column || node.loc?.start?.column || 0,
            message,
            'command-exec-env',
            severity
          ));
        }
      }
    }
  }

  /**
   * Check if node is exactly process.env (not process.env.X)
   */
  isProcessEnvDirect(node) {
    return node.type === 'MemberExpression' &&
      node.object?.name === 'process' &&
      node.property?.name === 'env';
  }

  /**
   * Check if node is promisify(exec) or similar pattern
   */
  isPromisifiedExec(node) {
    if (node.type !== 'CallExpression') return false;

    // promisify(exec)
    if (node.callee?.name === 'promisify' ||
        (node.callee?.property?.name === 'promisify')) {
      const arg = node.arguments[0];
      if (arg?.type === 'Identifier' && this.execSinks.has(arg.name)) {
        return true;
      }
      // child_process.exec
      if (arg?.type === 'MemberExpression' && this.execSinks.has(arg.property?.name)) {
        return true;
      }
    }

    // util.promisify(exec)
    if (node.callee?.type === 'MemberExpression' &&
        node.callee.property?.name === 'promisify') {
      const arg = node.arguments[0];
      if (arg?.type === 'Identifier' && this.execSinks.has(arg.name)) {
        return true;
      }
    }

    return false;
  }

  reportFinding(filePath, node, functionName, origin, findings, mcpContext) {
    const location = node.loc ? { line: node.loc.start.line, column: node.loc.start.column } : { line: 0, column: 0 };

    let message = `Dangerous command execution detected in '${functionName}'. `;

    // Provide more descriptive message based on origin type
    if (origin.startsWith('mcp-arg:')) {
      const argPath = origin.replace('mcp-arg:', '');
      message += `MCP tool argument '${argPath}' flows into shell command. This allows prompt injection attacks.`;
    } else if (origin.startsWith('mcp-param:')) {
      const paramName = origin.replace('mcp-param:', '');
      message += `MCP handler parameter '${paramName}' flows into shell command. User input must be validated.`;
    } else if (origin.startsWith('mcp-destructured:')) {
      const prop = origin.replace('mcp-destructured:', '');
      message += `Destructured property '${prop}' from MCP request flows into shell command.`;
    } else {
      message += `Tainted input from '${origin}' flows into this command.`;
    }

    const severity = origin.startsWith('mcp-') ? 'error' : 'error';

    findings.push(this.createFinding(filePath, location.line, location.column, message, 'command-exec', severity));
  }

  shouldAnalyze(filePath) {
    const ext = path.extname(filePath);
    if (this.testPatterns.some(pattern => filePath.includes(pattern))) return false;
    return this.extensions.includes(ext);
  }
}

module.exports = CommandExecAnalyzer;
