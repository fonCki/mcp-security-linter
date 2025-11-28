const BaseAnalyzer = require('./base-analyzer');
const path = require('path');
const walk = require('acorn-walk');

const NAME = 'command-exec';

class CommandExecAnalyzer extends BaseAnalyzer {
  constructor(options = {}) {
    super(NAME, options);

    const globalConfig = options.globalConfig || {};
    this.extensions = options.fileExtensions || globalConfig.fileExtensions || ['.js', '.ts', '.jsx', '.tsx'];
    this.testPatterns = options.testFilePatterns || globalConfig.testFilePatterns || ['.test.', '.spec.', '__tests__'];
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

      while (changed && iterations < MAX_ITERATIONS) {
        changed = false;
        iterations++;
        findings = [];

        const result = this.analyzePass(ast, filePath, content, functionTaints);
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

  analyzePass(ast, filePath, content, existingFunctionTaints) {
    const self = this;
    const findings = [];
    const newFunctionTaints = new Map();

    const state = {
      scopeStack: [new Map()],

      getCurrentScope() {
        return this.scopeStack[this.scopeStack.length - 1];
      },

      isTainted(name) {
        for (let i = this.scopeStack.length - 1; i >= 0; i--) {
          if (this.scopeStack[i].has(name)) {
            return this.scopeStack[i].get(name);
          }
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
        const funcName = node.id.name;

        if (existingFunctionTaints.has(funcName)) {
          const taintedParams = existingFunctionTaints.get(funcName);
          node.params.forEach((param, index) => {
            if (taintedParams.has(index) && param.type === 'Identifier') {
              st.taint(param.name, taintedParams.get(index));
            }
          });
        }

        c(node.body, st);
        st.popScope();
      },

      ArrowFunctionExpression(node, st, c) {
        st.pushScope();
        c(node.body, st);
        st.popScope();
      },

      FunctionExpression(node, st, c) {
        st.pushScope();
        c(node.body, st);
        st.popScope();
      },

      VariableDeclarator(node, st, c) {
        if (node.id.type === 'Identifier') {
          const varName = node.id.name;
          if (node.init) {
            if (self.isProcessEnv(node.init)) {
              st.taint(varName, 'process.env');
            } else {
              const result = self.getTaintOrigin(node.init, st.isTainted.bind(st));
              if (result) st.taint(varName, result.origin);
            }
          }
        }
        if (node.init) c(node.init, st);
      },

      AssignmentExpression(node, st, c) {
        if (node.left.type === 'Identifier') {
          const varName = node.left.name;
          if (self.isProcessEnv(node.right)) {
            st.taint(varName, 'process.env');
          } else {
            const result = self.getTaintOrigin(node.right, st.isTainted.bind(st));
            if (result) st.taint(varName, result.origin);
          }
        }
        c(node.right, st);
      },

      CallExpression(node, st, c) {
        self.checkCallExpression(node, st.isTainted.bind(st), filePath, findings, content);

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

  isProcessEnv(node) {
    if (node.type === 'MemberExpression') {
      if (node.object.type === 'MemberExpression' &&
        node.object.object.name === 'process' &&
        node.object.property.name === 'env') {
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

    if (node.type === 'ConditionalExpression') {
      return this.getTaintOrigin(node.consequent, isTainted) || this.getTaintOrigin(node.alternate, isTainted);
    }

    if (node.type === 'BinaryExpression') {
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

    if (this.isProcessEnv(node)) return { origin: 'process.env', source: node };

    return null;
  }

  checkCallExpression(node, isTainted, filePath, findings, content) {
    let functionName = '';
    if (node.callee.type === 'Identifier') {
      functionName = node.callee.name;
    } else if (node.callee.type === 'MemberExpression') {
      const prop = node.callee.property.name;
      const obj = node.callee.object.name;
      functionName = obj ? `${obj}.${prop}` : prop;
    }

    const isDangerous = /^(exec|execSync|spawn|spawnSync|eval)$/.test(functionName) ||
      /^(child_process|cp)\.(exec|execSync|spawn|spawnSync)$/.test(functionName) ||
      /^(vm)\.(runInContext|runInNewContext|runInThisContext)$/.test(functionName);

    if (isDangerous) {
      node.arguments.forEach((arg, index) => {
        // Only check first argument for exec/eval, or first/second for others?
        // For exec(cmd), it's arg 0.
        // For spawn(cmd, args), it's arg 0 and 1.
        // Let's check all args for taint to be safe/aggressive.

        const result = this.getTaintOrigin(arg, isTainted);
        if (result) {
          this.reportFinding(filePath, arg, functionName, result.origin, findings);
        }
      });
    }
  }

  reportFinding(filePath, node, functionName, origin, findings) {
    const location = node.loc ? { line: node.loc.start.line, column: node.loc.start.column } : { line: 0, column: 0 };
    const message = `Dangerous command execution detected in '${functionName}'. Tainted input from '${origin}' flows into this command.`;

    findings.push(this.createFinding(filePath, location.line, location.column, message, 'command-exec', 'error'));
  }

  shouldAnalyze(filePath) {
    const ext = path.extname(filePath);
    if (this.testPatterns.some(pattern => filePath.includes(pattern))) return false;
    return this.extensions.includes(ext);
  }
}

module.exports = CommandExecAnalyzer;
