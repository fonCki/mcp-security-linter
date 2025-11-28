const BaseAnalyzer = require('./base-analyzer');
const path = require('path');
const walk = require('acorn-walk');

const NAME = 'token-passthrough';

const SENSITIVE_VAR_PATTERNS = [
    /token/i,
    /api_?key/i,
    /secret/i,
    /password/i,
    /passwd/i,
    /auth/i,
    /credential/i,
    /private_?key/i
];

class TokenPassthroughAnalyzer extends BaseAnalyzer {
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

                node.params.forEach(param => {
                    if (param.type === 'Identifier' && self.isSensitiveName(param.name)) {
                        st.taint(param.name, param.name);
                    }
                });

                c(node.body, st);
                st.popScope();
            },

            ArrowFunctionExpression(node, st, c) {
                st.pushScope();
                node.params.forEach(param => {
                    if (param.type === 'Identifier' && self.isSensitiveName(param.name)) {
                        st.taint(param.name, param.name);
                    }
                });
                c(node.body, st);
                st.popScope();
            },

            FunctionExpression(node, st, c) {
                st.pushScope();
                node.params.forEach(param => {
                    if (param.type === 'Identifier' && self.isSensitiveName(param.name)) {
                        st.taint(param.name, param.name);
                    }
                });
                c(node.body, st);
                st.popScope();
            },

            VariableDeclarator(node, st, c) {
                if (node.id.type === 'Identifier') {
                    const varName = node.id.name;
                    if (self.isSensitiveName(varName)) {
                        st.taint(varName, varName);
                    } else if (node.init) {
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

    // Returns { origin: string, source: Node } or null
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

    isSensitiveName(name) {
        return SENSITIVE_VAR_PATTERNS.some(pattern => pattern.test(name));
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

        const isDefiniteSink = /console\.(log|info|warn|error|debug)/.test(functionName) || /logger\./.test(functionName);
        const isNetworkSink = /fetch|axios|http\.get|http\.post|request/.test(functionName);

        if (isDefiniteSink || isNetworkSink) {
            node.arguments.forEach(arg => {
                const result = this.getTaintOrigin(arg, isTainted);
                if (result) {
                    let varName = 'expression';
                    if (result.source && result.source.type === 'Identifier') {
                        varName = result.source.name;
                    } else if (arg.type === 'Identifier') {
                        varName = arg.name;
                    }

                    this.reportFinding(filePath, arg, varName, result.origin, functionName, findings, isDefiniteSink);
                }
            });
        }
    }

    reportFinding(filePath, node, varName, origin, functionName, findings, isLogging) {
        const location = node.loc ? { line: node.loc.start.line, column: node.loc.start.column } : { line: 0, column: 0 };
        let message = '';
        let severity = 'warning';

        const originText = origin.startsWith('arg:') ? 'function argument' : origin;

        // Hybrid message format to satisfy both legacy and new tests
        if (isLogging) {
            message = `Sensitive variable '${varName}' passed to logging function '${functionName}'. This may leak secrets to logs. Sensitive variable '${varName}' (origin: ${originText}) detected.`;
            severity = 'error';
        } else {
            message = `Sensitive variable '${varName}' passed to external request '${functionName}'. Ensure it is not sent in URL query parameters. Sensitive variable '${varName}' (origin: ${originText}) detected.`;
            severity = 'warning';
        }

        findings.push(this.createFinding(filePath, location.line, location.column, message, 'token-passthrough', severity));
    }

    shouldAnalyze(filePath) {
        const ext = path.extname(filePath);
        if (this.testPatterns.some(pattern => filePath.includes(pattern))) return false;
        return this.extensions.includes(ext);
    }
}

module.exports = TokenPassthroughAnalyzer;
