const BaseAnalyzer = require('./base-analyzer');
const path = require('path');

const NAME = 'unauthenticated-endpoints';

const AUTH_MIDDLEWARE_PATTERNS = [
    /auth/i,
    /passport/i,
    /jwt/i,
    /bearer/i,
    /token/i,
    /session/i,
    /protect/i,
    /guard/i,
    /verify/i,
    /login/i,
    /signin/i,
    /admin/i
];

class UnauthenticatedEndpointsAnalyzer extends BaseAnalyzer {
    constructor(options = {}) {
        super(NAME, options);

        const globalConfig = options.globalConfig || {};
        this.extensions = options.fileExtensions || globalConfig.fileExtensions || ['.js', '.cjs', '.mjs', '.ts', '.tsx', '.mts', '.cts', '.jsx'];
        this.testPatterns = options.testFilePatterns || globalConfig.testFilePatterns || ['.test.', '.spec.', '__tests__'];

        this.authPatterns = options.customAuthPatterns ?
            [...AUTH_MIDDLEWARE_PATTERNS, ...options.customAuthPatterns] :
            AUTH_MIDDLEWARE_PATTERNS;
    }

    analyze(filePath, content) {
        if (!this.shouldAnalyze(filePath)) {
            return [];
        }

        const ast = this.parseAST(content, filePath);
        if (!ast) {
            return [];
        }

        try {
            return this.analyzeAST(ast, filePath, content);
        } catch (err) {
            console.warn(`AST analysis failed for ${filePath}:`, err.message);
            return [];
        }
    }

    analyzeAST(ast, filePath, content) {
        const self = this;

        const routes = []; // { objName, method, path, localMiddleware, stackSnapshot, location }
        const mounts = []; // { parent, child, stackSnapshot }

        // Map<objName, Array<middleware>> - Current active stack during walk
        const activeStacks = new Map();
        const authGroups = new Set();

        function addToStack(objName, middleware) {
            if (!activeStacks.has(objName)) {
                activeStacks.set(objName, []);
            }
            activeStacks.get(objName).push(middleware);
        }

        function getSnapshot(objName) {
            return [...(activeStacks.get(objName) || [])];
        }

        this.walkAST(ast, {
            CallExpression(node) {
                if (node.callee.type === 'MemberExpression' && node.callee.property.name === 'use') {
                    const objName = node.callee.object.name;
                    if (objName) {
                        // Check all arguments
                        node.arguments.forEach(arg => {
                            if (arg.type === 'Identifier') {
                                if (self.isAuthMiddleware(arg.name, authGroups)) {
                                    addToStack(objName, arg.name);
                                } else {
                                    // Potential router mount
                                    // Record mount with current snapshot of parent stack
                                    mounts.push({
                                        parent: objName,
                                        child: arg.name,
                                        stackSnapshot: getSnapshot(objName)
                                    });
                                }
                            } else {
                                // CallExpression / ArrayExpression / SpreadElement etc.
                                // Reuse collectMiddlewareNames so middleware applied
                                // through member-expression callees (e.g.
                                // passport.authenticate('jwt')) is recognized.
                                const candidateNames = self.collectMiddlewareNames(arg);
                                const authName = candidateNames.find(name => self.isAuthMiddleware(name, authGroups));
                                if (authName) {
                                    addToStack(objName, authName);
                                }
                            }
                        });
                    }
                }

                self.collectRoute(node, routes, getSnapshot);
            },

            VariableDeclarator(node) {
                if (node.id.type === 'Identifier' && node.init && node.init.type === 'ArrayExpression') {
                    const hasAuth = self.collectMiddlewareNames(node.init).some(name => self.isAuthMiddleware(name));
                    if (hasAuth) authGroups.add(node.id.name);
                }
            }
        });

        const findings = [];

        routes.forEach(route => {
            // 1. Check local middleware
            const hasLocalAuth = route.localMiddleware.some(m => this.isAuthMiddleware(m, authGroups));
            if (hasLocalAuth) return;

            // 2. Check object stack snapshot (at time of definition)
            const hasObjAuth = route.stackSnapshot.some(m => this.isAuthMiddleware(m, authGroups));
            if (hasObjAuth) return;

            // 3. Check hierarchy (Parent stacks at time of mount)
            let protectedByParent = false;

            // Find all parents
            const parents = mounts.filter(m => m.child === route.objName);
            for (const mount of parents) {
                if (mount.stackSnapshot.some(m => this.isAuthMiddleware(m, authGroups))) {
                    protectedByParent = true;
                    break;
                }
            }

            if (protectedByParent) return;

            const pathValue = route.path || 'dynamic-path';
            if (pathValue === '/' || pathValue === '/health' || pathValue === '/login' || pathValue === '/register') {
                return;
            }

            findings.push(this.createFinding(
                filePath,
                route.location.line,
                route.location.column,
                `Potential unauthenticated endpoint detected: ${route.method.toUpperCase()} ${pathValue}. No obvious authentication middleware found.`,
                'unauthenticated-endpoint',
                'warning'
            ));
        });

        return findings;
    }

    collectRoute(node, routes, getSnapshot) {
        if (node.callee.type !== 'MemberExpression') return;

        const method = node.callee.property.name;
        const methods = ['get', 'post', 'put', 'delete', 'patch', 'all'];

        if (!methods.includes(method)) return;
        if (node.arguments.length < 2) return;

        const firstArg = node.arguments[0];
        if (firstArg.type !== 'Literal' && firstArg.type !== 'TemplateLiteral') return;
        if (firstArg.type === 'Literal' && typeof firstArg.value !== 'string') return;

        const objName = node.callee.object.name;
        const pathValue = firstArg.value;

        const middlewareArgs = node.arguments.slice(1);
        const localMiddleware = [];

        for (const arg of middlewareArgs) {
            localMiddleware.push(...this.collectMiddlewareNames(arg));
        }

        routes.push({
            objName,
            method,
            path: pathValue,
            localMiddleware,
            stackSnapshot: getSnapshot(objName), // Capture current stack
            location: node.loc ? { line: node.loc.start.line, column: node.loc.start.column } : { line: 0, column: 0 }
        });
    }

    isAuthMiddleware(name, authGroups) {
        if (authGroups && authGroups.has(name)) return true;
        return this.authPatterns.some(pattern => pattern.test(name));
    }

    collectMiddlewareNames(node) {
        if (!node) return [];

        if (node.type === 'Identifier') {
            return [node.name];
        }

        if (node.type === 'CallExpression') {
            if (node.callee.type === 'Identifier') return [node.callee.name];
            if (node.callee.type === 'MemberExpression') return [this.getPropertyName(node.callee.property)].filter(Boolean);
        }

        if (node.type === 'ArrayExpression') {
            return node.elements.flatMap(element => this.collectMiddlewareNames(element));
        }

        if (node.type === 'SpreadElement') {
            return this.collectMiddlewareNames(node.argument);
        }

        return [];
    }

    getPropertyName(node) {
        if (!node) return null;
        if (node.type === 'Identifier') return node.name;
        if (node.type === 'Literal') return node.value;
        return null;
    }

    shouldAnalyze(filePath) {
        const ext = path.extname(filePath);
        if (this.testPatterns.some(pattern => filePath.includes(pattern))) return false;
        return this.extensions.includes(ext);
    }
}

module.exports = UnauthenticatedEndpointsAnalyzer;
