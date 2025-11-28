# Security Analysis Implementation Report

## Overview
This document details the evolution, functionality, and verification of the three core security analyzers implemented in the `mcp-security-linter`. The goal was to transition from simple, regex-based heuristics to robust, control-flow-aware static analysis.

---

## 1. Token Passthrough Analyzer
**Goal**: Detect sensitive data (tokens, keys, secrets) being passed to dangerous sinks (logging, external network requests).

### Improvements from Naive Implementation
| Feature | Naive Approach | Advanced Implementation |
| :--- | :--- | :--- |
| **Detection Logic** | Regex matching on variable names in function calls (e.g., `log(password)`). | **Iterative Taint Analysis**: Tracks data flow from source to sink. |
| **Data Flow** | None. Only checked immediate usage. | **Recursive Propagation**: Tracks variables through assignments (`a = secret; b = a; log(b)`). |
| **Scope** | Ignored scope (false positives if variable names reused). | **Scope-Aware**: Respects variable shadowing and block scopes. |
| **Complex Structures** | Failed on objects/arrays. | **Deep Inspection**: Recursively checks `Object` and `Array` expressions (e.g., `json({ key: secret })`). |
| **Origin Tracking** | Unknown. | **Precise Origins**: Reports exactly where the data came from (e.g., `process.env.API_KEY`). |

### Scenarios & Tests
- **Variable Reassignment**: `const a = secret; const b = a; log(b)`
- **Ternary Operators**: `const key = isProd ? prodKey : devKey; log(key)`
- **Function Arguments**: `function log(val) { console.log(val) } log(secret)` (Intra-file)
- **Object/Array Wrappers**: `axios.post(url, { headers: { auth: key } })`
- **Source Detection**: `process.env`, variables matching sensitive patterns (`api_key`, `secret`, `token`).

---

## 2. Unauthenticated Endpoints Analyzer
**Goal**: Identify API endpoints that are exposed without authentication middleware.

### Improvements from Naive Implementation
| Feature | Naive Approach | Advanced Implementation |
| :--- | :--- | :--- |
| **Middleware Detection** | Checked if "auth" string existed in file. | **Stack Tracking**: Simulates the middleware stack at the exact line a route is defined. |
| **Order Sensitivity** | Ignored order. | **Order-Aware**: Knows that `app.get(public); app.use(auth); app.get(private)` protects only the second route. |
| **Router Mounting** | Failed on nested routers. | **Hierarchy Resolution**: Resolves middleware inherited from parent apps (`app.use('/api', protectedRouter)`). |
| **Granularity** | File-level heuristic. | **Route-level Precision**: Analyzes each route individually against its effective middleware stack. |

### Scenarios & Tests
- **Global Middleware**: `app.use(auth)` applied to subsequent routes.
- **Router-Level Middleware**: `router.use(auth)`.
- **Route-Specific Middleware**: `app.get('/path', auth, handler)`.
- **Nested Routers**: `app.use('/api', auth); app.use('/v1', apiRouter)`.
- **Public Routes**: Correctly ignores routes defined *before* auth middleware.

---

## 3. Command Execution Analyzer
**Goal**: Prevent Command Injection vulnerabilities where untrusted input flows into system commands.

### Improvements from Naive Implementation
| Feature | Naive Approach | Advanced Implementation |
| :--- | :--- | :--- |
| **Detection Logic** | Regex for `exec(` or `eval(`. | **Taint Analysis**: Only flags sinks if they receive **tainted input**. |
| **False Positives** | Flagged safe, hardcoded commands (`exec('ls')`). | **Safe by Default**: Ignores string literals. Only flags variables traced to untrusted sources. |
| **Input Sources** | None. | **Source Tracking**: `process.env`, function arguments, and explicit tainted variables. |
| **Sinks** | Limited to `exec`. | **Comprehensive Sinks**: `exec`, `execSync`, `spawn`, `spawnSync`, `eval`, `vm.runInContext`. |

### Scenarios & Tests
- **Indirect Execution**: `const cmd = input; exec(cmd)`
- **Concatenation**: `exec('ls ' + input)`
- **Template Literals**: `exec(\`ls \${input}\`)`
- **Helper Functions**: `runCommand(input)`
- **Safe Usage**: `exec('ls -la')` (Ignored)

---

## Evolution of the Implementation
The development followed a strict **Test-Driven Development (TDD)** cycle:
1.  **Contract Definition**: We wrote "tough" advanced tests first, defining the expected behavior for complex scenarios (reassignment, scope, order).
2.  **Failure**: We confirmed these tests failed against the naive implementations or empty stubs.
3.  **Refactoring**: We rewrote the analyzers using AST traversal (acorn-walk) and custom state management (taint maps, middleware stacks).
4.  **Refinement**: We iterated on the code to handle edge cases discovered during testing (e.g., `ObjectExpression` handling, hybrid message formatting).
5.  **Verification**: We ran full regression suites to ensure no existing functionality was broken.

---

## Assessment: Is it "Complete"?

While the current implementation is a significant leap forward and covers the vast majority of **local** vulnerabilities, it is **not** a "fully complete" static analysis solution in the academic sense.

### Strengths (What it does well)
- **Robust Local Analysis**: Within a single file, it is extremely powerful. It understands control flow, variable scope, and data propagation.
- **Low False Positives**: By using taint analysis instead of regex, it avoids flagging safe code (like hardcoded commands), which is the #1 complaint with security linters.
- **Context Awareness**: It understands specific framework patterns (Express.js middleware order).

### Limitations (Where it is still "naive")
1.  **Inter-file Analysis**: The analyzers process one file at a time. If a tainted variable is imported from another file (`import { secret } from './config'`), the analyzer doesn't know it's tainted unless we explicitly model it.
    *   *Improvement*: Requires a project-wide symbol table and dependency graph.
2.  **Dynamic Property Access**: Code like `obj['ex' + 'ec'](input)` would likely bypass detection. Static analysis struggles with dynamic metaprogramming.
3.  **Complex Control Flow**: While it handles basic branching, it doesn't perform full symbolic execution. It assumes all branches *could* be taken.
4.  **Framework Magic**: It models Express.js patterns explicitly. If a user uses a different framework (Fastify, Koa) or a custom router wrapper, the `UnauthenticatedEndpoints` analyzer won't understand the middleware stack.

### Verdict
**It is a "Commercial-Grade" Linter Implementation.**
It exceeds the capabilities of simple regex tools (like early versions of `eslint-plugin-security`) and matches the logic found in dedicated SAST (Static Application Security Testing) tools for **single-file analysis**. To go further would require building a full compiler-level analysis engine (like CodeQL), which is outside the scope of a linter.
