# Analysis Report: mcp-security-linter

## 1. Dangerous Command Implementation
The "dangerous command" detection is **properly implemented** in `src/analyzers/command-exec.js`.
- **Mechanism**: It uses a hybrid approach:
    - **AST Analysis**: For JavaScript/TypeScript files, it parses the code to find calls to `exec`, `spawn`, `eval`, etc. It checks arguments for dangerous patterns.
    - **Regex Fallback**: For other files (or if AST fails), it uses regex patterns to find dangerous commands.
    - **Shell Script Support**: It specifically parses `.sh`, `.bash`, `.zsh` files line-by-line.
- **Coverage**: It covers Node.js `child_process`, Python `subprocess`, and generic shell commands.
- **Patterns**: It includes a comprehensive list of dangerous patterns (e.g., `rm -rf`, `nc -e`, `chmod 777`).

## 2. Feasibility of Requested Features

### Execution
- **Status**: **Implemented** (`command-exec.js`).
- **Feasibility**: High. The current implementation is solid and can be easily extended with more patterns or language support.

### Token Passthrough
- **Status**: Not implemented (placeholder in `defaults.json`).
- **Feasibility**: **High**.
- **Implementation Strategy**:
    - Create a new analyzer `src/analyzers/token-passthrough.js`.
    - Use AST to identify sensitive variables (e.g., `process.env.API_KEY`, variables named `password`, `token`).
    - Track usage of these variables to see if they are passed to:
        - Logging functions (`console.log`, `logger.info`).
        - External processes (`exec`, `spawn`).
        - URL construction (query parameters).

### Unauthenticated Endpoints
- **Status**: Not implemented (placeholder in `defaults.json`).
- **Feasibility**: **Medium**.
- **Implementation Strategy**:
    - Create `src/analyzers/unauthenticated-endpoints.js`.
    - Focus on common frameworks like Express.js.
    - AST Analysis:
        - Identify route definitions (`app.get`, `router.post`).
        - Check for the presence of authentication middleware in the middleware chain.
        - Flag routes that do not have a known auth middleware.

### OAuth Weaknesses
- **Status**: Not implemented (placeholder in `defaults.json`).
- **Feasibility**: **Medium/Hard**.
- **Implementation Strategy**:
    - Create `src/analyzers/oauth-hygiene.js`.
    - Detect usage of OAuth libraries (e.g., `passport`, `simple-oauth2`).
    - Check for:
        - Hardcoded `client_secret`.
        - Missing `state` parameter in authorization URLs (CSRF protection).
        - Weak `scope` configurations.
        - Insecure `redirect_uri` (e.g., HTTP instead of HTTPS).

### Missing Argument Validation
- **Status**: Not implemented (placeholder in `defaults.json`).
- **Feasibility**: **Medium**.
- **Implementation Strategy**:
    - Create `src/analyzers/argument-validation.js`.
    - Focus on exported functions or API handlers.
    - AST Analysis:
        - Identify function arguments.
        - Check if arguments are used in "dangerous" sinks (e.g., database queries, file system access) without prior validation checks (e.g., `if (!arg) return`, `typeof arg`, or schema validation like `zod`/`joi`).

## Summary
The codebase provides a solid foundation with `BaseAnalyzer` and AST parsing capabilities. Implementing the requested features is feasible by creating new analyzers that leverage the existing infrastructure.
