# MCP-SecLint (MCP Security Linter)

[![npm version](https://img.shields.io/npm/v/mcp-security-linter.svg)](https://www.npmjs.com/package/mcp-security-linter)
[![npm downloads](https://img.shields.io/npm/dm/mcp-security-linter.svg)](https://www.npmjs.com/package/mcp-security-linter)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

MCP-SecLint is a static analysis tool for detecting security vulnerabilities in Model Context Protocol (MCP) server implementations.

## Overview

MCP-SecLint detects security vulnerabilities in JavaScript and TypeScript MCP server implementations using static analysis techniques including taint tracking and middleware pattern matching. The detection rules target vulnerability patterns identified in MCP security research and the official [MCP Security Best Practices](https://modelcontextprotocol.io/specification/draft/basic/security_best_practices).

## Paper Reproducibility

The IWSPA 2026 paper evaluated MCP-SecLint version `v1.4.2`. To reproduce the exact artifact used for the paper's ecosystem scan, run:

```bash
npx mcp-security-linter@1.4.2 .
```

The full ecosystem-analysis table is in [docs/ecosystem-analysis-results.md](docs/ecosystem-analysis-results.md). Current `master` may include post-paper maintenance fixes, so use the tagged `v1.4.2` release when reproducing the paper results.

### Parser architecture

The paper (§4.3, Figure 2, Ref [20]) describes the JavaScript pipeline as built on the [Acorn](https://github.com/acornjs/acorn) parser, with a noted limitation in §7.3 that complex TypeScript files could fail AST parsing. From `v1.6.0` onward this is implemented as a hybrid that preserves the original JS pipeline:

- `.js`, `.cjs`, `.mjs` files are parsed with **Acorn**, matching the architecture documented in the paper.
- `.ts`, `.tsx`, `.mts`, `.cts`, and `.jsx` files are parsed with **`@typescript-eslint/typescript-estree`**, which closes the §7.3 limitation while leaving the JS path unchanged.

Both parsers emit ESTree-shaped ASTs traversed by a single shared walker.

## Features

### Currently Implemented

1.  **Dangerous Command Execution Detection**
    *   **Technique**: Recursive Taint Analysis
    *   **Detects**: Command injection via Node.js process APIs, `eval`, `new Function`, `vm.runInContext`, `execa`, and the `$` template tag from `zx`.
    *   **Capabilities**: Tracks untrusted input (`process.env`, MCP arguments, function args) through variable assignments, aliases, string concatenation, and template literals.
    *   **Safety**: Ignores safe hardcoded commands (e.g., `exec('ls -la')`).

2.  **Token Passthrough Detection**
    *   **Technique**: Iterative Taint Analysis (Fixpoint)
    *   **Detects**: Sensitive data (API keys, secrets) passed to logging functions or external network requests.
    *   **Capabilities**: Tracks secrets through complex data flows, including object/array wrapping and ternary operators.
    *   **Scope**: Respects variable scope and shadowing.

3.  **Unauthenticated Endpoints Detection**
    *   **Technique**: Middleware Stack Simulation
    *   **Detects**: API endpoints exposed without authentication middleware.
    *   **Capabilities**: Understands `app.use()` order, router mounting hierarchies, and route-specific middleware.

### Planned Analyzers

The following checks are planned for future releases:

4.  **OAuth Hygiene Checker**
    *   *Goal*: Ensure proper handling of OAuth tokens and scopes.
5.  **Argument Validation**
    *   *Goal*: Verify that all user inputs are validated before use.

---

## Installation

### From NPM (Recommended)

Install globally to use the CLI anywhere:

```bash
npm install -g mcp-security-linter
```

Or add to your project as a dev dependency:

```bash
npm install --save-dev mcp-security-linter
```

Then run:

```bash
mcp-lint .                              # Scan current directory
mcp-lint src/ --format json             # Scan src/ with JSON output
mcp-lint --config custom-config.json    # Use custom config
```

### As a GitHub Action

#### Step 1: Create the workflow directory

In your repository, create the directory structure (if it doesn't exist):

```bash
mkdir -p .github/workflows
```

#### Step 2: Create a workflow file

Create a new file `.github/workflows/mcp-security.yml` (you can name it anything ending in `.yml`):

```yaml
name: MCP-SecLint Security Check

on: [push, pull_request]

jobs:
  security-lint:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write   # required to upload SARIF to GitHub Code Scanning
    steps:
      - uses: actions/checkout@v4
      - uses: fonCki/mcp-security-linter@v1.6.0
        id: lint
        with:
          path: '.'
          fail-on-warnings: true
      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ${{ steps.lint.outputs.sarif-file }}
          category: mcp-security
```

> **Note**: SARIF upload to GitHub Code Scanning requires either a public repository or GitHub Advanced Security enabled on private repos. Without it, the action still runs and reports findings as workflow annotations, but the SARIF upload step will fail.

#### Step 3: Commit and push

```bash
git add .github/workflows/mcp-security.yml
git commit -m "Add MCP-SecLint security workflow"
git push
```

The action will now run automatically on every push and pull request!

### For Contributors

If you want to contribute to development:

```bash
git clone https://github.com/fonCki/mcp-security-linter.git
cd mcp-security-linter
npm install
```

Requires Node.js 20.19.0 or newer.

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.

## Usage

### CLI

```bash
# From the project directory
node src/cli.js                           # Analyze current directory
node src/cli.js src/                      # Analyze specific path
node src/cli.js --format sarif --output results.sarif  # SARIF output
node src/cli.js --config .mcp-lint.json   # Use custom config
```

The CLI exits with status code `1` when findings are present, regardless of output format.

### Configuration

**v1.1.0+** introduces advanced configuration options. See **[CONFIGURATION.md](CONFIGURATION.md)** for the complete guide.

Create `.mcp-lint.json` (optional):

```json
{
  "command-exec": {
    "enabled": true,
    "severity": "error"
  },
  "token-passthrough": {
    "enabled": true,
    "severity": "warning"
  }
}
```

**Advanced Configuration (v1.1.0+):**
- Custom JavaScript/TypeScript file extensions
- Custom test patterns
- Custom exclude patterns
- Analyzer-specific overrides

See **[CONFIGURATION.md](CONFIGURATION.md)** for examples and detailed documentation.

## Development

```bash
# Install dependencies
npm install

# Run tests
npm test

# Run tests with coverage
npm run test:coverage
```

## Team

This project is developed as part of DTU Course 02234 - Research Topics in Cybersecurity.

For detailed team information, contributions, and contact details, see [TEAM.md](TEAM.md).

**Team Members:**
- Melissa Safari (s224818) — DTU Compute
- Zachary Kang (e1122217) — National University of Singapore
- Alfonso Pedro Ridao (s243942) — DTU Compute
- Nicola Dragoni — DTU Compute (advisor)

## License

MIT - See [LICENSE](LICENSE) file for details
