# MCP-SecLint (MCP Security Linter)

[![npm version](https://img.shields.io/npm/v/mcp-security-linter.svg)](https://www.npmjs.com/package/mcp-security-linter)
[![npm downloads](https://img.shields.io/npm/dm/mcp-security-linter.svg)](https://www.npmjs.com/package/mcp-security-linter)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

MCP-SecLint is a static analysis tool for detecting security vulnerabilities in Model Context Protocol (MCP) server implementations.

## Overview

MCP-SecLint detects security vulnerabilities in MCP server implementations using static analysis techniques including taint tracking, control flow analysis, and middleware pattern matching. The detection rules target vulnerability patterns identified in MCP security research and the official [MCP Security Best Practices](https://modelcontextprotocol.io/specification/draft/basic/security_best_practices).

## Features

### Currently Implemented (Advanced Analysis)

1.  **Dangerous Command Execution Detection** ✅
    *   **Technique**: Recursive Taint Analysis
    *   **Detects**: Command injection via `exec`, `spawn`, `eval`, `vm.runInContext`.
    *   **Capabilities**: Tracks untrusted input (`process.env`, function args) through variable assignments, string concatenation, and template literals.
    *   **Safety**: Ignores safe hardcoded commands (e.g., `exec('ls -la')`).

2.  **Token Passthrough Detection** ✅
    *   **Technique**: Iterative Taint Analysis (Fixpoint)
    *   **Detects**: Sensitive data (API keys, secrets) passed to logging functions or external network requests.
    *   **Capabilities**: Tracks secrets through complex data flows, including object/array wrapping and ternary operators.
    *   **Scope**: Respects variable scope and shadowing.

3.  **Unauthenticated Endpoints Detection** ✅
    *   **Technique**: Middleware Stack Simulation
    *   **Detects**: API endpoints exposed without authentication middleware.
    *   **Capabilities**: Understands `app.use()` order, router mounting hierarchies, and route-specific middleware.

### Planned Analyzers

The following checks are planned for future releases:

4.  **OAuth Hygiene Checker** ❌
    *   *Goal*: Ensure proper handling of OAuth tokens and scopes.
5.  **Argument Validation** ❌
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
    steps:
      - uses: actions/checkout@v3
      - uses: fonCki/mcp-security-linter@master
        with:
          path: '.'
          fail-on-warnings: true
```

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
- 📁 Custom file extensions (scan any language)
- 🧪 Custom test patterns (skip test files)
- 🚫 Custom exclude patterns (ignore directories)
- ⚙️ Analyzer-specific overrides

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
- Melissa Safari (s224818)
- Zachary Kang (s251598)
- Alfonso Pedro Ridao (s243942)

## License

MIT - See [LICENSE](LICENSE) file for details
