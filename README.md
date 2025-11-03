# MCP Security Linter

Static analysis tool for Model Context Protocol (MCP) repository security vulnerabilities.

## Features

- Detects dangerous command execution patterns (Working in progress)
- Identifies token passthrough anti-patterns ( Working in progress)
- Finds unauthenticated non-stdio endpoints ( Working in progress)
- Checks OAuth implementation hygiene (Working in progress)
- Validates tool argument schemas (Working in progress)
- AI-generated content detection (demo analyzer) -- Only test that actually works

## Installation

```bash
npm install mcp-security-linter
```

## Usage

### CLI

```bash
# Analyze current directory
npx mcp-lint

# Analyze specific path
npx mcp-lint src/

# Output SARIF format
npx mcp-lint --format sarif --output results.sarif

# Use custom config
npx mcp-lint --config .mcp-lint.json
```

### GitHub Action

```yaml
name: Security Check

on: [push, pull_request]

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: alfonsoridao/mcp-security-linter@v1
        with:
          path: '.'
          fail-on-warnings: true
```

### Configuration

Create `.mcp-lint.json`:

```json
{
  "ai-detector": {
    "enabled": true,
    "severity": "warning"
  },
  "command-injection": {
    "enabled": false,
    "severity": "error"
  },
  "token-passthrough": {
    "enabled": false,
    "severity": "error"
  }
}
```

## Security Checks

### 1. AI-Generated Content Detection

- **Severity:** Warning
- **Description:** Detects AI-generated content in source code.

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
