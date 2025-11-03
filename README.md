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

### As a GitHub Action (Recommended)

Add to your workflow:

```yaml
name: Security Check

on: [push, pull_request]

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: fonCki/mcp-security-linter@master
        with:
          path: '.'
          fail-on-warnings: true
```

### Local Development

Clone the repository and install dependencies:

```bash
git clone https://github.com/fonCki/mcp-security-linter.git
cd mcp-security-linter
npm install
```

## Usage

### CLI

```bash
# From the project directory
node src/cli.js                           # Analyze current directory
node src/cli.js src/                      # Analyze specific path
node src/cli.js --format sarif --output results.sarif  # SARIF output
node src/cli.js --config .mcp-lint.json   # Use custom config
```

### Using in Other Projects

Until published to npm, you can use it via:

```bash
# Option 1: Use as GitHub Action (see above)

# Option 2: Clone and run locally
git clone https://github.com/fonCki/mcp-security-linter.git
cd mcp-security-linter
npm install
node src/cli.js /path/to/your/project
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
