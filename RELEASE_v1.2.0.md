# Release v1.2.0 - Command Execution Security Analyzer

⚠️ **Current Status**

This version includes **2 of 5** planned security analyzers:
- ✅ AI-generated content detection
- ✅ **Dangerous command execution detection** (NEW)
- ⏳ Token passthrough (planned)
- ⏳ Unauthenticated endpoints (planned)
- ⏳ OAuth hygiene (planned)

---

## What's New in v1.2.0

### Command Execution Analyzer
Detects dangerous command patterns in your MCP server code:

- **Destructive operations**: `rm -rf /`, `dd if=/dev/zero`, filesystem wipes
- **Network exfiltration**: `curl | bash`, `wget | python`, data theft patterns
- **Reverse shells**: netcat backdoors, `/dev/tcp` connections
- **Credential theft**: access to `/etc/shadow`, SSH keys, AWS credentials
- **Encoded payloads**: PowerShell `-encodedcommand`, base64 obfuscation
- **Dynamic execution**: `eval()`, `new Function()`, unsafe code patterns

Supports multiple languages:
- JavaScript/TypeScript (exec, spawn, eval)
- Python (subprocess, os.system)
- Shell scripts (.sh, .bash, .zsh)
- JSON config files (.mcp-config.json, package.json)

### Better CLI Output
- Color-coded terminal output (errors in red, warnings in yellow)
- Summary footer with error/warning counts
- Cleaner formatting with icons (✖, ⚠, ✓)

---

## Installation

```bash
npm install -g mcp-security-linter
```

---

## Usage

```bash
# Scan current directory
mcp-lint .

# Generate SARIF for GitHub
mcp-lint . --format sarif --output results.sarif

# JSON output for automation
mcp-lint . --format json --output results.json
```

---

## Testing

We created a test repository with intentionally vulnerable code to validate the analyzer. It successfully detects 20+ security issues across different attack vectors.

---

## What's Next

Working on the remaining 3 analyzers:
- Token passthrough detection (prevent credential leaks)
- Unauthenticated endpoint scanner
- OAuth security checks

---

## Team

- Melissa Safari (s224818@dtu.dk)
- Zachary Kang (s251598@dtu.dk)
- Alfonso Pedro Ridao (s243942@dtu.dk)

Part of DTU Course 02234 - Research Topics in Cybersecurity
