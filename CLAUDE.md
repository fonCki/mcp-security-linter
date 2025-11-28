# CLAUDE.md - MCP Security Linter (Code Repository)

## Package Info

- **NPM:** `mcp-security-linter` v1.1.0
- **CLI:** `mcp-lint`
- **GitHub:** https://github.com/fonCki/mcp-security-linter
- **License:** MIT

---

## Architecture

```
mcp-security-linter/
├── src/
│   ├── index.js           # Config merging, analyzer auto-discovery
│   ├── cli.js             # Command-line interface
│   ├── action.js          # GitHub Action entry point
│   ├── analyzers/         # Security analyzers (auto-discovered)
│   │   ├── base-analyzer.js   # Base class with AST parsing (Acorn)
│   │   ├── command-exec.js    # IMPLEMENTED - Dangerous command detection
│   │   ├── ai-detector.js     # AI content detection
│   │   └── (future analyzers)
│   └── formatters/        # Output formatters
│       ├── sarif.js       # SARIF format for GitHub Security
│       └── json.js        # JSON format
├── defaults.json          # Default configuration
├── tests/                 # Jest tests
└── package.json           # Version single-source-of-truth
```

---

## Implementation Status

### Analyzer 1: Dangerous Command Execution (DONE)

**File:** `src/analyzers/command-exec.js`

**Detection Method:** Hybrid AST + Regex
- AST parsing with **Acorn** for JavaScript/TypeScript
- Regex patterns for sink identification and dangerous payloads
- Fallback to regex-only when AST parsing fails
- Direct regex for shell scripts (.sh, .bash, .zsh)

**Execution Sinks (17 patterns):**
- Node.js: `exec`, `execSync`, `spawn`, `spawnSync`, `execFile`, `execFileSync`, `fork`
- Python: `subprocess.call`, `subprocess.run`, `subprocess.Popen`, `os.system`, `os.popen`
- Dynamic: `eval`, `new Function`, `vm.runInNewContext`, `vm.runInThisContext`

**Dangerous Patterns (36 patterns in 6 categories):**
1. Destructive: `rm -rf /`, `rm -rf ~`, `dd if=...of=/dev/`, `mkfs`
2. Network exfiltration: `curl | bash`, `wget | sh`
3. Reverse shells: `nc -e`, `/dev/tcp/`
4. Encoded commands: PowerShell `-encodedCommand`, base64 decode
5. Credential access: `/etc/shadow`, `$AWS_SECRET_ACCESS_KEY`
6. Suspicious: `chmod 777`, output suppression

### Analyzers 2-5: PLACEHOLDER

Teammates (Melissa, Zachary) implementing:
- Token Passthrough Detection
- Unauthenticated Endpoint Detection
- OAuth Hygiene Checker
- Argument Validation Checker

---

## Coding Rules

### Adding New Analyzers

1. Create `src/analyzers/your-analyzer.js`
2. Extend `BaseAnalyzer` class
3. Implement `analyze(filePath, content)` method
4. Return array of findings with `ruleId`, `level`, `message`, `location`
5. Analyzers are auto-discovered from `src/analyzers/` directory

### Testing

```bash
npm test              # Run all tests
npm run test:watch    # Watch mode
npm run test:coverage # Coverage report
```

### Configuration

Users can create `.mcp-lint.json`:
```json
{
  "command-exec": {
    "enabled": true,
    "severity": "error"
  },
  "fileExtensions": [".js", ".ts", ".py"],
  "testFilePatterns": [".test.", ".spec."]
}
```

---

## Git Rules for This Repo

- This is a **submodule** of the ROOT repo
- Commits here are tracked as pointer updates in ROOT
- Do NOT commit session summaries here
- Push to GitHub after testing passes

---

## Key Technical Decisions

1. **Version source-of-truth:** `package.json` only
2. **Analyzer discovery:** Auto-load from `src/analyzers/*.js`
3. **Config merging:** `defaults.json` + user config + CLI args
4. **Output formats:** SARIF (GitHub Security), JSON (programmatic)
5. **Hybrid detection:** AST for structure, regex for patterns
