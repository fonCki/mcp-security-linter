# MCP Security Linter Configuration Guide

## Overview

The MCP Security Linter uses a flexible configuration system that allows you to customize:
- Which file types to scan
- Which patterns indicate test files (to skip)
- Which directories to exclude
- Analyzer-specific settings

## Configuration Files

### 1. `defaults.json` (Built-in)

This file contains the default configuration used when no user config is provided. It is located at the root of the project and is automatically loaded.

**You should NOT modify this file.** Instead, create a custom config file to override specific settings.

### 2. `.mcp-lint.json` (User Config)

Create this file in your project root to customize the linter behavior. Only specify the settings you want to override - all other settings will use defaults.

### 3. Custom Config Files

You can specify a custom config file path using:
- CLI: `node src/cli.js --config custom-config.json`
- GitHub Action: `config: custom-config.json` in workflow file

## Configuration Schema

### Global Settings

```json
{
  "global": {
    "fileExtensions": [".js", ".ts", ".jsx", ".tsx", ".py", ".java", ".go", ".rb"],
    "testFilePatterns": [".test.", ".spec.", "__tests__", "/tests/", "/test/"],
    "excludePatterns": [
      "**/node_modules/**",
      "**/dist/**",
      "**/.git/**",
      "**/tests/fixtures/**",
      "**/test/fixtures/**"
    ],
    "defaultSeverity": "warning"
  }
}
```

#### `fileExtensions`
- **Type:** Array of strings
- **Default:** `[".js", ".ts", ".jsx", ".tsx", ".py", ".java", ".go", ".rb"]`
- **Description:** File extensions to scan. Add more extensions to support additional languages.

**Example:** Add PHP and C++ files:
```json
{
  "global": {
    "fileExtensions": [".js", ".ts", ".py", ".php", ".cpp", ".c"]
  }
}
```

#### `testFilePatterns`
- **Type:** Array of strings
- **Default:** `[".test.", ".spec.", "__tests__", "/tests/", "/test/"]`
- **Description:** Patterns used to identify test files, which are automatically excluded from AI content detection.

**Example:** Custom test patterns for your project:
```json
{
  "global": {
    "testFilePatterns": ["_test.js", ".test.js", "/testing/", "/__snapshots__/"]
  }
}
```

#### `excludePatterns`
- **Type:** Array of strings (glob patterns)
- **Default:** `["**/node_modules/**", "**/dist/**", "**/.git/**", "**/tests/fixtures/**", "**/test/fixtures/**"]`
- **Description:** Directory patterns to exclude from scanning.

**Example:** Exclude additional directories:
```json
{
  "global": {
    "excludePatterns": [
      "**/node_modules/**",
      "**/build/**",
      "**/vendor/**",
      "**/.next/**"
    ]
  }
}
```

#### `defaultSeverity`
- **Type:** String (`"error"`, `"warning"`, or `"info"`)
- **Default:** `"warning"`
- **Description:** Default severity level for findings.

---

### Analyzer Settings

Each analyzer can be configured individually:

```json
{
  "analyzers": {
    "ai-detector": {
      "enabled": true,
      "severity": "warning",
      "fileExtensions": null,
      "testFilePatterns": null,
      "customPatterns": []
    }
  }
}
```

#### Common Analyzer Options

- **`enabled`**: (Boolean) Enable or disable the analyzer
- **`severity`**: (String) Set to `"error"`, `"warning"`, or `"info"`
- **`fileExtensions`**: (Array or null) Override global file extensions for this analyzer
- **`testFilePatterns`**: (Array or null) Override global test patterns for this analyzer

#### AI Detector Specific Options

- **`customPatterns`**: (Array of RegExp patterns as strings) Additional AI tool names to detect

**Example:** Detect additional AI tools:
```json
{
  "analyzers": {
    "ai-detector": {
      "enabled": true,
      "severity": "warning",
      "customPatterns": [
        "\\bcursor\\b",
        "\\btabnine\\b",
        "\\bcodeium\\b"
      ]
    }
  }
}
```

---

## Configuration Examples

### Example 1: Scan Only JavaScript/TypeScript

```json
{
  "global": {
    "fileExtensions": [".js", ".ts", ".jsx", ".tsx"]
  }
}
```

### Example 2: Polyglot Project (Multiple Languages)

```json
{
  "global": {
    "fileExtensions": [".js", ".ts", ".py", ".go", ".java", ".rb", ".php", ".rs"]
  }
}
```

### Example 3: Custom Test Patterns

```json
{
  "global": {
    "testFilePatterns": [
      "_spec.rb",
      "_test.py",
      ".test.js",
      "/e2e/",
      "/integration/"
    ]
  }
}
```

### Example 4: Monorepo Configuration

```json
{
  "global": {
    "excludePatterns": [
      "**/node_modules/**",
      "**/dist/**",
      "**/build/**",
      "**/packages/*/lib/**",
      "**/.turbo/**"
    ]
  }
}
```

### Example 5: Detect Organization-Specific AI Tools

```json
{
  "analyzers": {
    "ai-detector": {
      "enabled": true,
      "severity": "warning",
      "customPatterns": [
        "\\binternal-ai-assistant\\b",
        "\\bcompany-copilot\\b"
      ]
    }
  }
}
```

### Example 6: Disable AI Detection for Test Files Only

```json
{
  "analyzers": {
    "ai-detector": {
      "enabled": true,
      "testFilePatterns": [".test.", ".spec.", "__tests__"]
    }
  }
}
```

### Example 7: Scan Everything (Including Tests)

```json
{
  "analyzers": {
    "ai-detector": {
      "enabled": true,
      "testFilePatterns": []
    }
  }
}
```

---

## Configuration Merging

The linter uses a **merge strategy** for configuration:

1. Load `defaults.json` (built-in defaults)
2. Merge with user config file (`.mcp-lint.json` or custom path)
3. Apply to linter

**Merge Rules:**
- User config **overrides** defaults for specified keys
- Unspecified keys use defaults
- Arrays are **replaced** (not merged) when specified in user config

**Example:**

**defaults.json:**
```json
{
  "global": {
    "fileExtensions": [".js", ".ts"],
    "testFilePatterns": [".test."]
  }
}
```

**User .mcp-lint.json:**
```json
{
  "global": {
    "fileExtensions": [".py", ".rb"]
  }
}
```

**Resulting config:**
```json
{
  "global": {
    "fileExtensions": [".py", ".rb"],
    "testFilePatterns": [".test."]
  }
}
```

---

## Backward Compatibility

The old configuration format (flat structure) is still supported:

```json
{
  "ai-detector": {
    "enabled": true,
    "severity": "warning"
  }
}
```

This format automatically maps to the new structure:
```json
{
  "analyzers": {
    "ai-detector": {
      "enabled": true,
      "severity": "warning"
    }
  }
}
```

---

## Best Practices

1. **Start Small**: Only override settings you need to change
2. **Use Comments**: Add `"description"` fields to document your choices
3. **Version Control**: Commit `.mcp-lint.json` to share config with your team
4. **Test Locally**: Run `node src/cli.js` to verify config works before CI/CD
5. **Update Gradually**: Add more file types and patterns as your project evolves

---

## Troubleshooting

### "No files found to scan"
- Check `global.fileExtensions` includes your file types
- Verify `global.excludePatterns` isn't excluding your source directory

### "Test files are being scanned"
- Add patterns to `global.testFilePatterns` or analyzer-specific `testFilePatterns`

### "Custom patterns not working"
- Ensure regex patterns are properly escaped: `\\b` instead of `\b`
- Use `customPatterns` array, not `patterns` (which is reserved for built-in patterns)

---

## Version Information

This configuration system was introduced in **v1.1.0** and uses:
- `defaults.json` for built-in defaults
- Dynamic version from `package.json` in SARIF output
- Auto-discovery of analyzers from `src/analyzers/` directory
