# MCP-SecLint Configuration Guide

## Overview

MCP-SecLint supports JavaScript and TypeScript source analysis. The configuration system lets you customize:
- Which JS/TS file extensions to scan
- Which paths are treated as tests and skipped by analyzers
- Which directories or files are excluded
- Which analyzers are enabled and what severity they use

## Configuration Files

### Built-in defaults

`defaults.json` contains the built-in configuration. Prefer creating a project-level `.mcp-lint.json` instead of editing the defaults.

### User config

Create `.mcp-lint.json` in your project root, or pass a custom path:
- CLI: `node src/cli.js --config custom-config.json`
- GitHub Action: `config: custom-config.json`

Only specify settings you want to override.

## Configuration Schema

### Global Settings

```json
{
  "global": {
    "fileExtensions": [".js", ".ts", ".jsx", ".tsx"],
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
- **Default:** `[".js", ".ts", ".jsx", ".tsx"]`
- **Description:** JS/TS file extensions to scan. Other languages are not supported by the current analyzers.

#### `testFilePatterns`
- **Type:** Array of strings
- **Default:** `[".test.", ".spec.", "__tests__", "/tests/", "/test/"]`
- **Description:** Substrings used to identify test files that analyzers should skip.

#### `excludePatterns`
- **Type:** Array of glob patterns
- **Default:** excludes dependency, build, VCS, IDE, fixture, and lockfile paths
- **Description:** Files or directories to exclude from scanning.

#### `defaultSeverity`
- **Type:** `"error"`, `"warning"`, or `"info"`
- **Default:** `"warning"`
- **Description:** Default severity for analyzers that do not override it.

### Analyzer Settings

Each analyzer can be configured individually:

```json
{
  "analyzers": {
    "command-exec": {
      "enabled": true,
      "severity": "error",
      "fileExtensions": [".js", ".ts", ".jsx", ".tsx"],
      "testFilePatterns": [".test.", ".spec.", "__tests__"]
    }
  }
}
```

Common analyzer options:
- **`enabled`**: Enable or disable the analyzer.
- **`severity`**: Set default severity for findings emitted by the analyzer.
- **`fileExtensions`**: Override global file extensions for that analyzer.
- **`testFilePatterns`**: Override global test file patterns for that analyzer.

Built-in analyzers:
- `command-exec`
- `token-passthrough`
- `unauthenticated-endpoints`

## Examples

### Scan only JavaScript

```json
{
  "global": {
    "fileExtensions": [".js", ".jsx"]
  }
}
```

### Disable one analyzer

```json
{
  "analyzers": {
    "unauthenticated-endpoints": {
      "enabled": false
    }
  }
}
```

### Custom test patterns

```json
{
  "global": {
    "testFilePatterns": [
      ".test.",
      ".spec.",
      "/e2e/",
      "/integration/"
    ]
  }
}
```

### Monorepo excludes

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

## Configuration Merging

The linter merges configuration in this order:
1. Load `defaults.json`.
2. Merge `.mcp-lint.json` or the custom config file.
3. Apply the merged settings to analyzers.

Merge rules:
- User config overrides defaults for specified keys.
- Unspecified keys use defaults.
- Arrays are replaced, not merged.
- The legacy flat analyzer format is still supported:

```json
{
  "command-exec": {
    "enabled": false
  }
}
```

## Troubleshooting

### "No files found to scan"
- Check that `global.fileExtensions` includes your JS/TS file extension.
- Check that `global.excludePatterns` is not excluding your source directory.

### "Test files are being scanned"
- Add patterns to `global.testFilePatterns` or analyzer-specific `testFilePatterns`.

### "Non-JS/TS files are not scanned"
- This is expected in the current release. The active analyzers support JavaScript and TypeScript syntax only.
