# Changelog

All notable changes to MCP-SecLint are recorded here.

The IWSPA '26 paper artifact is **v1.4.2**. Releases after that may include
post-paper maintenance fixes; pin to `npx mcp-security-linter@1.4.2` when
reproducing the paper's ecosystem scan.

## [1.6.0] - 2026-05-01

This release stabilizes JS/TS analysis, removes vulnerable runtime
dependencies, and closes implementation gaps in the v1.4.2 sink and
handler coverage that the IWSPA '26 paper describes.

### Added

- TypeScript and JSX/TSX parsing via `@typescript-eslint/typescript-estree`.
  This addresses the limitation noted in §7.3 of the paper, where complex
  TypeScript type annotations caused `acorn` to fail and silently miss
  findings (e.g. `hdresearch-mcp-shell`).
- TypeScript-specific node handling in taint propagation: `TSAsExpression`,
  `TSTypeAssertion`, `TSNonNullExpression`, and `ChainExpression` no longer
  break taint flow.
- MCP handler coverage extended to the high-level SDK shapes documented in
  paper §4.1: `tool`, `registerTool`, `resource(s)`, `registerResource`,
  `readResource`, `prompt(s)`, `registerPrompt`. Handler params from these
  entry points are now tainted as MCP-controlled input.
- Dynamic-code-evaluation sink `new Function(...)` is now detected.
  Listed in paper §5.1 but not implemented in v1.4.2.
- The `$` tagged template from `zx` is now detected as a shell-execution
  sink. Detection is gated on the import source (`zx` or `zx/globals`),
  including aliased imports such as `import { $ as shell } from 'zx'` and
  destructured `require('zx')`. Arbitrary `$` template tags from non-zx
  libraries are not flagged.
- `child_process` namespace and destructured aliases are tracked:
  `import * as cp from 'child_process'` then `cp.exec(...)`, and
  `const { exec: run } = require('child_process')` then `run(...)`.
- `command-exec-env` and `command-exec` checks now follow the same alias
  set, so options-bag detection (e.g. `{ env: process.env, shell: true }`)
  fires on aliased exec calls too.
- `unauthenticated-endpoint` analyzer handles inline middleware arrays
  on route definitions and array variables containing middleware.
- Action output `results-file` reports the path of the requested
  non-SARIF artifact.
- Regression tests for: TS parsing, TS-node taint flow, taint clearing
  on safe-literal reassignment, command-exec aliases, MCP handler
  patterns (`server.tool`, `registerTool` with destructured / identifier
  params), `new Function`, zx `$` (direct + aliased + non-zx negative),
  endpoint middleware arrays, CLI exit codes for all output formats,
  Action entrypoint, and formatter output.

### Changed

- Auth-middleware pattern set in `unauthenticated-endpoint` no longer
  includes `/check/i`. The previous pattern produced false negatives by
  treating `checkInput`, `checkPayload`, and similar input-validation
  middleware as authentication. This **diverges from paper §5.3**, which
  documents v1.4.2 behavior; the change improves precision.
- CLI exits with status `1` whenever findings are present, regardless of
  output format. Previously `--format json` and `--format sarif` exited
  `0` even when error-level findings were emitted, which silently passed
  CI pipelines. Locked in by `tests/cli.test.js`.
- GitHub Action input env-var mapping renamed `INPUT_FAIL-ON-WARNINGS`
  → `INPUT_FAIL_ON_WARNINGS` (and analogous for other inputs). Hyphens
  are not valid in POSIX env-var names, so the previous mapping was
  silently using defaults.
- `actions/setup-node@v3` → `@v4`, and the action now runs on Node 20.
- Default file extensions narrowed to `.js`, `.ts`, `.jsx`, `.tsx`. The
  prior list of `.py`, `.java`, `.go`, `.rb`, `.sh`, `.yml`, `.env`, etc.
  was never actually parsed (analyzers are JS-AST only) and produced no
  findings; the narrower default reflects what the tool actually does.
- README "Paper Reproducibility" section pins reproduction to
  `mcp-security-linter@1.4.2` and notes that current `master` may include
  post-paper fixes.

### Removed

- `@actions/core` and `@actions/github` runtime dependencies (replaced
  by a small hand-rolled GitHub Actions protocol implementation in
  `src/action.js`). Resolves outstanding npm-audit advisories.
- `acorn`, `acorn-walk`, and `js-yaml` runtime dependencies (replaced by
  `@typescript-eslint/typescript-estree` + a small custom AST walker in
  `src/analyzers/base-analyzer.js`).
- Special-file globbing for `Dockerfile`, `.env*`, and similar files in
  `src/index.js`. These were collected but never analyzed.

### Security

- `npm audit`: 0 vulnerabilities (was 13 high/critical advisories on
  v1.4.2 due to the `@actions/*` runtime).
- Public `with:` interface of the GitHub Action is unchanged; the env-var
  mapping fix is internal only.

### Compatibility

- Minimum Node version is now `>=18.18.0` (was `>=14.0.0`). Node 14 and
  16 reached end-of-life in 2023; the prior floor did not match the
  actual runtime requirements of the `glob` and `acorn` versions in use.
- Public action inputs (`path`, `config`, `fail-on-warnings`,
  `output-format`, `github-token`) are unchanged.

### Known limitations carried forward

- The `unauthenticated-endpoint` analyzer matches any
  `<obj>.<method>(stringPath, ...)` call and may report outbound HTTP
  client calls (e.g. `axios.post('https://api.example.com/...', ...)`)
  as endpoints. This pre-existed in v1.4.2 and is the source of the
  unauth-endpoint findings on `dbx-mcp-server` reported in the paper.
  A scoped fix that gates route detection on `express()` / `Router()`
  bindings is planned for v1.6.1.
- Cross-file and cross-module taint tracking is still out of scope, as
  noted in paper §7.3.

## [1.5.0] - 2026

Rebrand to MCP-SecLint. Behavior unchanged from v1.4.2 plus
documentation cleanup.

## [1.4.2] - 2025-11-29

**Paper artifact.** This is the version evaluated in the IWSPA '26 paper.
Use `npx mcp-security-linter@1.4.2` to reproduce the ecosystem scan
described in §6 of the paper. See `docs/ecosystem-analysis-results.md`
and `docs/ecosystem-analysis-results.csv` for the full per-repository
breakdown.
