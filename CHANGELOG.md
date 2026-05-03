# Changelog

All notable changes to MCP-SecLint are recorded here.

The IWSPA '26 paper artifact is **v1.4.2**. Releases after that may include
post-paper maintenance fixes; pin to `npx mcp-security-linter@1.4.2` when
reproducing the paper's ecosystem scan.

## [1.6.1] - 2026-05-03

Documentation-only release. No code or behavior changes.

### Changed

- Added Nicola Dragoni (advisor, DTU Compute) to the project team
  across `LICENSE`, `README.md`, `TEAM.md`, `CONTRIBUTING.md`, and
  `package.json` `author` / `contributors` fields.
- Corrected Zachary Kang's identity everywhere from the legacy
  `zkjh@u.nus.edu` / `s251598` to the canonical `e1122217@u.nus.edu` /
  `e1122217` matching the IWSPA '26 paper. The `s251598` student ID
  in older docs was a DTU-format ID, but Zachary is at the National
  University of Singapore — `e1122217` is the correct NUS student
  number and the email used in the paper.
- Bumped `LICENSE` copyright year range to 2025-2026.
- Added a `Maintainers` section to `CONTRIBUTING.md` with current
  contact info for all four people.
- Added a Publication block to `TEAM.md` referencing IWSPA '26 and
  DOI 10.1145/3806007.3810961, plus the npm registry link.

## [1.6.0] - 2026-05-03

This release stabilizes JS/TS analysis, removes vulnerable runtime
dependencies, fixes a long-standing CLI exit-code bug and a broken
GitHub Action input wiring, and closes implementation gaps in the
v1.4.2 sink and handler coverage that the IWSPA '26 paper describes.

It is the first post-publication release. The v1.4.2 npm artifact
remains the paper-pinned version for ecosystem-scan reproducibility.

### Added

- TypeScript and JSX/TSX parsing via `@typescript-eslint/typescript-estree`.
  This addresses the limitation noted in §7.3 of the paper, where complex
  TypeScript type annotations caused `acorn` to fail and silently miss
  findings (e.g. `hdresearch-mcp-shell`). Acorn is preserved for the JS
  path (see "Changed" below) so the paper's architectural description in
  §4.3 and Figure 2 still accurately describes how `master` parses
  JavaScript.
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
- `unauthenticated-endpoint` analyzer now recognizes member-expression
  middleware inside `app.use(...)`. Previously the `app.use` handler only
  inspected `Identifier` callees, so common patterns like
  `app.use(passport.authenticate('jwt'))` were missed and downstream
  routes were falsely flagged as unauthenticated. The handler now reuses
  the existing `collectMiddlewareNames()` helper that already covers
  member-expression callees in route definitions. Locked in by two
  regression tests (positive: passport; negative: `bodyParser.json()`).
- `action.yml` composite-action outputs (`findings-count`, `sarif-file`,
  `results-file`) now propagate to consumers via explicit
  `value: ${{ steps.linter.outputs.* }}` mappings. Prior to this fix the
  internal `setOutput` calls wrote to `GITHUB_OUTPUT` correctly, but the
  composite wrapper did not forward them, so downstream workflows always
  saw empty strings. Bug existed in v1.4.2 too but was never noticed
  because no documented consumer referenced these outputs.
- CLI exits with status `1` whenever findings are present, regardless of
  output format. Previously `--format json` and `--format sarif` exited
  `0` even when error-level findings were emitted, which silently passed
  CI pipelines. Locked in by `tests/cli.test.js`.
- GitHub Action input env-var mapping renamed `INPUT_FAIL-ON-WARNINGS`
  → `INPUT_FAIL_ON_WARNINGS` (and analogous for other inputs). Hyphens
  are not valid in POSIX env-var names, so the previous mapping was
  silently using defaults.
- `actions/setup-node@v3` → `@v4`, and the action now runs on Node 20.
- Default file extensions narrowed to the JS/TS family:
  `.js`, `.cjs`, `.mjs`, `.ts`, `.tsx`, `.mts`, `.cts`, `.jsx`. The
  prior list of `.py`, `.java`, `.go`, `.rb`, `.sh`, `.yml`, `.env`, etc.
  was never actually parsed (analyzers are JS-AST only) and produced no
  findings; the narrower default reflects what the tool actually does.
- README "Paper Reproducibility" section pins reproduction to
  `mcp-security-linter@1.4.2` and notes that current `master` may include
  post-paper fixes.
- **Parser pipeline is now hybrid.** Acorn (paper Ref [20]) remains the
  parser for `.js`, `.cjs`, and `.mjs` files, preserving the architecture
  documented in paper §4.3 and Figure 2. `@typescript-eslint/typescript-estree`
  is used only for `.ts`, `.tsx`, `.mts`, `.cts`, and `.jsx`, where Acorn
  cannot parse the file. Both parsers emit ESTree-shaped ASTs that flow
  through the same custom walker. The TypeScript compiler is still pulled
  in transitively as a peer dependency of typescript-estree (~24 MB in
  node_modules); the hybrid is justified by paper-architecture fidelity,
  not by install footprint.

### Removed

- `@actions/core` and `@actions/github` runtime dependencies (replaced
  by a small hand-rolled GitHub Actions protocol implementation in
  `src/action.js`). Resolves outstanding npm-audit advisories.
- `acorn-walk` and `js-yaml` runtime dependencies. The custom walker in
  `src/analyzers/base-analyzer.js` traverses ESTree generically and
  handles both Acorn output and TypeScript-estree extension nodes
  (`TSAsExpression`, `TSNonNullExpression`, `ChainExpression`, etc.).
- Special-file globbing for `Dockerfile`, `.env*`, and similar files in
  `src/index.js`. These were collected but never analyzed.

### Security

- `npm audit`: 0 vulnerabilities (was 13 high/critical advisories on
  v1.4.2 due to the `@actions/*` runtime).
- Public `with:` interface of the GitHub Action is unchanged; the env-var
  mapping fix is internal only.

### Compatibility

- Minimum Node version is now `>=20.19.0` (was `>=14.0.0`). The floor is
  set by `eslint-visitor-keys@^5`, which is pulled in transitively by
  `@typescript-eslint/typescript-estree`. Node 14, 16, and 18 are all
  past end-of-life. Anyone running on a supported LTS (20.x or 22.x) is
  unaffected.
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
- The CLI does not validate the `--format` argument; an unknown value
  silently falls back to console output. The GitHub Action wrapper does
  validate. Planned tightening for v1.6.1.
- The programmatic API (`require('mcp-security-linter')`) is not yet
  documented in the README. The exported method is
  `new Linter(config).analyze(path)` and returns `Promise<Finding[]>`.
- Cross-file and cross-module taint tracking is still out of scope, as
  noted in paper §7.3.

### Validation

- 68/68 unit tests pass (was 60 on v1.5.0).
- `npm audit`: 0 vulnerabilities.
- The 5 paper-positive ecosystem repositories at the SHAs listed in
  `docs/ecosystem-analysis-results.csv` produce identical per-rule
  finding counts to the paper Table 3:
  CommandExecution=1, dbx-mcp-server=12, image-worker-mcp=4,
  influxdb-mcp-server=3, mcp-abap-adt=13.
- One paper-clean repository (`microsoft/azure-devops-mcp` @ d8b9642,
  paper Table 3 = 0) now produces 15 token-passthrough WARNINGs after
  the §7.3 TS-parsing fix. All 15 are legitimate `Bearer ${accessToken}`
  Authorization-header usage and surface as warnings per the design
  intent of paper §5.2 ("can be legitimate but still requires review").
  This is the §7.3 limitation lifting, not a regression.
- End-to-end real-user simulation: built `npm pack` tarball, installed
  into a fresh consumer, exercised CLI flags, formats, exit codes,
  programmatic API, config file discovery, and the GitHub Action
  composite consumer. All 14 simulated user journeys succeeded.

## [1.5.0] - 2026

Rebrand to MCP-SecLint. Behavior unchanged from v1.4.2 plus
documentation cleanup.

## [1.4.2] - 2025-11-29

**Paper artifact.** This is the version evaluated in the IWSPA '26 paper.
Use `npx mcp-security-linter@1.4.2` to reproduce the ecosystem scan
described in §6 of the paper. See `docs/ecosystem-analysis-results.md`
and `docs/ecosystem-analysis-results.csv` for the full per-repository
breakdown.
