# Contributing to MCP-SecLint

Thanks for your interest in contributing! This document covers analyzer plugins, tests, code style, and PR conventions. For team contact information, see [TEAM.md](TEAM.md).

## Maintainers

- Melissa Safari <s224818@dtu.dk> — DTU Compute
- Zachary Kang <e1122217@u.nus.edu> — National University of Singapore
- Alfonso Pedro Ridao <s243942@dtu.dk> — DTU Compute
- Nicola Dragoni <ndra@dtu.dk> — DTU Compute (advisor)

For non-trivial changes, please open an issue first to discuss the approach before submitting a PR.

## Adding a New Analyzer

1. Create a new file in `src/analyzers/`
2. Extend the `BaseAnalyzer` class
3. Implement the `analyze(filePath, content)` method
4. Add tests in `tests/unit/`

### Example Analyzer

```javascript
const BaseAnalyzer = require('./base-analyzer');

class MyAnalyzer extends BaseAnalyzer {
  constructor(options = {}) {
    super('my-analyzer', options);
  }

  analyze(filePath, content) {
    const findings = [];

    // Your analysis logic here
    if (content.includes('vulnerability')) {
      findings.push(this.createFinding(
        filePath,
        1, // line
        1, // column
        'Security issue detected',
        'my-rule-id'
      ));
    }

    return findings;
  }
}

module.exports = MyAnalyzer;
```

## Testing

Run tests with:

```bash
npm test
npm run test:coverage
```

## Pull Request Process

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## Code Style

- Use Node.js built-in modules when possible
- Keep dependencies minimal
- Write clear, self-documenting code
- Add JSDoc comments for public methods