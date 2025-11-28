const TokenPassthroughAnalyzer = require('../../src/analyzers/token-passthrough');

describe('TokenPassthroughAnalyzer (Advanced)', () => {
    let analyzer;

    beforeEach(() => {
        analyzer = new TokenPassthroughAnalyzer();
    });

    test('should detect sensitive variable after reassignment', () => {
        const code = `
      const apiKey = process.env.API_KEY;
      const key = apiKey;
      console.log(key);
    `;
        const findings = analyzer.analyze('test.js', code);
        expect(findings).toHaveLength(1);
        expect(findings[0].message).toContain("Sensitive variable 'key' (origin: apiKey)");
    });

    test('should detect sensitive variable through multiple reassignments', () => {
        const code = `
      const secret = '12345';
      const a = secret;
      const b = a;
      const c = b;
      fetch('https://api.com?token=' + c);
    `;
        const findings = analyzer.analyze('test.js', code);
        expect(findings).toHaveLength(1);
        expect(findings[0].message).toContain("Sensitive variable 'c' (origin: secret)");
    });

    test('should detect sensitive variable in ternary operator', () => {
        const code = `
      const prodKey = process.env.PROD_KEY;
      const devKey = 'dev-key';
      const activeKey = isProd ? prodKey : devKey;
      console.log(activeKey);
    `;
        const findings = analyzer.analyze('test.js', code);
        expect(findings).toHaveLength(1);
        // Should ideally identify it came from prodKey or devKey
        expect(findings[0].message).toMatch(/Sensitive variable 'activeKey'/);
    });

    test('should detect sensitive variable passed as function argument (intra-file)', () => {
        const code = `
      const apiKey = 'secret';
      
      function logData(data) {
        console.log(data);
      }
      
      logData(apiKey);
    `;
        const findings = analyzer.analyze('test.js', code);
        expect(findings).toHaveLength(1);
        expect(findings[0].message).toContain("Sensitive variable 'data' (origin: apiKey)");
    });

    test('should NOT flag safe variables even if they share name with sensitive ones in other scopes', () => {
        const code = `
      function safe() {
        const apiKey = 'safe-context';
        // do nothing
      }

      function unsafe() {
        const data = 'public';
        console.log(data);
      }
    `;
        const findings = analyzer.analyze('test.js', code);
        expect(findings).toHaveLength(0);
    });
});
