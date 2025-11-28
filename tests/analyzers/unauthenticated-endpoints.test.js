const UnauthenticatedEndpointsAnalyzer = require('../../src/analyzers/unauthenticated-endpoints');

describe('UnauthenticatedEndpointsAnalyzer', () => {
    let analyzer;

    beforeEach(() => {
        analyzer = new UnauthenticatedEndpointsAnalyzer();
    });

    test('should detect unauthenticated GET route', () => {
        const code = `
      app.get('/api/data', (req, res) => {
        res.send('data');
      });
    `;
        const findings = analyzer.analyze('routes.js', code);
        expect(findings).toHaveLength(1);
        expect(findings[0].message).toContain("Potential unauthenticated endpoint detected: GET /api/data");
    });

    test('should ignore route with auth middleware', () => {
        const code = `
      app.get('/api/secure', auth, (req, res) => {
        res.send('secure data');
      });
    `;
        const findings = analyzer.analyze('routes.js', code);
        expect(findings).toHaveLength(0);
    });

    test('should ignore route with passport.authenticate', () => {
        const code = `
      router.post('/api/login', passport.authenticate('local'), (req, res) => {
        res.send('logged in');
      });
    `;
        const findings = analyzer.analyze('routes.js', code);
        expect(findings).toHaveLength(0);
    });

    test('should ignore common public routes', () => {
        const code = `
      app.get('/health', (req, res) => res.send('ok'));
      app.post('/login', (req, res) => res.send('token'));
    `;
        const findings = analyzer.analyze('routes.js', code);
        expect(findings).toHaveLength(0);
    });
});
