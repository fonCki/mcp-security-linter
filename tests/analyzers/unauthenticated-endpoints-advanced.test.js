const UnauthenticatedEndpointsAnalyzer = require('../../src/analyzers/unauthenticated-endpoints');

describe('UnauthenticatedEndpointsAnalyzer (Advanced)', () => {
    let analyzer;

    beforeEach(() => {
        analyzer = new UnauthenticatedEndpointsAnalyzer();
    });

    test('should respect global middleware (app.use)', () => {
        const code = `
      const express = require('express');
      const app = express();
      const auth = require('./auth');

      app.use(auth); // Global auth

      app.get('/protected', (req, res) => {
        res.send('secure');
      });
    `;
        const findings = analyzer.analyze('app.js', code);
        expect(findings).toHaveLength(0);
    });

    test('should respect router-level middleware', () => {
        const code = `
      const router = express.Router();
      
      router.use(requireAuth); // Router level auth

      router.get('/users', (req, res) => {
        res.json([]);
      });
    `;
        const findings = analyzer.analyze('routes.js', code);
        expect(findings).toHaveLength(0);
    });

    test('should detect unauthenticated route defined BEFORE global middleware', () => {
        const code = `
      const app = express();
      
      // Vulnerable: defined before auth
      app.get('/public-oops', (req, res) => res.send('oops'));

      app.use(authMiddleware);

      app.get('/protected', (req, res) => res.send('ok'));
    `;
        const findings = analyzer.analyze('app.js', code);
        expect(findings).toHaveLength(1);
        expect(findings[0].message).toContain('GET /public-oops');
    });

    test('should handle middleware arrays', () => {
        const code = `
      const standardMiddleware = [logger, auth, parser];
      
      app.get('/api', standardMiddleware, (req, res) => {
        res.send('ok');
      });
    `;
        const findings = analyzer.analyze('app.js', code);
        expect(findings).toHaveLength(0);
    });

    test('should handle mounted routers with auth', () => {
        const code = `
      const apiRouter = express.Router();
      apiRouter.get('/data', (req, res) => res.send('data')); // Inherits auth from app.use

      app.use(auth);
      app.use('/api', apiRouter);
    `;
        // This is very hard for static analysis without full project graph.
        // But within single file, we can track 'apiRouter' usage.
        // If 'apiRouter' is used in 'app.use' AFTER 'app.use(auth)', it might be safe?
        // Actually, 'app.use(auth)' applies to all subsequent requests.
        // If we define router routes BEFORE mounting, it's tricky.
        // Let's assume standard pattern: define router, then mount it.
        // If app.use(auth) is called before app.use('/api', apiRouter), then apiRouter is protected?
        // Yes, in Express, middleware order matters for 'use'.

        // For this test, let's simplify: if the router itself doesn't have auth, 
        // but it's mounted to an app that HAS global auth, it should be safe.
        // BUT, the analyzer analyzes file by file. If 'app' and 'apiRouter' are in same file, we can check.

        const findings = analyzer.analyze('app.js', code);
        expect(findings).toHaveLength(0);
    });
});
