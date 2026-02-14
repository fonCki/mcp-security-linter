// demo-vulnerable.js
// Demonstrates token passthrough vulnerabilities detected by the linter.

// 1. Token Passthrough: env var logged to console
const apiKey = process.env.API_KEY;
console.log('Starting with key:', apiKey); // Flagged: token-passthrough (ERROR)

// 2. Token Passthrough: token sent to external service
const userToken = 'abc-123';
fetch(`https://api.example.com/data?token=${userToken}`); // Flagged: token-passthrough (WARNING)
