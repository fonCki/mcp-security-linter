// demo-vulnerable.js

// 1. Token Passthrough Vulnerabilities
const apiKey = process.env.API_KEY;
console.log('Starting with key:', apiKey); // Should be flagged

const userToken = 'abc-123';
fetch(`https://api.example.com/data?token=${userToken}`); // Should be flagged

// 2. Hardcoded Secrets
const awsKey = 'AKIAIOSFODNN7EXAMPLE'; // Should be flagged
const slackToken = 'xoxb-REDACTED-TOKEN'; // Should be flagged

// 3. Dangerous Command Execution (Existing check)
const { exec } = require('child_process');
const userInput = 'ls -la';
exec(userInput); // Should be flagged
