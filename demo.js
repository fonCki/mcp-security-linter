/**
 * MCP Security Linter Demo File
 *
 * This file contains intentional security vulnerabilities to demonstrate
 * the linter's capabilities across all three analyzers.
 */

const { exec } = require('child_process');
const express = require('express');

// 1. Token Passthrough Detection
const apiKey = process.env.API_KEY;

// Vulnerability: Logging sensitive data
console.log('Using API Key:', apiKey);

// Vulnerability: Passing token in URL query params
const userToken = 'abc-123';
fetch(`https://api.example.com/data?token=${userToken}`);

// 2. Dangerous Command Execution
const untrustedCmd = process.env.USER_CMD;
exec(`ls -la ${untrustedCmd}`);

// 3. Unauthenticated Endpoints
const app = express();

// No auth middleware before this route
app.delete('/admin/user/:id', (req, res) => {
  res.send('User deleted');
});
