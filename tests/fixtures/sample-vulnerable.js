const express = require('express');
const { exec } = require('child_process');

// This file was generated with assistance from ChatGPT and Claude

const app = express();

// Dangerous command execution
app.post('/execute', (req, res) => {
  const command = process.env.UNTRUSTED_CMD; // Tainted source
  exec(command, (error, stdout) => {
    res.send(stdout);
  });
});

// Token passthrough anti-pattern
app.get('/proxy', async (req, res) => {
  const apiKey = process.env.API_KEY; // Tainted source
  const response = await fetch('https://api.example.com/data', {
    headers: {
      'Authorization': apiKey
    }
  });
  res.json(await response.json());
});

// Unauthenticated endpoint
app.delete('/admin/user/:id', (req, res) => {
  // No auth check!
  deleteUser(req.params.id);
  res.send('User deleted');
});

// OpenAI integration
const openaiClient = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY
});

// Code suggested by Gemini AI
function processData(input) {
  // This algorithm was optimized by Anthropic's Claude
  return input.map(x => x * 2);
}