const { execFile } = require('child_process');
const { spawn } = require('child_process');

// SAFE: Controlled command with no dangerous patterns
function listFiles() {
  execFile('ls', ['-la', '/tmp'], (error, stdout) => {
    if (error) {
      console.error(`Error: ${error}`);
      return;
    }
    console.log(stdout);
  });
}

// SAFE: Safe file operations
function createDirectory(dirname) {
  // Using spawn with array args (safer than shell)
  const mkdir = spawn('mkdir', ['-p', dirname]);

  mkdir.on('close', (code) => {
    console.log(`Directory created with code ${code}`);
  });
}

// SAFE: Normal logging
function logMessage(message) {
  console.log(message);
}

module.exports = { listFiles, createDirectory, logMessage };
