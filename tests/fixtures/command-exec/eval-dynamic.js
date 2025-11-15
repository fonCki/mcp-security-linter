// DANGEROUS: eval() with user input
function evaluateUserCode(userInput) {
  eval(userInput);
}

// DANGEROUS: Function constructor
function createDynamicFunction(code) {
  const fn = new Function(code);
  fn();
}

// DANGEROUS: vm.runInNewContext
const vm = require('vm');
function runUntrustedCode(code) {
  vm.runInNewContext(code);
}

// DANGEROUS: vm.runInThisContext
function runCodeInContext(code) {
  vm.runInThisContext(code);
}

module.exports = { evaluateUserCode, createDynamicFunction, runUntrustedCode, runCodeInContext };
