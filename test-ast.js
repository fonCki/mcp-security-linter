// AST Test File
const { exec } = require('child_process');

function test() {
    // 1. Safe: Commented out dangerous command
    // exec('rm -rf /'); 

    // 2. Safe: Static string
    exec('ls -la');

    // 3. Dangerous: Dynamic argument (Template Literal)
    const userInput = 'foo; rm -rf /';
    exec(`ls ${userInput}`);

    // 4. Dangerous: Dynamic argument (Concatenation)
    exec('ls ' + userInput);

    // 5. Dangerous: Direct variable usage
    exec(userInput);
}
