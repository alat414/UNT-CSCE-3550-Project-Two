/* *************************************************
*  Name: Gustavo Alatriste
*  Assignment: Project One JWKS server
*  Purpose: Testing driver file
*           using group tests and blocks to 
*           ensure proper POST, GET, token,
*           error, and key(ID) returns 
*           keyStorage.tests.js
************************************************* */

const { execSync } = require('child_process');
const path = require('path');
const readline = require('readline');

const rl = readline.createInterface
({
    input: process.stdin,
    output: process.stdout
});


console.log
(
    `JWT Server Test Suite Runner`
);

console.log('Available test suites');
console.log('1: Unit tests - keyStorage');
console.log('2: Authentication Flow tests');
console.log('3: Key Rotation tests');
console.log('4: Token Expiry tests');
console.log('5: All tests');
console.log('6: Run with coverage');
console.log('7: Exit\n');

rl.question('Select test suite options 1-7: ', (answer) => 
{
    try
    {
        switch(answer)
        {
            case '1':
                execSync('npx jest test/unit_tests/keyStorage.tests.js', { stdio: 'inherit' });
                break;
            case '2':
                execSync('npx jest test/integration_tests/authentication-flow.tests.js', { stdio: 'inherit' });
                break;
            case '3':
                execSync('npx jest test/integration_tests/key-rotation.tests.js', { stdio: 'inherit' });
                break;
            case '4':
                execSync('npx jest test/integration_tests/token-expiry.tests.js', { stdio: 'inherit' });
                break;
            case '5':
                execSync('npx jest', { stdio: 'inherit' });
                break;
            case '6':
                execSync('npx jest --coverage', { stdio: 'inherit' });
                break;
            case '7':
                console.log('Exiting ...');
                break;
            default:
                console.log('Invalid option');

        }
    }    
    catch(error)
    {
        console.error('Tests failed: ', error.message);
    }
        
    rl.close();

})