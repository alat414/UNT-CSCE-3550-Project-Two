/* *************************************************
*  Name: Gustavo Alatriste
*  Assignment: Project One JWKS server
*  Purpose: Database testing functions
*           using functions and calls to ensure
*           database actions including opening,
*           creating, and connections are working
*           correctly. 
*           database.tests.js
************************************************* */

const sqlite3 = require('sqlite3');
const path = require('path');
const fs = require('fs');

jest.mock('sqlite3', () => 
{
    const mockRun = jest.fn();
    const mockSerialize = jest.fn((callback) => callback());
    const mockDatabase = jest.fn().mockImplementation(() => 
    ({
        serialize: mockSerialize,
        run: mockRun,
        close: jest.fn(),
        exec: jest.fn((query, callback) => callback(null))
    }));
    return { verbose: () => mockDatabase };
});
