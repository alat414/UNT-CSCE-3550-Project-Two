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


describe('Database Initialization Tests', () => {
    let dbModule;
    let testDbPath;

    beforeEach(() => {
        jest.clearAllMocks();
        // Reset module cache to test fresh database initialization
        delete require.cache[require.resolve('../../database')];
    });

    afterEach(() => {
        if (testDbPath && fs.existsSync(testDbPath)) {
            fs.unlinkSync(testDbPath);
        }
    });

    test('database.js should create keys table with correct schema', () => {
        const { db } = require('../../database');
        
        // Verify table creation was called
        expect(db.run).toHaveBeenCalled();
        
        // Check that CREATE TABLE statement contains correct columns
        const createTableCall = db.run.mock.calls.find(
            call => call[0] && call[0].includes('CREATE TABLE')
        );
        
        expect(createTableCall).toBeDefined();
        expect(createTableCall[0]).toContain('kid TEXT PRIMARY KEY');
        expect(createTableCall[0]).toContain('privateKey TEXT NOT NULL');
        expect(createTableCall[0]).toContain('publicKey TEXT NOT NULL');
        expect(createTableCall[0]).toContain('createdAt TEXT NOT NULL');
        expect(createTableCall[0]).toContain('expiresIn TEXT NOT NULL');
        expect(createTableCall[0]).toContain('isActive INTEGER NOT NULL DEFAULT 1');
    });

});