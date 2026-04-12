/* *************************************************
*  Name: Gustavo Alatriste
*  Assignment: JWKS server with SQLite integrated
*  Purpose: Implementation of a database using SQLite3
*           into the current JWKS server (database.js) 
************************************************* */
// database.js - Simplified working version
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const dbPath = path.join(__dirname, 'jwks-server.db');
console.log(`Connecting to SQLite database at: ${dbPath}`);

const db = new sqlite3.Database(dbPath);

// Create table immediately
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS keys (
        kid TEXT PRIMARY KEY,
        secret TEXT NOT NULL,
        createdAt TEXT NOT NULL,
        expiresIn TEXT NOT NULL,
        isActive INTEGER NOT NULL DEFAULT 1
    )`, (err) => {
        if (err) {
            console.error('Error creating table:', err.message);
        } else {
            console.log('Keys table ready');
        }
    });
});

// Handle graceful shutdown
process.on('SIGTERM', () => {
    console.log('Closing database...');
    db.close();
});

process.on('SIGINT', () => {
    console.log('Closing database...');
    db.close();
});

module.exports = db;