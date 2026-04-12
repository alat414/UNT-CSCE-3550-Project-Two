/* *************************************************
*  Name: Gustavo Alatriste
*  Assignment: JWKS server with SQLite integrated
*  Purpose: Implementation of a database using SQLite3
*           into the current JWKS server (database.js) 
************************************************* */
// database.js
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

// Define the path for your database file
const dbPath = path.join(__dirname, 'jwks-server.db');

console.log(`Connecting to SQLite database at: ${dbPath}`);

// Create database connection
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) 
    {
        console.error('Error connecting to database:', err.message);
    } 
    else 
    {
        console.log('Successfully connected to SQLite database');
        initializeDatabase();
    }
});

/**
 * Initializes the database by creating tables if they don't exist
 */
function initializeDatabase() {
    console.log('Initializing database and creating tables if needed...');

    // Create keys table - FIXED syntax
    db.run(`CREATE TABLE IF NOT EXISTS keys (
        kid TEXT PRIMARY KEY,
        secret TEXT NOT NULL,
        createdAt TEXT NOT NULL,
        expiresIn TEXT NOT NULL,
        isActive INTEGER NOT NULL DEFAULT 1
    )`, (err) => {
        if (err) 
        {
            console.error('Error creating keys table:', err.message);
            console.error('Full error:', err);
        }
        else 
        {
            console.log('Ensured "keys" table exists');
            
            // Check if we need to create an initial key
            db.get("SELECT COUNT(*) as count FROM keys", (err, row) => {
                if (err) 
                {
                    console.error('Error checking keys count:', err.message);
                } 
                else if (row.count === 0) 
                {
                    console.log('No keys found, will generate one...');
                }
            });
        }
    });
}

/**
 * Helper function to close the database connection gracefully
 */
function closeDatabase() 
{
    db.close((err) => {
        if (err) 
        {
            console.error('Error closing database:', err.message);
        } 
        else 
        {
            console.log('Database connection closed');
        }
    });
}

// Handle graceful shutdown
process.on('SIGTERM', () => {
    console.log('SIGTERM signal received: closing database connection...');
    closeDatabase();
});

process.on('SIGINT', () => {
    console.log('SIGINT signal received: closing database connection...');
    closeDatabase();
});

module.exports = db;