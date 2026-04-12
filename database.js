/* *************************************************
*  Name: Gustavo Alatriste
*  Assignment: JWKS server with SQLite integrated
*  Purpose: Implementation of a database using SQLite3
*           into the current JWKS server (database.js) 
************************************************* */

const sqlite3 = require('sqlite3').verbose();

const path = require('path');

const dbPath = path.join(__dirname, 'jwks-server.db');

console.log(`Connecting to SQLite database at: ${dbPath}`);

const db = new sqlite3.Database(dbPath, (err) => 
{
    if (err)
    {
        console.error('Error connecting to a database:', err.message);
    }
    else
    {
        console.log('Successfully connected to SQLite database');
        initalizeDatabase();
    }
});


/* *************************************************
* This function initalizes the database by creating new
* tables. 
* 
* @param : none
* @return :  none
* @exception : none
* @note : na
* ************************************************* */

function initalizeDatabase() 
{
    console.log('Initializing database and creating tables if needed: ');

    db.run(`CREATE TABLE IF NOT EXISTS keys (
        kid TEXT PRIMARY KEY,
        secret TEXT NOT NULL, 
        createdAt TEXT NOT NULL,
        expiresIn TEXT NOT NULL, 
        isActive INTEGER NOT NULL DEFAULT 1, 
    )`, (err) => {
    if(err)
    {
        console.error('Error creating keys table: ', err.message);
        console.error('Full error', err);
    }
    else
    {
        console.log('Ensured "keys" table exists');
        db.get("SELECT COUNT(*) as count FROM keys", (err,now) => {
            if(err)
            {
                console.error('Error checking keys count', err.message);
            }
            else if (row.count === 0)
            {
                console.log('No keys found, will generate one...');
            }
        })
    }
    });
}

/* *************************************************
* This function closes an existing database 
* 
* @param : none
* @return :  none
* @exception : none
* @note : na
* ************************************************* */
function closeDatabase() 
{
    db.close((err) => 
    {
    if(err)
    {
        console.error('Error closing database: ', err.message);
    }
    else
    {
        console.log('Database connection closed');
    }
    });
}

process.on('SIGTERM', () => 
{
    console.log('SIGTERM signal received: closing database connection... ');
    closeDatabase();
});

process.on('SIGINT', () => 
{
    console.log('SIGTERM signal received: closing database connection... ');
    closeDatabase();
});

module.exports = db;
