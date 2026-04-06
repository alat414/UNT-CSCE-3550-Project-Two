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

    db.run(`
        CREATE TABLE IF NOT EXISTS keys (
            kid,
            secret, 
            createdAt,
            expiresIn, 
            isActive, 
        )
    `, (err) => 
    {
    if(err)
    {
        console.error('Error creating keys table: ', err.message);
    }
    else
    {
        console.log('Ensured "keys" table exists');
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