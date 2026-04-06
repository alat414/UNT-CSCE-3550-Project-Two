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

app.get('/.well-known/jwks.json', (req, res) => 
{
    try
    {
        const jwks = 
        {
            keys: []
        };
        

        for (const [kid, keyData] of keyStorage.keys)
        {
            if(keyData.isActive && new Date() <= keyData.expiresIn)
            {
                jwks.keys.push
                ({
                    kid: kid,
                    kty: "oct",
                    alg: "HS256",
                    use: "sig",

                    exp: Math.floor(keyData.expiresIn.getTime() / 1000)
                });
            }
        }
        console.log(`JWKS endpoint: Returning ${jwks.keys.length} active keys`);
        res.json(jwks)
    }
    catch(error)
    {
        console.log('JWKS endpoint error: ',error);
        res.status(500).json
        ({
            error: 'Internal Server error'
        });
    }
});