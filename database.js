/* *************************************************
*  Name: Gustavo Alatriste
*  Assignment: JWKS server with SQLite integrated
*  Purpose: Implementation of the server with key
*           rotation; keyExpiry.js
************************************************* */
// Authenticate User
require('dotenv').config()

const express = require('express');

const jwt = require('jsonwebtoken')
const keyStorage = require('./keyStorage');
const { authenticateToken, posts, getUserPosts } = require('./app.js')

const app = express();
const port = 8080;

// Valid Users declared.
const VALID_USERS = ['Nanna', 'nanna', 'Raggi', 'raggi'];

app.use(express.json())

keyStorage.generateNewKey(1);

/* *************************************************
* This function calls the JWKS endpoint. 
* Only includes active keys, not expired ones. 
* 
* @return:  all active public keys 
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