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

/* *************************************************
* This function request the refresh token. 

* @param : request
* @param : response
* @return : refresh token
* @exception : none
* @note : na
* ************************************************* */
app.post('/token', (req, res) =>
{
    const refreshToken = req.body.token

    if (!refreshToken) 
    {
        console.log('Token refresh failed: No refresh token provided');
        return res.sendStatus(401)
    }

    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
        if (err)
        {
            console.log('Token refresh failed: Invalid refresh token');
            return res.status(403).json
            ({
                error: 'Invalid refresh token'
            });
        }   

        const currentKey = keyStorage.getCurrentKey();
        const currentKeyID = keyStorage.getCurrentKeyID();

        if(!currentKey || !currentKeyID)
        {
            console.error('Token refresh failed: No active key available');
            return res.status(500).json
            ({ 
                error: 'No active key available'
            });   
        }

        const keyData = keyStorage.keys.get(currentKeyID);
        if(!keyData || !keyData.isActive || new Date() > keyData.expiresIn)
        {
            console.error('Token refresh failed: Active key is expired');
            return res.status(500).json
            ({ 
                error: 'Active key expired'
            });   
        }

        const accessToken = jwt.sign
        (
            {
                name: user.name
            },
            currentKey,
            {
                expiresIn: '20s',
                header:
                {
                    kid: currentKeyID,
                    alg: 'HS256'

                }
            }
        );
        console.log(`Token refresh successful for user: ${user.name} using key ${currentKeyID}`);
        res.json({ accessToken: accessToken})
    })
})

/* *************************************************
* This function authenticates the user and issues
* tokens. First, validates the user, second, ensures
* the key is valid, and then, access token is generated-
* both access and refresh tokens. 


* @param req : request
* @param res : response
* @return : access or refresh token
* @exception : none
* @note : na
* ************************************************* */
app.post('/login', (req, res) => 
{
    const username = req.body.username;
    
    if (!username)
    {
        return res.status(400).json({ error: 'Username is required '})
    }
    
    if (!VALID_USERS.includes(username))
    {
        console.log(`Unauthorized login attempt: ${username}`);
        return res.status(401).json
        ({
            error: 'Unauthorized',
            message: 'Invalid Username'
        });
    }
    
    console.log(`Authorized user: ${username}`);
    const user = { name: username };

    const currentKey = keyStorage.getCurrentKey();
    const activeKeyID = keyStorage.getCurrentKeyID();
    
    if(!currentKey || !activeKeyID)
    {
        console.error('Login failed: No active key available');
        return res.status(500).json({ error: 'Server configuration error - No key available' });
    }

    const keyData = keyStorage.keys.get(currentKeyID);
    if(!keyData || !keyData.isActive || new Date() > keyData.expiresIn)
    {
        console.error('Login failed: Active key is expired');
        return res.status(500).json
        ({ 
            error: 'Key rotation in progress - try again'
        });   
    }

    const accessToken = jwt.sign
    (
        user,
        currentKey,
        {
            expiresIn: '30s',
            header: 
            {
                kid: activeKeyID,
                alg: 'HS256'
            }
        }
    );

    const refreshTokenSecret = process.env.REFRESH_TOKEN_SECRET;
    if(!refreshTokenSecret)
    {
        console.error('REFRESH_TOKEN_SECRET not set in environment');
        return res.status(500).json({ error:' Server Configuration error'});
    }
    const refreshToken = jwt.sign(user, refreshToken, {expiresIn: '7d'});

    res.json
    ({ 
        accessToken: accessToken, 
        refreshToken: refreshToken,
        keyID: activeKeyID,
        keyExpiresIn: keyData.expiresIn,
        tokenExpiresIn: '30 seconds'
    });

});

/* *************************************************
* This function returns posts for the authenticated 
* user.

* @param req : request
* @param res : response
* @return : user posts
* @exception : none
* @note : na
* ************************************************* */
app.get('/posts', authenticateToken, (req, res) => 
{
    console.log('GET /post - User:' , req.user.name);

    const userPosts = getUserPosts(req.user.name);

    res.json(userPosts);    
})

/* *************************************************
* This function successfully rotates the keys 
* previously generated. 

* @param req : request
* @param res : response
* @return : key ID and corresponding message
* @exception : none
* @note : na
* ************************************************* */
app.post('/rotate-keys', (req, res) =>
{
    try
    {
        console.log('Rotating keys:');
        const days = req.body.expiresInDays || 1;
        
        const newKeyID = keyStorage.generateNewKey(days);
        console.log(`New keys generated: ${newKeyID}`);

        const cleanedCount = keyStorage.removeExpiredKeys();
        console.log(`Cleaned up keys : ${cleanedCount}`);

        const activeKeyData = keyStorage.keys.get(keyStorage.activeKeyID);

        res.json
        ({
            success: true,
            message: 'Keys rotated successfully',
            newKeyID: newKeyID,
            activeKeyID: keyStorage.activeKeyID,
            activeKeyExpires: activeKeyData ? activeKeyData.expiresIn : null,
            cleanedupKeys: cleanedCount
        });
    }
    catch(error)
    {
        console.error('Error rotating keys:', error);
        res.status(500).json
        ({
            error: "Failed to rotate keys",
            details: error.message
        });
    }
});

/* *************************************************
* This function accepts two square objects,
*         compares there area and will return 0, 1 ,2.
* 0: they are equal
* 1: the first square is bigger
* 2: the second square is bigger

* @param sq1 : a Square object
* @param sq2 : a Square object
* @return 0,1,2 : which square is bigger
* @exception : none
* @note : na
* ************************************************* */
app.get('/key-status', (req, res) =>
{
    const status = [];
    for (const [id, key] of keyStorage.keys)
    {
        status.push
            ({
            kid: id,
            createdAt: key.createdAt,
            expiresIn: key.expiresIn,
            isActive: key.isActive,
            isCurrent: id === keyStorage.activeKeyID,
            expired: new Date() > key.expiresIn

        });
    }
    res.json(status);

});

/* *************************************************
* This function accepts two square objects,
*         compares there area and will return 0, 1 ,2.
* 0: they are equal
* 1: the first square is bigger
* 2: the second square is bigger

* @param sq1 : a Square object
* @param sq2 : a Square object
* @return 0,1,2 : which square is bigger
* @exception : none
* @note : na
* ************************************************* */
app.get('/health', (req, res) =>
{
    res.json
    ({
        status: 'OK',
        timestamp: new Date(),
        activeKeyID: keyStorage.activeKeyID,
        keyCount: keyStorage.keys.size
    });
});

/* *************************************************
* This function accepts two square objects,
*         compares there area and will return 0, 1 ,2.
* 0: they are equal
* 1: the first square is bigger
* 2: the second square is bigger

* @param sq1 : a Square object
* @param sq2 : a Square object
* @return 0,1,2 : which square is bigger
* @exception : none
* @note : na
* ************************************************* */
app.get('/debug-keys', (req, res) =>
{
    const rawKeys = [];
    for(const [id, key] of keyStorage.keys)
    {
        rawKeys.push
        ({
            id: id,
            fullObject: key
        });
    }
    res.json(rawKeys);
})

/* *************************************************
* This function accepts two square objects,
*         compares there area and will return 0, 1 ,2.
* 0: they are equal
* 1: the first square is bigger
* 2: the second square is bigger

* @param sq1 : a Square object
* @param sq2 : a Square object
* @return 0,1,2 : which square is bigger
* @exception : none
* @note : na
* ************************************************* */
function generateToken(user)
{
    const currentKey = keyStorage.getCurrentKey();
    const currentKeyID = keyStorage.getCurrentKeyID();

    return jwt.sign
    (
        user,
        currentKey,
        {
            expiresIn: '60s',
            header: 
            {
                kid: currentKeyID,
                alg: 'HS256'
            }
        }
    );
}

/* *************************************************
* This function accepts two square objects,
*         compares there area and will return 0, 1 ,2.
* 0: they are equal
* 1: the first square is bigger
* 2: the second square is bigger

* @param sq1 : a Square object
* @param sq2 : a Square object
* @return 0,1,2 : which square is bigger
* @exception : none
* @note : na
* ************************************************* */
app.listen(port, () => 
{
    console.log(`Using authenticateToken from app.js`);

    console.log
    (`
        KeyExpiry server running at http://localhost:${port}
        Available endpoints:
        - GET /health
        - GET /.well-known/jwks.json
        - GET /key-status
        - POST /login
        - POST /token
        - GET /posts
        - POST /rotate-keys
    
    `);
});

module.exports = { app, keyStorage, authenticateToken, posts };