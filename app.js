/* *************************************************
*  Name: Gustavo Alatriste
*  Assignment: JWKS Server with key id and token authentication.
*  Purpose: A demonstration of a properly
*           constructed and commented app.js
************************************************* */

require('dotenv').config()


const jwt = require('jsonwebtoken')
const keyStorage = require('./keyStorage');

/* *************************************************
* Post information used for the requests.

* @param sq1 : a square object
* @param sq2 : a square object
* @return : na
* @exception : na
* @note : na
* ************************************************* */
const posts = 
[
    {
        username: 'Nanna',
        title: 'lead singer'
    },
    {
        username: 'Raggi',
        title: 'lead singer two'
    }

]


/* *************************************************
* This function accepts two square objects, compares
* them by calling compareSquares() and prints the answer.
* Since is it a printing function, that is its only job.

* @param sq1 : a square object
* @param sq2 : a square object
* @return : na
* @exception : na
* @note : na
* ************************************************* */
function authenticateToken(req, res, next)
{
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token)
    {
        console.log('Authentiation failed: No token provided');
        return res.status(401).json({
            error: 'Authentication Required',
            message: 'No token provided in the Authoriztion Header'
        });
    }

    try
    {
        const decodedHeader = jwt.decode(token, { complete: true });

        if (!decodedHeader)
        {
            console.log('Authentiation failed: Invalid token format');
            return res.status(401).json({ 
                error: 'Invalid token',
                message: 'Token cannot be decoded' 
            });
        }

        if (!decodedHeader.header || !decodedHeader.header.kid)
        {
            console.log('Authentiation failed: No key ID in the token header');
            return res.status(401).json
            ({ 
                error: 'Invalid token structure',
                message: 'Token missing key ID (kid) in header' 
            });
        }

        const keyID = decodedHeader.header.kid;

        console.log(`Authenticating token with key ID: ${keyID}`);

        const signingKey = keyStorage.getKey(keyID);

        if(!signingKey)
        {
            console.log(`Authenticating token with key ID: ${keyID}`);
            return res.status(401).json
            ({
                error: 'Key invalid',
                message: 'Token was signed with invalid key, retry.'
            });
        }
        jwt.verify(token, signingKey, (err, user) => 
        {
            if (err)
            {
                if (err.name === 'TokenExpiredError')
                {
                    console.log(`Authentication failed: Token expired for key ${keyID}`);
                    return res.status(403).json
                    ({ 
                        error: 'Token Expired',
                        message: 'Your token has expired. Please login again'
                    });
                }

                if (err.name === 'JSONWebTokenError')
                {
                    console.log(`Authentication failed: Invalid signature for key ${keyID}`);
                    return res.status(403).json
                    ({ 
                        error: 'Invalid Token',
                        message: 'Token signature verification failed'
                    });
                }

                // Token is valid.
                console.log(`Authentication successful for user: ${user.name} using key ${keyID}`);
                req.user = user;
                next();

            }
        });
    }
    catch(error)
    {
        console.error('Authentication middleware error failed', error);
        return res.status(500).json
        ({ 
            error: 'Internal Server error',
            message: 'Error processing authentication'
        });
    } 
}

/* *************************************************
* This function accepts two square objects, compares
* them by calling compareSquares() and prints the answer.
* Since is it a printing function, that is its only job.

* @param sq1 : a square object
* @param sq2 : a square object
* @return : na
* @exception : na
* @note : na
* ************************************************* */
module.exports = 
{
    app, 
    authenticateToken,
    posts
}


/* *************************************************
* This function accepts two square objects, compares
* them by calling compareSquares() and prints the answer.
* Since is it a printing function, that is its only job.

* @param sq1 : a square object
* @param sq2 : a square object
* @return : na
* @exception : na
* @note : na
* ************************************************* */
module.exports = 
{
    app, 
    authenticateToken,
    posts
}

