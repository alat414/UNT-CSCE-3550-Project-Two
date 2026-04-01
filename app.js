/* *************************************************
*  Name: Gustavo Alatriste
*  Assignment: Demonstration Code
*  Purpose: A demonstration of a properly
*           constructed and commented functions.cpp
************************************************* */

require('dotenv').config()

const express = require('express');
const app = express();
const port = 8080;
const jwt = require('jsonwebtoken')
const keyStorage = require('./keyStorage');

app.use(express.json())
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
app.get('/posts', authenticateToken, (req, res) => 
{
    res.json(posts.filter(post => post.username === req.user.name));

});

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
app.post('/login', (req, res) => 
{
    const username = req.body.username
    const user = { name: username }

    const accessToken = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '15s'})
    res.json({ accessToken: accessToken});

});

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
    
    if (token == null) return res.sendStatus(401);

    const decodedHeader = jwt.decode(token, { complete: true });

    if (!decodedHeader || !decodedHeader.header || !decodedHeader.header.kid)
    {
        return res.status(401).json({ error: 'No key ID in token' });
    }

    const keyID = decodedHeader.header.kid;

    const signingKey = keyStorage.getKey(keyID);

    if(!signingKey)
    {
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
                return res.status(403).json({ error: 'Token Expired'});
            }
            return res.status(403).json({ error: 'Invalid Token'});

        } 
        
        console.log(`Token is verified for user: ${user.name}`);
        req.user = user;
        next();
    });

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

