/* *************************************************
*  Name: Gustavo Alatriste
*  Assignment: Project One JWKS server
*  Purpose: Token expiry testing functions
*           using group tests and blocks to 
*           ensure proper POST, GET, token,
*           error, and key (ID) returns 
*           token-expiry.tests.js
************************************************* */


/* *************************************************
*  Importing a local module in both 
*  testing environment and 
*  key testing functions.
************************************************* */

const {request, app } = require('../setup/testsEnvironment');


describe('Token Expiration', () => 
{
    let refreshToken;
    let accessToken;

    beforeAll(async () =>
    {
        const response = await request(app)
            .post('/login')
            .send({ username: 'Nanna'})
            .expect(200);
        
        accessToken = response.body.accessToken;
        refreshToken = response.body.refreshToken;

    })

    test('Reject expired tokens', async () =>
    {               
        await request(app)
            .get('/posts')
            .set('Authorization', `Bearer ${accessToken}`)
            .expect(200);

        await new Promise(resolve => setTimeout(resolve, 31000));
                    
        await request(app)
            .get('/posts')
            .set('Authorization', `Bearer ${accessToken}`)
            .expect(403);
    }, 35000);

    test('Allow refresh token to get new access token', async () =>
    {
        await new Promise(resolve => setTimeout(resolve, 31000));
                    
        const refreshResponse = await request(app)
            .post('/token')
            .send({ token: refreshToken})
            .expect(200);
                    
        expect(refreshResponse.body).toHaveProperty('accessToken');

        await request(app)
            .get('/posts')
            .set('Authorization', `Bearer ${refreshResponse.body.accessToken}`)
            .expect(200);
    }, 35000);
});