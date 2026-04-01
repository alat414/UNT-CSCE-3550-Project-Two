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

describe('Token Refresh testing', () => 
{
    let refreshToken;
    let accessToken;

    beforeAll(async () =>
    {
        const response = await request(app)
            .post('/login')
            .send({ username: 'Nanna'});
        
        accessToken = response.body.accessToken;
        refreshToken = response.body.refreshToken;

    });

    test('POST /token with valid refresh token returns new access token', async () =>
    {
        const response = await request(app)
            .post('/token')
            .send({ token: refreshToken})
            .expect(200);

        expect(response.body).toHaveProperty('accessToken');
        expect(response.body.accessToken).not.toBe(accessToken);

    });

    test('POST /token with invalid refresh token returns 403', async () =>
    {
        await request(app)
            .post('/token')
            .send({ token: 'invalid.refresh.token'})
            .expect(403);
    });

    

    test('POST /token without token returns 401', async () =>
    {
        await request(app)
            .post('/token')
            .send({})
            .expect(401);
    });

    test('New accesstoken from refresh call must work for post requests', async () =>
    {
        const refreshResponse = await request(app)
            .post('/token')
            .send({ token: refreshToken})
            .expect(200);

        const newToken  = refreshResponse.body.accessToken;

        await request(app)
            .get('/posts')
            .set({ 'Authorization': `Bear ${newToken}`})
            .expect(200);
    });
});