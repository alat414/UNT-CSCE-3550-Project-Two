/* *************************************************
*  Name: Gustavo Alatriste
*  Assignment: Project One JWKS server
*  Purpose: Token refresh testing functions
*           using group tests and blocks to 
*           ensure all callbacks and responses
*           are adequate and reflective of functions
*           token-expiry.tests.js
************************************************* */


/* *************************************************
*  Importing a local module in both 
*  testing environment and 
*  key testing functions.
************************************************* */

const request = require('supertest');
const { app } = require('../../keyExpiry');

describe('Token Refresh - Integration Tests', () => {
    let refreshToken;
    let accessToken;

    beforeAll(async () => 
    {
        const loginResponse = await request(app)
            .post('/login')
            .send({ username: 'Nanna' })
            .expect(200);
        
        accessToken = loginResponse.body.accessToken;
        refreshToken = loginResponse.body.refreshToken;
    });

    describe('Successful Refresh Flow', () => 
    {
        test('Refresh token should return new access token', async () => 
        {
            const response = await request(app)
                .post('/token')
                .send({ token: refreshToken })
                .expect(200);
            
            expect(response.body).toHaveProperty('accessToken');
            expect(response.body.accessToken).not.toBe(accessToken);
        });

        test('New access token should work for protected endpoints', async () => 
        {
            const refreshResponse = await request(app)
                .post('/token')
                .send({ token: refreshToken })
                .expect(200);
            
            const newAccessToken = refreshResponse.body.accessToken;
            
            const postsResponse = await request(app)
                .get('/posts')
                .set('Authorization', `Bearer ${newAccessToken}`)
                .expect(200);
            
            expect(postsResponse.body).toBeInstanceOf(Array);
        });

        test('Multiple refreshes should work sequentially', async () => 
        {
            let currentToken = refreshToken;
            
            for (let i = 0; i < 3; i++) 
            {
                const response = await request(app)
                    .post('/token')
                    .send({ token: currentToken })
                    .expect(200);
                
                expect(response.body).toHaveProperty('accessToken');
                currentToken = response.body.accessToken;
            }
        });
    });

    describe('Refresh Token Edge Cases', () => 
    {
        test('Empty token should return 401', async () => 
        {
            const response = await request(app)
                .post('/token')
                .send({ token: '' })
                .expect(401);
            
            expect(response.body.error).toBe('Refresh token required');
        });

        test('Null token should return 401', async () => 
        {
            const response = await request(app)
                .post('/token')
                .send({ token: null })
                .expect(401);
            
            expect(response.body.error).toBe('Refresh token required');
        });

        test('Malformed refresh token should return 403', async () => 
        {
            const response = await request(app)
                .post('/token')
                .send({ token: 'malformed-token' })
                .expect(403);
            
            expect(response.body.error).toBe('Invalid refresh token');
        });

        test('Tampered refresh token should return 403', async () => 
        {
            const tamperedToken = refreshToken.slice(0, -5) + 'xxxxx';
            
            const response = await request(app)
                .post('/token')
                .send({ token: tamperedToken })
                .expect(403);
            
            expect(response.body.error).toBe('Invalid refresh token');
        });
    });

    describe('Refresh with Expired Access Token', () => 
    {
        test('Should be able to refresh after access token expires', async () => 
        {
            // Wait for access token to expire
            await new Promise(resolve => setTimeout(resolve, 31000));
            
            // Access token should be expired
            await request(app)
                .get('/posts')
                .set('Authorization', `Bearer ${accessToken}`)
                .expect(403);
            
            // Refresh should still work
            const refreshResponse = await request(app)
                .post('/token')
                .send({ token: refreshToken })
                .expect(200);
            
            expect(refreshResponse.body).toHaveProperty('accessToken');
        }, 35000);
    });

    describe('Concurrent Refresh Requests', () => 
    {
        test('Multiple simultaneous refresh requests should all succeed', async () => 
        {
            const refreshPromises = [];
            
            for (let i = 0; i < 5; i++) 
            {
                refreshPromises.push(
                    request(app)
                        .post('/token')
                        .send({ token: refreshToken })
                        .expect(200)
                );
            }
            
            const responses = await Promise.all(refreshPromises);
            
            responses.forEach(response => {
                expect(response.body).toHaveProperty('accessToken');
            });
        });
    });
})