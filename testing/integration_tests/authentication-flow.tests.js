/* *************************************************
*  Name: Gustavo Alatriste
*  Assignment: Project One JWKS server
*  Purpose: Authentication testing functions
*           using group tests and blocks to 
*           ensure proper POST, GET, token,
*           error, and key (ID) returns 
*           authentication-flow.tests.js
************************************************* */


/* *************************************************
*  Importing a local module in both 
*  testing environment and 
*  key testing functions.
************************************************* */
const request = require('supertest');
const { app } = require('../../keyExpiry');
const { db } = require('../../database');
const jwt = require('jsonwebtoken')


describe('Authentication Flow', () => 
{
    let accessToken;
    let refreshToken;
    let keyID;

    beforeAll(async () => 
    {
        await new Promise((resolve, reject) => 
        {
            db.run(`DELETE FROM keys`, (err) => 
            {
                if (err) 
                {
                    reject(err);
                }
                else 
                {
                    resolve();
                }
            });
        });
    });

    afterAll((done) => 
    {
        db.close(done);
    });

    describe ('POST /login', () =>
    {
        test('Step 1: Health check should confirm server is ready', async () => 
        {
            const response = await request(app)
                .get('/health')
                .expect(200);
            
            expect(response.body.status).toBe('OK');
            expect(response.body).toHaveProperty('activeKeyID');
        });

        test('Step 2: Login with valid credentials should return tokens', async () => 
        {
            const response = await request(app)
                .post('/login')
                .send({ username: 'Nanna' })
                .expect(200);
            
            expect(response.body).toHaveProperty('accessToken');
            expect(response.body).toHaveProperty('refreshToken');
            expect(response.body).toHaveProperty('keyID');
            expect(response.body).toHaveProperty('tokenExpiresIn', '30 seconds');
            expect(response.body).toHaveProperty('algorithm', 'RS256');
            
            accessToken = response.body.accessToken;
            refreshToken = response.body.refreshToken;
            keyID = response.body.keyID;
        });

        test('Must return 200 with proper tokens if the username is valid', async () =>
        {
            for (const username of VALID_USERS)
            {
                const response = await request(app)
                    .post('/login')
                    .send({ username})
                    .expect(200);
                
                expect(response.body).toHaveProperty('accessToken');
                expect(response.body).toHaveProperty('refreshToken');
                expect(response.body).toHaveProperty('keyID');
                expect(response.body).toHaveProperty('keyExpiresIn');

                const tokenParts = response.body.accessToken.split('.');
                expect(tokenParts.length).toBe(3);

                global[`${username}AccessToken`] = response.body.accessToken;
                global[`${username}RefreshToken`] = response.body.refreshToken;
            }
        });
    })

})