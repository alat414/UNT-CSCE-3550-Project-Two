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

        test('Step 3: Access protected endpoint with valid token', async () => 
        {
            const response = await request(app)
                .get('/posts')
                .set('Authorization', `Bearer ${accessToken}`)
                .expect(200);
            
            expect(Array.isArray(response.body)).toBe(true);
            expect(response.body.length).toBeGreaterThan(0);
            expect(response.body[0]).toHaveProperty('username', 'Nanna');
            expect(response.body[0]).toHaveProperty('title');
        });

        test('Step 4: Different user should see their own posts', async () => 
        {
            const loginResponse = await request(app)
                .post('/login')
                .send({ username: 'Raggi' })
                .expect(200);
            
            const raggiToken = loginResponse.body.accessToken;
            
            const response = await request(app)
                .get('/posts')
                .set('Authorization', `Bearer ${raggiToken}`)
                .expect(200);
            
            expect(response.body[0]).toHaveProperty('username', 'Raggi');
        });

        test('Step 5: Invalid token should be rejected', async () => 
        {
            await request(app)
                .get('/posts')
                .set('Authorization', 'Bearer invalid.token.here')
                .expect(403);
        });

        test('Step 6: Missing token should be rejected', async () => 
        {
            await request(app)
                .get('/posts')
                .expect(401);
        });
    })

    describe ('Multiple User Sessions', () =>
    {
        test('Multiple users can authenticate simultaneously', async () => 
        {
            const users = ['Nanna', 'Raggi'];
            const tokens = [];
            
            for (const user of users) 
            {
                const response = await request(app)
                    .post('/login')
                    .send({ username: user })
                    .expect(200);
                
                tokens.push(response.body.accessToken);
            }
            
            for (let i = 0; i < tokens.length; i++) 
            {
                const response = await request(app)
                    .get('/posts')
                    .set('Authorization', `Bearer ${tokens[i]}`)
                    .expect(200);
                
                expect(response.body[0].username).toBe(users[i]);
            }
        });
    })
})