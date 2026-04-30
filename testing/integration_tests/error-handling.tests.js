/* *************************************************
*  Name: Gustavo Alatriste
*  Assignment: Project One JWKS server
*  Purpose: Error handling testing functions
*           using group tests and blocks to 
*           ensure proper POST, GET, token,
*           error, and key (ID) returns 
*           error-handling.tests.js
************************************************* */


/* *************************************************
*  Importing a local module in  
*  key testing functions.
************************************************* */

const request = require('supertest');
const { app } = require('../../keyExpiry');
const { db } = require('../../database');


describe('Error Handling - Integration Tests', () => 
{
    beforeAll(async () => 
    {
        await new Promise((resolve, reject) => 
        {
            db.run(`DELETE FROM keys`, (err) => 
            {
                if (err) reject(err);
                else resolve();
            });
        });
    });

    afterAll((done) => 
    {
        db.close(done);
    });

    describe('Login Endpoint Errors', () => 
    {
        test('Missing username should return 400', async () => 
        {
            const response = await request(app)
                .post('/login')
                .send({})
                .expect(400);
            
            expect(response.body.error).toBe('Username is required');
        });

        test('Empty username should return 400', async () => 
        {
            const response = await request(app)
                .post('/login')
                .send({ username: '' })
                .expect(400);
            
            expect(response.body.error).toBe('Username is required');
        });

        test('Invalid username should return 401', async () => 
        {
            const response = await request(app)
                .post('/login')
                .send({ username: 'Hacker' })
                .expect(401);
            
            expect(response.body.error).toBe('Unauthorized');
            expect(response.body.message).toBe('Invalid Username');
        });

        test('Case-sensitive username should work with exact case', async () => 
        {
            const response = await request(app)
                .post('/login')
                .send({ username: 'nanna' })
                .expect(200);
            
            expect(response.body).toHaveProperty('accessToken');
        });
    });

    describe('Token Endpoint Errors', () => 
    {
        test('Missing token should return 401', async () => 
        {
            const response = await request(app)
                .post('/token')
                .send({})
                .expect(401);
            
            expect(response.body.error).toBe('Refresh token required');
        });

        test('Invalid token format should return 403', async () => 
        {
            const response = await request(app)
                .post('/token')
                .send({ token: 'not.a.valid.jwt' })
                .expect(403);
            
            expect(response.body.error).toBe('Invalid refresh token');
        });

        test('Malformed JSON should return 400', async () => 
        {
            await request(app)
                .post('/token')
                .set('Content-Type', 'application/json')
                .send('{invalid json}')
                .expect(400);
        });
    });

    describe('Protected Endpoint Errors', () => {
        test('No Authorization header should return 401', async () => 
        {
            const response = await request(app)
                .get('/posts')
                .expect(401);
            
            expect(response.body.error).toBe('Authentication Required');
        });

        test('Wrong token type (Bearer missing) should return 401', async () => 
        {
            const response = await request(app)
                .get('/posts')
                .set('Authorization', 'some-token')
                .expect(401);
            
            expect(response.body.error).toBe('Authentication Required');
        });

        test('Expired token should return 403', async () => 
        {
            // This test requires waiting or mocking time
            const loginResponse = await request(app)
                .post('/login')
                .send({ username: 'Nanna' })
                .expect(200);
            
            const token = loginResponse.body.accessToken;
            
            // Wait for token to expire (30 seconds)
            await new Promise(resolve => setTimeout(resolve, 31000));
            
            const response = await request(app)
                .get('/posts')
                .set('Authorization', `Bearer ${token}`)
                .expect(403);
            
            expect(response.body.error).toBe('Token Expired');
        }, 35000);
    });

    describe('Key Rotation Endpoint Errors', () => 
    {
        test('Invalid expiresInDays should use default', async () => 
        {
            const response = await request(app)
                .post('/rotate-keys')
                .send({ expiresInDays: 'invalid' })
                .expect(200);
            
            expect(response.body.success).toBe(true);
        });

        test('Negative expiresInDays should be clamped to 1', async () => 
        {
            const response = await request(app)
                .post('/rotate-keys')
                .send({ expiresInDays: -5 })
                .expect(200);
            
            expect(response.body.success).toBe(true);
        });
    });

    describe('Non-existent Endpoints', () => 
    {
        test('GET /non-existent should return 404', async () => 
        {
            await request(app)
                .get('/non-existent-endpoint')
                .expect(404);
        });

        test('POST /non-existent should return 404', async () => 
        {
            await request(app)
                .post('/api/unknown')
                .send({ data: 'test' })
                .expect(404);
        });
    });
});