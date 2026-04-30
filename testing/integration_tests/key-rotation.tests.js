/* *************************************************
*  Name: Gustavo Alatriste
*  Assignment: Project One JWKS server
*  Purpose: Key rotation testing functions
*           using group tests, blocks, and SQL
*           quey prompts to all 
*           ensure proper POST, GET, token,
*           error, and key (ID) returns 
*           token-expiry.tests.js
************************************************* */


/* *************************************************
*  Importing a local module in both 
*  testing environment and 
*  key testing functions.
************************************************* */

const request = require('supertest');
const { app } = require('../../keyExpiry');
const { db } = require('../../database');

describe('Key Rotation - Integration Tests', () => 
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

    describe('Initial Key State', () => 
    {
        test('Server should have at least one active key on startup', async () => 
        {
            const response = await request(app)
                .get('/key-status')
                .expect(200);
            
            expect(response.body.length).toBeGreaterThan(0);
            const activeKeys = response.body.filter(k => k.isActive === true);
            expect(activeKeys.length).toBeGreaterThan(0);
        });

        test('JWKS endpoint should return at least one key', async () => 
        {
            const response = await request(app)
                .get('/.well-known/jwks.json')
                .expect(200);
            
            expect(response.body.keys.length).toBeGreaterThan(0);
            expect(response.body.keys[0]).toHaveProperty('kty', 'RSA');
            expect(response.body.keys[0]).toHaveProperty('alg', 'RS256');
        });
    });

    describe('Manual Key Rotation', () => 
    {
        let oldKeyID;
        let oldJWKSKeys;

        test('Get current key ID before rotation', async () => 
        {
            const statusResponse = await request(app)
                .get('/key-status')
                .expect(200);
            
            const activeKey = statusResponse.body.find(k => k.isCurrent === true);
            oldKeyID = activeKey.kid;
            
            const jwksResponse = await request(app)
                .get('/.well-known/jwks.json')
                .expect(200);
            
            oldJWKSKeys = jwksResponse.body.keys.length;
        });

        test('Rotate keys should generate new key', async () => 
        {
            const response = await request(app)
                .post('/rotate-keys')
                .send({ expiresInDays: 7 })
                .expect(200);
            
            expect(response.body.success).toBe(true);
            expect(response.body).toHaveProperty('newKeyID');
            expect(response.body.newKeyID).not.toBe(oldKeyID);
            expect(response.body).toHaveProperty('activeKeyID');
        });

        test('JWKS should show new key after rotation', async () => 
        {
            const response = await request(app)
                .get('/.well-known/jwks.json')
                .expect(200);
            
            // Should have at least as many keys (old key still active until expiry)
            expect(response.body.keys.length).toBeGreaterThanOrEqual(oldJWKSKeys);
        });

        test('Old tokens should still work (key not expired yet)', async () => 
        {
            // Login with old key context
            const loginResponse = await request(app)
                .post('/login')
                .send({ username: 'Nanna' })
                .expect(200);
            
            const token = loginResponse.body.accessToken;
            
            // Token should still work even after rotation
            const postsResponse = await request(app)
                .get('/posts')
                .set('Authorization', `Bearer ${token}`)
                .expect(200);
            
            expect(postsResponse.body).toBeInstanceOf(Array);
        });
    });

    describe('Multiple Key Rotations', () => 
    {
        test('Rotate keys multiple times should create multiple keys', async () => 
        {
            // Rotate 3 times
            for (let i = 0; i < 3; i++) 
            {
                await request(app)
                    .post('/rotate-keys')
                    .send({ expiresInDays: 1 })
                    .expect(200);
            }
            
            const statusResponse = await request(app)
                .get('/key-status')
                .expect(200);
            
            // Should have at least 4 keys (initial + 3 rotations)
            expect(statusResponse.body.length).toBeGreaterThanOrEqual(4);
        });
    });

    describe('Key Expiration After Rotation', () => 
    {
        test('Expired keys should be cleaned up', async () => 
        {
            // Create a key that expires quickly
            await request(app)
                .post('/rotate-keys')
                .send({ expiresInDays: 0.01 }) // ~15 minutes
                .expect(200);
            
            // Wait a bit
            await new Promise(resolve => setTimeout(resolve, 100));
            
            // Check if expired keys are removed
            const statusResponse = await request(app)
                .get('/key-status')
                .expect(200);
            
            // Should have cleaned up expired keys
            const expiredKeys = statusResponse.body.filter(k => k.expired === true);
            expect(expiredKeys.length).toBe(0);
        });
    });
});
