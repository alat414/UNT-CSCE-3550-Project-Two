/* *************************************************
*  Name: Gustavo Alatriste
*  Assignment: Project One JWKS server
*  Purpose: Key Storage testing functions
*           using group tests and blocks to 
*           ensure proper POST, GET, token,
*           error, and key(ID) returns 
*           keyStorage.tests.js
************************************************* */

const request = require('supertest'); 
const jwt = require('jsonwebtoken'); 
const { app, authenticateToken, posts } = require('../../app'); 

jest.mock('../../keyStorage',()  => 
    ({
        getKey: jest.fn(),
    }));

const keyStorage = require('../../keyStorage'); 

describe('app.js - Authentication middleware', () =>
{
    beforeEach(() => 
    {
        jest.clearAllMocks();
    });

    test('Authentication test for handling verification erros', async () =>
    {
        keyStorage.getKey.mockReturnValue('valid-secret');

        const token = jwt.sign(
            { name: 'Nanna' }, 
            'wrong=secret',
            { 
                expiresIn: '15s',
                header: { kid: 'test-key-id', alg: 'HS256' } 
            }
        );

        const response = await request(app)
            .get('/posts')
            .set('Authorization', `Bearer ${token}`)
            .expect(403);

        expect(response.body.error).toBe('Invalid Token');
           
    });

    test('App.js file must successfully export without starting the server', async () =>
    {
        expect(app).toBeDefined();
        expect(authenticateToken).toBeDefined();
        expect(typeof authenticateToken).toBe('function');
        expect(posts).toBeDefined();
        expect(Array.isArray(posts)).toBe(true);
        expect(posts.length).toBe(2);
    });

    test('Should return 401 when token has no key ID', async () =>
    {
        keyStorage.getKey.mockReturnValue(null);

        const token = jwt.sign(
            { name: 'Nanna' }, 
            'some=secret',
            { expiresIn: '15s' }
        );

        const response = await request(app)
            .get('/posts')
            .set('Authorization', `Bearer ${token}`)
            .expect(401);

        expect(response.body.error).toBe('No key ID in token');
           
    });

    test('Should return 401 when signing key is invalid', async () =>
    {
        keyStorage.getKey.mockReturnValue(null);

        const token = jwt.sign(
            { name: 'Nanna' }, 
            'some-secret',
            { 
                expiresIn: '15s',
                header: { kid: 'non-existent-key', alg: 'HS256' } 
            }
        );

        const response = await request(app)
            .get('/posts')
            .set('Authorization', `Bearer ${token}`)
            .expect(401);

        expect(response.body.error).toBe('Key invalid');
        expect(response.body.message).toBe('Token was signed with invalid key, retry.');
    });

    test('Should return 403 for expired token', async () =>
    {
        keyStorage.getKey.mockReturnValue('valid-secret');

        const token = jwt.sign(
            { name: 'Nanna' }, 
            'valid-secret',
            { 
                expiresIn: '-10s',
                header: { kid: 'test-key-id', alg: 'HS256' } 
            }
        );

        const response = await request(app)
            .get('/posts')
            .set('Authorization', `Bearer ${token}`)
            .expect(403);

        expect(response.body.error).toBe('Token Expired');
    });

    test('Should return 200 with posts for valid tokens', async () =>
    {
        keyStorage.getKey.mockReturnValue('valid-secret');

        const token = jwt.sign(
            { name: 'Nanna' }, 
            'valid-secret',
            { 
                expiresIn: '15s',
                header: { kid: 'test-key-id', alg: 'HS256' } 
            }
        );

        const response = await request(app)
            .get('/posts')
            .set('Authorization', `Bearer ${token}`)
            .expect(200);

        expect(Array.isArray(response.body)).toBe(true);
        expect(response.body[0].username).toBe('Nanna');
    });

    test('Should return 401 for malformed authorization header', async () =>
    {
        await request(app)
            .get('/posts')
            .set('Authorization', 'Bearer')
            .expect(401);
    });

    test('Should return 401 for no authorization header', async () =>
    {
        await request(app)
            .get('/posts')
            .expect(401);
    });
});