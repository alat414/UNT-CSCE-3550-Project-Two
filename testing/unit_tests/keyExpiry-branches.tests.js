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
const { app } = require('../../keyExpiry'); 
const keyStorage = require('../../keyStorage');
const jwt = require('jsonwebtoken');

jest.mock('../../keyStorage',()  => 
    ({
        generateNewKey: jest.fn(),
        getCurrentKey: jest.fn(),
        getCurrentKeyID: jest.fn(),
        getKey: jest.fn(),
        removeExpiredKeys: jest.fn(),
        keys:
        {
            size: 0,
            values: jest.fn().mockReturnValue([]),
            [Symbol.iterator]: jest.fn().mockReturnValue([])
        },
        activeKeyID: null
    }));

describe('keyExpiry.js - Branch Coverage Tests', () =>
{
    beforeEach(() => 
    {
        jest.clearAllMocks();

        jest.spyOn(console, 'error').mockImplementation(() => {});

        keyStorage.getCurrentKey.mockReturnValue('test-secret');
        keyStorage.getCurrentKeyID.mockReturnValue('test-key-id');
        keyStorage.generateNewKey.mockReturnValue('new-key-id');
        keyStorage.removeExpiredKeys.mockReturnValue(0);
    });

    test('POST /token should handle invalid refresh token', async () =>
    {
        jest.spyOn(jwt, 'verify').mockImplementationOnce((token, secret, cb) =>
        {
            cb(new Error('Invalid token'), null);
        })

        await request(app)
            .post('/token')
            .send({ token: 'some-token'})
            .expect(403);
    });

    test('POST /login should handle no key available', async () =>
    {
        keyStorage.getCurrentKey.mockReturnValue(null);

        const response = await request(app)
            .post('/login')
            .send({ username: 'Nanna' })
            .expect(500);

        expect(response.body.error).toBe('No key available');
    });

    test('POST /rotate-keys should handle errors', async () =>
    {
        keyStorage.generateNewKey.mockImplementationOnce( () => 
        {
            throw new Error('Test error');
        });

        const response = await request(app)
            .post('/rotate-keys')
            .send({ expiresInDays: 1 })
            .expect(500);

        expect(response.body.error).toBe('Failed to rotate keys');
    });

    test('GET /key-status should handle empty keys', async () =>
    {
        keyStorage.keys[Symbol.iterator] = jest.fn().mockReturnValue([][Symbol.iterator]());
        const response = await request(app)
            .get('/key-status')
            .expect(200);

        expect(Array.isArray(response.body)).toBe(true);
    });

    test('Function generateToken should handle missing key', async () =>
    {
        keyStorage.getCurrentKey.mockReturnValue(null);

        return request(app)
            .post('/login')
            .send({ username: 'Nanna' })
            .expect(500)
            .then(response => 
            {
                expect(response.body.error).toBe('No key available');
            });
    });

    test('GET /key-status should handle keys with different states', async () =>
    {
        const mockKeys =
        [{
            kid: 'key1',
            createdAt: new Date(),
            expiresIn: new Date(),
            isActive: true,
            isCurrent: true,
            expired: false
        }];

        keyStorage.keys[Symbol.iterator] = jest.fn().mockReturnValue(mockKeys.entries());

        const response = await request(app)
            .get('/key-status')
            .expect(200);

        expect(Array.isArray(response.body)).toBe(true);
    });

    test('POST /token should work with valid refresh token', async () =>
    {
        jest.spyOn(jwt, 'verify').mockImplementationOnce((token, secret, cb) =>
        {
            cb(null, { name: 'Nanna' });
        });

        keyStorage.getCurrentKey.mockReturnValue('valid-secret');
        keyStorage.getCurrentKeyID.mockReturnValue('valid-key-id');

        const response = await request(app)
            .post('/token')
            .send({ token: 'valid.refresh.token' })
            .expect(200);

        expect(response.body).toHaveProperty('accessToken');
    });

    test('POST /rotate-keys should work with valid input', async () =>
    {
        keyStorage.generateNewKey.mockReturnValue('new-key-id');
        keyStorage.removeExpiredKeys.mockReturnValue(1);

        keyStorage.keys.get = jest.fn().mockReturnValue({
            id: 'new-key-id',
            expiresIn: new Date()
        });

        keyStorage.keys[Symbol.iterator] = jest.fn().mockReturnValue([][Symbol.iterator]());

        const response = await request(app)
            .post('/rotate-keys')
            .send({ expiresInDays: 1 })
            .expect(200);

        expect(response.body.success).toBe(true);
        expect(response.body).toHaveProperty('newKeyID');
    });

    afterAll(() => 
    {
        jest.restoreAllMocks();
    })

});