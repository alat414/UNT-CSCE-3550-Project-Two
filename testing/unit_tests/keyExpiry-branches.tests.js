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
const { db } = require('../../database');
const { run } = require('jest');

jest.mock('../../keyStorage',()  => 
({
    generateNewKey: jest.fn(),
    getCurrentKey: jest.fn(),
    getCurrentKeyID: jest.fn(),
    getCurrentPrivateKey: jest.fn(),
    getCurrentPublicKey: jest.fn(),
    getPrivateKey: jest.fn(),
    getPublicKey: jest.fn(),
    getKey: jest.fn(),
    getKeyData: jest.fn(),
    removeExpiredKeys: jest.fn(),
    getActiveKeys: jest.fn(),
    getAllKeys: jest.fn(),
    setActiveKey: jest.fn(),
    deactivateKey: jest.fn(),
    activeKeyID: null,
    initialized: true
}));

jest.mock('../../database',()  => 
({  db:
    {
        get: jest.fn(),
        run: jest.fn(),
        all: jest.fn(),
        close: jest.fn(),
    }   
}));

describe('keyExpiry.js - Comprehensive Tests', () =>
{
    let consoleErrorSpy;
    let consoleLogSpy;

    beforeEach(() => 
    {
        jest.clearAllMocks();

        consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
        consoleLogSpy = jest.spyOn(console, 'error').mockImplementation(() => {});

        keyStorage.getCurrentPrivateKey.mockResolvedValue('-----BEGIN RSA PRIVATE KEY-----\nmock-private-key\n-----END RSA PRIVATE KEY-----');
        keyStorage.getCurrentKeyID.mockReturnValue('test-rsa-key-id');
        keyStorage.getCurrentKey.mockResolvedValue('mock-private-key');
        keyStorage.generateNewKey.mockResolvedValue('new-rsa-key-id');
        keyStorage.removeExpiredKeys.mockResolvedValue(0);
        keyStorage.getActiveKeys.mockResolvedValue([
            {
                kid:'test-rsa-key-id',
                kty: 'RSA',
                alg: 'RS256',
                use: 'sig',
                n: 'mock-modulus',
                e: 'AQAB',
                exp: Math.floor(Date.now() / 1000) + 86400
            }
        ]);

        keyStorage.getAllKeys.mockResolvedValue([]);
        keyStorage.getKeyData.mockResolvedValue({
            kid: 'test-rsa-key-id',
            privateKey: 'mock-private-key',
            publicKey: 'mock-public-key',
            isActive: 1,
            expiresIn: new Date(Date.now() + 86400000).toISOString()
        });
    });

    afterEach(() => {
        consoleErrorSpy.mockRestore();
        consoleLogSpy.mockRestore();
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