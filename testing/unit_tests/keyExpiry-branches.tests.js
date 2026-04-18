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
    getKeyData: jest.fn(),
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

        const mockPrivateKey = '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAokYPxwi90/SFvu6TL\n-----END RSA PRIVATE KEY-----';
        const mockPublicKey = '-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEAokYPxwi90/SFvu6TL\n-----END RSA PUBLIC KEY-----';

        const mockKeyData = {
            kid: 'test-rsa-key-id',
            privateKey: mockPrivateKey,
            publicKey: mockPublicKey,
            createdAt: new Date().toISOString(),
            expiresIn: new Date(Date.now() + 86400000).toISOString(),
            isActive: 1
        };

        keyStorage.getCurrentPrivateKey.mockResolvedValue(mockPrivateKey);
        keyStorage.getCurrentPublicKey.mockResolvedValue(mockPublicKey);
        keyStorage.getCurrentKeyID.mockReturnValue('test-rsa-key-id');
        keyStorage.getCurrentKey.mockResolvedValue(mockPrivateKey);
        keyStorage.generateNewKey.mockResolvedValue('new-rsa-key-id');
        keyStorage.removeExpiredKeys.mockResolvedValue(0);
        keyStorage.getKeyData.mockResolvedValue(mockKeyData);
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
        keyStorage.getAllKeys.mockResolvedValue({
            kid: 'test-rsa-key-id',
            privateKey: mockPrivateKey,
            publicKey: mockPublicKey,
            createdAt: new Date().toISOString(),
            expiresIn: new Date(Date.now() + 86400000).toISOString(),
            isActive: 1
        });
        keyStorage.getPrivateKey.mockResolvedValue(mockPrivateKey);
        keyStorage.getPublicKey.mockResolvedValue(mockPublicKey);
        keyStorage.getKey.mockResolvedValue(mockPrivateKey);
    });

    afterEach(() => {
        consoleErrorSpy.mockRestore();
        consoleLogSpy.mockRestore();
    });

    describe('GET /health', () => 
    {
        test('Should return health status with active key information', async () =>
        {
            const response = await request(app)
                .get('/health')
                .expect(200);

            expect(response.body).toHaveProperty('status', 'OK');
            expect(response.body).toHaveProperty('timestamp');
            expect(response.body).toHaveProperty('activeKeyID', 'test-rsa-key-id');
            expect(response.body).toHaveProperty('keyCount');
            expect(response.body).toHaveProperty('activeKeyValid');
            expect(response.body).toHaveProperty('uptime');
            expect(response.body).toHaveProperty('database', 'SQLite (jwks-server.db)');
        });

        test('should handle errors when getting active keys', async () =>
        {
            keyStorage.getActiveKeys.mockRejectedValueOnce(new Error ('Database error'));

            const response = await request(app)
                .get('/.well-known/jwks.json')
                .expect(500);

            expect(response.body).toHaveProperty('error');
        });

    });

    describe('POST /login', () => 
    {
        test('Should successfully login with valid username', async () =>
        {
            const response = await request(app)
                .postt('/login')
                .send({ username: 'Nanna'})
                .expect(200);

            expect(response.body).toHaveProperty('accessToken');
            expect(response.body).toHaveProperty('refreshToken');
            expect(response.body).toHaveProperty('keyID');
            expect(response.body).toHaveProperty('keyExpiresIn');
            expect(response.body).toHaveProperty('tokenExpiresIn', '30 seconds');
            expect(response.body).toHaveProperty('algorithm', 'RS256');
        });

        test('should return 400 when username is missing', async () =>
        {
            const response = await request(app)
                .post('/login')
                .send({})
                .expect(400);

            expect(response.body).toHaveProperty('error', 'Username is required');
        });

        test('should return 401 when username is invalid', async () =>
        {
            const response = await request(app)
                .post('/login')
                .send({ username: 'InvalidUser'})
                .expect(401);

            expect(response.body).toHaveProperty('error', 'Unauthorized');
            expect(response.body).toHaveProperty('message', 'Invalid Username');
        });

        test('Should return 500 when no active key available', async () =>
        {
            keyStorage.getCurrentPrivateKey.mockResolvedValueOnce(null);
            keyStorage.getCurrentKeyID.mockResolvedValueOnce(null);

            const response = await request(app)
                .post('/login')
                .send({ username: 'Nanna'})
                .expect(500);

            expect(response.body).toHaveProperty('error', 'Server Configuration error- No key available');
        });

    

        test('should return 500 when key is expired', async () =>
        {
            keyStorage.getKeyData.mockResolvedValueOnce(  
            {
                isActive: 0,
                expiresIn: new Date(Date.now() - 86400000).toISOString()
            });

            const response = await request(app)
                .post('/login')
                .send({ username: 'Nanna' })
                .expect(500);

            expect(response.body).toHaveProperty('error', 'Key Rotation in progress - please try again');
        });

        

        test('should return 500 when REFRESH_TOKEN_SECRET is not set', async () =>
        {
            const originalSecret = process.env.REFRESH_TOKEN_SECRET;
            delete process.env.REFRESH_TOKEN_SECRET;

            const response = await request(app)
                .post('/login')
                .send({ username: 'Nanna' })
                .expect(500);

            expect(response.body).toHaveProperty('error', 'Server Configuration Error');

            process.env.REFRESH_TOKEN_SECRET = originalSecret;

        });

    });

    describe('GET /key-status', () => 
    {
        test('Should return key status information', async () =>
        {
            const mockKeys = [
                {   
                    kid: 'key1',
                    createdAt: new Date().toISOString(),
                    expiresIn: new Date(Date.now() + 86400000).toISOString(),
                    isActive: 1
                }
            ];

            keyStorage.getAllKeys.mockResolvedValueOnce(mockKeys);

            const response = await request(app)
                .get('/key-status')
                .expect(200);

            expect(Array.isArray(response.body)).toBe(true);
            
        });

        test('should handle errors', async () =>
        {
            keyStorage.getAllKeys.mockRejectedValueOnce(new Error ('Database error'));

            const response = await request(app)
                .get('/key-status')
                .expect(500);

            expect(response.body).toHaveProperty('error', 'Internal Server Error');
        });

    });

    describe('GET /debug-keys', () => 
    {
        test('Should return debug key information', async () =>
        {
            const mockKeys = [
                {   
                    kid: 'debug-key-1',
                    secret: 'mock-secret-12345678901234567890',
                    createdAt: new Date().toISOString(),
                    expiresIn: new Date(Date.now() + 86400000).toISOString(),
                    isActive: 1
                }
            ];

            keyStorage.getAllKeys.mockResolvedValueOnce(mockKeys);

            const response = await request(app)
                .get('/debug-keys')
                .expect(200);

            expect(Array.isArray(response.body)).toBe(true);
            
        });

        test('should handle errors', async () =>
        {
            keyStorage.getAllKeys.mockRejectedValueOnce(new Error ('Database error'));

            const response = await request(app)
                .get('/debug-keys')
                .expect(500);

            expect(response.body).toHaveProperty('error', 'Internal Server Error');
        });
    });

    describe('GET /debug-key-status', () => 
    {
        test('Should return detailed key status', async () =>
        {
            const response = await request(app)
                .get('/debug-key-status')
                .expect(200);

            expect(response.body).toHaveProperty('currentTime');
            expect(response.body).toHaveProperty('totalKeys');
            expect(response.body).toHaveProperty('keys');
            expect(response.body).toHaveProperty('activeKeyCount');
        });
    });
});