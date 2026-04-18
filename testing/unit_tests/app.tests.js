/* *************************************************
*  Name: Gustavo Alatriste
*  Assignment: Project One JWKS server
*  Purpose: Testing middleware functions
*           using functions, calls, and returns
*           to ensure functionality.
*           app.tests.js
************************************************* */

const jwt = require('jsonwebtoken');
const keyStorage = require('../../keyStorage');

// Mock keyStorage
jest.mock('../../keyStorage', () => 
({
    getKey: jest.fn(),
    getPublicKey: jest.fn(),
    getCurrentKeyID: jest.fn(),
    activeKeyID: null
}));


const { authenticateToken, getUserPosts, posts } = require('../../app');

describe('app.js - Authentication middleware', () =>
{
    let req, res, next;

    beforeEach(() => 
    {
        jest.clearAllMocks();

        req = 
        {
            headers: {},
            user: null
        };
        res = 
        {
            status: jest.fn().mockReturnThis(),
            json: jest.fn().mockReturnThis(),
            sendStatus: jest.fn().mockReturnThis()
        };

        next = jest.fn();

    });

    describe('authenticationToken Middleware', () =>{
        test('should return 401 when no token provided', () => 
        {
            req.headers.authorization = null;
            
            authenticateToken(req, res, next);
            
            expect(res.status).toHaveBeenCalledWith(401);
            expect(res.json).toHaveBeenCalledWith
            ({
                error: 'Authentication Required',
                message: 'No token provided in the Authorization Header'
            });
            expect(next).not.toHaveBeenCalled();
        });

        test('should return 401 when token has invalid format', () => 
        {
            req.headers.authorization = 'InvalidFormat';
            
            authenticateToken(req, res, next);
            
            expect(res.status).toHaveBeenCalledWith(401);
            expect(res.json).toHaveBeenCalledWith
            ({
                error: 'Authentication Required',
                message: 'No token provided in the Authorization Header'
            });
        });

        test('Should return 401 when token has no key ID in header', async () =>
        {
            const token = jwt.sign({ name: 'Nanna' }, 'secret');
            req.headers.authorization = `Bearer ${token}`;
            
            authenticateToken(req, res, next);
            
            expect(res.status).toHaveBeenCalledWith(401);
            expect(res.json).toHaveBeenCalledWith
            ({
                error: 'Invalid token structure',
                message: 'Token missing key ID (kid) in header'
            });

            
        });

        test('should return 401 when key ID not found', () => 
        {
            const token = jwt.sign({ name: 'Nanna' }, 'secret', {
                header: { kid: 'non-existent-key', alg: 'RS256' }
            });
            req.headers.authorization = `Bearer ${token}`;
            
            keyStorage.getPublicKey.mockResolvedValue(null);
            
            // Need to handle async middleware
            const promise = new Promise((resolve) => 
            {
                authenticateToken(req, res, (err) => 
                {
                    resolve();
                });
            });
            
            return promise.then(() => 
            {
                expect(res.status).toHaveBeenCalledWith(401);
                expect(res.json).toHaveBeenCalledWith
                ({
                    error: 'Key invalid',
                    message: 'Token was signed with invalid key, retry.'
                });
            });
        });


        test('should call next() when token is valid', async () => 
        {
            const mockPublicKey = '-----BEGIN RSA PUBLIC KEY-----\nmock\n-----END RSA PUBLIC KEY-----';
            const token = jwt.sign({ name: 'Nanna' }, 'private-key', {
                header: { kid: 'valid-key', alg: 'RS256' }
            });
            req.headers.authorization = `Bearer ${token}`;
            
            keyStorage.getPublicKey.mockResolvedValue(mockPublicKey);
            
            // Mock jwt.verify to succeed
            jest.spyOn(jwt, 'verify').mockImplementation((token, key, cb) => 
            {
                cb(null, { name: 'Nanna' });
            });
            
            await new Promise((resolve) => 
            {
                authenticateToken(req, res, () => 
                {
                    expect(next).toHaveBeenCalled();
                    expect(req.user).toBeDefined();
                    resolve();
                });
            });
        });

    });

    describe('authenticationToken Middleware', () =>{
        test('should return 401 when no token provided', () => 
        {
            req.headers.authorization = null;
            
            authenticateToken(req, res, next);
            
            expect(res.status).toHaveBeenCalledWith(401);
            expect(res.json).toHaveBeenCalledWith
            ({
                error: 'Authentication Required',
                message: 'No token provided in the Authorization Header'
            });
            expect(next).not.toHaveBeenCalled();
        });

        test('should return 401 when token has invalid format', () => 
        {
            req.headers.authorization = 'InvalidFormat';
            
            authenticateToken(req, res, next);
            
            expect(res.status).toHaveBeenCalledWith(401);
            expect(res.json).toHaveBeenCalledWith
            ({
                error: 'Authentication Required',
                message: 'No token provided in the Authorization Header'
            });
        });

        test('Should return 401 when token has no key ID in header', async () =>
        {
            const token = jwt.sign({ name: 'Nanna' }, 'secret');
            req.headers.authorization = `Bearer ${token}`;
            
            authenticateToken(req, res, next);
            
            expect(res.status).toHaveBeenCalledWith(401);
            expect(res.json).toHaveBeenCalledWith
            ({
                error: 'Invalid token structure',
                message: 'Token missing key ID (kid) in header'
            });

            
        });

        test('should return 401 when key ID not found', () => 
        {
            const token = jwt.sign({ name: 'Nanna' }, 'secret', {
                header: { kid: 'non-existent-key', alg: 'RS256' }
            });
            req.headers.authorization = `Bearer ${token}`;
            
            keyStorage.getPublicKey.mockResolvedValue(null);
            
            // Need to handle async middleware
            const promise = new Promise((resolve) => 
            {
                authenticateToken(req, res, (err) => 
                {
                    resolve();
                });
            });
            
            return promise.then(() => 
            {
                expect(res.status).toHaveBeenCalledWith(401);
                expect(res.json).toHaveBeenCalledWith
                ({
                    error: 'Key invalid',
                    message: 'Token was signed with invalid key, retry.'
                });
            });
        });


        test('should call next() when token is valid', async () => 
        {
            const mockPublicKey = '-----BEGIN RSA PUBLIC KEY-----\nmock\n-----END RSA PUBLIC KEY-----';
            const token = jwt.sign({ name: 'Nanna' }, 'private-key', {
                header: { kid: 'valid-key', alg: 'RS256' }
            });
            req.headers.authorization = `Bearer ${token}`;
            
            keyStorage.getPublicKey.mockResolvedValue(mockPublicKey);
            
            // Mock jwt.verify to succeed
            jest.spyOn(jwt, 'verify').mockImplementation((token, key, cb) => 
            {
                cb(null, { name: 'Nanna' });
            });
            
            await new Promise((resolve) => 
            {
                authenticateToken(req, res, () => 
                {
                    expect(next).toHaveBeenCalled();
                    expect(req.user).toBeDefined();
                    resolve();
                });
            });
        });

    });
});    