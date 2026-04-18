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
});    