/* *************************************************
*  Name: Gustavo Alatriste
*  Assignment: Project One JWKS server
*  Purpose: Error handling testing functions
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

const {request, app } = require('../setup/testsEnvironment');

const jwt = require('jsonwebtoken');


describe('Error Handling Flow', () => 
{
   
    test('GET /posts return 401 for malformed tokens', async () =>
    {
        await request(app)
            .get('/posts')
            .set('Authorization', 'Bearer malformed.token.here')
            .expect(401);
    });

    test('GET /posts return 401 for tokens with missing kid in header', async () =>
    {
        const token = jwt.sign(   
            { name: 'Nanna' },
            'some-secret',
            { expiresIn: '30s' }
        );
        await request(app)
            .get('/posts')
            .set('Authorization', `Bearer ${token}`)
            .expect(401);
    });

    test('GET /posts return 401 for an expired keyID', async () =>
    {
        const token = jwt.sign(   
            { name: 'Nanna' },
            'some-secret',
            {
                expiresIn: '30s',
                header: { kid: 'non-existent-key', alg: 'HS256'}
            }
        );
        await request(app)
            .get('/posts')
            .set('Authorization', `Bearer ${token}`)
            .expect(401);
    });

    test('POST /token return 403 for malformed refresh tokens', async () =>
    {
        await request(app)
            .post('/token')
            .send({ token: 'malformed.refresh.token' })
            .expect(403);
    });

    test('POST /login return 401 for missing refresh tokens', async () =>
    {
        await request(app)
            .post('/token')
            .send({})
            .expect(401);
    });

    test('POST /rotate-keys should handle errors gently', async () =>
    {
        const response = await request(app)
            .post('/rotate-keys')
            .send({ expiresInDays: 'Invalid' })
            .expect(200);

    });

    test('GET /posts return 401 for wrong authorization formats', async () =>
    {
        await request(app)
            .get('/posts')
            .set('Authorization', 'NotBearer token')
            .expect(401);
    });

    test('POST /login return 400 for malformed JSON', async () =>
    {
        await request(app)
            .post('/login')
            .set('Content-Type', 'application/json')
            .send('{ "username": "Nanna"')
            .expect(400);
    });

    
    test('GET /posts with token signed with wrong key must return 401', async () =>
    {
        const loginResponse = await request(app)
            .post('/login')
            .send({ username: 'Nanna' })
            .expect(200);

        const validToken = loginResponse.body.accessToken;
        const parts = validToken.split('.');

        const header = JSON.parse(Buffer.from(parts[0],'base64').toString());
        header.kid = 'wrong-key-id';

        const newHeader = Buffer.from(JSON.stringify(header)).toString('base64').replace(/=/g, '');
        const tamperedToken = `${newHeader}.${parts[1]}.${parts[2]}`;

        await request(app)
            .get('/posts')
            .set( 'Authorization', `Bearer ${tamperedToken}`)
            .expect(401);
    });

    test('POST /login return 400 for missing username', async () =>
    {
        await request(app)
            .post('/login')
            .send({})
            .expect(400);
    });

    test('POST /login return 401 for invalid username', async () =>
    {
        await request(app)
            .post('/login')
            .send({ username: 'InvalidUser'})
            .expect(401);
    });
});
