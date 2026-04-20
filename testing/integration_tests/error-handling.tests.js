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


describe('Error Handling Flow', () => 
{
    /* *************************************************
    * This function clears all data using query prompt

    * @param  : none
    * @return : emoty
    * @exception : none
    * @note : na
    * ************************************************* */
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

    /* *************************************************
    * This function closes database after last prompt. 

    * @param  done: calling function 
    * @return : none 
    * @exception : none
    * @note : na
    * ************************************************* */
    afterAll((done) => 
    {
        db.close(done);
    });
    
    describe('Login Endpoint Errors', () =>{

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
                .send({ username: 'Brynjar' })
                .expect(401);
            
            expect(response.body.error).toBe('Unauthorized');
            expect(response.body.message).toBe('Invalid Username');
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
});
