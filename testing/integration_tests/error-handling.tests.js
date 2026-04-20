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

        test('Case-sensitive username should work with exact case', async () => 
        {
            const response = await request(app)
                .post('/login')
                .send({ username: 'nanna' })
                .expect(200);
            
            expect(response.body).toHaveProperty('accessToken');
        });

        
    });
});
