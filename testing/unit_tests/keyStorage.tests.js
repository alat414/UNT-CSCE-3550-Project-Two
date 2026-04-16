/* *************************************************
*  Name: Gustavo Alatriste
*  Assignment: Project One JWKS server
*  Purpose: Key Storage testing functions file
*           using proper methods and callbacks 
*           ensure proper POST, GET, token,
*           error, and key(ID) returns 
*           keyStorage.tests.js
************************************************* */

const keyStorage = require('../../keyStorage');
const { db } = require('../../database');
const crypto = require('crypto');

async function clearDatabase()
{
    return new Promise((resolve, reject) => 
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
}

describe('KeyStorage Unit tests - RSA PKCS1 REM', () =>
{
    beforeEach(async () => 
    {
        await clearDatabase();
        keyStorage.activeKeyID = null;
        keyStorage.initialized = false;
        await keyStorage.loadActiveKey();
    });

    afterEach(async () => 
    {
        await clearDatabase();
    });

    afterAll((done) => 
    {
        db.close(done);
    });

    describe('Key Generation Tests', () => 
    {
        test('generateNewKey must create a valid RSA key pair', async () =>
        {
            const keyID = keyStorage.generateNewKey(1);
            expect(keyID).toBeDefined();
            expect(keyID).toMatch(/^rsa-\d+-[a-f0-9]+$/);


            const keyData = await keyStorage.getKeyData(keyID);
            expect(keyData).toBeDefined();
            expect(keyData.kid).toBe(keyID);
            expect(keyData.privateKey).toBeDefined();
            expect(keyData.publicKey).toBeDefined();
            expect(keyData.isActive).toBe(1);

            expect(keyData.privateKey).toContain('-----BEGIN RSA PRIVATE KEY-----');
            expect(keyData.publicKey).toContain('-----BEGIN RSA PUBLIC KEY-----');
                    
        }, 10000);
        
        

        test('The generateNewKey function should respect expiration days parameter', async () =>
        {
            const keyID = await keyStorage.generateNewKey(7);

            const keyData = await keyStorage.getKeyData(keyID);
            
            const expiresIn = new Date(keyData.expiresIn);

            const now = new Date();

            const daysDifference = (expiresIn - now) / (1000 * 60 * 60 * 24);

            expect(daysDifference).toBeGreaterThan(6.9);

            expect(daysDifference).toBeLessThan(7.1);

        });

        
        test('generateNewKey should strengthen the expiration between 1 to 30 days', async () =>
        {
            const keyIDOne = await keyStorage.generateNewKey(0);
            const keyDataOne = await keyStorage.getKeyData(keyIDOne);
            const expiresInOne = new Date(keyIDOne.expiresIn);
            const now = new Date();
            const daysDifferenceOne = (expiresInOne - now) / (1000 * 60 * 60 * 24);
            expect(daysDifferenceOne).toBeGreaterThanOrEqual(0.9);

            const keyIDTwo = await keyStorage.generateNewKey(365);
            const keyDataTwo = await keyStorage.getKeyData(keyIDTwo);
            const expiresInTwo = new Date(keyIDTwo.expiresIn);
            const daysDifferenceTwo = (expiresInTwo - now) / (1000 * 60 * 60 * 24);
            expect(daysDifferenceTwo).toBeLessThanOrEqual(30.1);
        });
    });

    describe('Key Retrieval Tests', () => 
    {
        test('generateNewKey must create a valid RSA key pair', async () =>
        {
            const keyID = await keyStorage.generateNewKey(1);
            const keyData = await keyStorage.getCurrentPrivateKey();
            expect(privateKey).toBeDefined();
            expect(privateKey).toContain('-----BEGIN RSA PRIVATE KEY-----');

        });
        
        

        test('The generateNewKey function should respect expiration days parameter', async () =>
        {
            const keyID = await keyStorage.generateNewKey(7);

            const keyData = await keyStorage.getKeyData(keyID);
            
            const expiresIn = new Date(keyData.expiresIn);

            const now = new Date();

            const daysDifference = (expiresIn - now) / (1000 * 60 * 60 * 24);

            expect(daysDifference).toBeGreaterThan(6.9);

            expect(daysDifference).toBeLessThan(7.1);

        });

        
        test('generateNewKey should strengthen the expiration between 1 to 30 days', async () =>
        {
            const keyIDOne = await keyStorage.generateNewKey(0);
            const keyDataOne = await keyStorage.getKeyData(keyIDOne);
            const expiresInOne = new Date(keyIDOne.expiresIn);
            const now = new Date();
            const daysDifferenceOne = (expiresInOne - now) / (1000 * 60 * 60 * 24);
            expect(daysDifferenceOne).toBeGreaterThanOrEqual(0.9);

            const keyIDTwo = await keyStorage.generateNewKey(365);
            const keyDataTwo = await keyStorage.getKeyData(keyIDTwo);
            const expiresInTwo = new Date(keyIDTwo.expiresIn);
            const daysDifferenceTwo = (expiresInTwo - now) / (1000 * 60 * 60 * 24);
            expect(daysDifferenceTwo).toBeLessThanOrEqual(30.1);
        });
    });
    test('The function getPublicKey must create a valid, public key', async () =>
    {
        const keyID = keyStorage.getPublicKey(1);
        expect(keyID).toBeDefined();
        expect(keyStorage.keys.size).toBe(1);

        const key = keyStorage.keys.get(keyID);
        expect(key.id).toBe(keyID);
        expect(key.isActive).toBe(true);
        expect(key.createdAt).toBeInstanceOf(Date);
        expect(key.expiresIn).toBeInstanceOf(Date);
        
    });

    test('getKey returning null for an expired key', async () =>
    {
        const keyID = keyStorage.generateNewKey(0.0000001);

        await new Promise(resolve => setTimeout(resolve, 50));

        const secret = keyStorage.getKey(keyID);
        expect(secret).toBeNull();

        const key = keyStorage.keys.get(keyID);
        expect(key.isActive).toBe(false);
    }, 1000);
    
    test('Deactivate key should be set to inactive', () =>
    {
        const keyID = keyStorage.generateNewKey(1);

        keyStorage.deactivateKey(keyID);

        const key = keyStorage.keys.get(keyID);
        expect(key.isActive).toBe(false);
    });

    test('Call promoteNextKey must activate the following valid key', () =>
    {
        const firstKeyID = keyStorage.generateNewKey(1);

        keyStorage.deactivateKey(firstKeyID);

        const secondKeyID = keyStorage.generateNewKey(1);

        expect(keyStorage.activeKeyID).toBe(secondKeyID);
        
        keyStorage.promoteNextKey();
        expect(keyStorage.activeKeyID).toBe(secondKeyID);
    });
    
});