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

    describe('Key Generation Tests', () => {
        test('generateNewKey must create a valid RSA key pair', async () =>
        {
            const keyID = keyStorage.generateNewKey(1);
            expect(keyID).toBeDefined();
            expect(keyID).toMatch(/^rsa-\d+-[a-f0-9]+$/);

            expect(keyStorage.keys.size).toBe(1);

            const keyData = await keyStorage.getKeyData(keyID);
            expect(keyData).toBeDefined();
            expect(keyData.kid).toBe(keyID);
            expect(keyData.privateKey).toBeDefined();
            expect(keyData.publicKey).toBeDefined();
            expect(keyData.isActive).toBe(1);

            expect(keyData.privateKey).toContain('-----BEGIN RSA PRIVATE KEY-----');
            expect(keyData.publicKey).toContain('-----BEGIN RSA PUBLIC KEY-----');
                
        }, 10000);
    })
    

    test('Clean up expired keys in removeExpiredKeys', async () =>
    {
        const expiredKeyID = keyStorage.generateNewKey(0.0000001);

        const validKeyIDOne = keyStorage.generateNewKey(1);
        const validKeyIDTwo = keyStorage.generateNewKey(1);

        await new Promise(resolve => setTimeout(resolve, 50));

        const removed = keyStorage.removeExpiredKeys();


        expect(removed).toBe(1);

        expect(keyStorage.keys.size).toBe(2);

        expect(keyStorage.keys.has(expiredKeyID)).toBe(false);
        expect(keyStorage.keys.has(validKeyIDOne)).toBe(true);
        expect(keyStorage.keys.has(validKeyIDTwo)).toBe(true);

    }, 2000);

    test('The function generateNewKey must create a valid key', async () =>
    {
        
        
    });
    
    test('The function getPrivateKey must create a valid, private key', async () =>
    {
        const keyID = keyStorage.getPrivateKey(1);
        expect(keyID).toBeDefined();
        expect(keyStorage.keys.size).toBe(1);

        const key = keyStorage.keys.get(keyID);
        expect(key.id).toBe(keyID);
        expect(key.isActive).toBe(true);
        expect(key.createdAt).toBeInstanceOf(Date);
        expect(key.expiresIn).toBeInstanceOf(Date);
        
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