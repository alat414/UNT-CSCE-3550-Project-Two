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
        
        test('getCurrentKey should return null when no active key exists', async () =>
        {
            await clearDatabase();
            keyStorage.activeKeyID = null;
            const privateKey = await keyStorage.getCurrentPrivateKey();
            expect(privateKey).toBeNull();
        });

        test('getPublicKey should return valid public key for given keyID', async () =>
        {
            const keyID = await keyStorage.generateNewKey(1);
            const keyData = await keyStorage.getPublicKey(keyID);
            expect(publicKey).toBeDefined();
            expect(publicKey).toContain('-----BEGIN RSA PUBLIC KEY-----');

        });
        
        test('getPrivateKey should return valid private key for given keyID', async () =>
        {
            const keyID = await keyStorage.generateNewKey(1);
            const keyData = await keyStorage.getPrivateKey(keyID);
            expect(privateKey).toBeDefined();
            expect(privateKey).toContain('-----BEGIN RSA PRIVATE KEY-----');

        });

        test('getKey should return null for non existent key ', async () =>
        {
            const result = await keyStorage.getkey('non-existent-key');
            expect(result).toBeNull();
        });
    });
    
    describe('Active Key Management Tests', () => 
    {
        test('setActiveKeys must deactivate other keys', async () =>
        {
            const keyIDOne = await keyStorage.generateNewKey(1);
            const keyIDTwo = await keyStorage.generateNewKey(1);
            const keyIDThree = await keyStorage.generateNewKey(1);

            await keyStorage.setActiveKey(keyIDTwo);

            const keyOne = await keyStorage.getKeyData(keyIDOne);
            const keyTwo = await keyStorage.getKeyData(keyIDTwo);
            const keyThree = await keyStorage.getKeyData(keyIDThree);

            expect(keyOne.isActive).toBe(0);
            expect(keyTwo.isActive).toBe(1);
            expect(keyThree.isActive).toBe(0);

            expect(keyStorage.getCurrentKeyID()).toBe(keyIDTwo);

        });
        
        test('getCurrentKeyID should return the active key ID', async () =>
        {
            const keyID = await keyStorage.generateNewKey(1);
            expect(keyStorage.getCurrentKeyID).toBe(keyID);
        });

        test('promoteNextKey should active the next valid key', async () =>
        {
            const keyIDOne = await keyStorage.generateNewKey(1);
            const keyIDTwo = await keyStorage.generateNewKey(1);

            await keyStorage.setActiveKey(keyIDOne);
            await keyStorage.deactivateKey(keyIDOne);
            
            expect(keyStorage.getCurrentKeyID()).toBe(keyIDTwo);
        });
    });
    
    describe('Key Expiration Tests', () => 
    {
        test('removeExpiredKeys must delete expired keys', async () =>
        {
            const expiredKeyID = await keyStorage.generateNewKey(0.001);
            const validKeyIDOne = await keyStorage.generateNewKey(1);
            const validKeyIDTwo = await keyStorage.generateNewKey(1);

            await new Promise(resolve => setTimeout(resolve, 100));

            const removedCount = await keyStorage.removeExpiredKeys();

            expect(removedCount).toBe(1);

            const expiredKey = await keyStorage.getKeyData(expiredKeyID);
            const validKeyOne = await keyStorage.getKeyData(validKeyIDOne);
            const validKeyTwo = await keyStorage.getKeyData(validKeyIDTwo);

            expect(expiredKey).toBeUndefined();
            expect(validKeyOne).toBeDefined();
            expect(validKeyTwo).toBeDefined();
        }, 5000);
        
        test('getKey should return null for expired key', async () =>
        {
            const keyID = await keyStorage.generateNewKey(0.001);

            await new Promise(resolve => setTimeout(resolve, 100));

            const privateKey = await keyStorage.getPrivateKey(keyID);
            expect(privateKey).toBeNull();
        });
    });

    describe('JWKS Key Export Tests', () => 
    {
        test('getActiveKeys should return correctly formatted JWKS keys', async () =>
        {
            await keyStorage.generateNewKey(1);

            const activeKeys = await keyStorage.getActiveKeys();

            expect(activeKeys).toBeInstanceOf(Array);
            expect(activeKeys.length).toBe(1);

            const jwksKey = activeKeys[0];

            expect(jwksKey).toHaveProperty('kid');
            expect(jwksKey).toHaveProperty('kty', 'RSA');
            expect(jwksKey).toHaveProperty('alg', 'RS256');
            expect(jwksKey).toHaveProperty('use', 'sig');
            expect(jwksKey).toHaveProperty('n',);
            expect(jwksKey).toHaveProperty('e');
            expect(jwksKey).toHaveProperty('exp');
        });
        
        test('getActiveKeys should return only active, non expired keys', async () =>
        {
            await keyStorage.generateNewKey(0.001);

            const activeKeyID = await keyStorage.generateNewKey(1);

            await new Promise (resolve => setTimeout(resolve, 100));

            await keyStorage.removeExpiredKeys();

            const activeKeys = await keyStorage.getActiveKeys();

            expect(activeKeys.length).toBe(1);
            expect(activeKeys[0].kid).toBe(activeKeyID);
        }, 5000);

        test('promoteNextKey should active the next valid key', async () =>
        {
            const keyIDOne = await keyStorage.generateNewKey(1);
            const keyIDTwo = await keyStorage.generateNewKey(1);

            await keyStorage.setActiveKey(keyIDOne);
            await keyStorage.deactivateKey(keyIDOne);
            
            expect(keyStorage.getCurrentKeyID()).toBe(keyIDTwo);
        });
    });
    
    describe('Key Expiration Tests', () => 
    {
        test('removeExpiredKeys must delete expired keys', async () =>
        {
            const expiredKeyID = await keyStorage.generateNewKey(0.001);
            const validKeyIDOne = await keyStorage.generateNewKey(1);
            const validKeyIDTwo = await keyStorage.generateNewKey(1);

            await new Promise(resolve => setTimeout(resolve, 100));

            const removedCount = await keyStorage.removeExpiredKeys();

            expect(removedCount).toBe(1);

            const expiredKey = await keyStorage.getKeyData(expiredKeyID);
            const validKeyOne = await keyStorage.getKeyData(validKeyIDOne);
            const validKeyTwo = await keyStorage.getKeyData(validKeyIDTwo);

            expect(expiredKey).toBeUndefined();
            expect(validKeyOne).toBeDefined();
            expect(validKeyTwo).toBeDefined();
        }, 5000);
        
        test('getKey should return null for expired key', async () =>
        {
            const keyID = await keyStorage.generateNewKey(0.001);

            await new Promise(resolve => setTimeout(resolve, 100));

            const privateKey = await keyStorage.getPrivateKey(keyID);
            expect(privateKey).toBeNull();
        });
    });
});