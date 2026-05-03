/* *************************************************
*  Name: Gustavo Alatriste
*  Assignment: JWKS Server with Key Rotation
*  Purpose: A demonstration of a properly
*           constructed and commented keyStorage.js
************************************************* */
const crypto = require('crypto');
const { promisify } = require('util');
const { db, onTableReady } = require('./database');


const dbGet = promisify(db.get).bind(db);
const dbRun = promisify(db.run).bind(db);
const dbAll = promisify(db.all).bind(db);

class keyStorage
{
    constructor()
    {
        this.keys = new Map();
        this.activeKeyID = null;
        this.initialized = false;
        onTableReady(() => {
            this.loadActiveKey();
        });
    }

    /* **********************************
    * Loading the active key from database 
    * during the server startup.
    * @param  - None
    * @return - None
    ********************************** */
    async loadActiveKey() 
    {
        try 
        {
            console.log('Loading active AES key from database...'); 
            const row = await dbGet(`
                SELECT kid FROM keys 
                WHERE isActive = 1 AND datetime(expiresIn) > datetime('now') 
                ORDER BY createdAt DESC LIMIT 1
            `);
            
            if (row) 
            {
                this.activeKeyID = row.kid;
                console.log(`Loaded active AES key from database: ${this.activeKeyID}`);
            } 
            else 
            {
                console.log('No active key found in the database, will generate a key');
                await this.generateNewKey(1);
            }
            this.initialized = true;
            console.log(`Key storage initialized. Active Key ID: ${this.activeKeyID}`);
        } 
        catch (err) 
        {
            console.error('Error loading active key:', err.message);
            // Generate a key even if there's an error
            await this.generateNewKey(1);
            this.initialized = true;
        }
    }

    /* **********************************
    * Generate a new AES encryption key
    * via the randomBytes function and passing
    * to the database saved. 
    * @param expiresInDays - Number of days until key expiration
    * @return - Generated AES key ID
    ********************************** */
    async generateNewKey(expiresInDays = 1) 
    {
        try 
        {
            const days = Math.max(1, Math.min(30, expiresInDays));
            const keyID = `aes-${Date.now()}-${crypto.randomBytes(8).toString('hex')}`;

            const aesKey =  crypto.randomBytes(32);
            const aesKeyBase64 = aesKey.toString('base64');

            const createdAt = new Date().toISOString();
            const expiresIn = new Date();
            expiresIn.setDate(expiresIn.getDate() + days);
            
            console.log(`Generating new AES key with ID: ${keyID}`);
            console.log(`Created at: ${createdAt}`);
            console.log(`Expires at: ${expiresIn.toISOString()}`);

            // Insert into database - FIXED parameter order
            const query = `
                INSERT INTO keys (kid, secretKey, createdAt, expiresIn, isActive)
                VALUES (?, ?, ?, ?, ?)
            `;

            const params = [
                keyID,                    // kid
                privateKeyPem,            // private key
                publicKeyPem,             // public key
                createdAt,                // createdAt
                expiresIn.toISOString(),  // expiresIn
                1                         // isActive
            ];
            
            console.log('Executing INSERT query...');
            await dbRun(query, params);
            
            console.log(`Successfully saved AES key to database: ${keyID}`);
            await this.setActiveKey(keyID);
            return keyID;
        } 
        catch (err) 
        {
            console.error('Error saving AES key to database:', err.message);
            console.error('Full error object:', err);
            throw err;
        }
    }

    /* **********************************
    * The function sets the key as an active key
    * @param keyID - key ID for retrieving
    * @return - None
    ********************************** */
    async setActiveKey(keyID)
    {
        try 
        {
            await dbRun(`UPDATE keys SET isActive = 0`); 
            await dbRun(`UPDATE keys SET isActive = 1 WHERE kid = ?`, [keyID]);
            this.activeKeyID = keyID;
            console.log(`Key ${keyID} set as active`);
            
        } 
        catch (err) 
        {
            console.error('Error activiating key:', err.message);
            throw err;
        }       
    }
    /* **********************************
    * Obtain a public key from the database.
    * using SQL query prompts.
    * 
    * @param keyID - key ID for retrieving
    * @param callback - key ID for retrieving
    * @return secret - The private key or null if expired or invalid.
    ********************************** */
    async getKey(keyID)
    {
        try 
        {
            const row = await dbGet(`SELECT secretKey, isActive, expiresIn FROM keys WHERE kid = ?`, [keyID]);
            
            if(!row)
            {
                console.log(`Key ${keyID} not found`);
                return null;
            }

            const now = new Date();
            const expiresIn = new Date(row.expiresIn);

            if (now > expiresIn)
            {
                console.log(`Key ${keyID} is expired`);
                await dbRun(`UPDATE keys SET isActive = 0 WHERE kid = ?`, [keyID])
                return null;
            }

            if (!row.isActive)
            {
                console.log(`Key ${keyID} is inactive`);
                return null;
            }
            const keyBuffer = Buffer.from(row.secretKey, 'base64');
            console.log(`Retrieved AES key for ${keyID} (${keyBuffer.length} bytes)`);
            return keyBuffer;
            
        } 
        catch (err) 
        {
            console.error(`Error retrieving key ${keyID}:`, err.message);
            return null;
        }
    }

    

    /* *************************************************
    * This function returns the current, active
    *  key via the getKey method. 
    * 
    * @param  : none
    * @return : The active AES key or null if no key exists.
    * @exception : none
    * @note : na
    * ************************************************* */
    async getCurrentKey()
    {
        console.log(`Getting current AES key. Active key ID: ${this.activeKeyID}`);
        if (!this.activeKeyID)
        {
            console.log('No active keyID set');
            return null;
        }
        const key = await this.getKey(this.activeKeyID);
        console.log(`Key Found: ${!!key}`);
        return key;
    }

    /* *************************************************
    * This function returns the current, active public key
    * via the getpublickey method. 
    * 
    * @param  : none
    * @return : The active, public key or null if no key exists.
    * @exception : none
    * @note : na
    * ************************************************* */
    async getCurrentPublicKey()
    {
        console.log(`Getting current public key. Active key ID: ${this.activeKeyID}`);
        if (!this.activeKeyID)
        {
            console.log('No active keyID set');
            return null;
        }
        const key = await this.getPublicKey(this.activeKeyID);
        console.log(`Key Found: ${!!key}`);
        return key;
    }
    /* *************************************************
    * This function returns the current active key ID

    * @param  : none
    * @return keyID: Active key ID, or null.
    * @exception : none
    * @note : na
    * ************************************************* */
    getCurrentKeyID()
    {
        return this.activeKeyID;
    }

   
    /* *************************************************
    * This function removes all expired keys from database
    *
    * @param  callback: function used to backtrack
    * @return : none
    * @exception : none
    * @note : na
    * ************************************************* */
    async removeExpiredKeys()
    {
        try 
        {
            const result = await dbRun(`DELETE FROM keys WHERE datetime(expiresIn) <= datetime('now')`);
            const count = result.changes || 0;
            console.log(`Removed ${count} expired keys`);
            return count;
        } 
        catch (error) 
        {
            console.error('Error removing expired keys:', error.message);
            return 0;
        }
    }

    /* *************************************************
    * This function gets all active keys for JWKS endpoint

    * @param  callback: function used to backtrack
    * @return : Array of active key metadata
    * @exception : none
    * @note : na
    * ************************************************* */
    async getActiveKeys()
    {
        try 
        {
            /*
            console.log('=== getActiveKeys() called ===');
            
            // First, check total keys in database
            const totalKeys = await dbAll(`SELECT COUNT(*) as count FROM keys`);
            console.log(`Total keys in database: ${totalKeys[0].count}`);
            
            // Check all keys with their status
            const allKeysStatus = await dbAll(`SELECT kid, isActive, expiresIn, datetime('now') as now FROM keys`);
            console.log('All keys in database:', allKeysStatus.map(k => ({
                kid: k.kid,
                isActive: k.isActive,
                expiresIn: k.expiresIn,
                now: k.now,
                isExpired: new Date(k.expiresIn) <= new Date()
            })));
            */
            
            const rows = await dbAll(`
                SELECT kid, expiresIn, publicKey FROM keys 
                WHERE isActive = 1 AND datetime(expiresIn) > datetime('now')
            `);
            
            console.log(`Query returned ${rows.length} active, non-expired keys`);
            
            const activeKeys = [];

            for (const row of rows)
            {
                console.log(`Processing key: ${row.kid}`);
                try 
                {
                    const publicKey = crypto.createPublicKey(row.publicKey);
                    const jwk = publicKey.export({ format: 'jwk'});
                    
                    activeKeys.push({
                        kid: row.kid,
                        kty: "RSA",
                        alg: "RS256",
                        use: "sig",
                        n: jwk.n,
                        e: jwk.e,
                        exp: Math.floor(new Date(row.expiresIn).getTime() / 1000)
                    });

                    console.log(`Successfully parsed key ${row.kid}`);
                } 
                catch (err) 
                {
                    console.error(`Error parsing key ${row.kid}:`, parseError.message);
                }
            }
            
            console.log(`Found ${activeKeys.length} active keys for JWKS server`);
            return activeKeys;
        } 
        catch (err) 
        {
            console.error('Error getting active keys:', err.message);
            return [];       
        }
    }

    /* *************************************************
    * This function gets all key data via SQL query prompt

    * @param  keyID: kid
    * @return : kid details
    * @exception : none
    * @note : na
    * ************************************************* */
    async getKeyData(keyID)
    {
        try 
        {
            return await dbGet(`SELECT * FROM keys WHERE kid = ?`, [keyID]);
            
        } 
        catch (err) 
        {
            console.error(`Error getting key data for ${keyID}:`, err.message);
            return null;
        }
    }

    /* *************************************************
    * This function gets all active keys for JWKS endpoint

    * @param  : none
    * @return : key id 
    * @exception : none
    * @note : na
    * ************************************************* */
    async getAllKeys()
    {
        try 
        {
            return await dbAll(`SELECT kid, createdAt, expiresIn, isActive FROM keys ORDER BY createdAt DESC`);
        } 
        catch (err) 
        {
            console.error('Error getting all keys:', err.message);
            return [];
        }
    }
}



// Export a singleton instance.
module.exports = new keyStorage();