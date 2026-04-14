/* *************************************************
*  Name: Gustavo Alatriste
*  Assignment: JWKS Server with Key Rotation
*  Purpose: A demonstration of a properly
*           constructed and commented keyStorage.js
************************************************* */
const crypto = require('crypto');
const { promisify } = require('util');
const db = require('./database');
const NodeRSA = require('node-rsa');

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
        this.loadActiveKey();
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
            console.log('Loading active key from database...'); 
            const row = await dbGet(`
                SELECT kid FROM keys 
                WHERE isActive = 1 AND datetime(expiresIn) > datetime('now') 
                ORDER BY createdAt DESC LIMIT 1
            `);
            
            if (row) 
            {
                this.activeKeyID = row.kid;
                console.log(`Loaded active key from database: ${this.activeKeyID}`);
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
    * Generate a new encryption RSA pair keys;
    * passing the new key in PKCS1 PEM format
    * to the database saved. 
    * @param expiresInDays - Number of days until key expiration
    * @return - Generated key ID
    ********************************** */
    async generateNewKey(expiresInDays = 1) 
    {
        try 
        {
            const days = Math.max(1, Math.min(30, expiresInDays));
            const keyID = `rsa-${Date.now()}-${crypto.randomBytes(8).toString('hex')}`;

            const key = new NodeRSA({ b: 2048 });
            const privateKeyPem = key.exportKey('pkcs1-private-pem');
            const publicKeyPem = key.exportKey('pkcs1-public-pem');

            const createdAt = new Date().toISOString();
            const expiresIn = new Date();
            expiresIn.setDate(expiresIn.getDate() + days);
            
            console.log(`Generating new RSA key with ID: ${keyID}`);
            console.log(`Private key (PCKS1 PEM): ${privateKeyPem.substring(0, 60)}...`);
            console.log(`Public key (PCKS1 PEM): ${publicKeyPem.substring(0, 60)}...`);
            console.log(`Created at: ${createdAt}`);
            console.log(`Expires at: ${expiresIn.toISOString()}`);
            
            // Insert into database - FIXED parameter order
            const query = `
                INSERT INTO keys (kid, privateKey, publicKey, createdAt, expiresIn, isActive)
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
            
            console.log(`Successfully saved RSA key pair to database: ${keyID}`);
            await this.setActiveKey(keyID);
            return keyID;
        } 
        catch (err) 
        {
            console.error('Error saving key to database:', err.message);
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
    async getPrivateKey(keyID)
    {
        try 
        {
            const row = await dbGet(`SELECT privateKey, isActive, expiresIn FROM keys WHERE kid = ?`, [keyID]);
            {
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

                console.log(`Retrieved private key for ${keyID} (PKCS1 PEM format)`)
                return row.privateKey;
            };
        } 
        catch (err) 
        {
            console.error(`Error retrieving key ${keyID}:`, err.message);
            return null;
        }
    }

    /* **********************************
    * Obtain a key from the database.
    * @param keyID - key ID for retrieving
    * @param callback - key ID for retrieving
    * @return secret - The key secret or null if expired or invalid.
    ********************************** */
    async getPublicKey(keyID)
    {
        try 
        {
            const row = await dbGet(`SELECT publicKey, isActive, expiresIn FROM keys WHERE kid = ?`, [keyID]);
            {
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
                    return null;
                }

                if (!row.isActive)
                {
                    console.log(`Key ${keyID} is inactive`);
                    return null;
                }

                console.log(`Retrieved public key for ${keyID} (PKCS1 PEM format)`)
                return row.publicKey;
            };
        } 
        catch (err) 
        {
            console.error(`Error retrieving public key ${keyID}:`, err.message);
            return null;
        }
    }

    /* *************************************************
    * This function returns the current, active
    * private key via the getPrivatekey method. 
    * 
    * @param  : none
    * @return : The active private key or null if no key exists.
    * @exception : none
    * @note : na
    * ************************************************* */
    async getCurrentPrivateKey()
    {
        console.log(`Getting current, private key. Active key ID: ${this.activeKeyID}`);
        if (!this.activeKeyID)
        {
            console.log('No active keyID set');
            return null;
        }
        const key = await this.getPrivateKey(this.activeKeyID);
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
            const rows = await dbAll(
            `SELECT kid, expiresIn, publicKey FROM keys 
            WHERE isActive = 1 AND datetime(expiresIn) > datetime('now')`);

            const activeKeys = await Promise.all(rows.map(async (row) => {
                const key = new NodeRSA(row.publicKey);
                const keyComponents = key.exportKey('components');

                return {
                    kid: row.kid,
                    kty: "RSA",
                    alg: "RS256",
                    use: "sig",
                    n: keyComponents.n.toString('base64'),
                    e: keyComponents.e.toString('base64'),
                    exp: Math.floor(new Date(row.expiresIn).getTime() / 1000)
                };
              
            }));

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