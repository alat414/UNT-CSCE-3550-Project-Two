/* *************************************************
*  Name: Gustavo Alatriste
*  Assignment: JWKS Server with Key Rotation
*  Purpose: A demonstration of a properly
*           constructed and commented keyStorage.js
************************************************* */
const crypto = require('crypto');
const { promisify } = require('util');
const db = require('./database');

const dbGet = promisify(db.get).bind(db);
const dbRun = promisify(db.run).bind(db);
const dbAll = promisify(db.all).bind(db);

class keyStorage
{
    constructor()
    {
        this.keys = new Map();
        this.activeKeyID = null;
        this.intialized = false;
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
    * Generate a new encryption key; passing the new key 
    * to the database saved. 
    * @param expiresInDays - Number of days until key expiration
    * @return - Generated key ID
    ********************************** */
    async generateNewKey(expiresInDays = 1)
    {
        const days = Math.max(1, Math.min(30, expiresInDays));
        const keyID = `key-${Date.now()}-${crypto.randomBytes(8).toString('hex')}`;
        const secret = crypto.randomBytes(64).toString('hex');
        const createdAt = new Date().toISOString();
        const expiresIn = new Date();
        expiresIn.setDate(expiresIn.getDate() + expiresInDays);

        const keyData =
        {
            id: keyID,
            secret: secret,
            createdAt: createdAt,
            expiresIn: expiresIn.toISOString(),
            isActive: 1
        };

        try
        {
            await dbRun(`INSERT INTO keys (kid, secret, createdAt, expiresIn, isActive)
                VALUES (?, ?, ?, ?, ?)
                `, [keyData.id], [keyData.secret], [keyData.createdAt], [keyData.expiresIn], [keyData.isActive]);
            
            console.log(`Generated and saved new key: ${keyID}, expires in ${days} days`); 
            await this.setActiveKey(keyID);
            return keyID;
        }
        catch (err)
        {
            console.error('Error saving key into database:', err.message);
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
        catch (error) 
        {
            console.error('Error activiating key:', err.message);
            throw err;
        }       
    }
    /* **********************************
    * Obtain a key from the database.
    * @param keyID - key ID for retrieving
    * @param callback - key ID for retrieving
    * @return secret - The key secret or null if expired or invalid.
    ********************************** */
    async getKey(keyID)
    {
        try 
        {
            const row = await dbGet(`SELECT secret, isActive, expiresIn FROM key WHERE kid = ?`, [keyID]);
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

                return row.secret;
            };
        } 
        catch (err) 
        {
            console.error(`Error retrieving key ${keyID}:`, err.message);
            return null;
        }
    }

    /* *************************************************
    * This function returns the current, active key
    * via the getkey method. 
    * 
    * @param  : none
    * @return : The active key scret or null if no key exists.
    * @exception : none
    * @note : na
    * ************************************************* */
    async getCurrentKey()
    {
        if (!this.activeKeyID)
        {
            return null;
        }
        return await this.getKey(this.activeKeyID);
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
            console.log`(Removed ${count} expired keys)`;
            return count;
        } 
        catch (error) 
        {
            console.error('Error removing expired keys:', err.message);
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
            `SELECT kid, expiresIn FROM keys 
            WHERE isActive = 1 AND  datetime(expireIn) > datetime('now')`);

            const activeKeys = rows.maps(row => ({
                kid: row.kid,
                kty: "oct",
                alg: "HS256",
                use: "sig",
                exp: Math.floor(new Date(row.expiresIn).getTime() / 1000)
            }));

            console.log(`Found ${activeKeys.length} active keys for JWKS server`);
            return activeKeys;
        } 
        catch (error) 
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
            return await dbAll(`SELECT * FROM keys ORDER BY createdAt DESC`, [keyID]);
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