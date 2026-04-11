/* *************************************************
*  Name: Gustavo Alatriste
*  Assignment: JWKS Server with Key Rotation
*  Purpose: A demonstration of a properly
*           constructed and commented keyStorage.js
************************************************* */
const crypto = require('crypto');


class keyStorage
{
    constructor()
    {
        this.keys = new Map();
        this.activeKeyID = null;
        this.loadActiveKey();
    }


    /* **********************************
    * Loading the active key from database 
    * during the server startup.
    * @param  - None
    * @return - None
    ********************************** */
    loadActiveKey()
    {
        db.get(`SELECT kid FROM keys WHERE isActive = 1 AND datetime(expiresIn) > datetime('now') ORDER BY 
        createdAt DESC LIMIT 1`, 
        (err, row) => 
        {
            if (err)
            {
                console.error('Error loading active key', err.message);
            }
            else if (row)
            {
                this.activeKeyID = row.kid;
                console.error(`Loaded active key from database: ${this.activeKeyID}`);
            }
            else
            {
                console.log('No active key found in the database, will generate a key'); 
                this.generateNewKey(1);
            }
        });
    }

    /* **********************************
    * Generate a new encryption key; passing the new key 
    * to the database saved. 
    * @param expiresInDays - Number of days until key expiration
    * @return - Generated key ID
    ********************************** */
    generateNewKey(expiresInDays = 1)
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

        db.run(`INSERT INTO keys (kid, secret, createdAt, expiresIn, isActive)
                VALUES (?, ?, ?, ?, ?)
                `, [keyData.id], [keyData.secret], [keyData.createdAt], [keyData.expiresIn], [keyData.isActive], 
        (err) => 
        {
            if (err)
            {
                console.error('Error saving key into database', err.message);
            }
            else
            {
                console.log(`Generated and saved new key: ${keyID}, expires in ${days} days`); 
                this.setActiveKey(keyID);
            }
        });

       return keyID;
    }

    /* **********************************
    * The function sets the key as an active key
    * @param keyID - key ID for retrieving
    * @return - None
    ********************************** */
    setActiveKey(keyID)
    {
        db.run(`UPDATE keys SET isActive = 0`, (err) => 
        {
            if (err)
            {
                console.log('Error deactivating keys:', err.message);
                return;
            }
            db.run(`UPDATE keys SET isActive = 1 WHERE kid = ?`, [keyID], (err) =>
            {
                if (keyID === this.activeKeyID)
                {
                    console.error('Error activiating key:', err.message);
                }
                else
                {
                    this.activeKeyID = keyID;
                    console.log(`Key ${keyID} set as active`);
                }
            });
        });
                
    }
    /* **********************************
    * Obtain a key from the database.
    * @param keyID - key ID for retrieving
    * @param callback - key ID for retrieving
    * @return secret - The key secret or null if expired or invalid.
    ********************************** */
    getKey(keyID, callback)
    {
        db.get(`SELECT secret, isActive, expiresIn FROM key WHERE kid = ?`, [keyID], (err, row) =>
        {
            if (err)
            {
                console.error(`Error retrieving key ${keyID}:`, err.message);

                callback(null);
                return;
            }

            if(!row)
            {
                console.log(`Key ${keyID} not found`);
                callback(null);
                return;
            }

            const now = new Date();
            const expiresIn = new Date(row.expiresIn);

            if (now > expiresIn)
            {
                console.log(`Key ${keyID} is expired`);

                db.run(`UPDATE keys SET isActive = 0 WHERE kid = ?`, keyID, err => 
                {
                    if (err)
                    {
                        console.error('Error deactivating expired key' , err.message);
                    }
                })

                callback(null);
                return;
            }

            if (!row.isActive)
            {
                console.log(`Key ${keyID} is inactive`);

                callback(null);
                return;
            }

            callback(row.secret);
        });
        
    }

    /* *************************************************
    * This function returns the current, active key
    * via the Promise async use. 
    * 
    * @param  : none
    * @return : The active key scret or null if no key exists.
    * @exception : none
    * @note : na
    * ************************************************* */
    getCurrentKey()
    {
        return new Promise((resolve, reject) =>
        {
            if (!this.activeKeyID)
            {
                reject(null);
                return;
            }

            this.getKey(this.activeKeyID, (secret) =>
            {
                resolve(secret);
            });
        })
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
    removeExpiredKeys(callback)
    {
        db.run(`DELETE FROM keys WHERE datetime(expiresIn) <= datetime(now)`, function(err)
        {
            // In the instance where query leads to an error, program backtracks.
            if (err)
            {
                console.error('Error removing expired keys:', err.message);
                if (callback)
                {
                    callback(0);
                }
            }
            else
            {
                console.log`(Removed ${this.changes} expired keys)`;
                if (callback)
                {
                    callback(this.changes);
                }
            }
        });
    }

    /* *************************************************
    * This function gets all active keys for JWKS endpoint

    * @param  callback: function used to backtrack
    * @return : Array of active key metadata
    * @exception : none
    * @note : na
    * ************************************************* */
    getActiveKeys(callback)
    {
        db.all(
            `SELECT kid, expiresIn FROM keys 
            WHERE isActive = 1 AND  datetime(expireIn) > datetime('now')`
            , (err, rows) => {
            if (err)
            {
                console.error('Error getting active keys:', err.message);
                callback([]);
                return;
            }
            
            const activeKeys = rows.maps(row => ({
                kid: row.kid,
                kty: "oct",
                alg: "HS256",
                use: "sig",
                exp: Math.floor(new Date(row.expiresIn).getTime() / 1000)
            }));

            console.log(`Found ${activeKeys.length} active keys for JWKS`);
            callback(activeKeys);

        });
    }   
}

// Export a singleton instance.
module.exports = new keyStorage();