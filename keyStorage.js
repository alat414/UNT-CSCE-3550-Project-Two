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
    }

    /* **********************************
    * Generate a new encryption key
    * @param expiresInDays - Number of days until key expiration
    * @return - Generated key ID
    ********************************** */
    generateNewKey(expiresInDays = 1)
    {
        const days = Math.max(1, Math.min(30, expiresInDays));

        const keyID = `key-${Date.now()}-${crypto.randomBytes(8).toString('hex')}`;
       
        const secret = crypto.randomBytes(64).toString('hex');
        
        const expiresIn = new Date();
        expiresIn.setDate(expiresIn.getDate() + expiresInDays);

        const keyData =
        {
            id: keyID,
            secret: secret,
            createdAt: new Date(),
            expiresIn: expiresIn,
            isActive: true
        };

        this.keys.set(keyID, keyData);
        this.activeKeyID = keyID;

       console.log(`Generated new key: ${keyID}, expires in ${days} days (${expiresIn.toISOString()})`);

       return keyID;
    }

    /* **********************************
    * Obtain a key by its kid, if the key is active
    * @param keyID - key ID for retrieving
    * @return secret - The key secret or null if expired or invalid.
    ********************************** */
    getKey(keyID)
    {
        const key = this.keys.get(keyID);
        if (!key)
        {
            console.log(`key ${keyID} not found`);
            return null;
        }

        const now = new Date();
        if (now > key.expiresIn)
        {
            console.log(`Key ${keyID} is expired (expired at {key.expiresIn.toISOString()})`);

            if(key.isActive)
            {
                key.isActive = false;
                console.log(`Deactivated expired key: ${keyID}`);

                if (keyID === this.activeKeyID)
                {
                    this.promoteNextKey();
                }
            }
            return null;
        }

        if(!key.isActive)
        {
            console.log(`Key ${keyID} is inactive`);
            return null;
        }

        return key.secret;
        
    }

        /* *************************************************
    * This function returns the active key

    * @param  : none
    * @return : The active key scret or null if no key exists.
    * @exception : none
    * @note : na
    * ************************************************* */
    getCurrentKey()
    {
        if (!this.activeKeyID)
        {
            console.log('No active key ID set');
            return null;
        }
        return this.getKey(this.activeKeyID);
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
        if (!this.activeKeyID)
        {
            return null;
        }

        const key = this.keys.get(this.activeKeyID);
        // Validates that the active kid is pointing to a valid key.
        if (!key || !key.isActive || new Date() > key.expiresIn)
        {
            console.log(`Current active key ${this.activeKeyID} is no longer valid`);
            this.promoteNextKey();
        }

        return this.activeKeyID;
    }
    /* *************************************************
    * This function disables a specific key.

    * @param  keyID: key ID
    * @return : none
    * @exception : none
    * @note : na
    * ************************************************* */
    deactivateKey(keyID)
    {
        const key = this.keys.get(keyID);
        if(key && key.isActive)
        {
            key.isActive = false;
            console.log(`Key ${keyID} deactivated`);
        }

        if (keyID === this.activeKeyID)
        {
            console.log(`Active key ${keyID} was deactivated, promoting new key`);
            this.promoteNextKey();
        }
    }
    /* *************************************************
    * This function passing the next key to an active status

    * @param  : none
    * @return : none
    * @exception : none
    * @note : na
    * ************************************************* */
    promoteNextKey()
    {
        const now = new Date();

        for (const [id, key] of this.keys)
        {
            if (key.isActive && now <= key.expiresIn)
            {
                this.activeKeyID = id;
                console.log(` Promoted key ${id} as active`);
                return;
            }
        }
        console.log('No active keys available')
        this.activeKeyID = this.generateNewKey(1);
    }
    /* *************************************************
    * This function removes all expired keys from storage

    * @param  : none
    * @return count : Number of keys removed
    * @exception : none
    * @note : na
    * ************************************************* */
    removeExpiredKeys()
    {
        console.log(` Removing expired keys...`);
        const now = new Date();
        let expiredCount = 0;
        let activeKeyWasRemoved = false;
        const keysToRemove = [];

        for (const [id, key] of this.keys)
        {
            if (now > key.expiresIn)
            {
                keysToRemove.push(id);
                if (id === this.activeKeyID)
                {
                    activeKeyWasRemoved = true;
                }
            }
        }

        // Removing key
        for (const id of keysToRemove)
        {
            this.keys.delete(id);
            expiredCount++;
            console.log(`Removed expired key: ${id}`);
        }

        // Function ensures the active key was removed and new key was placed
        if (activeKeyWasRemoved)
        {
            console.log('Active key was removed, promoting next available key');
            this.promoteNextKey();
        }

        console.log(`Removed ${expiredCount} expired keys`);
        return expiredCount;
    }

    /* *************************************************
    * This function initalizes the server

    * @param  : none
    * @return : none
    * @exception : none
    * @note : na
    * ************************************************* */
    getActiveKeys()
    {
        const activeKeys = [];
        const now = new Date();

        for (const [id, key] of this.keys)
        {
            console.log(`Checking key ${id}:`,
            {
                isActive: key.isActive,
                expiresIn: key.expiresIn,
                isCurrent: id === this.activeKeyID
            });


            if(key.isActive && now <= key.expiresIn)
            {
                activeKeys.push
                ({
                    kid: id,
                    kty: "oct",
                    alg: "HS256",
                    use: "sig",
                    exp: Math.floor(key.expiresIn.getTime() / 1000)
                });
            }
        }
        console.log(` Found ${activeKeys.length} active keys for JWKS`);
        return activeKeys;
    }   
}

module.exports = new keyStorage();