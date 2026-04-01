/* *************************************************
*  Name: Gustavo Alatriste
*  Assignment: Demonstration Code
*  Purpose: A demonstration of a properly
*           constructed and commented functions.cpp
************************************************* */
const crypto = require('crypto');

/* *************************************************
* This function accepts two square objects,
*         compares there area and will return 0, 1 ,2.
* 0: they are equal
* 1: the first square is bigger
* 2: the second square is bigger

* @param sq1 : a Square object
* @param sq2 : a Square object
* @return 0,1,2 : which square is bigger
* @exception : none
* @note : na
* ************************************************* */
class keyStorage
{
    constructor()
    {
        this.keys = new Map();
        this.activeKeyID = null;
    }

    generateNewKey(expiresInDays = 1)
    {
        const keyID = `key-${new Date().toISOString().split('T')[0]}-${crypto.randomBytes(4).toString('hex')}`;
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

        setTimeout(() => 
        {
            this.deactivateKey(keyID);

        }, expiresInDays * 24 * 60 * 60 * 1000);

        return keyID;
    }

    getKey(keyID)
    {
        const key = this.keys.get(keyID);
        if (!key)
        {
            return null;
        }

        if (new Date() > key.expiresIn)
        {
            this.deactivateKey(keyID);
            return null;
        }

        return key.secret;
    }

    getCurrentKey()
    {
        return this.activeKeyID ? this.getKey(this.activeKeyID) : null;
    }

    getCurrentKeyID()
    {
        return this.activeKeyID;
    }

    deactivateKey(keyID)
    {
        const key = this.keys.get(keyID);
        if(key)
        {
            key.isActive = false;
            console.log(`Key ${keyID} expired and deactivated`);
        }

        if (keyID === this.activeKeyID)
        {
            this.promoteNextKey();
        }
    }

    promoteNextKey()
    {
        for (const [id, key] of this.keys)
        {
            if (key.isActive && new Date() <= key.expiresIn)
            {
                this.activeKeyID = id;
                console.log(` Promoted key ${id} as active`);
                return;
            }
        }
        console.log('No active keys available')
        this.activeKeyID = null;
    }

    removeExpiredKeys()
    {
        console.log(` Removing expired keys...`);
        const now = new Date();
        let expiredCount = 0;

        for (const [id, key] of this.keys)
        {
            if (now > key.expiresIn)
            {
                this.deactivateKey(id);
                this.keys.delete(id);
                expiredCount++;
            }
        }
        console.log(`Removed ${expiredCount} expired keys`);
        return expiredCount;
    }

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

/* *************************************************
* This function accepts two square objects,
*         compares there area and will return 0, 1 ,2.
* 0: they are equal
* 1: the first square is bigger
* 2: the second square is bigger

* @param sq1 : a Square object
* @param sq2 : a Square object
* @return 0,1,2 : which square is bigger
* @exception : none
* @note : na
* ************************************************* */
module.exports = new keyStorage();