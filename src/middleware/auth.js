const { db } = require('../services/firebase');
const { redisClient } = require('../services/redis');

const API_KEYS_COLLECTION = 'apiKeys';

// API key authentication middleware
const apiKeyAuth = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return next(); // No key, continue
        }
        const apiKey = authHeader.split(' ')[1];
        if (!apiKey) {
             return next(); // Has 'Bearer ' but no key
        }

        // Try getting from cache first
        let userAuth = null;
        if (redisClient) {
            try {
                const cachedAuth = await redisClient.get(`apikey:${apiKey}`);
                if (cachedAuth) {
                    userAuth = JSON.parse(cachedAuth);
                    req.userAuth = userAuth;
                    return next();
                }
            } catch (e) {
                console.warn("Redis GET error for API key:", e.message);
            }
        }

        // If no cache, query Firestore
        const keysSnapshot = await db.collection(API_KEYS_COLLECTION).get();
        for (const doc of keysSnapshot.docs) {
            const data = doc.data();
            if (data.publicKey === apiKey) { userAuth = { userId: doc.id, type: 'public' }; break; }
            if (data.privateKey === apiKey) { userAuth = { userId: doc.id, type: 'private' }; break; }
        }
        
        if (!userAuth) {
             return res.status(403).send({ error: 'Invalid or expired API Key.' });
        }

        // Save to cache
        if (redisClient) {
             try {
                await redisClient.set(`apikey:${apiKey}`, JSON.stringify(userAuth), 'EX', 3600); // Cache key for 1 hour
             } catch (e) {
                 console.warn("Redis SET error for API key:", e.message);
             }
        }

        req.userAuth = userAuth;
        next();
    } catch (error) {
        console.error("API Key Auth Error:", error);
        return res.status(500).send({ error: 'Server error during API key authentication.' });
    }
};

module.exports = { apiKeyAuth };
