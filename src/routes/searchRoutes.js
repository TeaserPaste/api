const express = require('express');
const router = express.Router();
const { db } = require('../services/firebase');
const { redisClient } = require('../services/redis');

const SNIPPETS_COLLECTION = 'snippets';
const CACHE_TTL_SECONDS = 300;

router.post('/searchSnippets', async (req, res) => {
    try {
        const { term } = req.body;
        // const size = parseInt(req.body.size, 10) || 20; // Pagination logic for Firestore is different (startAfter)
        // Ignoring 'from' and 'size' as strictly implemented for pagination for now, 
        // or implementing basic limit. 
        // Let's implement basic limit.
        const size = parseInt(req.body.size, 10) || 20;

        if (!term || typeof term !== 'string' || term.trim() === '') {
            return res.status(400).send({ error: 'Missing or invalid: term (search keyword).' });
        }

        const searchTerm = term.trim();
        const cacheKey = `search:${searchTerm}:size${size}`; // Ignoring 'from' for simplicity in this implementation

        // 1. CHECK CACHE FIRST
        if (redisClient) {
            try {
                const cachedResults = await redisClient.get(cacheKey);
                if (cachedResults) {
                    console.log("CACHE HIT:", cacheKey);
                    let responseData = JSON.parse(cachedResults);
                    responseData.additional = { cache: 'hit' }; 
                    return res.status(200).send(responseData);
                }
                console.log("CACHE MISS:", cacheKey);
            } catch (err) {
                console.error("Redis GET error:", err.message);
            }
        }

        // Firestore Query
        // Title prefix search: title >= searchTerm AND title <= searchTerm + '\uf8ff'
        // And visibility == 'public'
        
        let query = db.collection(SNIPPETS_COLLECTION)
            .where('visibility', '==', 'public')
            .where('title', '>=', searchTerm)
            .where('title', '<=', searchTerm + '\uf8ff')
            .limit(size);

        const snapshot = await query.get();

        const results = [];
        const now = new Date();

        snapshot.forEach(doc => {
            const data = doc.data();
            
            // Check expiration (manual filter)
            if (data.expiresAt) {
                const expiresAtDate = data.expiresAt.toDate();
                if (expiresAtDate <= now) {
                    return; // Expired
                }
            }
            
            // Format dates
            if (data.createdAt && data.createdAt.toDate) data.createdAt = data.createdAt.toDate().toISOString();
            if (data.updatedAt && data.updatedAt.toDate) data.updatedAt = data.updatedAt.toDate().toISOString();
            if (data.expiresAt && data.expiresAt.toDate) data.expiresAt = data.expiresAt.toDate().toISOString();

            results.push({
                id: doc.id,
                ...data
            });
        });

        // Search by tags? 
        // Firestore limits: In a compound query, range (<, <=, >, >=) and inequality (!=, not-in) comparisons must all filter on the same field.
        // So we cannot search (title prefix) OR (tags array-contains) in one query.
        // We will stick to title search as primary.
        
        const finalResponse = {
            hits: results,
            total: results.length, // Approximate
            from: 0, // Not supported well without more complex logic
            size: size,
            additional: { cache: 'miss' }
        };

        // 2. SAVE RESULTS TO CACHE
        if (redisClient) {
            try {
                await redisClient.set(cacheKey, JSON.stringify(finalResponse), 'EX', CACHE_TTL_SECONDS);
                console.log("CACHE SET:", cacheKey);
            } catch (err) {
                console.error("Redis SET error:", err.message);
            }
        }

        return res.status(200).send(finalResponse);

    } catch (error) {
        console.error("Error in route /searchSnippets:", error);
        return res.status(500).send({ error: 'Server error during search.' });
    }
});

module.exports = router;
