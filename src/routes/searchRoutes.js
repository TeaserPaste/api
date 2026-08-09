const express = require('express');
const router = express.Router();
const { redisClient } = require('../services/redis');
const { osClient } = require('../services/opensearch');

const CACHE_TTL_SECONDS = 300;

router.post('/searchSnippets', async (req, res) => {
    if (!osClient) {
        return res.status(503).send({ error: 'Search service is currently unavailable.' });
    }

    try {
        const { term } = req.body;
        const size = parseInt(req.body.size, 10) || 20;
        const from = parseInt(req.body.from, 10) || 0;

        if (!term || typeof term !== 'string' || term.trim() === '') {
            return res.status(400).send({ error: 'Missing or invalid: term (search keyword).' });
        }

        if (term.length > 100) {
            return res.status(400).send({ error: 'term must be 100 characters or less.' });
        }

        const trimmedTerm = term.trim();
        const searchTerm = trimmedTerm.replace(/\s+/g, ' ').toLowerCase();
        const cacheKey = `search:${searchTerm}:size${size}:from${from}`;

        // 1. CHECK CACHE FIRST
        if (redisClient) {
            try {
                const cachedResults = await redisClient.get(cacheKey);
                if (cachedResults) {
                    console.log("CACHE HIT:", cacheKey);
                    res.setHeader('X-Cache', 'HIT');

                    const parsedData = JSON.parse(cachedResults);
                    if (parsedData.additional) {
                        parsedData.additional.cache = 'hit';
                    }

                    return res.status(200).json(parsedData);
                }
                console.log("CACHE MISS:", cacheKey);
            } catch (err) {
                console.error("Redis GET error:", err.message);
            }
        }

        const indexName = process.env.OPENSEARCH_INDEX || 'snippets';

        const queryBody = {
            size: size,
            from: from,
            query: {
                bool: {
                    should: [
                        {
                            multi_match: {
                                query: searchTerm,
                                fields: ["title^5", "tags^3", "creatorName"], 
                                fuzziness: "AUTO",
                                operator: "OR"
                            }
                        },
                        {
                            multi_match: {
                                query: searchTerm,
                                type: "phrase_prefix",
                                fields: ["title^10", "tags^5"],
                            }
                        }
                    ],
                    minimum_should_match: 1,
                    filter: [
                        { term: { "visibility.keyword": "public" } },
                        // Add filter for expiresAt
                        {
                            bool: {
                                should: [
                                    { bool: { must_not: { exists: { field: "expiresAt" } } } }, // Or does not exist
                                    { range: { expiresAt: { gt: "now/m" } } } // Or greater than now
                                ]
                            }
                        }
                    ]
                }
            },
            sort: [
                { "_score": { "order": "desc" } },
                { "ai_priority": { "order": "desc", "missing": "_last" } },
                { "createdAt": { "order": "desc" } }
            ],
            // Highlight feature (Optional)
            /*
             highlight: {
                pre_tags: ["<mark>"],
                post_tags: ["</mark>"],
                fields: {
                    "title": {},
                    "content": {}
                }
            }
            */
        };

        const response = await osClient.search({
            index: indexName,
            body: queryBody,
        });

        const results = response.body.hits.hits.map(hit => ({
            id: hit._id,
            ...hit._source,
            // highlight: hit.highlight 
        }));

        const finalResponse = {
            hits: results,
            total: response.body.hits.total.value,
            from: from,
            size: size,
            additional: { cache: 'miss' }
        };

        // 2. SAVE RESULTS TO CACHE
        if (redisClient) {
            try {
                // Requirement 3: Use CACHE_TTL_SECONDS (now set to 300)
                await redisClient.set(cacheKey, JSON.stringify(finalResponse), 'EX', CACHE_TTL_SECONDS);
                console.log("CACHE SET:", cacheKey);
            } catch (err) {
                console.error("Redis SET error:", err.message);
            }
        }

        return res.status(200).send(finalResponse);

    } catch (error) {
        console.error("Error in route /searchSnippets:", error.meta ? error.meta.body : error.message);
        const errorMessage = error.meta?.body?.error?.reason || 'Server error during search.';
        return res.status(500).send({ error: errorMessage });
    }
});

const fetchSnippetHandler = async (req, res) => {
    if (!osClient) {
        return res.status(503).send({ error: 'Search service is currently unavailable.' });
    }

    try {
        const id = req.query.id || req.query.snippetId || req.body?.id || req.body?.snippetId;
        const fields = req.body?.fields || req.query?.fields;

        if (!id || typeof id !== 'string' || id.trim() === '') {
            return res.status(400).send({ error: 'Missing or invalid: id.' });
        }

        const trimmedId = id.trim();
        let sourceFiltering = true;

        if (fields) {
            if (Array.isArray(fields)) {
                sourceFiltering = fields;
            } else if (typeof fields === 'string') {
                sourceFiltering = fields.split(',').map(f => f.trim()).filter(Boolean);
            }
        }

        if (Array.isArray(sourceFiltering) && sourceFiltering.length === 0) {
            sourceFiltering = true;
        }

        // Sort fields to make cacheKey deterministic
        let cacheFields = sourceFiltering;
        if (Array.isArray(cacheFields)) {
            cacheFields = [...cacheFields].sort();
        }
        const cacheKey = `snippet:${trimmedId}:fields:${JSON.stringify(cacheFields)}`;

        // 1. CHECK CACHE FIRST
        if (redisClient) {
            try {
                const cachedSnippet = await redisClient.get(cacheKey);
                if (cachedSnippet) {
                    console.log("CACHE HIT:", cacheKey);
                    res.setHeader('X-Cache', 'HIT');
                    return res.status(200).json(JSON.parse(cachedSnippet));
                }
                console.log("CACHE MISS:", cacheKey);
            } catch (err) {
                console.error("Redis GET error:", err.message);
            }
        }

        const getParams = {
            index: process.env.OPENSEARCH_INDEX || 'snippets',
            id: trimmedId,
        };

        if (sourceFiltering !== true) {
            getParams._source = sourceFiltering;
        }

        const response = await osClient.get(getParams);

        if (response.body && response.body.found) {
            const responseData = {
                id: response.body._id,
                ...response.body._source
            };

            // 2. SAVE TO CACHE (TTL 30 seconds)
            if (redisClient) {
                try {
                    await redisClient.set(cacheKey, JSON.stringify(responseData), 'EX', 30);
                    console.log("CACHE SET:", cacheKey);
                } catch (err) {
                    console.error("Redis SET error:", err.message);
                }
            }

            res.setHeader('X-Cache', 'MISS');
            return res.status(200).send(responseData);
        } else {
            return res.status(404).send({ error: `Snippet '${trimmedId}' not found.` });
        }

    } catch (error) {
        const is404 = error.status === 404 || 
                      error.statusCode === 404 || 
                      error.meta?.statusCode === 404 || 
                      error.meta?.status === 404;

        if (is404) {
            const id = req.body.id || req.query.id || req.body.snippetId || req.query.snippetId;
            const trimmedId = typeof id === 'string' ? id.trim() : '';
            return res.status(404).send({ error: `Snippet '${trimmedId}' not found.` });
        }

        console.error("Error in route /fetchSnippet:", error.meta ? error.meta.body : error.message);
        const errorMessage = error.meta?.body?.error?.reason || 'Server error while fetching snippet.';
        return res.status(500).send({ error: errorMessage });
    }
};

router.post('/fetchSnippet', fetchSnippetHandler);
router.get('/fetchSnippet', fetchSnippetHandler);

module.exports = router;

