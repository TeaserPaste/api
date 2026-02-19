const Redis = require('ioredis');

// --- 2.5. INITIALIZE REDIS CLIENT ---
let redisClient = null;
if (process.env.REDIS_URL) {
    try {
        redisClient = new Redis(process.env.REDIS_URL, {
            // Add safe options for production
            tls: process.env.REDIS_URL.startsWith('rediss://'),
            maxRetriesPerRequest: 3
        });
        redisClient.on('error', (err) => console.error("❌ Redis Error:", err.message));
        redisClient.on('connect', () => console.log("Redis client connected successfully."));
    } catch (e) {
        console.error("❌ Failed to initialize Redis client:", e.message);
    }
} else {
    console.warn("⚠️ REDIS_URL environment variable not set. Caching and View Count functionality will be disabled.");
}

module.exports = { redisClient };
