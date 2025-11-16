// index.js (Complete version for Vercel with OpenSearch)

const admin = require('firebase-admin');
const express = require('express');
const cors = require('cors');
const { Client } = require('@opensearch-project/opensearch');
const Redis = require('ioredis');

// --- 1. INITIALIZE FIREBASE ADMIN SDK ---
let serviceAccountCredentials;
let rtdb; // Variable for Realtime Database

try {
    // Ensure FIREBASE_PRIVATE_KEY is parsed correctly
    const privateKey = (process.env.FIREBASE_PRIVATE_KEY || '').replace(/\\n/g, '\n');
    
    if (!process.env.FIREBASE_PROJECT_ID || !privateKey || !process.env.FIREBASE_CLIENT_EMAIL) {
        throw new Error('Missing Firebase Admin SDK environment variables (PROJECT_ID, PRIVATE_KEY, CLIENT_EMAIL).');
    }

    serviceAccountCredentials = {
        type: 'service_account',
        project_id: process.env.FIREBASE_PROJECT_ID,
        private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID,
        private_key: privateKey,
        client_email: process.env.FIREBASE_CLIENT_EMAIL,
        client_id: process.env.FIREBASE_CLIENT_ID,
        auth_uri: 'https://accounts.google.com/o/oauth2/auth',
        token_uri: 'https://oauth2.googleapis.com/token',
        auth_provider_x509_cert_url: 'https://www.googleapis.com/oauth2/v1/certs',
        client_x509_cert_url: `https://www.googleapis.com/robot/v1/metadata/x509/${encodeURIComponent(process.env.FIREBASE_CLIENT_EMAIL)}`,
    };

    if (!admin.apps.length) {
        admin.initializeApp({
            credential: admin.credential.cert(serviceAccountCredentials),
            databaseURL: process.env.FIREBASE_DATABASE_URL // Add databaseURL for RTDB
        });
        console.log("Firebase Admin SDK initialized successfully.");
    }

    // Initialize services
    db = admin.firestore();
    rtdb = admin.database(); // Initialize Realtime Database
    console.log("Firestore and RTDB services initialized.");

} catch (e) {
    console.error("❌ Firebase Config Error: Make sure you have set all FIREBASE_* environment variables on Vercel.", e.message);
}

const app = express();

const SNIPPETS_COLLECTION = 'snippets';
const API_KEYS_COLLECTION = 'apiKeys';
const USERS_COLLECTION = 'users';

// --- 2. INITIALIZE OPENSEARCH CLIENT ---
let osClient = null;
if (process.env.OPENSEARCH_HOST && process.env.OPENSEARCH_USER && process.env.OPENSEARCH_PASSWORD) {
    const opensearchNode = `${process.env.OPENSEARCH_SCHEME || 'https'}://${process.env.OPENSEARCH_HOST}:${process.env.OPENSEARCH_PORT || '443'}`;
    const opensearchAuth = {
        username: process.env.OPENSEARCH_USER,
        password: process.env.OPENSEARCH_PASSWORD,
    };

    try {
        osClient = new Client({
            node: opensearchNode,
            auth: opensearchAuth,
            ssl: {
                rejectUnauthorized: process.env.NODE_ENV === 'production',
            },
        });
        console.log(`OpenSearch client initialized for node: ${opensearchNode}`);
        osClient.ping()
            .then(response => console.log('OpenSearch cluster ping successful.'))
            .catch(error => console.warn('OpenSearch cluster ping failed:', error.message));
    } catch (e) {
        console.error("❌ Failed to initialize OpenSearch client:", e.message);
    }
} else {
    console.warn("⚠️ OpenSearch environment variables (HOST, USER, PASSWORD) not set. Search functionality will be disabled.");
}

// --- 2.5. INITIALIZE REDIS CLIENT ---
const VIEW_TIMEOUT_MS = 300000; // 5 minutes (from use-view-snippet.ts)
const CACHE_TTL_SECONDS = 60; // 60 seconds for search cache

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


// --- 3. MIDDLEWARE ---
app.use(cors());
app.use(express.json());

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
app.use(apiKeyAuth);

// Helper to get user info (used internally)
const getActorInfo = async (userId) => {
    if (!userId) return { actorName: 'Anonymous', actorPhoto: null };
    try {
        const userRef = db.collection(USERS_COLLECTION).doc(userId);
        const userSnap = await userRef.get();
        if (!userSnap.exists) return { actorName: 'Anonymous', actorPhoto: null };
        const userData = userSnap.data();
        return {
            actorName: userData.displayName || 'Anonymous',
            actorPhoto: userData.photoURL || null
        };
    } catch (error) {
        console.error("Failed to fetch actor info:", error);
        return { actorName: 'Anonymous', actorPhoto: null }; // Fallback
    }
};

// --- 4. API ROUTES ---

app.post('/getSnippet', async (req, res) => {
    const { snippetId, password } = req.body;
    if (!snippetId) return res.status(400).send({ error: 'Missing snippetId.' });

    try {
        const docRef = db.collection(SNIPPETS_COLlection).doc(snippetId);
        const docSnap = await docRef.get();

        if (!docSnap.exists) return res.status(404).send({ error: `Snippet '${snippetId}' does not exist.` });
        
        const data = docSnap.data();
        const isOwner = req.userAuth && req.userAuth.userId === data.creatorId;

        // Check visibility
        if (data.visibility === 'deleted') return res.status(404).send({ error: 'This snippet has been deleted.' });
        if (data.visibility === 'private' && (!isOwner || req.userAuth.type !== 'private')) {
            return res.status(403).send({ error: `Snippet is PRIVATE and you do not have access.` });
        }

        // Check password
        let passwordBypassed = false;
        if (data.visibility === 'unlisted' && data.password && data.password.length > 0) {
            if (isOwner && req.userAuth.type === 'private') {
                passwordBypassed = true;
            } else if (password !== data.password) {
                if (!password) return res.status(401).send({ error: 'This snippet requires a password.', requiresPassword: true });
                return res.status(403).send({ error: 'Incorrect password.' });
            }
        }
        
        // ** NEW REQUIREMENT: VIEW COUNT AND TIMEOUT **
        if (redisClient && req.userAuth?.userId && req.userAuth.userId !== data.creatorId) {
            const userId = req.userAuth.userId;
            const redisKey = `view_tracker:${snippetId}:${userId}`;
            try {
                const viewed = await redisClient.get(redisKey);
                if (!viewed) {
                    // 1. Set timeout flag in Redis
                    await redisClient.set(redisKey, "1", "PX", VIEW_TIMEOUT_MS);
                    
                    // 2. Increment view count in RTDB (no need to wait)
                    if (rtdb) {
                        rtdb.ref(`view_counts/${snippetId}`).transaction((count) => (count || 0) + 1);
                        // Note: No notification for views, per frontend logic
                    }
                }
            } catch (e) {
                console.warn("Redis/RTDB view count error:", e.message);
                // Don't block the response if view count logic fails
            }
        }

        // Prepare response data
        const responseData = { id: docSnap.id, ...data, passwordBypassed };
        if (responseData.createdAt && responseData.createdAt.toDate) {
            responseData.createdAt = responseData.createdAt.toDate().toISOString();
        }
        if (responseData.updatedAt && responseData.updatedAt.toDate) {
            responseData.updatedAt = responseData.updatedAt.toDate().toISOString();
        }
         if (responseData.expiresAt && responseData.expiresAt.toDate) {
            responseData.expiresAt = responseData.expiresAt.toDate().toISOString();
        }
        
        return res.status(200).send(responseData);

    } catch (error) {
         console.error("Error in route /getSnippet:", error);
        return res.status(500).send({ error: 'Server error while getting snippet.' });
    }
});

app.get('/getUserInfo', async (req, res) => {
    if (!req.userAuth || !req.userAuth.userId) return res.status(401).send({ error: 'A valid API key is required.' });
    try {
        const { actorName, actorPhoto } = await getActorInfo(req.userAuth.userId);
        return res.status(200).send({ 
            userId: req.userAuth.userId, 
            displayName: actorName, 
            photoURL: actorPhoto 
        });
    } catch (error) {
         console.error("Error in route /getUserInfo:", error);
        return res.status(500).send({ error: 'Server error while querying user information.' });
    }
});

function calculateExpiresAt(expires) {
    if (!expires) return null;
    const unit = expires.slice(-1).toLowerCase();
    const value = parseInt(expires.slice(0, -1), 10);
    if (isNaN(value)) return null;

    const now = new Date();
    if (unit === 'm') now.setMinutes(now.getMinutes() + value); // Add minutes
    else if (unit === 'h') now.setHours(now.getHours() + value);
    else if (unit === 'd') now.setDate(now.getDate() + value);
    else if (unit === 'w') now.setDate(now.getDate() + (value * 7));
    else return null;
    return admin.firestore.Timestamp.fromDate(now); // Return Timestamp
}

app.post('/createSnippet', async (req, res) => {
    if (!req.userAuth || req.userAuth.type !== 'private') return res.status(403).send({ error: 'A private key is required to create a snippet.' });
    try {
        const { title, content, language = 'plaintext', visibility = 'unlisted', tags = [], password = '', expires = null } = req.body;
        if (!title || !content) return res.status(400).send({ error: 'Title and content are required.' });
        
        const { actorName, actorPhoto } = await getActorInfo(req.userAuth.userId);

        const newSnippetData = {
            title, content, language, visibility,
            tags: Array.isArray(tags) ? tags.slice(0, 10) : [], // Limit 10 tags
            password: visibility === 'unlisted' ? password : '',
            creatorId: req.userAuth.userId,
            creatorName: actorName,
            creatorPhotoURL: actorPhoto,
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
            updatedAt: admin.firestore.FieldValue.serverTimestamp(),
            expiresAt: calculateExpiresAt(expires),
            isVerified: false,
            copyCount: 0, // Initialize
            starCount: 0  // Initialize
        };

        const docRef = await db.collection(SNIPPETS_COLLECTION).add(newSnippetData);
        const savedDoc = await docRef.get();
        const savedData = savedDoc.data();
         
        if (savedData.createdAt && savedData.createdAt.toDate) {
            savedData.createdAt = savedData.createdAt.toDate().toISOString();
        }
        if (savedData.updatedAt && savedData.updatedAt.toDate) {
            savedData.updatedAt = savedData.updatedAt.toDate().toISOString();
        }
         if (savedData.expiresAt && savedData.expiresAt.toDate) {
            savedData.expiresAt = savedData.expiresAt.toDate().toISOString();
        }

        return res.status(201).send({ id: docRef.id, ...savedData });
    } catch (error) {
        console.error("Error in route /createSnippet:", error);
        return res.status(500).send({ error: 'Server error while creating snippet.' });
    }
});

app.patch('/updateSnippet', async (req, res) => {
    if (!req.userAuth || req.userAuth.type !== 'private') return res.status(403).send({ error: 'A private key is required to update a snippet.' });
    try {
        const { snippetId, updates } = req.body;
        if (!snippetId || !updates) return res.status(400).send({ error: 'Missing snippet ID or update data.' });
        
        const snippetRef = db.collection(SNIPPETS_COLLECTION).doc(snippetId);
        const docSnap = await snippetRef.get();
        
        if (!docSnap.exists) return res.status(404).send({ error: 'Snippet does not exist.' });
        if (docSnap.data().creatorId !== req.userAuth.userId) return res.status(403).send({ error: 'You do not have permission to edit this snippet.' });
        if (docSnap.data().visibility === 'deleted') return res.status(400).send({ error: 'Cannot edit a deleted snippet.' });

        const allowedUpdates = ['title', 'content', 'language', 'visibility', 'password', 'tags', 'expiresAt'];
        const validUpdates = {};
        for (const key of Object.keys(updates)) { 
            if (allowedUpdates.includes(key)) {
                if (key === 'expiresAt') {
                    validUpdates[key] = calculateExpiresAt(updates[key]);
                } else if (key === 'tags') {
                    validUpdates[key] = Array.isArray(updates[key]) ? updates[key].slice(0, 10) : [];
                } else {
                    validUpdates[key] = updates[key];
                }
            }
        }
        if (Object.keys(validUpdates).length === 0) return res.status(400).send({ error: 'No valid fields to update.' });

        if (validUpdates.visibility && validUpdates.visibility !== 'unlisted') {
            validUpdates.password = ''; 
        } else if ('visibility' in validUpdates && validUpdates.visibility === 'unlisted' && !('password' in validUpdates)) {
             delete validUpdates.password;
        }

        validUpdates.updatedAt = admin.firestore.FieldValue.serverTimestamp(); // Always update timestamp

        await snippetRef.update(validUpdates);
        const updatedDoc = await snippetRef.get();
        const updatedData = updatedDoc.data();
        
        if (updatedData.createdAt && updatedData.createdAt.toDate) {
            updatedData.createdAt = updatedData.createdAt.toDate().toISOString();
        }
        if (updatedData.updatedAt && updatedData.updatedAt.toDate) {
            updatedData.updatedAt = updatedData.updatedAt.toDate().toISOString();
        }
        if (updatedData.expiresAt && updatedData.expiresAt.toDate) {
            updatedData.expiresAt = updatedData.expiresAt.toDate().toISOString();
        }
        return res.status(200).send({ id: updatedDoc.id, ...updatedData });
    } catch (error) {
        console.error("Error in route /updateSnippet:", error);
        return res.status(500).send({ error: 'Server error while updating snippet.' });
    }
});

app.delete('/deleteSnippet', async (req, res) => {
    // ** UPDATE: Add oldVisibility on delete **
    if (!req.userAuth || req.userAuth.type !== 'private') return res.status(403).send({ error: 'A private key is required to delete a snippet.' });
    try {
        const { snippetId } = req.body;
        if (!snippetId) return res.status(400).send({ error: 'Missing snippet ID.' });
        
        const snippetRef = db.collection(SNIPPETS_COLLECTION).doc(snippetId);
        const docSnap = await snippetRef.get();
        
        if (!docSnap.exists) return res.status(404).send({ error: 'Snippet does not exist.' });
        if (docSnap.data().creatorId !== req.userAuth.userId) return res.status(403).send({ error: 'You do not have permission to delete this snippet.' });
        
        const currentVisibility = docSnap.data().visibility;
        if (currentVisibility === 'deleted') {
            return res.status(400).send({ error: 'This snippet has already been deleted.' });
        }

        await snippetRef.update({ 
            visibility: 'deleted',
            oldVisibility: currentVisibility, // Add oldVisibility field
            updatedAt: admin.firestore.FieldValue.serverTimestamp() // Add timestamp
        });

        return res.status(200).send({ message: `Snippet '${snippetId}' has been moved to the trash.` });
    } catch (error) {
        console.error("Error in route /deleteSnippet:", error);
        return res.status(500).send({ error: 'Server error while deleting snippet.' });
    }
});

// ** NEW ROUTE: /restoreSnippet **
app.post('/restoreSnippet', async (req, res) => {
    if (!req.userAuth || req.userAuth.type !== 'private') return res.status(403).send({ error: 'A private key is required to restore a snippet.' });
    try {
        const { snippetId } = req.body;
        if (!snippetId) return res.status(400).send({ error: 'Missing snippet ID.' });

        const snippetRef = db.collection(SNIPPETS_COLLECTION).doc(snippetId);
        const docSnap = await snippetRef.get();

        if (!docSnap.exists) return res.status(404).send({ error: 'Snippet does not exist.' });
        if (docSnap.data().creatorId !== req.userAuth.userId) return res.status(403).send({ error: 'You do not have permission to restore this snippet.' });
        if (docSnap.data().visibility !== 'deleted') return res.status(400).send({ error: 'This snippet is not in the trash.' });

        const newVisibility = docSnap.data().oldVisibility || 'private'; // Restore to 'private' if unknown

        await snippetRef.update({
            visibility: newVisibility,
            oldVisibility: admin.firestore.FieldValue.delete(), // Delete oldVisibility field
            updatedAt: admin.firestore.FieldValue.serverTimestamp()
        });
        
        return res.status(200).send({ message: `Snippet '${snippetId}' has been restored to '${newVisibility}' state.` });

    } catch (error) {
        console.error("Error in route /restoreSnippet:", error);
        return res.status(500).send({ error: 'Server error while restoring snippet.' });
    }
});

// ** NEW ROUTE: /starSnippet **
app.post('/starSnippet', async (req, res) => {
    if (!rtdb) return res.status(503).send({ error: 'Realtime Database service is not available.' });
    if (!req.userAuth || req.userAuth.type !== 'private') return res.status(403).send({ error: 'A private key is required to star a snippet.' });
    
    try {
        const { snippetId, star } = req.body; // star is boolean (true: star, false: unstar)
        if (!snippetId || typeof star !== 'boolean') {
            return res.status(400).send({ error: 'Missing snippetId or star status (boolean).' });
        }

        const userId = req.userAuth.userId;
        const snippetSnap = await db.collection(SNIPPETS_COLLECTION).doc(snippetId).get();
        if (!snippetSnap.exists) return res.status(404).send({ error: 'Snippet does not exist.' });
        
        const snippet = snippetSnap.data();
        if (snippet.creatorId === userId) return res.status(403).send({ error: 'You cannot star your own snippet.' });
        
        const starCountRef = rtdb.ref(`star_counts/${snippetId}`);
        const starDetailsRef = rtdb.ref(`star_details/${snippetId}/${userId}`);
        const isStarredSnap = await starDetailsRef.once('value');
        const isStarred = isStarredSnap.exists();

        if (star && !isStarred) {
            // Star
            await starCountRef.transaction((count) => (count || 0) + 1);
            await starDetailsRef.set(true);

            // Send notification
            const { actorName } = await getActorInfo(userId);
            const notificationsRef = rtdb.ref(`notifications/${snippet.creatorId}`);
            await notificationsRef.push({
                type: 'star',
                actorUid: userId,
                actorName: actorName,
                snippetId: snippetId,
                snippetTitle: snippet.title,
                timestamp: admin.database.ServerValue.TIMESTAMP, // Use RTDB server timestamp
                read: false,
            });
            return res.status(200).send({ status: 'starred', starCount: (await starCountRef.once('value')).val() });

        } else if (!star && isStarred) {
            // Unstar
            await starCountRef.transaction((count) => (count > 0 ? count - 1 : 0));
            await starDetailsRef.set(null);
            return res.status(200).send({ status: 'unstarred', starCount: (await starCountRef.once('value')).val() });
        }
        
        // State unchanged
        return res.status(200).send({ status: isStarred ? 'already_starred' : 'already_unstarred', starCount: (await starCountRef.once('value')).val() });

    } catch (error) {
        console.error("Error in route /starSnippet:", error);
        return res.status(500).send({ error: 'Server error while starring snippet.' });
    }
});

// ** NEW ROUTE: /copySnippet **
app.post('/copySnippet', async (req, res) => {
    if (!req.userAuth || req.userAuth.type !== 'private') return res.status(403).send({ error: 'A private key is required to copy a snippet.' });
    
    try {
        const { snippetId } = req.body;
        if (!snippetId) return res.status(400).send({ error: 'Missing snippetId.' });

        const userId = req.userAuth.userId;
        const originalSnippetRef = db.collection(SNIPPETS_COLLECTION).doc(snippetId);
        const originalSnap = await originalSnippetRef.get();

        if (!originalSnap.exists) return res.status(404).send({ error: 'Original snippet does not exist.' });
        
        const originalData = originalSnap.data();
        
        // Access check (like /getSnippet, no password check as API key has rights)
        if (originalData.visibility === 'deleted') return res.status(404).send({ error: 'Original snippet has been deleted.' });
        if (originalData.visibility === 'private' && originalData.creatorId !== userId) {
            return res.status(403).send({ error: 'You do not have permission to copy this private snippet.' });
        }
        if (originalData.creatorId === userId) return res.status(403).send({ error: 'You cannot copy your own snippet.' });

        const { actorName, actorPhoto } = await getActorInfo(userId);
        
        // Use batch write
        const batch = db.batch();
        const newSnippetRef = db.collection(SNIPPETS_COLLECTION).doc(); // Create new ref

        const {
            id, isVerified, oldVisibility, // Remove unnecessary fields
            creatorId, creatorName, creatorPhotoURL, // Replace with copier
            createdAt, updatedAt, // Create new
            starCount, copyCount, // Reset
            ...restOfSnippet // Keep title, content, language, tags, etc.
        } = originalData;

        const newSnippetData = {
            ...restOfSnippet,
            creatorId: userId,
            creatorName: actorName,
            creatorPhotoURL: actorPhoto,
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
            updatedAt: admin.firestore.FieldValue.serverTimestamp(),
            originalSnippetId: snippetId, // Track original snippet
            originalCreatorId: originalData.creatorId,
            originalCreatorName: originalData.creatorName,
            starCount: 0,
            copyCount: 0,
            visibility: 'private', // Always private when copied
            password: '', // Remove password
            expiresAt: null, // Remove expiration
        };

        batch.set(newSnippetRef, newSnippetData);

        // Increment copyCount of original snippet
        batch.update(originalSnippetRef, {
            copyCount: admin.firestore.FieldValue.increment(1),
            updatedAt: admin.firestore.FieldValue.serverTimestamp()
        });

        await batch.commit();

        // Send notification (RTDB)
        if (rtdb) {
            const notificationsRef = rtdb.ref(`notifications/${originalData.creatorId}`);
            await notificationsRef.push({
                type: 'copy',
                actorUid: userId,
                actorName: actorName,
                snippetId: snippetId, // Original snippet ID
                snippetTitle: originalData.title,
                newSnippetId: newSnippetRef.id, // New snippet ID (if needed)
                timestamp: admin.database.ServerValue.TIMESTAMP,
                read: false,
            });
        }

        return res.status(201).send({ 
            message: 'Snippet copied successfully.', 
            newSnippetId: newSnippetRef.id 
        });

    } catch (error) {
        console.error("Error in route /copySnippet:", error);
        return res.status(500).send({ error: 'Server error while copying snippet.' });
    }
});


app.post('/listSnippets', async (req, res) => {
    if (!req.userAuth || req.userAuth.type !== 'private') return res.status(403).send({ error: 'A private key is required to list snippets.' });
    try {
        let { limit = 20, visibility, includeDeleted = false } = req.body;
        limit = Math.min(Math.max(1, parseInt(limit, 10)), 100); // Limit 1-100

        let query = db.collection(SNIPPETS_COLLECTION).where('creatorId', '==', req.userAuth.userId);
        
        if (visibility) {
            query = query.where('visibility', '==', visibility);
        } else if (!includeDeleted) {
            // Default: exclude deleted snippets, unless visibility='deleted'
            query = query.where('visibility', '!=', 'deleted');
        }

        const snapshot = await query.orderBy('updatedAt', 'desc').limit(limit).get(); // Sort by updatedAt
        
        const snippets = snapshot.docs.map(doc => {
             const data = doc.data();
             if (data.createdAt && data.createdAt.toDate) {
                data.createdAt = data.createdAt.toDate().toISOString();
             }
             if (data.updatedAt && data.updatedAt.toDate) {
                data.updatedAt = data.updatedAt.toDate().toISOString();
             }
             if (data.expiresAt && data.expiresAt.toDate) {
                 data.expiresAt = data.expiresAt.toDate().toISOString();
             }
            return { id: doc.id, ...data };
        });
        return res.status(200).send(snippets);
    } catch (error) {
         console.error("Error in route /listSnippets:", error);
        return res.status(500).send({ error: 'Server error while listing snippets.' });
    }
});

app.post('/getUserPublicSnippets', async (req, res) => {
    try {
        const { userId } = req.body;
        if (!userId) return res.status(400).send({ error: 'Missing userId.' });
        
        const snapshot = await db.collection(SNIPPETS_COLLECTION)
            .where('creatorId', '==', userId)
            .where('visibility', '==', 'public')
            // Skip expired snippets (if any)
            .where('expiresAt', '>', admin.firestore.Timestamp.now())
            .orderBy('expiresAt') // Must orderBy the comparison field
            .orderBy('createdAt', 'desc')
            .limit(20)
            .get();

        // Need a separate query for snippets that never expire
        const noExpirySnapshot = await db.collection(SNIPPETS_COLLECTION)
            .where('creatorId', '==', userId)
            .where('visibility', '==', 'public')
            .where('expiresAt', '==', null)
            .orderBy('createdAt', 'desc')
            .limit(20)
            .get();

        const snippetsMap = new Map();
        snapshot.docs.forEach(doc => {
            const data = doc.data();
            if (data.createdAt && data.createdAt.toDate) data.createdAt = data.createdAt.toDate().toISOString();
            if (data.updatedAt && data.updatedAt.toDate) data.updatedAt = data.updatedAt.toDate().toISOString();
            if (data.expiresAt && data.expiresAt.toDate) data.expiresAt = data.expiresAt.toDate().toISOString();
            snippetsMap.set(doc.id, { id: doc.id, ...data });
        });
        noExpirySnapshot.docs.forEach(doc => {
             const data = doc.data();
             if (data.createdAt && data.createdAt.toDate) data.createdAt = data.createdAt.toDate().toISOString();
             if (data.updatedAt && data.updatedAt.toDate) data.updatedAt = data.updatedAt.toDate().toISOString();
             if (data.expiresAt && data.expiresAt.toDate) data.expiresAt = data.expiresAt.toDate().toISOString();
            snippetsMap.set(doc.id, { id: doc.id, ...data });
        });

        const snippets = Array.from(snippetsMap.values())
            .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()) // Re-sort
            .slice(0, 20); // Take 20
            
        return res.status(200).send(snippets);
    } catch (error) {
         console.error("Error in route /getUserPublicSnippets:", error);
        return res.status(500).send({ error: 'Server error while getting public snippets.' });
    }
});


// --- UPDATE ROUTE /searchSnippets ---
app.post('/searchSnippets', async (req, res) => {
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

        const searchTerm = term.trim();
        const cacheKey = `search:${searchTerm}:size${size}:from${from}`;

        // 1. CHECK CACHE FIRST
        if (redisClient) {
            try {
                const cachedResults = await redisClient.get(cacheKey);
                if (cachedResults) {
                    console.log("CACHE HIT:", cacheKey);
                    return res.status(200).send(JSON.parse(cachedResults));
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
                                fields: ["title^5", "tags^3", "content^1", "creatorName"],
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
                                    { range: { expiresAt: { gt: "now/ms" } } } // Or greater than now
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
            // Add highlight (optional)
             highlight: {
                pre_tags: ["<mark>"],
                post_tags: ["</mark>"],
                fields: {
                    "title": {},
                    "content": {}
                }
            }
        };

        const response = await osClient.search({
            index: indexName,
            body: queryBody,
        });

        const results = response.body.hits.hits.map(hit => ({
            id: hit._id,
            ...hit._source,
            highlight: hit.highlight // Add highlight
        }));

        const finalResponse = {
            hits: results,
            total: response.body.hits.total.value,
            from: from,
            size: size
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
        console.error("Error in route /searchSnippets:", error.meta ? error.meta.body : error.message);
        const errorMessage = error.meta?.body?.error?.reason || 'Server error during search.';
        return res.status(500).send({ error: errorMessage });
    }
});

// --- 5. EXPORT APP FOR VERCEL ---
module.exports = app;