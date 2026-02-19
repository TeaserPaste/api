const express = require('express');
const router = express.Router();
const { admin, db, rtdb } = require('../services/firebase');
const { redisClient } = require('../services/redis');
const { getActorInfo, calculateExpiresAt } = require('../utils/helpers');

const SNIPPETS_COLLECTION = 'snippets';
const VIEW_TIMEOUT_MS = 300000; // 5 minutes

router.post('/getSnippet', async (req, res) => {
    const { snippetId, password } = req.body;
    if (!snippetId) return res.status(400).send({ error: 'Missing snippetId.' });

    try {
        const docRef = db.collection(SNIPPETS_COLLECTION).doc(snippetId);
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

router.post('/createSnippet', async (req, res) => {
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

router.patch('/updateSnippet', async (req, res) => {
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

router.delete('/deleteSnippet', async (req, res) => {
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

router.post('/restoreSnippet', async (req, res) => {
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

router.post('/listSnippets', async (req, res) => {
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

router.post('/getUserPublicSnippets', async (req, res) => {
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

module.exports = router;
