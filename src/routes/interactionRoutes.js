const express = require('express');
const router = express.Router();
const { admin, db, rtdb } = require('../services/firebase');
const { getActorInfo } = require('../utils/helpers');

const SNIPPETS_COLLECTION = 'snippets';

router.post('/starSnippet', async (req, res) => {
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

router.post('/copySnippet', async (req, res) => {
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

module.exports = router;
