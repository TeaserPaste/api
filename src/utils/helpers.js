const { admin, db } = require('../services/firebase');

const USERS_COLLECTION = 'users';

// Helper to get user info
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

module.exports = { getActorInfo, calculateExpiresAt };
