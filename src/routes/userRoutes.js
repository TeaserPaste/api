const express = require('express');
const router = express.Router();
const { getActorInfo } = require('../utils/helpers');

router.get('/getUserInfo', async (req, res) => {
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

module.exports = router;
