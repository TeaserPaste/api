// index.js (Phiên bản hoàn chỉnh cho Vercel)

const admin = require('firebase-admin');
const express = require('express');
const cors = require('cors');

// --- 1. KHỞI TẠO FIREBASE ADMIN SDK ---
let serviceAccountCredentials;
try {
    const privateKey = process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n');
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
} catch (e) {
    console.error("❌ Lỗi Config: Hãy chắc chắn rằng bạn đã thiết lập đầy đủ các biến môi trường FIREBASE_* trên Vercel.", e);
}

if (!admin.apps.length) {
    admin.initializeApp({
        credential: admin.credential.cert(serviceAccountCredentials),
    });
}

const db = admin.firestore();
const app = express();

const SNIPPETS_COLLECTION = 'snippets';
const API_KEYS_COLLECTION = 'apiKeys';
const USERS_COLLECTION = 'users';

// --- 2. MIDDLEWARE ---
app.use(cors()); 
app.use(express.json());

const apiKeyAuth = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return next();
        }
        const apiKey = authHeader.split(' ')[1];
        if (!apiKey) {
            return res.status(401).send({ error: 'Định dạng API Key không hợp lệ.' });
        }
        const keysSnapshot = await db.collection(API_KEYS_COLlection).get();
        let userAuth = null;
        for (const doc of keysSnapshot.docs) {
            const data = doc.data();
            if (data.publicKey === apiKey) { userAuth = { userId: doc.id, type: 'public' }; break; }
            if (data.privateKey === apiKey) { userAuth = { userId: doc.id, type: 'private' }; break; }
        }
        if (!userAuth) {
            return res.status(403).send({ error: 'API Key không hợp lệ hoặc đã hết hạn.' });
        }
        req.userAuth = userAuth;
        next();
    } catch (error) {
        return res.status(500).send({ error: 'Lỗi máy chủ khi xác thực API key.' });
    }
};
app.use(apiKeyAuth);

// --- 3. CÁC ROUTES API ---

app.post('/getSnippet', async (req, res) => {
    const { snippetId, password } = req.body;
    if (!snippetId) return res.status(400).send({ error: 'Thiếu snippetId.' });
    try {
        const docSnap = await db.collection(SNIPPETS_COLLECTION).doc(snippetId).get();
        if (!docSnap.exists) return res.status(404).send({ error: `Snippet '${snippetId}' không tồn tại.` });
        const data = docSnap.data();
        const isOwner = req.userAuth && req.userAuth.userId === data.creatorId;
        if (data.visibility === 'private' && (!isOwner || req.userAuth.type !== 'private')) {
            return res.status(403).send({ error: `Snippet là PRIVATE và bạn không có quyền truy cập.` });
        }
        let passwordBypassed = false;
        if (data.visibility === 'unlisted' && data.password && data.password.length > 0) {
            if (isOwner && req.userAuth.type === 'private') { passwordBypassed = true; } 
            else if (password !== data.password) {
                if (!password) return res.status(401).send({ error: 'Snippet này cần mật khẩu.', requiresPassword: true });
                return res.status(403).send({ error: 'Mật khẩu không chính xác.' });
            }
        }
        const responseData = { id: docSnap.id, ...data, passwordBypassed };
        return res.status(200).send(responseData);
    } catch (error) {
        return res.status(500).send({ error: 'Lỗi máy chủ khi lấy snippet.' });
    }
});

app.get('/getUserInfo', async (req, res) => {
    if (!req.userAuth || !req.userAuth.userId) return res.status(401).send({ error: 'Yêu cầu cần có API key hợp lệ.' });
    try {
        const userRef = db.collection(USERS_COLLECTION).doc(req.userAuth.userId);
        const userSnap = await userRef.get();
        if (!userSnap.exists) return res.status(404).send({ error: 'Không tìm thấy người dùng.' });
        const userData = userSnap.data();
        const publicUserInfo = { userId: userSnap.id, displayName: userData.displayName || 'Anonymous', photoURL: userData.photoURL || null };
        return res.status(200).send(publicUserInfo);
    } catch (error) {
        return res.status(500).send({ error: 'Lỗi máy chủ khi truy vấn thông tin người dùng.' });
    }
});

function calculateExpiresAt(expires) {
    if (!expires) return null;
    const unit = expires.slice(-1).toLowerCase();
    const value = parseInt(expires.slice(0, -1), 10);
    if (isNaN(value)) return null;

    const now = new Date();
    if (unit === 'h') now.setHours(now.getHours() + value);
    else if (unit === 'd') now.setDate(now.getDate() + value);
    else if (unit === 'w') now.setDate(now.getDate() + (value * 7));
    else return null;
    return now;
}

app.post('/createSnippet', async (req, res) => {
    if (!req.userAuth || req.userAuth.type !== 'private') return res.status(403).send({ error: 'Cần có private key để tạo snippet.' });
    try {
        const { title, content, language = 'plaintext', visibility = 'unlisted', tags = [], password = '', expires = null } = req.body;
        if (!title || !content) return res.status(400).send({ error: 'Tiêu đề và nội dung là bắt buộc.' });
        const userRef = await db.collection(USERS_COLLECTION).doc(req.userAuth.userId).get();
        if (!userRef.exists) return res.status(404).send({ error: 'Người dùng không tồn tại.' });
        
        const newSnippetData = { 
            title, content, language, visibility, 
            tags: Array.isArray(tags) ? tags : [], 
            password: visibility === 'unlisted' ? password : '', 
            creatorId: req.userAuth.userId, 
            creatorName: userRef.data().displayName || 'Anonymous', 
            createdAt: new Date(), 
            expiresAt: calculateExpiresAt(expires), 
            hasSensitiveContent: false, 
            isVerified: false 
        };

        const docRef = await db.collection(SNIPPETS_COLLECTION).add(newSnippetData);
        return res.status(201).send({ id: docRef.id, ...newSnippetData });
    } catch (error) {
        console.error("Lỗi route /createSnippet:", error);
        return res.status(500).send({ error: 'Lỗi máy chủ khi tạo snippet.' });
    }
});

app.patch('/updateSnippet', async (req, res) => {
    if (!req.userAuth || req.userAuth.type !== 'private') return res.status(403).send({ error: 'Cần có private key để cập nhật snippet.' });
    try {
        const { snippetId, updates } = req.body;
        if (!snippetId || !updates) return res.status(400).send({ error: 'Thiếu ID snippet hoặc dữ liệu cập nhật.' });
        const snippetRef = db.collection(SNIPPETS_COLLECTION).doc(snippetId);
        const docSnap = await snippetRef.get();
        if (!docSnap.exists) return res.status(404).send({ error: 'Snippet không tồn tại.' });
        if (docSnap.data().creatorId !== req.userAuth.userId) return res.status(403).send({ error: 'Bạn không có quyền chỉnh sửa snippet này.' });
        
        const allowedUpdates = ['title', 'content', 'language', 'visibility', 'password', 'tags'];
        const validUpdates = {};
        for (const key of Object.keys(updates)) { if (allowedUpdates.includes(key)) validUpdates[key] = updates[key]; }
        if (Object.keys(validUpdates).length === 0) return res.status(400).send({ error: 'Không có trường hợp lệ nào để cập nhật.' });
        
        await snippetRef.update(validUpdates);
        const updatedDoc = await snippetRef.get();
        return res.status(200).send({ id: updatedDoc.id, ...updatedDoc.data() });
    } catch (error) {
        return res.status(500).send({ error: 'Lỗi máy chủ khi cập nhật snippet.' });
    }
});

app.delete('/deleteSnippet', async (req, res) => {
    if (!req.userAuth || req.userAuth.type !== 'private') return res.status(403).send({ error: 'Cần có private key để xóa snippet.' });
    try {
        const { snippetId } = req.body;
        if (!snippetId) return res.status(400).send({ error: 'Thiếu ID snippet.' });
        const snippetRef = db.collection(SNIPPETS_COLLECTION).doc(snippetId);
        const docSnap = await snippetRef.get();
        if (!docSnap.exists) return res.status(404).send({ error: 'Snippet không tồn tại.' });
        if (docSnap.data().creatorId !== req.userAuth.userId) return res.status(403).send({ error: 'Bạn không có quyền xóa snippet này.' });
        await snippetRef.delete();
        return res.status(200).send({ message: `Snippet '${snippetId}' đã được xóa thành công.` });
    } catch (error) {
        return res.status(500).send({ error: 'Lỗi máy chủ khi xóa snippet.' });
    }
});

app.post('/listSnippets', async (req, res) => {
    if (!req.userAuth || req.userAuth.type !== 'private') return res.status(403).send({ error: 'Cần có private key để liệt kê snippets.' });
    try {
        const { limit = 20, visibility } = req.body;
        let query = db.collection(SNIPPETS_COLLECTION).where('creatorId', '==', req.userAuth.userId);
        if (visibility) query = query.where('visibility', '==', visibility);
        const snapshot = await query.orderBy('createdAt', 'desc').limit(limit).get();
        const snippets = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
        return res.status(200).send(snippets);
    } catch (error) {
        return res.status(500).send({ error: 'Lỗi máy chủ khi liệt kê snippets.' });
    }
});

app.post('/getUserPublicSnippets', async (req, res) => {
    try {
        const { userId } = req.body;
        if (!userId) return res.status(400).send({ error: 'Thiếu userId.' });
        const snapshot = await db.collection(SNIPPETS_COLLECTION)
            .where('creatorId', '==', userId)
            .where('visibility', '==', 'public')
            .orderBy('createdAt', 'desc')
            .limit(20)
            .get();
        const snippets = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
        return res.status(200).send(snippets);
    } catch (error) {
        return res.status(500).send({ error: 'Lỗi máy chủ khi lấy public snippets.' });
    }
});

app.post('/searchSnippets', async (req, res) => {
    try {
        const { term } = req.body;
        if (!term) return res.status(400).send({ error: 'Thiếu từ khóa tìm kiếm.' });
        
        const lowerCaseTerm = term.toLowerCase();
        
        const tagsQuery = db.collection(SNIPPETS_COLLECTION)
            .where('visibility', '==', 'public')
            .where('tags', 'array-contains', lowerCaseTerm);
            
        // Firestore không hỗ trợ OR query phức tạp. Chúng ta sẽ chạy 2 query và gộp kết quả.
        // Đây là cách đơn giản nhất, với lượng dữ liệu lớn cần giải pháp tìm kiếm chuyên dụng hơn (เช่น Algolia, Typesense).
        const titleQuery = db.collection(SNIPPETS_COLLECTION)
             .where('visibility', '==', 'public');

        const [tagsSnapshot, titleSnapshot] = await Promise.all([tagsQuery.get(), titleQuery.get()]);

        const resultsMap = new Map();
        tagsSnapshot.docs.forEach(doc => resultsMap.set(doc.id, { id: doc.id, ...doc.data() }));
        
        // Lọc title thủ công vì Firestore không hỗ trợ contains/lowercase search
        titleSnapshot.docs.forEach(doc => {
            const data = doc.data();
            if (data.title && data.title.toLowerCase().includes(lowerCaseTerm)) {
                 resultsMap.set(doc.id, { id: doc.id, ...data });
            }
        });
        
        const results = Array.from(resultsMap.values());
        return res.status(200).send(results);
    } catch (error) {
        console.error("Lỗi route /searchSnippets:", error);
        return res.status(500).send({ error: 'Lỗi máy chủ khi tìm kiếm.' });
    }
});

// --- 4. EXPORT APP CHO VERCEL ---
module.exports = app;
