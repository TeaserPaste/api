// index.js (Phiên bản hoàn chỉnh cho Vercel)

const admin = require('firebase-admin');
const express = require('express');
const cors = require('cors');

// --- 1. KHỞI TẠO FIREBASE ADMIN SDK ---
// Đảm bảo bạn đã thiết lập các biến môi trường này trên Vercel
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

// Khởi tạo app chỉ một lần duy nhất
if (!admin.apps.length) {
    admin.initializeApp({
        credential: admin.credential.cert(serviceAccountCredentials),
    });
    console.log("✅ Firebase Admin SDK initialized for Vercel.");
}

const db = admin.firestore();
const app = express();

// Định nghĩa tên các collection
const SNIPPETS_COLLECTION = 'snippets';
const API_KEYS_COLLECTION = 'apiKeys';
const USERS_COLLECTION = 'users';

// --- 2. MIDDLEWARE ---
app.use(cors()); 
app.use(express.json());

// Middleware xác thực API key (public/private)
const apiKeyAuth = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            // Không có token, vẫn cho qua để xử lý các request public
            return next();
        }

        const apiKey = authHeader.split(' ')[1];
        if (!apiKey) {
            return res.status(401).send({ error: 'Định dạng API Key không hợp lệ.' });
        }

        const keysSnapshot = await db.collection(API_KEYS_COLLECTION).get();
        let userAuth = null;

        for (const doc of keysSnapshot.docs) {
            const data = doc.data();
            if (data.publicKey === apiKey) {
                userAuth = { userId: doc.id, type: 'public' };
                break;
            }
            if (data.privateKey === apiKey) {
                userAuth = { userId: doc.id, type: 'private' };
                break;
            }
        }

        if (!userAuth) {
            return res.status(403).send({ error: 'API Key không hợp lệ hoặc đã hết hạn.' });
        }

        req.userAuth = userAuth; // Gắn thông tin xác thực vào request
        next();
    } catch (error) {
        console.error("Lỗi middleware apiKeyAuth:", error);
        return res.status(500).send({ error: 'Lỗi máy chủ khi xác thực API key.' });
    }
};

app.use(apiKeyAuth); // Áp dụng middleware cho tất cả các route

// --- 3. CÁC ROUTES API ---

/**
 * @route   POST /getSnippet
 * @desc    Lấy thông tin một snippet, hỗ trợ bypass mật khẩu cho chủ sở hữu.
 */
app.post('/getSnippet', async (req, res) => {
    const { snippetId, password } = req.body;
    if (!snippetId) {
        return res.status(400).send({ error: 'Thiếu snippetId.' });
    }

    try {
        const docSnap = await db.collection(SNIPPETS_COLLECTION).doc(snippetId).get();
        if (!docSnap.exists) {
            return res.status(404).send({ error: `Snippet '${snippetId}' không tồn tại.` });
        }
        
        const data = docSnap.data();
        const isOwner = req.userAuth && req.userAuth.userId === data.creatorId;

        // Kiểm tra quyền truy cập
        if (data.visibility === 'private' && (!isOwner || req.userAuth.type !== 'private')) {
            return res.status(403).send({ error: `Snippet '${snippetId}' là PRIVATE và bạn không có quyền truy cập.` });
        }

        let passwordBypassed = false;
        if (data.visibility === 'unlisted' && data.password && data.password.length > 0) {
            // Chủ sở hữu dùng private key có thể bypass mật khẩu
            if (isOwner && req.userAuth.type === 'private') {
                passwordBypassed = true;
            } else if (password !== data.password) {
                if (!password) {
                    return res.status(401).send({ error: 'Snippet này cần mật khẩu.', requiresPassword: true });
                }
                return res.status(403).send({ error: 'Mật khẩu không chính xác.' });
            }
        }
        
        const responseData = {
            id: docSnap.id,
            title: data.title || 'Untitled',
            content: data.content || '',
            language: data.language || 'plaintext',
            creatorName: data.creatorName || 'Unknown',
            tags: data.tags || [],
            visibility: data.visibility,
            isVerified: data.isVerified || false,
            passwordBypassed // Trả về trạng thái bypass
        };

        return res.status(200).send(responseData);
    } catch (error) {
        console.error("Lỗi route /getSnippet:", error);
        return res.status(500).send({ error: 'Lỗi máy chủ khi lấy snippet.' });
    }
});

/**
 * @route   GET /getUserInfo
 * @desc    Lấy thông tin public của người dùng qua API key.
 */
app.get('/getUserInfo', async (req, res) => {
    if (!req.userAuth || !req.userAuth.userId) {
        return res.status(401).send({ error: 'Yêu cầu cần có API key hợp lệ (public hoặc private).' });
    }

    try {
        const userRef = db.collection(USERS_COLLECTION).doc(req.userAuth.userId);
        const userSnap = await userRef.get();

        if (!userSnap.exists) {
            return res.status(404).send({ error: 'Không tìm thấy người dùng tương ứng với API key này.' });
        }

        const userData = userSnap.data();
        const publicUserInfo = {
            userId: userSnap.id,
            displayName: userData.displayName || 'Anonymous',
            photoURL: userData.photoURL || null,
        };

        return res.status(200).send(publicUserInfo);
    } catch (error) {
        console.error("Lỗi route /getUserInfo:", error);
        return res.status(500).send({ error: 'Lỗi máy chủ khi truy vấn thông tin người dùng.' });
    }
});

/**
 * @route   POST /createSnippet
 * @desc    Tạo một snippet mới, yêu cầu private key.
 */
app.post('/createSnippet', async (req, res) => {
    if (!req.userAuth || req.userAuth.type !== 'private') {
        return res.status(403).send({ error: 'Cần có private key để tạo snippet.' });
    }

    try {
        const { title, content, language = 'plaintext', visibility = 'unlisted', tags = [], password = '' } = req.body;

        if (!title || !content) {
            return res.status(400).send({ error: 'Tiêu đề và nội dung là bắt buộc.' });
        }
        
        const userRef = await db.collection(USERS_COLLECTION).doc(req.userAuth.userId).get();
        if (!userRef.exists) {
            return res.status(404).send({ error: 'Người dùng không tồn tại.' });
        }
        
        const newSnippetData = {
            title,
            content,
            language,
            visibility,
            tags: Array.isArray(tags) ? tags : [],
            password: visibility === 'unlisted' ? password : '',
            creatorId: req.userAuth.userId,
            creatorName: userRef.data().displayName || 'Anonymous',
            createdAt: new Date(),
            expiresAt: null,
            hasSensitiveContent: false,
            isVerified: false // Snippet mới tạo qua API mặc định là không verified
        };

        const docRef = await db.collection(SNIPPETS_COLLECTION).add(newSnippetData);

        return res.status(201).send({ id: docRef.id, ...newSnippetData });
    } catch (error) {
        console.error("Lỗi route /createSnippet:", error);
        return res.status(500).send({ error: 'Lỗi máy chủ khi tạo snippet.' });
    }
});

// --- 4. EXPORT APP CHO VERCEL ---
module.exports = app;
