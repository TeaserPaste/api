// index.js
const admin = require('firebase-admin');
const express = require('express');
const cors = require('cors');

// --- TẢI CONFIGURATION TỪ VERCEL ENVIRONMENT VARIABLES ---
let serviceAccountCredentials;

// Vercel sẽ tự động cung cấp các biến môi trường này
// Bạn cần setup chúng trong phần Settings > Environment Variables của project trên Vercel
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
        auth_provider_x5509_cert_url: 'https://www.googleapis.com/oauth2/v1/certs',
        client_x509_cert_url: `https://www.googleapis.com/robot/v1/metadata/x509/${encodeURIComponent(process.env.FIREBASE_CLIENT_EMAIL)}`,
    };
    console.log("✅ Config: Đã tải cấu hình Admin SDK từ Vercel Environment Variables.");
} catch (e) {
    console.error("❌ Lỗi Config: Hãy chắc chắn rằng bạn đã thiết lập đầy đủ các biến môi trường FIREBASE_* trên Vercel.", e);
    // Không thoát process ở đây để Vercel có thể xử lý lỗi
}

// --- KHỞI TẠO ADMIN SDK (CHỈ MỘT LẦN) ---
if (!admin.apps.length) {
    admin.initializeApp({
        credential: admin.credential.cert(serviceAccountCredentials),
    });
    console.log("✅ Firebase Admin SDK initialized.");
}

const db = admin.firestore();
const app = express();
const SNIPPETS_COLLECTION = 'snippets';
const API_KEYS_COLLECTION = 'apiKeys';
const USERS_COLLECTION = 'users';

// --- MIDDLEWARE ---
app.use(cors()); 
app.use(express.json());

// --- MIDDLEWARE XÁC THỰC API KEY ---
const apiKeyAuth = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return next();
    }

    const apiKey = authHeader.split(' ')[1];
    if (!apiKey) {
        return res.status(401).send({ error: 'API Key không hợp lệ.' });
    }

    try {
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

        req.userAuth = userAuth;
        next();
    } catch (error) {
        console.error("Lỗi xác thực API Key:", error);
        return res.status(500).send({ error: 'Lỗi máy chủ khi xác thực API key.' });
    }
};

app.use(apiKeyAuth); // Áp dụng middleware

// --- Logic Xử lý Snippet ---
async function getSnippetData(snippetId, password, userAuth) {
    const snippetRef = db.collection(SNIPPETS_COLLECTION).doc(snippetId);
    const docSnap = await snippetRef.get();

    if (!docSnap.exists) {
        throw new Error(`Snippet '${snippetId}' không tồn tại.`);
    }
    
    const data = docSnap.data();
    const visibility = data.visibility;

    if (data.expiresAt && new Date(data.expiresAt) < new Date()) {
        throw new Error(`Snippet '${snippetId}' đã hết hạn.`);
    }

    const isOwner = userAuth && userAuth.userId === data.creatorId;

    if (visibility === 'private') {
        if (!isOwner || userAuth.type !== 'private') {
            throw new Error(`Snippet '${snippetId}' là PRIVATE và bạn không có quyền truy cập.`);
        }
    }

    if (visibility === 'unlisted' && data.password && data.password.length > 0) {
        if (!password) {
            throw new Error('REQUIRED_PASSWORD');
        }
        if (password !== data.password) {
            throw new Error(`Mật khẩu không chính xác.`);
        }
    }
    
    return { 
        id: docSnap.id,
        title: data.title || 'Untitled',
        content: data.content || '',
        language: data.language || 'plaintext',
        creatorName: data.creatorName || 'Unknown',
        tags: data.tags || [],
        visibility: visibility,
        isVerified: data.isVerified || false
    };
}

// --- API ROUTE: POST /getSnippet ---
app.post('/getSnippet', async (req, res) => {
    const { snippetId, password } = req.body;

    if (!snippetId) {
        return res.status(400).send({ error: 'Thiếu snippetId.' });
    }

    try {
        const snippetData = await getSnippetData(snippetId, password, req.userAuth);
        return res.status(200).send(snippetData);

    } catch (error) {
        console.error("Lỗi API Backend:", error.message);
        
        if (error.message === 'REQUIRED_PASSWORD') {
             return res.status(401).send({ error: 'Snippet này cần mật khẩu.', requiresPassword: true });
        }
        const status = (error.message.includes('không tồn tại') || error.message.includes('hết hạn')) ? 404 : 403;
        return res.status(status).send({ error: error.message });
    }
});

// --- API ROUTE MỚI: GET /getUserInfo ---
app.get('/getUserInfo', async (req, res) => {
    // Middleware 'apiKeyAuth' đã chạy trước đó và đính kèm 'req.userAuth' nếu key hợp lệ
    if (!req.userAuth || !req.userAuth.userId) {
        return res.status(401).send({ error: 'Yêu cầu cần có API key hợp lệ (public hoặc private).' });
    }

    try {
        const userId = req.userAuth.userId;
        const userRef = db.collection(USERS_COLLECTION).doc(userId);
        const userSnap = await userRef.get();

        if (!userSnap.exists) {
            return res.status(404).send({ error: 'Không tìm thấy người dùng tương ứng với API key này.' });
        }

        const userData = userSnap.data();

        // Chỉ trả về các thông tin public, không trả về email hay các thông tin nhạy cảm khác
        const publicUserInfo = {
            userId: userSnap.id,
            displayName: userData.displayName || 'Anonymous',
            photoURL: userData.photoURL || null,
            isVerified: userData.isVerified || false
        };

        return res.status(200).send(publicUserInfo);

    } catch (error) {
        console.error("Lỗi khi lấy thông tin người dùng:", error);
        return res.status(500).send({ error: 'Lỗi máy chủ khi truy vấn thông tin người dùng.' });
    }
});

// --- EXPORT APP CHO VERCEL ---
// Vercel sẽ sử dụng module export này để chạy serverless function.
module.exports = app;
