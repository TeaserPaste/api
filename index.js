// index.js
const admin = require('firebase-admin');
const express = require('express');
const cors = require('cors');

// Tải biến môi trường từ file .env (chỉ dùng khi chạy local)
require('dotenv').config();

// --- TẢI CONFIGURATION DỰA TRÊN BIẾN MÔI TRƯỜNG ---
let serviceAccountCredentials;

if (process.env.FIREBASE_CONFIG_JSON) {
    try {
        serviceAccountCredentials = JSON.parse(process.env.FIREBASE_CONFIG_JSON);
        console.log("✅ Config: Đã tải cấu hình Admin SDK từ biến FIREBASE_CONFIG_JSON.");
    } catch (e) {
        console.error("❌ Lỗi Config: Không thể phân tích JSON từ FIREBASE_CONFIG_JSON.");
        process.exit(1);
    }
} else if (process.env.FIREBASE_PROJECT_ID && process.env.FIREBASE_PRIVATE_KEY) {
    const privateKey = process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n');
    
    serviceAccountCredentials = {
        type: 'service_account',
        project_id: process.env.FIREBASE_PROJECT_ID,
        private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID || '',
        private_key: privateKey,
        client_email: process.env.FIREBASE_CLIENT_EMAIL || '',
        client_id: process.env.FIREBASE_CLIENT_ID || '',
        auth_uri: 'https://accounts.google.com/o/oauth2/auth',
        token_uri: 'https://oauth2.googleapis.com/token',
        auth_provider_x509_cert_url: 'https://www.googleapis.com/oauth2/v1/certs',
        client_x509_cert_url: `https://www.googleapis.com/robot/v1/metadata/x509/${encodeURIComponent(process.env.FIREBASE_CLIENT_EMAIL)}`,
    };
    console.log("✅ Config: Đã tải cấu hình Admin SDK từ các biến môi trường riêng lẻ.");
} else {
    console.error("❌ Lỗi Config: Không tìm thấy biến môi trường cần thiết (FIREBASE_CONFIG_JSON hoặc các trường riêng lẻ).");
    process.exit(1);
}

// --- KHỞI TẠO ADMIN SDK VỚI CREDENTIALS TỪ BIẾN MÔI TRƯỜNG ---
admin.initializeApp({
  credential: admin.credential.cert(serviceAccountCredentials),
});

const db = admin.firestore();
const app = express();
const SNIPPETS_COLLECTION = 'snippets';
const API_KEYS_COLLECTION = 'apiKeys';
const PORT = process.env.PORT || 3000;

// --- MIDDLEWARE ---
app.use(cors()); 
app.use(express.json());

// --- MIDDLEWARE XÁC THỰC API KEY (MỚI) ---
const apiKeyAuth = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        // Không có API key, tiếp tục xử lý bình thường (cho các snippet public/unlisted không cần key)
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

app.use(apiKeyAuth); // Áp dụng middleware cho tất cả các request

// --- Logic Xử lý Snippet (ĐÃ CẬP NHẬT) ---
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

    if (visibility === 'unlisted') {
        if (data.password && data.password.length > 0) {
            if (!password) {
                throw new Error('REQUIRED_PASSWORD');
            }
            if (password !== data.password) {
                throw new Error(`Mật khẩu không chính xác.`);
            }
        } else if (!isOwner && visibility === 'unlisted') {
            // Unlisted snippets without a password are still accessible via link, but might be restricted via API
            // Depending on your logic, you might want to allow public keys here or not.
            // For now, we'll allow it.
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

// --- API ROUTE: POST /getSnippet (ĐÃ CẬP NHẬT) ---
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

// --- START SERVER ---
app.listen(PORT, () => {
  console.log(`\n🎉 TeaserPaste API Server đang chạy tại http://localhost:${PORT}`);
  console.log(`BASE_API_URL cho CLI: http://localhost:${PORT}`);
});PORT}`);
  console.log(`BASE_API_URL cho CLI: http://localhost:${PORT}`);
});
