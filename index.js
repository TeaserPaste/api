// index.js
const admin = require('firebase-admin');
const express = require('express');
const cors = require('cors');

// Tải biến môi trường từ file .env (chỉ dùng khi chạy local)
require('dotenv').config();

// --- TẢI CONFIGURATION DỰA TRÊN BIẾN MÔI TRƯỜNG ---
let serviceAccountCredentials;

// --- PHÂN TÍCH CONFIG: ƯU TIÊN JSON NGUYÊN BẢN (PHƯƠNG PHÁP A) ---
if (process.env.FIREBASE_CONFIG_JSON) {
    try {
        // Parse chuỗi JSON thành đối tượng
        serviceAccountCredentials = JSON.parse(process.env.FIREBASE_CONFIG_JSON);
        console.log("✅ Config: Đã tải cấu hình Admin SDK từ biến FIREBASE_CONFIG_JSON.");
    } catch (e) {
        console.error("❌ Lỗi Config: Không thể phân tích JSON từ FIREBASE_CONFIG_JSON.");
        process.exit(1);
    }
} 
// --- HOẶC TẢI TỪNG TRƯỜNG RIÊNG LẺ (PHƯƠNG PHÁP B) ---
else if (process.env.FIREBASE_PROJECT_ID && process.env.FIREBASE_PRIVATE_KEY) {
    // Đảm bảo ký tự xuống dòng được định dạng đúng.
    const privateKey = process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n');
    
    serviceAccountCredentials = {
        type: 'service_account',
        project_id: process.env.FIREBASE_PROJECT_ID,
        private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID || '',
        private_key: privateKey,
        client_email: process.env.FIREBASE_CLIENT_EMAIL || '',
        client_id: process.env.FIREBASE_CLIENT_ID || '',
        auth_uri: 'https://accounts.google.com/o/oauth2/auth', // Hardcode an toàn
        token_uri: 'https://oauth2.googleapis.com/token', // Hardcode an toàn
        auth_provider_x509_cert_url: 'https://www.googleapis.com/oauth2/v1/certs', // Hardcode an toàn
        client_x509_cert_url: `https://www.googleapis.com/robot/v1/metadata/x509/${encodeURIComponent(process.env.FIREBASE_CLIENT_EMAIL)}`, // Cần email
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
const PORT = process.env.PORT || 3000;

// (Phần còn lại của code middleware và route từ bước trước giữ nguyên)

// --- MIDDLEWARE ---
app.use(cors()); 
app.use(express.json());

// --- Logic Xử lý Snippet (ĐÃ CẬP NHẬT) ---
async function getSnippetData(snippetId, password) {
    const snippetRef = db.collection(SNIPPETS_COLLECTION).doc(snippetId);
    const docSnap = await snippetRef.get();

    if (!docSnap.exists) {
        throw new Error(`Snippet '${snippetId}' không tồn tại.`);
    }
    
    const data = docSnap.data();

    // ... [Logic kiểm tra hết hạn, private, và mật khẩu unlisted giữ nguyên] ...
    const visibility = data.visibility;

    if (data.expiresAt && new Date(data.expiresAt) < new Date()) {
        throw new Error(`Snippet '${snippetId}' đã hết hạn.`);
    }

    if (visibility === 'private') {
        throw new Error(`Snippet '${snippetId}' là PRIVATE và cần xác thực người dùng.`);
    }

    if (visibility === 'unlisted' && data.password && data.password.length > 0) {
        if (!password) {
            throw new Error('REQUIRED_PASSWORD');
        }
        if (password !== data.password) {
            throw new Error(`Mật khẩu không chính xác.`);
        }
    }
    
    // 🚨 ĐÃ BỔ SUNG: Đảm bảo trả về trường isVerified
    return { 
        id: docSnap.id,
        title: data.title || 'Untitled',
        content: data.content || '',
        language: data.language || 'plaintext',
        creatorName: data.creatorName || 'Unknown',
        tags: data.tags || [],
        visibility: visibility,
        isVerified: data.isVerified || false // Thêm trường này vào response
    };
}


// --- API ROUTE: POST /getSnippet (Giữ nguyên) ---
app.post('/getSnippet', async (req, res) => {
    const { snippetId, password } = req.body;

    if (!snippetId) {
        return res.status(400).send({ error: 'Thiếu snippetId.' });
    }

    try {
        const snippetData = await getSnippetData(snippetId, password);
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
});