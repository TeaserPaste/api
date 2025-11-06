// index.js (Phiên bản hoàn chỉnh cho Vercel với OpenSearch)

const admin = require('firebase-admin');
const express = require('express');
const cors = require('cors');
const { Client } = require('@opensearch-project/opensearch'); // Thêm OpenSearch client

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
    console.error("❌ Lỗi Config Firebase: Hãy chắc chắn rằng bạn đã thiết lập đầy đủ các biến môi trường FIREBASE_* trên Vercel.", e);
}

if (!admin.apps.length) {
    try {
        admin.initializeApp({
            credential: admin.credential.cert(serviceAccountCredentials),
        });
        console.log("Firebase Admin SDK initialized successfully.");
    } catch (e) {
        console.error("❌ Failed to initialize Firebase Admin SDK:", e);
    }
}

const db = admin.firestore();
const app = express();

const SNIPPETS_COLLECTION = 'snippets';
const API_KEYS_COLLECTION = 'apiKeys';
const USERS_COLLECTION = 'users';

// --- 2. KHỞI TẠO OPENSEARCH CLIENT ---
let osClient = null;
const opensearchNode = `${process.env.OPENSEARCH_SCHEME || 'https'}://${process.env.OPENSEARCH_HOST}:${process.env.OPENSEARCH_PORT || '443'}`;
const opensearchAuth = {
    username: process.env.OPENSEARCH_USER,
    password: process.env.OPENSEARCH_PASSWORD,
};

if (process.env.OPENSEARCH_HOST) {
    try {
        osClient = new Client({
            node: opensearchNode,
            auth: (opensearchAuth.username && opensearchAuth.password) ? opensearchAuth : undefined,
            ssl: {
                // Có thể cần cấu hình thêm nếu dùng self-signed certs
                rejectUnauthorized: process.env.NODE_ENV === 'production', // Chỉ bật kiểm tra cert trong production
            },
        });
        console.log(`OpenSearch client initialized for node: ${opensearchNode}`);
        // Kiểm tra kết nối (tùy chọn)
        osClient.ping()
            .then(response => console.log('OpenSearch cluster ping successful.'))
            .catch(error => console.warn('OpenSearch cluster ping failed:', error));
    } catch (e) {
        console.error("❌ Failed to initialize OpenSearch client:", e);
    }
} else {
    console.warn("⚠️ OpenSearch environment variables not set. Search functionality will be disabled.");
}

// --- 2.5. KHỞI TẠO REDIS CLIENT ---
const Redis = require('ioredis');
const CACHE_TTL_SECONDS = 60; // Thời gian sống của cache là 60 giây

let redisClient = null;
if (process.env.REDIS_URL) {
    try {
        redisClient = new Redis(process.env.REDIS_URL);
        redisClient.on('error', (err) => console.error("❌ Redis Error:", err));
        console.log("Redis client initialized successfully.");
    } catch (e) {
        console.error("❌ Failed to initialize Redis client:", e);
    }
} else {
    console.warn("⚠️ REDIS_URL environment variable not set. Caching functionality will be disabled.");
}


// --- 3. MIDDLEWARE ---
app.use(cors());
app.use(express.json());

const apiKeyAuth = async (req, res, next) => {
    // ... (Giữ nguyên logic xác thực API key)
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return next();
        }
        const apiKey = authHeader.split(' ')[1];
        if (!apiKey) {
            // Không phải lỗi 401 mà chỉ là không có key, tiếp tục để các route khác xử lý
             return next();
        }
        const keysSnapshot = await db.collection(API_KEYS_COLLECTION).get();
        let userAuth = null;
        for (const doc of keysSnapshot.docs) {
            const data = doc.data();
            if (data.publicKey === apiKey) { userAuth = { userId: doc.id, type: 'public' }; break; }
            if (data.privateKey === apiKey) { userAuth = { userId: doc.id, type: 'private' }; break; }
        }
        // Nếu cung cấp key nhưng không hợp lệ -> lỗi 403
        if (!userAuth && apiKey) {
             return res.status(403).send({ error: 'API Key không hợp lệ hoặc đã hết hạn.' });
        }
        req.userAuth = userAuth;
        next();
    } catch (error) {
        console.error("API Key Auth Error:", error);
        // Trả về lỗi 500 nếu có lỗi trong quá trình xác thực
        return res.status(500).send({ error: 'Lỗi máy chủ khi xác thực API key.' });
    }
};
app.use(apiKeyAuth);

// --- 4. CÁC ROUTES API ---

// ... (Các route getSnippet, getUserInfo, createSnippet, updateSnippet, deleteSnippet, listSnippets, getUserPublicSnippets giữ nguyên) ...
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
        // Chuyển đổi Timestamp thành ISO string nếu có
        const responseData = { id: docSnap.id, ...data, passwordBypassed };
        if (responseData.createdAt && responseData.createdAt.toDate) {
            responseData.createdAt = responseData.createdAt.toDate().toISOString();
        }
         if (responseData.expiresAt && responseData.expiresAt.toDate) {
            responseData.expiresAt = responseData.expiresAt.toDate().toISOString();
        }
        return res.status(200).send(responseData);
    } catch (error) {
         console.error("Lỗi route /getSnippet:", error);
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
         console.error("Lỗi route /getUserInfo:", error);
        return res.status(500).send({ error: 'Lỗi máy chủ khi truy vấn thông tin người dùng.' });
    }
});

function calculateExpiresAt(expires) {
    if (!expires) return null;
    const unit = expires.slice(-1).toLowerCase();
    const value = parseInt(expires.slice(0, -1), 10);
    if (isNaN(value)) return null;

    const now = new Date();
    if (unit === 'm') now.setMinutes(now.getMinutes() + value); // Thêm minutes
    else if (unit === 'h') now.setHours(now.getHours() + value);
    else if (unit === 'd') now.setDate(now.getDate() + value);
    else if (unit === 'w') now.setDate(now.getDate() + (value * 7));
    else return null;
    return admin.firestore.Timestamp.fromDate(now); // Trả về Timestamp
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
            creatorPhotoURL: userRef.data().photoURL || null, // Thêm photoURL
            createdAt: admin.firestore.FieldValue.serverTimestamp(), // Dùng server timestamp
            expiresAt: calculateExpiresAt(expires),
            isVerified: false
        };

        const docRef = await db.collection(SNIPPETS_COLLECTION).add(newSnippetData);
        // Lấy lại dữ liệu vừa tạo để có createdAt chính xác (nếu cần)
        const savedDoc = await docRef.get();
        const savedData = savedDoc.data();
         // Chuyển đổi Timestamp thành ISO string trước khi gửi về client
        if (savedData.createdAt && savedData.createdAt.toDate) {
            savedData.createdAt = savedData.createdAt.toDate().toISOString();
        }
         if (savedData.expiresAt && savedData.expiresAt.toDate) {
            savedData.expiresAt = savedData.expiresAt.toDate().toISOString();
        }

        return res.status(201).send({ id: docRef.id, ...savedData });
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

        // Đảm bảo không ghi đè password nếu visibility không phải là 'unlisted'
        if (validUpdates.visibility && validUpdates.visibility !== 'unlisted') {
            validUpdates.password = ''; // Xóa password nếu không phải unlisted
        } else if ('visibility' in validUpdates && validUpdates.visibility === 'unlisted' && !('password' in validUpdates)) {
             // Giữ nguyên password cũ nếu chuyển sang unlisted mà không cung cấp password mới
             delete validUpdates.password;
        }

        await snippetRef.update(validUpdates);
        const updatedDoc = await snippetRef.get();
        const updatedData = updatedDoc.data();
        // Chuyển đổi Timestamp thành ISO string
        if (updatedData.createdAt && updatedData.createdAt.toDate) {
            updatedData.createdAt = updatedData.createdAt.toDate().toISOString();
        }
         if (updatedData.expiresAt && updatedData.expiresAt.toDate) {
            updatedData.expiresAt = updatedData.expiresAt.toDate().toISOString();
        }
        return res.status(200).send({ id: updatedDoc.id, ...updatedData });
    } catch (error) {
        console.error("Lỗi route /updateSnippet:", error);
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
        console.error("Lỗi route /deleteSnippet:", error);
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
        const snippets = snapshot.docs.map(doc => {
             const data = doc.data();
             // Chuyển đổi Timestamp thành ISO string
             if (data.createdAt && data.createdAt.toDate) {
                data.createdAt = data.createdAt.toDate().toISOString();
             }
             if (data.expiresAt && data.expiresAt.toDate) {
                 data.expiresAt = data.expiresAt.toDate().toISOString();
             }
            return { id: doc.id, ...data };
        });
        return res.status(200).send(snippets);
    } catch (error) {
         console.error("Lỗi route /listSnippets:", error);
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
        const snippets = snapshot.docs.map(doc => {
            const data = doc.data();
             // Chuyển đổi Timestamp thành ISO string
             if (data.createdAt && data.createdAt.toDate) {
                data.createdAt = data.createdAt.toDate().toISOString();
             }
             if (data.expiresAt && data.expiresAt.toDate) {
                 data.expiresAt = data.expiresAt.toDate().toISOString();
             }
            return { id: doc.id, ...data };
        });
        return res.status(200).send(snippets);
    } catch (error) {
         console.error("Lỗi route /getUserPublicSnippets:", error);
        return res.status(500).send({ error: 'Lỗi máy chủ khi lấy public snippets.' });
    }
});


// --- CẬP NHẬT ROUTE /searchSnippets ---
app.post('/searchSnippets', async (req, res) => {
    if (!osClient) {
        return res.status(503).send({ error: 'Dịch vụ tìm kiếm hiện không khả dụng.' });
    }

    try {
        const { term } = req.body;
        const size = parseInt(req.body.size, 10) || 20;
        const from = parseInt(req.body.from, 10) || 0;

        if (!term || typeof term !== 'string' || term.trim() === '') {
            return res.status(400).send({ error: 'Thiếu hoặc không hợp lệ: term (từ khóa tìm kiếm).' });
        }

        const searchTerm = term.trim();
        const cacheKey = `search:${searchTerm}:size${size}:from${from}`;

        // 1. KIỂM TRA CACHE TRƯỚC
        if (redisClient) {
            try {
                const cachedResults = await redisClient.get(cacheKey);
                if (cachedResults) {
                    console.log("CACHE HIT:", cacheKey);
                    return res.status(200).send(JSON.parse(cachedResults));
                }
                console.log("CACHE MISS:", cacheKey);
            } catch (err) {
                console.error("Redis GET error:", err);
                // Không chặn request nếu Redis lỗi, chỉ log lại
            }
        }

        const indexName = process.env.OPENSEARCH_INDEX || 'snippets';

        // Tạo query body cho OpenSearch
        const queryBody = {
            size: size,
            from: from,
            query: {
                bool: {
                    should: [
                        // 1. Multi Match (Tìm kiếm chung, có fuzziness)
                        {
                            multi_match: {
                                query: searchTerm,
                                fields: [
                                    "title^5",      // Tăng boost cho title (rất quan trọng)
                                    "tags^3",       // Tăng boost cho tags
                                    "content^1",    // Giữ content ở mức cơ bản
                                    "creatorName"
                                ],
                                fuzziness: "AUTO",  // Cho phép lỗi chính tả nhỏ
                                operator: "OR"
                            }
                        },
                        // 2. Phrase Prefix Match (Tìm kiếm gợi ý/autocomplete)
                        {
                            multi_match: {
                                query: searchTerm,
                                type: "phrase_prefix", // Giúp tìm thấy các snippet có cụm từ bắt đầu bằng searchTerm
                                fields: ["title^10", "tags^5"], // Tăng boost mạnh cho kết quả khớp cụm từ
                            }
                        }
                    ],
                    minimum_should_match: 1, // Chỉ cần khớp 1 trong các điều kiện 'should'
                    filter: [
                        { term: { "visibility.keyword": "public" } }
                    ]
                }
            },
            // Giữ nguyên logic sắp xếp
            sort: [
                { "_score": { "order": "desc" } },
                { "ai_priority": { "order": "desc", "missing": "_last" } },
                { "createdAt": { "order": "desc" } }
            ],
        };

        const response = await osClient.search({
            index: indexName,
            body: queryBody,
        });

        const results = response.body.hits.hits.map(hit => ({
            id: hit._id,
            ...hit._source
        }));

        const finalResponse = {
            hits: results,
            total: response.body.hits.total.value,
            from: from,
            size: size
        };

        // 2. LƯU KẾT QUẢ VÀO CACHE
        if (redisClient) {
            try {
                await redisClient.set(cacheKey, JSON.stringify(finalResponse), 'EX', CACHE_TTL_SECONDS);
                console.log("CACHE SET:", cacheKey);
            } catch (err) {
                console.error("Redis SET error:", err);
            }
        }

        return res.status(200).send(finalResponse);

    } catch (error) {
        console.error("Lỗi route /searchSnippets:", error.meta ? error.meta.body : error);
        // Trả về lỗi chi tiết hơn nếu có từ OpenSearch
        const errorMessage = error.meta?.body?.error?.reason || 'Lỗi máy chủ khi tìm kiếm.';
        return res.status(500).send({ error: errorMessage });
    }
});

// --- 5. EXPORT APP CHO VERCEL ---
module.exports = app;
