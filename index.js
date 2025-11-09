// index.js (Phiên bản hoàn chỉnh cho Vercel với OpenSearch)

const admin = require('firebase-admin');
const express = require('express');
const cors = require('cors');
const { Client } = require('@opensearch-project/opensearch');
const Redis = require('ioredis');

// --- 1. KHỞI TẠO FIREBASE ADMIN SDK ---
let serviceAccountCredentials;
let rtdb; // Biến cho Realtime Database

try {
    // Đảm bảo FIREBASE_PRIVATE_KEY được parse chính xác
    const privateKey = (process.env.FIREBASE_PRIVATE_KEY || '').replace(/\\n/g, '\n');
    
    if (!process.env.FIREBASE_PROJECT_ID || !privateKey || !process.env.FIREBASE_CLIENT_EMAIL) {
        throw new Error('Thiếu các biến môi trường Firebase Admin SDK (PROJECT_ID, PRIVATE_KEY, CLIENT_EMAIL).');
    }

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

    if (!admin.apps.length) {
        admin.initializeApp({
            credential: admin.credential.cert(serviceAccountCredentials),
            databaseURL: process.env.FIREBASE_DATABASE_URL // Thêm databaseURL cho RTDB
        });
        console.log("Firebase Admin SDK initialized successfully.");
    }

    // Khởi tạo các dịch vụ
    db = admin.firestore();
    rtdb = admin.database(); // Khởi tạo Realtime Database
    console.log("Firestore and RTDB services initialized.");

} catch (e) {
    console.error("❌ Lỗi Config Firebase: Hãy chắc chắn rằng bạn đã thiết lập đầy đủ các biến môi trường FIREBASE_* trên Vercel.", e.message);
}

const app = express();

const SNIPPETS_COLLECTION = 'snippets';
const API_KEYS_COLLECTION = 'apiKeys';
const USERS_COLLECTION = 'users';

// --- 2. KHỞI TẠO OPENSEARCH CLIENT ---
let osClient = null;
if (process.env.OPENSEARCH_HOST && process.env.OPENSEARCH_USER && process.env.OPENSEARCH_PASSWORD) {
    const opensearchNode = `${process.env.OPENSEARCH_SCHEME || 'https'}://${process.env.OPENSEARCH_HOST}:${process.env.OPENSEARCH_PORT || '443'}`;
    const opensearchAuth = {
        username: process.env.OPENSEARCH_USER,
        password: process.env.OPENSEARCH_PASSWORD,
    };

    try {
        osClient = new Client({
            node: opensearchNode,
            auth: opensearchAuth,
            ssl: {
                rejectUnauthorized: process.env.NODE_ENV === 'production',
            },
        });
        console.log(`OpenSearch client initialized for node: ${opensearchNode}`);
        osClient.ping()
            .then(response => console.log('OpenSearch cluster ping successful.'))
            .catch(error => console.warn('OpenSearch cluster ping failed:', error.message));
    } catch (e) {
        console.error("❌ Failed to initialize OpenSearch client:", e.message);
    }
} else {
    console.warn("⚠️ OpenSearch environment variables (HOST, USER, PASSWORD) not set. Search functionality will be disabled.");
}

// --- 2.5. KHỞI TẠO REDIS CLIENT ---
const VIEW_TIMEOUT_MS = 300000; // 5 phút (từ use-view-snippet.ts)
const CACHE_TTL_SECONDS = 60; // 60 giây cho cache tìm kiếm

let redisClient = null;
if (process.env.REDIS_URL) {
    try {
        redisClient = new Redis(process.env.REDIS_URL, {
            // Thêm các tùy chọn an toàn cho production
            tls: process.env.REDIS_URL.startsWith('rediss://'),
            maxRetriesPerRequest: 3
        });
        redisClient.on('error', (err) => console.error("❌ Redis Error:", err.message));
        redisClient.on('connect', () => console.log("Redis client connected successfully."));
    } catch (e) {
        console.error("❌ Failed to initialize Redis client:", e.message);
    }
} else {
    console.warn("⚠️ REDIS_URL environment variable not set. Caching and View Count functionality will be disabled.");
}


// --- 3. MIDDLEWARE ---
app.use(cors());
app.use(express.json());

// Middleware xác thực API key
const apiKeyAuth = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return next(); // Không có key, tiếp tục
        }
        const apiKey = authHeader.split(' ')[1];
        if (!apiKey) {
             return next(); // Có 'Bearer ' nhưng không có key
        }

        // Thử lấy từ cache trước
        let userAuth = null;
        if (redisClient) {
            try {
                const cachedAuth = await redisClient.get(`apikey:${apiKey}`);
                if (cachedAuth) {
                    userAuth = JSON.parse(cachedAuth);
                    req.userAuth = userAuth;
                    return next();
                }
            } catch (e) {
                console.warn("Redis GET error for API key:", e.message);
            }
        }

        // Nếu không có cache, query Firestore
        const keysSnapshot = await db.collection(API_KEYS_COLLECTION).get();
        for (const doc of keysSnapshot.docs) {
            const data = doc.data();
            if (data.publicKey === apiKey) { userAuth = { userId: doc.id, type: 'public' }; break; }
            if (data.privateKey === apiKey) { userAuth = { userId: doc.id, type: 'private' }; break; }
        }
        
        if (!userAuth) {
             return res.status(403).send({ error: 'API Key không hợp lệ hoặc đã hết hạn.' });
        }

        // Lưu vào cache
        if (redisClient) {
             try {
                await redisClient.set(`apikey:${apiKey}`, JSON.stringify(userAuth), 'EX', 3600); // Cache key 1 giờ
             } catch (e) {
                 console.warn("Redis SET error for API key:", e.message);
             }
        }

        req.userAuth = userAuth;
        next();
    } catch (error) {
        console.error("API Key Auth Error:", error);
        return res.status(500).send({ error: 'Lỗi máy chủ khi xác thực API key.' });
    }
};
app.use(apiKeyAuth);

// Helper lấy thông tin user (dùng nội bộ)
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

// --- 4. CÁC ROUTES API ---

app.post('/getSnippet', async (req, res) => {
    const { snippetId, password } = req.body;
    if (!snippetId) return res.status(400).send({ error: 'Thiếu snippetId.' });

    try {
        const docRef = db.collection(SNIPPETS_COLLECTION).doc(snippetId);
        const docSnap = await docRef.get();

        if (!docSnap.exists) return res.status(404).send({ error: `Snippet '${snippetId}' không tồn tại.` });
        
        const data = docSnap.data();
        const isOwner = req.userAuth && req.userAuth.userId === data.creatorId;

        // Kiểm tra visibility
        if (data.visibility === 'deleted') return res.status(404).send({ error: 'Snippet này đã bị xóa.' });
        if (data.visibility === 'private' && (!isOwner || req.userAuth.type !== 'private')) {
            return res.status(403).send({ error: `Snippet là PRIVATE và bạn không có quyền truy cập.` });
        }

        // Kiểm tra password
        let passwordBypassed = false;
        if (data.visibility === 'unlisted' && data.password && data.password.length > 0) {
            if (isOwner && req.userAuth.type === 'private') {
                passwordBypassed = true;
            } else if (password !== data.password) {
                if (!password) return res.status(401).send({ error: 'Snippet này cần mật khẩu.', requiresPassword: true });
                return res.status(403).send({ error: 'Mật khẩu không chính xác.' });
            }
        }
        
        // ** YÊU CẦU MỚI: ĐẾM VIEW VÀ TIMEOUT **
        if (redisClient && req.userAuth?.userId && req.userAuth.userId !== data.creatorId) {
            const userId = req.userAuth.userId;
            const redisKey = `view_tracker:${snippetId}:${userId}`;
            try {
                const viewed = await redisClient.get(redisKey);
                if (!viewed) {
                    // 1. Đặt cờ timeout trong Redis
                    await redisClient.set(redisKey, "1", "PX", VIEW_TIMEOUT_MS);
                    
                    // 2. Tăng đếm view trong RTDB (không cần chờ)
                    if (rtdb) {
                        rtdb.ref(`view_counts/${snippetId}`).transaction((count) => (count || 0) + 1);
                        // Lưu ý: Không push notification cho view, theo logic frontend
                    }
                }
            } catch (e) {
                console.warn("Redis/RTDB view count error:", e.message);
                // Không chặn response nếu logic đếm view lỗi
            }
        }

        // Chuẩn bị data trả về
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
         console.error("Lỗi route /getSnippet:", error);
        return res.status(500).send({ error: 'Lỗi máy chủ khi lấy snippet.' });
    }
});

app.get('/getUserInfo', async (req, res) => {
    if (!req.userAuth || !req.userAuth.userId) return res.status(401).send({ error: 'Yêu cầu cần có API key hợp lệ.' });
    try {
        const { actorName, actorPhoto } = await getActorInfo(req.userAuth.userId);
        return res.status(200).send({ 
            userId: req.userAuth.userId, 
            displayName: actorName, 
            photoURL: actorPhoto 
        });
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
        
        const { actorName, actorPhoto } = await getActorInfo(req.userAuth.userId);

        const newSnippetData = {
            title, content, language, visibility,
            tags: Array.isArray(tags) ? tags.slice(0, 10) : [], // Giới hạn 10 tags
            password: visibility === 'unlisted' ? password : '',
            creatorId: req.userAuth.userId,
            creatorName: actorName,
            creatorPhotoURL: actorPhoto,
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
            updatedAt: admin.firestore.FieldValue.serverTimestamp(),
            expiresAt: calculateExpiresAt(expires),
            isVerified: false,
            copyCount: 0, // Khởi tạo
            starCount: 0  // Khởi tạo
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
        if (docSnap.data().visibility === 'deleted') return res.status(400).send({ error: 'Không thể chỉnh sửa snippet đã bị xóa.' });

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
        if (Object.keys(validUpdates).length === 0) return res.status(400).send({ error: 'Không có trường hợp lệ nào để cập nhật.' });

        if (validUpdates.visibility && validUpdates.visibility !== 'unlisted') {
            validUpdates.password = ''; 
        } else if ('visibility' in validUpdates && validUpdates.visibility === 'unlisted' && !('password' in validUpdates)) {
             delete validUpdates.password;
        }

        validUpdates.updatedAt = admin.firestore.FieldValue.serverTimestamp(); // Luôn cập nhật timestamp

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
        console.error("Lỗi route /updateSnippet:", error);
        return res.status(500).send({ error: 'Lỗi máy chủ khi cập nhật snippet.' });
    }
});

app.delete('/deleteSnippet', async (req, res) => {
    // ** CẬP NHẬT: Thêm oldVisibility khi xóa **
    if (!req.userAuth || req.userAuth.type !== 'private') return res.status(403).send({ error: 'Cần có private key để xóa snippet.' });
    try {
        const { snippetId } = req.body;
        if (!snippetId) return res.status(400).send({ error: 'Thiếu ID snippet.' });
        
        const snippetRef = db.collection(SNIPPETS_COLLECTION).doc(snippetId);
        const docSnap = await snippetRef.get();
        
        if (!docSnap.exists) return res.status(404).send({ error: 'Snippet không tồn tại.' });
        if (docSnap.data().creatorId !== req.userAuth.userId) return res.status(403).send({ error: 'Bạn không có quyền xóa snippet này.' });
        
        const currentVisibility = docSnap.data().visibility;
        if (currentVisibility === 'deleted') {
            return res.status(400).send({ error: 'Snippet này đã bị xóa trước đó.' });
        }

        await snippetRef.update({ 
            visibility: 'deleted',
            oldVisibility: currentVisibility, // Thêm trường oldVisibility
            updatedAt: admin.firestore.FieldValue.serverTimestamp() // Thêm timestamp
        });

        return res.status(200).send({ message: `Snippet '${snippetId}' đã được chuyển vào thùng rác.` });
    } catch (error) {
        console.error("Lỗi route /deleteSnippet:", error);
        return res.status(500).send({ error: 'Lỗi máy chủ khi xóa snippet.' });
    }
});

// ** ROUTE MỚI: /restoreSnippet **
app.post('/restoreSnippet', async (req, res) => {
    if (!req.userAuth || req.userAuth.type !== 'private') return res.status(403).send({ error: 'Cần có private key để khôi phục snippet.' });
    try {
        const { snippetId } = req.body;
        if (!snippetId) return res.status(400).send({ error: 'Thiếu ID snippet.' });

        const snippetRef = db.collection(SNIPPETS_COLLECTION).doc(snippetId);
        const docSnap = await snippetRef.get();

        if (!docSnap.exists) return res.status(404).send({ error: 'Snippet không tồn tại.' });
        if (docSnap.data().creatorId !== req.userAuth.userId) return res.status(403).send({ error: 'Bạn không có quyền khôi phục snippet này.' });
        if (docSnap.data().visibility !== 'deleted') return res.status(400).send({ error: 'Snippet này không ở trong thùng rác.' });

        const newVisibility = docSnap.data().oldVisibility || 'private'; // Khôi phục về 'private' nếu không rõ

        await snippetRef.update({
            visibility: newVisibility,
            oldVisibility: admin.firestore.FieldValue.delete(), // Xóa trường oldVisibility
            updatedAt: admin.firestore.FieldValue.serverTimestamp()
        });
        
        return res.status(200).send({ message: `Snippet '${snippetId}' đã được khôi phục về trạng thái '${newVisibility}'.` });

    } catch (error) {
        console.error("Lỗi route /restoreSnippet:", error);
        return res.status(500).send({ error: 'Lỗi máy chủ khi khôi phục snippet.' });
    }
});

// ** ROUTE MỚI: /starSnippet **
app.post('/starSnippet', async (req, res) => {
    if (!rtdb) return res.status(503).send({ error: 'Dịch vụ Realtime Database không khả dụng.' });
    if (!req.userAuth || req.userAuth.type !== 'private') return res.status(403).send({ error: 'Cần có private key để star snippet.' });
    
    try {
        const { snippetId, star } = req.body; // star là boolean (true: star, false: unstar)
        if (!snippetId || typeof star !== 'boolean') {
            return res.status(400).send({ error: 'Thiếu snippetId hoặc trạng thái star (boolean).' });
        }

        const userId = req.userAuth.userId;
        const snippetSnap = await db.collection(SNIPPETS_COLLECTION).doc(snippetId).get();
        if (!snippetSnap.exists) return res.status(404).send({ error: 'Snippet không tồn tại.' });
        
        const snippet = snippetSnap.data();
        if (snippet.creatorId === userId) return res.status(403).send({ error: 'Bạn không thể star snippet của chính mình.' });
        
        const starCountRef = rtdb.ref(`star_counts/${snippetId}`);
        const starDetailsRef = rtdb.ref(`star_details/${snippetId}/${userId}`);
        const isStarredSnap = await starDetailsRef.once('value');
        const isStarred = isStarredSnap.exists();

        if (star && !isStarred) {
            // Star
            await starCountRef.transaction((count) => (count || 0) + 1);
            await starDetailsRef.set(true);

            // Gửi notification
            const { actorName } = await getActorInfo(userId);
            const notificationsRef = rtdb.ref(`notifications/${snippet.creatorId}`);
            await notificationsRef.push({
                type: 'star',
                actorUid: userId,
                actorName: actorName,
                snippetId: snippetId,
                snippetTitle: snippet.title,
                timestamp: admin.database.ServerValue.TIMESTAMP, // Dùng RTDB server timestamp
                read: false,
            });
            return res.status(200).send({ status: 'starred', starCount: (await starCountRef.once('value')).val() });

        } else if (!star && isStarred) {
            // Unstar
            await starCountRef.transaction((count) => (count > 0 ? count - 1 : 0));
            await starDetailsRef.set(null);
            return res.status(200).send({ status: 'unstarred', starCount: (await starCountRef.once('value')).val() });
        }
        
        // Trạng thái không đổi
        return res.status(200).send({ status: isStarred ? 'already_starred' : 'already_unstarred', starCount: (await starCountRef.once('value')).val() });

    } catch (error) {
        console.error("Lỗi route /starSnippet:", error);
        return res.status(500).send({ error: 'Lỗi máy chủ khi star snippet.' });
    }
});

// ** ROUTE MỚI: /copySnippet **
app.post('/copySnippet', async (req, res) => {
    if (!req.userAuth || req.userAuth.type !== 'private') return res.status(403).send({ error: 'Cần có private key để copy snippet.' });
    
    try {
        const { snippetId } = req.body;
        if (!snippetId) return res.status(400).send({ error: 'Thiếu snippetId.' });

        const userId = req.userAuth.userId;
        const originalSnippetRef = db.collection(SNIPPETS_COLLECTION).doc(snippetId);
        const originalSnap = await originalSnippetRef.get();

        if (!originalSnap.exists) return res.status(404).send({ error: 'Snippet gốc không tồn tại.' });
        
        const originalData = originalSnap.data();
        
        // Kiểm tra quyền truy cập (giống /getSnippet, không check password vì API key đã có quyền)
        if (originalData.visibility === 'deleted') return res.status(404).send({ error: 'Snippet gốc đã bị xóa.' });
        if (originalData.visibility === 'private' && originalData.creatorId !== userId) {
            return res.status(403).send({ error: 'Bạn không có quyền copy snippet private này.' });
        }
        if (originalData.creatorId === userId) return res.status(403).send({ error: 'Bạn không thể copy snippet của chính mình.' });

        const { actorName, actorPhoto } = await getActorInfo(userId);
        
        // Dùng batch write
        const batch = db.batch();
        const newSnippetRef = db.collection(SNIPPETS_COLLECTION).doc(); // Tạo ref mới

        const {
            id, isVerified, oldVisibility, // Xóa các trường không cần thiết
            creatorId, creatorName, creatorPhotoURL, // Thay bằng người copy
            createdAt, updatedAt, // Tạo mới
            starCount, copyCount, // Reset
            ...restOfSnippet // Giữ lại title, content, language, tags, v.v.
        } = originalData;

        const newSnippetData = {
            ...restOfSnippet,
            creatorId: userId,
            creatorName: actorName,
            creatorPhotoURL: actorPhoto,
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
            updatedAt: admin.firestore.FieldValue.serverTimestamp(),
            originalSnippetId: snippetId, // Theo dõi snippet gốc
            originalCreatorId: originalData.creatorId,
            originalCreatorName: originalData.creatorName,
            starCount: 0,
            copyCount: 0,
            visibility: 'private', // Luôn là private khi copy
            password: '', // Xóa password
            expiresAt: null, // Xóa hạn HSD
        };

        batch.set(newSnippetRef, newSnippetData);

        // Tăng copyCount của snippet gốc
        batch.update(originalSnippetRef, {
            copyCount: admin.firestore.FieldValue.increment(1),
            updatedAt: admin.firestore.FieldValue.serverTimestamp()
        });

        await batch.commit();

        // Gửi notification (RTDB)
        if (rtdb) {
            const notificationsRef = rtdb.ref(`notifications/${originalData.creatorId}`);
            await notificationsRef.push({
                type: 'copy',
                actorUid: userId,
                actorName: actorName,
                snippetId: snippetId, // ID snippet gốc
                snippetTitle: originalData.title,
                newSnippetId: newSnippetRef.id, // ID snippet mới (nếu cần)
                timestamp: admin.database.ServerValue.TIMESTAMP,
                read: false,
            });
        }

        return res.status(201).send({ 
            message: 'Snippet đã được copy thành công.', 
            newSnippetId: newSnippetRef.id 
        });

    } catch (error) {
        console.error("Lỗi route /copySnippet:", error);
        return res.status(500).send({ error: 'Lỗi máy chủ khi copy snippet.' });
    }
});


app.post('/listSnippets', async (req, res) => {
    if (!req.userAuth || req.userAuth.type !== 'private') return res.status(403).send({ error: 'Cần có private key để liệt kê snippets.' });
    try {
        let { limit = 20, visibility, includeDeleted = false } = req.body;
        limit = Math.min(Math.max(1, parseInt(limit, 10)), 100); // Giới hạn 1-100

        let query = db.collection(SNIPPETS_COLLECTION).where('creatorId', '==', req.userAuth.userId);
        
        if (visibility) {
            query = query.where('visibility', '==', visibility);
        } else if (!includeDeleted) {
            // Mặc định không bao gồm snippet đã xóa, trừ khi visibility='deleted'
            query = query.where('visibility', '!=', 'deleted');
        }

        const snapshot = await query.orderBy('updatedAt', 'desc').limit(limit).get(); // Sắp xếp theo updatedAt
        
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
            // Bỏ qua các snippet đã hết hạn (nếu có)
            .where('expiresAt', '>', admin.firestore.Timestamp.now())
            .orderBy('expiresAt') // Phải orderBy trường so sánh
            .orderBy('createdAt', 'desc')
            .limit(20)
            .get();

        // Cần một query riêng cho các snippet không bao giờ hết hạn
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
            .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()) // Sắp xếp lại
            .slice(0, 20); // Lấy 20
            
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
                console.error("Redis GET error:", err.message);
            }
        }

        const indexName = process.env.OPENSEARCH_INDEX || 'snippets';

        const queryBody = {
            size: size,
            from: from,
            query: {
                bool: {
                    should: [
                        {
                            multi_match: {
                                query: searchTerm,
                                fields: ["title^5", "tags^3", "content^1", "creatorName"],
                                fuzziness: "AUTO",
                                operator: "OR"
                            }
                        },
                        {
                            multi_match: {
                                query: searchTerm,
                                type: "phrase_prefix",
                                fields: ["title^10", "tags^5"],
                            }
                        }
                    ],
                    minimum_should_match: 1,
                    filter: [
                        { term: { "visibility.keyword": "public" } },
                        // Thêm filter cho expiresAt
                        {
                            bool: {
                                should: [
                                    { bool: { must_not: { exists: { field: "expiresAt" } } } }, // Hoặc không có
                                    { range: { expiresAt: { gt: "now/ms" } } } // Hoặc lớn hơn bây giờ
                                ]
                            }
                        }
                    ]
                }
            },
            sort: [
                { "_score": { "order": "desc" } },
                { "ai_priority": { "order": "desc", "missing": "_last" } },
                { "createdAt": { "order": "desc" } }
            ],
            // Thêm highlight (tùy chọn)
             highlight: {
                pre_tags: ["<mark>"],
                post_tags: ["</mark>"],
                fields: {
                    "title": {},
                    "content": {}
                }
            }
        };

        const response = await osClient.search({
            index: indexName,
            body: queryBody,
        });

        const results = response.body.hits.hits.map(hit => ({
            id: hit._id,
            ...hit._source,
            highlight: hit.highlight // Thêm highlight
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
                console.error("Redis SET error:", err.message);
            }
        }

        return res.status(200).send(finalResponse);

    } catch (error) {
        console.error("Lỗi route /searchSnippets:", error.meta ? error.meta.body : error.message);
        const errorMessage = error.meta?.body?.error?.reason || 'Lỗi máy chủ khi tìm kiếm.';
        return res.status(500).send({ error: errorMessage });
    }
});

// --- 5. EXPORT APP CHO VERCEL ---
module.exports = app;
