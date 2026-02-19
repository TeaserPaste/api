const admin = require('firebase-admin');

// --- 1. INITIALIZE FIREBASE ADMIN SDK ---
let serviceAccountCredentials;
let db;
let rtdb; // Variable for Realtime Database

try {
    // Ensure FIREBASE_PRIVATE_KEY is parsed correctly
    const privateKey = (process.env.FIREBASE_PRIVATE_KEY || '').replace(/\\n/g, '\n');
    
    if (!process.env.FIREBASE_PROJECT_ID || !privateKey || !process.env.FIREBASE_CLIENT_EMAIL) {
        throw new Error('Missing Firebase Admin SDK environment variables (PROJECT_ID, PRIVATE_KEY, CLIENT_EMAIL).');
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
            databaseURL: process.env.FIREBASE_DATABASE_URL // Add databaseURL for RTDB
        });
        console.log("Firebase Admin SDK initialized successfully.");
    }

    // Initialize services
    db = admin.firestore();
    rtdb = admin.database(); // Initialize Realtime Database
    console.log("Firestore and RTDB services initialized.");

} catch (e) {
    console.error("❌ Firebase Config Error: Make sure you have set all FIREBASE_* environment variables on Vercel.", e.message);
}

module.exports = { admin, db, rtdb };
