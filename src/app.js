const express = require('express');
const cors = require('cors');
const { apiKeyAuth } = require('./middleware/auth');
const snippetRoutes = require('./routes/snippetRoutes');
const userRoutes = require('./routes/userRoutes');
const interactionRoutes = require('./routes/interactionRoutes');
const searchRoutes = require('./routes/searchRoutes');

const app = express();

// --- MIDDLEWARE ---
app.use(cors());
app.use(express.json());

// API key authentication middleware
app.use(apiKeyAuth);

// --- ROUTES ---
// Mount routes.
// Note: Original code had all routes at root level (e.g. /getSnippet).
// So I will mount them at root.
app.use(snippetRoutes);
app.use(userRoutes);
app.use(interactionRoutes);
app.use(searchRoutes);

module.exports = app;
