const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { apiKeyAuth } = require('./middleware/auth');
const snippetRoutes = require('./routes/snippetRoutes');
const userRoutes = require('./routes/userRoutes');
const interactionRoutes = require('./routes/interactionRoutes');
const searchRoutes = require('./routes/searchRoutes');

const app = express();

// Rate limiting middleware
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
    legacyHeaders: false, // Disable the `X-RateLimit-*` headers
    message: {
      status: 429,
      error: 'Too many requests, please try again later.'
    }
});
// Rate limiting for every routes
app.use(limiter);

// Rate limiting for search routes
const searchLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 minute
    max: 30, // limit each IP to 30 requests per windowMs
    standardHeaders: true,
    legacyHeaders: false,
    message: {
      status: 429,
      error: 'Too many search requests, please try again later.'
    }
});
app.use('/search', limiter, searchLimiter);

// --- MIDDLEWARE ---
app.use(cors());
app.use(express.json());

// API key authentication middleware
app.use(apiKeyAuth);

// --- ROUTES ---
app.use(snippetRoutes);
app.use(userRoutes);
app.use(interactionRoutes);
app.use(searchRoutes);

module.exports = app;
