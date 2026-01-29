// === FOODLE BACKEND SERVER ===
// AI-powered food recommendation app with mobile GPS integration

// Load environment variables from .env file
require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const path = require('path');
const axios = require('axios');
const { OpenAI } = require('openai');
const multer = require('multer');
const QRCode = require('qrcode');
const { v4: uuidv4 } = require('uuid');
const http = require('http');
const { Server } = require('socket.io');
const { getRestaurantDescription } = require('./restaurant-descriptions');

// Define PORT early so it can be used throughout the file
const PORT = process.env.PORT || 5000;

// JWT Secret for token verification
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
    console.error('❌ CRITICAL: JWT_SECRET environment variable not set!');
    process.exit(1);
}

const app = express();
app.use(express.json());

// Create HTTP server for WebSocket support
const server = http.createServer(app);
const io = new Server(server, {
    cors: {
        origin: process.env.FRONTEND_URL ? process.env.FRONTEND_URL.split(',') : ['http://localhost:3000', 'http://localhost:3001'],
        credentials: true
    }
});

// In-memory storage for mobile GPS sessions (use Redis in production)
global.locationSessions = new Map();

// Debug middleware to log all requests and session state
app.use((req, res, next) => {
    console.log(`📥 ${req.method} ${req.path} from ${req.ip}`);
    console.log(`📥 Session state:`, {
        id: req.session?.id,
        email: req.session?.email,
        hasSession: !!req.session
    });
    console.log(`📥 Headers:`, {
        'user-agent': req.get('User-Agent'),
        'cookie': req.get('Cookie'),
        'origin': req.get('Origin')
    });
    next();
});

// === MIDDLEWARE CONFIGURATION ===

// Session middleware - MUST be configured before CORS to work properly
if (!process.env.SESSION_SECRET) {
    console.error('❌ CRITICAL: SESSION_SECRET environment variable not set!');
    process.exit(1);
}
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true, // CRITICAL: Save empty sessions so cookies are set on first request
    rolling: true, // Reset expiration on each request
    cookie: {
        secure: process.env.NODE_ENV === 'production', // true in production (HTTPS), false in development
        httpOnly: true, // Prevent XSS attacks
        maxAge: 24 * 60 * 60 * 1000, // 24 hours
        sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax', // 'none' for production cross-origin, 'lax' for development
        domain: process.env.NODE_ENV === 'production' ? undefined : 'localhost' // Don't restrict domain in production
    },
    name: 'foodle.session' // Custom session name
}));

app.use(passport.initialize());
app.use(passport.session());

// CORS configuration - MUST be after session middleware for proper credential handling
app.use(cors({
    origin: function(origin, callback) {
        // Build allowed origins list
        const allowedOrigins = [
            'http://localhost:3000',
            'http://localhost:3001',
            'http://localhost:5001'
        ];

        // Add production frontend URLs from env var
        if (process.env.FRONTEND_URL) {
            allowedOrigins.push(...process.env.FRONTEND_URL.split(',').map(url => url.trim()));
        }

        // Allow all Vercel preview and production deployments
        // Matches: *.vercel.app domains (covers preview and production)
        const allowVercelPattern = /^https:\/\/.*\.vercel\.app$/;

        // Allow requests with no origin (like mobile apps or curl requests)
        if (!origin) return callback(null, true);

        // Check if origin matches allowed list or Vercel pattern
        if (allowedOrigins.includes(origin) || allowVercelPattern.test(origin)) {
            callback(null, true); // Allow for development - restrict in production
        }
    },
    credentials: true, // Enable credentials (cookies, authorization headers)
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
    exposedHeaders: ['Set-Cookie']
}));

// === DATABASE CONNECTION ===

mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
}).then(() => {
    console.log('📊 Connected to MongoDB');
}).catch((err) => {
    console.error('❌ MongoDB connection error:', err);
});

// === USER SCHEMA & MODEL ===
const userSchema = new mongoose.Schema({
    firstName: String,
    lastName: String,
    email: { type: String, unique: true },
    passwordHash: String,
    profileImageUrl: String,
    country: String,
    preferences: {
        type: {
            cuisines: { type: [String], default: [] },
            priceRange: { type: String, default: "$$" },
            dietType: { type: String, default: "No restrictions" },
            allergies: { type: [String], default: [] }
        },
        default: () => ({
            cuisines: [],
            priceRange: "$$",
            dietType: "No restrictions",
            allergies: []
        })
    },
    lastKnownLocation: {
        latitude: { type: Number, default: null },
        longitude: { type: Number, default: null },
        accuracy: { type: Number, default: null },
        timestamp: { type: Date, default: null },
        source: { type: String, default: null } // 'mobile-gps', 'browser', etc.
    },
    previousMeals: {
        type: [{
            recommendationText: { type: String, required: true }, // Full AI recommendation message (cleaned)
            restaurantName: String,
            restaurantId: String, // Google Places ID
            userQuery: String, // User's original request
            timestamp: { type: Date, default: Date.now },
            filters: {
                priceLevel: mongoose.Schema.Types.Mixed, // Can be single number or array
                maxDistance: Number,
                category: String,
                minRating: Number,
                maxRating: Number
            },
            restaurant: mongoose.Schema.Types.Mixed // Complete restaurant data object
        }],
        default: []
    },
    savedRecommendations: {
        type: [{
            recommendationText: { type: String, required: true }, // Full AI recommendation message (legacy - keep for compatibility)
            restaurantName: String,
            restaurantId: String, // Google Places ID
            userQuery: String, // User's original request
            timestamp: { type: Date, default: Date.now },
            filters: {
                priceLevel: mongoose.Schema.Types.Mixed, // Can be single number or array
                maxDistance: Number,
                category: String,
                minRating: Number,
                maxRating: Number
            }
        }],
        default: []
    },
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

// === ADDITIONAL SCHEMAS FOR ENHANCED FUNCTIONALITY ===

// Favorites Schema - for user's favorite restaurants
const favoriteSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    restaurantId: { type: String, required: true }, // Google Places ID
    restaurantName: String,
    restaurantAddress: String,
    dateAdded: { type: Date, default: Date.now },
    notes: String,
    tags: [String], // custom user tags like "date night", "quick lunch", etc.
    lastVisited: Date
});

const Favorite = mongoose.model('Favorite', favoriteSchema);

// Reviews Schema - for user reviews of restaurants
const reviewSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    restaurantId: { type: String, required: true }, // Google Places ID
    restaurantName: String,
    rating: { type: Number, min: 1, max: 5, required: true },
    review: String,
    photos: [String], // URLs to uploaded photos
    visitDate: Date,
    createdAt: { type: Date, default: Date.now },
    helpful: { type: Number, default: 0 }, // how many users found this helpful
    tags: [String] // "great service", "loud", "good for groups", etc.
});

const Review = mongoose.model('Review', reviewSchema);

// Conversation History Schema - for AI chat history
const conversationSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    sessionId: String, // for anonymous users
    messages: [{
        type: { type: String, enum: ['user', 'ai'], required: true },
        content: String,
        timestamp: { type: Date, default: Date.now },
        metadata: {
            location: {
                latitude: Number,
                longitude: Number
            },
            restaurantContext: String, // if message was about a specific restaurant
            intent: String // "find_restaurant", "get_directions", "ask_question", etc.
        }
    }],
    startedAt: { type: Date, default: Date.now },
    lastActiveAt: { type: Date, default: Date.now }
});

const Conversation = mongoose.model('Conversation', conversationSchema);

// Restaurant Visit History Schema
const visitHistorySchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    restaurantId: { type: String, required: true }, // Google Places ID
    restaurantName: String,
    restaurantAddress: String,
    visitDate: { type: Date, default: Date.now },
    location: {
        latitude: Number,
        longitude: Number
    },
    howFound: { type: String, enum: ['ai_recommendation', 'search', 'qr_scan', 'manual'], default: 'search' },
    walkingTime: String,
    notes: String
});

const VisitHistory = mongoose.model('VisitHistory', visitHistorySchema);

// User Lists Schema - for custom restaurant lists like "Want to Try", "Business Lunches", etc.
const userListSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    name: { type: String, required: true },
    description: String,
    isPublic: { type: Boolean, default: false },
    restaurants: [{
        restaurantId: String, // Google Places ID
        restaurantName: String,
        restaurantAddress: String,
        addedAt: { type: Date, default: Date.now },
        notes: String,
        priority: { type: Number, default: 1 } // 1-5 scale
    }],
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

const UserList = mongoose.model('UserList', userListSchema);

// === HELPER FUNCTIONS ===

// Global distance calculation function (Haversine formula)
function calculateDistance(lat1, lon1, lat2, lon2) {
    const R = 6371; // Earth's radius in km
    const dLat = (lat2 - lat1) * Math.PI / 180;
    const dLon = (lon2 - lon1) * Math.PI / 180;
    const a = Math.sin(dLat / 2) * Math.sin(dLat / 2) +
            Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) *
            Math.sin(dLon / 2) * Math.sin(dLon / 2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
    return R * c; // Distance in km
}

// Distance calculation function that returns meters (for location checks)
function calculateDistanceBetweenCoords(lat1, lon1, lat2, lon2) {
    const R = 6371000; // Earth's radius in meters
    const dLat = (lat2 - lat1) * Math.PI / 180;
    const dLon = (lon2 - lon1) * Math.PI / 180;
    const a = Math.sin(dLat / 2) * Math.sin(dLat / 2) +
            Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) *
            Math.sin(dLon / 2) * Math.sin(dLon / 2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
    return R * c; // Distance in meters
}

// === USER ROUTES ===

// Registration endpoint
app.post('/api/register', async (req, res) => {
    const { firstName, lastName, email, password } = req.body;
    if (!firstName || !lastName || !email || !password) {
        return res.status(400).json({ message: 'All fields are required.' });
    }
    try {
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: 'Email already registered.' });
        }
        const passwordHash = await bcrypt.hash(password, 10);
        const user = new User({ firstName, lastName, email, passwordHash });
        await user.save();
        req.session.email = user.email; // Set session for new user!
        res.status(201).json({ message: 'Registration successful.' });
    } catch (err) {
        console.error('Registration error:', err);
        res.status(500).json({ message: 'Server error.' });
    }
});

// Login endpoint
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    console.log(`📥 POST /api/login - Email: ${email}`);
    console.log(`📥 Session before login:`, req.session);
    console.log(`📥 Cookies received:`, req.headers.cookie);
    
    if (!email || !password) {
        return res.status(400).json({ message: 'Email and password are required.' });
    }
    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: 'Email not found. Would you like to create an account?' });
        }
        const isMatch = await bcrypt.compare(password, user.passwordHash);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid password.' });
        }
        req.session.email = user.email; // Store email in session!
        // Save session explicitly and send response with cookie headers
        req.session.save((err) => {
            if (err) {
                console.error('❌ Session save error:', err);
                return res.status(500).json({ message: 'Session error.' });
            }
            console.log(`✅ Session saved for ${email}:`, req.session);
            console.log(`✅ Session ID:`, req.sessionID);
            res.status(200).json({ message: 'Login successful.' });
        });
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ message: 'Server error.' });
    }
});

// === GOOGLE OAUTH CONFIGURATION ===

// Helper function to get the current server URL
const getServerUrl = () => {
    const port = process.env.PORT || 3000;
    return `http://localhost:${port}`;
};

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: `http://localhost:${PORT}/auth/google/callback`
}, async (accessToken, refreshToken, profile, done) => {
    try {
        console.log('🔍 Google OAuth callback received for:', profile.emails[0].value);
        console.log('🔍 Profile ID:', profile.id);
        console.log('🔍 Profile Name:', profile.displayName);
        
        // Find or create user in your DB
        let user = await User.findOne({ email: profile.emails[0].value });
        if (!user) {
            console.log('👤 Creating new user from Google OAuth:', profile.emails[0].value);
            user = new User({
                firstName: profile.name.givenName,
                lastName: profile.name.familyName,
                email: profile.emails[0].value,
                passwordHash: '', // No password for Google users
                profileImageUrl: profile.photos && profile.photos.length > 0 ? profile.photos[0].value : null
            });
            await user.save();
            console.log('✅ New user created successfully');
        } else {
            console.log('👤 Found existing user for Google OAuth:', user.email);
            // Always update profile image from Google OAuth if available
            if (profile.photos && profile.photos.length > 0) {
                user.profileImageUrl = profile.photos[0].value;
                await user.save();
                console.log('✅ Profile image updated from Google OAuth');
            }
        }
        return done(null, user);
    } catch (err) {
        console.error('❌ Google OAuth error:', err);
        return done(err, null);
    }
}));

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    try {
        const user = await User.findById(id);
        done(null, user);
    } catch (err) {
        done(err, null);
    }
});

// Google OAuth routes
app.get('/auth/google', (req, res, next) => {
    console.log('🔍 Google OAuth initiation requested');
    console.log('🔍 Client ID:', process.env.GOOGLE_CLIENT_ID || 'USING DEFAULT');
    console.log('🔍 Callback URL:', `http://localhost:${PORT}/auth/google/callback`);
    
    // Store the referer in session to remember which frontend port to redirect to
    const referer = req.get('Referer');
    console.log('🔍 OAuth referer:', referer);
    
    if (referer) {
        try {
            const url = new URL(referer);
            if (url.hostname === 'localhost' || url.hostname === '127.0.0.1') {
                req.session.oauthReferer = `${url.protocol}//${url.host}`;
                console.log('🔍 Stored OAuth referer:', req.session.oauthReferer);
            }
        } catch (e) {
            console.log('⚠️ Invalid referer URL:', e.message);
        }
    }
    
    next();
}, passport.authenticate('google', { 
    scope: ['profile', 'email'],
    prompt: 'select_account' // Always show account selection
}));

// Helper function to get frontend URL
const getFrontendUrl = (req) => {
    const envUrls = process.env.FRONTEND_URL ? process.env.FRONTEND_URL.split(',') : [];
    const defaultUrl = envUrls[0] || 'http://localhost:3001'; // Changed to 3001 to match React dev server
    
    // Check if we stored the OAuth referer in session
    if (req.session?.oauthReferer) {
        const storedUrl = req.session.oauthReferer;
        if (envUrls.includes(storedUrl) || envUrls.length === 0) {
            return storedUrl;
        }
    }
    
    // Try to determine from referer header
    const referer = req.get('Referer');
    if (referer) {
        try {
            const url = new URL(referer);
            if (url.hostname === 'localhost' || url.hostname === '127.0.0.1') {
                const candidateUrl = `${url.protocol}//${url.host}`;
                if (envUrls.includes(candidateUrl) || envUrls.length === 0) {
                    return candidateUrl;
                }
            }
        } catch (e) {
            // Invalid URL in referer, use default
        }
    }
    
    return defaultUrl;
};

app.get('/auth/google/callback',
    passport.authenticate('google', { failureRedirect: '/auth/google/failure' }),
    async (req, res) => {
        try {
            console.log('🔍 Google OAuth callback successful');
            console.log('🔍 User:', req.user?.email);
            
            // Store email in session for profile operations
            if (req.user?.email) {
                req.session.email = req.user.email;
                console.log('🔍 Stored email in session:', req.session.email);
            }
            
            const frontendUrl = getFrontendUrl(req);
            console.log('🔍 Redirecting to frontend:', frontendUrl);
            
            // Clean up the stored referer
            if (req.session?.oauthReferer) {
                delete req.session.oauthReferer;
            }
            
            // Save session before redirect
            req.session.save((err) => {
                if (err) {
                    console.error('❌ Session save error during OAuth callback:', err);
                }
                res.redirect(`${frontendUrl}/home?auth=success`);
            });
            
        } catch (error) {
            console.error('❌ OAuth callback error:', error);
            const frontendUrl = getFrontendUrl(req);
            res.redirect(`${frontendUrl}/signin?error=oauth_callback_error`);
        }
    }
);

// Google OAuth failure redirect
app.get('/auth/google/failure', (req, res) => {
    console.log('❌ Google OAuth failed');
    console.log('❌ Query parameters:', req.query);
    console.log('❌ Session data:', req.session);
    
    // Log common OAuth errors
    if (req.query.error) {
        console.log('❌ OAuth error:', req.query.error);
        console.log('❌ Error description:', req.query.error_description);
        
        // Log specific error types
        if (req.query.error === 'access_denied') {
            console.log('❌ User denied access to the application');
        } else if (req.query.error === 'invalid_request') {
            console.log('❌ Invalid OAuth request - check your Google Cloud Console configuration');
            console.log('❌ Expected redirect URI: http://localhost:' + PORT + '/auth/google/callback');
        } else if (req.query.error === 'unauthorized_client') {
            console.log('❌ Unauthorized client - check your client ID and secret');
        }
    }
    
    const frontendUrl = getFrontendUrl(req);
    const errorMessage = req.query.error || 'oauth_failed';
    res.redirect(`${frontendUrl}/signin?error=${errorMessage}`);
});

// OAuth debug endpoint
app.get('/auth/debug', (req, res) => {
    res.json({
        message: 'OAuth Debug Information',
        config: {
            clientId: process.env.GOOGLE_CLIENT_ID ? 'Set' : 'Not set',
            clientSecret: process.env.GOOGLE_CLIENT_SECRET ? 'Set' : 'Not set',
            callbackUrl: `http://localhost:${PORT}/auth/google/callback`,
            sessionSecret: process.env.SESSION_SECRET ? 'Set' : 'Not set'
        },
        requiredGoogleCloudConfig: {
            authorizedJavaScriptOrigins: [
                `http://localhost:${PORT}`,
                `http://127.0.0.1:${PORT}`,
                'http://localhost:3000',
                'http://127.0.0.1:3000',
                'http://localhost:3001',
                'http://127.0.0.1:3001'
            ],
            authorizedRedirectUris: [
                `http://localhost:${PORT}/auth/google/callback`,
                `http://127.0.0.1:${PORT}/auth/google/callback`
            ]
        },
        testUrls: {
            startOAuth: `http://localhost:${PORT}/auth/google`,
            alternativeStart: `http://127.0.0.1:${PORT}/auth/google`,
            debugInfo: `http://localhost:${PORT}/auth/debug`
        }
    });
});

// Search endpoint
app.post('/api/search', async (req, res) => {
    console.log('Search query received:', req.body.query);
    const { query } = req.body;
    
    if (!query) {
        return res.status(400).json({ message: 'Search query is required.' });
    }
    
    console.log(`User searched for: "${query}"`);
    
    res.status(200).json({ 
        message: 'Search received successfully',
        searchQuery: query 
    });
});

// OpenAI GPT endpoint
const openai = new OpenAI({
    apiKey: process.env.OPENAI_API_KEY
});

// Shared restaurant recommendation logic
async function getRestaurantRecommendation({ message, preferences, location, session, generateAnother = false, inputAnalysis = null }) {
    try {
        let { latitude, longitude } = location || {};
        
        console.log(`🤖 AI Recommendation request received`);
        console.log(`🤖 Full user message:`, message);
        console.log(`🤖 Location:`, location);
        console.log(`🤖 Generate Another flag:`, generateAnother);
        console.log(`🤖 Session email:`, session?.email);
        console.log(`🤖 Session ID:`, session?.id);
        
        // CRITICAL DEBUG: Show preferences received
        console.log(`\n🎯 ===== PREFERENCES DEBUG =====`);
        console.log(`🎯 preferences object:`, preferences);
        console.log(`🎯 preferences type:`, typeof preferences);
        console.log(`🎯 preferences.filters:`, preferences?.filters);
        console.log(`🎯 preferences.filters type:`, typeof preferences?.filters);
        if (preferences?.filters) {
            console.log(`🎯 priceLevel: ${preferences.filters.priceLevel} (${typeof preferences.filters.priceLevel})`);
            console.log(`🎯 category: ${preferences.filters.category}`);
            console.log(`🎯 maxDistance: ${preferences.filters.maxDistance}`);
            console.log(`🎯 minRating: ${preferences.filters.minRating}`);
            console.log(`🎯 maxRating: ${preferences.filters.maxRating}`);
        }
        console.log(`🎯 ==============================\n`);
        
        console.log(`🧠 SESSION DEBUG in getRestaurantRecommendation:`, {
            sessionExists: !!session,
            sessionId: session?.id,
            sessionEmail: session?.email,
            recommendedRestaurants: session?.recommendedRestaurants || [],
            recommendedCount: session?.recommendedRestaurants?.length || 0
        });
        
        // Handle both location formats from frontend
        if (location && typeof location === 'object') {
            console.log(`🤖 Using nested location object:`, location);
            latitude = location.latitude;
            longitude = location.longitude;
        }
        
        console.log(`🤖 Extracted coordinates:`, { latitude, longitude });

        const apiKey = process.env.GOOGLE_PLACES_API_KEY;
        if (!apiKey) {
            console.error('❌ Google Places API key is missing');
            return {
                success: false,
                error: 'Server configuration error: Google Places API key is missing.'
            };
        }
        
        // Get user information for database preferences and location
        let user = null;
        
        // Try to get user from session first
        if (session && session.email) {
            try {
                user = await User.findOne({ email: session.email });
                console.log(`🤖 Found user from session: ${user?.firstName} ${user?.lastName}`);
            } catch (error) {
                console.error('❌ Error fetching user from session:', error);
            }
        }
        
        // PRIORITY 1: Use stored location from database if available
        if (user && user.lastKnownLocation && user.lastKnownLocation.latitude && user.lastKnownLocation.longitude) {
            const storedLat = user.lastKnownLocation.latitude;
            const storedLng = user.lastKnownLocation.longitude;
            
            // Check if we have a provided location to compare with
            if (latitude && longitude) {
                // Calculate distance between stored and provided location
                const distance = calculateDistance(storedLat, storedLng, latitude, longitude);
                const distanceKm = distance;
                
                console.log(`🤖 Distance check: stored location vs provided location = ${distanceKm.toFixed(2)}km`);
                
                if (distanceKm <= 5.0) {
                    // Use stored location if within 5km of provided location
                    console.log(`🤖 Using stored location (within ${distanceKm.toFixed(2)}km of provided):`, {
                        lat: storedLat,
                        lng: storedLng,
                        source: user.lastKnownLocation.source
                    });
                    
                    latitude = storedLat;
                    longitude = storedLng;
                } else {
                    // Provided location is significantly different, use it and update stored location
                    console.log(`🤖 Provided location is ${distanceKm.toFixed(2)}km away from stored, using provided location`);
                    console.log(`🤖 Will update stored location from (${storedLat}, ${storedLng}) to (${latitude}, ${longitude})`);
                }
            } else {
                // No provided location, always use stored location regardless of age
                const locationTimestamp = user.lastKnownLocation.timestamp;
                const hoursOld = locationTimestamp ? 
                    (Date.now() - new Date(locationTimestamp).getTime()) / (1000 * 60 * 60) : 0;
                
                console.log(`🤖 No provided location, using stored location (${hoursOld.toFixed(1)}h old):`, {
                    lat: storedLat,
                    lng: storedLng,
                    source: user.lastKnownLocation.source
                });
                
                latitude = storedLat;
                longitude = storedLng;
            }
        }
        
        // PRIORITY 2: Use provided coordinates if no stored location or stored location is old
        if (!latitude || !longitude) {
            console.log('🤖 No coordinates provided and no stored location available');
            return {
                success: false,
                error: 'Location required. Please share your location first.'
            };
        }
        
        // ENHANCED: Dynamic search radius with MUCH larger coverage for better restaurant discovery
        const maxDistanceKm = preferences?.filters?.maxDistance || 10; // Increased default to 10km
        const searchRadius = Math.min(maxDistanceKm * 1000, 50000); // INCREASED: max 50km for much better coverage
        
        console.log(`🤖 Final coordinates for search and calculations: ${latitude}, ${longitude}`);
        console.log(`🤖 🔍 ENHANCED SEARCH RADIUS: ${searchRadius}m (${maxDistanceKm}km from filter) - MUCH LARGER COVERAGE!`);
        console.log(`🤖 Full user message will be analyzed by AI:`, message);
        
        console.log(`🤖 📍 USER LOCATION FOR ALL CALCULATIONS: lat=${latitude}, lng=${longitude}`);
        
        // Find nearby restaurants
        const restaurants = await findNearbyRestaurants(latitude, longitude, searchRadius, apiKey);
        
        if (!restaurants || restaurants.length === 0) {
            console.log('❌ No restaurants found nearby');
            return {
                success: false,
                error: 'No restaurants found in your area. Try expanding the search radius.'
            };
        }
        
        console.log(`🍽️ Found ${restaurants.length} restaurants nearby`);
        
        // Apply AI-powered filtering and ranking with detailed restaurant information
        console.log(`🤖 Starting AI-powered restaurant analysis with full user message...`);
        const aiResult = await selectBestRestaurantWithAI(restaurants, preferences || {}, message, user, session, generateAnother, inputAnalysis);
        let bestRestaurant = aiResult?.restaurant; // Extract restaurant from new return format
        
        // Check if no restaurants match the filters
        if (aiResult?.noResultsMessage) {
            console.log(`❌ No restaurants match filters: ${aiResult.noResultsMessage}`);
            return {
                success: true,
                data: {
                    type: "no_results",
                    message: aiResult.noResultsMessage,
                    recommendationId: aiResult.recommendationId,
                    debug: {
                        appliedFilters: aiResult.debuggingData?.appliedFilters || {},
                        excludedCount: aiResult.debuggingData?.excludedCount || 0,
                        filterExplanation: aiResult.debuggingData?.filterExplanation || [],
                        selectionMethod: aiResult.debuggingData?.selectionMethod || 'no-results-found',
                        totalRestaurantsFound: restaurants.length
                    }
                }
            };
        }
        
        // Select the best restaurant
        if (!bestRestaurant) {
            console.log('❌ No suitable restaurant found after AI analysis');
            
            // Check if this is because all restaurants were filtered out due to session memory
            const sessionRecommendations = session?.recommendedRestaurants || [];
            if (sessionRecommendations.length > 0 && restaurants.length > 0) {
                console.log('🔄 All suitable restaurants already recommended this session, clearing session memory');
                if (session) session.recommendedRestaurants = [];
                
                // Retry AI analysis without session memory
                const retryResult = await selectBestRestaurantWithAI(restaurants, preferences || {}, message, user, session, generateAnother);
                const retryBest = retryResult?.restaurant; // Extract restaurant from new return format
                
                // Check if retry also returned no results
                if (retryResult?.noResultsMessage) {
                    console.log(`❌ Still no restaurants after retry: ${retryResult.noResultsMessage}`);
                    return {
                        success: true,
                        data: {
                            type: "no_results",
                            message: retryResult.noResultsMessage,
                            recommendationId: retryResult.recommendationId,
                            debug: {
                                appliedFilters: retryResult.debuggingData?.appliedFilters || {},
                                excludedCount: retryResult.debuggingData?.excludedCount || 0,
                                filterExplanation: retryResult.debuggingData?.filterExplanation || [],
                                selectionMethod: 'no-results-after-retry',
                                totalRestaurantsFound: restaurants.length
                            }
                        }
                    };
                }
                
                if (retryBest) {
                    console.log(`🔄 Found restaurant after clearing session memory: ${retryBest.name}`);
                    bestRestaurant = retryBest;
                } else {
                    return {
                        success: false,
                        error: 'No suitable restaurants found matching your preferences.'
                    };
                }
            } else {
                return {
                    success: false,
                    error: 'No suitable restaurants found matching your preferences.'
                };
            }
        }
        
        console.log(`🔍 Enhancing restaurant: ${bestRestaurant.name} (AI selected)`);
        
        // Get detailed restaurant information
        const details = await getRestaurantDetails(bestRestaurant.placeId, apiKey);
        
        // Calculate walking time using user's actual location
        console.log(`🚶 📍 WALKING TIME CALCULATION:`);
        console.log(`🚶 📍 FROM USER LOCATION: (${latitude}, ${longitude})`);
        console.log(`🚶 📍 TO RESTAURANT: ${bestRestaurant.name} at (${bestRestaurant.latitude}, ${bestRestaurant.longitude})`);
        const walkingTimeInfo = await calculateWalkingTime(
            latitude, longitude, 
            bestRestaurant.latitude, bestRestaurant.longitude, 
            apiKey
        );
        
        // Process photos
        const photos = processRestaurantPhotos(details.photos || [], apiKey);
        console.log(`📸 Photos processing for ${bestRestaurant.name}:`, {
            photosFromAPI: details.photos?.length || 0,
            processedPhotos: photos.length,
            firstPhotoUrl: photos[0]?.url || 'None'
        });
        
        // Build complete restaurant object matching frontend expectations
        const enhancedRestaurant = {
            name: bestRestaurant.name,
            address: details.address || bestRestaurant.address,
            rating: bestRestaurant.rating || 'N/A',
            reviewCount: details.reviewCount || bestRestaurant.reviewCount || 0,
            priceLevel: (() => {
                const pl = details.priceLevel || bestRestaurant.priceLevel;
                if (typeof pl === 'number' && pl >= 1 && pl <= 4) {
                    return ['', '$', '$$', '$$$', '$$$$'][pl] || 'N/A';
                }
                return 'N/A';
            })(),
            walkingTime: walkingTimeInfo,
            placeId: bestRestaurant.placeId,
            location: {
                lat: bestRestaurant.latitude,
                lng: bestRestaurant.longitude
            },
            website: details.website || null,
            phoneNumber: details.phoneNumber || null,
            distance: bestRestaurant.distance || 0,
            distanceText: bestRestaurant.distance < 1 ? 
                `${Math.round(bestRestaurant.distance * 1000)}m` : 
                `${Math.round(bestRestaurant.distance * 10) / 10}km`,
            photos: photos
        };
        
        // ENHANCED SESSION TRACKING: Add to new tracking system instead of old session array
        if (session) {
            console.log(`🧠 ===== ENHANCED SESSION TRACKING =====`);
            
            // Initialize new tracking system if needed
            if (!session.recommendationTracking) {
                session.recommendationTracking = {};
                console.log(`🆕 Initialized recommendation tracking system`);
            }
            
            // Extract recommendation ID from AI result
            const recommendationId = bestRestaurant.recommendationId || aiResult.recommendationId;
            
            if (recommendationId) {
                console.log(`🧠 Using recommendation ID from AI result: ${recommendationId}`);
                
                // The restaurant should already be in the tracking from the AI selection
                const tracking = session.recommendationTracking[recommendationId];
                if (tracking) {
                    console.log(`🧠 ✅ TRACKING CONFIRMED: ${bestRestaurant.name} already tracked for ${recommendationId}`);
                    console.log(`🧠 Current exclusion count: ${tracking.excludedRestaurants.length}`);
                } else {
                    console.log(`🧠 ⚠️ WARNING: No tracking found for recommendation ID ${recommendationId}`);
                }
            } else {
                console.log(`🧠 ⚠️ WARNING: No recommendation ID found in AI result`);
            }
            
            // Legacy system: Still maintain old array for compatibility
            if (!session.recommendedRestaurants) {
                session.recommendedRestaurants = [];
                console.log(`🧠 Initialized legacy recommendedRestaurants array`);
            }
            console.log(`🧠 Legacy system before adding: ${session.recommendedRestaurants.length} restaurants`);
            session.recommendedRestaurants.push({
                placeId: bestRestaurant.placeId,
                name: bestRestaurant.name
            });
            console.log(`💾 Added to legacy system: ${bestRestaurant.name} (${bestRestaurant.placeId})`);
            console.log(`🧠 Legacy system after adding: ${session.recommendedRestaurants.length} restaurants`);
            console.log(`🧠 Legacy restaurants:`, session.recommendedRestaurants.map(r => r.name || r));
            
            console.log(`🧠 ===== END ENHANCED SESSION TRACKING =====`);
        } else {
            console.log(`🚨 WARNING: No session provided to getRestaurantRecommendation, cannot save to memory!`);
        }
        
        console.log(`✅ AI Recommendation complete: ${enhancedRestaurant.name}`);
        console.log(`✅ Final walking time: ${JSON.stringify(enhancedRestaurant.walkingTime)}`);
        console.log(`✅ Photos included: ${enhancedRestaurant.photos.length}`);
        
        return {
            success: true,
            data: {
                type: "restaurant",
                restaurant: enhancedRestaurant,
                recommendationId: bestRestaurant.recommendationId || aiResult.recommendationId,
                aiResponse: aiResult.recommendationText || aiResult.explanation || `I found a great restaurant for you: ${enhancedRestaurant.name}! This restaurant matches your preferences and is highly rated in your area.`, // Include AI explanation
                // Include raw Google API data for browser console debugging
                debug: {
                    rawGoogleApiData: restaurants,
                    totalRestaurantsFound: restaurants.length,
                    userMessage: message,
                    sessionRecommendations: session?.recommendedRestaurants || [],
                    enhancedTracking: session?.recommendationTracking || {},
                    aiResult: aiResult.debuggingData || {}
                }
            }
        };
        
    } catch (error) {
        console.error('❌ Error in restaurant recommendation:', error);
        return {
            success: false,
            error: 'An error occurred while finding restaurants.'
        };
    }
}

// Initialize session-based restaurant memory
if (!global.sessionRestaurantMemory) {
    global.sessionRestaurantMemory = new Map();
}

// Enhanced API endpoint for chat messages including restaurant recommendations
// Supports both regular requests and "Generate Another" functionality via flag
// Body: { message: string, location?: object, generateAnother?: boolean }
app.post('/api/message', async (req, res) => {
    console.log('🚨🚨🚨 API MESSAGE ENDPOINT HIT - FIXES ARE LOADED 🚨🚨🚨');
    const { message, extraInfo, location, generateAnother, preferences } = req.body;
    // Use extraInfo if provided, otherwise use message
    const userInput = (typeof extraInfo === 'string' && extraInfo.trim().length > 0) ? extraInfo : message;
    console.log(`💬 Received message: "${userInput}"`);
    console.log(`📍 Received location:`, location);
    console.log(`🔄 Generate Another flag:`, generateAnother);
    console.log(`🎯 Received preferences:`, preferences);
    console.log(`🎯 Received preferences.filters:`, preferences?.filters);
    console.log(`🧠 SESSION DEBUG at start of /api/message:`, {
        sessionExists: !!req.session,
        sessionId: req.session?.id,
        sessionEmail: req.session?.email,
        recommendedRestaurants: req.session?.recommendedRestaurants || [],
        recommendedCount: req.session?.recommendedRestaurants?.length || 0
    });
    if (!userInput) {
        return res.status(400).json({ message: 'Message is required.' });
    }
    
    try {
        console.log(`💬 Chat message request: "${userInput}"`);
        console.log(`💬 Session ID:`, req.session?.id);
        console.log(`💬 Session email:`, req.session?.email);
        console.log(`💬 Frontend location data:`, location);
        
        // Debug location data
        console.log(`💬 Active location sessions:`, global.locationSessions?.size || 0);
        if (global.locationSessions && global.locationSessions.size > 0) {
            for (const [sessionId, sessionData] of global.locationSessions.entries()) {
                const age = (Date.now() - sessionData.createdAt) / (1000 * 60);
                console.log(`💬 Session ${sessionId}: ${age.toFixed(1)}min old, has location: ${!!sessionData.location}`);
            }
        }
        
        // Enhanced input analysis to determine response type
        const inputAnalysis = analyzeUserInput(userInput);
        console.log(`🧠 Input Analysis:`, inputAnalysis);
        
        // Check for "Generate another" request using the flag instead of text detection
        const isGenerateAnother = generateAnother || false;
        console.log(`🔍 Generate Another check: flag=${generateAnother} → isGenerateAnother: ${isGenerateAnother}`);
        
        // Decide response type based on analysis
        if (!inputAnalysis.needsRecommendation) {
            // Handle non-food requests with normal AI response
            console.log(`💬 Non-food request detected - using normal AI response`);
            
            const completion = await openai.chat.completions.create({
                model: "gpt-3.5-turbo",
                messages: [
                    {
                        role: "system",
                        content: "You are Foodle, a friendly food recommendation assistant. Help users with food-related questions and conversations. Be conversational, helpful, and enthusiastic about food!"
                    },
                    {
                        role: "user",
                        content: userInput
                    }
                ],
                max_tokens: 400,
                temperature: 0.7
            });
            
            const aiResponse = completion.choices[0].message.content;
            console.log(`💬 AI Response generated: ${aiResponse.substring(0, 100)}...`);
            
            return res.status(200).json({ 
                aiResponse: aiResponse,
                type: "message"
            });
        }
        
        // Handle restaurant recommendation requests
        console.log(`🤖 Restaurant request detected: "${userInput}"`);
        console.log(`🔄 Is this a regeneration request? ${isGenerateAnother}`);
        console.log(`🍽️ Has cuisine specified: ${inputAnalysis.hasCuisineSpecified}`);
        console.log(`🎯 Should use preferred cuisine: ${inputAnalysis.shouldUsePreferredCuisine}`);
        
        // Initialize session arrays if they don't exist
        if (!req.session.recommendedRestaurants) {
            req.session.recommendedRestaurants = [];
            console.log(`📝 Initialized session recommendedRestaurants array`);
        }
        
        // Handle "Generate Another" - remove last recommendation from memory
        if (isGenerateAnother) {
            console.log(`🔄 "Generate Another" detected - removing last recommendation from session memory`);
            console.log(`🔄 Session recommendations before removal:`, req.session.recommendedRestaurants);
            
            // Remove the last recommended restaurant from session memory to avoid repeating it
            if (req.session.recommendedRestaurants && req.session.recommendedRestaurants.length > 0) {
                const lastRecommended = req.session.recommendedRestaurants.pop();
                const lastRecommendedInfo = typeof lastRecommended === 'string' ? 
                    `PlaceID: ${lastRecommended}` : 
                    `${lastRecommended.name} (${lastRecommended.placeId})`;
                console.log(`🗑️ Removed last recommended restaurant from session: ${lastRecommendedInfo}`);
                console.log(`🗑️ Remaining recommended restaurants in session: ${req.session.recommendedRestaurants.length}`);
            }
        }
        
        try {
            console.log(`💬 Processing restaurant recommendation with enhanced input analysis...`);
            
            // Pass input analysis to the recommendation function
            const recommendationResult = await getRestaurantRecommendation({
                message: userInput,
                preferences: preferences || {}, // ✅ Use actual preferences from frontend
                location: location,
                session: req.session,
                generateAnother: generateAnother,
                inputAnalysis: inputAnalysis // Pass the analysis for smarter AI prompting
            });
                
                if (recommendationResult.success && recommendationResult.data.restaurant) {
                    console.log(`💬 Enhanced restaurant recommendation received: ${recommendationResult.data.restaurant.name}`);
                    
                    // CRITICAL: Ensure session persistence after restaurant recommendation
                    if (req.session) {
                        console.log(`🧠 Ensuring session memory is saved for /api/message endpoint`);
                        console.log(`🧠 Session recommendations before save: ${req.session.recommendedRestaurants?.length || 0}`);
                        
                        req.session.save((err) => {
                            if (err) {
                                console.error('❌ Session save error in /api/message:', err);
                            } else {
                                console.log('✅ Session saved successfully in /api/message endpoint');
                                console.log(`🧠 Session recommendations after save: ${req.session.recommendedRestaurants?.length || 0}`);
                            }
                        });
                    }
                    
                    return res.status(200).json(recommendationResult.data);
                } else {
                    console.error('❌ Enhanced restaurant recommendation failed:', recommendationResult.error);
                    return res.status(200).json({ 
                        aiResponse: recommendationResult.error || "I couldn't find any restaurants matching your preferences right now.",
                        type: "message"
                    });
                }
            } catch (error) {
                console.error('❌ Error in enhanced restaurant recommendation:', error);
                return res.status(200).json({ 
                    aiResponse: "I'm having trouble finding restaurants right now. Please try again later!",
                    type: "message"
                });
            }
        
    } catch (err) {
        console.error('💬 Chat API error:', err);
        res.status(500).json({ 
            aiResponse: "I'm having trouble connecting right now. Please try again later!",
            type: "message"
        });
    }
});

// Nearby Restaurants endpoint
app.post('/api/nearby-restaurants', async (req, res) => {
    const { latitude, longitude, accuracy, isGeocoded, locationSource, accuracyCategory } = req.body;
    if (!latitude || !longitude) {
        return res.status(400).json({ message: 'Latitude and longitude are required.' });
    }

    console.log('=== RESTAURANT SEARCH REQUEST ===');
    console.log(`Coordinates: ${latitude}, ${longitude}`);
    console.log(`Accuracy: ${accuracy ? accuracy + ' meters' : 'unknown'}`);
    console.log(`Source: ${locationSource || 'unknown'}`);
    console.log(`Category: ${accuracyCategory || 'unknown'}`);
    console.log(`Geocoded: ${isGeocoded ? 'Yes' : 'No'}`);

    const apiKey = process.env.GOOGLE_PLACES_API_KEY;
    if (!apiKey) {
        console.error('❌ Google Places API key is missing in nearby-restaurants endpoint');
        return res.status(500).json({ 
            message: 'Server configuration error: Google Places API key is missing.',
            debug: 'Check your .env file contains: GOOGLE_PLACES_API_KEY=your_api_key_here'
        });
    }
    
    // Intelligent radius selection based on accuracy and source - LIMITED TO 2KM MAX
    let radius = 1000; // default 1km
    let searchStrategy = 'standard';
    
    if (isGeocoded) {
        // High confidence in geocoded addresses
        radius = 2000;
        searchStrategy = 'geocoded';
        console.log('Using geocoded search strategy with 2km radius');
    } else if (accuracy) {
        if (accuracy <= 100) {
            // Excellent GPS accuracy
            radius = 500;
            searchStrategy = 'precise';
            console.log('Excellent accuracy detected - using precise 500m search');
        } else if (accuracy <= 500) {
            // Good GPS accuracy
            radius = 1000;
            searchStrategy = 'standard';
            console.log('Good accuracy detected - using standard 1km search');
        } else {
            // Any moderate to poor accuracy - limit to 2km maximum
            radius = 2000;
            searchStrategy = 'max-radius';
            console.log('Moderate to poor accuracy detected - using maximum 2km search');
        }
    }

    // Force maximum 2km radius regardless of location source
    radius = Math.min(radius, 2000);
    
    if (locationSource === 'ip-based') {
        radius = 2000; // Still limit IP-based to 2km
        searchStrategy = 'ip-based-limited';
        console.log('IP-based location - using 2km search (limited)');
    }

    const type = 'restaurant';
    let allResults = [];
    let pagetoken = '';
    let url = `https://maps.googleapis.com/maps/api/place/nearbysearch/json?location=${latitude},${longitude}&radius=${radius}&type=${type}&key=${apiKey}`;

    try {
        // Get ALL available pages of results for complete coverage
        const maxPages = 5; // Always fetch 5 pages for maximum restaurant coverage (up to 100 restaurants)
        
        for (let i = 0; i < maxPages; i++) {
            console.log(`Fetching page ${i + 1}/${maxPages} from Google Places API...`);
            
            const response = await axios.get(url);
            
            if (response.data.status === 'OK' && response.data.results) {
                allResults = allResults.concat(response.data.results);
                console.log(`Page ${i + 1}: Found ${response.data.results.length} restaurants`);
            } else if (response.data.status === 'ZERO_RESULTS') {
                console.log(`Page ${i + 1}: No results found`);
                break;
            } else {
                console.warn(`Page ${i + 1}: API returned status ${response.data.status}`);
            }
            
            if (response.data.next_page_token) {
                pagetoken = response.data.next_page_token;
                // Google requires a short delay before the next_page_token becomes active
                await new Promise(resolve => setTimeout(resolve, 2000));
                url = `https://maps.googleapis.com/maps/api/place/nearbysearch/json?pagetoken=${pagetoken}&key=${apiKey}`;
            } else {
                break;
            }
        }
        
        // Process and enhance results with detailed restaurant info
        console.log('🔍 Fetching detailed restaurant information...');
        const results = [];
        
        for (const place of allResults) {
            const distance = calculateDistance(
                latitude, longitude,
                place.geometry.location.lat, place.geometry.location.lng
            );
            
            // Get detailed restaurant info including photos, review count, and descriptions
            let detailedInfo = {};
            try {
                const detailsResponse = await axios.get(
                    `https://maps.googleapis.com/maps/api/place/details/json?place_id=${place.place_id}&fields=name,rating,user_ratings_total,price_level,photos,formatted_address,types,editorial_summary&key=${apiKey}`
                );
                
                if (detailsResponse.data.status === 'OK' && detailsResponse.data.result) {
                    detailedInfo = detailsResponse.data.result;
                }
            } catch (error) {
                console.warn(`Failed to fetch details for place ${place.place_id}:`, error.message);
            }
            
            const restaurant = {
                name: place.name,
                address: detailedInfo.formatted_address || place.vicinity,
                cuisineType: determineCuisineType(detailedInfo.types || place.types || []),
                diningType: determineDiningType(detailedInfo.types || place.types || []),
                rating: place.rating || detailedInfo.rating || 'N/A',
                reviewCount: detailedInfo.user_ratings_total || 0,
                priceLevel: (() => {
                    const placePriceLevel = place.price_level;
                    const detailedPriceLevel = detailedInfo.price_level;
                    const finalPriceLevel = detailedPriceLevel !== undefined ? detailedPriceLevel : placePriceLevel;
                    
                    console.log(`💰 Price level debug for ${place.name}:`, {
                        placePriceLevel,
                        detailedPriceLevel,
                        finalPriceLevel,
                        types: ['placePriceLevel', typeof placePriceLevel, 'detailedPriceLevel', typeof detailedPriceLevel]
                    });
                    
                    return finalPriceLevel; // Keep raw numeric value
                })(),
                price_level: (() => {
                    const placePriceLevel = place.price_level;
                    const detailedPriceLevel = detailedInfo.price_level;
                    return detailedPriceLevel !== undefined ? detailedPriceLevel : placePriceLevel;
                })(), // Add backup field for consistency
                location: place.geometry.location,
                latitude: place.geometry.location.lat,
                longitude: place.geometry.location.lng,
                placeId: place.place_id,
                types: detailedInfo.types || place.types || [],
                editorial_summary: detailedInfo.editorial_summary || null, // Add description for AI
                distance: Math.round(distance * 100) / 100, // Round to 2 decimal places
                distanceText: distance < 1 ? 
                    `${Math.round(distance * 1000)}m` : 
                    `${Math.round(distance * 10) / 10}km`,
                photos: processRestaurantPhotos(detailedInfo.photos, apiKey).map(photo => photo.url)
            };
            
            results.push(restaurant);
        }
        
        // Sort by distance (closest first)
        results.sort((a, b) => a.distance - b.distance);
        
        // Limit results based on search strategy
        let maxResults = 20;
        if (searchStrategy === 'precise') maxResults = 15;
        else if (searchStrategy === 'wide' || searchStrategy === 'very-wide') maxResults = 30;
        
        const limitedResults = results.slice(0, maxResults);
        
        // Get walking times for all restaurants using batch processing
        console.log('🚶 Fetching walking times for restaurants...');
        const walkingTimes = await getBatchWalkingTimes(latitude, longitude, limitedResults, apiKey);
        
        // Add walking time data to results
        const resultsWithWalkingTime = limitedResults.map(restaurant => {
            const walkingData = walkingTimes.get(restaurant.placeId);
            
            return {
                ...restaurant,
                walkingTime: walkingData ? walkingData.duration : 'N/A',
                walkingTimeValue: walkingData ? walkingData.durationValue : null,
                walkingDistance: walkingData ? walkingData.distance : 'N/A',
                walkingDistanceValue: walkingData ? walkingData.distanceValue : null
            };
        });
        
        // 🚨 ENFORCE 2KM LIMIT: Filter out any restaurants beyond 2km
        const restaurantsWithin2km = resultsWithWalkingTime.filter(restaurant => {
            const isWithin2km = restaurant.distance <= 2.0; // 2km in decimal
            if (!isWithin2km) {
                console.log(`🚫 Filtering out ${restaurant.name} - ${restaurant.distance.toFixed(2)}km exceeds 2km limit`);
            }
            return isWithin2km;
        });
        
        console.log(`🔍 Before 2km filter: ${resultsWithWalkingTime.length} restaurants`);
        console.log(`✅ After 2km filter: ${restaurantsWithin2km.length} restaurants`);
        
        // Sort by walking time (fastest first) if available, otherwise by distance
        restaurantsWithin2km.sort((a, b) => {
            if (a.walkingTimeValue && b.walkingTimeValue) {
                return a.walkingTimeValue - b.walkingTimeValue;
            }
            return a.distance - b.distance;
        });
        
        console.log(`=== SEARCH RESULTS ===`);
        console.log(`Total found: ${allResults.length}`);
        console.log(`After processing: ${results.length}`);
        console.log(`Returned to client: ${resultsWithWalkingTime.length}`);
        console.log(`Search radius: ${radius}m (${radius/1000}km)`);
        
        // Quick stats
        const restaurantsOver2km = restaurantsWithin2km.filter(r => r.distance > 2);
        if (restaurantsOver2km.length > 0) {
            console.log(`⚠️ WARNING: ${restaurantsOver2km.length} restaurants exceed 2km radius`);
        } else {
            console.log(`✅ All ${restaurantsWithin2km.length} restaurants are within 2km radius`);
        }
        
        console.log(`Closest: ${restaurantsWithin2km[0]?.name || 'None'} (${restaurantsWithin2km[0]?.distanceText || 'N/A'})`);
        console.log(`Furthest: ${restaurantsWithin2km[restaurantsWithin2km.length - 1]?.name || 'None'} (${restaurantsWithin2km[restaurantsWithin2km.length - 1]?.distanceText || 'N/A'})`);
        console.log(`======================`);
        
        res.json({ 
            restaurants: restaurantsWithin2km,
            searchInfo: {
                radius: radius,
                strategy: searchStrategy,
                accuracy: accuracy,
                totalFound: allResults.length,
                returned: restaurantsWithin2km.length,
                walkingTimesIncluded: true
            }
        });
    } catch (error) {
        console.error('Google Places API error:', error.message);
        console.error('Error details:', error.response?.data || error);
        res.status(500).json({ message: 'Failed to fetch restaurants. Please try again.' });
    }
});

// --- User Profile API ---

// Get user profile
app.get('/api/user/profile', async (req, res) => {
    try {
        // Check authentication
        if (!req.session || !req.session.email) {
            return res.status(401).json({ message: 'Not authenticated.' });
        }
        // Find user by session email
        const user = await User.findOne({ email: req.session.email });
        if (!user) {
            return res.status(404).json({ message: 'User not found.' });
        }
        // Respond with user profile data
        res.json({
            _id: user._id, // Include MongoDB ObjectId for room joining
            firstName: user.firstName,
            lastName: user.lastName,
            email: user.email,
            profileImageUrl: user.profileImageUrl || null,
            country: user.country || null,
            preferences: {
                cuisines: user.preferences?.cuisines ?? [],
                priceRange: user.preferences?.priceRange ?? "$$",
                dietType: user.preferences?.dietType ?? "No restrictions",
                allergies: user.preferences?.allergies ?? []
            },
            lastKnownLocation: user.lastKnownLocation || null,
            previousMeals: user.previousMeals || [],
            savedRecommendations: user.savedRecommendations || [], // Keep for compatibility
            createdAt: user.createdAt
        });
    } catch (err) {
        console.error('GET /api/user/profile error:', err);
        res.status(500).json({ message: 'Server error.' });
    }
});

// Update user profile
app.patch('/api/user/profile', async (req, res) => {
    try {
        console.log('🔧 PATCH /api/user/profile request received');
        console.log('📋 Request body:', req.body);
        console.log('👤 Session:', req.session?.email || 'No session');
        
        if (!req.session || !req.session.email) {
            console.log('❌ No authentication session found');
            return res.status(401).json({ message: 'Not authenticated.' });
        }
        
        const user = await User.findOne({ email: req.session.email });
        if (!user) {
            console.log('❌ User not found for email:', req.session.email);
            return res.status(404).json({ message: 'User not found.' });
        }

        console.log('✅ User found:', user.email);

        // Only update fields present in the request body
        const { firstName, lastName, email, country, preferences } = req.body;
        let updated = false;
        
        if (firstName !== undefined) {
            user.firstName = firstName;
            updated = true;
            console.log('📝 Updated firstName:', firstName);
        }
        if (lastName !== undefined) {
            user.lastName = lastName;
            updated = true;
            console.log('📝 Updated lastName:', lastName);
        }
        if (email !== undefined) {
            user.email = email;
            updated = true;
            console.log('📝 Updated email:', email);
        }
        if (country !== undefined) {
            user.country = country;
            updated = true;
            console.log('📝 Updated country:', country);
        }
        if (preferences !== undefined) {
            if (!user.preferences) user.preferences = {};
            if (preferences.cuisines !== undefined) {
                user.preferences.cuisines = preferences.cuisines;
                console.log('📝 Updated cuisines:', preferences.cuisines);
                updated = true;
            }
            if (preferences.priceRange !== undefined) {
                user.preferences.priceRange = preferences.priceRange;
                console.log('📝 Updated priceRange:', preferences.priceRange);
                updated = true;
            }
            if (preferences.dietType !== undefined) {
                user.preferences.dietType = preferences.dietType;
                console.log('📝 Updated dietType:', preferences.dietType);
                updated = true;
            }
            if (preferences.allergies !== undefined) {
                user.preferences.allergies = preferences.allergies;
                console.log('📝 Updated allergies:', preferences.allergies);
                updated = true;
            }
        }

        if (updated) {
            await user.save();
            console.log('💾 User profile saved successfully');
            
            // Update session email if it was changed
            if (email !== undefined) {
                req.session.email = email;
                console.log('🔄 Session email updated to:', email);
            }
            
            res.json({ 
                message: 'Profile updated successfully.',
                user: {
                    firstName: user.firstName,
                    lastName: user.lastName,
                    email: user.email,
                    country: user.country,
                    preferences: user.preferences
                }
            });
        } else {
            console.log('⚠️ No changes detected');
            res.json({ message: 'No changes to save.' });
        }
        
    } catch (err) {
        console.error('❌ PATCH /api/user/profile error:', err);
        res.status(500).json({ 
            message: 'Server error while updating profile.', 
            error: err.message 
        });
    }
});

// Dedicated preferences update endpoint
app.patch('/api/user/preferences', async (req, res) => {
    try {
        console.log('🎯 PATCH /api/user/preferences request received');
        console.log('📋 Request body:', req.body);
        console.log('👤 Session:', req.session?.email || 'No session');
        
        if (!req.session || !req.session.email) {
            console.log('❌ No authentication session found');
            return res.status(401).json({ message: 'Not authenticated.' });
        }
        
        const user = await User.findOne({ email: req.session.email });
        if (!user) {
            console.log('❌ User not found for email:', req.session.email);
            return res.status(404).json({ message: 'User not found.' });
        }

        console.log('✅ User found:', user.email);

        // Initialize preferences if they don't exist
        if (!user.preferences) {
            user.preferences = {};
        }

        // Update preferences
        const { cuisines, priceRange, dietType, allergies } = req.body;
        let updated = false;
        
        if (cuisines !== undefined) {
            user.preferences.cuisines = cuisines;
            console.log('📝 Updated cuisines:', cuisines);
            updated = true;
        }
        if (priceRange !== undefined) {
            user.preferences.priceRange = priceRange;
            console.log('📝 Updated priceRange:', priceRange);
            updated = true;
        }
        if (dietType !== undefined) {
            user.preferences.dietType = dietType;
            console.log('📝 Updated dietType:', dietType);
            updated = true;
        }
        if (allergies !== undefined) {
            user.preferences.allergies = allergies;
            console.log('📝 Updated allergies:', allergies);
            updated = true;
        }

        if (updated) {
            await user.save();
            console.log('💾 User preferences saved successfully');
            
            res.json({ 
                message: 'Preferences updated successfully.',
                preferences: user.preferences
            });
        } else {
            console.log('⚠️ No preference changes detected');
            res.json({ 
                message: 'No changes to save.',
                preferences: user.preferences
            });
        }
        
    } catch (err) {
        console.error('❌ PATCH /api/user/preferences error:', err);
        res.status(500).json({ 
            message: 'Server error while updating preferences.', 
            error: err.message 
        });
    }
});

// Save recommendation to user previous meals endpoint
app.post('/api/save-recommendation', async (req, res) => {
    try {
        console.log('💾 POST /api/save-recommendation request received');
        console.log('📋 Request body:', req.body);
        console.log('👤 Session:', req.session?.email || 'No session');
        
        if (!req.session || !req.session.email) {
            console.log('❌ No authentication session found');
            return res.status(401).json({ message: 'Not authenticated.' });
        }
        
        const user = await User.findOne({ email: req.session.email });
        if (!user) {
            console.log('❌ User not found for email:', req.session.email);
            return res.status(404).json({ message: 'User not found.' });
        }

        console.log('✅ User found:', user.email);

        const { 
            recommendationText, 
            restaurantName, 
            restaurantId, 
            userQuery, 
            filters,
            restaurant
        } = req.body;

        // ENHANCED DEBUG: Log all request body fields
        console.log('🔍 DETAILED REQUEST BODY ANALYSIS:');
        console.log('📝 recommendationText type:', typeof recommendationText);
        console.log('📝 recommendationText value:', recommendationText);
        console.log('📝 recommendationText length:', recommendationText?.length || 'undefined');
        console.log('📝 restaurantName:', restaurantName);
        console.log('📝 restaurantId:', restaurantId);
        console.log('📝 userQuery:', userQuery);
        console.log('📝 filters:', filters);
        console.log('📝 restaurant data received:', restaurant);
        console.log('📝 restaurant data type:', typeof restaurant);
        console.log('📝 restaurant data keys:', restaurant ? Object.keys(restaurant) : 'No restaurant data');
        console.log('📝 Raw request body keys:', Object.keys(req.body));
        console.log('📝 Raw request body:', JSON.stringify(req.body, null, 2));

        // Validate required fields
        if (!recommendationText || recommendationText.trim() === '') {
            console.log('❌ Missing recommendation text:', recommendationText);
            console.log('❌ Request body for debugging:', JSON.stringify(req.body, null, 2));
            return res.status(400).json({ message: 'Recommendation text is required.' });
        }

        // Clean the recommendation text by removing "Generate Another" and "Confirm Choice" button references
        let cleanedText = recommendationText.trim();
        
        console.log('🧹 Original recommendation text:', cleanedText.substring(0, 200) + '...');
        
        // Remove common button-related text that might be included
        const buttonsToRemove = [
            /Generate Another/gi,
            /Confirm Choice/gi,
            /\s*\|\s*Generate Another\s*/gi,
            /\s*\|\s*Confirm Choice\s*/gi
        ];
        
        buttonsToRemove.forEach(pattern => {
            cleanedText = cleanedText.replace(pattern, '');
        });
        
        // Clean up any double spaces or trailing periods/commas
        cleanedText = cleanedText.replace(/\s+/g, ' ').trim();
        cleanedText = cleanedText.replace(/[,\.\s]+$/, ''); // Remove trailing punctuation and spaces
        
        console.log('🧹 Cleaned recommendation text:', cleanedText.substring(0, 200) + '...');
        console.log('🧹 Text cleaning stats:', {
            originalLength: recommendationText.length,
            cleanedLength: cleanedText.length,
            removed: recommendationText.length - cleanedText.length
        });

        // Create recommendation object for previous meals
        const previousMeal = {
            recommendationText: cleanedText,
            restaurantName: restaurantName || 'Unknown Restaurant',
            restaurantId: restaurantId || null,
            userQuery: userQuery || 'No query provided',
            timestamp: new Date(),
            filters: filters || {},
            restaurant: restaurant || null // Store complete restaurant data for display
        };

        console.log('📝 Saving to previous meals:', {
            restaurantName: previousMeal.restaurantName,
            userQuery: previousMeal.userQuery,
            timestamp: previousMeal.timestamp,
            textLength: cleanedText.length,
            hasRestaurantData: !!previousMeal.restaurant,
            restaurantDataKeys: previousMeal.restaurant ? Object.keys(previousMeal.restaurant) : 'No restaurant data'
        });

        console.log('🏪 Complete restaurant object being saved:', JSON.stringify(previousMeal.restaurant, null, 2));

        // Initialize previousMeals array if it doesn't exist
        if (!user.previousMeals) {
            user.previousMeals = [];
        }

        // Add meal to user's previous meals
        user.previousMeals.push(previousMeal);

        // Save user document
        await user.save();
        
        console.log('💾 ✅ Previous meal saved successfully');
        console.log(`📊 User now has ${user.previousMeals.length} previous meals`);
        
        res.json({ 
            message: 'Previous meal saved successfully.',
            totalSaved: user.previousMeals.length,
            savedMeal: {
                restaurantName: previousMeal.restaurantName,
                timestamp: previousMeal.timestamp
            }
        });
        
    } catch (err) {
        console.error('❌ POST /api/save-recommendation error:', err);
        res.status(500).json({ 
            message: 'Server error while saving previous meal.', 
            error: err.message 
        });
    }
});

// Remove previous meal endpoint
app.delete('/api/remove-previous-meal/:index', async (req, res) => {
    try {
        console.log('🗑️ DELETE /api/remove-previous-meal request received');
        console.log('📋 Meal index:', req.params.index);
        console.log('👤 Session:', req.session?.email || 'No session');
        
        if (!req.session || !req.session.email) {
            console.log('❌ No authentication session found');
            return res.status(401).json({ message: 'Not authenticated.' });
        }
        
        const user = await User.findOne({ email: req.session.email });
        if (!user) {
            console.log('❌ User not found for email:', req.session.email);
            return res.status(404).json({ message: 'User not found.' });
        }

        console.log('✅ User found:', user.email);

        const mealIndex = parseInt(req.params.index);
        
        // Validate index
        if (isNaN(mealIndex) || mealIndex < 0 || mealIndex >= (user.previousMeals?.length || 0)) {
            console.log('❌ Invalid meal index:', mealIndex);
            return res.status(400).json({ message: 'Invalid meal index.' });
        }

        // Initialize previousMeals array if it doesn't exist
        if (!user.previousMeals) {
            user.previousMeals = [];
        }

        // Remove the meal at the specified index
        const removedMeal = user.previousMeals.splice(mealIndex, 1)[0];

        // Save user document
        await user.save();
        
        console.log('🗑️ ✅ Previous meal removed successfully');
        console.log(`📊 User now has ${user.previousMeals.length} previous meals`);
        
        res.json({ 
            message: 'Previous meal removed successfully.',
            totalRemaining: user.previousMeals.length,
            removedMeal: {
                restaurantName: removedMeal.restaurantName,
                timestamp: removedMeal.timestamp
            }
        });
        
    } catch (err) {
        console.error('❌ DELETE /api/remove-previous-meal error:', err);
        res.status(500).json({ 
            message: 'Server error while removing previous meal.', 
            error: err.message 
        });
    }
});

// Update user location endpoint (called from socket handler)
app.post('/api/update-user-location', async (req, res) => {
    try {
        const { latitude, longitude, accuracy, source } = req.body;
        
        console.log('📍 Location update request:', { latitude, longitude, accuracy, source });
        
        if (!latitude || !longitude) {
            return res.status(400).json({ message: 'Latitude and longitude are required.' });
        }

        let user = null;
        
        // Try to find user by session (authenticated users)
        if (req.session && req.session.email) {
            user = await User.findOne({ email: req.session.email });
            console.log('📍 Updating location for authenticated user:', req.session.email);
        }
        
        // If no authenticated user, we can't update location in database
        if (!user) {
            console.log('📍 No authenticated user found - skipping database update');
            return res.json({ 
                message: 'No authenticated user - location not stored in database',
                updated: false
            });
        }
        
        // Update user's last known location
        user.lastKnownLocation = {
            latitude: latitude,
            longitude: longitude,
            accuracy: accuracy || null,
            timestamp: new Date(),
            source: source || 'unknown'
        };
        
        await user.save();
        
        console.log(`📍 Location updated for ${user.email}:`, {
            lat: latitude,
            lng: longitude,
            accuracy: accuracy,
            source: source
        });
        
        res.json({ 
            message: 'Location updated successfully',
            updated: true,
            location: user.lastKnownLocation
        });
        
    } catch (err) {
        console.error('Location update error:', err);
        res.status(500).json({ message: 'Server error during location update.' });
    }
});

// Walking time API endpoint
app.post('/api/walking-time', async (req, res) => {
    try {
        const { origin, destination, restaurantName } = req.body;
        
        console.log('🚶 Walking time request for:', restaurantName);
        console.log('🚶 Origin:', origin);
        console.log('🚶 Destination:', destination);
        
        if (!origin || !destination || !origin.latitude || !origin.longitude || !destination.lat || !destination.lng) {
            return res.status(400).json({ 
                message: 'Origin and destination coordinates are required',
                received: { origin, destination }
            });
        }

        const apiKey = process.env.GOOGLE_PLACES_API_KEY;
        if (!apiKey) {
            return res.status(500).json({ message: 'Google Places API key not configured' });
        }

        // Get walking time using existing function
        const walkingData = await getWalkingTime(
            origin.latitude,
            origin.longitude, 
            destination.lat,
            destination.lng,
            apiKey
        );

        if (walkingData) {
            console.log(`✅ Walking time calculated for ${restaurantName}: ${walkingData.duration}`);
            res.json({ 
                walkingTime: walkingData.duration,
                walkingTimeValue: walkingData.durationValue,
                distance: walkingData.distance,
                distanceValue: walkingData.distanceValue,
                restaurantName: restaurantName
            });
        } else {
            console.log(`⚠️ No walking route found for ${restaurantName}`);
            res.json({ 
                walkingTime: 'N/A',
                message: 'No walking route found',
                restaurantName: restaurantName
            });
        }

    } catch (error) {
        console.error('❌ Walking time API error:', error);
        res.status(500).json({ 
            message: 'Error calculating walking time', 
            error: error.message 
        });
    }
});

// === WALKING DIRECTIONS FUNCTIONALITY ===

// Function to get walking time from Google Directions API
async function getWalkingTime(originLat, originLng, destLat, destLng, apiKey) {
    try {
        const url = `https://maps.googleapis.com/maps/api/directions/json?` +
            `origin=${originLat},${originLng}&` +
            `destination=${destLat},${destLng}&` +
            `mode=walking&` +
            `units=metric&` +
            `key=${apiKey}`;
        
        const response = await axios.get(url);
        
        if (response.data.status === 'OK' && response.data.routes.length > 0) {
            const route = response.data.routes[0];
            const leg = route.legs[0];
            
            return {
                duration: leg.duration.text,
                durationValue: leg.duration.value, // in seconds
                distance: leg.distance.text,
                distanceValue: leg.distance.value, // in meters
                steps: leg.steps.map(step => ({
                    instruction: step.html_instructions.replace(/<[^>]*>/g, ''), // Remove HTML tags
                    distance: step.distance.text,
                    duration: step.duration.text
                }))
            };
        } else {
            console.warn('No walking route found or API error:', response.data.status);
            return null;
        }
    } catch (error) {
        console.error('Google Directions API error:', error.message);
        return null;
    }
}

// Function to get walking times for multiple destinations (batch processing)
async function getBatchWalkingTimes(originLat, originLng, restaurants, apiKey) {
    console.log(`🚶 📍 BATCH WALKING TIMES FROM USER LOCATION: (${originLat}, ${originLng})`);
    const BATCH_SIZE = 10; // Google allows up to 25 waypoints, but we'll be conservative
    const results = new Map();
    
    // Process restaurants in batches to avoid API limits
    for (let i = 0; i < restaurants.length; i += BATCH_SIZE) {
        const batch = restaurants.slice(i, i + BATCH_SIZE);
        
        // Create destinations string for batch request
        const destinations = batch.map(r => `${r.location.lat},${r.location.lng}`).join('|');
        
        try {
            const url = `https://maps.googleapis.com/maps/api/distancematrix/json?` +
                `origins=${originLat},${originLng}&` +
                `destinations=${destinations}&` +
                `mode=walking&` +
                `units=metric&` +
                `key=${apiKey}`;
            
            const response = await axios.get(url);
            
            if (response.data.status === 'OK') {
                const elements = response.data.rows[0].elements;
                
                for (let j = 0; j < batch.length; j++) {
                    const element = elements[j];
                    const restaurant = batch[j];
                    
                    if (element.status === 'OK') {
                        results.set(restaurant.placeId, {
                            duration: element.duration.text,
                            durationValue: element.duration.value,
                            distance: element.distance.text,
                            distanceValue: element.distance.value
                        });
                    } else {
                        console.warn(`No walking route found for ${restaurant.name}:`, element.status);
                        results.set(restaurant.placeId, null);
                    }
                }
            } else {
                console.warn('Distance Matrix API error:', response.data.status);
                // Set all restaurants in this batch to null
                batch.forEach(r => results.set(r.placeId, null));
            }
            
            // Add delay between batches to respect rate limits
            if (i + BATCH_SIZE < restaurants.length) {
                await new Promise(resolve => setTimeout(resolve, 100));
            }
        } catch (error) {
            console.error('Distance Matrix API error:', error.message);
            // Set all restaurants in this batch to null
            batch.forEach(r => results.set(r.placeId, null));
        }
    }
    
    return results;
}

// Search endpoint with walking time
app.post('/api/search-restaurants', async (req, res) => {
    const { query, latitude, longitude, accuracy } = req.body;
    
    if (!query || !latitude || !longitude) {
        return res.status(400).json({ message: 'Query, latitude, and longitude are required.' });
    }
    
    console.log(`Searching for "${query}" near ${latitude}, ${longitude} with accuracy ${accuracy}m`);
    
    // Step 1: Find nearby restaurants using Google Places API
    const placesApiKey = process.env.GOOGLE_PLACES_API_KEY;
    if (!placesApiKey) {
        console.error('❌ Google Places API key is missing in search-restaurants endpoint');
        return res.status(500).json({ 
            message: 'Server configuration error: Google Places API key is missing.',
            debug: 'Check your .env file contains: GOOGLE_PLACES_API_KEY=your_api_key_here'
        });
    }
    
    const nearbyResults = await findNearbyRestaurants(latitude, longitude, accuracy || 2000, placesApiKey);
    
    if (!nearbyResults || nearbyResults.length === 0) {
        return res.status(404).json({ message: 'No restaurants found nearby.' });
    }
    
    console.log(`Found ${nearbyResults.length} nearby restaurants. Calculating walking times...`);
    
    // Step 2: Get walking times to each restaurant
    const walkingTimes = await getBatchWalkingTimes(latitude, longitude, nearbyResults, placesApiKey);
    
    // Enrich restaurant data with walking times
    const enrichedResults = nearbyResults.map(restaurant => {
        const walkingTime = walkingTimes.get(restaurant.placeId);
        return {
            ...restaurant,
            walkingTime: walkingTime ? walkingTime.duration : 'N/A',
            walkingTimeValue: walkingTime ? walkingTime.durationValue : null,
            walkingDistance: walkingTime ? walkingTime.distance : 'N/A',
            walkingDistanceValue: walkingTime ? walkingTime.distanceValue : null
        };
    });
    
    // Sort by walking time (fastest first) if available, otherwise by distance
    enrichedResults.sort((a, b) => {
        if (a.walkingTimeValue && b.walkingTimeValue) {
            return a.walkingTimeValue - b.walkingTimeValue;
        }
        return a.distance - b.distance;
    });
    
    // Limit to top 10 results
    const topResults = enrichedResults.slice(0, 10);
    
    res.json({ 
        restaurants: topResults,
        totalFound: enrichedResults.length
    });
});

// Helper function to find nearby restaurants using Google Places API
async function findNearbyRestaurants(latitude, longitude, radiusOrAccuracy, apiKey) {
    console.log(`🔍 Searching for restaurants near ${latitude}, ${longitude} with radius ${radiusOrAccuracy}m`);
    
    if (!apiKey) {
        console.error('❌ Google Places API key is missing');
        return [];
    }
    
    const radius = Math.min(Math.max(radiusOrAccuracy, 500), 50000); // INCREASED: Clamp radius between 500m and 50km for much better coverage
    let allResults = [];
    
    try {
        // ULTRA-COMPREHENSIVE APPROACH: Maximum possible search coverage for finding ALL restaurants
        const searchConfigs = [
            // PRIMARY TYPES - Core restaurant searches
            { type: 'restaurant', keyword: '' },
            { type: 'food', keyword: '' },
            { type: 'meal_takeaway', keyword: '' },
            { type: 'meal_delivery', keyword: '' },
            { type: 'bakery', keyword: '' },
            { type: 'cafe', keyword: '' },
            { type: 'bar', keyword: '' },
            { type: 'night_club', keyword: '' },
            
            // GENERAL ESTABLISHMENT SEARCHES - Cast widest net
            { type: 'establishment', keyword: 'restaurant' },
            { type: 'establishment', keyword: 'food' },
            { type: 'establishment', keyword: 'dining' },
            { type: 'establishment', keyword: 'eatery' },
            { type: 'establishment', keyword: 'bistro' },
            { type: 'establishment', keyword: 'grill' },
            { type: 'establishment', keyword: 'kitchen' },
            { type: 'establishment', keyword: 'diner' },
            
            // CUISINE-SPECIFIC SEARCHES - Major cuisines
            { type: 'establishment', keyword: 'pizza' },
            { type: 'establishment', keyword: 'sushi' },
            { type: 'establishment', keyword: 'chinese' },
            { type: 'establishment', keyword: 'mexican' },
            { type: 'establishment', keyword: 'italian' },
            { type: 'establishment', keyword: 'burger' },
            { type: 'establishment', keyword: 'thai' },
            { type: 'establishment', keyword: 'indian' },
            { type: 'establishment', keyword: 'seafood' },
            { type: 'establishment', keyword: 'steakhouse' },
            { type: 'establishment', keyword: 'bbq' },
            { type: 'establishment', keyword: 'asian' },
            { type: 'establishment', keyword: 'american' },
            
            // ADDITIONAL CUISINE SEARCHES - Extended coverage
            { type: 'establishment', keyword: 'japanese' },
            { type: 'establishment', keyword: 'korean' },
            { type: 'establishment', keyword: 'vietnamese' },
            { type: 'establishment', keyword: 'french' },
            { type: 'establishment', keyword: 'greek' },
            { type: 'establishment', keyword: 'mediterranean' },
            { type: 'establishment', keyword: 'spanish' },
            { type: 'establishment', keyword: 'lebanese' },
            { type: 'establishment', keyword: 'turkish' },
            { type: 'establishment', keyword: 'ethiopian' },
            
            // FOOD TYPE SEARCHES - Specific foods
            { type: 'establishment', keyword: 'tacos' },
            { type: 'establishment', keyword: 'pasta' },
            { type: 'establishment', keyword: 'ramen' },
            { type: 'establishment', keyword: 'pho' },
            { type: 'establishment', keyword: 'wings' },
            { type: 'establishment', keyword: 'sandwich' },
            { type: 'establishment', keyword: 'salad' },
            { type: 'establishment', keyword: 'chicken' },
            { type: 'establishment', keyword: 'steak' },
            
            // ESTABLISHMENT TYPE SEARCHES - Different business types
            { type: 'establishment', keyword: 'pub' },
            { type: 'establishment', keyword: 'tavern' },
            { type: 'establishment', keyword: 'gastropub' },
            { type: 'establishment', keyword: 'brasserie' },
            { type: 'establishment', keyword: 'trattoria' },
            { type: 'establishment', keyword: 'cantina' },
            { type: 'establishment', keyword: 'brewpub' },
            { type: 'establishment', keyword: 'lounge' }
        ];
        
        console.log(`🚀 PHASE 1: Starting comprehensive nearby search for ${searchConfigs.length} restaurant types and keywords...`);
        const startTime = Date.now();
        
        // PHASE 1: Nearby Search - Run all searches in parallel for much faster performance
        const searchPromises = searchConfigs.map(async (config) => {
            let typeResults = [];
            
            let pagetoken = '';
            let url = `https://maps.googleapis.com/maps/api/place/nearbysearch/json?location=${latitude},${longitude}&radius=${radius}&type=${config.type}&key=${apiKey}`;
            if (config.keyword) {
                url += `&keyword=${encodeURIComponent(config.keyword)}`;
            }

            // Get more pages for comprehensive coverage
            const maxPages = 3; // Increased back to 3 for thoroughness
            
            for (let i = 0; i < maxPages; i++) {
                try {
                    const response = await axios.get(url, {
                        timeout: 8000, // Reduced timeout for faster failure detection
                        headers: {
                            'User-Agent': 'Foodle-Restaurant-Finder/1.0'
                        }
                    });
                    
                    if (response.data.status === 'OK' && response.data.results) {
                        typeResults = typeResults.concat(response.data.results);
                        
                    } else if (response.data.status === 'ZERO_RESULTS') {
                        break;
                    } else {
                        console.error(`❌ Type ${config.type} Page ${i + 1}: API returned status ${response.data.status}`);
                        break;
                    }
                    
                    if (response.data.next_page_token) {
                        pagetoken = response.data.next_page_token;
                        // Google requires a short delay before the next_page_token becomes active
                        await new Promise(resolve => setTimeout(resolve, 2000));
                        url = `https://maps.googleapis.com/maps/api/place/nearbysearch/json?pagetoken=${pagetoken}&key=${apiKey}`;
                    } else {
                        break;
                    }
                } catch (error) {
                    console.error(`❌ Error searching ${config.type} page ${i + 1}:`, error.message);
                    break;
                }
            }
            
            return { type: config.type, keyword: config.keyword, count: typeResults.length, results: typeResults };
        });
        
        // Wait for all parallel searches to complete
        const allSearchResults = await Promise.all(searchPromises);
        
        // Log search summary in one line
        const searchSummary = allSearchResults.map(result => 
            `${result.type}${result.keyword ? `+${result.keyword}` : ''}(${result.count})`
        ).join(', ');
        console.log(`🔍 Phase 1 completed: ${searchSummary}`);
        
        // PHASE 2: Text Search - Additional comprehensive coverage
        console.log(`🚀 PHASE 2: Starting text search for additional restaurant discovery...`);
        const textSearches = [
            'restaurants near me',
            'food near me', 
            'dining near me',
            'places to eat near me',
            'cafes near me',
            'bars near me',
            'fast food near me',
            'fine dining near me',
            'takeaway near me',
            'delivery food near me',
            'lunch near me',
            'dinner near me',
            'breakfast near me',
            'eateries near me'
        ];
        
        const textSearchPromises = textSearches.map(async (query) => {
            try {
                const params = {
                    query: query,
                    location: `${latitude},${longitude}`,
                    radius: radius,
                    key: apiKey
                };
                
                const response = await axios.get('https://maps.googleapis.com/maps/api/place/textsearch/json', { params });
                return response.data.results || [];
            } catch (error) {
                console.error(`❌ Text search "${query}" failed:`, error.message);
                return [];
            }
        });

        const textSearchResults = await Promise.all(textSearchPromises);
        const flatTextResults = textSearchResults.flat();
        console.log(`📝 Text search completed: ${flatTextResults.length} additional results found`);
        
        // Flatten and deduplicate results from both phases
        const flatResults = [...allSearchResults.flatMap(result => result.results), ...flatTextResults];
        const uniqueResults = [];
        const seenPlaceIds = new Set();
        
        for (const place of flatResults) {
            if (!seenPlaceIds.has(place.place_id)) {
                seenPlaceIds.add(place.place_id);
                uniqueResults.push(place);
            }
        }
        
        allResults = uniqueResults;
        const endTime = Date.now();
        const searchDuration = ((endTime - startTime) / 1000).toFixed(2);
        
        console.log(`🎯 ULTRA-COMPREHENSIVE SEARCH COMPLETED in ${searchDuration}s: ${allResults.length} unique restaurants found`);
        console.log(`📊 Phase 1 (Nearby): ${allSearchResults.flatMap(r => r.results).length} results | Phase 2 (Text): ${flatTextResults.length} results | Final Unique: ${allResults.length}`);
        
        if (allResults.length === 0) {
            console.log('❌ No restaurants found even with ultra-comprehensive search approach');
            return [];
        }
        
        // Process and format the results consistently with enhanced restaurant info
        console.log('🔍 Processing restaurant information...');
        const processedResults = [];
        let priceStats = { defined: 0, undefined: 0 };
        
        for (const place of allResults) {
            const distance = calculateDistance(
                latitude, longitude,
                place.geometry.location.lat, place.geometry.location.lng
            );
            
            const restaurant = {
                name: place.name,
                address: place.vicinity,
                cuisineType: determineCuisineType(place.types || []),
                diningType: determineDiningType(place.types || []),
                rating: place.rating || 'N/A',
                reviewCount: place.user_ratings_total || 0,
                priceLevel: (() => {
                    if (place.price_level !== undefined) {
                        priceStats.defined++;
                    } else {
                        priceStats.undefined++;
                    }
                    return place.price_level; // Keep raw numeric value
                })(),
                location: place.geometry.location,
                latitude: place.geometry.location.lat,
                longitude: place.geometry.location.lng,
                placeId: place.place_id,
                types: place.types || [],
                distance: Math.round(distance * 100) / 100,
                distanceText: distance < 1 ? 
                    `${Math.round(distance * 1000)}m` : 
                    `${Math.round(distance * 10) / 10}km`,
                photos: place.photos || [],
                openNow: place.opening_hours?.open_now || false
            };
            
            processedResults.push(restaurant);
        }
        
        console.log(`💰 Price levels: ${priceStats.defined} defined, ${priceStats.undefined} undefined`);
        
        // Sort by distance (closest first)
        processedResults.sort((a, b) => a.distance - b.distance);
        
        console.log(`✅ Processed ${processedResults.length} restaurants near ${latitude}, ${longitude}`);
        
        // Filter to only restaurants within 2km and log ALL of them
        const restaurantsWithin2km = processedResults.filter(r => r.distance <= 2);
        
        console.log(`🍽️ Found ${restaurantsWithin2km.length} restaurants within 2km radius`);
        
        return processedResults;
    } catch (error) {
        console.error('❌ Google Places API error:', error.message);
        if (error.response) {
            console.error('❌ API Response Status:', error.response.status);
            console.error('❌ API Response Data:', error.response.data);
        }
        return [];
    }
}

// Helper function to get enhanced restaurant details including photos
async function getRestaurantDetails(placeId, apiKey) {
    try {
        const detailsUrl = `https://maps.googleapis.com/maps/api/place/details/json?place_id=${placeId}&fields=name,formatted_address,rating,user_ratings_total,price_level,photos,opening_hours,formatted_phone_number,website,editorial_summary,types&key=${apiKey}`;
        const detailsResponse = await axios.get(detailsUrl);
        
        if (detailsResponse.data.status === 'OK') {
            return detailsResponse.data.result;
        } else {
            console.warn('⚠️ Could not fetch restaurant details for', placeId, ':', detailsResponse.data.status);
            return null;
        }
    } catch (error) {
        console.error('❌ Error fetching restaurant details for', placeId, ':', error.message);
        return null;
    }
}

// Helper function to determine cuisine type from restaurant types
function getCuisineType(types) {
    const cuisineMap = {
        'italian_restaurant': 'Italian',
        'mexican_restaurant': 'Mexican',
        'chinese_restaurant': 'Chinese',
        'japanese_restaurant': 'Japanese',
        'thai_restaurant': 'Thai',
        'indian_restaurant': 'Indian',
        'korean_restaurant': 'Korean',
        'vietnamese_restaurant': 'Vietnamese',
        'french_restaurant': 'French',
        'greek_restaurant': 'Greek',
        'mediterranean_restaurant': 'Mediterranean',
        'middle_eastern_restaurant': 'Middle Eastern',
        'american_restaurant': 'American',
        'steakhouse': 'Steakhouse',
        'seafood_restaurant': 'Seafood',
        'pizza_restaurant': 'Pizza',
        'bakery': 'Bakery',
        'cafe': 'Cafe',
        'sandwich_shop': 'Sandwiches',
        'fast_food_restaurant': 'Fast Food',
        'hamburger_restaurant': 'Burgers',
        'taco_restaurant': 'Tacos',
        'sushi_restaurant': 'Sushi',
        'barbecue_restaurant': 'BBQ'
    };
    
    for (const type of types) {
        if (cuisineMap[type]) {
            return cuisineMap[type];
        }
    }
    
    // Fallback: check for general cuisine keywords
    const typeString = types.join(' ').toLowerCase();
    if (typeString.includes('pizza')) return 'Pizza';
    if (typeString.includes('burger')) return 'Burgers';
    if (typeString.includes('coffee')) return 'Coffee';
    if (typeString.includes('dessert')) return 'Desserts';
    
    return 'International'; // Default fallback
}

// Helper function to determine dining type from restaurant types  
function getDiningType(types, priceLevel) {
    if (types.includes('fine_dining_restaurant')) return 'Fine Dining';
    if (types.includes('fast_food_restaurant')) return 'Fast Food';
    if (types.includes('fast_casual_restaurant')) return 'Fast Casual';
    if (types.includes('cafe') || types.includes('coffee_shop')) return 'Cafe';
    if (types.includes('bar') || types.includes('night_club')) return 'Bar';
    if (types.includes('takeout') || types.includes('meal_takeaway')) return 'Takeout';
    if (types.includes('family_restaurant')) return 'Family';
    if (types.includes('upscale_restaurant')) return 'Upscale';
    
    // Check price level for dining type inference
    if (priceLevel === 4) return 'Fine Dining';
    if (priceLevel === 3) return 'Upscale';
    if (priceLevel === 1) return 'Fast Food';
    
    return 'Casual'; // Default
}

// Helper function to process restaurant photos
function processRestaurantPhotos(photos, apiKey, maxPhotos = 5) {
    if (!photos || !Array.isArray(photos)) {
        return [];
    }
    
    const processedPhotos = photos.slice(0, maxPhotos).map((photo) => {
        // Return just the URL string, not an object with url property
        return `https://maps.googleapis.com/maps/api/place/photo?maxwidth=400&photo_reference=${photo.photo_reference}&key=${apiKey}`;
    });
    
    console.log(`📸 Processed ${processedPhotos.length} photos for restaurant`);
    return processedPhotos;
}

// === HELPER FUNCTIONS FOR RESTAURANT ENHANCEMENT ===

// Enhanced cuisine type determination
function determineCuisineType(types) {
    if (!types || !Array.isArray(types)) return 'International';
    
    const cuisineMap = {
        'american_restaurant': 'American',
        'italian_restaurant': 'Italian',
        'chinese_restaurant': 'Chinese',
        'japanese_restaurant': 'Japanese',
        'mexican_restaurant': 'Mexican',
        'indian_restaurant': 'Indian',
        'french_restaurant': 'French',
        'thai_restaurant': 'Thai',
        'greek_restaurant': 'Greek',
        'spanish_restaurant': 'Spanish',
        'korean_restaurant': 'Korean',
        'vietnamese_restaurant': 'Vietnamese',
        'brazilian_restaurant': 'Brazilian',
        'turkish_restaurant': 'Turkish',
        'lebanese_restaurant': 'Lebanese',
        'pizza_restaurant': 'Pizza',
        'seafood_restaurant': 'Seafood',
        'steak_house': 'Steakhouse',
        'sushi_restaurant': 'Sushi',
        'barbecue_restaurant': 'BBQ',
        'vegetarian_restaurant': 'Vegetarian',
        'vegan_restaurant': 'Vegan'
    };
    
    for (const type of types) {
        if (cuisineMap[type]) {
            return cuisineMap[type];
        }
    }
    
    // Fallback: check for general cuisine keywords
    const typeString = types.join(' ').toLowerCase();
    if (typeString.includes('pizza')) return 'Pizza';
    if (typeString.includes('burger')) return 'American';
    if (typeString.includes('coffee')) return 'Cafe';
    if (typeString.includes('dessert')) return 'Dessert';
    if (typeString.includes('bakery')) return 'Bakery';
    
    return 'International';
}

// Enhanced dining type determination
function determineDiningType(types, priceLevel) {
    if (!types || !Array.isArray(types)) return 'Casual';
    
    if (types.includes('fine_dining_restaurant')) return 'Fine Dining';
    if (types.includes('fast_food_restaurant')) return 'Fast Food';
    if (types.includes('fast_casual_restaurant')) return 'Fast Casual';
    if (types.includes('cafe') || types.includes('coffee_shop')) return 'Cafe';
    if (types.includes('bar') || types.includes('night_club')) return 'Bar & Lounge';
    if (types.includes('takeout') || types.includes('meal_takeaway')) return 'Takeout';
    if (types.includes('food_delivery')) return 'Delivery';
    if (types.includes('family_restaurant')) return 'Family';
    if (types.includes('upscale_restaurant')) return 'Upscale';
    
    // Check price level for dining type inference
    if (priceLevel === 4) return 'Fine Dining';
    if (priceLevel === 3) return 'Upscale';
    if (priceLevel === 1) return 'Budget';
    
    return 'Casual';
}

// Enhanced price level formatting
function formatPriceLevel(priceLevel) {
    console.log(`💰 formatPriceLevel called with:`, {
        value: priceLevel,
        type: typeof priceLevel,
        isUndefined: priceLevel === undefined,
        isNull: priceLevel === null
    });
    
    // Handle invalid/missing price level
    if (priceLevel === undefined || priceLevel === null) {
        console.log(`💰 Price level is ${priceLevel}, returning "N/A"`);
        return "N/A";
    }
    
    // Google Places price_level is 0-4 scale: 0=Free, 1=Inexpensive, 2=Moderate, 3=Expensive, 4=Very Expensive
    const priceMap = {
        0: "$",     // Free -> $
        1: "$",     // Inexpensive  
        2: "$$",    // Moderate
        3: "$$$",   // Expensive
        4: "$$$$"   // Very Expensive
    };
    
    if (priceMap.hasOwnProperty(priceLevel)) {
        const result = priceMap[priceLevel];
        console.log(`💰 Mapped price level ${priceLevel} to "${result}"`);
        return result;
    } else {
        console.log(`💰 Price level ${priceLevel} not found in mapping, returning "N/A"`);
        return "N/A";
    }
}

// Calculate walking time between two points
async function calculateWalkingTime(originLat, originLng, destLat, destLng, apiKey) {
    try {
        const response = await axios.get('https://maps.googleapis.com/maps/api/distancematrix/json', {
            params: {
                origins: `${originLat},${originLng}`,
                destinations: `${destLat},${destLng}`,
                mode: 'walking',
                units: 'metric',
                key: apiKey
            }
        });

        if (response.data.status === 'OK' && 
            response.data.rows[0] && 
            response.data.rows[0].elements[0] && 
            response.data.rows[0].elements[0].status === 'OK') {
            
            const element = response.data.rows[0].elements[0];
            return {
                duration: element.duration.text,
                distance: element.distance.text,
                durationValue: element.duration.value, // in seconds
                distanceValue: element.distance.value  // in meters
            };
        }
        
        return null;
    } catch (error) {
        console.error('Error calculating walking time:', error);
        return null;
    }
}

// === SOCKET.IO SERVER HANDLERS ===

io.on('connection', (socket) => {
    console.log('🔌 New client connected:', socket.id);
    
    // Handle user joining a location session
    socket.on('join-location-session', (token) => {
        if (token && global.locationSessions.has(token)) {
            socket.join(`location-${token}`);
            console.log(`📱 Client ${socket.id} joined location session: ${token.substring(0, 8)}...`);
            
            // Confirm to the client that they joined successfully
            socket.emit('location-session-joined', { 
                success: true, 
                token: token.substring(0, 8) + '...',
                room: `location-${token}` 
            });
        } else {
            console.log(`❌ Invalid or expired token for session join: ${token}`);
            socket.emit('error', 'Invalid or expired session token');
        }
    });
    
    // Handle mobile location updates
    socket.on('mobile-location-update', async (data) => {
        try {
            const { token, location } = data;
            console.log('📍 Mobile location update received:', { token: token?.substring(0, 8) + '...', location });
            
            if (!token || !location) {
                socket.emit('error', 'Invalid location data');
                return;
            }
            
            const session = global.locationSessions.get(token);
            if (!session || Date.now() > session.expires) {
                socket.emit('error', 'Session expired');
                return;
            }
            
            // Update location in database if user is authenticated
            try {
                const user = await User.findOne({ email: session.userEmail });
                if (user && session.userEmail !== 'demo@foodle.com') {
                    user.lastKnownLocation = {
                        latitude: location.latitude,
                        longitude: location.longitude,
                        accuracy: location.accuracy,
                        timestamp: new Date(),
                        source: 'mobile-gps'
                    };
                    await user.save();
                    console.log('💾 Location saved to database for user:', session.userEmail);
                }
            } catch (dbError) {
                console.error('❌ Database error during location save:', dbError.message);
            }
            
            // Broadcast to the specific location session room
            console.log(`🔌 Broadcasting to room: location-${token}`);
            console.log(`🔌 Connected clients in room:`, socket.adapter.rooms.get(`location-${token}`)?.size || 0);
            
            socket.to(`location-${token}`).emit('desktop-location-update', {
                location,
                userInfo: {
                    name: session.userName,
                    email: session.userEmail
                }
            });
            
            console.log('✅ desktop-location-update event emitted to room');
            
            // Confirm to mobile device
            socket.emit('location-received', { 
                success: true, 
                message: 'Location sent to computer' 
            });
            
            console.log('✅ Location update broadcasted to desktop');
            
        } catch (error) {
            console.error('❌ Mobile location update error:', error);
            socket.emit('error', 'Failed to process location update');
        }
    });
    
    // Handle desktop joining for location updates
    socket.on('join-desktop-session', (userId) => {
        if (userId) {
            socket.join(`desktop-${userId}`);
            console.log(`💻 Desktop client ${socket.id} joined session for user: ${userId}`);
        }
    });
    
    // Handle chat/recommendation requests
    socket.on('chat-message', async (data) => {
        try {
            const { message, userLocation, userId } = data;
            console.log('💬 Chat message received:', { message: message?.substring(0, 50) + '...', userId });
            
            // Emit to user's room
            socket.to(`desktop-${userId}`).emit('chat-response', {
                message: message,
                timestamp: new Date(),
                type: 'user'
            });
            
            // Here you could add AI processing and respond
            // For now, just acknowledge
            socket.emit('chat-received', { success: true });
            
        } catch (error) {
            console.error('❌ Chat message error:', error);
            socket.emit('error', 'Failed to process chat message');
        }
    });
    
    // Handle real-time restaurant search requests
    socket.on('search-restaurants-realtime', async (data) => {
        try {
            const { latitude, longitude, accuracy, filters, userId } = data;
            console.log('🔍 Real-time restaurant search:', { lat: latitude, lng: longitude, userId });
            
            // Emit search started
            socket.emit('search-started', { message: 'Searching for restaurants...' });
            
            // Perform restaurant search (using existing function)
            const apiKey = process.env.GOOGLE_PLACES_API_KEY;
            const restaurants = await findNearbyRestaurants(latitude, longitude, accuracy || 2000, apiKey);
            
            if (restaurants && restaurants.length > 0) {
                // Get walking times
                const walkingTimes = await getBatchWalkingTimes(latitude, longitude, restaurants, apiKey);
                
                // Enrich with walking times
                const enrichedResults = restaurants.map(restaurant => {
                    const walkingTime = walkingTimes.get(restaurant.placeId);
                    return {
                        ...restaurant,
                        walkingTime: walkingTime ? {
                            duration: walkingTime.duration,
                            distance: walkingTime.distance
                        } : null
                    };
                });
                
                // Sort by walking time
                enrichedResults.sort((a, b) => {
                    if (a.walkingTime?.durationValue && b.walkingTime?.durationValue) {
                        return a.walkingTime.durationValue - b.walkingTime.durationValue;
                    }
                    return a.distance - b.distance;
                });
                
                socket.emit('search-results', { 
                    restaurants: enrichedResults.slice(0, 20),
                    totalFound: enrichedResults.length
                });
                
                console.log(`✅ Sent ${enrichedResults.length} restaurants via WebSocket`);
            } else {
                socket.emit('search-results', { restaurants: [], totalFound: 0 });
            }
            
        } catch (error) {
            console.error('❌ Real-time search error:', error);
            socket.emit('search-error', { message: 'Failed to search restaurants' });
        }
    });
    
    // Handle disconnect
    socket.on('disconnect', () => {
        console.log('🔌 Client disconnected:', socket.id);
    });
});

// Multer configuration for file uploads
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, path.join(__dirname, 'uploads/'));
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({ 
    storage: storage,
    limits: {
        fileSize: 5 * 1024 * 1024 // 5MB limit
    },
    fileFilter: function (req, file, cb) {
        // Check file type
        if (file.mimetype.startsWith('image/')) {
            cb(null, true);
        } else {
            cb(new Error('Only image files are allowed!'), false);
        }
    }
});

// Profile image upload endpoint
app.post('/api/user/profile-image', upload.single('profileImage'), async (req, res) => {
    try {
        if (!req.session || !req.session.email) {
            return res.status(401).json({ message: 'Authentication required.' });
        }
        
        if (!req.file) {
            return res.status(400).json({ message: 'No file uploaded.' });
        }
        
        console.log('File uploaded:', req.file.filename, 'for user:', req.session.email);
        
        const user = await User.findOne({ email: req.session.email });
        if (!user) {
            console.log('Upload failed: User not found');
            return res.status(404).json({ message: 'User not found.' });
        }
        
        // Save the file path
        user.profileImageUrl = `/uploads/${req.file.filename}`;
        await user.save();
        
        console.log('Profile image saved successfully:', user.profileImageUrl);
        res.json({ profileImageUrl: user.profileImageUrl });
    } catch (err) {
        console.error('Profile image upload error:', err);
        res.status(500).json({ message: 'Server error.' });
    }
});

// Serve uploaded images statically
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Logout endpoint
app.post('/api/logout', (req, res) => {
    console.log('🚨🚨🚨 LOGOUT ENDPOINT HIT - SESSION CLEARING LOGIC ACTIVE 🚨🚨🚨');
    // Clear session-based restaurant memory for this user
    if (req.session?.id && global.sessionRestaurantMemory) {
        console.log(`🔄 Clearing restaurant memory for session: ${req.session.id}`);
        global.sessionRestaurantMemory.delete(req.session.id);
    }
    
    // Clear session recommendation memory and original request
    if (req.session) {
        req.session.recommendedRestaurants = [];
        req.session.originalRequest = null;
        console.log(`🔄 Cleared session recommendation memory and original request`);
    }
    
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).json({ message: 'Could not log out.' });
        }
        res.clearCookie('connect.sid');
        console.log(`🔄 User logged out successfully - all session memory cleared`);
        res.json({ message: 'Logged out successfully.' });
    });
});

// Clear recommendation memory endpoint
app.post('/api/clear-recommendation-memory', (req, res) => {
    try {
        if (req.session) {
            const previousCount = req.session.recommendedRestaurants?.length || 0;
            req.session.recommendedRestaurants = [];
            console.log(`🧠 Cleared ${previousCount} restaurants from session memory`);
            
            res.json({ 
                message: 'Recommendation memory cleared successfully.',
                clearedCount: previousCount,
                sessionId: req.session.id
            });
        } else {
            res.json({ 
                message: 'No active session found.',
                clearedCount: 0
            });
        }
    } catch (error) {
        console.error('❌ Error clearing recommendation memory:', error);
        res.status(500).json({ message: 'Failed to clear recommendation memory.' });
    }
});

// Get recommendation memory status endpoint
app.get('/api/recommendation-memory-status', (req, res) => {
    try {
        const sessionRecommendations = req.session?.recommendedRestaurants || [];
        res.json({
            sessionActive: !!req.session,
            sessionId: req.session?.id,
            restaurantsRemembered: sessionRecommendations.length,
            sessionRecommendations: sessionRecommendations
        });
    } catch (error) {
        console.error('❌ Error getting recommendation memory status:', error);
        res.status(500).json({ message: 'Failed to get recommendation memory status.' });
    }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        timestamp: new Date().toISOString(),
        uptime: process.uptime()
    });
});

// 📸 Photo proxy endpoint to serve Google Places API photos
app.get('/api/photo-proxy', async (req, res) => {
    try {
        const { url } = req.query;
        
        if (!url || !url.includes('maps.googleapis.com')) {
            return res.status(400).json({ error: 'Invalid photo URL' });
        }

        console.log('📸 Proxying photo request:', url);
        
        const response = await fetch(url);
        
        if (!response.ok) {
            console.error('❌ Photo proxy failed:', response.status, response.statusText);
            return res.status(response.status).json({ error: 'Failed to fetch photo' });
        }
        
        // Get the image data
        const imageBuffer = await response.buffer();
        const contentType = response.headers.get('content-type') || 'image/jpeg';
        
        // Set appropriate headers
        res.set({
            'Content-Type': contentType,
            'Cache-Control': 'public, max-age=3600',
            'Access-Control-Allow-Origin': '*'
        });
        
        res.send(imageBuffer);
        
    } catch (error) {
        console.error('❌ Photo proxy error:', error);
        res.status(500).json({ error: 'Photo proxy failed' });
    }
});

// 📸 Refresh photos endpoint - get fresh photo URLs from Google Places API
app.post('/api/refresh-photos', async (req, res) => {
    try {
        const { placeId } = req.body;
        
        if (!placeId) {
            return res.status(400).json({ error: 'Place ID required' });
        }

        console.log('📸 Refreshing photos for place:', placeId);
        
        // Get place details with photos
        const detailsUrl = `https://maps.googleapis.com/maps/api/place/details/json?place_id=${placeId}&fields=photos&key=${process.env.GOOGLE_PLACES_API_KEY}`;
        
        const response = await fetch(detailsUrl);
        const data = await response.json();
        
        if (data.status !== 'OK') {
            console.error('❌ Failed to fetch place details:', data.status, data.error_message);
            return res.status(400).json({ error: 'Failed to fetch place details' });
        }
        
        // Process the photos
        const photos = processRestaurantPhotos(data.result?.photos || [], process.env.GOOGLE_PLACES_API_KEY);
        
        console.log(`📸 Refreshed ${photos.length} photos for place ${placeId}`);
        res.json({ photos });
        
    } catch (error) {
        console.error('❌ Photo refresh error:', error);
        res.status(500).json({ error: 'Photo refresh failed' });
    }
});

// Real-time filter change logging endpoint
app.post('/api/log-filter-change', (req, res) => {
    try {
        const { changeType, oldValue, newValue, fullFilters, timestamp } = req.body;
        
        if (changeType === 'page_load_defaults') {
            console.log(`\n🎯 ===== PAGE LOAD - DEFAULT FILTERS [${timestamp}] =====`);
            console.log(`🎯 📋 DEFAULT FILTER STATE:`);
            console.log(`🎯    💰 Price Level: ${fullFilters.priceLevel} (${'$'.repeat(fullFilters.priceLevel)})`);
            console.log(`🎯    🏷️  Category: ${fullFilters.category}`);
            console.log(`🎯    📍 Max Distance: ${fullFilters.maxDistance}km`);
            console.log(`🎯    ⭐ Min Rating: ${fullFilters.minRating}⭐`);
            console.log(`🎯    ⭐ Max Rating: ${fullFilters.maxRating}⭐`);
            console.log(`🎯 System ready for filter changes`);
            console.log(`🎯 ================================================\n`);
        } else {
            console.log(`\n🎯 ===== FILTER CHANGE [${timestamp}] =====`);
            console.log(`🎯 📝 Type: ${changeType}`);
            console.log(`🎯 🔄 Change: ${oldValue} → ${newValue}`);
            console.log(`🎯 📊 Updated State:`);
            console.log(`🎯    � Price: ${fullFilters.priceLevel} (${'$'.repeat(fullFilters.priceLevel)})`);
            console.log(`🎯    🏷️  Category: ${fullFilters.category}`);
            console.log(`🎯    📍 Distance: ${fullFilters.maxDistance}km`);
            console.log(`🎯    ⭐ Rating: ${fullFilters.minRating}-${fullFilters.maxRating}⭐`);
            console.log(`🎯 =======================================\n`);
        }
        
        res.json({ success: true, logged: true });
    } catch (error) {
        console.error('❌ Error logging filter change:', error);
        res.status(500).json({ success: false, error: 'Failed to log filter change' });
    }
});

// Save user preferences endpoint
app.post('/api/save-preferences', async (req, res) => {
    try {
        const { filters, saveType } = req.body;
        const timestamp = new Date().toISOString();
        
        console.log(`\n💾 ===== SAVING USER PREFERENCES [${new Date().toLocaleTimeString()}] =====`);
        console.log(`💾 Save Type: ${saveType || 'manual'}`);
        console.log(`💾 📋 PREFERENCES TO SAVE:`);
        console.log(`💾    💰 Price Level: ${filters.priceLevel} (${'$'.repeat(filters.priceLevel)})`);
        console.log(`💾    🏷️  Category: ${filters.category}`);
        console.log(`💾    📍 Max Distance: ${filters.maxDistance}km`);
        console.log(`💾    ⭐ Min Rating: ${filters.minRating}⭐`);
        console.log(`💾    ⭐ Max Rating: ${filters.maxRating}⭐`);
        
        // Get user from session/token
        let user = null;
        
        // Try to get authenticated user from session
        if (req.session && req.session.user) {
            console.log(`💾 🔐 Authenticated user found in session: ${req.session.user.email}`);
            user = await User.findById(req.session.user._id);
        }
        // Try to get user from token in cookies
        else if (req.cookies && req.cookies.token) {
            try {
                const decoded = jwt.verify(req.cookies.token, JWT_SECRET);
                console.log(`💾 🔐 User found from JWT token: ${decoded.email}`);
                user = await User.findById(decoded.userId);
            } catch (tokenError) {
                console.log(`💾 ⚠️ Invalid JWT token:`, tokenError.message);
            }
        }
        
        if (user) {
            // Save preferences to authenticated user
            const previousPrefs = user.preferences || {};
            
            user.preferences = {
                ...user.preferences,
                filters: {
                    priceLevel: filters.priceLevel,
                    category: filters.category,
                    maxDistance: filters.maxDistance,
                    minRating: filters.minRating,
                    maxRating: filters.maxRating,
                    lastUpdated: timestamp
                }
            };
            
            await user.save();
            
            console.log(`💾 ✅ SAVED to authenticated user: ${user.email}`);
            console.log(`💾 📊 Previous filters:`, previousPrefs.filters || 'None');
            console.log(`💾 📊 Updated filters:`, user.preferences.filters);
            console.log(`💾 ================================================\n`);
            
            res.json({ 
                success: true, 
                saved: true, 
                userType: 'authenticated',
                userId: user._id,
                email: user.email,
                preferences: user.preferences 
            });
        } else {
            // For non-authenticated users, save to localStorage (client-side) or session
            console.log(`💾 👤 No authenticated user found - saving to session`);
            
            if (!req.session.guestPreferences) {
                req.session.guestPreferences = {};
            }
            
            req.session.guestPreferences.filters = {
                priceLevel: filters.priceLevel,
                category: filters.category,
                maxDistance: filters.maxDistance,
                minRating: filters.minRating,
                maxRating: filters.maxRating,
                lastUpdated: timestamp
            };
            
            console.log(`💾 ✅ SAVED to guest session`);
            console.log(`💾 📊 Session preferences:`, req.session.guestPreferences.filters);
            console.log(`💾 ================================================\n`);
            
            res.json({ 
                success: true, 
                saved: true, 
                userType: 'guest',
                sessionId: req.sessionID,
                preferences: req.session.guestPreferences 
            });
        }
        
    } catch (error) {
        console.error('❌ Error saving preferences:', error);
        res.status(500).json({ success: false, error: 'Failed to save preferences', details: error.message });
    }
});

// Get user preferences endpoint
app.get('/api/get-preferences', async (req, res) => {
    try {
        console.log(`\n📥 ===== LOADING USER PREFERENCES [${new Date().toLocaleTimeString()}] =====`);
        
        // Get user from session/token
        let user = null;
        let preferences = null;
        
        // Try to get authenticated user from session
        if (req.session && req.session.user) {
            console.log(`📥 🔐 Loading preferences for authenticated user: ${req.session.user.email}`);
            user = await User.findById(req.session.user._id);
            
            if (user && user.preferences && user.preferences.filters) {
                preferences = user.preferences.filters;
                console.log(`📥 ✅ LOADED authenticated user preferences:`);
                console.log(`📥    💰 Price Level: ${preferences.priceLevel} (${'$'.repeat(preferences.priceLevel)})`);
                console.log(`📥    🏷️  Category: ${preferences.category}`);
                console.log(`📥    📍 Max Distance: ${preferences.maxDistance}km`);
                console.log(`📥    ⭐ Min Rating: ${preferences.minRating}⭐`);
                console.log(`📥    ⭐ Max Rating: ${preferences.maxRating}⭐`);
                console.log(`📥    📅 Last Updated: ${preferences.lastUpdated}`);
            } else {
                console.log(`📥 ℹ️ No saved preferences found for authenticated user`);
            }
        }
        // Try to get user from token in cookies
        else if (req.cookies && req.cookies.token) {
            try {
                const decoded = jwt.verify(req.cookies.token, JWT_SECRET);
                console.log(`📥 🔐 Loading preferences for JWT user: ${decoded.email}`);
                user = await User.findById(decoded.userId);
                
                if (user && user.preferences && user.preferences.filters) {
                    preferences = user.preferences.filters;
                    console.log(`📥 ✅ LOADED JWT user preferences:`);
                    console.log(`📥    💰 Price Level: ${preferences.priceLevel} (${'$'.repeat(preferences.priceLevel)})`);
                    console.log(`📥    🏷️  Category: ${preferences.category}`);
                    console.log(`📥    📍 Max Distance: ${preferences.maxDistance}km`);
                    console.log(`📥    ⭐ Min Rating: ${preferences.minRating}⭐`);
                    console.log(`📥    ⭐ Max Rating: ${preferences.maxRating}⭐`);
                    console.log(`📥    📅 Last Updated: ${preferences.lastUpdated}`);
                } else {
                    console.log(`📥 ℹ️ No saved preferences found for JWT user`);
                }
            } catch (tokenError) {
                console.log(`📥 ⚠️ Invalid JWT token:`, tokenError.message);
            }
        }
        
        // Try guest session as fallback
        if (!preferences && req.session && req.session.guestPreferences && req.session.guestPreferences.filters) {
            preferences = req.session.guestPreferences.filters;
            console.log(`📥 👤 LOADED guest session preferences:`);
            console.log(`📥    💰 Price Level: ${preferences.priceLevel} (${'$'.repeat(preferences.priceLevel)})`);
            console.log(`📥    🏷️  Category: ${preferences.category}`);
            console.log(`📥    📍 Max Distance: ${preferences.maxDistance}km`);
            console.log(`📥    ⭐ Min Rating: ${preferences.minRating}⭐`);
            console.log(`📥    ⭐ Max Rating: ${preferences.maxRating}⭐`);
            console.log(`📥    📅 Last Updated: ${preferences.lastUpdated}`);
        }
        
        if (preferences) {
            console.log(`📥 ✅ RETURNING saved preferences`);
            console.log(`📥 ================================================\n`);
            
            res.json({
                success: true,
                hasPreferences: true,
                preferences: preferences,
                userType: user ? 'authenticated' : 'guest',
                userId: user ? user._id : req.sessionID,
                email: user ? user.email : null
            });
        } else {
            console.log(`📥 ℹ️ NO PREFERENCES FOUND - returning defaults`);
            console.log(`📥 ================================================\n`);
            
            // Return default preferences
            const defaultPrefs = {
                priceLevel: 1,
                category: 'any',
                maxDistance: 5,
                minRating: 4.0,
                maxRating: 5.0
            };
            
            res.json({
                success: true,
                hasPreferences: false,
                preferences: defaultPrefs,
                userType: user ? 'authenticated' : 'guest',
                userId: user ? user._id : req.sessionID,
                email: user ? user.email : null
            });
        }
        
    } catch (error) {
        console.error('❌ Error loading preferences:', error);
        res.status(500).json({ success: false, error: 'Failed to load preferences', details: error.message });
    }
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Error:', err);
    res.status(500).json({ message: 'Internal server error.' });
});

// Add global error handlers
process.on('uncaughtException', (error) => {
    console.error('🚨 Uncaught Exception:', error);
    console.error('Stack trace:', error.stack);
    // Don't exit the process for now, just log the error
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('🚨 Unhandled Rejection at:', promise, 'reason:', reason);
    console.error('Stack trace:', reason.stack || reason);
});

// Add error handler for the server
server.on('error', (error) => {
    console.error('🚨 Server error:', error);
    if (error.code === 'EADDRNOTAVAIL') {
        console.error('❌ Address not available. Check your network configuration.');
    } else if (error.code === 'EADDRINUSE') {
        console.error('❌ Port already in use. Try a different port or stop other services.');
    } else if (error.code === 'EACCES') {
        console.error('❌ Permission denied. Try running as administrator or use a different port.');
    }
});

// === SERVER STARTUP ===

// Helper function to check if a port is available
const isPortAvailable = (port) => {
    return new Promise((resolve) => {
        const testServer = require('net').createServer();
        testServer.listen(port, '0.0.0.0', () => {
            testServer.close(() => resolve(true));
        });
        testServer.on('error', () => resolve(false));
    });
};

// Find an available port starting from the preferred port
const findAvailablePort = async (startPort, maxAttempts = 5) => {
    for (let i = 0; i < maxAttempts; i++) {
        const port = startPort + i;
        const available = await isPortAvailable(port);
        if (available) {
            return port;
        }
        console.log(`⚠️  Port ${port} is in use, trying ${port + 1}...`);
    }
    throw new Error(`Could not find available port starting from ${startPort}`);
};

// Start server with port fallback
const startServer = async () => {
    try {
        // Force server to use port 5000 only
        const finalPort = 5000;
        
        server.listen(finalPort, '0.0.0.0', () => {
            const frontendUrls = process.env.FRONTEND_URL ? process.env.FRONTEND_URL.split(',') : ['http://localhost:3001'];
            
            // Debug environment variables
            console.log('🔧 Environment Variables Check:');
            console.log('📍 GOOGLE_PLACES_API_KEY:', process.env.GOOGLE_PLACES_API_KEY ? 'Present ✅' : 'Missing ❌');
            console.log('🤖 OPENAI_API_KEY:', process.env.OPENAI_API_KEY ? 'Present ✅' : 'Missing ❌');
            console.log('🔑 GOOGLE_CLIENT_ID:', process.env.GOOGLE_CLIENT_ID ? 'Present ✅' : 'Missing ❌');
            console.log('🔐 GOOGLE_CLIENT_SECRET:', process.env.GOOGLE_CLIENT_SECRET ? 'Present ✅' : 'Missing ❌');
            console.log('');
            
            if (finalPort !== PORT) {
                console.log(`⚠️  Port ${PORT} was in use, switched to port ${finalPort}`);
            }
            
            console.log(`🚀 Foodle backend server running on port ${finalPort}`);
            console.log(`📊 Health check: http://localhost:${finalPort}/api/health`);
            console.log(`🔗 CORS enabled for: ${frontendUrls.join(', ')}`);
            console.log(`📱 Mobile GPS service: /mobile-gps`);
            console.log(`🔌 WebSocket server ready for real-time location updates`);
            console.log(`🌐 Ready for ngrok: ngrok http ${finalPort}`);
        }).on('error', (error) => {
            console.error('🚨 Failed to start server:', error);
            process.exit(1);
        });
    } catch (error) {
        console.error('🚨 Server startup error:', error);
        process.exit(1);
    }
};

// Start the server
startServer();

// === MOBILE GPS QR CODE SYSTEM ===

// QR Code generation endpoint (supports both GET and POST)
app.get('/api/generate-location-qr', generateLocationQRHandler);
app.post('/api/generate-location-qr', generateLocationQRHandler);

async function generateLocationQRHandler(req, res) {
    try {
        console.log('🔍 QR Generation - Request method:', req.method);
        console.log('🔍 QR Generation - Request body:', req.body);
        console.log('🔍 QR Generation - Session exists:', !!req.session);
        console.log('🔍 QR Generation - Session email:', req.session?.email);
        
        let userId, userEmail, userName;
        
        // Priority 1: Use authenticated session data (highest priority for real users)
        if (req.session && req.session.email) {
            const user = await User.findOne({ email: req.session.email });
            if (user) {
                userId = user._id.toString();
                userEmail = user.email;
                userName = `${user.firstName} ${user.lastName}`;
                console.log('🔍 QR Generation - Using authenticated session user data:', { userId, userEmail, userName });
            }
        }
        
        // Priority 2: Use request body data (for non-authenticated but entered data)
        if (!userId && req.method === 'POST' && req.body && req.body.userId) {
            userId = req.body.userId;
            userEmail = req.body.userEmail || 'demo@foodle.com';
            userName = req.body.userName || 'Demo User';
            console.log('🔍 QR Generation - Using request body user data:', { userId, userEmail, userName });
        }
        
        // Priority 3: Fallback to demo data
        if (!userId) {
            userId = 'demo-user-' + Date.now();
            userEmail = 'demo@foodle.com';
            userName = 'Demo User';
            console.log('🔍 QR Generation - Using fallback demo data:', { userId, userEmail, userName });
        }

        console.log('🔍 QR Generation - Final userId:', userId);
        console.log('🔍 QR Generation - Request body userId:', req.body?.userId);
        console.log('🔍 QR Generation - Room name will be: location-' + userId);

        // Generate unique session token
        const locationToken = uuidv4();
        
        // Store session (expires in 10 minutes)
        const locationSession = {
            userId,
            userEmail,
            userName,
            token: locationToken,
            created: Date.now(),
            expires: Date.now() + (10 * 60 * 1000) // 10 minutes
        };
        
        global.locationSessions.set(locationToken, locationSession);
        
        // Clean up expired sessions
        for (const [token, session] of global.locationSessions.entries()) {
            if (Date.now() > session.expires) {
                global.locationSessions.delete(token);
            }
        }

        // Generate mobile PWA URL (needs to be accessible from mobile device)
        // Priority: 1. ngrok URL (if available), 2. Local IP for same network
        const getBackendUrl = async () => {
            // Check if ngrok URL is available (look for common ngrok environment or file)
            if (process.env.NGROK_URL) {
                console.log('🌐 Using ngrok URL from environment variable');
                return process.env.NGROK_URL;
            }
            
            // Check for ngrok API (if running locally)
            const checkNgrokAPI = async () => {
                try {
                    const axios = require('axios');
                    const response = await axios.get('http://127.0.0.1:4040/api/tunnels');
                    const tunnels = response.data.tunnels;
                    const httpsTunnel = tunnels.find(tunnel => 
                        tunnel.config.addr.includes(`:${PORT}`) && 
                        tunnel.proto === 'https'
                    );
                    if (httpsTunnel) {
                        console.log('🌐 Auto-detected ngrok HTTPS tunnel:', httpsTunnel.public_url);
                        return httpsTunnel.public_url;
                    }
                } catch (error) {
                    // ngrok not running or API not available
                }
                return null;
            };
            
            // Try to get ngrok URL
            const ngrokUrl = await checkNgrokAPI();
            if (ngrokUrl) {
                // Store for next requests
                process.env.DETECTED_NGROK_URL = ngrokUrl;
                return ngrokUrl;
            }
            
            // Use detected ngrok URL if available
            if (process.env.DETECTED_NGROK_URL) {
                console.log('🌐 Using detected ngrok URL');
                return process.env.DETECTED_NGROK_URL;
            }
            
            // Fallback to local IP for same-network access
            const os = require('os');
            const networkInterfaces = os.networkInterfaces();
            let computerIP = 'localhost';
            
            // Find the first non-internal IPv4 address (usually WiFi)
            for (const interfaceName in networkInterfaces) {
                const addresses = networkInterfaces[interfaceName];
                for (const address of addresses) {
                    if (address.family === 'IPv4' && !address.internal) {
                        computerIP = address.address;
                        break;
                    }
                }
                if (computerIP !== 'localhost') break;
            }
            
            const port = PORT;
            const localUrl = `http://${computerIP}:${port}`;
            console.log('🏠 Using local network URL (same WiFi only):', localUrl);
            console.log('💡 For cross-network access, use ngrok: https://ngrok.com');
            return localUrl;
        };
        
        const backendUrl = await getBackendUrl();
        const mobileLocationUrl = `${backendUrl}/mobile-gps?token=${locationToken}`;
        
        console.log(`📱 Mobile URL generated: ${mobileLocationUrl}`);
        
        // Generate professional QR codes using server-compatible method
        const generateProfessionalQR = async (options = {}) => {
            return await QRCode.toDataURL(mobileLocationUrl, {
                width: 400,
                margin: 4,
                errorCorrectionLevel: 'M', // Good balance of data/reliability
                color: {
                    dark: options.dotsColor || '#1F2937',
                    light: options.backgroundColor || '#FFFFFF'
                },
                rendererOpts: {
                    quality: 0.95 // High quality rendering
                }
            });
        };
        
        // Generate the professional QR code
        const qrCodeDataUrl = await generateProfessionalQR({
            dotsColor: "#EF4444",        // Foodle red color
            backgroundColor: "#FFFBF7"   // Match foodle-bg background color
        });

        console.log(`📱 Generated professional QR code for ${userEmail}, token: ${locationToken.substring(0, 8)}...`);
        console.log(`📱 Server-compatible QR generation | Size: 400x400px | High quality: Yes | Original Foodle branding: Ready`);
        
        res.json({
            qrCode: qrCodeDataUrl,              // Single professional QR code
            token: locationToken,
            expiresIn: 600, // 10 minutes
            mobileUrl: mobileLocationUrl,
            userId: userId,
            userInfo: {
                name: userName,
                email: userEmail
            }
        });

    } catch (error) {
        console.error('QR generation error:', error);
        res.status(500).json({ 
            message: 'Failed to generate QR code',
            error: error.message 
        });
    }
}

// Mobile PWA endpoint - serves the GPS interface
app.get('/mobile-gps', async (req, res) => {
    const { token } = req.query;
    
    if (!token) {
        return res.status(400).send(`
            <html><body style="font-family: -apple-system, BlinkMacSystemFont, sans-serif; padding: 20px; text-align: center;">
                <h2>❌ Invalid Request</h2>
                <p>No location token provided. Please scan the QR code from your computer.</p>
            </body></html>
        `);
    }
    
    // Verify token exists and is valid
    const session = global.locationSessions.get(token);
    if (!session || Date.now() > session.expires) {
        return res.status(400).send(`
            <html><body style="font-family: -apple-system, BlinkMacSystemFont, sans-serif; padding: 20px; text-align: center;">
                <h2>🔒 QR Code Expired</h2>
                <p>This location request has expired. Please generate a new QR code from your computer.</p>
                <p style="color: #666; font-size: 14px;">QR codes expire after 10 minutes for security.</p>
            </body></html>
        `);
    }
    
    // Get the backend URL for the mobile page
    const getBackendUrl = async () => {
        // Check if ngrok URL is available (look for common ngrok environment or file)
        if (process.env.NGROK_URL) {
            console.log('🌐 Using ngrok URL from environment variable');
            return process.env.NGROK_URL;
        }
        
        // Check for ngrok API (if running locally)
        const checkNgrokAPI = async () => {
            try {
                const axios = require('axios');
                const response = await axios.get('http://127.0.0.1:4040/api/tunnels');
                const tunnels = response.data.tunnels;
                const httpsTunnel = tunnels.find(tunnel => 
                    tunnel.config.addr.includes(`:${PORT}`) && 
                    tunnel.proto === 'https'
                );
                if (httpsTunnel) {
                    console.log('🌐 Auto-detected ngrok HTTPS tunnel:', httpsTunnel.public_url);
                    return httpsTunnel.public_url;
                }
            } catch (error) {
                // ngrok not running or API not available
            }
            return null;
        };
        
        // Try to get ngrok URL
        const ngrokUrl = await checkNgrokAPI();
        if (ngrokUrl) {
            // Store for next requests
            process.env.DETECTED_NGROK_URL = ngrokUrl;
            return ngrokUrl;
        }
        
        // Use detected ngrok URL if available
        if (process.env.DETECTED_NGROK_URL) {
            console.log('🌐 Using detected ngrok URL');
            return process.env.DETECTED_NGROK_URL;
        }
        
        // Fallback to local IP for same-network access
        const os = require('os');
        const networkInterfaces = os.networkInterfaces();
        let computerIP = 'localhost';
        
        // Find the first non-internal IPv4 address (usually WiFi)
        for (const interfaceName in networkInterfaces) {
            const addresses = networkInterfaces[interfaceName];
            for (const address of addresses) {
                if (address.family === 'IPv4' && !address.internal) {
                    computerIP = address.address;
                    break;
                }
            }
            if (computerIP !== 'localhost') break;
        }
        
        const port = PORT;
        const localUrl = `http://${computerIP}:${port}`;
        console.log('🏠 Using local network URL (same WiFi only):', localUrl);
        console.log('💡 For cross-network access, use ngrok: https://ngrok.com');
        return localUrl;
    };
    
    const backendUrl = await getBackendUrl();
    
    // Serve the mobile GPS PWA interface
    res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Foodle GPS - Location Service</title>
        <meta name="theme-color" content="#EF4444">
        
        <!-- PWA capabilities -->
        <meta name="apple-mobile-web-app-capable" content="yes">
        <meta name="apple-mobile-web-app-status-bar-style" content="default">
        <meta name="apple-mobile-web-app-title" content="Foodle GPS">
        
        <script src="https://cdn.tailwindcss.com"></script>
        <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin="">
        <script>
            window.FontAwesomeConfig = { autoReplaceSvg: 'nest' };
        </script>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/js/all.min.js" crossorigin="anonymous" referrerpolicy="no-referrer"></script>
        <script>tailwind.config = {
          "theme": {
            "extend": {
              "fontFamily": {
                "sans": [
                  "Inter",
                  "sans-serif"
                ]
              },
              "colors": {
                "foodle-red": "#EF4444",
                "foodle-dark": "#1F2937",
                "foodle-bg": "#FFFBF7",
                "foodle-card": "#FEFDFB",
                "foodle-secondary-text": "#6B7280"
              }
            }
          }
        };</script>
        <style>
            ::-webkit-scrollbar { display: none; }
            .glass-effect {
                backdrop-filter: blur(20px);
                background: rgba(255, 255, 255, 0.8);
                border: 1px solid rgba(255, 255, 255, 0.2);
            }
            .location-pulse {
                animation: pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite;
            }
            @keyframes pulse {
                0%, 100% { opacity: 1; }
                50% { opacity: .5; }
            }
            .animate-spin {
                animation: spin 1s linear infinite;
            }
            @keyframes spin {
                from { transform: rotate(0deg); }
                to { transform: rotate(360deg); }
            }
        </style>
        <link rel="preconnect" href="https://fonts.googleapis.com">
        <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@100;200;300;500;600;700;800;900&display=swap">
        <style>
          body {
            font-family: 'Inter', sans-serif !important;
          }
          
          /* Preserve Font Awesome icons */
          .fa, .fas, .far, .fal, .fab {
            font-family: "Font Awesome 6 Free", "Font Awesome 6 Brands" !important;
          }
        </style>
    </head>
    <body class="bg-gradient-to-br from-foodle-red to-red-600 font-sans min-h-screen">
        <div id="location-container" class="min-h-screen flex flex-col items-center justify-center p-6 relative overflow-hidden">
            
            <!-- Logo and Brand -->
            <div id="brand-section" class="flex flex-col items-center mb-12 z-10">
                <div class="w-16 h-12 text-white mb-4">
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 50" fill="currentColor">
                        <path d="M54.5,14.2H9.5C4.3,14.2,0,18.5,0,23.7v0c0,5.3,4.3,9.5,9.5,9.5h45.1c5.3,0,9.5-4.3,9.5-9.5v0 C64,18.5,59.7,14.2,54.5,14.2z M5.1,23.7c0-2.4,2-4.4,4.4-4.4h45.1c2.4,0,4.4,2,4.4,4.4c0,2.4-2,4.4-4.4,4.4H9.5 C7.1,28.1,5.1,26.1,5.1,23.7z"></path>
                        <path d="M58.9,0H5.1C2.3,0,0,2.3,0,5.1v0C0,8,2.3,10.3,5.1,10.3h53.8c2.8,0,5.1-2.3,5.1-5.1v0C64,2.3,61.7,0,58.9,0z"></path>
                    </svg>
                </div>
                <h1 class="text-4xl font-bold text-white mb-2">Foodle</h1>
                <p class="text-white/80 text-lg text-center">Find your perfect meal</p>
            </div>

            <!-- Main Location Card -->
            <div id="location-card" class="glass-effect rounded-3xl p-8 w-full max-w-sm shadow-2xl z-10">
                <div class="text-center mb-8">
                    <div id="location-icon" class="w-20 h-20 bg-white/20 rounded-full flex items-center justify-center mx-auto mb-6 location-pulse">
                        <i class="fa-solid fa-location-dot text-3xl text-white"></i>
                    </div>
                    <h2 id="card-title" class="text-2xl font-bold text-foodle-dark mb-2">Share Your Location</h2>
                    <p id="card-subtitle" class="text-foodle-secondary-text text-center leading-relaxed">
                        We need your location to find the best restaurants near you
                    </p>
                </div>

                <!-- Location Status -->
                <div id="location-status" class="mb-6 hidden">
                    <div class="flex items-center justify-center space-x-2 text-green-600 bg-green-50 rounded-lg p-3">
                        <i class="fa-solid fa-check-circle"></i>
                        <span class="font-medium">Location detected</span>
                    </div>
                </div>

                <!-- Action Buttons -->
                <div id="location-actions" class="space-y-4">
                    <button id="enable-location-btn" class="w-full bg-foodle-red hover:bg-red-500 text-white font-semibold py-4 px-6 rounded-xl transition-all duration-300 shadow-lg hover:shadow-xl transform hover:-translate-y-1 flex items-center justify-center space-x-2">
                        <i class="fa-solid fa-crosshairs"></i>
                        <span>Enable Location</span>
                    </button>
                    
                    <button id="help-btn" class="w-full bg-white/20 hover:bg-white/30 text-foodle-dark font-medium py-3 px-6 rounded-xl transition-colors border border-white/30 flex items-center justify-center space-x-2">
                        <i class="fa-solid fa-question-circle"></i>
                        <span>Need Help?</span>
                    </button>
                </div>

                <!-- Help Content (Hidden by default) -->
                <div id="help-content" class="hidden mt-6 p-4 bg-white/10 rounded-xl text-sm text-foodle-dark">
                    <p class="font-medium mb-2">📍 Location Help:</p>
                    <ul class="space-y-1 text-sm">
                        <li><strong>iPhone:</strong> Tap "Allow" when prompted</li>
                        <li><strong>Android:</strong> Tap "Allow" when prompted</li>
                    </ul>
                    <p class="mt-2 text-xs text-foodle-secondary-text">
                        If no popup appears, check browser location settings and ensure Location Services are enabled.
                    </p>
                </div>

                <!-- Location Details (Hidden by default) -->
                <div id="location-details" class="hidden mt-6 p-4 bg-green-50 rounded-xl text-sm">
                    <p class="font-medium text-green-800 mb-2">📍 Location Details:</p>
                    <div id="location-info" class="text-green-700"></div>
                </div>
            </div>

            <div id="location-footer" class="text-center mt-6 z-10">
                <p class="text-white/60 text-sm">
                    Your location is used only to find nearby restaurants
                </p>
            </div>

        </div>

        <!-- Footer - Right next to container -->

        <!-- Main JavaScript -->
        <script>
            // Configuration
            const BACKEND_URL = '${backendUrl}';
            const SESSION_TOKEN = '${token}';
            
            // Socket.IO connection
            let socket = null;
            let socketConnected = false;
            
            // UI Elements
            const enableLocationBtn = document.getElementById('enable-location-btn');
            const helpBtn = document.getElementById('help-btn');
            const helpContent = document.getElementById('help-content');
            const locationStatus = document.getElementById('location-status');
            const locationActions = document.getElementById('location-actions');
            const locationIcon = document.getElementById('location-icon');
            const cardTitle = document.getElementById('card-title');
            const cardSubtitle = document.getElementById('card-subtitle');

            let locationEnabled = false;
            
            console.log('🍔 Foodle Mobile GPS initialized');
            
            // Help button functionality
            helpBtn.addEventListener('click', () => {
                helpContent.classList.toggle('hidden');
            });

            // Enable location button functionality
            enableLocationBtn.addEventListener('click', () => {
                getHighAccuracyLocation();
            });

            function getHighAccuracyLocation() {
                if (!navigator.geolocation) {
                    showError('❌ Geolocation not supported by this browser');
                    return;
                }

                // Update UI to loading state
                enableLocationBtn.innerHTML = '<i class="fa-solid fa-spinner animate-spin"></i><span class="ml-2">Getting Location...</span>';
                enableLocationBtn.disabled = true;
                enableLocationBtn.classList.remove('bg-foodle-red', 'hover:bg-red-500');
                enableLocationBtn.classList.add('bg-gray-400');
                
                // Update icon and text
                locationIcon.innerHTML = '<i class="fa-solid fa-spinner animate-spin text-3xl text-white"></i>';
                cardTitle.textContent = 'Getting Your Location';
                cardSubtitle.textContent = 'Please allow location access when prompted...';

                // Check HTTPS requirement for iOS
                if (window.location.protocol !== 'https:' && window.location.hostname !== 'localhost') {
                    showError('⚠️ HTTPS required for location access. Make sure ngrok is running.');
                    return;
                }
                
                // Get location with high accuracy
                navigator.geolocation.getCurrentPosition(
                    function(position) {
                        const lat = position.coords.latitude;
                        const lng = position.coords.longitude;
                        const accuracy = Math.round(position.coords.accuracy);
                        
                        console.log('✅ Location obtained:', lat, lng, '±' + accuracy + 'm');
                        
                        // Update UI to success state
                        showSuccess(lat, lng, accuracy);
                        
                        // Send location to desktop
                        sendLocationToDesktop(lat, lng, accuracy);
                    },
                    function(error) {
                        let errorMessage = '❌ Location failed: ';
                        switch(error.code) {
                            case error.PERMISSION_DENIED:
                                errorMessage += 'Permission denied';
                                break;
                            case error.POSITION_UNAVAILABLE:
                                errorMessage += 'Position unavailable';
                                break;
                            case error.TIMEOUT:
                                errorMessage += 'Request timeout';
                                break;
                            default:
                                errorMessage += 'Unknown error';
                        }
                        
                        console.error('Location error:', error);
                        showError(errorMessage);
                    },
                    {
                        enableHighAccuracy: true,
                        timeout: 30000,
                        maximumAge: 0
                    }
                );
            }

            function showSuccess(lat, lng, accuracy) {
                // Update icon
                locationIcon.innerHTML = '<i class="fa-solid fa-check-circle text-3xl text-green-500"></i>';
                locationIcon.classList.remove('location-pulse', 'bg-white/20');
                locationIcon.classList.add('bg-green-100');
                
                // Update text
                cardTitle.textContent = 'Location Shared!';
                cardSubtitle.textContent = 'Your location has been sent to your computer';
                
                // Show location status
                locationStatus.classList.remove('hidden');
                
                // Hide action buttons
                locationActions.classList.add('hidden');
            }

            function showError(message) {
                // Update icon
                locationIcon.innerHTML = '<i class="fa-solid fa-exclamation-triangle text-3xl text-red-500"></i>';
                locationIcon.classList.remove('location-pulse', 'bg-white/20');
                locationIcon.classList.add('bg-red-100');
                
                // Update text
                cardTitle.textContent = 'Location Error';
                cardSubtitle.textContent = message;
                
                // Reset button
                enableLocationBtn.innerHTML = '<i class="fa-solid fa-crosshairs"></i><span class="ml-2">Try Again</span>';
                enableLocationBtn.disabled = false;
                enableLocationBtn.classList.remove('bg-gray-400');
                enableLocationBtn.classList.add('bg-foodle-red', 'hover:bg-red-500');
                
                console.error('Location error:', message);
            }
            
            // Send location to desktop
            function sendLocationToDesktop(lat, lng, accuracy) {
                if (!socket || !socketConnected) {
                    console.warn('⚠️ Socket not connected, cannot send location to desktop');
                    return;
                }
                
                console.log('📤 Sending location to desktop via socket...');
                
                socket.emit('mobile-location-update', {
                    token: SESSION_TOKEN,
                    location: {
                        latitude: lat,
                        longitude: lng,
                        accuracy: accuracy,
                        timestamp: Date.now()
                    }
                });
            }
            
            // Socket.IO initialization
            window.ioLoaded = false;
            window.ioError = null;
            
            function initializeSocket() {
                if (window.ioError || !window.ioLoaded || typeof io === 'undefined') {
                    setTimeout(initializeSocket, 1000);
                    return;
                }
                
                try {
                    console.log('🔌 Initializing socket connection...');
                    socket = io(BACKEND_URL);
                    
                    socket.on('connect', () => {
                        socketConnected = true;
                        console.log('✅ Connected to server');
                        socket.emit('join-location-session', SESSION_TOKEN);
                    });
                    
                    socket.on('disconnect', () => {
                        socketConnected = false;
                        console.log('❌ Disconnected from server');
                    });
                    
                    socket.on('location-received', (response) => {
                        console.log('🎉 Location successfully sent to computer!');
                        // UI already updated in showSuccess()
                    });

                    socket.on('error', (error) => {
                        console.error('🚨 Socket error:', error);
                    });
                } catch (error) {
                    console.error('🚨 Socket initialization error:', error);
                    socketConnected = false;
                }
            }
            
            // Initialize when ready
            if (document.readyState === 'loading') {
                document.addEventListener('DOMContentLoaded', () => {
                    setTimeout(initializeSocket, 500);
                });
            } else {
                setTimeout(initializeSocket, 500);
            }
        </script>
        
        <!-- Socket.IO script -->
        <script src="${backendUrl}/socket.io/socket.io.js" 
                onload="window.ioLoaded = true;" 
                onerror="window.ioError = 'Failed to load';">
        </script>
    </body>
    </html>
    `);
});

// Alias endpoint for frontend compatibility
app.post('/api/check-qr-needed', async (req, res) => {
    try {
        const { latitude, longitude, userId, userEmail } = req.body;
        
        console.log('🔍 Location check request (via check-qr-needed alias):', { latitude, longitude, userId, userEmail });
        
        // Special case: If no coordinates provided, check based on user's stored location age
        if (!latitude || !longitude) {
            let user = null;
            
            // Try to find user by session first (authenticated users)
            if (req.session && req.session.email) {
                user = await User.findOne({ email: req.session.email });
                console.log('🔍 Found authenticated user for no-GPS check:', req.session.email);
            }
            
            // If no authenticated user but we have userEmail from request, try to find by email
            if (!user && userEmail && userEmail !== 'demo@foodle.com') {
                user = await User.findOne({ email: userEmail });
                console.log('🔍 Found user by provided email for no-GPS check:', userEmail);
            }
            
            // If no user found or no stored location, show QR
            if (!user || !user.lastKnownLocation || 
                user.lastKnownLocation.latitude === null || 
                user.lastKnownLocation.longitude === null) {
                console.log('🔍 No user or stored location - showing QR');
                return res.json({ 
                    showQR: true,
                    reason: user ? 'no_stored_location' : 'no_user_found',
                    message: 'Location sharing needed'
                });
            }
            
            // Check how old the stored location is (older than 24 hours = show QR)
            const locationAge = Date.now() - new Date(user.lastKnownLocation.timestamp).getTime();
            const hoursOld = locationAge / (1000 * 60 * 60);
            const showQR = hoursOld > 24; // Show QR if location is older than 24 hours
            
            console.log('🔍 Stored location age check:', Math.round(hoursOld), 'hours old, showQR:', showQR);
            
            return res.json({
                showQR,
                reason: showQR ? 'location_too_old' : 'stored_location_recent',
                hoursOld: Math.round(hoursOld),
                threshold: 24,
                storedLocation: {
                    latitude: user.lastKnownLocation.latitude,
                    longitude: user.lastKnownLocation.longitude,
                    timestamp: user.lastKnownLocation.timestamp
                }
            });
        }

        let user = null;
        
        // Try to find user by session first (authenticated users)
        if (req.session && req.session.email) {
            user = await User.findOne({ email: req.session.email });
            console.log('🔍 Found authenticated user:', req.session.email);
        }
        
        // If no authenticated user but we have userEmail from request, try to find by email
        if (!user && userEmail && userEmail !== 'demo@foodle.com') {
            user = await User.findOne({ email: userEmail });
            console.log('🔍 Found user by provided email:', userEmail);
        }
        
        // If no user found, show QR (first time or demo user)
        if (!user) {
            console.log('🔍 No user found - showing QR (first time or demo user)');
            return res.json({ 
                showQR: true,
                reason: 'no_user_found',
                message: 'New user or demo mode - location sharing needed'
            });
        }
        
        // Check if the user's location is already stored
        if (user.lastKnownLocation && 
            user.lastKnownLocation.latitude !== null && 
            user.lastKnownLocation.longitude !== null) {
            // Calculate distance from current location to last known location
            const distance = calculateDistanceBetweenCoords(
                latitude, longitude,
                user.lastKnownLocation.latitude, user.lastKnownLocation.longitude
            );

            console.log('🔍 Location check - Distance to last known location:', Math.round(distance), 'meters');

            const DISTANCE_THRESHOLD = 5000; // 5000 meters = 5km
            const showQR = distance > DISTANCE_THRESHOLD;

            console.log('🔍 Location check - Show QR:', showQR, '(threshold: ' + DISTANCE_THRESHOLD + 'm)');

            return res.json({
                showQR,
                reason: showQR ? 'location_changed' : 'same_location',
                distance: Math.round(distance),
                threshold: DISTANCE_THRESHOLD,
                storedLocation: {
                    latitude: user.lastKnownLocation.latitude,
                    longitude: user.lastKnownLocation.longitude,
                    timestamp: user.lastKnownLocation.timestamp
                }
            });
        } else {
            // No valid stored location, show QR code
            console.log('🔍 No valid stored location - showing QR code');
            return res.json({ 
                showQR: true,
                reason: 'no_valid_stored_location',
                message: 'Location sharing needed'
            });
        }

    } catch (error) {
        console.error('❌ Location check error:', error);
        res.status(500).json({ 
            showQR: true, 
            reason: 'server_error',
            error: error.message 
        });
    }
});

// Location checking endpoint - determines if QR code should be shown
app.post('/api/check-location-needed', async (req, res) => {
    try {
        const { latitude, longitude, userId, userEmail } = req.body;
        
        console.log('🔍 Location check request:', { latitude, longitude, userId, userEmail });
        
        // Special case: If no coordinates provided, check based on user's stored location age
        if (!latitude || !longitude) {
            let user = null;
            
            // Try to find user by session first (authenticated users)
            if (req.session && req.session.email) {
                user = await User.findOne({ email: req.session.email });
                console.log('🔍 Found authenticated user for no-GPS check:', req.session.email);
            }
            
            // If no authenticated user but we have userEmail from request, try to find by email
            if (!user && userEmail && userEmail !== 'demo@foodle.com') {
                user = await User.findOne({ email: userEmail });
                console.log('🔍 Found user by provided email for no-GPS check:', userEmail);
            }
            
            // If no user found or no stored location, show QR
            if (!user || !user.lastKnownLocation || 
                user.lastKnownLocation.latitude === null || 
                user.lastKnownLocation.longitude === null) {
                console.log('🔍 No user or stored location - showing QR');
                return res.json({ 
                    showQR: true,
                    reason: user ? 'no_stored_location' : 'no_user_found',
                    message: 'Location sharing needed'
                });
            }
            
            // Check how old the stored location is (older than 24 hours = show QR)
            const locationAge = Date.now() - new Date(user.lastKnownLocation.timestamp).getTime();
            const hoursOld = locationAge / (1000 * 60 * 60);
            const showQR = hoursOld > 24; // Show QR if location is older than 24 hours
            
            console.log('🔍 Stored location age check:', Math.round(hoursOld), 'hours old, showQR:', showQR);
            
            return res.json({
                showQR,
                reason: showQR ? 'location_too_old' : 'stored_location_recent',
                hoursOld: Math.round(hoursOld),
                threshold: 24,
                storedLocation: {
                    latitude: user.lastKnownLocation.latitude,
                    longitude: user.lastKnownLocation.longitude,
                    timestamp: user.lastKnownLocation.timestamp
                }
            });
        }

        let user = null;
        
        // Try to find user by session first (authenticated users)
        if (req.session && req.session.email) {
            user = await User.findOne({ email: req.session.email });
            console.log('🔍 Found authenticated user:', req.session.email);
        }
        
        // If no authenticated user but we have userEmail from request, try to find by email
        if (!user && userEmail && userEmail !== 'demo@foodle.com') {
            user = await User.findOne({ email: userEmail });
            console.log('🔍 Found user by provided email:', userEmail);
        }
        
        // If no user found, show QR (first time or demo user)
        if (!user) {
            console.log('🔍 No user found - showing QR (first time or demo user)');
            return res.json({ 
                showQR: true,
                reason: 'no_user_found',
                message: 'New user or demo mode - location sharing needed'
            });
        }
        
        // Check if the user's location is already stored
        if (user.lastKnownLocation && 
            user.lastKnownLocation.latitude !== null && 
            user.lastKnownLocation.longitude !== null) {
            // Calculate distance from current location to last known location
            const distance = calculateDistanceBetweenCoords(
                latitude, longitude,
                user.lastKnownLocation.latitude, user.lastKnownLocation.longitude
            );

            console.log('🔍 Location check - Distance to last known location:', Math.round(distance), 'meters');

            const DISTANCE_THRESHOLD = 5000; // 5000 meters = 5km
            const showQR = distance > DISTANCE_THRESHOLD;

            console.log('🔍 Location check - Show QR:', showQR, '(threshold: ' + DISTANCE_THRESHOLD + 'm)');

            return res.json({
                showQR,
                reason: showQR ? 'location_changed' : 'same_location',
                distance: Math.round(distance),
                threshold: DISTANCE_THRESHOLD,
                storedLocation: {
                    latitude: user.lastKnownLocation.latitude,
                    longitude: user.lastKnownLocation.longitude,
                    timestamp: user.lastKnownLocation.timestamp
                }
            });
        } else {
            // No valid stored location, show QR code
            console.log('🔍 No valid stored location - showing QR code');
            return res.json({ 
                showQR: true,
                reason: 'no_valid_stored_location',
                message: 'Location sharing needed'
            });
        }

    } catch (error) {
        console.error('❌ Location check error:', error);
        res.status(500).json({ 
            showQR: true, 
            reason: 'server_error',
            error: error.message 
        });
    }
});

// Debug endpoint to test restaurant finding
app.post('/api/debug-restaurants', async (req, res) => {
    try {
        const { latitude, longitude, radius } = req.body;
        
        if (!latitude || !longitude) {
            return res.status(400).json({ message: 'Latitude and longitude are required.' });
        }

        const apiKey = process.env.GOOGLE_PLACES_API_KEY;
        if (!apiKey) {
            console.error('❌ Google Places API key is missing in debug endpoint');
            return res.status(500).json({ 
                message: 'Server configuration error: Google Places API key is missing.',
                debug: 'Check your .env file contains: GOOGLE_PLACES_API_KEY=your_api_key_here'
            });
        }
        
        const searchRadius = radius || 2000;
        
        // Find nearby restaurants
        const restaurants = await findNearbyRestaurants(latitude, longitude, searchRadius, apiKey);
        
        res.json({
            message: 'Debug restaurants found',
            count: restaurants.length,
            location: { latitude, longitude },
            radius: searchRadius,
            restaurants: restaurants.slice(0, 5) // First 5 for debug
        });

    } catch (error) {
        console.error('❌ Debug restaurants error:', error);
        res.status(500).json({ 
            message: 'Failed to find debug restaurants.',
            error: error.message 
        });
    }
});

// Direct restaurant recommendation endpoint (POST) - Main endpoint  
// Supports both regular requests and "Generate Another" functionality via flag
// Body: { latitude: number, longitude: number, message: string, preferences?: object, generateAnother?: boolean }
app.post('/api/recommend-restaurant', async (req, res) => {
    try {
        console.log(`\n🔥 API Request | Generate Another: ${!!req.body.generateAnother}`);
        
        // FILTER DEBUG - Check what we received
        console.log(`� Request Structure:`);
        console.log(`  - preferences.filters: ${!!req.body.preferences?.filters ? 'YES' : 'NO'}`);
        console.log(`  - direct filters: ${!!req.body.filters ? 'YES' : 'NO'}`);
        console.log(`  - direct priceLevel: ${req.body.priceLevel !== undefined ? 'YES' : 'NO'}`);
        
        let { latitude, longitude, preferences, message, location, generateAnother } = req.body;
        
        // Fix preferences structure if needed
        if (!preferences || typeof preferences !== 'object') {
            preferences = {};
        }
        
        // Try to find filters in different locations
        let filtersFound = false;
        
        if (!preferences.filters && req.body.filters) {
            preferences.filters = req.body.filters;
            filtersFound = true;
        }
        
        if (!filtersFound && req.body.priceLevel !== undefined) {
            preferences.filters = {
                priceLevel: req.body.priceLevel,
                maxDistance: req.body.maxDistance,
                category: req.body.category,
                minRating: req.body.minRating,
                maxRating: req.body.maxRating
            };
            filtersFound = true;
        }
        
        if (!filtersFound && preferences.priceLevel !== undefined) {
            preferences.filters = {
                priceLevel: preferences.priceLevel,
                maxDistance: preferences.maxDistance,
                category: preferences.category,
                minRating: preferences.minRating,
                maxRating: preferences.maxRating
            };
            filtersFound = true;
        }
        
        console.log(`🎯 Filters detected: ${filtersFound ? 'YES' : 'NO'}`);
        if (filtersFound && preferences.filters) {
            const filterDetails = [];
            if (preferences.filters.priceLevel) filterDetails.push(`Price: ${preferences.filters.priceLevel}`);
            if (preferences.filters.maxDistance) filterDetails.push(`Distance: ${preferences.filters.maxDistance}km`);
            if (preferences.filters.category) filterDetails.push(`Category: ${preferences.filters.category}`);
            if (preferences.filters.minRating) filterDetails.push(`MinRating: ${preferences.filters.minRating}`);
            if (preferences.filters.maxRating) filterDetails.push(`MaxRating: ${preferences.filters.maxRating}`);
            console.log(`🎯 Active filters: ${filterDetails.join(', ')}`);
        }
        
        // COMPREHENSIVE FILTER LOGGING FOR DEBUGGING
        console.log(`\n🔧 ===== COMPLETE FILTER DEBUG =====`);
        console.log(`🔧 RAW REQUEST BODY:`);
        console.log(`  - req.body.preferences:`, req.body.preferences);
        console.log(`  - req.body.filters:`, req.body.filters);
        console.log(`  - req.body.priceLevel:`, req.body.priceLevel);
        console.log(`  - req.body.maxDistance:`, req.body.maxDistance);
        console.log(`  - req.body.category:`, req.body.category);
        console.log(`  - req.body.minRating:`, req.body.minRating);
        console.log(`  - req.body.maxRating:`, req.body.maxRating);
        console.log(`🔧 PROCESSED FILTERS:`);
        console.log(`  - preferences.filters:`, preferences.filters);
        console.log(`🔧 ===== END FILTER DEBUG =====\n`);
        
        // Handle both location formats from frontend
        if (location && typeof location === 'object') {
            latitude = location.latitude;
            longitude = location.longitude;
        }

        const apiKey = process.env.GOOGLE_PLACES_API_KEY;
        if (!apiKey) {
            console.error('❌ Google Places API key is missing');
            return res.status(500).json({ 
                message: 'Server configuration error: Google Places API key is missing.',
                debug: 'Check your .env file contains: GOOGLE_PLACES_API_KEY=your_api_key_here'
            });
        }
        
        // Get user information first (for location and preferences)
        let user = null;
        
        // Try to get user from session first
        if (req.session && req.session.email) {
            try {
                user = await User.findOne({ email: req.session.email });
                console.log(`🤖 Found user from session: ${user?.firstName} ${user?.lastName}`);
            } catch (error) {
                console.error('❌ Error fetching user from session:', error);
            }
        }
        
        // PRIORITY 1: Use user's stored lastKnownLocation if available
        if (user && user.lastKnownLocation && 
            user.lastKnownLocation.latitude && user.lastKnownLocation.longitude) {
            
            const storedLat = user.lastKnownLocation.latitude;
            const storedLng = user.lastKnownLocation.longitude;
            
            // Check if we have a provided location to compare with
            if (latitude && longitude) {
                // Calculate distance between stored and provided location
                const distance = calculateDistance(storedLat, storedLng, latitude, longitude);
                const distanceKm = distance;
                
                console.log(`🤖 Distance check: stored location vs provided location = ${distanceKm.toFixed(2)}km`);
                
                if (distanceKm <= 5.0) {
                    // Use stored location if within 5km of provided location
                    console.log(`🤖 Using stored location (within ${distanceKm.toFixed(2)}km of provided):`, {
                        lat: storedLat,
                        lng: storedLng,
                        source: user.lastKnownLocation.source
                    });
                    
                    latitude = storedLat;
                    longitude = storedLng;
                } else {
                    // Provided location is significantly different, use it and update stored location
                    console.log(`🤖 Provided location is ${distanceKm.toFixed(2)}km away from stored, using provided location`);
                    console.log(`🤖 Will update stored location from (${storedLat}, ${storedLng}) to (${latitude}, ${longitude})`);
                }
            } else {
                // No provided location, always use stored location regardless of age
                const locationAge = Date.now() - new Date(user.lastKnownLocation.timestamp).getTime();
                const hoursOld = locationAge / (1000 * 60 * 60);
                
                console.log(`🤖 No provided location, using stored location (${hoursOld.toFixed(1)}h old):`, {
                    lat: storedLat,
                    lng: storedLng,
                    source: user.lastKnownLocation.source
                });
                
                latitude = storedLat;
                longitude = storedLng;
            }
        }
        
        // PRIORITY 2: Use provided coordinates if no stored location or stored location is old
        if (!latitude || !longitude) {
            console.log('🤖 No coordinates provided and no stored location available');
            return res.status(400).json({ 
                message: 'Location required. Please share your location first.',
                showLocationPrompt: true,
                debug: {
                    userFound: !!user,
                    hasStoredLocation: !!(user?.lastKnownLocation),
                    sessionEmail: req.session?.email
                }
            });
        }
        
        // Dynamic search radius based on user filter preferences
        const maxDistanceKm = preferences?.filters?.maxDistance || 5; // Default to 5km if no filter
        const searchRadius = Math.min(maxDistanceKm * 1000, 5000); // Convert km to meters, max 5km for API limits
        
        console.log(`🤖 Final coordinates for search and calculations: ${latitude}, ${longitude}`);
        console.log(`🤖 Search radius: ${searchRadius}m (${maxDistanceKm}km from filter - all restaurants will be within this radius)`);
        console.log(`🤖 Preferences:`, preferences);
        console.log(`🤖 Message:`, message);
        
        // Set up user preferences and history (user already loaded above)
        let userPreferences = {
            cuisines: [],
            priceRange: '$$',
            dietType: null,
            allergies: []
        };
        let userHistory = {
            recentVisits: [],
            favorites: [],
            reviews: []
        };
        
        // Extract user preferences if available (user already loaded above)
        if (user) {
            console.log(`🤖 Processing preferences for user: ${user.firstName} ${user.lastName}`);
            // Extract user preferences if available
            if (user.preferences) {
                userPreferences = { ...userPreferences, ...user.preferences };
            }
            if (user.history) {
                userHistory = { ...userHistory, ...user.history };
            }
        } else {
            console.log('🤖 No user found, using anonymous recommendations');
        }
        
        // Merge request preferences with user preferences
        const finalPreferences = { ...userPreferences, ...preferences };
        
        // CRITICAL: Ensure filters are properly carried forward after all our fixes
        if (!finalPreferences.filters && preferences.filters) {
            finalPreferences.filters = preferences.filters;
        }
        
        console.log(`🎯 Final Filters: ${!!finalPreferences?.filters ? 'YES' : 'NO'} | Price: ${finalPreferences?.filters?.priceLevel || 'None'} | Distance: ${finalPreferences?.filters?.maxDistance || 'Default'}km`);
        
        console.log(`🤖 📍 USER LOCATION FOR ALL CALCULATIONS: lat=${latitude}, lng=${longitude}`);
        
        // Find nearby restaurants
        const restaurants = await findNearbyRestaurants(latitude, longitude, searchRadius, apiKey);
        
        if (!restaurants || restaurants.length === 0) {
            return res.status(404).json({ 
                message: 'No restaurants found in your area. Try expanding the search radius.',
                location: { latitude, longitude },
                radius: searchRadius
            });
        }
        
        console.log(`🍽️ Found ${restaurants.length} restaurants nearby`);
        
        // Apply AI-powered filtering and ranking with detailed restaurant information
        let aiResult;
        try {
            aiResult = await selectBestRestaurantWithAI(restaurants, finalPreferences, message, user, req.session, generateAnother);
        } catch (error) {
            console.error(`❌ AI function threw error:`, error);
            throw error;
        }
        
        let bestRestaurant = aiResult?.restaurant;
        let debuggingData = aiResult?.debuggingData;
        
        // Select the best restaurant
        if (!bestRestaurant) {
            console.log('❌ No suitable restaurant found after AI analysis');
            
            // Check if this is because all restaurants were filtered out due to session memory
            const sessionRecommendations = req.session?.recommendedRestaurants || [];
            if (sessionRecommendations.length > 0 && restaurants.length > 0) {
                console.log('🔄 All suitable restaurants already recommended this session, clearing session memory');
                req.session.recommendedRestaurants = [];
                
                // Retry AI analysis without session memory
                const retryResult = await selectBestRestaurantWithAI(restaurants, finalPreferences, message, user, req.session, generateAnother);
                
                if (retryResult?.restaurant) {
                    console.log(`🔄 Found restaurant after clearing session memory: ${retryResult.restaurant.name}`);
                    bestRestaurant = retryResult.restaurant;
                    debuggingData = retryResult.debuggingData;
                } else {
                    return res.status(404).json({ 
                        message: 'No suitable restaurants found matching your preferences.',
                        totalFound: restaurants.length,
                        preferences: finalPreferences,
                        sessionRecommendations: sessionRecommendations.length
                    });
                }
            } else {
                return res.status(404).json({ 
                    message: 'No suitable restaurants found matching your preferences.',
                    totalFound: restaurants.length,
                    preferences: finalPreferences,
                    sessionRecommendations: sessionRecommendations.length
                });
            }
        }
        
        console.log(`🔍 Enhancing restaurant: ${bestRestaurant.name} (AI selected)`);
        console.log(`🔍 Restaurant price data:`, {
            priceLevel: bestRestaurant.priceLevel,
            price_level: bestRestaurant.price_level,
            typeof_priceLevel: typeof bestRestaurant.priceLevel,
            typeof_price_level: typeof bestRestaurant.price_level
        });
        
        // Get detailed restaurant information
        const details = await getRestaurantDetails(bestRestaurant.placeId, apiKey);
        
        // Calculate walking time using user's actual location
        console.log(`🚶 📍 WALKING TIME CALCULATION:`);
        console.log(`🚶 📍 FROM USER LOCATION: (${latitude}, ${longitude})`);
        console.log(`🚶 📍 TO RESTAURANT: ${bestRestaurant.name} at (${bestRestaurant.latitude}, ${bestRestaurant.longitude})`);
        const walkingTimeInfo = await calculateWalkingTime(
            latitude, longitude, 
            bestRestaurant.latitude, bestRestaurant.longitude, 
            apiKey
        );
        
        // Process photos
        const photos = processRestaurantPhotos(details.photos || [], apiKey);
        console.log(`📸 Photos processing for ${bestRestaurant.name}:`, {
            photosFromAPI: details.photos?.length || 0,
            processedPhotos: photos.length,
            firstPhotoUrl: photos[0]?.url || 'None'
        });
        
        // Build complete restaurant object matching frontend expectations
        const enhancedRestaurant = {
            name: bestRestaurant.name,
            address: details.address || bestRestaurant.address,
            rating: bestRestaurant.rating || 'N/A',
            reviewCount: bestRestaurant.reviewCount || 0,
            cuisine: getCuisineType(bestRestaurant.types || []),
            diningStyle: getDiningType(bestRestaurant.types || [], bestRestaurant.priceLevel),
            distance: bestRestaurant.distanceText || formatDistance(bestRestaurant.distance),
            website: details.website || null,
            walkingTime: walkingTimeInfo.duration || 'N/A',
            walkingDistance: walkingTimeInfo.distance || bestRestaurant.distanceText,
            directions: walkingTimeInfo.steps || [],
            photos: photos.map(photo => photo.url), // Send simple URL array to frontend
            priceLevel: (() => {
                const pl = bestRestaurant.priceLevel ?? bestRestaurant.price_level ?? details.priceLevel ?? details.price_level;
                
                // Convert to standard 1-4 scale for display: 1=$, 2=$$, 3=$$$, 4=$$$$
                if (typeof pl === 'number' && pl >= 0 && pl <= 4) {
                    // Google Places: 0=Free, 1=Inexpensive, 2=Moderate, 3=Expensive, 4=Very Expensive
                    // Our Display: 1=$, 2=$$, 3=$$$, 4=$$$$
                    // Mapping: Google 0,1 -> Our 1($), Google 2 -> Our 2($$), Google 3 -> Our 3($$$), Google 4 -> Our 4($$$$)
                    if (pl === 0 || pl === 1) {
                        return '$';
                    } else if (pl === 2) {
                        return '$$';
                    } else if (pl === 3) {
                        return '$$$';
                    } else if (pl === 4) {
                        return '$$$$';
                    }
                }
                
                return '$$'; // Return moderate price level as default instead of null
            })(),
            phone: details.phone || null,
            openingHours: details.openingHours || null,
            placeId: bestRestaurant.placeId,
            latitude: bestRestaurant.latitude,
            longitude: bestRestaurant.longitude,
            recommendationScore: bestRestaurant.recommendationScore,
            recommendationReason: bestRestaurant.recommendationReason
        };

        // Generate simple recommendation message (AI already handled selection)
        const aiMessage = `I found ${enhancedRestaurant.name}! This ${enhancedRestaurant.cuisine} restaurant has ${enhancedRestaurant.rating} stars and is ${enhancedRestaurant.walkingTime} away. ${enhancedRestaurant.recommendationReason || 'It looks like a great match for your request!'}`;

        console.log(`✅ Enhanced restaurant complete:`, {
            name: enhancedRestaurant.name,
            cuisine: enhancedRestaurant.cuisine,
            diningStyle: enhancedRestaurant.diningStyle,
            rating: enhancedRestaurant.rating,
            reviewCount: enhancedRestaurant.reviewCount,
            priceLevel: enhancedRestaurant.priceLevel,
            walkingTime: enhancedRestaurant.walkingTime,
            walkingDistance: enhancedRestaurant.walkingDistance,
            straightLineDistance: enhancedRestaurant.distance,
            photosCount: enhancedRestaurant.photos.length,
            hasWebsite: !!enhancedRestaurant.websiteLink,
            score: enhancedRestaurant.recommendationScore,
            userLocation: `${latitude}, ${longitude}`,
            restaurantLocation: `${bestRestaurant.latitude}, ${bestRestaurant.longitude}`
        });
        
        // Session debugging and preservation
        console.log(`🤖 Session before processing:`, {
            id: req.session?.id,
            email: req.session?.email,
            cookie: req.session?.cookie
        });
        
        // Force session save to ensure it persists
        if (req.session) {
            req.session.lastAccessed = new Date();
            req.session.touch(); // Update the session expiration
            
            // Add this restaurant to session memory to prevent immediate repeats
            if (!req.session.recommendedRestaurants) {
                req.session.recommendedRestaurants = [];
            }
            // Store both placeId and name for better exclusion handling
            req.session.recommendedRestaurants.push({
                placeId: bestRestaurant.placeId,
                name: bestRestaurant.name
            });
            
            // Keep only the last 20 recommendations to prevent memory bloat
            if (req.session.recommendedRestaurants.length > 20) {
                req.session.recommendedRestaurants = req.session.recommendedRestaurants.slice(-20);
            }
            
            console.log(`🧠 Session memory updated: ${req.session.recommendedRestaurants.length} restaurants remembered`);
            console.log(`🔍 SESSION STRUCTURE SAMPLE:`, req.session.recommendedRestaurants.slice(-3).map(rec => 
                typeof rec === 'string' ? `OLD: ${rec}` : `NEW: ${rec.name} (${rec.placeId})`
            ));
        }
        
        res.json({
            restaurant: enhancedRestaurant,
            aiMessage: aiMessage,
            userFound: !!user,
            userEmail: user?.email,
            sessionPreserved: !!req.session?.email,
            sessionId: req.session?.id,
            coordinatesUsed: {
                search: `${latitude}, ${longitude}`,
                distance: `${latitude}, ${longitude}`,
                walking: `${latitude}, ${longitude}`,
                source: user?.lastKnownLocation?.source || 'request'
            },
            sessionMemory: {
                restaurantsRemembered: req.session?.recommendedRestaurants?.length || 0,
                thisRecommendation: bestRestaurant.placeId
            },
            debug: {
                sessionId: req.session?.id,
                sessionEmail: req.session?.email,
                requestHadSession: !!req.session,
                sessionCookie: req.session?.cookie
            },
            foodleDebug: debuggingData // This will appear in browser console for debugging
        });
        
        // Log session memory array for exclusion debugging
        if (req.session?.recommendedRestaurants) {
            const recentRecs = req.session.recommendedRestaurants.slice(-10); // Show last 10
            console.log(`🧠 Session exclusion array (${req.session.recommendedRestaurants.length} total):`, 
                recentRecs.map(rec => typeof rec === 'string' ? rec : rec.name).join(', ')
            );
        }
        
        // Save session after response
        if (req.session) {
            req.session.save((err) => {
                if (err) {
                    console.error('❌ Session save error after response:', err);
                } else {
                    console.log('✅ Session saved successfully after response');
                }
            });
        }

    } catch (error) {
        console.error('❌ Recommendation endpoint error:', error);
        res.status(500).json({ message: 'Failed to get restaurant recommendations.', error: error.message });
    }
});

// Restaurant recommendation endpoint (GET) - for compatibility
app.get('/api/recommend-restaurant', async (req, res) => {
    try {
        const { latitude, longitude, preferences, message } = req.query;
        
        if (!latitude || !longitude) {
            return res.status(400).json({ message: 'Latitude and longitude are required.' });
        }

        // Convert GET parameters to POST format
        const requestBody = {
            latitude: parseFloat(latitude),
            longitude: parseFloat(longitude),
            preferences: preferences ? JSON.parse(preferences) : {},
            message: message || 'Looking for restaurant recommendations'
        };

        // Set request body and forward to POST handler
        req.body = requestBody;
        req.method = 'POST';
        
        // Forward to POST endpoint
        return app._router.handle(req, res);

    } catch (error) {
        console.error('❌ GET Recommendation endpoint error:', error);
        res.status(500).json({ message: 'Failed to get restaurant recommendations.' });
    }
});

// Enhanced schema for tracking user recommendations
const userRecommendationSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    restaurantId: { type: String, required: true }, // Google Places ID
    restaurantName: String,
    recommendedAt: { type: Date, default: Date.now },
    sessionId: String,
    preferences: {
        cuisines: [String],
        priceRange: String,
        dietType: String
    },
    rating: Number,
    acceptedRecommendation: { type: Boolean, default: false }
});

const UserRecommendation = mongoose.model('UserRecommendation', userRecommendationSchema);

// Enhanced restaurant filtering - eliminate non-restaurants immediately
function isActualRestaurant(types) {
    if (!types || !Array.isArray(types)) return false;
    
    // HARD EXCLUDE: These are definitely not restaurants
    const hardExcludes = [
        'gas_station', 'bank', 'atm', 'hospital', 'pharmacy', 'doctor',
        'dentist', 'veterinary_care', 'car_repair', 'store', 'supermarket',
        'clothing_store', 'electronics_store', 'furniture_store', 'gym',
        'hair_care', 'beauty_salon', 'spa', 'church', 'mosque', 'synagogue',
        'school', 'university', 'library', 'post_office', 'police'
    ];
    
    // Check for hard excludes first
    if (types.some(type => hardExcludes.includes(type))) {
        return false;
    }
    
    // ACTUAL RESTAURANTS: Full-service dining
    const fullServiceRestaurants = [
        'restaurant', 'establishment', 'food', 'point_of_interest'
    ];
    
    // FAST FOOD: Quick service but still food
    const fastFood = [
        'meal_takeaway', 'meal_delivery'
    ];
    
    // BARS/CAFES: Food secondary
    const barsAndCafes = [
        'bar', 'night_club', 'cafe', 'bakery'
    ];
    
    // Must have at least one food-related type
    const hasFoodType = types.some(type => 
        fullServiceRestaurants.includes(type) || 
        fastFood.includes(type) || 
        barsAndCafes.includes(type)
    );
    
    return hasFoodType;
}

// Smart restaurant categorization for filtering
function getRestaurantCategory(types) {
    if (!types || !Array.isArray(types)) return 'unknown';
    
    // Priority order matters here
    if (types.includes('meal_takeaway') || types.includes('meal_delivery')) {
        return 'fast_food';
    }
    if (types.includes('bar') || types.includes('night_club')) {
        return 'bar';
    }
    if (types.includes('cafe') || types.includes('bakery')) {
        return 'cafe';
    }
    if (types.includes('restaurant') || types.includes('establishment')) {
        return 'restaurant';
    }
    
    return 'restaurant'; // Default to restaurant if food-related
}

// Extremely lightweight cuisine detection for pre-filtering
function getSimpleCuisine(types, name) {
    if (!types) types = [];
    const allText = [...types, name || ''].join(' ').toLowerCase();
    
    // Only detect the most obvious cuisines to reduce pool
    if (allText.includes('pizza') || allText.includes('italian')) return 'italian';
    if (allText.includes('chinese') || allText.includes('asian')) return 'chinese';
    if (allText.includes('mexican') || allText.includes('taco')) return 'mexican';
    if (allText.includes('japanese') || allText.includes('sushi')) return 'japanese';
    if (allText.includes('indian') || allText.includes('curry')) return 'indian';
    if (allText.includes('thai')) return 'thai';
    if (allText.includes('burger') || allText.includes('american')) return 'american';
    
    return 'general'; // Most restaurants fall here
}

// Ultra-fast user intent detection
function detectUserIntent(message) {
    if (!message) return { type: 'general', cuisine: null, category: null };
    
    const msg = message.toLowerCase();
    
    // Detect specific cuisine requests
    const cuisines = {
        'pizza': 'italian', 'italian': 'italian',
        'chinese': 'chinese', 'asian': 'chinese',
        'mexican': 'mexican', 'taco': 'mexican',
        'sushi': 'japanese', 'japanese': 'japanese',
        'indian': 'indian', 'curry': 'indian',
        'thai': 'thai',
        'burger': 'american', 'american': 'american'
    };
    
    // Detect category preferences
    const categories = {
        'fast food': 'fast_food', 'quick': 'fast_food', 'takeaway': 'fast_food',
        'bar': 'bar', 'drinks': 'bar', 'nightlife': 'bar',
        'cafe': 'cafe', 'coffee': 'cafe', 'bakery': 'cafe'
    };
    
    // Find matches
    let detectedCuisine = null;
    let detectedCategory = null;
    
    for (const [keyword, cuisine] of Object.entries(cuisines)) {
        if (msg.includes(keyword)) {
            detectedCuisine = cuisine;
            break;
        }
    }
    
    for (const [keyword, category] of Object.entries(categories)) {
        if (msg.includes(keyword)) {
            detectedCategory = category;
            break;
        }
    }
    
    return {
        type: detectedCuisine || detectedCategory ? 'specific' : 'general',
        cuisine: detectedCuisine,
        category: detectedCategory
    };
}

// Comprehensive cuisine list for random selection
const AVAILABLE_CUISINES = [
    'italian', 'chinese', 'mexican', 'japanese', 'indian', 'american', 'thai',
    'french', 'korean', 'vietnamese', 'mediterranean', 'greek', 'spanish',
    'middle_eastern', 'turkish', 'brazilian', 'german', 'british', 'seafood',
    'bbq', 'steakhouse', 'vegetarian', 'pizza', 'burger', 'sushi', 'ramen'
];

// Smart random cuisine selection - finds cuisines that actually exist in the geographic range
async function findRandomCuisineWithRestaurants(restaurants, userFilters, maxAttempts = 10) {
    console.log(`🎲 ===== SMART RANDOM CUISINE SELECTION =====`);
    console.log(`🎲 Starting random cuisine search with ${restaurants.length} total restaurants`);
    console.log(`🎲 User filters:`, userFilters);
    
    // Create a shuffled copy of cuisines for random selection
    const shuffledCuisines = [...AVAILABLE_CUISINES];
    for (let i = shuffledCuisines.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [shuffledCuisines[i], shuffledCuisines[j]] = [shuffledCuisines[j], shuffledCuisines[i]];
    }
    
    for (let attempt = 0; attempt < maxAttempts && attempt < shuffledCuisines.length; attempt++) {
        const randomCuisine = shuffledCuisines[attempt];
        console.log(`🎲 Attempt ${attempt + 1}: Testing cuisine "${randomCuisine}"`);
        
        // Filter restaurants by this cuisine
        let cuisineRestaurants = restaurants.filter(r => {
            const restaurantCuisine = getSimpleCuisine(r.types, r.name);
            return restaurantCuisine === randomCuisine;
        });
        
        console.log(`🎲 Found ${cuisineRestaurants.length} restaurants for "${randomCuisine}" cuisine`);
        
        if (cuisineRestaurants.length === 0) {
            console.log(`🎲 ❌ No "${randomCuisine}" restaurants found, trying next cuisine...`);
            continue;
        }
        
        // Apply user's filters to this cuisine's restaurants
        if (userFilters) {
            const originalCount = cuisineRestaurants.length;
            
            // Apply price filter
            if (userFilters.priceLevel !== undefined && userFilters.priceLevel !== null) {
                cuisineRestaurants = cuisineRestaurants.filter(r => {
                    const restaurantPrice = r.priceLevel || r.price_level || 1;
                    return restaurantPrice === userFilters.priceLevel;
                });
                console.log(`🎲 After price filter (${'$'.repeat(userFilters.priceLevel)}): ${cuisineRestaurants.length} restaurants`);
            }
            
            // Apply distance filter
            if (userFilters.maxDistance) {
                cuisineRestaurants = cuisineRestaurants.filter(r => (r.distance || 0) <= userFilters.maxDistance);
                console.log(`🎲 After distance filter (${userFilters.maxDistance}km): ${cuisineRestaurants.length} restaurants`);
            }
            
            // Apply rating filter
            if (userFilters.minRating || userFilters.maxRating) {
                cuisineRestaurants = cuisineRestaurants.filter(r => {
                    const rating = r.rating || 0;
                    return rating >= (userFilters.minRating || 0) && rating <= (userFilters.maxRating || 5);
                });
                console.log(`🎲 After rating filter (${userFilters.minRating || 0}-${userFilters.maxRating || 5}⭐): ${cuisineRestaurants.length} restaurants`);
            }
            
            // Apply category filter
            if (userFilters.category && userFilters.category !== 'any') {
                cuisineRestaurants = cuisineRestaurants.filter(r => {
                    const restaurantCategory = getRestaurantCategory(r.types);
                    return restaurantCategory === userFilters.category;
                });
                console.log(`🎲 After category filter (${userFilters.category}): ${cuisineRestaurants.length} restaurants`);
            }
            
            if (cuisineRestaurants.length === 0) {
                console.log(`🎲 ❌ All "${randomCuisine}" restaurants eliminated by filters, trying next cuisine...`);
                continue;
            }
        }
        
        console.log(`🎲 ✅ SUCCESS! Found ${cuisineRestaurants.length} "${randomCuisine}" restaurants that match all filters`);
        console.log(`🎲 ===== END RANDOM CUISINE SELECTION =====`);
        return {
            cuisine: randomCuisine,
            restaurants: cuisineRestaurants,
            totalAttempts: attempt + 1
        };
    }
    
    console.log(`🎲 ❌ FAILED: No cuisine found with restaurants matching filters after ${maxAttempts} attempts`);
    console.log(`🎲 ===== END RANDOM CUISINE SELECTION =====`);
    return null;
}

// Analyze user input to understand intent and type
function analyzeUserInput(message) {
    if (!message || message.trim().length === 0) {
        return { 
            type: 'empty', 
            needsContext: true, 
            isValidRequest: false,
            needsRecommendation: false,
            hasCuisineSpecified: false,
            shouldUsePreferredCuisine: false
        };
    }
    
    const msg = message.toLowerCase().trim();
    
    // FIRST: Check for food-related context (this takes priority)
    const foodKeywords = [
        'eat', 'food', 'hungry', 'meal', 'lunch', 'dinner', 'breakfast',
        'restaurant', 'cafe', 'bar', 'pizza', 'burger', 'sushi', 
        'craving', 'want', 'looking for', 'find', 'recommend', 'suggestion'
    ];
    
    const hasFoodContext = foodKeywords.some(keyword => msg.includes(keyword));
    
    // Check for specific cuisine mentioned
    const cuisineKeywords = [
        'chinese', 'italian', 'mexican', 'thai', 'indian', 'american', 'japanese',
        'french', 'spanish', 'korean', 'vietnamese', 'mediterranean', 'greek',
        'pizza', 'burger', 'sushi', 'tacos', 'pasta', 'ramen', 'pho',
        'bbq', 'barbecue', 'steakhouse', 'seafood', 'vegetarian', 'vegan'
    ];
    
    const hasCuisineSpecified = cuisineKeywords.some(cuisine => msg.includes(cuisine));
    
    // Check for specific food requests vs general requests
    const specificIndicators = [
        'want', 'craving', 'looking for', 'find me', 'i need', 'prefer',
        'would like', 'spicy', 'sweet', 'cheap', 'expensive', 'nearby', 'close'
    ];
    
    const hasSpecificContext = specificIndicators.some(indicator => msg.includes(indicator));
    
    // IF FOOD CONTEXT IS DETECTED, it's a food request regardless of other patterns
    if (hasFoodContext || hasCuisineSpecified || hasSpecificContext) {
        console.log(`🍽️ FOOD REQUEST DETECTED: hasFoodContext=${hasFoodContext}, hasCuisineSpecified=${hasCuisineSpecified}, hasSpecificContext=${hasSpecificContext}`);
        return { 
            type: 'food_request', 
            needsContext: false, 
            isValidRequest: true,
            needsRecommendation: true,
            hasCuisineSpecified: hasCuisineSpecified,
            shouldUsePreferredCuisine: !hasCuisineSpecified, // Use preferred cuisine only if no cuisine specified
            hasSpecificContext: hasSpecificContext
        };
    }
    
    // ONLY IF NO FOOD CONTEXT: Check for non-food related inputs
    const nonFoodPatterns = [
        'thank you', 'thanks', 'thx', 'ty',
        'hello', 'hi', 'hey', 'good morning', 'good afternoon', 'good evening',
        'how are you', 'what is this', 'help', 'about',
        'yes', 'no', 'ok', 'okay', 'sure', 'maybe',
        'test', 'testing', '123', 'abc'
    ];
    
    const isNonFood = nonFoodPatterns.some(pattern => 
        msg.includes(pattern) || msg === pattern
    );
    
    if (isNonFood) {
        console.log(`💬 NON-FOOD REQUEST DETECTED: matched pattern`);
        return { 
            type: 'non_food', 
            needsContext: true, 
            isValidRequest: false,
            needsRecommendation: false,
            hasCuisineSpecified: false,
            shouldUsePreferredCuisine: false
        };
    }
    
    // If unclear, assume it's a general food request
    console.log(`🤔 GENERAL REQUEST - assuming food-related`);
    return { 
        type: 'general_request', 
        needsContext: true, 
        isValidRequest: true,
        needsRecommendation: true,
        hasCuisineSpecified: false,
        shouldUsePreferredCuisine: true, // Use preferred cuisine for general requests
        hasSpecificContext: false
    };
}

// Legacy function kept for compatibility
function extractCuisineFromMessage(message) {
    const intent = detectUserIntent(message);
    return intent.cuisine ? [intent.cuisine] : [];
}

// ULTRA-EFFICIENT AI selection - <1000 tokens guaranteed
async function selectBestRestaurantWithAI(restaurants, preferences, userMessage, user, session, generateAnother = false, inputAnalysis = null) {
    try {
        console.log(`\n🎯 === AI RESTAURANT SELECTION ===`);
        console.log(`� Pool: ${restaurants.length} restaurants`);
        console.log(`� Generate Another: ${generateAnother}`);
        
        // ENHANCED EXCLUSION TRACKING: Initialize session tracking for multiple recommendations
        if (!session.recommendationTracking) {
            session.recommendationTracking = {};
            console.log(`🆕 Initialized new recommendation tracking system`);
        }
        
        // Get current recommendation ID from preferences (or create new one)
        const currentRecommendationId = preferences?.recommendationId || `rec_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
        console.log(`🆔 RECOMMENDATION ID: ${currentRecommendationId}`);
        
        // Initialize tracking for this recommendation if it doesn't exist
        if (!session.recommendationTracking[currentRecommendationId]) {
            session.recommendationTracking[currentRecommendationId] = {
                excludedRestaurants: [],
                history: []
            };
            console.log(`🆕 Created new tracking for recommendation: ${currentRecommendationId}`);
        }
        
        const currentTracking = session.recommendationTracking[currentRecommendationId];
        const excludedRestaurants = currentTracking.excludedRestaurants;
        
        // EXCLUSION DEBUG: Show detailed session memory for THIS recommendation
        console.log(`\n🔄 ===== EXCLUSION TRACKING DEBUG =====`);
        console.log(`🔄 Current Recommendation ID: ${currentRecommendationId}`);
        console.log(`🔄 Generate Another: ${generateAnother}`);
        console.log(`🔄 Excluded Restaurants Count: ${excludedRestaurants.length}`);
        
        if (excludedRestaurants.length > 0) {
            console.log(`🔄 🚫 EXCLUDED RESTAURANTS FOR THIS RECOMMENDATION:`);
            excludedRestaurants.forEach((restaurant, index) => {
                console.log(`🔄 ${index + 1}. ${restaurant.name} (${restaurant.placeId})`);
            });
        } else {
            console.log(`🔄 ✨ No restaurants excluded yet for this recommendation`);
        }
        
        // Show tracking for ALL active recommendations
        const allRecommendationIds = Object.keys(session.recommendationTracking);
        console.log(`🔄 📊 TOTAL ACTIVE RECOMMENDATIONS: ${allRecommendationIds.length}`);
        allRecommendationIds.forEach(recId => {
            const tracking = session.recommendationTracking[recId];
            const isActive = recId === currentRecommendationId;
            console.log(`🔄   ${isActive ? '🎯' : '  '} ${recId}: ${tracking.excludedRestaurants.length} excluded, ${tracking.history.length} history`);
        });
        console.log(`🔄 ===== END EXCLUSION TRACKING DEBUG =====`);
        
        // FILTER DEBUG: Show what filters were received by AI function
        console.log(`\n🔍 FILTERS RECEIVED BY AI:`);
        console.log(`- preferences type: ${typeof preferences}`);
        console.log(`- preferences.filters exists: ${!!preferences?.filters}`);
        if (preferences?.filters) {
            console.log(`- Price Level: ${preferences.filters.priceLevel}`);
            console.log(`- Max Distance: ${preferences.filters.maxDistance}km`);
            console.log(`- Category: ${preferences.filters.category || 'Any'}`);
            console.log(`- Min Rating: ${preferences.filters.minRating || 'Any'}`);
            console.log(`- Max Rating: ${preferences.filters.maxRating || 'Any'}`);
        } else {
            console.log(`- NO FILTERS FOUND IN PREFERENCES!`);
        }
        if (generateAnother) {
            console.log(`\n� EXCLUSION DEBUG:`);
            console.log(`- Session has ${excludedRestaurants.length} previous recommendations`);
            if (excludedRestaurants.length > 0) {
                console.log(`- Will exclude:`, excludedRestaurants.map(rec => rec.name).join(', '));
            }
        }
        
        let availableRestaurants = restaurants;
        if (generateAnother && excludedRestaurants.length > 0) {
            const beforeCount = availableRestaurants.length;
            
            console.log(`🔄 🚫 ===== APPLYING EXCLUSION FILTER =====`);
            console.log(`🔄 🚫 REMOVING ${excludedRestaurants.length} PREVIOUSLY RECOMMENDED RESTAURANTS...`);
            
            availableRestaurants = availableRestaurants.filter(r => {
                const shouldExclude = excludedRestaurants.some(excluded => {
                    return excluded.placeId === r.placeId;
                });
                
                if (shouldExclude) {
                    console.log(`🔄 🚫 EXCLUDED: ${r.name} (already recommended for this conversation)`);
                }
                
                return !shouldExclude;
            });
            
            const excludedCount = beforeCount - availableRestaurants.length;
            console.log(`🔄 🚫 EXCLUSION SUMMARY: Removed ${excludedCount} restaurants, ${availableRestaurants.length} remaining`);
            console.log(`🔄 🚫 ===== END EXCLUSION FILTER =====`);
        } else if (generateAnother) {
            console.log(`🔄 ℹ️ No restaurants to exclude for this recommendation yet`);
        }
        
        // STEP 2: RESTAURANT TYPE FILTERING - Remove non-restaurants
        const actualRestaurants = availableRestaurants.filter(r => isActualRestaurant(r.types));
        console.log(`🚀 After restaurant filter: ${actualRestaurants.length} (removed ${availableRestaurants.length - actualRestaurants.length})`);
        
        // STEP 3: REVIEW FILTER - Only 15+ reviews (quality gate)
        const qualityRestaurants = actualRestaurants.filter(r => {
            const reviewCount = r.reviewCount || r.user_ratings_total || r.review_count || 0;
            return reviewCount >= 15;
        });
        console.log(`🚀 After review filter: ${qualityRestaurants.length} (removed ${actualRestaurants.length - qualityRestaurants.length})`);
        
        // STEP 4: ANALYZE USER INPUT AND DETECT INTENT
        const inputAnalysis = analyzeUserInput(userMessage);
        const userIntent = detectUserIntent(userMessage);
        console.log(`🚀 Input analysis:`, inputAnalysis);
        console.log(`🚀 User intent:`, userIntent);
        
        // STEP 5: SMART FILTERING based on intent AND frontend filters
        let filteredRestaurants = qualityRestaurants;
        
        console.log(`🚀 ===== CHECKING FOR FILTERS =====`);
        console.log(`🚀 preferences object:`, preferences);
        console.log(`🚀 preferences.filters exists: ${!!preferences.filters}`);
        console.log(`🚀 preferences.filters:`, preferences.filters);
        console.log(`🚀 ==================================`);
        
        // Apply frontend filters if provided in preferences
        if (preferences.filters) {
            const filters = preferences.filters;
            console.log(`🚀 ===== APPLYING FRONTEND FILTERS =====`);
            console.log(`🚀 📋 FILTERS RECEIVED FROM FRONTEND:`);
            console.log(`🚀    💰 Price Level: ${filters.priceLevel ? (Array.isArray(filters.priceLevel) ? filters.priceLevel.map(p => '$'.repeat(p)).join(', ') : '$'.repeat(filters.priceLevel)) : 'Not set'}`);
            console.log(`🚀    📍 Max Distance: ${filters.maxDistance ? filters.maxDistance + 'km' : 'Not set'}`);
            console.log(`🚀    🍽️ Category: ${filters.category && filters.category !== 'any' ? filters.category : 'Not set'}`);
            console.log(`🚀    ⭐ Min Rating: ${filters.minRating ? filters.minRating + '⭐' : 'Not set'}`);
            console.log(`🚀    ⭐ Max Rating: ${filters.maxRating ? filters.maxRating + '⭐' : 'Not set'}`);
            console.log(`🚀 Restaurant pool before filtering: ${filteredRestaurants.length}`);
            console.log(`🚀 ========================================`);
            
            // ENHANCED: Price Level Filter with Multi-Selection Support
            if (filters.priceLevel !== null && filters.priceLevel !== undefined) {
                const beforePriceCount = filteredRestaurants.length;
                
                // Handle both single value and array of price levels
                const targetPriceLevels = Array.isArray(filters.priceLevel) ? filters.priceLevel : [filters.priceLevel];
                
                console.log(`🚀 💰 ===== ENHANCED PRICE LEVEL ELIMINATION =====`);
                console.log(`🚀 💰 TARGET PRICE LEVELS: ${targetPriceLevels.map(t => '$'.repeat(t)).join(' OR ')} (levels: ${targetPriceLevels.join(', ')})`);
                console.log(`🚀 💰 MULTI-SELECTION SUPPORT: ${targetPriceLevels.length > 1 ? 'YES' : 'NO'}`);
                console.log(`🚀 💰 CHECKING ${beforePriceCount} RESTAURANTS...`);
                
                let eliminatedCount = 0;
                
                filteredRestaurants = filteredRestaurants.filter(r => {
                    const restaurantPrice = r.priceLevel ?? r.price_level;
                    
                    // Skip restaurants with no price level
                    if (restaurantPrice === undefined || restaurantPrice === null) {
                        eliminatedCount++;
                        console.log(`🚀 💰 ❌ ELIMINATED: ${r.name} - NO PRICE DATA`);
                        return false;
                    }
                    
                    // Enhanced matching - check if restaurant price is in any of the target levels
                    const isMatch = targetPriceLevels.includes(restaurantPrice);
                    
                    if (isMatch) {
                        console.log(`🚀 💰 ✅ KEPT: ${r.name} - ${'$'.repeat(restaurantPrice)} matches target [${targetPriceLevels.map(t => '$'.repeat(t)).join(', ')}]`);
                    } else {
                        eliminatedCount++;
                        const restaurantPriceDisplay = '$'.repeat(restaurantPrice);
                        const targetDisplay = targetPriceLevels.map(t => '$'.repeat(t)).join(' OR ');
                        console.log(`🚀 💰 ❌ ELIMINATED: ${r.name} - ${restaurantPriceDisplay} doesn't match any of [${targetDisplay}]`);
                    }
                    
                    return isMatch;
                });
                
                const afterPriceCount = filteredRestaurants.length;
                console.log(`🚀 💰 SUMMARY: Selected ${targetPriceLevels.length} price level(s), eliminated ${eliminatedCount} restaurants, ${afterPriceCount} remaining`);
                console.log(`🚀 💰 ===== END ENHANCED PRICE ELIMINATION =====`);
            }
            
            // Category Filter
            if (filters.category && filters.category !== 'any') {
                const beforeCategoryCount = filteredRestaurants.length;
                
                console.log(`🚀 🍽️ ===== RESTAURANT TYPE ELIMINATION =====`);
                console.log(`🚀 🍽️ TARGET TYPE: ${filters.category.toUpperCase()}`);
                console.log(`🚀 🍽️ CHECKING ${beforeCategoryCount} RESTAURANTS...`);
                
                let eliminatedCount = 0;
                
                filteredRestaurants = filteredRestaurants.filter(r => {
                    const detectedCategory = getRestaurantCategory(r.types);
                    const match = detectedCategory === filters.category;
                    
                    if (match) {
                        console.log(`🚀 🍽️ ✅ KEPT: ${r.name} - Type: ${detectedCategory.toUpperCase()}`);
                    } else {
                        eliminatedCount++;
                        console.log(`🚀 🍽️ ❌ ELIMINATED: ${r.name} - Type: ${detectedCategory.toUpperCase()} (wanted: ${filters.category.toUpperCase()})`);
                    }
                    
                    return match;
                });
                
                console.log(`🚀 🍽️ SUMMARY: Eliminated ${eliminatedCount} restaurants, ${filteredRestaurants.length} remaining`);
                console.log(`🚀 🍽️ ===== END TYPE ELIMINATION =====`);
            }
            
            // Distance Filter - Apply frontend distance filter
            if (filters.maxDistance !== undefined && filters.maxDistance !== null) {
                const beforeDistanceCount = filteredRestaurants.length;
                const maxDistanceKm = filters.maxDistance;
                
                console.log(`🚀 📍 ===== DISTANCE ELIMINATION =====`);
                console.log(`🚀 📍 MAX DISTANCE: ${maxDistanceKm}km`);
                console.log(`🚀 📍 CHECKING ${beforeDistanceCount} RESTAURANTS...`);
                
                let eliminatedCount = 0;
                
                filteredRestaurants = filteredRestaurants.filter(r => {
                    const distanceKm = r.distance || 0; // Distance should already be in km
                    const withinRange = distanceKm <= maxDistanceKm;
                    
                    if (withinRange) {
                        console.log(`🚀 📍 ✅ KEPT: ${r.name} - ${distanceKm.toFixed(2)}km (within ${maxDistanceKm}km)`);
                    } else {
                        eliminatedCount++;
                        console.log(`🚀 📍 ❌ ELIMINATED: ${r.name} - ${distanceKm.toFixed(2)}km (exceeds ${maxDistanceKm}km)`);
                    }
                    
                    return withinRange;
                });
                
                console.log(`🚀 📍 SUMMARY: Eliminated ${eliminatedCount} restaurants, ${filteredRestaurants.length} remaining`);
                console.log(`🚀 📍 ===== END DISTANCE ELIMINATION =====`);
            } else {
                console.log(`🚀 📍 DISTANCE FILTER SKIPPED - No maxDistance specified`);
            }
            
            // Rating Filter
            if (filters.minRating !== undefined || filters.maxRating !== undefined) {
                const beforeRatingCount = filteredRestaurants.length;
                const minRating = filters.minRating || 0;
                const maxRating = filters.maxRating || 5;
                
                console.log(`🚀 ⭐ ===== RATING ELIMINATION =====`);
                console.log(`🚀 ⭐ RATING RANGE: ${minRating.toFixed(1)}⭐ - ${maxRating.toFixed(1)}⭐`);
                console.log(`🚀 ⭐ CHECKING ${beforeRatingCount} RESTAURANTS...`);
                
                let eliminatedCount = 0;
                
                filteredRestaurants = filteredRestaurants.filter(r => {
                    const rating = r.rating || 0;
                    const withinRange = rating >= minRating && rating <= maxRating;
                    
                    if (withinRange) {
                        console.log(`🚀 ⭐ ✅ KEPT: ${r.name} - ${rating}⭐ (within range)`);
                    } else {
                        eliminatedCount++;
                        if (rating < minRating) {
                            console.log(`🚀 ⭐ ❌ ELIMINATED: ${r.name} - ${rating}⭐ (below ${minRating}⭐)`);
                        } else {
                            console.log(`🚀 ⭐ ❌ ELIMINATED: ${r.name} - ${rating}⭐ (above ${maxRating}⭐)`);
                        }
                    }
                    
                    return withinRange;
                });
                
                console.log(`🚀 ⭐ SUMMARY: Eliminated ${eliminatedCount} restaurants, ${filteredRestaurants.length} remaining`);
                console.log(`🚀 ⭐ ===== END RATING ELIMINATION =====`);
            }
        }
        
        // Filter Summary
        if (preferences.filters) {
            console.log(`🚀 📊 ===== FILTER SUMMARY =====`);
            console.log(`🚀 📊 FILTERS APPLIED:`);
            if (preferences.filters.priceLevel) console.log(`🚀 📊   💰 Price Level: ${Array.isArray(preferences.filters.priceLevel) ? preferences.filters.priceLevel.map(p => '$'.repeat(p)).join(', ') : '$'.repeat(preferences.filters.priceLevel)}`);
            if (preferences.filters.maxDistance) console.log(`🚀 📊   📍 Max Distance: ${preferences.filters.maxDistance}km`);
            if (preferences.filters.category && preferences.filters.category !== 'any') console.log(`🚀 📊   🍽️ Category: ${preferences.filters.category}`);
            if (preferences.filters.minRating || preferences.filters.maxRating) console.log(`🚀 📊   ⭐ Rating: ${preferences.filters.minRating || 0}-${preferences.filters.maxRating || 5}⭐`);
            console.log(`🚀 📊 FINAL RESULT: ${filteredRestaurants.length} restaurants passed all filters`);
            console.log(`🚀 📊 ============================`);
        } else {
            console.log(`🚀 📊 ===== NO FILTERS PROVIDED =====`);
            console.log(`🚀 📊 No frontend filters were applied`);
            console.log(`🚀 📊 Continuing with ${filteredRestaurants.length} restaurants`);
            console.log(`🚀 📊 ================================`);
        }
        
        // Apply user intent filtering (cuisine/category from text)
        if (userIntent.type === 'specific') {
            // Apply aggressive filtering for specific requests
            if (userIntent.cuisine) {
                const beforeIntentCount = filteredRestaurants.length;
                filteredRestaurants = filteredRestaurants.filter(r => {
                    const cuisine = getSimpleCuisine(r.types, r.name);
                    return cuisine === userIntent.cuisine;
                });
                console.log(`🚀 After intent cuisine filter (${userIntent.cuisine}): ${filteredRestaurants.length} (removed ${beforeIntentCount - filteredRestaurants.length})`);
            }
            
            if (userIntent.category) {
                const beforeIntentCount = filteredRestaurants.length;
                filteredRestaurants = filteredRestaurants.filter(r => {
                    const category = getRestaurantCategory(r.types);
                    return category === userIntent.category;
                });
                console.log(`🚀 After intent category filter (${userIntent.category}): ${filteredRestaurants.length} (removed ${beforeIntentCount - filteredRestaurants.length})`);
            }
        }
        
        // Session exclusion was already handled at the beginning of the function
        
        // STEP 6: VALIDATE FILTERING RESULTS BEFORE RANDOM SELECTION
        console.log(`🚀 ===== PRE-RANDOM VALIDATION =====`);
        console.log(`🚀 RESTAURANTS AFTER ALL FILTERS: ${filteredRestaurants.length}`);
        
        if (filteredRestaurants.length > 0) {
            console.log(`🚀 VALIDATION - Checking if restaurants meet criteria:`);
            
            // Check distance compliance and RE-FILTER if violations found
            if (preferences?.filters?.maxDistance) {
                const maxDist = preferences.filters.maxDistance;
                const beforeValidation = filteredRestaurants.length;
                
                filteredRestaurants = filteredRestaurants.filter(r => {
                    const distance = r.distance || 0;
                    const isValid = distance <= maxDist;
                    if (!isValid) {
                        console.log(`🚀 ⚠️ RE-FILTERING: ${r.name}: ${distance.toFixed(2)}km > ${maxDist}km - REMOVING`);
                    }
                    return isValid;
                });
                
                if (beforeValidation !== filteredRestaurants.length) {
                    console.log(`🚀 ⚠️ DISTANCE RE-FILTER: Removed ${beforeValidation - filteredRestaurants.length} restaurants that violated distance filter`);
                } else {
                    console.log(`🚀 ✅ DISTANCE OK: All ${filteredRestaurants.length} restaurants within ${maxDist}km`);
                }
            }
            
            // Check price level compliance and RE-FILTER if violations found
            if (preferences?.filters?.priceLevel) {
                const targetPrices = Array.isArray(preferences.filters.priceLevel) ? preferences.filters.priceLevel : [preferences.filters.priceLevel];
                const beforeValidation = filteredRestaurants.length;
                
                filteredRestaurants = filteredRestaurants.filter(r => {
                    const restaurantPrice = r.priceLevel ?? r.price_level;
                    if (restaurantPrice === undefined || restaurantPrice === null) {
                        console.log(`🚀 ⚠️ RE-FILTERING: ${r.name}: No price data - REMOVING`);
                        return false;
                    }
                    
                    // ENHANCED: Check if matches any target price level (simplified for multi-selection)
                    const isValid = targetPrices.includes(restaurantPrice);
                    
                    if (!isValid) {
                        console.log(`🚀 ⚠️ RE-FILTERING: ${r.name}: price=${restaurantPrice} doesn't match ${targetPrices.map(t => '$'.repeat(t)).join(' or ')} - REMOVING`);
                    }
                    
                    return isValid;
                });
                
                if (beforeValidation !== filteredRestaurants.length) {
                    console.log(`🚀 ⚠️ PRICE RE-FILTER: Removed ${beforeValidation - filteredRestaurants.length} restaurants that violated price filter`);
                } else {
                    console.log(`🚀 ✅ PRICE OK: All ${filteredRestaurants.length} restaurants match price filter`);
                }
            }
        }
        console.log(`🚀 ===== END PRE-RANDOM VALIDATION =====`);
        
        // STEP 7: SMART REDUCTION - Keep 10 RANDOM candidates for variety (reduced from 20 for better AI analysis)
        const maxCandidates = 10; // Hard limit for efficiency and better AI decision making
        
        // FILTERING SUMMARY
        console.log(`🚀 ===== FILTERING SUMMARY =====`);
        console.log(`🚀 Original pool: ${restaurants.length} restaurants`);
        console.log(`🚀 After restaurant filter: ${actualRestaurants.length}`);
        console.log(`🚀 After review filter: ${qualityRestaurants.length}`);
        console.log(`🚀 After all filters: ${filteredRestaurants.length}`);
        console.log(`🚀 Final candidates for AI: ${Math.min(filteredRestaurants.length, maxCandidates)}`);
        if (filteredRestaurants.length > maxCandidates) {
            // Random selection for variety between searches
            const shuffled = [...filteredRestaurants];
            for (let i = shuffled.length - 1; i > 0; i--) {
                const j = Math.floor(Math.random() * (i + 1));
                [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
            }
            filteredRestaurants = shuffled.slice(0, maxCandidates);
            
            console.log(`🚀 Random selection: ${filteredRestaurants.length} random candidates selected`);
        }
        
        // STEP 8: FINAL VALIDATION AFTER RANDOM SELECTION
        console.log(`🚀 ===== FINAL AI INPUT VALIDATION =====`);
        console.log(`🚀 RESTAURANTS GOING TO AI: ${filteredRestaurants.length}`);
        
        if (filteredRestaurants.length > 0) {
            console.log(`🚀 FINAL CHECK - Restaurants being sent to AI:`);
            
            filteredRestaurants.forEach((r, index) => {
                const distance = (r.distance || 0).toFixed(2);
                const price = r.priceLevel ?? r.price_level ?? 'N/A';
                console.log(`🚀 ${index + 1}. ${r.name}: ${distance}km, price=${price} (${price !== 'N/A' ? '$'.repeat(price) : 'N/A'}), rating=${r.rating}⭐`);
            });
            
            // Double-check no violations remain
            if (preferences?.filters?.maxDistance) {
                const violations = filteredRestaurants.filter(r => (r.distance || 0) > preferences.filters.maxDistance);
                if (violations.length > 0) {
                    console.log(`🚀 🚨 CRITICAL: ${violations.length} distance violations still exist!`);
                }
            }
            
            if (preferences?.filters?.priceLevel) {
                const targetPrices = Array.isArray(preferences.filters.priceLevel) ? preferences.filters.priceLevel : [preferences.filters.priceLevel];
                const violations = filteredRestaurants.filter(r => {
                    const restaurantPrice = r.priceLevel ?? r.price_level;
                    if (restaurantPrice === undefined || restaurantPrice === null) return true;
                    // ENHANCED: Simple exact matching for multi-selection support
                    return !targetPrices.includes(restaurantPrice);
                });
                if (violations.length > 0) {
                    console.log(`🚀 🚨 CRITICAL: ${violations.length} price violations still exist!`);
                }
            }
        }
        console.log(`🚀 ===== END FINAL VALIDATION =====`);
        
        // STEP 9: SMART RANDOM CUISINE SELECTION FOR EMPTY RESULTS
        if (filteredRestaurants.length === 0) {
            console.log(`🎲 ===== NO RESTAURANTS FOUND - INITIATING SMART RANDOM CUISINE SELECTION =====`);
            
            // Determine if we should use random cuisine selection
            let shouldUseRandomCuisine = false;
            let reasonForRandomSelection = '';
            
            // Check if user specified no cuisine AND has no preferences
            const userSpecifiedCuisine = inputAnalysis && inputAnalysis.hasCuisineSpecified;
            const userHasPreferredCuisine = user && user.preferences && user.preferences.cuisines && user.preferences.cuisines.length > 0;
            
            if (!userSpecifiedCuisine && !userHasPreferredCuisine) {
                shouldUseRandomCuisine = true;
                reasonForRandomSelection = 'No cuisine specified in input and no user cuisine preferences';
            } else if (userSpecifiedCuisine) {
                shouldUseRandomCuisine = true;
                reasonForRandomSelection = 'User requested specific cuisine but no restaurants found in range';
            } else if (userHasPreferredCuisine) {
                shouldUseRandomCuisine = true;
                reasonForRandomSelection = 'User has preferred cuisine but no restaurants found in range';
            }
            
            console.log(`🎲 Random cuisine selection decision: ${shouldUseRandomCuisine ? 'YES' : 'NO'}`);
            console.log(`🎲 Reason: ${reasonForRandomSelection}`);
            
            if (shouldUseRandomCuisine) {
                // Try to find a random cuisine that has restaurants matching the user's OTHER filters
                const randomCuisineResult = await findRandomCuisineWithRestaurants(
                    qualityRestaurants, // Use the quality-filtered restaurants as base
                    preferences.filters, // Apply the same filters except cuisine
                    15 // Try up to 15 different cuisines
                );
                
                if (randomCuisineResult) {
                    console.log(`🎲 ✅ RANDOM CUISINE SUCCESS!`);
                    console.log(`🎲 Selected cuisine: "${randomCuisineResult.cuisine}"`);
                    console.log(`🎲 Found restaurants: ${randomCuisineResult.restaurants.length}`);
                    console.log(`🎲 Attempts needed: ${randomCuisineResult.totalAttempts}`);
                    
                    // Use the restaurants from the random cuisine selection
                    filteredRestaurants = randomCuisineResult.restaurants;
                    
                    // Log the successful random selection
                    console.log(`🎲 Updated restaurant pool with random cuisine restaurants:`);
                    filteredRestaurants.forEach((r, index) => {
                        const distance = (r.distance || 0).toFixed(2);
                        const price = r.priceLevel ?? r.price_level ?? 'N/A';
                        console.log(`🎲 ${index + 1}. ${r.name}: ${distance}km, price=${price} (${price !== 'N/A' ? '$'.repeat(price) : 'N/A'}), rating=${r.rating}⭐, cuisine=${randomCuisineResult.cuisine}`);
                    });
                } else {
                    console.log(`🎲 ❌ RANDOM CUISINE FAILED - No cuisines found with restaurants matching filters`);
                    console.log(`🎲 Falling back to highest-rated restaurant regardless of filters`);
                }
            }
            
            console.log(`🎲 ===== END SMART RANDOM CUISINE SELECTION =====`);
        }
        
        // STEP 10: ENHANCED FALLBACK FOR COMPLETELY EMPTY RESULTS
        if (filteredRestaurants.length === 0) {
            console.log(`🚀 ===== NO RESTAURANTS MATCH FILTERS =====`);
            console.log(`🚀 No restaurants found after applying all filters and exclusions`);
            
            // Create a helpful message explaining what filters caused the issue
            let filterExplanation = [];
            if (preferences?.filters) {
                if (preferences.filters.priceLevel !== null && preferences.filters.priceLevel !== undefined) {
                    // ENHANCED: Handle both single values and arrays for multi-selection
                    const priceLevels = Array.isArray(preferences.filters.priceLevel) ? preferences.filters.priceLevel : [preferences.filters.priceLevel];
                    const priceText = priceLevels.map(p => '$'.repeat(p)).join(' or ');
                    filterExplanation.push(`price level ${priceText}`);
                }
                if (preferences.filters.maxDistance) {
                    filterExplanation.push(`within ${preferences.filters.maxDistance}km`);
                }
                if (preferences.filters.category && preferences.filters.category !== 'any') {
                    filterExplanation.push(`${preferences.filters.category} restaurants`);
                }
                if (preferences.filters.minRating || preferences.filters.maxRating) {
                    const minRating = preferences.filters.minRating || 0;
                    const maxRating = preferences.filters.maxRating || 5;
                    filterExplanation.push(`rating ${minRating}-${maxRating}⭐`);
                }
            }
            
            // Add exclusion info if this is a regeneration
            if (generateAnother && excludedRestaurants.length > 0) {
                filterExplanation.push(`excluding ${excludedRestaurants.length} previously recommended restaurant${excludedRestaurants.length > 1 ? 's' : ''}`);
            }
            
            const noResultsMessage = filterExplanation.length > 0 
                ? `No restaurants found matching your criteria: ${filterExplanation.join(', ')}. Try adjusting your filters for more options.`
                : "No restaurants found in your area. Try expanding your search distance or adjusting your preferences.";
            
            console.log(`🚀 Returning helpful message: "${noResultsMessage}"`);
            console.log(`🚀 ===== END NO RESULTS HANDLING =====`);
            
            return { 
                restaurant: null,
                noResultsMessage: noResultsMessage,
                recommendationId: currentRecommendationId,
                debuggingData: { 
                    selectionMethod: 'no-results-found', 
                    filteredCount: 0,
                    appliedFilters: preferences?.filters || {},
                    excludedCount: excludedRestaurants.length,
                    recommendationId: currentRecommendationId,
                    filterExplanation: filterExplanation
                }
            };
        }
        
        // STEP 11: ULTRA-COMPACT AI PROMPT
        console.log(`🚀 GENERATING RESTAURANT DATA FOR AI...`);
        const minimalData = await Promise.all(filteredRestaurants.map(async (r, i) => {
            // Fix price level: handle both number and undefined cases
            let priceLevel = r.priceLevel ?? r.price_level ?? 2; // Default to $$ if undefined
            if (typeof priceLevel !== 'number' || priceLevel < 1 || priceLevel > 4) {
                priceLevel = 2; // Default to moderate price
            }
            
            const entry = {
                id: i + 1,
                nm: r.name.length > 25 ? r.name.substring(0, 25) + '...' : r.name, // Shortened name
                cu: getSimpleCuisine(r.types, r.name), // cuisine
                rt: r.rating || 0, // rating
                pr: priceLevel, // price (1-4)
                dt: Math.round((r.distance || 0) * 10) / 10 // distance is already in km, just round to 1 decimal
            };
            
            // Descriptions removed - not needed for AI prompt
            
            return entry;
        }));
        
        // Descriptions removed from AI prompt
        
        // Validate user message length (15 words max)
        const words = userMessage.trim().split(/\s+/);
        const validatedMessage = words.length > 15 ? 
            words.slice(0, 15).join(' ') + '...' : 
            userMessage;
        
        // Build context-aware prompt based on input analysis
        let promptContext = '';
        let userPrefsText = '';
        
        // Always include user message if it has actual content
        if (validatedMessage && validatedMessage.trim().length > 0 && !validatedMessage.includes('I want food')) {
            promptContext = `User request: "${validatedMessage}"`;
        }
        
        // SMART CUISINE PREFERENCE LOGIC based on input analysis
        if (inputAnalysis?.shouldUsePreferredCuisine && user?.preferences?.cuisines?.length > 0) {
            // Randomly pick one of the user's preferred cuisines
            const randomCuisine = user.preferences.cuisines[Math.floor(Math.random() * user.preferences.cuisines.length)];
            console.log(`🎲 No cuisine specified in input - randomly selected preferred cuisine: ${randomCuisine}`);
            
            // Add to prompt context
            if (promptContext) {
                promptContext += `. User particularly enjoys ${randomCuisine} food`;
            } else {
                promptContext = `User request: Looking for ${randomCuisine} food`;
            }
            
            userPrefsText = `User profile: particularly enjoys ${randomCuisine}`;
        } else if (inputAnalysis?.hasCuisineSpecified) {
            console.log(`🎯 Cuisine specified in user input - using message as-is without adding preferences`);
            
            // Don't add additional cuisine preferences since user specified one
            if (user?.preferences) {
                const userPrefs = user.preferences;
                let prefParts = [];
                
                if (userPrefs.priceRange) {
                    prefParts.push(`prefers ${userPrefs.priceRange} price range`);
                }
                if (userPrefs.dietType) {
                    prefParts.push(`follows ${userPrefs.dietType} diet`);
                }
                
                if (prefParts.length > 0) {
                    userPrefsText = `User profile: ${prefParts.join(', ')}`;
                }
            }
        } else {
            // Original logic for other cases
            if (user?.preferences) {
                const userPrefs = user.preferences;
                let prefParts = [];
                
                if (userPrefs.cuisines && userPrefs.cuisines.length > 0) {
                    prefParts.push(`likes ${userPrefs.cuisines.join(', ')}`);
                }
                if (userPrefs.priceRange) {
                    prefParts.push(`prefers ${userPrefs.priceRange} price range`);
                }
                if (userPrefs.dietType) {
                    prefParts.push(`follows ${userPrefs.dietType} diet`);
                }
                
                if (prefParts.length > 0) {
                    userPrefsText = `User profile: ${prefParts.join(', ')}`;
                }
            }
        }
        
        // Add filter preferences if available
        if (preferences?.filters) {
            let filterParts = [];
            
            if (preferences.filters.cuisines && preferences.filters.cuisines.length > 0) {
                filterParts.push(`wants ${preferences.filters.cuisines.join(' or ')}`);
            }
            
            // ENHANCED: Handle both single values and arrays for multi-selection price levels
            if (preferences.filters.priceLevel !== undefined && preferences.filters.priceLevel !== null) {
                const priceMap = {1: '$', 2: '$$', 3: '$$$', 4: '$$$$'};
                const priceLevels = Array.isArray(preferences.filters.priceLevel) ? preferences.filters.priceLevel : [preferences.filters.priceLevel];
                const priceText = priceLevels.map(p => priceMap[p] || p).join(' or ');
                filterParts.push(`budget ${priceText}`);
                console.log(`🚀 FILTER CONTEXT: Added price filter "${priceText}" to AI prompt (multi-selection: ${priceLevels.length > 1})`);
            }
            
            if (preferences.filters.category && preferences.filters.category !== 'any') {
                filterParts.push(`category ${preferences.filters.category}`);
                console.log(`🚀 FILTER CONTEXT: Added category filter "${preferences.filters.category}" to AI prompt`);
            }
            
            if (preferences.filters.maxDistance) {
                filterParts.push(`within ${preferences.filters.maxDistance}km`);
                console.log(`🚀 FILTER CONTEXT: Added distance filter "${preferences.filters.maxDistance}km" to AI prompt`);
            }
            
            if (filterParts.length > 0) {
                const filterText = `Current filters: ${filterParts.join(', ')}`;
                userPrefsText = userPrefsText ? `${userPrefsText}. ${filterText}` : filterText;
                console.log(`🚀 FILTER CONTEXT: Complete filter text added to AI prompt: "${filterText}"`);
            }
        }
        
        // Combine context
        let fullContext = '';
        if (promptContext && userPrefsText) {
            fullContext = `${promptContext}. ${userPrefsText}`;
        } else if (promptContext) {
            fullContext = promptContext;
        } else if (userPrefsText) {
            fullContext = userPrefsText;
        } else {
            fullContext = 'Find the best restaurant option';
        }
        
        // ENHANCED PROMPT with better context and descriptions
        let excludedInfo = '';
        if (generateAnother && excludedRestaurants.length > 0) {
            const excludedNames = excludedRestaurants.map(rec => rec.name).slice(-5); // Show last 5 excluded
            excludedInfo = `\nEXCLUDE: Previously recommended: ${excludedNames.join(', ')}`;
        }
        
        const promptText = `${fullContext}${excludedInfo}
${JSON.stringify({ restaurants: minimalData })}
Return only a single number (1-${minimalData.length}) indicating the best restaurant choice. No JSON, no explanation, just the number.`;        const estimatedTokens = promptText.length / 4;
        
        // Simplified AI prompt logging - show restaurant data in one line (no descriptions)
        const restaurantSummary = minimalData.map((r, i) => {
            const priceSymbol = '$'.repeat(r.pr);
            return `${i+1}:${r.nm}(${r.cu},${r.rt}⭐,${r.pr}=${priceSymbol},${r.dt}km)`;
        }).join(' | ');
        
        console.log(`🚀 AI Context: "${fullContext}"`);
        console.log(`🚀 Restaurants: ${restaurantSummary}`);
        if (generateAnother && excludedRestaurants.length > 0) {
            console.log(`🚀 Excluding: ${excludedRestaurants.slice(-3).map(r => r.name).join(', ')}`);
        }
        console.log(`🚀 Prompt: ${promptText.length} chars (~${Math.ceil(estimatedTokens)} tokens)`);
        
        // Show the EXACT AI prompt for debugging
        console.log(`🚀 ===== EXACT AI PROMPT =====`);
        console.log(promptText);
        console.log(`🚀 ===== END AI PROMPT =====`);
        
        if (estimatedTokens > 600) {
            console.log(`🚀 Still too long (>${Math.ceil(estimatedTokens)} tokens), emergency fallback to top-rated`);
            const fallback = filteredRestaurants.sort((a, b) => (b.rating || 0) - (a.rating || 0))[0];
            return { 
                restaurant: fallback, 
                recommendationId: currentRecommendationId,
                debuggingData: { 
                    selectionMethod: 'emergency-fallback', 
                    estimatedTokens,
                    recommendationId: currentRecommendationId
                }
            };
        }
        
        // STEP 8: AI CALL - Enhanced system message for better selection
        const completion = await openai.chat.completions.create({
            model: "gpt-4",
            messages: [
                {
                    role: "system",
                    content: "You are a restaurant recommendation expert. Analyze the provided restaurant options and user request. Consider cuisine preferences, price budget, ratings, location. Select the restaurant ID that best matches the user's needs and preferences. Return ONLY a single number (1-10) - no JSON, no explanation, just the number."
                },
                {
                    role: "user",
                    content: promptText
                }
            ],
            max_tokens: 5,
            temperature: 0.0
        });

        const response = completion.choices[0].message.content.trim();
        
        // Parse response as simple number
        let selectedIndex = -1;
        const responseNumber = parseInt(response);
        
        if (!isNaN(responseNumber) && responseNumber >= 1 && responseNumber <= filteredRestaurants.length) {
            selectedIndex = responseNumber - 1;
            console.log(`🚀 AI selected: ${responseNumber} (index ${selectedIndex})`);
        } else {
            console.log(`🚀 Invalid AI response: "${response}" - using fallback`);
        }
        
        if (selectedIndex >= 0 && selectedIndex < filteredRestaurants.length) {
            const selectedRestaurant = filteredRestaurants[selectedIndex];
            console.log(`🚀 ✅ AI SELECTED: ${selectedRestaurant.name}`);
            
            // ENHANCED TRACKING: Add this restaurant to exclusion list for THIS recommendation
            console.log(`🔄 📝 ===== ADDING TO EXCLUSION LIST =====`);
            console.log(`🔄 📝 Adding ${selectedRestaurant.name} to exclusion list for recommendation: ${currentRecommendationId}`);
            
            const restaurantForExclusion = {
                placeId: selectedRestaurant.placeId,
                name: selectedRestaurant.name,
                selectedAt: new Date().toISOString()
            };
            
            currentTracking.excludedRestaurants.push(restaurantForExclusion);
            currentTracking.history.push(restaurantForExclusion);
            
            console.log(`🔄 📝 ✅ ADDED TO EXCLUSION LIST:`);
            console.log(`🔄 📝    Restaurant: ${selectedRestaurant.name}`);
            console.log(`🔄 📝    Place ID: ${selectedRestaurant.placeId}`);
            console.log(`🔄 📝    Recommendation ID: ${currentRecommendationId}`);
            console.log(`🔄 📝    Total excluded for this recommendation: ${currentTracking.excludedRestaurants.length}`);
            
            // Show the updated exclusion array
            console.log(`🔄 📝 📋 UPDATED EXCLUSION ARRAY FOR ${currentRecommendationId}:`);
            currentTracking.excludedRestaurants.forEach((excluded, index) => {
                console.log(`🔄 📝 ${index + 1}. ${excluded.name} (${excluded.placeId}) - ${excluded.selectedAt}`);
            });
            console.log(`🔄 📝 ===== END EXCLUSION LIST UPDATE =====`);
            
            return {
                restaurant: selectedRestaurant,
                recommendationId: currentRecommendationId,
                debuggingData: {
                    originalPool: restaurants.length,
                    finalPool: filteredRestaurants.length,
                    userIntent: userIntent,
                    inputAnalysis: inputAnalysis,
                    estimatedTokens: estimatedTokens,
                    selectionMethod: 'ai',
                    selectedRestaurant: selectedRestaurant.name,
                    promptContext: promptContext,
                    recommendationId: currentRecommendationId,
                    excludedCount: currentTracking.excludedRestaurants.length
                }
            };
        } else {
            // Fallback to top-rated
            const fallback = filteredRestaurants.sort((a, b) => (b.rating || 0) - (a.rating || 0))[0];
            console.log(`🚀 Invalid AI response, fallback: ${fallback?.name}`);
            
            // ENHANCED TRACKING: Add fallback restaurant to exclusion list too
            if (fallback) {
                console.log(`🔄 📝 ===== ADDING FALLBACK TO EXCLUSION LIST =====`);
                const restaurantForExclusion = {
                    placeId: fallback.placeId,
                    name: fallback.name,
                    selectedAt: new Date().toISOString()
                };
                
                currentTracking.excludedRestaurants.push(restaurantForExclusion);
                currentTracking.history.push(restaurantForExclusion);
                
                console.log(`🔄 📝 ✅ ADDED FALLBACK TO EXCLUSION LIST: ${fallback.name}`);
                console.log(`🔄 📝 ===== END FALLBACK EXCLUSION UPDATE =====`);
            }
            
            return {
                restaurant: fallback,
                recommendationId: currentRecommendationId,
                debuggingData: {
                    originalPool: restaurants.length,
                    finalPool: filteredRestaurants.length,
                    userIntent: userIntent,
                    inputAnalysis: inputAnalysis,
                    aiResponse: response,
                    selectionMethod: 'fallback',
                    selectedRestaurant: fallback?.name,
                    promptContext: promptContext,
                    recommendationId: currentRecommendationId,
                    excludedCount: currentTracking.excludedRestaurants.length
                }
            };
        }
        
    } catch (error) {
        console.error('🚀 ❌ Error in efficient AI selection:', error);
        
        // Emergency fallback
        const fallback = restaurants
            .filter(r => (r.reviewCount || r.user_ratings_total || 0) >= 15)
            .sort((a, b) => (b.rating || 0) - (a.rating || 0))[0];
        
        return {
            restaurant: fallback,
            recommendationId: currentRecommendationId,
            debuggingData: {
                error: error.message,
                selectionMethod: 'error-fallback',
                selectedRestaurant: fallback?.name,
                recommendationId: currentRecommendationId
            }
        };
    }
}

// Helper function to check dietary compatibility
function checkDietaryCompatibility(types, dietType) {
    if (!types || !Array.isArray(types)) return false;
    
    const typeString = types.join(' ').toLowerCase();
    
    switch (dietType.toLowerCase()) {
        case 'vegetarian':
            return typeString.includes('vegetarian') || 
                   typeString.includes('vegan') || 
                   typeString.includes('health') ||
                   typeString.includes('salad');
        case 'vegan':
            return typeString.includes('vegan') || 
                   typeString.includes('health') ||
                   typeString.includes('juice');
        case 'gluten-free':
            return typeString.includes('gluten') || 
                   typeString.includes('health') ||
                   typeString.includes('salad');
        case 'keto':
            return typeString.includes('steakhouse') || 
                   typeString.includes('seafood') ||
                   typeString.includes('grill');
        default:
            return false;
    }
}

// Function to save user recommendation for tracking
async function saveUserRecommendation(user, restaurant, preferences, sessionId) {
    try {
        if (!user || !restaurant) return;
        
        const recommendation = new UserRecommendation({
            userId: user._id,
            restaurantId: restaurant.placeId,
            restaurantName: restaurant.name,
            sessionId: sessionId,
            preferences: {
                cuisines: preferences.cuisines || [],
                priceRange: preferences.priceRange || '$$',
                dietType: preferences.dietType || null
            },
            rating: restaurant.rating || null
        });
        
        await recommendation.save();
        console.log(`📝 Saved recommendation for ${user.email}: ${restaurant.name}`);
        
    } catch (error) {
        console.error('Error saving user recommendation:', error);
    }
}

// OAuth error handler middleware
app.use('/auth/google', (err, req, res, next) => {
    console.log('❌ OAuth middleware error:', err.message);
    console.log('❌ Error details:', err);
    
    // Common OAuth errors
    if (err.message.includes('redirect_uri_mismatch')) {
        console.log('❌ REDIRECT URI MISMATCH: Check Google Cloud Console settings');
        console.log('❌ Expected redirect URI: http://localhost:' + PORT + '/auth/google/callback');
    }
    
    if (err.message.includes('invalid_client')) {
        console.log('❌ INVALID CLIENT: Check your Client ID and Secret');
    }
    
    if (err.message.includes('access_denied')) {
        console.log('❌ ACCESS DENIED: User denied permission or app is not verified');
    }
    
    const frontendUrl = getFrontendUrl(req);
    res.redirect(`${frontendUrl}/signin?error=oauth_error&details=${encodeURIComponent(err.message)}`);
});
