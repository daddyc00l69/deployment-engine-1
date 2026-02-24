const rateLimit = require('express-rate-limit');

// Strict rate limit for authentication routes to prevent brute force
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    // 5/15m is too aggressive for real users (and QA). Account lockout is handled separately.
    limit: 30, // Limit each IP to 30 requests per windowMs
    // /auth/me is called automatically by the frontend to hydrate sessions.
    // It must not consume the same strict bucket as login/register attempts.
    skip: (req) => {
        if (req.method === 'OPTIONS') return true; // don't rate-limit preflight
        // Depending on mount/baseUrl, Express may expose either '/me' or '/auth/me'.
        const p = req.path || '';
        const u = req.originalUrl || req.url || '';
        if ((req.method === 'GET' || req.method === 'HEAD') && (p === '/me' || p === '/auth/me' || u === '/auth/me')) return true;
        // These are cookie management routes; throttling them aggressively breaks UX.
        if (req.method === 'POST' && (p === '/logout' || p === '/refresh' || p === '/auth/logout' || p === '/auth/refresh')) return true;
        return false;
    },
    message: { error: 'Too many authentication requests from this IP, please try again after 15 minutes' },
    standardHeaders: 'draft-7', // draft-6: `RateLimit-*` headers; draft-7: combined `RateLimit` header
    legacyHeaders: false, // Disable the `X-RateLimit-*` headers
});

// Global API rate limit to prevent generic DDoS/scraping
const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    limit: 150, // Limit each IP to 150 requests per windowMs
    // Ensure preflight and session hydration don't get blocked (otherwise browser reports CORS errors).
    skip: (req) => {
        if (req.method === 'OPTIONS') return true;
        // Frontend calls this on every page load to hydrate cookie-session state.
        if (req.method === 'GET' && req.path === '/auth/me') return true;
        return false;
    },
    message: { error: 'Too many requests from this IP, please try again after 15 minutes' },
    standardHeaders: 'draft-7',
    legacyHeaders: false,
});

// Stricter rate limit for core engine functions like deployments to prevent CPU exhaustion
const deployLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    limit: 20, // Limit each IP to 20 deployment API hits per hour
    message: { error: 'Too many deployment requests from this IP, please try again after an hour' },
    standardHeaders: 'draft-7',
    legacyHeaders: false,
});

module.exports = {
    authLimiter,
    deployLimiter,
    globalLimiter
};
