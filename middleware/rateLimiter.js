const rateLimit = require('express-rate-limit');

// Strict rate limit for authentication routes to prevent brute force
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    limit: 5, // Limit each IP to 5 requests per windowMs
    message: { error: 'Too many login/register attempts from this IP, please try again after 15 minutes' },
    standardHeaders: 'draft-7', // draft-6: `RateLimit-*` headers; draft-7: combined `RateLimit` header
    legacyHeaders: false, // Disable the `X-RateLimit-*` headers
});

// Global API rate limit to prevent generic DDoS/scraping
const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    limit: 150, // Limit each IP to 150 requests per windowMs
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
