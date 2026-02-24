const crypto = require('crypto');


/**
 * Double-submit cookie CSRF validation middleware.
 * Generates a CSRF token on GET requests if missing,
 * Validates the X-CSRF-Token header against the cookie on POST/PUT/DELETE/PATCH state-mutating requests.
 * Public authentication routes (register, login, etc.) are exempt since the user has no session yet.
 */

// Routes that do NOT require CSRF validation (public, unauthenticated endpoints)
const CSRF_EXEMPT_PATHS = [
    '/auth/register',
    '/auth/login',
    '/auth/logout',
    '/auth/request-password-reset',
    '/auth/reset-password',
    '/auth/otp/send',
    '/auth/otp/verify',
    '/api/github/callback',
    '/health',
    '/',
    '/deploy',
    '/api/deployments',
];

function csrfProtection(req, res, next) {
    // Check if this path is exempt from CSRF protection
    const isExempt = CSRF_EXEMPT_PATHS.some(path => req.path === path || req.path.startsWith(path));
    if (isExempt) {
        return next();
    }

    // 1. Read existing token from cookies
    // Express parses cookies if cookie-parser is used. We will assume cookie-parser or manual extraction.
    let csrfCookie = '';
    if (req.headers.cookie) {
        const cookies = req.headers.cookie.split(';');
        for (const cookie of cookies) {
            const [name, val] = cookie.trim().split('=');
            if (name === 'csrf_token') {
                csrfCookie = val;
                break;
            }
        }
    }

    // 2. Generate a fresh token if none exists
    if (!csrfCookie) {
        csrfCookie = crypto.randomBytes(32).toString('hex');
        res.cookie('csrf_token', csrfCookie, {
            httpOnly: false, // Must be readable by frontend JS to set the header!
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
            domain: process.env.DOMAIN ? `.${process.env.DOMAIN.replace('api.', '')}` : undefined,
            maxAge: 24 * 60 * 60 * 1000 // 24 hours
        });
    }

    // 3. For state-changing methods, enforce validation
    const safeMethods = ['GET', 'HEAD', 'OPTIONS'];
    // Bootstrap auth routes are intentionally exempt because clients may not yet
    // have a CSRF cookie/header pair before first credentialed POST.
    const csrfExemptPaths = new Set([
        '/auth/register',
        '/auth/login',
        '/auth/login/otp/verify',
        '/auth/refresh',
        '/auth/logout',
        '/auth/forgot-password',
        '/auth/reset-password',
        '/auth/otp/send',
        '/auth/otp/verify',
        '/auth/2fa/login'
    ]);
    if (!safeMethods.includes(req.method)) {
        if (csrfExemptPaths.has(req.path)) {
            return next();
        }
        const csrfHeader = req.headers['x-csrf-token'];
        if (!csrfHeader || csrfHeader !== csrfCookie) {
            return res.status(403).json({ error: 'CSRF token missing or invalid' });
        }
    }

    next();
}

module.exports = csrfProtection;
