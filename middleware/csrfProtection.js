const crypto = require('crypto');

/**
 * Double-submit cookie CSRF validation middleware.
 * Generates a CSRF token on GET requests if missing,
 * Validates the X-CSRF-Token header against the cookie on POST/PUT/DELETE/PATCH state-mutating requests.
 */
function csrfProtection(req, res, next) {
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
            sameSite: 'strict',
            maxAge: 24 * 60 * 60 * 1000 // 24 hours
        });
    }

    // 3. For state-changing methods, enforce validation
    const safeMethods = ['GET', 'HEAD', 'OPTIONS'];
    if (!safeMethods.includes(req.method)) {
        const csrfHeader = req.headers['x-csrf-token'];
        if (!csrfHeader || csrfHeader !== csrfCookie) {
            return res.status(403).json({ error: 'CSRF token missing or invalid' });
        }
    }

    next();
}

module.exports = csrfProtection;
