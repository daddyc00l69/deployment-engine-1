const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret';

function authMiddleware(req, res, next) {
    // Support both Bearer token and cookie-based auth for browser sessions.
    const authHeader = req.header('Authorization');
    const bearer = authHeader && authHeader.startsWith('Bearer ') ? authHeader.slice('Bearer '.length) : null;
    const cookieToken = req.cookies?.vpsphere_token || req.cookies?.token || null;
    const token = bearer || cookieToken;

    if (!token) {
        return res.status(401).json({ error: 'Access denied. No token provided.' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded; // Contains id, username, plan_id
        next();
    } catch (ex) {
        res.status(400).json({ error: 'Invalid token.' });
    }
}

module.exports = authMiddleware;
