const jwt = require('jsonwebtoken');

const supabaseAuth = (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;

        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ error: 'Unauthorized: No token provided' });
        }

        const token = authHeader.split(' ')[1];
        const secret = process.env.JWT_SECRET || process.env.SUPABASE_JWT_SECRET;

        if (!secret) {
            console.error('[SupabaseAuth] JWT_SECRET environment variable is missing.');
            return res.status(500).json({ error: 'Server authentication configuration error.' });
        }

        const decoded = jwt.verify(token, secret);
        req.user = decoded;

        next();
    } catch (error) {
        // Handle common JWT errors gracefully
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({ error: 'Unauthorized: Token has expired.' });
        }
        return res.status(401).json({ error: 'Unauthorized: Invalid token.' });
    }
};

module.exports = supabaseAuth;
