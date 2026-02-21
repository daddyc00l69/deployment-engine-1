const { pool } = require('../services/db');
const logger = require('../utils/logger');

/**
 * Middleware to restrict access based on user role.
 * Requires `supabaseAuth` to have been called first so `req.user` is populated.
 * @param {string} requiredRole - The role required to access the route (e.g., 'admin').
 */
const requireRole = (requiredRole) => {
    return async (req, res, next) => {
        try {
            if (!req.user || !req.user.id) {
                return res.status(401).json({ error: 'Unauthorized: No user session found' });
            }

            // Fetch the user's role from the database
            const result = await pool.query('SELECT role FROM users WHERE id = $1', [req.user.id]);

            if (result.rowCount === 0) {
                return res.status(404).json({ error: 'User not found' });
            }

            const userRole = result.rows[0].role;

            if (userRole !== requiredRole) {
                logger.warn(`Access denied: User ${req.user.id} requested ${req.originalUrl} requiring role '${requiredRole}' but has '${userRole}'.`);
                return res.status(403).json({ error: `Forbidden: Requires ${requiredRole} privileges` });
            }

            // User has the required role
            next();

        } catch (error) {
            logger.error(`Error in requireRole middleware: ${error.message}`);
            return res.status(500).json({ error: 'Internal server error verifying permissions' });
        }
    };
};

module.exports = requireRole;
