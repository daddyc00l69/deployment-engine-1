const { pool } = require('../services/db');

/**
 * Updates user_sessions.last_active for the current session (sid) with throttling.
 * This keeps the Active Devices list fresh without writing on every request.
 */
function sessionActivity(options = {}) {
    const minIntervalSeconds = Number(options.minIntervalSeconds || 120);

    return async function sessionActivityMiddleware(req, _res, next) {
        try {
            const sid = req.user?.sid;
            const userId = req.user?.id;
            if (!sid || !userId) return next();

            await pool.query(
                `
                UPDATE user_sessions
                SET last_active = NOW()
                WHERE id = $1
                  AND user_id = $2
                  AND is_revoked = false
                  AND last_active < NOW() - ($3::text || ' seconds')::interval
                `,
                [sid, userId, String(minIntervalSeconds)]
            );
        } catch {
            // Never block requests due to activity tracking.
        }
        next();
    };
}

module.exports = sessionActivity;

