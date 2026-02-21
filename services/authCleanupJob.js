const { pool } = require('./db');
const logger = require('../utils/logger');

function startAuthCleanupJob() {
    logger.info('Starting Auth Cleanup Background Job (runs every 5 minutes)');

    setInterval(async () => {
        try {
            // Delete users who are pending and whose verification token has expired
            // Also ensure we don't accidentally delete legacy users by checking if verification_expires_at is NOT NULL
            const result = await pool.query(`
                DELETE FROM users 
                WHERE status = 'pending' 
                AND verification_expires_at IS NOT NULL 
                AND verification_expires_at < NOW()
                RETURNING email
            `);

            if (result.rowCount > 0) {
                logger.info(`Auth Cleanup Job: Deleted ${result.rowCount} expired pending accounts.`);
            }
        } catch (error) {
            logger.error(`Auth Cleanup Job Error: ${error.message}`);
        }
    }, 5 * 60 * 1000); // 5 minutes
}

module.exports = { startAuthCleanupJob };
