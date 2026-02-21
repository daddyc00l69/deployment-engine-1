const { pool } = require('./db');
const logger = require('../utils/logger');

const auditLogger = {
    /**
     * Log an authentication attempt
     * @param {string} userId - UUID of the user (can be null for failed unknown emails)
     * @param {string} ip - IP Address of the client
     * @param {string} userAgent - User Agent string
     * @param {string} status - 'success', 'failed', 'locked'
     */
    async logLoginAttempt(userId, ip, userAgent, status) {
        try {
            await pool.query(
                `INSERT INTO login_logs (user_id, ip_address, user_agent, status) VALUES ($1, $2, $3, $4)`,
                [userId, ip, userAgent, status]
            );
        } catch (error) {
            logger.error(`Failed to record login_log for user ${userId}: ${error.message}`);
        }
    },

    /**
     * Log a general platform audit action
     * @param {string} userId - UUID of the user performing the action
     * @param {string} action - Short string describing the action (e.g., 'ENABLE_2FA', 'PROJECT_CREATED')
     * @param {string} targetResource - Optional string identifying what was acted upon
     * @param {object} details - Optional JSON object with extra metadata
     * @param {string} ip - IP address of the user
     */
    async logAuditAction(userId, action, targetResource = null, details = null, ip = null) {
        try {
            await pool.query(
                `INSERT INTO audit_logs (user_id, action, target_resource, details, ip_address) VALUES ($1, $2, $3, $4, $5)`,
                [userId, action, targetResource, details, ip]
            );
        } catch (error) {
            logger.error(`Failed to record audit action '${action}' for user ${userId}: ${error.message}`);
        }
    }
};

module.exports = auditLogger;
