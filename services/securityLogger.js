const { pool } = require('./db');
const logger = require('../utils/logger');

async function logSecurityEvent({ userId, ipAddress, country, riskScore, reason }) {
    try {
        await pool.query(
            `INSERT INTO security_logs (user_id, ip_address, country, risk_score, reason)
             VALUES ($1, $2, $3, $4, $5)`,
            [userId, ipAddress || null, country || null, Number(riskScore) || 0, reason || null]
        );
    } catch (e) {
        logger.error(`Failed to write security_logs: ${e.message}`);
    }
}

module.exports = { logSecurityEvent };

