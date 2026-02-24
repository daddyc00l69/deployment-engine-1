const { pool } = require('./db');

/**
 * Calculate login risk score (0-100) for a successful credential check.
 * This is intentionally heuristic (enterprise-style "risk signals"), not ML.
 */
async function calculateLoginRisk({
    userId,
    deviceFingerprint,
    country,
    ipAddress,
    userAgent,
}) {
    const reasons = [];
    let score = 0;

    // 1) New Device (+25)
    let isNewDevice = false;
    if (deviceFingerprint) {
        const dev = await pool.query(
            `SELECT 1 FROM user_sessions WHERE user_id = $1 AND device_fingerprint = $2 LIMIT 1`,
            [userId, deviceFingerprint]
        );
        isNewDevice = dev.rows.length === 0;
        if (isNewDevice) {
            score += 25;
            reasons.push('new_device');
        }
    }

    // 2) New Country (+35)
    let isNewCountry = false;
    let lastCountry = null;
    let lastCountryAt = null;
    if (country) {
        const prev = await pool.query(
            `SELECT country, created_at
             FROM user_sessions
             WHERE user_id = $1 AND country IS NOT NULL
             ORDER BY created_at DESC
             LIMIT 1`,
            [userId]
        );
        if (prev.rows.length > 0) {
            lastCountry = prev.rows[0].country;
            lastCountryAt = prev.rows[0].created_at;
            if (String(lastCountry) !== String(country)) {
                isNewCountry = true;
                score += 35;
                reasons.push('new_country');
            }
        }
    }

    // 4) Impossible travel (+40)
    // Heuristic: country changed within 6 hours of last country-tagged session.
    if (isNewCountry && lastCountryAt) {
        const dtMs = Math.abs(new Date().getTime() - new Date(lastCountryAt).getTime());
        const hours = dtMs / (1000 * 60 * 60);
        if (hours < 6) {
            score += 40;
            reasons.push('impossible_travel');
        }
    }

    // 5) Multiple failed attempts (+30)
    // Count failed logins in last 15 minutes.
    const failed = await pool.query(
        `
        SELECT COUNT(*)::int AS cnt
        FROM login_logs
        WHERE user_id = $1
          AND status IN ('failed', 'failed_2fa', 'failed_unverified')
          AND created_at > NOW() - INTERVAL '15 minutes'
        `,
        [userId]
    );
    const failedCount = failed.rows[0]?.cnt || 0;
    if (failedCount >= 3) {
        score += 30;
        reasons.push('multiple_failed_attempts');
    }

    // Clamp to 0-100
    score = Math.max(0, Math.min(100, score));

    return {
        score,
        reasons,
        signals: {
            isNewDevice,
            isNewCountry,
            lastCountry,
            failedCount,
            country,
            ipAddress,
            userAgent,
        }
    };
}

module.exports = { calculateLoginRisk };

