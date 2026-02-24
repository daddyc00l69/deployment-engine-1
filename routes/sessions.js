const express = require('express');
const { pool } = require('../services/db');

const router = express.Router();

/**
 * GET /api/sessions
 * Returns active sessions/devices for the current user.
 */
router.get('/', async (req, res) => {
    try {
        const userId = req.user?.id;
        if (!userId) return res.status(401).json({ error: 'Unauthorized' });

        const { rows } = await pool.query(
            `
            SELECT
              id,
              device_name,
              browser,
              os,
              ip_address,
              country,
              created_at,
              last_active,
              expires_at,
              is_revoked
            FROM user_sessions
            WHERE user_id = $1
              AND is_revoked = false
              AND expires_at > NOW()
            ORDER BY last_active DESC
            `,
            [userId]
        );

        const currentSid = req.user?.sid || null;
        const sessions = rows.map((s) => ({
            id: s.id,
            device_name: s.device_name,
            browser: s.browser,
            os: s.os,
            ip: s.ip_address,
            country: s.country,
            last_active: s.last_active,
            created_at: s.created_at,
            expires_at: s.expires_at,
            current_device: currentSid ? String(s.id) === String(currentSid) : false,
        }));

        res.json({ sessions });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * POST /api/sessions/:id/revoke
 * Revoke a specific session/device.
 */
router.post('/:id/revoke', async (req, res) => {
    try {
        const userId = req.user?.id;
        if (!userId) return res.status(401).json({ error: 'Unauthorized' });

        const sessionId = req.params.id;
        const sessionRow = await pool.query(
            `SELECT id, device_name FROM user_sessions WHERE id = $1 AND user_id = $2 LIMIT 1`,
            [sessionId, userId]
        );
        if (sessionRow.rows.length === 0) {
            return res.status(404).json({ error: 'Session not found' });
        }

        const update = await pool.query(
            `
            UPDATE user_sessions
            SET is_revoked = true, revoked_at = NOW()
            WHERE id = $1 AND user_id = $2 AND is_revoked = false
            `,
            [sessionId, userId]
        );

        if (update.rowCount === 0) {
            return res.status(404).json({ error: 'Session not found' });
        }

        // If user revoked their current session, clear cookies so browser is logged out immediately.
        if (req.user?.sid && String(req.user.sid) === String(sessionId)) {
            const COOKIE_DOMAIN = process.env.COOKIE_DOMAIN
                || (process.env.DOMAIN
                    ? `.${String(process.env.DOMAIN).replace(/^https?:\/\//, '').replace(/^api\./, '')}`
                    : undefined);
            const clearBase = {
                domain: COOKIE_DOMAIN,
                sameSite: 'strict',
                secure: process.env.NODE_ENV === 'production'
            };
            res.clearCookie('vpsphere_token', clearBase);
            res.clearCookie('token', clearBase);
            res.clearCookie('refreshToken', { ...clearBase, path: '/auth/refresh' });
        }

        // Best-effort email notification for device removal (non-blocking).
        try {
            const userEmailRes = await pool.query('SELECT email FROM users WHERE id = $1', [userId]);
            const email = userEmailRes.rows[0]?.email;
            if (email) {
                const { sendDeviceRemovedEmail } = require('../services/mailer-otp');
                if (typeof sendDeviceRemovedEmail === 'function') {
                    sendDeviceRemovedEmail(email, sessionRow.rows[0].device_name || 'Unknown device').catch(() => {});
                }
            }
        } catch { /* ignore */ }

        res.json({ message: 'Session revoked' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * POST /api/sessions/revoke-all
 * Revoke all sessions/devices except current.
 */
router.post('/revoke-all', async (req, res) => {
    try {
        const userId = req.user?.id;
        const currentSid = req.user?.sid;
        if (!userId) return res.status(401).json({ error: 'Unauthorized' });
        if (!currentSid) return res.status(400).json({ error: 'Current session id missing' });

        const update = await pool.query(
            `
            UPDATE user_sessions
            SET is_revoked = true, revoked_at = NOW()
            WHERE user_id = $1
              AND id <> $2
              AND is_revoked = false
            `,
            [userId, currentSid]
        );

        res.json({ message: 'Other sessions revoked', revoked: update.rowCount || 0 });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

module.exports = router;

