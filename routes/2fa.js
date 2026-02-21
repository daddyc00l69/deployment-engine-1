const express = require('express');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const { pool } = require('../services/db');
const jwt = require('jsonwebtoken');
const auditLogger = require('../services/auditLogger');
const supabaseAuth = require('../middleware/supabaseAuth');

const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret';

router.post('/generate', supabaseAuth, async (req, res) => {
    try {
        const result = await pool.query('SELECT email FROM users WHERE id = $1', [req.user.id]);
        const email = result.rows[0].email;

        const secret = speakeasy.generateSecret({ length: 20, name: `VPSphere (${email})` });

        // Save the secret temporarily to DB (user must verify to enable)
        await pool.query('UPDATE users SET two_factor_secret = $1 WHERE id = $2', [secret.base32, req.user.id]);

        const dataURL = await qrcode.toDataURL(secret.otpauth_url);
        res.json({ secret: secret.base32, qrcode: dataURL });
    } catch (error) {
        console.error('2FA Generate Error:', error);
        res.status(500).json({ error: 'Failed to generate 2FA secret' });
    }
});

router.post('/verify-setup', supabaseAuth, async (req, res) => {
    try {
        const { token } = req.body;
        const result = await pool.query('SELECT two_factor_secret FROM users WHERE id = $1', [req.user.id]);
        if (result.rows.length === 0) return res.status(404).json({ error: 'User not found' });

        const secret = result.rows[0].two_factor_secret;

        const verified = speakeasy.totp.verify({
            secret: secret,
            encoding: 'base32',
            token: token,
            window: 1
        });

        if (verified) {
            await pool.query('UPDATE users SET two_factor_enabled = true WHERE id = $1', [req.user.id]);
            await auditLogger.logAuditAction(req.user.id, 'ENABLE_2FA', null, null, req.ip);
            res.json({ message: '2FA enabled successfully' });
        } else {
            res.status(400).json({ error: 'Invalid 2FA code' });
        }
    } catch (error) {
        console.error('2FA Verify Setup Error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

router.post('/login', async (req, res) => {
    try {
        const { userId, token } = req.body;
        const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
        const userAgent = req.headers['user-agent'] || 'Unknown';

        const result = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);
        if (result.rows.length === 0) return res.status(401).json({ error: 'User not found' });

        const user = result.rows[0];

        if (!user.two_factor_enabled || !user.two_factor_secret) {
            return res.status(400).json({ error: '2FA is not enabled on this account. Proceed with standard login.' });
        }

        const verified = speakeasy.totp.verify({
            secret: user.two_factor_secret,
            encoding: 'base32',
            token: token,
            window: 1
        });

        if (!verified) {
            await auditLogger.logLoginAttempt(user.id, ip, userAgent, 'failed_2fa');
            return res.status(401).json({ error: 'Invalid 2FA authentication code' });
        }

        const previousLogins = await pool.query("SELECT id FROM login_logs WHERE user_id = $1 AND ip_address = $2 AND status IN ('success', 'success_2fa') LIMIT 1", [user.id, ip]);
        const isNewIp = previousLogins.rows.length === 0;

        await auditLogger.logLoginAttempt(user.id, ip, userAgent, 'success_2fa');

        if (isNewIp) {
            const { sendNewLoginSecurityEmail } = require('../services/mailer-otp');
            if (typeof sendNewLoginSecurityEmail === 'function') {
                sendNewLoginSecurityEmail(user.email, ip, userAgent).catch(e => console.error(e));
            }
        }

        const accessToken = jwt.sign(
            { id: user.id, username: user.username, plan_id: user.plan_id },
            JWT_SECRET,
            { expiresIn: '15m' }
        );

        const crypto = require('crypto');
        const refreshToken = crypto.randomBytes(40).toString('hex');
        const hashedRefreshToken = crypto.createHash('sha256').update(refreshToken).digest('hex');

        await pool.query(
            `INSERT INTO refresh_tokens (user_id, hashed_token, expires_at) VALUES ($1, $2, NOW() + INTERVAL '7 days')`,
            [user.id, hashedRefreshToken]
        );

        res.cookie('token', accessToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 15 * 60 * 1000 // 15 mins
        });

        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
        });

        res.json({ token: accessToken, user: { id: user.id, username: user.username, plan_id: user.plan_id } });

    } catch (error) {
        console.error('2FA Login Error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

module.exports = router;
