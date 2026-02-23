const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { pool } = require('../services/db');
const logger = require('../utils/logger');
const auditLogger = require('../services/auditLogger');
const requireRole = require('../middleware/requireRole');
const router = express.Router();
const crypto = require('crypto');
const otpRoutes = require('../modules/email-otp/index');
const twoFactorRoutes = require('./2fa');
const authMiddleware = require('../middleware/authMiddleware');
const UAParser = require('ua-parser-js');
const { calculateLoginRisk } = require('../services/riskScoring');
const { logSecurityEvent } = require('../services/securityLogger');

const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret';
const COOKIE_DOMAIN = process.env.COOKIE_DOMAIN
    || (process.env.DOMAIN
        ? `.${String(process.env.DOMAIN).replace(/^https?:\/\//, '').replace(/^api\./, '')}`
        : undefined);

function sha256Hex(input) {
    return crypto.createHash('sha256').update(String(input)).digest('hex');
}

function generateRefreshToken() {
    // 320 bits of entropy
    return crypto.randomBytes(40).toString('hex');
}

function getClientIp(req) {
    // trust proxy is enabled globally; req.ip should be accurate
    const xf = req.headers['x-forwarded-for'];
    if (xf) return String(xf).split(',')[0].trim();
    return req.ip || req.socket?.remoteAddress || null;
}

function getCountry(req) {
    // Cloudflare provides cf-ipcountry, else null
    const c = req.headers['cf-ipcountry'];
    return c ? String(c) : null;
}

function parseDeviceInfo(userAgent) {
    const ua = new UAParser(userAgent || '');
    const browser = ua.getBrowser();
    const os = ua.getOS();
    const device = ua.getDevice();

    const browserText = [browser.name, browser.version].filter(Boolean).join(' ');
    const osText = [os.name, os.version].filter(Boolean).join(' ');
    const deviceText = [device.vendor, device.model].filter(Boolean).join(' ').trim()
        || device.type
        || 'Unknown device';

    const deviceFingerprint = sha256Hex([browserText, osText, userAgent || ''].join('|'));

    return {
        device_name: deviceText,
        browser: browserText || null,
        os: osText || null,
        device_fingerprint: deviceFingerprint,
    };
}

async function createLoginChallenge({ user, riskScore, reasons, ip, country, userAgent, deviceFingerprint }) {
    const otp = crypto.randomInt(100000, 999999).toString();
    const salt = await bcrypt.genSalt(12);
    const otpHash = await bcrypt.hash(otp, salt);

    const insert = await pool.query(
        `INSERT INTO login_challenges (
            user_id, email, otp_hash, risk_score, reason, ip_address, country, user_agent, device_fingerprint, expires_at
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9, NOW() + INTERVAL '5 minutes')
         RETURNING id`,
        [
            user.id,
            user.email,
            otpHash,
            riskScore,
            reasons.join(','),
            ip,
            country,
            userAgent,
            deviceFingerprint
        ]
    );

    const { sendLoginBlockedOtpEmail } = require('../services/mailer-otp');
    await sendLoginBlockedOtpEmail(user.email, otp, ip, userAgent, country);

    return insert.rows[0]?.id;
}

function setSessionCookies(res, accessToken, refreshToken) {
    const baseOptions = {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        domain: COOKIE_DOMAIN
    };

    // Shared-cookie name used by Next.js middleware (frontend domain).
    res.cookie('vpsphere_token', accessToken, {
        ...baseOptions,
        maxAge: 15 * 60 * 1000
    });

    // Backwards-compat for older code paths (can be removed after rollout).
    res.cookie('token', accessToken, {
        ...baseOptions,
        maxAge: 15 * 60 * 1000
    });

    if (refreshToken) {
        res.cookie('refreshToken', refreshToken, {
            ...baseOptions,
            path: '/auth/refresh',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });
    }
}

function clearSessionCookies(res) {
    const clearBase = {
        domain: COOKIE_DOMAIN,
        sameSite: 'strict',
        secure: process.env.NODE_ENV === 'production'
    };
    res.clearCookie('vpsphere_token', clearBase);
    res.clearCookie('token', clearBase);
    res.clearCookie('refreshToken', { ...clearBase, path: '/auth/refresh' });
}

// Mount OTP routes
router.use('/otp', otpRoutes);
router.use('/2fa', twoFactorRoutes);


router.post('/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;

        if (!username || !email || !password) {
            return res.status(400).json({ error: 'Username, email and password are required' });
        }

        const validUsername = /^[a-z0-9]+$/.test(username);
        if (!validUsername) {
            return res.status(400).json({ error: 'Username must be lowercase alphanumeric only' });
        }

        const validPassword = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{12,}$/.test(password);
        if (!validPassword) {
            return res.status(400).json({ error: 'Password must be at least 12 characters and include uppercase, lowercase, number, and special character.' });
        }

        const client = await pool.connect();
        try {
            // Check if user exists
            const userCheck = await client.query('SELECT id FROM users WHERE username = $1 OR email = $2', [username, email]);
            if (userCheck.rows.length > 0) {
                return res.status(409).json({ error: 'Username or email already exists' });
            }

            // Assign default free plan (Plan ID 1)
            const planCheck = await client.query('SELECT id FROM plans WHERE name = $1', ['Free']);
            if (planCheck.rows.length === 0) {
                return res.status(500).json({ error: 'No default plan configured in database' });
            }
            const planId = planCheck.rows[0].id;

            const crypto = require('crypto');
            const fs = require('fs');
            const path = require('path');
            const { sendOTP } = require('../services/mailer-otp');

            // Generate OTP
            const otp = crypto.randomInt(100000, 999999).toString();
            const saltOtp = await bcrypt.genSalt(12);
            const hashedOtp = await bcrypt.hash(otp, saltOtp);

            const salt = await bcrypt.genSalt(12);
            const hashedPassword = await bcrypt.hash(password, salt);

            // Insert User and OTP securely directly into Postgres
            const result = await client.query(
                `INSERT INTO users 
                (username, email, password_hash, plan_id, email_verified, status, otp_hash, verification_expires_at) 
                VALUES ($1, $2, $3, $4, false, 'pending', $5, NOW() + INTERVAL '15 minutes') 
                RETURNING id, username, email, plan_id`,
                [username, email, hashedPassword, planId, hashedOtp]
            );

            logger.info(`User registered successfully: ${username}`);
            console.log(`[DEBUG] Registration Complete. User: ${email}, OTP Hash generated.`);

            // Send OTP via email
            const otpSent = await sendOTP(email, otp);
            if (!otpSent) {
                // Avoid leaving a "pending" account that can never be verified.
                // If SMTP is temporarily down, user can retry registration once fixed.
                await client.query('DELETE FROM users WHERE id = $1', [result.rows[0].id]);
                return res.status(500).json({ error: 'Failed to send OTP email. Please try again later.' });
            }

            try {
                const logPath = path.join(__dirname, '../project-logs/user-flow-log.txt');
                fs.appendFileSync(logPath, `[${new Date().toISOString()}]\nFLOW: Registration\nSTATUS: OTP Sent\nUSER: ${email}\n\n`);
            } catch (e) { }

            res.status(202).json({ message: 'User registered, verification required', status: 'verification_required', email });

        } finally {
            client.release();
        }

    } catch (error) {
        logger.error(`Registration error: ${error.message}`);
        res.status(500).json({ error: 'Internal server error' });
    }
});

router.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const ip = getClientIp(req);
        const userAgent = req.headers['user-agent'] || 'Unknown';
        const country = getCountry(req);

        if (!username || !password) {
            return res.status(400).json({ error: 'Username/Email and password are required' });
        }

        const result = await pool.query('SELECT * FROM users WHERE username = $1 OR email = $1', [username]);
        if (result.rows.length === 0) {
            await auditLogger.logLoginAttempt(null, ip, userAgent, 'failed');
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const user = result.rows[0];

        // 1. Check if Account is Locked
        if (user.locked_until && new Date() < new Date(user.locked_until)) {
            const minutesLeft = Math.ceil((new Date(user.locked_until) - new Date()) / 60000);
            await auditLogger.logLoginAttempt(user.id, ip, userAgent, 'locked');
            return res.status(403).json({ error: `Account locked due to too many failed attempts. Try again in ${minutesLeft} minutes.` });
        }

        // 2. Validate Password
        const validPassword = await bcrypt.compare(password, user.password_hash);

        // Debugging strictly as requested for credentials check
        console.log(`[DEBUG] Login Attempt: ${username}, Password valid? ${validPassword}`);

        if (!validPassword) {
            const newAttempts = (user.failed_login_attempts || 0) + 1;
            if (newAttempts >= 5) {
                // Lock account for 15 minutes
                await pool.query(`UPDATE users SET failed_login_attempts = $1, locked_until = NOW() + INTERVAL '15 minutes' WHERE id = $2`, [newAttempts, user.id]);
                await auditLogger.logLoginAttempt(user.id, ip, userAgent, 'locked');

                const { sendAccountLockedEmail } = require('../services/mailer-otp');
                if (typeof sendAccountLockedEmail === 'function') {
                    await sendAccountLockedEmail(user.email, ip, userAgent);
                }

                return res.status(403).json({ error: 'Account locked due to 5 failed login attempts. Try again in 15 minutes.' });
            } else {
                await pool.query(`UPDATE users SET failed_login_attempts = $1 WHERE id = $2`, [newAttempts, user.id]);
                await auditLogger.logLoginAttempt(user.id, ip, userAgent, 'failed');
                return res.status(401).json({ error: 'Invalid email or password' });
            }
        }

        // 3. Reset failed attempts on success
        if (user.failed_login_attempts > 0 || user.locked_until) {
            await pool.query(`UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = $1`, [user.id]);
        }

        // 4. Require Active Registration Status
        if (user.status !== 'active') {
            await auditLogger.logLoginAttempt(user.id, ip, userAgent, 'failed_unverified');
            return res.status(403).json({ error: 'Account is not fully verified yet. Please check your email.', status: 'verification_required' });
        }

        const deviceInfo = parseDeviceInfo(userAgent);
        const risk = await calculateLoginRisk({
            userId: user.id,
            deviceFingerprint: deviceInfo.device_fingerprint,
            country,
            ipAddress: ip,
            userAgent
        });

        // Medium risk: alert but allow login
        if (risk.score >= 31 && risk.score < 60) {
            await logSecurityEvent({
                userId: user.id,
                ipAddress: ip,
                country,
                riskScore: risk.score,
                reason: risk.reasons.join(',')
            });
            const { sendSuspiciousLoginAttemptEmail } = require('../services/mailer-otp');
            if (typeof sendSuspiciousLoginAttemptEmail === 'function') {
                sendSuspiciousLoginAttemptEmail(user.email, ip, userAgent, country).catch(e => logger.error(e));
            }
        }

        // High risk behavior is configurable:
        // - block_otp (default): block login and require OTP challenge
        // - allow_alert: allow login, but log + alert
        const highRiskMode = String(process.env.HIGH_RISK_LOGIN_MODE || 'block_otp').toLowerCase();

        // High risk: log security event (always)
        if (risk.score >= 60) {
            await logSecurityEvent({
                userId: user.id,
                ipAddress: ip,
                country,
                riskScore: risk.score,
                reason: risk.reasons.join(',')
            });

            // Allow + alert mode (requested): do NOT block the session creation.
            // This avoids breaking the login flow since the frontend does not currently implement OTP challenge UI.
            if (highRiskMode === 'allow_alert') {
                const { sendSuspiciousLoginAttemptEmail } = require('../services/mailer-otp');
                if (typeof sendSuspiciousLoginAttemptEmail === 'function') {
                    sendSuspiciousLoginAttemptEmail(user.email, ip, userAgent, country).catch(e => logger.error(e));
                }
            } else {
                // Default: block and require OTP challenge
                const challengeId = await createLoginChallenge({
                    user,
                    riskScore: risk.score,
                    reasons: risk.reasons,
                    ip,
                    country,
                    userAgent,
                    deviceFingerprint: deviceInfo.device_fingerprint
                });

                return res.status(202).json({
                    requires_otp: true,
                    challengeId,
                    message: 'Login blocked. Verification required.'
                });
            }
        }

        if (user.two_factor_enabled) {
            await auditLogger.logLoginAttempt(user.id, ip, userAgent, 'pending_2fa');
            return res.status(202).json({ requires_2fa: true, userId: user.id, message: '2FA token required.' });
        }

        const previousLogins = await pool.query("SELECT id FROM login_logs WHERE user_id = $1 AND ip_address = $2 AND status = 'success' LIMIT 1", [user.id, ip]);
        const isNewIp = previousLogins.rows.length === 0;

        await auditLogger.logLoginAttempt(user.id, ip, userAgent, 'success');

        if (isNewIp) {
            const { sendNewLoginSecurityEmail } = require('../services/mailer-otp');
            if (typeof sendNewLoginSecurityEmail === 'function') {
                sendNewLoginSecurityEmail(user.email, ip, userAgent).catch(e => logger.error(e));
            }
        }

        // New device detection (by device fingerprint)
        const existingDevice = await pool.query(
            `SELECT id FROM user_sessions
             WHERE user_id = $1 AND device_fingerprint = $2
             LIMIT 1`,
            [user.id, deviceInfo.device_fingerprint]
        );
        const isNewDevice = existingDevice.rows.length === 0;

        const refreshToken = generateRefreshToken();
        const refreshTokenHash = sha256Hex(refreshToken);

        const sessionInsert = await pool.query(
            `INSERT INTO user_sessions (
                user_id,
                device_name,
                browser,
                os,
                user_agent,
                ip_address,
                country,
                device_fingerprint,
                refresh_token_hash,
                expires_at
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9, NOW() + INTERVAL '7 days')
            RETURNING id`,
            [
                user.id,
                deviceInfo.device_name,
                deviceInfo.browser,
                deviceInfo.os,
                userAgent,
                ip,
                country,
                deviceInfo.device_fingerprint,
                refreshTokenHash
            ]
        );

        const sessionId = sessionInsert.rows[0]?.id;
        const accessToken = jwt.sign(
            { id: user.id, username: user.username, plan_id: user.plan_id, sid: sessionId },
            JWT_SECRET,
            { expiresIn: '15m' }
        );

        setSessionCookies(res, accessToken, refreshToken);

        if (isNewDevice) {
            const { sendNewDeviceLoginDetectedEmail } = require('../services/mailer-otp');
            if (typeof sendNewDeviceLoginDetectedEmail === 'function') {
                sendNewDeviceLoginDetectedEmail(user.email, ip, userAgent, country).catch(e => logger.error(e));
            }
        }

        try {
            const fs = require('fs');
            const path = require('path');
            const logPath = path.join(__dirname, '../project-logs/user-flow-log.txt');
            fs.appendFileSync(logPath, `[${new Date().toISOString()}]\nFLOW: Login\nSTATUS: Success\nUSER: ${user.email}\n\n`);
        } catch (e) { }

        res.json({ token: accessToken, user: { id: user.id, username: user.username, plan_id: user.plan_id } });

    } catch (error) {
        logger.error(`Login error: ${error.message}`);
        res.status(500).json({ error: 'Internal server error' });
    }
});

const cookieParser = require('cookie-parser');
router.use(cookieParser());

// Refresh Route
router.post('/refresh', async (req, res) => {
    try {
        const { refreshToken } = req.cookies;
        if (!refreshToken) return res.status(401).json({ error: 'No refresh token provided' });

        const presentedHash = sha256Hex(refreshToken);

        // 1) Happy path: token matches current refresh secret for a session.
        const sessRes = await pool.query(
            `SELECT id, user_id, is_revoked, expires_at, previous_refresh_token_hash
             FROM user_sessions
             WHERE refresh_token_hash = $1
             LIMIT 1`,
            [presentedHash]
        );

        // 2) Reuse detection: token matches "previous_refresh_token_hash" for an active session.
        if (sessRes.rows.length === 0) {
            const reuseRes = await pool.query(
                `SELECT id FROM user_sessions
                 WHERE previous_refresh_token_hash = $1 AND is_revoked = false
                 LIMIT 1`,
                [presentedHash]
            );
            if (reuseRes.rows.length > 0) {
                await pool.query(
                    `UPDATE user_sessions SET is_revoked = true, revoked_at = NOW() WHERE id = $1`,
                    [reuseRes.rows[0].id]
                );
                clearSessionCookies(res);
                return res.status(403).json({ error: 'Refresh token reuse detected. Session revoked.' });
            }

            clearSessionCookies(res);
            return res.status(403).json({ error: 'Invalid refresh token' });
        }

        const session = sessRes.rows[0];
        if (session.is_revoked || new Date() > new Date(session.expires_at)) {
            clearSessionCookies(res);
            return res.status(403).json({ error: 'Refresh token expired or revoked' });
        }

        // Fetch User
        const userResult = await pool.query(
            'SELECT id, username, plan_id, status FROM users WHERE id = $1',
            [session.user_id]
        );
        if (userResult.rows.length === 0 || userResult.rows[0].status !== 'active') {
            clearSessionCookies(res);
            return res.status(403).json({ error: 'User is invalid' });
        }
        const user = userResult.rows[0];

        // Rotate refresh token (strict rotation)
        const newRefreshToken = generateRefreshToken();
        const newHash = sha256Hex(newRefreshToken);

        await pool.query(
            `UPDATE user_sessions
             SET previous_refresh_token_hash = $1,
                 refresh_token_hash = $2,
                 last_active = NOW(),
                 expires_at = NOW() + INTERVAL '7 days'
             WHERE id = $3`,
            [presentedHash, newHash, session.id]
        );

        const accessToken = jwt.sign(
            { id: user.id, username: user.username, plan_id: user.plan_id, sid: session.id },
            JWT_SECRET,
            { expiresIn: '15m' }
        );

        setSessionCookies(res, accessToken, newRefreshToken);
        res.json({ token: accessToken });
    } catch (error) {
        logger.error(`Refresh error: ${error.message}`);
        res.status(500).json({ error: 'Internal server error during refresh' });
    }
});

/**
 * POST /auth/login/otp/verify
 * Completes a high-risk login by verifying the emailed OTP challenge, then issuing session cookies.
 */
router.post('/login/otp/verify', async (req, res) => {
    try {
        const { challengeId, otp } = req.body || {};
        if (!challengeId || !otp) return res.status(400).json({ error: 'challengeId and otp are required' });

        const cRes = await pool.query(
            `SELECT id, user_id, email, otp_hash, expires_at, verified_at, ip_address, country, user_agent, device_fingerprint
             FROM login_challenges
             WHERE id = $1
             LIMIT 1`,
            [challengeId]
        );
        if (cRes.rows.length === 0) return res.status(400).json({ error: 'Invalid challenge' });
        const ch = cRes.rows[0];
        if (ch.verified_at) return res.status(400).json({ error: 'Challenge already used' });
        if (new Date() > new Date(ch.expires_at)) return res.status(400).json({ error: 'Challenge expired' });

        const ok = await bcrypt.compare(String(otp), ch.otp_hash);
        if (!ok) return res.status(401).json({ error: 'Invalid OTP' });

        await pool.query(`UPDATE login_challenges SET verified_at = NOW() WHERE id = $1`, [ch.id]);

        const userRes = await pool.query(
            'SELECT id, username, plan_id, status, two_factor_enabled FROM users WHERE id = $1',
            [ch.user_id]
        );
        if (userRes.rows.length === 0 || userRes.rows[0].status !== 'active') {
            return res.status(403).json({ error: 'User is invalid' });
        }
        const user = userRes.rows[0];

        if (user.two_factor_enabled) {
            // OTP passed; still need 2FA for final login.
            return res.status(202).json({ requires_2fa: true, userId: user.id, message: '2FA token required.' });
        }

        const refreshToken = generateRefreshToken();
        const refreshTokenHash = sha256Hex(refreshToken);

        const sessionInsert = await pool.query(
            `INSERT INTO user_sessions (
                user_id, device_name, browser, os, user_agent, ip_address, country, device_fingerprint, refresh_token_hash, expires_at
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9, NOW() + INTERVAL '7 days')
            RETURNING id`,
            [
                user.id,
                'Verified login',
                null,
                null,
                ch.user_agent,
                ch.ip_address,
                ch.country,
                ch.device_fingerprint,
                refreshTokenHash
            ]
        );
        const sessionId = sessionInsert.rows[0]?.id;

        const accessToken = jwt.sign(
            { id: user.id, username: user.username, plan_id: user.plan_id, sid: sessionId },
            JWT_SECRET,
            { expiresIn: '15m' }
        );

        setSessionCookies(res, accessToken, refreshToken);
        res.json({ token: accessToken, user: { id: user.id, username: user.username, plan_id: user.plan_id } });
    } catch (error) {
        logger.error(`Login OTP verify error: ${error.message}`);
        res.status(500).json({ error: 'Internal server error' });
    }
});

router.post('/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) return res.status(400).json({ error: 'Email is required' });

        const result = await pool.query('SELECT id, status FROM users WHERE email = $1', [email]);
        if (result.rows.length === 0) {
            // Return 200 anyway to prevent email enumeration
            return res.status(200).json({ message: 'If that email is in our database, we have sent a reset link' });
        }

        const user = result.rows[0];
        if (user.status !== 'active') {
            return res.status(400).json({ error: 'Account is not verified yet.' });
        }

        const crypto = require('crypto');
        const token = crypto.randomBytes(32).toString('hex');

        const salt = await bcrypt.genSalt(10);
        const hashedToken = await bcrypt.hash(token, salt);

        await pool.query(
            `UPDATE users SET reset_token_hash = $1, reset_expires_at = NOW() + INTERVAL '15 minutes' WHERE id = $2`,
            [hashedToken, user.id]
        );

        const { sendPasswordResetEmail } = require('../services/mailer-otp');
        const resetLink = `https://devtushar.uk/reset-password?token=${token}&email=${encodeURIComponent(email)}`;
        console.log("Reset email triggered for:", email, "Link:", resetLink);

        await sendPasswordResetEmail(email, resetLink);

        res.status(200).json({ message: 'If that email is in our database, we have sent a reset link' });

    } catch (error) {
        logger.error(`Forgot password error: ${error.message}`);
        res.status(500).json({ error: 'Internal server error processing reset request' });
    }
});

router.post('/reset-password', async (req, res) => {
    try {
        const { email, token, newPassword } = req.body;
        if (!email || !token || !newPassword) {
            return res.status(400).json({ error: 'Missing required fields' });
        }
        const validPassword = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{12,}$/.test(newPassword);
        if (!validPassword) {
            return res.status(400).json({ error: 'Password must be at least 12 characters and include uppercase, lowercase, number, and special character.' });
        }

        const result = await pool.query(
            'SELECT id, username, plan_id, reset_token_hash, reset_expires_at FROM users WHERE email = $1',
            [email]
        );

        if (result.rows.length === 0) {
            return res.status(400).json({ error: 'Invalid reset link' });
        }

        const user = result.rows[0];

        if (!user.reset_token_hash || new Date() > new Date(user.reset_expires_at)) {
            return res.status(400).json({ error: 'Reset link has expired. Please request a new one.' });
        }

        const isValid = await bcrypt.compare(token, user.reset_token_hash);
        if (!isValid) {
            return res.status(400).json({ error: 'Invalid reset link' });
        }

        // Token matches! Update password and wipe reset token
        const salt = await bcrypt.genSalt(12);
        const hashedPassword = await bcrypt.hash(newPassword, salt);

        await pool.query(
            `UPDATE users 
             SET password_hash = $1, reset_token_hash = NULL, reset_expires_at = NULL, failed_login_attempts = 0, locked_until = NULL 
             WHERE id = $2`,
            [hashedPassword, user.id]
        );

        // Revoke all prior cross-device authentications
        await pool.query('UPDATE user_sessions SET is_revoked = true, revoked_at = NOW() WHERE user_id = $1', [user.id]);

        // Auto-login user as a fresh session (device unknown)
        const ip = getClientIp(req);
        const userAgent = req.headers['user-agent'] || 'Unknown';
        const country = getCountry(req);

        const newRefreshToken = generateRefreshToken();
        const newHash = sha256Hex(newRefreshToken);
        const sessInsert = await pool.query(
            `INSERT INTO user_sessions (
                user_id, device_name, browser, os, user_agent, ip_address, country, device_fingerprint, refresh_token_hash, expires_at
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9, NOW() + INTERVAL '7 days')
            RETURNING id`,
            [
                user.id,
                'Password reset session',
                null,
                null,
                userAgent,
                ip,
                country,
                sha256Hex(userAgent),
                newHash
            ]
        );
        const sessionId = sessInsert.rows[0]?.id;

        const accessToken = jwt.sign(
            { id: user.id, username: user.username, plan_id: user.plan_id, sid: sessionId },
            JWT_SECRET,
            { expiresIn: '15m' }
        );

        setSessionCookies(res, accessToken, newRefreshToken);

        const { sendPasswordResetSuccessEmail } = require('../services/mailer-otp');
        if (typeof sendPasswordResetSuccessEmail === 'function') {
            sendPasswordResetSuccessEmail(email).catch(e => logger.error(e));
        }

        res.status(200).json({ message: 'Password reset successfully', token: accessToken, user: { id: user.id, username: user.username } });

    } catch (error) {
        logger.error(`Reset password error: ${error.message}`);
        res.status(500).json({ error: 'Internal server error processing reset' });
    }
});

// User Audit & Login Logs (cookie-based auth)
router.get('/audit-logs', authMiddleware, async (req, res) => {
    try {
        const logs = await pool.query(`
            SELECT id, ip_address, user_agent, status as event, created_at 
            FROM login_logs 
            WHERE user_id = $1 
            ORDER BY created_at DESC 
            LIMIT 20
        `, [req.user.id]);

        res.json(logs.rows);
    } catch (error) {
        logger.error(`Audit Logs Error: ${error.message}`);
        res.status(500).json({ error: 'Failed to fetch logs' });
    }
});

// POST /logout - Revoke current session (if possible) then clear cookies.
// We don't require authMiddleware; access cookie may already be expired, but refresh can still identify the session.
router.post('/logout', async (req, res) => {
    try {
        const refreshToken = req.cookies?.refreshToken || null;
        if (refreshToken) {
            const h = sha256Hex(refreshToken);
            await pool.query(
                `UPDATE user_sessions
                 SET is_revoked = true, revoked_at = NOW()
                 WHERE refresh_token_hash = $1 OR previous_refresh_token_hash = $1`,
                [h]
            );
        } else {
            // If we can decode access token, revoke by sid.
            const access = req.cookies?.vpsphere_token || req.cookies?.token || null;
            if (access) {
                try {
                    const decoded = jwt.verify(access, JWT_SECRET);
                    if (decoded?.sid) {
                        await pool.query(
                            `UPDATE user_sessions SET is_revoked = true, revoked_at = NOW()
                             WHERE id = $1 AND user_id = $2`,
                            [decoded.sid, decoded.id]
                        );
                    }
                } catch { /* ignore */ }
            }
        }

        // We can optionally log the auth attempt if we have user ID, but we might not.

        clearSessionCookies(res);

        res.json({ message: 'Logged out successfully' });
    } catch (error) {
        logger.error(`Logout Error: ${error.message}`);
        // Even if DB delete fails, we should still clear local cookies
        clearSessionCookies(res);
        res.status(500).json({ error: 'Failed to process logout fully, but local session cleared' });
    }
});

/**
 * GET /auth/me
 * Returns current authenticated user (cookie or Bearer token).
 */
router.get('/me', authMiddleware, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT id, username, email, plan_id, status, email_verified FROM users WHERE id = $1',
            [req.user.id]
        );
        if (result.rows.length === 0) return res.status(404).json({ error: 'User not found' });
        res.json({ user: result.rows[0] });
    } catch (error) {
        logger.error(`Auth /me error: ${error.message}`);
        res.status(500).json({ error: 'Failed to load user profile' });
    }
});

/**
 * POST /admin/reset-user/:id
 * Admin ONLY: Force User Account Reset
 * Nuke all outstanding refresh tokens and clear 2FA locks
 */
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1] || req.cookies?.token;
    if (!token) return res.status(401).json({ error: 'Access denied' });
    jwt.verify(token, process.env.JWT_SECRET || 'fallback_secret', (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });
        req.user = user;
        next();
    });
};

router.post('/admin/reset-user/:id', authenticateToken, requireRole('admin'), async (req, res) => {
    const targetUserId = req.params.id;
    try {
        const client = await pool.connect();
        try {
            await client.query('BEGIN');

            await client.query(
                `UPDATE users SET two_factor_secret = NULL, two_factor_enabled = false, status = 'active' WHERE id = $1`,
                [targetUserId]
            );

            await client.query(
                `UPDATE user_sessions SET is_revoked = true, revoked_at = NOW() WHERE user_id = $1`,
                [targetUserId]
            );

            await client.query('COMMIT');
            logger.info(`Admin ${req.user.id} forcefully reset account for user ${targetUserId}`);
            res.status(200).json({ message: 'User account security reset successfully.' });

        } catch (txnError) {
            await client.query('ROLLBACK');
            throw txnError;
        } finally {
            client.release();
        }
    } catch (error) {
        logger.error(`Admin Force-Reset Error for User ${targetUserId}: ${error.message}`);
        res.status(500).json({ error: 'Failed to execute administrative account reset.' });
    }
});

module.exports = router;
