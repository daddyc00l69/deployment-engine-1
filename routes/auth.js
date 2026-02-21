const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { pool } = require('../services/db');
const logger = require('../utils/logger');
const auditLogger = require('../services/auditLogger');
const router = express.Router();
const crypto = require('crypto');
const otpRoutes = require('../modules/email-otp/index');
const twoFactorRoutes = require('./2fa');
const supabaseAuth = require('../middleware/supabaseAuth');

const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret';

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
            await sendOTP(email, otp);

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
        const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
        const userAgent = req.headers['user-agent'] || 'Unknown';

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
        console.log(`[DEBUG] Login Attempt: ${email || username}, Password valid? ${validPassword}`);

        if (!validPassword) {
            const newAttempts = (user.failed_login_attempts || 0) + 1;
            if (newAttempts >= 5) {
                // Lock account for 15 minutes
                await pool.query(`UPDATE users SET failed_login_attempts = $1, locked_until = NOW() + INTERVAL '15 minutes' WHERE id = $2`, [newAttempts, user.id]);
                await auditLogger.logLoginAttempt(user.id, ip, userAgent, 'locked');

                const { sendSuspiciousActivityEmail } = require('../services/mailer-otp');
                if (typeof sendSuspiciousActivityEmail === 'function') {
                    await sendSuspiciousActivityEmail(user.email, ip, userAgent);
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

        const accessToken = jwt.sign(
            { id: user.id, username: user.username, plan_id: user.plan_id },
            JWT_SECRET,
            { expiresIn: '15m' }
        );

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
            path: '/auth/refresh',
            maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
        });

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

        const hashedRefreshToken = crypto.createHash('sha256').update(refreshToken).digest('hex');
        const result = await pool.query('SELECT * FROM refresh_tokens WHERE hashed_token = $1', [hashedRefreshToken]);

        if (result.rows.length === 0) {
            return res.status(403).json({ error: 'Invalid refresh token' });
        }

        const rtData = result.rows[0];

        // Ensure token has not been historically revoked and has not expired
        if (rtData.revoked || new Date() > new Date(rtData.expires_at)) {
            return res.status(403).json({ error: 'Refresh token expired or revoked' });
        }

        // Fetch User
        const userResult = await pool.query('SELECT id, username, plan_id, status FROM users WHERE id = $1', [rtData.user_id]);
        if (userResult.rows.length === 0 || userResult.rows[0].status !== 'active') {
            return res.status(403).json({ error: 'User is invalid' });
        }

        const user = userResult.rows[0];

        // Issue new Access Token
        const accessToken = jwt.sign(
            { id: user.id, username: user.username, plan_id: user.plan_id },
            JWT_SECRET,
            { expiresIn: '15m' }
        );

        // Security Mechanism: Token Rotation. Revoke the utilized refresh token.
        await pool.query('UPDATE refresh_tokens SET revoked = true WHERE id = $1', [rtData.id]);

        // Issue strictly new Refresh Token
        const newRefreshToken = crypto.randomBytes(40).toString('hex');
        const newHashedRT = crypto.createHash('sha256').update(newRefreshToken).digest('hex');

        await pool.query(
            `INSERT INTO refresh_tokens (user_id, hashed_token, expires_at) VALUES ($1, $2, NOW() + INTERVAL '7 days')`,
            [user.id, newHashedRT]
        );

        res.cookie('token', accessToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 15 * 60 * 1000 // 15 mins
        });

        res.cookie('refreshToken', newRefreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            path: '/auth/refresh',
            maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
        });

        res.json({ token: accessToken });
    } catch (error) {
        logger.error(`Refresh error: ${error.message}`);
        res.status(500).json({ error: 'Internal server error during refresh' });
    }
});

// Logout Route (Revokes Tokens)
router.post('/logout', async (req, res) => {
    try {
        const { refreshToken } = req.cookies;
        if (refreshToken) {
            const hashedRefreshToken = crypto.createHash('sha256').update(refreshToken).digest('hex');
            await pool.query('UPDATE refresh_tokens SET revoked = true WHERE hashed_token = $1', [hashedRefreshToken]);
        }
    } catch (e) { /* ignore */ }

    res.clearCookie('token');
    res.clearCookie('refreshToken', { path: '/auth/refresh' });
    res.status(200).json({ message: 'Logged out completely' });
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
        await pool.query('UPDATE refresh_tokens SET revoked = true WHERE user_id = $1', [user.id]);

        // Auto-login user
        const accessToken = jwt.sign(
            { id: user.id, username: user.username, plan_id: user.plan_id },
            JWT_SECRET,
            { expiresIn: '15m' }
        );

        const newRefreshToken = crypto.randomBytes(40).toString('hex');
        const newHashedRT = crypto.createHash('sha256').update(newRefreshToken).digest('hex');

        await pool.query(
            `INSERT INTO refresh_tokens (user_id, hashed_token, expires_at) VALUES ($1, $2, NOW() + INTERVAL '7 days')`,
            [user.id, newHashedRT]
        );

        res.cookie('token', accessToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 15 * 60 * 1000 // 15 mins
        });

        res.cookie('refreshToken', newRefreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            path: '/auth/refresh',
            maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
        });

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

// User Audit & Login Logs
router.get('/audit-logs', supabaseAuth, async (req, res) => {
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

module.exports = router;
