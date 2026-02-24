const express = require('express');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const { sendOTP } = require('../../services/mailer-otp');
const logger = require('../../utils/logger');
const fs = require('fs');
const path = require('path');

const router = express.Router();

const OTP_EXPIRY_SECONDS = 300; // 5 minutes
const COOKIE_DOMAIN = process.env.COOKIE_DOMAIN
    || (process.env.DOMAIN
        ? `.${String(process.env.DOMAIN).replace(/^https?:\/\//, '').replace(/^api\./, '')}`
        : undefined);

// structured logging for OTP
const appendOTPLog = (status, email, details) => {
    const timestamp = new Date().toISOString();
    const logPath = path.join(__dirname, '../../project-logs/otp-system-log.txt');
    const logStr = `[${timestamp}]\nTASK: OTP Verification\nSTATUS: ${status}\nEMAIL: ${email}\nDETAILS: ${details}\n\n`;
    try {
        if (!fs.existsSync(path.dirname(logPath))) {
            fs.mkdirSync(path.dirname(logPath), { recursive: true });
        }
        fs.appendFileSync(logPath, logStr);
    } catch (e) {
        logger.error(`Failed to write OTP log: ${e.message}`);
    }
};

router.post('/send', async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) {
            return res.status(400).json({ error: 'Email is required' });
        }

        // Generate a 6 digit code
        const otp = crypto.randomInt(100000, 999999).toString();

        // Hash it for secure storage
        const salt = await bcrypt.genSalt(10);
        const hashedOtp = await bcrypt.hash(otp, salt);

        // Store directly in PostgreSQL users table
        const { pool } = require('../../services/db');
        const updateRes = await pool.query(
            `UPDATE users 
             SET otp_hash = $1, verification_expires_at = NOW() + INTERVAL '15 minutes' 
             WHERE email = $2 AND status = 'pending'`,
            [hashedOtp, email]
        );

        if (updateRes.rowCount === 0) {
            return res.status(400).json({ error: 'Account either does not exist or is already active.' });
        }

        // Send Email
        const sent = await sendOTP(email, otp);

        if (!sent) {
            appendOTPLog('Failed', email, 'SMTP Failed to send OTP');
            return res.status(500).json({ error: 'Failed to send OTP email' });
        }

        appendOTPLog('Sent', email, 'Successfully sent 6-digit OTP code');
        res.status(200).json({ message: 'OTP sent successfully to email' });
    } catch (err) {
        logger.error(`OTP Generation Error: ${err.message}`);
        appendOTPLog('Error', req.body.email || 'Unknown', err.message);
        res.status(500).json({ error: 'Internal server error while sending OTP' });
    }
});

router.post('/verify', async (req, res) => {
    try {
        const { email, otp } = req.body;
        if (!email || !otp) {
            return res.status(400).json({ error: 'Email and OTP are required' });
        }

        const { pool } = require('../../services/db');

        const userCheck = await pool.query(
            `SELECT id, username, plan_id, otp_hash, verification_expires_at 
             FROM users 
             WHERE email = $1 AND status = 'pending'`,
            [email]
        );

        if (userCheck.rows.length === 0) {
            appendOTPLog('Failed', email, 'User not found or is already active');
            return res.status(400).json({ error: 'Invalid or expired OTP session' });
        }

        const user = userCheck.rows[0];
        const dbHashedOtp = user.otp_hash;

        if (!dbHashedOtp || new Date() > new Date(user.verification_expires_at)) {
            appendOTPLog('Expired', email, 'User attempted to verify an expired or missing OTP');
            return res.status(400).json({ error: 'OTP expired or invalid' });
        }

        const isValid = await bcrypt.compare(otp.toString(), dbHashedOtp);

        if (!isValid) {
            appendOTPLog('Failed', email, 'User entered incorrect OTP');
            return res.status(401).json({ error: 'Invalid OTP' });
        }

        // OTP is correct! Activate the user
        await pool.query(
            `UPDATE users 
             SET status = 'active', email_verified = true, otp_hash = NULL, verification_expires_at = NULL 
             WHERE id = $1`,
            [user.id]
        );

        const jwt = require('jsonwebtoken');
        let token = jwt.sign(
            { id: user.id, username: user.username, plan_id: user.plan_id },
            process.env.JWT_SECRET || 'fallback_secret',
            { expiresIn: '24h' }
        );

        // Share cookie across app + api subdomains for seamless middleware gating.
        res.cookie('vpsphere_token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
            domain: COOKIE_DOMAIN,
            maxAge: 24 * 60 * 60 * 1000
        });
        // Backwards-compat
        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
            domain: COOKIE_DOMAIN,
            maxAge: 24 * 60 * 60 * 1000
        });

        try {
            const logPath = path.join(__dirname, '../../project-logs/user-flow-log.txt');
            fs.appendFileSync(logPath, `[${new Date().toISOString()}]\\nFLOW: Onboarding\\nSTATUS: Auto-login Success\\nUSER: ${email}\\n\\n`);
        } catch (e) { }

        let userData = user;

        appendOTPLog('Success', email, 'OTP verified successfully');
        res.status(200).json({ message: 'OTP verified successfully', verified: true, email, token, user: userData });

    } catch (err) {
        logger.error(`OTP Verification Error: ${err.message}`);
        appendOTPLog('Error', req.body.email || 'Unknown', err.message);
        res.status(500).json({ error: 'Internal server error during OTP verification' });
    }
});

module.exports = router;
