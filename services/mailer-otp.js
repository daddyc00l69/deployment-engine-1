const nodemailer = require('nodemailer');
const logger = require('../utils/logger');

const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 587,
    secure: false, // true for 465, false for 587
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

const fs = require('fs');
const path = require('path');

function readTemplate(relativePath) {
    const templatePath = path.join(__dirname, '..', 'email', 'templates', relativePath);
    return fs.readFileSync(templatePath, 'utf8');
}

function safeReplaceAll(html, key, value) {
    const v = value === undefined || value === null ? '' : String(value);
    return html.replaceAll(new RegExp(`\\{\\{${key}\\}\\}`, 'g'), v);
}

const sendOTP = async (email, otp) => {
    try {
        let htmlTemplate = readTemplate('vpsphere_email_verification_email.html');
        const verifyLink = `https://${process.env.DOMAIN || 'devtushar.uk'}/verify-email?email=${encodeURIComponent(email)}`;
        htmlTemplate = safeReplaceAll(htmlTemplate, 'otp', otp);
        htmlTemplate = safeReplaceAll(htmlTemplate, 'verify_link', verifyLink);

        const info = await transporter.sendMail({
            from: `"VPSphere Security" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: 'VPSphere - Your Verification Code',
            text: `Your verification code is: ${otp}. It will expire in 5 minutes.`,
            html: htmlTemplate
        });
        logger.info(`OTP Email sent to ${email} (Message ID: ${info.messageId})`);
        return true;
    } catch (error) {
        logger.error(`Failed to send OTP email to ${email}: ${error.message}`);
        return false;
    }
};

const sendPasswordResetEmail = async (email, resetLink, ipAddress = "Unknown", requestTime = new Date().toUTCString()) => {
    try {
        let htmlTemplate = readTemplate('vpsphere_password_reset_email.html');
        htmlTemplate = safeReplaceAll(htmlTemplate, 'reset_link', resetLink);
        htmlTemplate = safeReplaceAll(htmlTemplate, 'ip_address', ipAddress);
        htmlTemplate = safeReplaceAll(htmlTemplate, 'request_time', requestTime);

        const info = await transporter.sendMail({
            from: `"VPSphere Support" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: 'VPSphere - Password Reset Request',
            text: `Please click the following link to reset your password: ${resetLink}. It will expire in 15 minutes.`,
            html: htmlTemplate
        });
        logger.info(`Password Reset Email sent to ${email} (Message ID: ${info.messageId})`);
        return true;
    } catch (error) {
        logger.error(`Failed to send Password Reset email to ${email}: ${error.message}`);
        return false;
    }
};

const sendSuspiciousActivityEmail = async (email, ipAddress, userAgent, country = null) => {
    try {
        let htmlTemplate;
        try {
            htmlTemplate = readTemplate('vpsphere_suspicious_activity_alert_email.html');
            htmlTemplate = safeReplaceAll(htmlTemplate, 'ip', ipAddress || 'Unknown IP');
            htmlTemplate = safeReplaceAll(htmlTemplate, 'agent', userAgent || 'Unknown Device');
            htmlTemplate = safeReplaceAll(htmlTemplate, 'country', country || 'Unknown');
            htmlTemplate = safeReplaceAll(htmlTemplate, 'time', new Date().toUTCString());
            htmlTemplate = safeReplaceAll(htmlTemplate, 'secure_link', `https://${process.env.DOMAIN || 'devtushar.uk'}/settings/security`);
        } catch (e) {
            logger.warn(`Failed to read suspicious template: ${e.message}`);
            htmlTemplate = `<p>We blocked a suspicious login attempt to your account from IP: <b>${ipAddress}</b> using device <b>${userAgent}</b>.</p>`;
        }

        const info = await transporter.sendMail({
            from: `"VPSphere Security" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: 'Security Alert: Suspicious Login Attempt Blocked',
            text: `We blocked a suspicious login attempt to your account from IP: ${ipAddress} using device ${userAgent}.`,
            html: htmlTemplate
        });
        logger.info(`Suspicious Activity Email sent to ${email} (Message ID: ${info.messageId})`);
        return true;
    } catch (error) {
        logger.error(`Failed to send Suspicious Activity Email to ${email}: ${error.message}`);
        return false;
    }
};

const send2FAEnabledEmail = async (email) => {
    try {
        let htmlTemplate;
        try {
            htmlTemplate = readTemplate('vpsphere_2fa_enabled_email.html');
            htmlTemplate = safeReplaceAll(htmlTemplate, 'time', new Date().toUTCString());
            htmlTemplate = safeReplaceAll(htmlTemplate, 'secure_link', `https://${process.env.DOMAIN || 'devtushar.uk'}/settings/security`);
        } catch (e) {
            logger.warn(`Failed to read 2FA template: ${e.message}`);
            htmlTemplate = `<p>Two-Factor Authentication (2FA) was successfully enabled on your VPSphere account.</p>`;
        }
        const info = await transporter.sendMail({
            from: `"VPSphere Security" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: 'Security Notice: 2FA Enabled',
            text: `Two-Factor Authentication (2FA) was successfully enabled on your VPSphere account.`,
            html: htmlTemplate
        });
        logger.info(`2FA Enabled Email sent to ${email} (Message ID: ${info.messageId})`);
        return true;
    } catch (error) {
        logger.error(`Failed to send 2FA Enabled Email to ${email}: ${error.message}`);
        return false;
    }
};

const sendPasswordResetSuccessEmail = async (email) => {
    try {
        let htmlTemplate;
        try {
            htmlTemplate = readTemplate('vpsphere_password_reset_success_email.html');
            htmlTemplate = safeReplaceAll(htmlTemplate, 'time', new Date().toUTCString());
            htmlTemplate = safeReplaceAll(htmlTemplate, 'secure_link', `https://${process.env.DOMAIN || 'devtushar.uk'}/settings/security`);
        } catch (e) {
            logger.warn(`Failed to read password reset success template: ${e.message}`);
            htmlTemplate = `<p>Your password was successfully reset. If you did not make this change, please contact support immediately.</p>`;
        }
        const info = await transporter.sendMail({
            from: `"VPSphere Security" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: 'Security Notice: Password Reset Successful',
            text: `Your password was successfully reset.`,
            html: htmlTemplate
        });
        logger.info(`Password Reset Success Email sent to ${email} (Message ID: ${info.messageId})`);
        return true;
    } catch (error) {
        logger.error(`Failed to send Password Reset Success Email to ${email}: ${error.message}`);
        return false;
    }
};

const sendNewLoginSecurityEmail = async (email, ipAddress, userAgent, country = null) => {
    try {
        let htmlTemplate;
        try {
            htmlTemplate = readTemplate('vpsphere_new_login_security_email.html');
            htmlTemplate = safeReplaceAll(htmlTemplate, 'ip', ipAddress || 'Unknown IP');
            htmlTemplate = safeReplaceAll(htmlTemplate, 'agent', userAgent || 'Unknown Device');
            htmlTemplate = safeReplaceAll(htmlTemplate, 'country', country || 'Unknown');
            htmlTemplate = safeReplaceAll(htmlTemplate, 'time', new Date().toUTCString());
            htmlTemplate = safeReplaceAll(htmlTemplate, 'secure_link', `https://${process.env.DOMAIN || 'devtushar.uk'}/settings/security`);
        } catch (e) {
            logger.warn(`Failed to read new login template: ${e.message}`);
            htmlTemplate = `<p>We detected a new login to your account from IP: <b>${ipAddress}</b> using device <b>${userAgent}</b>. If this was you, you can ignore this email.</p>`;
        }
        const info = await transporter.sendMail({
            from: `"VPSphere Security" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: 'Security Alert: New Login Detected',
            text: `New login detected from IP: ${ipAddress} using device ${userAgent}.`,
            html: htmlTemplate
        });
        logger.info(`New Login Security Email sent to ${email} (Message ID: ${info.messageId})`);
        return true;
    } catch (error) {
        logger.error(`Failed to send New Login Email to ${email}: ${error.message}`);
        return false;
    }
};

const sendNewDeviceLoginDetectedEmail = async (email, ipAddress, userAgent, country = null) => {
    try {
        let htmlTemplate = readTemplate('vpsphere_new_login_security_email.html');
        htmlTemplate = safeReplaceAll(htmlTemplate, 'ip', ipAddress || 'Unknown IP');
        htmlTemplate = safeReplaceAll(htmlTemplate, 'agent', userAgent || 'Unknown Device');
        htmlTemplate = safeReplaceAll(htmlTemplate, 'country', country || 'Unknown');
        htmlTemplate = safeReplaceAll(htmlTemplate, 'time', new Date().toUTCString());
        htmlTemplate = safeReplaceAll(htmlTemplate, 'secure_link', `https://${process.env.DOMAIN || 'devtushar.uk'}/settings/security`);

        const info = await transporter.sendMail({
            from: `"VPSphere Security" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: 'New Device Login Detected',
            text: `New device login detected from IP: ${ipAddress} (${country || 'Unknown'}). Device: ${userAgent}`,
            html: htmlTemplate
        });
        logger.info(`New Device Email sent to ${email} (Message ID: ${info.messageId})`);
        return true;
    } catch (error) {
        logger.error(`Failed to send New Device Email to ${email}: ${error.message}`);
        return false;
    }
};

const sendSuspiciousLoginAttemptEmail = async (email, ipAddress, userAgent, country = null) => {
    try {
        let htmlTemplate = readTemplate('vpsphere_suspicious_activity_alert_email.html');
        htmlTemplate = safeReplaceAll(htmlTemplate, 'ip', ipAddress || 'Unknown IP');
        htmlTemplate = safeReplaceAll(htmlTemplate, 'agent', userAgent || 'Unknown Device');
        htmlTemplate = safeReplaceAll(htmlTemplate, 'country', country || 'Unknown');
        htmlTemplate = safeReplaceAll(htmlTemplate, 'time', new Date().toUTCString());
        htmlTemplate = safeReplaceAll(htmlTemplate, 'secure_link', `https://${process.env.DOMAIN || 'devtushar.uk'}/settings/security`);

        const info = await transporter.sendMail({
            from: `"VPSphere Security" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: 'Suspicious Login Attempt Detected',
            text: `Suspicious login attempt detected from IP: ${ipAddress} (${country || 'Unknown'}). Device: ${userAgent}`,
            html: htmlTemplate
        });
        logger.info(`Suspicious Login Email sent to ${email} (Message ID: ${info.messageId})`);
        return true;
    } catch (error) {
        logger.error(`Failed to send Suspicious Login Email to ${email}: ${error.message}`);
        return false;
    }
};

const sendAccountLockedEmail = async (email, ipAddress, userAgent, country = null) => {
    try {
        let htmlTemplate = readTemplate('vpsphere_suspicious_activity_alert_email.html');
        htmlTemplate = safeReplaceAll(htmlTemplate, 'ip', ipAddress || 'Unknown IP');
        htmlTemplate = safeReplaceAll(htmlTemplate, 'agent', userAgent || 'Unknown Device');
        htmlTemplate = safeReplaceAll(htmlTemplate, 'country', country || 'Unknown');
        htmlTemplate = safeReplaceAll(htmlTemplate, 'time', new Date().toUTCString());
        htmlTemplate = safeReplaceAll(htmlTemplate, 'secure_link', `https://${process.env.DOMAIN || 'devtushar.uk'}/settings/security`);

        const info = await transporter.sendMail({
            from: `"VPSphere Security" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: 'Account Locked (Too Many Attempts)',
            text: `Your account was locked due to repeated failed attempts from IP: ${ipAddress}.`,
            html: htmlTemplate
        });
        logger.info(`Account Locked Email sent to ${email} (Message ID: ${info.messageId})`);
        return true;
    } catch (error) {
        logger.error(`Failed to send Account Locked Email to ${email}: ${error.message}`);
        return false;
    }
};

const sendLoginBlockedOtpEmail = async (email, otp, ipAddress, userAgent, country = null) => {
    try {
        let htmlTemplate = readTemplate('vpsphere_login_blocked_verification_required_email.html');
        htmlTemplate = safeReplaceAll(htmlTemplate, 'otp', otp);
        htmlTemplate = safeReplaceAll(htmlTemplate, 'ip', ipAddress || 'Unknown IP');
        htmlTemplate = safeReplaceAll(htmlTemplate, 'agent', userAgent || 'Unknown Device');
        htmlTemplate = safeReplaceAll(htmlTemplate, 'country', country || 'Unknown');
        htmlTemplate = safeReplaceAll(htmlTemplate, 'time', new Date().toUTCString());
        htmlTemplate = safeReplaceAll(htmlTemplate, 'secure_link', `https://${process.env.DOMAIN || 'devtushar.uk'}/settings/security`);

        const info = await transporter.sendMail({
            from: `"VPSphere Security" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: 'Login Blocked — Verification Required',
            text: `Login blocked. Verification code: ${otp}. If this wasn't you, secure your account immediately.`,
            html: htmlTemplate
        });
        logger.info(`Login Blocked OTP Email sent to ${email} (Message ID: ${info.messageId})`);
        return true;
    } catch (error) {
        logger.error(`Failed to send Login Blocked OTP email to ${email}: ${error.message}`);
        return false;
    }
};

const sendDeviceRemovedEmail = async (email, deviceName = 'Unknown device') => {
    try {
        let htmlTemplate = readTemplate('vpsphere_device_removed_email.html');
        htmlTemplate = safeReplaceAll(htmlTemplate, 'device_name', deviceName);
        htmlTemplate = safeReplaceAll(htmlTemplate, 'time', new Date().toUTCString());
        htmlTemplate = safeReplaceAll(htmlTemplate, 'secure_link', `https://${process.env.DOMAIN || 'devtushar.uk'}/settings/security`);

        const info = await transporter.sendMail({
            from: `"VPSphere Security" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: 'Device Removed',
            text: `A device session was removed: ${deviceName}`,
            html: htmlTemplate
        });
        logger.info(`Device Removed Email sent to ${email} (Message ID: ${info.messageId})`);
        return true;
    } catch (error) {
        logger.error(`Failed to send Device Removed email to ${email}: ${error.message}`);
        return false;
    }
};

module.exports = {
    sendOTP,
    sendPasswordResetEmail,
    sendSuspiciousActivityEmail,
    send2FAEnabledEmail,
    sendPasswordResetSuccessEmail,
    sendNewLoginSecurityEmail,
    sendNewDeviceLoginDetectedEmail,
    sendSuspiciousLoginAttemptEmail,
    sendAccountLockedEmail,
    sendLoginBlockedOtpEmail,
    sendDeviceRemovedEmail
};
