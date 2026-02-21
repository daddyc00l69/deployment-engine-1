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

const sendOTP = async (email, otp) => {
    try {
        const templatePath = path.join(__dirname, '../email/templates/vpsphere_email_verification_email.html');
        let htmlTemplate = fs.readFileSync(templatePath, 'utf8');
        htmlTemplate = htmlTemplate.replace(/\{\{otp\}\}/g, otp);

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

const sendPasswordResetEmail = async (email, resetLink) => {
    try {
        const templatePath = path.join(__dirname, '../email/templates/vpsphere_password_reset_email.html');
        let htmlTemplate = fs.readFileSync(templatePath, 'utf8');
        htmlTemplate = htmlTemplate.replace(/\{\{reset_link\}\}/g, resetLink);

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

const sendSuspiciousActivityEmail = async (email, ipAddress, userAgent) => {
    try {
        const templatePath = path.join(__dirname, '../email/templates/vpsphere_suspicious_activity_alert_email.html');
        let htmlTemplate;
        try {
            htmlTemplate = fs.readFileSync(templatePath, 'utf8');
            htmlTemplate = htmlTemplate.replace(/\{\{ip\}\}/g, ipAddress || 'Unknown IP');
            htmlTemplate = htmlTemplate.replace(/\{\{agent\}\}/g, userAgent || 'Unknown Device');
            htmlTemplate = htmlTemplate.replace(/\{\{time\}\}/g, new Date().toUTCString());
        } catch (e) {
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
        const templatePath = path.join(__dirname, '../email/templates/vpsphere_2fa_enabled_email.html');
        let htmlTemplate;
        try {
            htmlTemplate = fs.readFileSync(templatePath, 'utf8');
            htmlTemplate = htmlTemplate.replace(/\{\{time\}\}/g, new Date().toUTCString());
        } catch (e) {
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
        const templatePath = path.join(__dirname, '../email/templates/vpsphere_password_reset_success_email.html');
        let htmlTemplate;
        try {
            htmlTemplate = fs.readFileSync(templatePath, 'utf8');
            htmlTemplate = htmlTemplate.replace(/\{\{time\}\}/g, new Date().toUTCString());
        } catch (e) {
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

const sendNewLoginSecurityEmail = async (email, ipAddress, userAgent) => {
    try {
        const templatePath = path.join(__dirname, '../email/templates/vpsphere_new_login_security_email.html');
        let htmlTemplate;
        try {
            htmlTemplate = fs.readFileSync(templatePath, 'utf8');
            htmlTemplate = htmlTemplate.replace(/\{\{ip\}\}/g, ipAddress || 'Unknown IP');
            htmlTemplate = htmlTemplate.replace(/\{\{agent\}\}/g, userAgent || 'Unknown Device');
            htmlTemplate = htmlTemplate.replace(/\{\{time\}\}/g, new Date().toUTCString());
        } catch (e) {
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

module.exports = {
    sendOTP,
    sendPasswordResetEmail,
    sendSuspiciousActivityEmail,
    send2FAEnabledEmail,
    sendPasswordResetSuccessEmail,
    sendNewLoginSecurityEmail
};
