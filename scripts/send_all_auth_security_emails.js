/**
 * Sends a batch of auth/security emails to a single address so you can visually
 * verify templates render correctly in real clients.
 *
 * Usage:
 *   node scripts/send_all_auth_security_emails.js Tushar0p.verify+testemaill@gmail.com
 */
require('dotenv').config();

const logger = require('../utils/logger');
const mailer = require('../services/mailer-otp');

async function main() {
    const to = process.argv[2];
    if (!to) {
        console.error('Usage: node scripts/send_all_auth_security_emails.js <email>');
        process.exit(1);
    }

    const now = new Date().toUTCString();
    const ip = '203.0.113.10';
    const agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) VPSphere-QA';
    const country = 'IN';
    const otp = '123456';
    const resetLink = `https://${process.env.DOMAIN || 'devtushar.uk'}/reset-password?token=dummy&email=${encodeURIComponent(to)}`;

    const steps = [
        { name: 'sendOTP (verification)', fn: () => mailer.sendOTP?.(to, otp) },
        { name: 'sendPasswordResetEmail', fn: () => mailer.sendPasswordResetEmail?.(to, resetLink, ip, now) },
        { name: 'sendPasswordResetSuccessEmail', fn: () => mailer.sendPasswordResetSuccessEmail?.(to) },
        { name: 'send2FAEnabledEmail', fn: () => mailer.send2FAEnabledEmail?.(to) },
        { name: 'sendNewLoginSecurityEmail', fn: () => mailer.sendNewLoginSecurityEmail?.(to, ip, agent) },
        { name: 'sendNewDeviceLoginDetectedEmail', fn: () => mailer.sendNewDeviceLoginDetectedEmail?.(to, ip, agent, country) },
        { name: 'sendSuspiciousLoginAttemptEmail', fn: () => mailer.sendSuspiciousLoginAttemptEmail?.(to, ip, agent, country) },
        { name: 'sendAccountLockedEmail', fn: () => mailer.sendAccountLockedEmail?.(to, ip, agent) },
        { name: 'sendLoginBlockedOtpEmail', fn: () => mailer.sendLoginBlockedOtpEmail?.(to, otp, ip, agent, country) },
        { name: 'sendDeviceRemovedEmail', fn: () => mailer.sendDeviceRemovedEmail?.(to, 'QA Device (Chrome on Windows)') },
    ];

    logger.info(`Sending ${steps.length} template emails to ${to}...`);

    for (const step of steps) {
        if (typeof step.fn !== 'function') {
            logger.warn(`SKIP ${step.name}: missing function`);
            continue;
        }
        try {
            const ok = await step.fn();
            logger.info(`${step.name}: ${ok ? 'OK' : 'FAILED'}`);
        } catch (e) {
            logger.error(`${step.name}: ERROR ${e.message}`);
        }
    }

    logger.info('Done.');
}

if (require.main === module) {
    main().then(() => process.exit(0)).catch(() => process.exit(1));
}

