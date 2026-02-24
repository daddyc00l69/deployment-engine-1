const nodemailer = require('nodemailer');
const logger = require('../utils/logger');

// Create the transporter with standard SMTP configuration
const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST || 'smtp.gmail.com',
    port: process.env.SMTP_PORT || 587,
    secure: process.env.SMTP_SECURE === 'true',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
});

/**
 * Helper to dispatch an email
 */
async function sendEmail(to, subject, html) {
    try {
        const info = await transporter.sendMail({
            from: `"VPSphere" <${process.env.SMTP_FROM || 'no-reply@vpsphere.local'}>`,
            to,
            subject,
            html,
        });
        logger.info(`Email sent to ${to}: ${info.messageId}`);
    } catch (error) {
        // Log locally, avoid crashing the app flow if mail fails
        logger.error(`Failed to send email to ${to}: ${error.message}`);
    }
}

async function sendWelcomeEmail(to, username) {
    await sendEmail(
        to,
        'Welcome to VPSphere PaaS! 🚀',
        `<h1>Welcome, ${username}!</h1><p>Your account has been successfully created. You can now deploy applications.</p>`
    );
}

async function sendDeploymentSuccess(to, projectName, url) {
    await sendEmail(
        to,
        `Deployment Successful: ${projectName} ✅`,
        `<h1>Deployment Completed!</h1><p>Your project <b>${projectName}</b> is up and running.</p><p><a href="${url}">View your app here</a></p>`
    );
}

async function sendPaymentSuccess(to, amount) {
    await sendEmail(
        to,
        'Payment successful 💸',
        `<h1>Thank you for your payment!</h1><p>We've successfully processed your payment of ₹${amount}. Your plan has been upgraded.</p>`
    );
}

async function sendPaymentFailed(to) {
    await sendEmail(
        to,
        'Action Required: Payment Failed ⚠️',
        `<h1>Your payment failed.</h1><p>We were unable to process your recent subscription payment. Your account has been temporarily downgraded to the Free tier until this is resolved.</p>`
    );
}

module.exports = {
    sendWelcomeEmail,
    sendDeploymentSuccess,
    sendPaymentSuccess,
    sendPaymentFailed
};
