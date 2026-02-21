const crypto = require('crypto');

// Generate a random 32-byte key for AES-256 (should be done once and stored in .env)
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex');

// Requires a 32-byte (64 hex char) encryption key
// If ENCRYPTION_KEY is dynamically generated at runtime, variables won't be decryptable after restart!
// IMPORTANT: Add ENCRYPTION_KEY to your .env file in production.

const ALGORITHM = 'aes-256-gcm';

function encrypt(text) {
    if (!text) return text;
    // Derive a 32-byte buffer from the hex key or raw string
    const keyBuffer = Buffer.from(ENCRYPTION_KEY.length === 64 ? ENCRYPTION_KEY : crypto.createHash('sha256').update(String(ENCRYPTION_KEY)).digest('hex'), 'hex');

    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(ALGORITHM, keyBuffer, iv);

    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag().toString('hex');

    // Format: iv:authTag:encryptedData
    return `${iv.toString('hex')}:${authTag}:${encrypted}`;
}

function decrypt(encryptedText) {
    if (!encryptedText) return encryptedText;

    try {
        const textParts = encryptedText.split(':');
        if (textParts.length !== 3) return encryptedText; // Not encrypted with this cipher or plaintext

        const iv = Buffer.from(textParts[0], 'hex');
        const authTag = Buffer.from(textParts[1], 'hex');
        const encryptedData = Buffer.from(textParts[2], 'hex');

        const keyBuffer = Buffer.from(ENCRYPTION_KEY.length === 64 ? ENCRYPTION_KEY : crypto.createHash('sha256').update(String(ENCRYPTION_KEY)).digest('hex'), 'hex');

        const decipher = crypto.createDecipheriv(ALGORITHM, keyBuffer, iv);
        decipher.setAuthTag(authTag);

        let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
        decrypted += decipher.final('utf8');

        return decrypted;
    } catch (error) {
        console.error('Decryption failed. Invalid key or corrupted data.', error.message);
        return 'ERROR_DECRYPTING';
    }
}

module.exports = { encrypt, decrypt };
