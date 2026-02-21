const { pool } = require('../services/db');

async function migrateAuthFields() {
    try {
        console.log("Starting DB Auth Migration...");
        await pool.query(`
            ALTER TABLE users 
            ADD COLUMN IF NOT EXISTS email_verified BOOLEAN DEFAULT false,
            ADD COLUMN IF NOT EXISTS status VARCHAR(20) DEFAULT 'pending',
            ADD COLUMN IF NOT EXISTS verification_expires_at TIMESTAMP WITH TIME ZONE,
            ADD COLUMN IF NOT EXISTS otp_hash VARCHAR(255),
            ADD COLUMN IF NOT EXISTS failed_login_attempts INTEGER DEFAULT 0,
            ADD COLUMN IF NOT EXISTS locked_until TIMESTAMP WITH TIME ZONE,
            ADD COLUMN IF NOT EXISTS reset_token_hash VARCHAR(255),
            ADD COLUMN IF NOT EXISTS reset_expires_at TIMESTAMP WITH TIME ZONE;
        `);

        // Ensure existing users are grandfathered in as active & verified to not break them
        await pool.query(`
            UPDATE users SET email_verified = true, status = 'active' WHERE status = 'pending' AND otp_hash IS NULL;
        `);

        console.log("Migration complete!");
        process.exit(0);
    } catch (e) {
        console.error("Migration failed:", e);
        process.exit(1);
    }
}

migrateAuthFields();
