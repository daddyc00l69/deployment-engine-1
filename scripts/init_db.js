const { pool } = require('../services/db');
const logger = require('../utils/logger');

async function initializeDatabase() {
    logger.info('Initializing database schema...');

    const client = await pool.connect();

    try {
        await client.query('BEGIN');

        // Needed for gen_random_uuid()
        await client.query(`CREATE EXTENSION IF NOT EXISTS pgcrypto`);

        // Users Table
        await client.query(`
            CREATE TABLE IF NOT EXISTS users (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                username VARCHAR(50) UNIQUE NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                role VARCHAR(20) DEFAULT 'user',
                plan_id INTEGER NOT NULL,
                razorpay_customer_id VARCHAR(255),
                email_verified BOOLEAN DEFAULT false,
                status VARCHAR(20) DEFAULT 'pending',
                verification_expires_at TIMESTAMP WITH TIME ZONE,
                otp_hash VARCHAR(255),
                failed_login_attempts INTEGER DEFAULT 0,
                locked_until TIMESTAMP WITH TIME ZONE,
                reset_token_hash VARCHAR(255),
                reset_expires_at TIMESTAMP WITH TIME ZONE,
                two_factor_secret VARCHAR(255),
                two_factor_enabled BOOLEAN DEFAULT false,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Plans Table
        await client.query(`
            CREATE TABLE IF NOT EXISTS plans (
                id SERIAL PRIMARY KEY,
                name VARCHAR(50) NOT NULL,
                max_projects INTEGER NOT NULL,
                memory_limit_mb INTEGER NOT NULL,
                cpu_limit NUMERIC(3,2) NOT NULL,
                price NUMERIC(10,2) NOT NULL
            )
        `);

        // Insert default plans if none exist
        const result = await client.query('SELECT COUNT(*) FROM plans');
        if (parseInt(result.rows[0].count) === 0) {
            await client.query(`
                INSERT INTO plans (name, max_projects, memory_limit_mb, cpu_limit, price)
                VALUES 
                    ('Free', 1, 256, 0.25, 0.00),
                    ('Pro', 5, 512, 0.50, 10.00),
                    ('Max', 20, 1024, 1.00, 30.00)
            `);
            logger.info('Inserted default Plans.');
        }

        // Projects Table
        await client.query(`
            CREATE TABLE IF NOT EXISTS projects (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                user_id UUID REFERENCES users(id) ON DELETE CASCADE,
                name VARCHAR(50) NOT NULL,
                subdomain VARCHAR(255) UNIQUE NOT NULL,
                status VARCHAR(50) DEFAULT 'uninitialized',
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_id, name)
            )
        `);

        // Deployments Table
        await client.query(`
            CREATE TABLE IF NOT EXISTS deployments (
                id SERIAL PRIMARY KEY,
                project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
                status VARCHAR(50) NOT NULL,
                logs_path VARCHAR(500),
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Project Environment Variables (Encrypted At Rest)
        await client.query(`
            CREATE TABLE IF NOT EXISTS project_envs (
                id SERIAL PRIMARY KEY,
                project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
                key_name VARCHAR(255) NOT NULL,
                value_encrypted TEXT NOT NULL,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(project_id, key_name)
            )
        `);

        // Subscriptions Table
        await client.query(`
            CREATE TABLE IF NOT EXISTS subscriptions (
                id SERIAL PRIMARY KEY,
                user_id UUID REFERENCES users(id) ON DELETE CASCADE,
                razorpay_subscription_id VARCHAR(255) UNIQUE NOT NULL,
                plan_id INTEGER NOT NULL,
                status VARCHAR(50) NOT NULL,
                current_end TIMESTAMP WITH TIME ZONE,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Invoices Table
        await client.query(`
            CREATE TABLE IF NOT EXISTS invoices (
                id SERIAL PRIMARY KEY,
                user_id UUID REFERENCES users(id) ON DELETE CASCADE,
                razorpay_invoice_id VARCHAR(255) UNIQUE NOT NULL,
                amount NUMERIC(10,2) NOT NULL,
                status VARCHAR(50) NOT NULL,
                paid_at TIMESTAMP WITH TIME ZONE,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // AuditLog Table
        await client.query(`
            CREATE TABLE IF NOT EXISTS audit_logs (
                id SERIAL PRIMARY KEY,
                user_id UUID REFERENCES users(id) ON DELETE CASCADE,
                action VARCHAR(100) NOT NULL,
                target_resource VARCHAR(255),
                details JSONB,
                ip_address VARCHAR(45),
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Login Logs Table (Anomaly Detection & Auditing)
        await client.query(`
            CREATE TABLE IF NOT EXISTS login_logs (
                id SERIAL PRIMARY KEY,
                user_id UUID REFERENCES users(id) ON DELETE CASCADE,
                ip_address VARCHAR(45) NOT NULL,
                user_agent TEXT,
                status VARCHAR(20) NOT NULL,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Refresh Tokens Table (Token Rotation & Revocation)
        await client.query(`
            CREATE TABLE IF NOT EXISTS refresh_tokens (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                user_id UUID REFERENCES users(id) ON DELETE CASCADE,
                hashed_token VARCHAR(255) NOT NULL,
                revoked BOOLEAN DEFAULT false,
                expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Enterprise session tracking (device-based refresh token rotation + revocation)
        await client.query(`
            CREATE TABLE IF NOT EXISTS user_sessions (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                user_id UUID REFERENCES users(id) ON DELETE CASCADE,
                device_name TEXT,
                browser TEXT,
                os TEXT,
                user_agent TEXT,
                ip_address TEXT,
                country TEXT,
                device_fingerprint TEXT,
                refresh_token_hash TEXT NOT NULL,
                previous_refresh_token_hash TEXT,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                last_active TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
                is_revoked BOOLEAN DEFAULT FALSE,
                revoked_at TIMESTAMP WITH TIME ZONE
            )
        `);

        // Prevent duplicate sessions for the same refresh token secret
        await client.query(`
            CREATE UNIQUE INDEX IF NOT EXISTS user_sessions_refresh_token_hash_uniq
            ON user_sessions(refresh_token_hash)
        `);
        await client.query(`
            CREATE INDEX IF NOT EXISTS user_sessions_user_id_last_active_idx
            ON user_sessions(user_id, last_active DESC)
        `);
        await client.query(`
            CREATE INDEX IF NOT EXISTS user_sessions_user_id_revoked_idx
            ON user_sessions(user_id, is_revoked)
        `);

        // Phase 2: security logs for risk scoring & suspicious login events
        await client.query(`
            CREATE TABLE IF NOT EXISTS security_logs (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                user_id UUID,
                ip_address TEXT,
                country TEXT,
                risk_score INTEGER,
                reason TEXT,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
            )
        `);
        await client.query(`
            CREATE INDEX IF NOT EXISTS security_logs_user_id_created_at_idx
            ON security_logs(user_id, created_at DESC)
        `);

        // High-risk login challenges (OTP gating for suspicious logins)
        await client.query(`
            CREATE TABLE IF NOT EXISTS login_challenges (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                user_id UUID REFERENCES users(id) ON DELETE CASCADE,
                email VARCHAR(255) NOT NULL,
                otp_hash VARCHAR(255) NOT NULL,
                risk_score INTEGER NOT NULL,
                reason TEXT,
                ip_address TEXT,
                country TEXT,
                user_agent TEXT,
                device_fingerprint TEXT,
                expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
                verified_at TIMESTAMP WITH TIME ZONE,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
            )
        `);
        await client.query(`
            CREATE INDEX IF NOT EXISTS login_challenges_user_id_created_at_idx
            ON login_challenges(user_id, created_at DESC)
        `);

        // API Keys (Personal Access Tokens)
        await client.query(`
            CREATE TABLE IF NOT EXISTS api_keys (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                user_id UUID REFERENCES users(id) ON DELETE CASCADE,
                name VARCHAR(50) NOT NULL,
                key_hash VARCHAR(255) UNIQUE NOT NULL,
                prefix VARCHAR(10) NOT NULL,
                last_used_at TIMESTAMP WITH TIME ZONE,
                expires_at TIMESTAMP WITH TIME ZONE,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            )
        `);

        await client.query('COMMIT');
        logger.info('Database initialized successfully.');

    } catch (error) {
        await client.query('ROLLBACK');
        logger.error(`Database initialization failed: ${error.message}`);
        throw error;
    } finally {
        client.release();
    }
}

// Run if called directly
if (require.main === module) {
    initializeDatabase()
        .then(() => process.exit(0))
        .catch(() => process.exit(1));
}

module.exports = { initializeDatabase };
