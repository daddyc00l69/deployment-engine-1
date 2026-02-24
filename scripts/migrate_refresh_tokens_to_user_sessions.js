const { pool } = require('../services/db');
const logger = require('../utils/logger');

/**
 * One-time migration:
 * - Copies legacy `refresh_tokens` rows into `user_sessions` so existing refresh cookies
 *   continue working after we switch rotation source-of-truth to `user_sessions`.
 *
 * Safe to run multiple times due to unique index on `user_sessions.refresh_token_hash`.
 */
async function migrateRefreshTokensToUserSessions() {
    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        // Ensure destination table exists even if init_db wasn't run.
        await client.query(`CREATE EXTENSION IF NOT EXISTS pgcrypto`);
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
        await client.query(`
            CREATE UNIQUE INDEX IF NOT EXISTS user_sessions_refresh_token_hash_uniq
            ON user_sessions(refresh_token_hash)
        `);

        const { rows } = await client.query(`
            SELECT id, user_id, hashed_token, revoked, expires_at, created_at
            FROM refresh_tokens
        `);

        let inserted = 0;
        for (const rt of rows) {
            const res = await client.query(
                `
                INSERT INTO user_sessions (
                    user_id,
                    device_name,
                    refresh_token_hash,
                    created_at,
                    last_active,
                    expires_at,
                    is_revoked,
                    revoked_at
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, CASE WHEN $7 THEN NOW() ELSE NULL END)
                ON CONFLICT (refresh_token_hash) DO NOTHING
                `,
                [
                    rt.user_id,
                    'Legacy session',
                    rt.hashed_token,
                    rt.created_at || new Date(),
                    rt.created_at || new Date(),
                    rt.expires_at,
                    !!rt.revoked
                ]
            );
            inserted += res.rowCount || 0;
        }

        await client.query('COMMIT');
        logger.info(`Migrated refresh_tokens -> user_sessions. Inserted: ${inserted}, total_refresh_tokens: ${rows.length}`);
    } catch (err) {
        await client.query('ROLLBACK');
        logger.error(`Migration failed: ${err.message}`);
        throw err;
    } finally {
        client.release();
    }
}

if (require.main === module) {
    migrateRefreshTokensToUserSessions()
        .then(() => process.exit(0))
        .catch(() => process.exit(1));
}

module.exports = { migrateRefreshTokensToUserSessions };

