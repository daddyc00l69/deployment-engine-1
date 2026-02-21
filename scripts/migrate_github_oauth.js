const { pool } = require('../services/db');

async function migrate() {
    const client = await pool.connect();
    try {
        console.log('Starting GitHub OAuth schema migration...');

        await client.query(`
            CREATE TABLE IF NOT EXISTS github_accounts (
                id SERIAL PRIMARY KEY,
                user_id UUID REFERENCES users(id) ON DELETE CASCADE,
                github_id VARCHAR(255) UNIQUE NOT NULL,
                username VARCHAR(255) NOT NULL,
                access_token TEXT NOT NULL,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        `);
        console.log('Created github_accounts table');

        // Note: access_token will be stored encrypted in production
        // In this migration we just set up the schema.

        console.log('Migration completed successfully.');
    } catch (error) {
        console.error('Migration failed:', error);
    } finally {
        client.release();
        process.exit(0);
    }
}

migrate();
