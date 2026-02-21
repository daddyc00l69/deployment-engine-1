const { pool } = require('../services/db');

async function migrate() {
    const client = await pool.connect();
    try {
        console.log('Starting deployments table schema migration...');

        // Add repository-specific columns for tracking real GitHub deployments
        await client.query(`
            ALTER TABLE deployments
            ADD COLUMN IF NOT EXISTS user_id UUID REFERENCES users(id) ON DELETE CASCADE,
            ADD COLUMN IF NOT EXISTS repo_name VARCHAR(255),
            ADD COLUMN IF NOT EXISTS branch VARCHAR(255) DEFAULT 'main',
            ADD COLUMN IF NOT EXISTS commit_hash VARCHAR(40),
            ADD COLUMN IF NOT EXISTS logs TEXT
        `);

        // Convert the logs_path approach to in-database terminal logs storage
        // (Often better for WebSockets/SSE to read directly from a DB string or Redis,
        // though large logs may require external storage later. For simplicity we use TEXT)

        console.log('Migration completed successfully.');
    } catch (error) {
        console.error('Migration failed:', error);
    } finally {
        client.release();
        process.exit(0);
    }
}

migrate();
