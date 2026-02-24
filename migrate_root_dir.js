const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
});

async function migrate() {
    try {
        console.log('Starting migration to add root_directory column...');
        await pool.query(`
            ALTER TABLE projects ADD COLUMN IF NOT EXISTS root_directory TEXT DEFAULT './';
            ALTER TABLE deployments ADD COLUMN IF NOT EXISTS root_directory TEXT DEFAULT './';
        `);
        console.log('Migration successful: root_directory column added to projects and deployments tables.');
    } catch (err) {
        console.error('Migration failed:', err.message);
        process.exit(1);
    } finally {
        await pool.end();
    }
}

migrate();
