const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
});

async function migrate() {
    try {
        console.log('Starting migration...');
        await pool.query(`
            ALTER TABLE projects ADD COLUMN IF NOT EXISTS build_command TEXT;
            ALTER TABLE projects ADD COLUMN IF NOT EXISTS start_command TEXT;
            ALTER TABLE deployments ADD COLUMN IF NOT EXISTS build_command TEXT;
            ALTER TABLE deployments ADD COLUMN IF NOT EXISTS start_command TEXT;
        `);
        console.log('Migration successful: Columns added to projects and deployments tables.');
    } catch (err) {
        console.error('Migration failed:', err.message);
        process.exit(1);
    } finally {
        await pool.end();
    }
}

migrate();
