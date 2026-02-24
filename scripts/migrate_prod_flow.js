const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
});

async function migrate() {
    try {
        console.log('Starting migration for Production-Grade Docker Flow...');

        await pool.query(`
            -- Projects Table Updates
            ALTER TABLE projects ADD COLUMN IF NOT EXISTS repo_url TEXT;
            ALTER TABLE projects ADD COLUMN IF NOT EXISTS branch TEXT DEFAULT 'main';
            ALTER TABLE projects ADD COLUMN IF NOT EXISTS deployment_type VARCHAR(50) DEFAULT 'web_service';
            
            -- Deployments Table Updates
            ALTER TABLE deployments ADD COLUMN IF NOT EXISTS docker_image TEXT;
            ALTER TABLE deployments ADD COLUMN IF NOT EXISTS container_name TEXT;
            ALTER TABLE deployments ADD COLUMN IF NOT EXISTS port INTEGER;
            ALTER TABLE deployments ADD COLUMN IF NOT EXISTS build_logs TEXT DEFAULT '';
        `);

        console.log('Migration successful: Projects and Deployments tables updated.');
    } catch (err) {
        console.error('Migration failed:', err.message);
        process.exit(1);
    } finally {
        await pool.end();
    }
}

migrate();
