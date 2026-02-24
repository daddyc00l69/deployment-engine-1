const { Pool } = require('pg');
const pool = new Pool({ connectionString: 'postgresql://vpsphere_user:Vp$ph3rE_2026_DB@localhost:5432/vpsphere' });

async function migrate() {
    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        console.log('Migrating schema to match Docker model specification...');

        // 1. Ensure projects table has correct fields
        await client.query(`
            ALTER TABLE projects 
            ADD COLUMN IF NOT EXISTS deployment_type TEXT DEFAULT 'web_service'
        `);

        // 2. Ensure deployments table has correct fields
        await client.query(`
            ALTER TABLE deployments 
            ADD COLUMN IF NOT EXISTS docker_image TEXT,
            ADD COLUMN IF NOT EXISTS container_name TEXT,
            ADD COLUMN IF NOT EXISTS port INTEGER,
            ADD COLUMN IF NOT EXISTS build_logs TEXT
        `);

        // 3. Create project_envs if not exists
        await client.query(`
            CREATE TABLE IF NOT EXISTS project_envs (
                id SERIAL PRIMARY KEY,
                project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
                key_name TEXT NOT NULL,
                value_encrypted TEXT NOT NULL,
                is_secret BOOLEAN DEFAULT true,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            )
        `);

        await client.query('COMMIT');
        console.log('Migration completed successfully.');
    } catch (e) {
        await client.query('ROLLBACK');
        console.error('Migration failed:', e);
    } finally {
        client.release();
        await pool.end();
    }
}

migrate();
