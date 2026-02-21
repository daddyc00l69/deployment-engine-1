const { Pool } = require('pg');

const pool = new Pool({
    connectionString: "postgresql://vpsphere_user:Vp$ph3rE_2026_DB@localhost:5432/vpsphere"
});

async function migrate() {
    const client = await pool.connect();
    try {
        console.log('Starting projects port schema migration...');

        await client.query(`
            ALTER TABLE projects
            ADD COLUMN IF NOT EXISTS assigned_port INTEGER UNIQUE
        `);

        // And apply the GitHub Deployments tracking too since the earlier run failed 
        // due to the same Auth issue on the VM
        await client.query(`
            ALTER TABLE deployments
            ADD COLUMN IF NOT EXISTS user_id UUID REFERENCES users(id) ON DELETE CASCADE,
            ADD COLUMN IF NOT EXISTS repo_name VARCHAR(255),
            ADD COLUMN IF NOT EXISTS branch VARCHAR(255) DEFAULT 'main',
            ADD COLUMN IF NOT EXISTS commit_hash VARCHAR(40),
            ADD COLUMN IF NOT EXISTS logs TEXT
        `);

        console.log('Migration completed successfully.');
    } catch (error) {
        console.error('Migration failed:', error);
    } finally {
        client.release();
        process.exit(0);
    }
}

migrate();
