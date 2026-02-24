const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
});

async function getSchema() {
    try {
        const tables = ['projects', 'deployments', 'project_envs', 'users', 'plans'];
        for (const table of tables) {
            console.log(`\n--- Schema for table: ${table} ---`);
            const res = await pool.query(`
                SELECT column_name, data_type, column_default
                FROM information_schema.columns
                WHERE table_name = $1
                ORDER BY ordinal_position;
            `, [table]);
            console.table(res.rows);
        }
    } catch (err) {
        console.error('Error fetching schema:', err.message);
    } finally {
        await pool.end();
    }
}

getSchema();
