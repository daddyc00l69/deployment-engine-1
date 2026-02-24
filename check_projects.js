const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
});

async function checkProjectCounts() {
    try {
        console.log('Project counts by user:');
        const res = await pool.query(`
            SELECT u.username, COUNT(p.id) as project_count, pl.max_projects
            FROM users u
            LEFT JOIN projects p ON u.id = p.user_id
            JOIN plans pl ON u.plan_id = pl.id
            GROUP BY u.username, pl.max_projects
        `);
        console.log(JSON.stringify(res.rows, null, 2));

    } catch (err) {
        console.error('Error:', err.message);
    } finally {
        await pool.end();
    }
}

checkProjectCounts();
