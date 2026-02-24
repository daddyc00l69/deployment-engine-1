const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
});

async function checkUserProjects() {
    try {
        const username = 'tushar0p';
        console.log(`Checking projects for user: ${username}`);

        const res = await pool.query(`
            SELECT p.name, p.status, p.created_at
            FROM projects p
            JOIN users u ON p.user_id = u.id
            WHERE u.username = $1
        `, [username]);

        console.log(JSON.stringify(res.rows, null, 2));

    } catch (err) {
        console.error('Error:', err.message);
    } finally {
        await pool.end();
    }
}

checkUserProjects();
