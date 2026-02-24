const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
});

async function checkLimits() {
    try {
        const username = 'tusha';
        console.log(`Checking limits for user: ${username}`);

        const userRes = await pool.query(`
            SELECT u.id, u.username, u.plan_id, p.name as plan_name, p.max_projects 
            FROM users u 
            JOIN plans p ON u.plan_id = p.id 
            WHERE u.username = $1
        `, [username]);

        if (userRes.rows.length === 0) {
            console.log('User not found');
            return;
        }

        const user = userRes.rows[0];
        console.log('User Details:', JSON.stringify(user, null, 2));

        const projectCountRes = await pool.query('SELECT COUNT(*) FROM projects WHERE user_id = $1', [user.id]);
        console.log('Current Project Count:', projectCountRes.rows[0].count);

    } catch (err) {
        console.error('Error:', err.message);
    } finally {
        await pool.end();
    }
}

checkLimits();
