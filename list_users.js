const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
});

async function listUsers() {
    try {
        console.log('Listing all users:');
        const res = await pool.query('SELECT id, username, email, plan_id FROM users');
        console.log(JSON.stringify(res.rows, null, 2));

        console.log('\nListing all plans:');
        const planRes = await pool.query('SELECT * FROM plans');
        console.log(JSON.stringify(planRes.rows, null, 2));

    } catch (err) {
        console.error('Error:', err.message);
    } finally {
        await pool.end();
    }
}

listUsers();
