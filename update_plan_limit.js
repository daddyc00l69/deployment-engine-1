const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
});

async function updatePlanLimit() {
    try {
        console.log('Increasing max_projects for Free plan (ID: 1) to 10...');

        await pool.query(`
            UPDATE plans SET max_projects = 10 WHERE id = 1
        `);

        console.log('Update successful: Free plan now allows 10 projects.');

    } catch (err) {
        console.error('Error:', err.message);
        process.exit(1);
    } finally {
        await pool.end();
    }
}

updatePlanLimit();
