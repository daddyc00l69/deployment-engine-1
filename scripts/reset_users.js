require('dotenv').config({ path: __dirname + '/../.env' });
const { Pool } = require('pg');
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

pool.query('TRUNCATE TABLE users CASCADE;')
    .then(() => {
        console.log('Successfully cleared all users from the database!');
        process.exit(0);
    })
    .catch(err => {
        console.error('Error clearing users:', err);
        process.exit(1);
    });
