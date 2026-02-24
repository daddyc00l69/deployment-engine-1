const bcrypt = require('bcrypt');
const { pool } = require('../services/db');

const hash = bcrypt.hashSync('Testadmin123!', 12);
pool.query("UPDATE users SET email = 'testadmin@devtushar.uk', password_hash = $1, status = 'active' WHERE id = $2", [hash, '93c58807-e657-4403-94a1-d8036cbd1bf3'], (err, res) => {
    if (err) {
        console.error(err);
        process.exit(1);
    }
    console.log('User testadmin updated successfully');
    process.exit(0);
});
