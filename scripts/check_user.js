const { pool } = require('../services/db');
pool.query('SELECT id, email, username FROM users', (err, res) => {
    if (err) {
        console.error(err);
        process.exit(1);
    }
    console.log(JSON.stringify(res.rows, null, 2));
    process.exit(0);
});
