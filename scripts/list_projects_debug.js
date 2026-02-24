const { pool } = require('../services/db');
pool.query('SELECT name, repo_url, branch, status, created_at FROM projects ORDER BY created_at DESC LIMIT 5', (err, res) => {
    if (err) {
        console.error(err);
        process.exit(1);
    }
    console.log(JSON.stringify(res.rows, null, 2));
    process.exit(0);
});
