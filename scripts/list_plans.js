const { Pool } = require('pg');
const pool = new Pool({ connectionString: 'postgresql://vpsphere_user:Vp$ph3rE_2026_DB@localhost:5432/vpsphere' });
pool.query('SELECT id, name FROM plans')
    .then(res => { console.log(JSON.stringify(res.rows)); process.exit(0); });
