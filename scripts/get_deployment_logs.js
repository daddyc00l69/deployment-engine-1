const { Pool } = require('pg');
const pool = new Pool({ connectionString: 'postgresql://vpsphere_user:Vp$ph3rE_2026_DB@localhost:5432/vpsphere' });
pool.query('SELECT build_logs, logs, status FROM deployments WHERE id = 7')
    .then(res => { console.log(JSON.stringify(res.rows[0])); process.exit(0); });
