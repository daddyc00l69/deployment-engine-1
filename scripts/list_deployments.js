const { Pool } = require('pg');
const pool = new Pool({ connectionString: 'postgresql://vpsphere_user:Vp$ph3rE_2026_DB@localhost:5432/vpsphere' });
pool.query('SELECT d.id, p.name as project_name, d.status, d.created_at FROM deployments d JOIN projects p ON d.project_id = p.id ORDER BY d.created_at DESC LIMIT 10')
    .then(res => { console.log(JSON.stringify(res.rows)); process.exit(0); });
