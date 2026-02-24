const { Pool } = require('pg');
const pool = new Pool({ connectionString: 'postgresql://vpsphere_user:Vp$ph3rE_2026_DB@localhost:5432/vpsphere' });

pool.query("SELECT id FROM projects WHERE name = 'final-spec-verif'")
    .then(res => {
        if (res.rows.length > 0) {
            console.log(res.rows[0].id);
        } else {
            console.log('Project not found');
        }
        process.exit(0);
    })
    .catch(err => {
        console.error(err);
        process.exit(1);
    });
