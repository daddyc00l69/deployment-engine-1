const { Pool } = require('pg');
const pool = new Pool({ connectionString: 'postgresql://vpsphere_user:Vp$ph3rE_2026_DB@localhost:5432/vpsphere' });

async function checkSchema() {
    try {
        const projectsMeta = await pool.query("SELECT column_name, data_type FROM information_schema.columns WHERE table_name = 'projects'");
        const deploymentsMeta = await pool.query("SELECT column_name, data_type FROM information_schema.columns WHERE table_name = 'deployments'");

        console.log('--- PROJECTS TABLE ---');
        console.table(projectsMeta.rows);
        console.log('--- DEPLOYMENTS TABLE ---');
        console.table(deploymentsMeta.rows);
    } catch (e) {
        console.error(e);
    } finally {
        await pool.end();
    }
}

checkSchema();
