const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
});

async function setupTrigger() {
    try {
        console.log('Setting up Postgres NOTIFY trigger for deployment updates...');
        await pool.query(`
            CREATE OR REPLACE FUNCTION notify_deployment_update() RETURNS trigger AS $$
            DECLARE
                payload TEXT;
            BEGIN
                payload := json_build_object(
                    'projectId', NEW.project_id,
                    'status', NEW.status,
                    'logs', NEW.logs
                )::text;
                PERFORM pg_notify('deployment_updates', payload);
                RETURN NEW;
            END;
            $$ LANGUAGE plpgsql;

            DO $$
            BEGIN
                IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'deployment_update_trigger') THEN
                    CREATE TRIGGER deployment_update_trigger
                    AFTER INSERT OR UPDATE ON deployments
                    FOR EACH ROW EXECUTE FUNCTION notify_deployment_update();
                END IF;
            END $$;
        `);
        console.log('Trigger setup successful.');
    } catch (err) {
        console.error('Trigger setup failed:', err.message);
        process.exit(1);
    } finally {
        await pool.end();
    }
}

setupTrigger();
