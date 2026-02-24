const { Pool } = require('pg');
const bcrypt = require('bcrypt');

const pool = new Pool({ connectionString: 'postgresql://vpsphere_user:Vp$ph3rE_2026_DB@localhost:5432/vpsphere' });

async function createTestUser() {
    try {
        const username = 'testadmin';
        const email = 'testadmin@vpsphere.local';
        const password = 'TestPassword123!';
        const salt = await bcrypt.genSalt(10);
        const hash = await bcrypt.hash(password, salt);

        // Check if exists
        const check = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
        if (check.rows.length > 0) {
            await pool.query("UPDATE users SET status = 'active', password_hash = $1 WHERE email = $2", [hash, email]);
            console.log('User updated and activated.');
        } else {
            // Default plan ID is 1 (Free)
            await pool.query(
                "INSERT INTO users (username, email, password_hash, status, plan_id, email_verified) VALUES ($1, $2, $3, 'active', 1, true)",
                [username, email, hash]
            );
            console.log('User created and activated.');
        }
    } catch (e) {
        console.error(e);
    } finally {
        await pool.end();
    }
}

createTestUser();
