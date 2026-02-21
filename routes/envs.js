const express = require('express');
const router = express.Router();
const { pool } = require('../services/db');
const authMiddleware = require('../middleware/authMiddleware');
const logger = require('../utils/logger');
const { encrypt, decrypt } = require('../utils/encryption');
const { logAudit } = require('../services/auditLogger');

// All env routes require authentication
router.use(authMiddleware);

// Helper to verify project ownership
async function getOwnedProject(userId, projectId, res) {
    const result = await pool.query('SELECT * FROM projects WHERE id = $1', [projectId]);
    if (result.rows.length === 0) {
        res.status(404).json({ error: 'Project not found' });
        return null;
    }
    const project = result.rows[0];
    if (project.user_id !== userId) {
        res.status(403).json({ error: 'Access denied' });
        return null;
    }
    return project;
}

// GET /api/envs/:projectId - List environment variables for a project (decrypted for UI)
router.get('/:projectId', async (req, res) => {
    try {
        const project = await getOwnedProject(req.user.id, req.params.projectId, res);
        if (!project) return;

        const result = await pool.query('SELECT id, key_name, value_encrypted, created_at FROM project_envs WHERE project_id = $1 ORDER BY key_name ASC', [project.id]);

        // Decrypt values for the frontend
        const envs = result.rows.map(env => ({
            id: env.id,
            key: env.key_name,
            value: decrypt(env.value_encrypted), // Send back decrypted to frontend user who owns it
            createdAt: env.created_at
        }));

        res.json(envs);
    } catch (error) {
        logger.error(`Error fetching envs: ${error.message}`);
        res.status(500).json({ error: 'Internal server error fetching environment variables' });
    }
});

// POST /api/envs/:projectId - Add or update an environment variable
router.post('/:projectId', async (req, res) => {
    try {
        const { key, value } = req.body;

        if (!key || value === undefined) {
            return res.status(400).json({ error: 'Key and value are required' });
        }

        const project = await getOwnedProject(req.user.id, req.params.projectId, res);
        if (!project) return;

        // Encrypt the value before storing it in DB!
        const encryptedValue = encrypt(value);

        // Upsert logic
        const result = await pool.query(`
            INSERT INTO project_envs (project_id, key_name, value_encrypted)
            VALUES ($1, $2, $3)
            ON CONFLICT (project_id, key_name) 
            DO UPDATE SET value_encrypted = EXCLUDED.value_encrypted, created_at = CURRENT_TIMESTAMP
            RETURNING id, key_name, created_at
        `, [project.id, key, encryptedValue]);

        await logAudit(req.user.id, 'set_env', project.name, { key }, req.ip);

        res.json({
            message: 'Environment variable saved securely',
            env: {
                id: result.rows[0].id,
                key: result.rows[0].key_name,
                value: value, // Echo back plaintext
                createdAt: result.rows[0].created_at
            }
        });

    } catch (error) {
        logger.error(`Error saving env: ${error.message}`);
        res.status(500).json({ error: 'Internal server error saving environment variable' });
    }
});

// DELETE /api/envs/:projectId/:keyName - Remove an environment variable
router.delete('/:projectId/:keyName', async (req, res) => {
    try {
        const project = await getOwnedProject(req.user.id, req.params.projectId, res);
        if (!project) return;

        const result = await pool.query('DELETE FROM project_envs WHERE project_id = $1 AND key_name = $2 RETURNING id', [project.id, req.params.keyName]);

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Environment variable not found' });
        }

        await logAudit(req.user.id, 'delete_env', project.name, { key: req.params.keyName }, req.ip);

        res.json({ message: 'Environment variable deleted' });
    } catch (error) {
        logger.error(`Error deleting env: ${error.message}`);
        res.status(500).json({ error: 'Internal server error deleting environment variable' });
    }
});

module.exports = router;
