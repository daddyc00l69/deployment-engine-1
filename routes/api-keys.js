const express = require('express');
const { pool } = require('../services/db');
const crypto = require('crypto');
const supabaseAuth = require('../middleware/supabaseAuth');
const auditLogger = require('../services/auditLogger');
const logger = require('../utils/logger');

const router = express.Router();

router.use(supabaseAuth);

// GET all API Keys for the user
router.get('/', async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT id, name, prefix, created_at, last_used_at, expires_at FROM api_keys WHERE user_id = $1 ORDER BY created_at DESC',
            [req.user.id]
        );

        res.json(result.rows);
    } catch (error) {
        logger.error(`Error fetching API keys: ${error.message}`);
        res.status(500).json({ error: 'Failed to retrieve API keys' });
    }
});

// POST to create a new API Key
router.POST('/', async (req, res) => {
    try {
        const { name } = req.body;
        if (!name) return res.status(400).json({ error: 'Key name is required' });

        // Generate cryptographically secure token
        const rawToken = crypto.randomBytes(32).toString('hex');
        const tokenPrefix = 'vp_live_';
        const fullPlaintextToken = `${tokenPrefix}${rawToken}`;

        // Hash token for storage
        const keyHash = crypto.createHash('sha256').update(fullPlaintextToken).digest('hex');

        // Define string display prefix (e.g. vp_live_a1b2...)
        const displayPrefix = fullPlaintextToken.substring(0, 14);

        const result = await pool.query(`
            INSERT INTO api_keys (user_id, name, key_hash, prefix)
            VALUES ($1, $2, $3, $4)
            RETURNING id, name, prefix, created_at
        `, [req.user.id, name, keyHash, displayPrefix]);

        await auditLogger.logEvent(req.user.id, 'API Key Generated', 'api_key_created', req.ip, req.headers['user-agent'], `Generated key: ${name}`);

        res.status(201).json({
            message: 'API Key generated successfully',
            key: result.rows[0],
            plaintext_token: fullPlaintextToken // ONLY returned once!
        });
    } catch (error) {
        logger.error(`Error generating API key: ${error.message}`);
        res.status(500).json({ error: 'Failed to generate API key' });
    }
});

// DELETE to revoke an API Key
router.delete('/:id', async (req, res) => {
    try {
        const keyId = req.params.id;

        const result = await pool.query(
            'DELETE FROM api_keys WHERE id = $1 AND user_id = $2 RETURNING name',
            [keyId, req.user.id]
        );

        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'API key not found' });
        }

        await auditLogger.logEvent(req.user.id, 'API Key Revoked', 'api_key_deleted', req.ip, req.headers['user-agent'], `Revoked key: ${result.rows[0].name}`);

        res.json({ message: 'API key revoked successfully' });
    } catch (error) {
        logger.error(`Error revoking API key: ${error.message}`);
        res.status(500).json({ error: 'Failed to revoke API key' });
    }
});

module.exports = router;
