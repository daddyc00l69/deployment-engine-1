const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const { pool } = require('../services/db');
const logger = require('../utils/logger');
const jwt = require('jsonwebtoken');

const router = express.Router();

// Encryption helper for the access_token
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex'); // 32 chars for AES-256
const IV_LENGTH = 16;

function encrypt(text) {
    let iv = crypto.randomBytes(IV_LENGTH);
    let cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decrypt(text) {
    let textParts = text.split(':');
    let iv = Buffer.from(textParts.shift(), 'hex');
    let encryptedText = Buffer.from(textParts.join(':'), 'hex');
    let decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
}

/**
 * Middleware to verify JWT token
 */
const authenticateToken = (req, res, next) => {
    // Check headers or cookies
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1] || req.cookies?.token;

    if (!token) return res.status(401).json({ error: 'Access denied, token missing' });

    jwt.verify(token, process.env.JWT_SECRET || 'fallback_secret', (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });
        req.user = user;
        next();
    });
};

/**
 * GET /github/connect
 * Redirects the user to GitHub's OAuth authorization page.
 */
router.get('/connect', authenticateToken, (req, res) => {
    const clientId = process.env.GITHUB_CLIENT_ID;
    const redirectUri = encodeURIComponent(`${process.env.DOMAIN || 'https://api.devtushar.uk'}/api/github/callback`);

    // Pass user.id in state securely to link account on return
    const state = jwt.sign({ userId: req.user.id }, process.env.JWT_SECRET || 'fallback_secret', { expiresIn: '15m' });

    const githubAuthUrl = `https://github.com/login/oauth/authorize?client_id=${clientId}&redirect_uri=${redirectUri}&scope=repo,user:email&state=${state}`;

    res.json({ url: githubAuthUrl });
});

/**
 * GET /github/callback
 * Handles the OAuth redirect from GitHub, exchanges the code for a token, and links to the user account.
 */
router.get('/callback', async (req, res) => {
    const { code, state } = req.query;

    if (!code || !state) {
        return res.status(400).send('Missing code or state parameter');
    }

    try {
        // Decode state to get user ID
        const decoded = jwt.verify(state, process.env.JWT_SECRET || 'fallback_secret');
        const userId = decoded.userId;

        // Exchange code for access token
        const tokenResponse = await axios.post('https://github.com/login/oauth/access_token', {
            client_id: process.env.GITHUB_CLIENT_ID,
            client_secret: process.env.GITHUB_CLIENT_SECRET,
            code: code,
            redirect_uri: `${process.env.DOMAIN || 'https://api.devtushar.uk'}/api/github/callback`
        }, {
            headers: {
                Accept: 'application/json'
            }
        });

        const accessToken = tokenResponse.data.access_token;

        if (!accessToken) {
            throw new Error('Failed to retrieve access token from GitHub');
        }

        // Fetch User details from GitHub
        const githubUserResponse = await axios.get('https://api.github.com/user', {
            headers: {
                Authorization: `Bearer ${accessToken}`
            }
        });

        const githubUser = githubUserResponse.data;
        const encryptedToken = encrypt(accessToken);

        // Store or update in database
        const client = await pool.connect();
        try {
            await client.query(`
                INSERT INTO github_accounts (user_id, github_id, username, access_token)
                VALUES ($1, $2, $3, $4)
                ON CONFLICT (github_id) DO UPDATE SET
                    access_token = EXCLUDED.access_token,
                    username = EXCLUDED.username,
                    user_id = EXCLUDED.user_id,
                    updated_at = NOW()
            `, [userId, githubUser.id.toString(), githubUser.login, encryptedToken]);

            logger.info(`GitHub account ${githubUser.login} linked to user ${userId}`);
        } finally {
            client.release();
        }

        // Redirect back to frontend settings page on success
        res.redirect(`${process.env.FRONTEND_URL || 'https://devtushar.uk'}/settings/connections?github=success`);

    } catch (error) {
        logger.error(`GitHub OAuth Callback Error: ${error.message}`);
        res.redirect(`${process.env.FRONTEND_URL || 'https://devtushar.uk'}/settings/connections?github=error`);
    }
});

/**
 * GET /github/status
 * Checks if the current user has a linked GitHub account.
 */
router.get('/status', authenticateToken, async (req, res) => {
    try {
        const client = await pool.connect();
        try {
            const result = await client.query(
                'SELECT username, updated_at FROM github_accounts WHERE user_id = $1',
                [req.user.id]
            );

            if (result.rows.length > 0) {
                res.json({ connected: true, username: result.rows[0].username, linkedAt: result.rows[0].updated_at });
            } else {
                res.json({ connected: false });
            }
        } finally {
            client.release();
        }
    } catch (error) {
        logger.error(`GitHub Status check error: ${error.message}`);
        res.status(500).json({ error: 'Internal server error' });
    }
});

/**
 * DELETE /github/disconnect
 * Unlinks the GitHub account and securely deletes the token.
 */
router.delete('/disconnect', authenticateToken, async (req, res) => {
    try {
        const client = await pool.connect();
        try {
            await client.query('DELETE FROM github_accounts WHERE user_id = $1', [req.user.id]);
            logger.info(`GitHub account disconnected for user ${req.user.id}`);
            res.json({ success: true, message: 'GitHub account disconnected successfully' });
        } finally {
            client.release();
        }
    } catch (error) {
        logger.error(`GitHub Disconnect Error: ${error.message}`);
        res.status(500).json({ error: 'Internal server error' });
    }
});

/**
 * GET /github/repos
 * Fetches the user's connected GitHub repositories
 */
router.get('/repos', authenticateToken, async (req, res) => {
    try {
        const client = await pool.connect();
        let accessToken;

        try {
            const result = await client.query('SELECT access_token FROM github_accounts WHERE user_id = $1', [req.user.id]);
            if (result.rows.length === 0) return res.status(404).json({ error: 'No GitHub account connected' });

            accessToken = decrypt(result.rows[0].access_token);
        } finally {
            client.release();
        }

        // Fetch from authentic GitHub API
        const githubRes = await axios.get('https://api.github.com/user/repos?sort=updated&per_page=100', {
            headers: { Authorization: `Bearer ${accessToken}`, Accept: 'application/vnd.github.v3+json' }
        });

        // Map down bloated payload to minimal frontend requirements
        const repos = githubRes.data.map(r => ({
            id: r.id,
            name: r.name,
            full_name: r.full_name,
            private: r.private,
            language: r.language,
            clone_url: r.clone_url,
            default_branch: r.default_branch,
            updated_at: r.updated_at
        }));

        res.json(repos);

    } catch (error) {
        logger.error(`Failed to fetch GitHub Repos: ${error.message}`);
        res.status(500).json({ error: 'Failed to communicate with GitHub API' });
    }
});

module.exports = router;
module.exports.decrypt = decrypt; // Exporting decrypt specifically for the Deploy pipeline later
