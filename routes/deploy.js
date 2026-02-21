const express = require('express');
const router = express.Router();
const logger = require('../utils/logger');
const { sanitizeProjectName } = require('../utils/sanitizer');
const authMiddleware = require('../middleware/authMiddleware');
const { pool } = require('../services/db');
const { logAudit } = require('../services/auditLogger');
const { deploymentQueue } = require('../services/queue');
const gitService = require('../services/gitService');
const frameworkDetector = require('../services/frameworkDetector');
const dockerfileGenerator = require('../services/dockerfileGenerator');
const deploymentEngine = require('../services/deploymentEngine');

router.post('/', authMiddleware, async (req, res) => {
    try {
        const { repoUrl, projectName, branch, repoId } = req.body;

        if (!repoUrl || !projectName) {
            return res.status(400).json({ error: 'repoUrl and projectName are required' });
        }

        const safeProjectName = sanitizeProjectName(projectName);
        if (!safeProjectName) {
            return res.status(400).json({ error: 'Invalid projectName' });
        }

        const user = req.user;

        logger.info(`Received deployment request for ${safeProjectName} from ${user.username}`);

        const client = await pool.connect();

        try {
            // Count projects
            const projectCountRes = await client.query('SELECT COUNT(*) as count FROM projects WHERE user_id = $1', [user.id]);
            const projectCount = parseInt(projectCountRes.rows[0].count);

            // Fetch Plan
            const planRes = await client.query('SELECT max_projects, memory_limit_mb, cpu_limit FROM plans WHERE id = $1', [user.plan_id]);
            const plan = planRes.rows[0];

            if (projectCount >= plan.max_projects) {
                return res.status(403).json({ error: `Plan limit reached. Max projects allowed: ${plan.max_projects}` });
            }

            // Create or update Project Record
            const subdomain = `${safeProjectName}.${user.username}.${process.env.BASE_DOMAIN || 'mydomain.net'}`;
            let projectId;

            const existingProjectReq = await client.query('SELECT id FROM projects WHERE user_id = $1 AND name = $2', [user.id, safeProjectName]);
            if (existingProjectReq.rows.length > 0) {
                projectId = existingProjectReq.rows[0].id;
                await client.query("UPDATE projects SET status = 'building' WHERE id = $1", [projectId]);
            } else {
                const projectInsert = await client.query(
                    "INSERT INTO projects (user_id, name, subdomain, status) VALUES ($1, $2, $3, 'building') RETURNING id",
                    [user.id, safeProjectName, subdomain]
                );
                projectId = projectInsert.rows[0].id;
            }

            // Create Deployment Record
            const deployInsert = await client.query(
                "INSERT INTO deployments (project_id, user_id, repo_name, branch, status, logs) VALUES ($1, $2, $3, $4, 'pending', 'Deployment queued.') RETURNING id",
                [projectId, user.id, repoUrl, branch || 'main']
            );
            const deploymentId = deployInsert.rows[0].id;

            await logAudit(user.id, 'deploy', safeProjectName, { repoUrl }, req.ip);

            // Queue the job
            await deploymentQueue.add('deploy-app', {
                repoUrl,
                projectName: safeProjectName,
                branch: branch || 'main',
                user: { id: user.id, username: user.username },
                plan: { memory_limit_mb: plan.memory_limit_mb, cpu_limit: plan.cpu_limit },
                projectId,
                deploymentId
            });

            res.status(202).json({
                message: 'Deployment queued successfully',
                projectId,
                projectName: safeProjectName,
                url: `http://${subdomain}`
            });

        } finally {
            client.release();
        }

    } catch (error) {
        logger.error(`Error processing deployment request: ${error.message}`);
        res.status(500).json({ error: 'Internal server error' });
    }
});

module.exports = router;
