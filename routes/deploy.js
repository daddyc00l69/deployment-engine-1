const express = require('express');
const router = express.Router();
const logger = require('../utils/logger');
const { sanitizeProjectName } = require('../utils/sanitizer');
const authMiddleware = require('../middleware/authMiddleware');
const { pool } = require('../services/db');
const { logAuditAction } = require('../services/auditLogger');
const { deploymentQueue } = require('../services/queue');
const gitService = require('../services/gitService');
const frameworkDetector = require('../services/frameworkDetector');
const dockerfileGenerator = require('../services/dockerfileGenerator');
const deploymentEngine = require('../services/deploymentEngine');

const deployHandler = async (req, res) => {
    try {
        const { repoUrl, projectName, branch, buildCommand, startCommand, rootDirectory } = req.body;

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
            const projectCount = Number.parseInt(projectCountRes.rows[0].count);

            // Fetch Plan
            const planRes = await client.query('SELECT max_projects, memory_limit_mb, cpu_limit FROM plans WHERE id = $1', [user.plan_id]);
            const plan = planRes.rows[0];

            if (projectCount >= plan.max_projects) {
                return res.status(403).json({ error: `Plan limit reached. Max projects allowed: ${plan.max_projects}` });
            }

            // Create or update Project Record
            const subdomain = `${safeProjectName}-${user.username}.${process.env.BASE_DOMAIN || 'mydomain.net'}`;
            let projectId;

            const existingProjectReq = await client.query('SELECT id FROM projects WHERE user_id = $1 AND name = $2', [user.id, safeProjectName]);
            if (existingProjectReq.rows.length > 0) {
                projectId = existingProjectReq.rows[0].id;
                await client.query(
                    "UPDATE projects SET status = 'building', build_command = $2, start_command = $3, root_directory = $4, repo_url = $5, branch = $6, deployment_type = $7 WHERE id = $1",
                    [projectId, buildCommand, startCommand, rootDirectory || './', repoUrl, branch || 'main', req.body.deploymentType || 'web_service']
                );
            } else {
                const projectInsert = await client.query(
                    "INSERT INTO projects (user_id, name, subdomain, status, build_command, start_command, root_directory, repo_url, branch, deployment_type) VALUES ($1, $2, $3, 'building', $4, $5, $6, $7, $8, $9) RETURNING id",
                    [user.id, safeProjectName, subdomain, buildCommand, startCommand, rootDirectory || './', repoUrl, branch || 'main', req.body.deploymentType || 'web_service']
                );
                projectId = projectInsert.rows[0].id;
            }

            // Create Deployment Record
            const deployInsert = await client.query(
                "INSERT INTO deployments (project_id, user_id, status, logs, build_command, start_command, root_directory, branch) VALUES ($1, $2, 'pending', 'Deployment queued.', $3, $4, $5, $6) RETURNING id",
                [projectId, user.id, buildCommand, startCommand, rootDirectory || './', branch || 'main']
            );
            const deploymentId = deployInsert.rows[0].id;

            await logAuditAction(user.id, 'deploy', safeProjectName, { repoUrl }, req.ip);

            // Queue the job
            await deploymentQueue.add('deploy-app', {
                repoUrl,
                projectName: safeProjectName,
                branch: branch || 'main',
                user: { id: user.id, username: user.username },
                plan: { memory_limit_mb: plan.memory_limit_mb, cpu_limit: plan.cpu_limit },
                projectId,
                deploymentId,
                buildCommand,
                startCommand,
                rootDirectory: rootDirectory || './'
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
};

const getDeployments = async (req, res) => {
    try {
        const user = req.user;
        const result = await pool.query(
            'SELECT d.*, p.name as project_name FROM deployments d JOIN projects p ON d.project_id = p.id WHERE d.user_id = $1 ORDER BY d.created_at DESC LIMIT 50',
            [user.id]
        );
        res.json(result.rows);
    } catch (error) {
        logger.error(`Error fetching deployments: ${error.message}`);
        res.status(500).json({ error: 'Internal server error' });
    }
};

const getDeploymentById = async (req, res) => {
    try {
        const user = req.user;
        const { id } = req.params;
        const result = await pool.query(
            'SELECT d.*, p.name as project_name FROM deployments d JOIN projects p ON d.project_id = p.id WHERE d.id = $1 AND d.user_id = $2',
            [id, user.id]
        );
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Deployment not found' });
        }
        res.json(result.rows[0]);
    } catch (error) {
        logger.error(`Error fetching deployment by id: ${error.message}`);
        res.status(500).json({ error: 'Internal server error' });
    }
};

router.get('/', authMiddleware, getDeployments);
router.get('/:id', authMiddleware, getDeploymentById);
router.post('/', authMiddleware, deployHandler);
router.post('/import', authMiddleware, deployHandler);

module.exports = router;
