const express = require('express');
const router = express.Router();
const { pool } = require('../services/db');
const authMiddleware = require('../middleware/authMiddleware');
const { spawn } = require('node:child_process');
const logger = require('../utils/logger');
const fs = require('node:fs');
const path = require('node:path');
const { logAudit } = require('../services/auditLogger');

// Execute docker securely
function execDocker(args) {
    return new Promise((resolve, reject) => {
        logger.info(`Executing: docker ${args.join(' ')}`);
        const child = spawn('docker', args, { shell: false });

        child.on('close', (code) => {
            if (code === 0) resolve();
            else reject(new Error(`Docker exited with code ${code}`));
        });
        child.on('error', (err) => reject(err));
    });
}

// All project routes require auth
router.use(authMiddleware);

/**
 * Frontend compatibility routes
 * The frontend api-client calls:
 * - GET  /project/list
 * - POST /project/start  { projectId }
 * - POST /project/stop   { projectId }
 * - POST /project/delete { projectId }
 *
 * Keep the existing REST-style routes too (/:id/start, etc.).
 */
router.get('/list', async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT id, name, subdomain, status, created_at
             FROM projects
             WHERE user_id = $1
             ORDER BY created_at DESC`,
            [req.user.id]
        );
        res.json({ projects: result.rows });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

router.post('/start', async (req, res) => {
    try {
        const { projectId } = req.body || {};
        if (!projectId) return res.status(400).json({ error: 'projectId is required' });

        const project = await getOwnedProject(req.user.id, projectId, res);
        if (!project) return;

        const containerName = getContainerName(req.user.id, project.name);
        await execDocker(['start', containerName]);
        await pool.query("UPDATE projects SET status = 'running' WHERE id = $1", [project.id]);
        await logAudit(req.user.id, 'start', project.name, { containerName }, req.ip);

        res.json({ message: 'Project started' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

router.post('/stop', async (req, res) => {
    try {
        const { projectId } = req.body || {};
        if (!projectId) return res.status(400).json({ error: 'projectId is required' });

        const project = await getOwnedProject(req.user.id, projectId, res);
        if (!project) return;

        const containerName = getContainerName(req.user.id, project.name);
        await execDocker(['stop', containerName]);
        await pool.query("UPDATE projects SET status = 'stopped' WHERE id = $1", [project.id]);
        await logAudit(req.user.id, 'stop', project.name, { containerName }, req.ip);

        res.json({ message: 'Project stopped' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

router.post('/delete', async (req, res) => {
    try {
        const { projectId } = req.body || {};
        if (!projectId) return res.status(400).json({ error: 'projectId is required' });

        const project = await getOwnedProject(req.user.id, projectId, res);
        if (!project) return;

        const containerName = getContainerName(req.user.id, project.name);

        // Remove docker container (force)
        try {
            await execDocker(['rm', '-f', containerName]);
        } catch (e) {
            logger.warn(`Could not remove container ${containerName}, might not exist.`);
        }

        // Remove files
        const DEPLOYMENTS_ROOT = path.resolve(__dirname, '../../deployments');
        const projectPath = path.join(DEPLOYMENTS_ROOT, req.user.id, project.name);
        if (fs.existsSync(projectPath)) {
            fs.rmSync(projectPath, { recursive: true, force: true });
        }

        // Remove DB Record (cascade will drop deployments)
        await pool.query('DELETE FROM projects WHERE id = $1', [project.id]);
        await logAudit(req.user.id, 'delete', project.name, {}, req.ip);

        res.json({ message: 'Project deleted successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Helper to get project and verify ownership
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

// Generate container name identically to deploymentEngine
function getContainerName(userId, projectName) {
    return `${userId.substring(0, 8)}-${projectName}`;
}

router.post('/:id/start', async (req, res) => {
    try {
        const project = await getOwnedProject(req.user.id, req.params.id, res);
        if (!project) return;

        const containerName = getContainerName(req.user.id, project.name);

        await execDocker(['start', containerName]);
        await pool.query("UPDATE projects SET status = 'running' WHERE id = $1", [project.id]);

        await logAudit(req.user.id, 'start', project.name, { containerName }, req.ip);

        res.json({ message: 'Project started' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

router.post('/:id/stop', async (req, res) => {
    try {
        const project = await getOwnedProject(req.user.id, req.params.id, res);
        if (!project) return;

        const containerName = getContainerName(req.user.id, project.name);

        await execDocker(['stop', containerName]);
        await pool.query("UPDATE projects SET status = 'stopped' WHERE id = $1", [project.id]);

        await logAudit(req.user.id, 'stop', project.name, { containerName }, req.ip);

        res.json({ message: 'Project stopped' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

router.delete('/:id', async (req, res) => {
    try {
        const project = await getOwnedProject(req.user.id, req.params.id, res);
        if (!project) return;

        const containerName = getContainerName(req.user.id, project.name);

        // Remove docker container (force)
        try {
            await execDocker(['rm', '-f', containerName]);
        } catch (e) {
            logger.warn(`Could not remove container ${containerName}, might not exist.`);
        }

        // Remove files
        const DEPLOYMENTS_ROOT = path.resolve(__dirname, '../../deployments');
        const projectPath = path.join(DEPLOYMENTS_ROOT, req.user.id, project.name);
        if (fs.existsSync(projectPath)) {
            fs.rmSync(projectPath, { recursive: true, force: true });
        }

        // Remove DB Record (cascade will drop deployments)
        await pool.query('DELETE FROM projects WHERE id = $1', [project.id]);

        await logAudit(req.user.id, 'delete', project.name, {}, req.ip);

        res.json({ message: 'Project deleted successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

router.get('/:id', async (req, res) => {
    try {
        const project = await getOwnedProject(req.user.id, req.params.id, res);
        if (!project) return;
        res.json(project);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

module.exports = router;
