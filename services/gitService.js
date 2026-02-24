const { execFile } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const util = require('node:util');
const logger = require('../utils/logger');

const execFilePromise = util.promisify(execFile);

// Assuming deploying relative to the project root, adjust as needed. 
// E.g. d:\antigravitey\VPSphere\deployments
let DEPLOYMENTS_ROOT = process.platform === 'linux' ? '/var/deployments' : path.resolve(__dirname, '../../deployments');

// Fallback logic for production if /var/deployments is not writable
if (process.platform === 'linux') {
    try {
        if (!fs.existsSync(DEPLOYMENTS_ROOT)) {
            // Try to create it, if fails, it will catch
            fs.mkdirSync(DEPLOYMENTS_ROOT, { recursive: true });
        }
    } catch (e) {
        const fallback = path.join(process.env.HOME || '/home/tushar', 'deployments');
        logger.warn(`Directory ${DEPLOYMENTS_ROOT} is not writable. Falling back to ${fallback}. Please run: sudo mkdir -p /var/deployments && sudo chown -R $(whoami) /var/deployments`);
        DEPLOYMENTS_ROOT = fallback;
    }
}

/**
 * Clones a git repository into the deployments directory isolated per user.
 * 
 * @param {string} repoUrl URL of the repository (HTTP/HTTPS)
 * @param {string} projectName Sanitized project name
 * @param {string} projectId UUID of the project
 * @param {string} githubToken Raw OAuth Access token (Optional)
 * @returns {Promise<string>} The absolute path to the cloned repository
 */
async function clone(repoUrl, projectName, projectId, githubToken = null) {
    if (!projectId) {
        throw new Error('Project ID is required for cloning isolated projects');
    }

    const targetPath = path.join(DEPLOYMENTS_ROOT, projectId, projectName);
    const parentDir = path.dirname(targetPath);

    try {
        if (!fs.existsSync(parentDir)) {
            fs.mkdirSync(parentDir, { recursive: true });
        }

        if (fs.existsSync(targetPath)) {
            logger.info(`[${projectName}] Directory exists. Wiping and cloning fresh...`);
            fs.rmSync(targetPath, { recursive: true, force: true });
        }

        // Configure private URL authentication
        let authUrl = repoUrl;
        if (githubToken && repoUrl.startsWith('https://')) {
            authUrl = repoUrl.replace('https://', `https://x-access-token:${githubToken}@`);
        }

        logger.info(`[${projectName}] Cloning repository: ${repoUrl}`); // Don't log authUrl!
        const { stdout } = await execFilePromise('git', ['clone', authUrl, targetPath]);

        if (stdout) logger.info(`[${projectName}] Git Clone output: ${stdout}`);

        return targetPath;

    } catch (error) {
        logger.error(`[${projectName}] Git clone failed: ${error.message}`);
        throw new Error(`Failed to clone repository: ${error.message}`);
    }
}

module.exports = {
    clone
};
