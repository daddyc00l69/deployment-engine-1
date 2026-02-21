const { spawn } = require('node:child_process');
const logger = require('../utils/logger');
const { pool } = require('./db');
const { decrypt } = require('../utils/encryption');

/**
 * Runs a shell command and logs its output locally. Resolves on success, rejects on failure.
 */
function runCommand(command, args, cwd) {
    return new Promise((resolve, reject) => {
        const cmdString = `${command} ${args.join(' ')}`;
        logger.info(`[Executing]: ${cmdString}`);

        const child = spawn(command, args, { cwd, shell: false });

        child.stdout.on('data', (data) => {
            logger.info(`[STDOUT] ${data.toString().trim()}`);
        });

        child.stderr.on('data', (data) => {
            // Docker build outputs to stderr a lot, so we treat it as info unless process fails
            logger.info(`[STDERR/INFO] ${data.toString().trim()}`);
        });

        child.on('close', (code) => {
            if (code === 0) {
                resolve();
            } else {
                reject(new Error(`Command failed with exit code ${code}`));
            }
        });

        child.on('error', (err) => {
            reject(new Error(`Failed to start subprocess: ${err.message}`));
        });
    });
}

/**
 * Builds and runs the Docker container using docker CLI with tenant isolation.
 * 
 * @param {string} projectPath Absolute path to the cloned repository
 * @param {string} projectName Sanitized project name
 * @param {string} framework 'next', 'react', 'node', 'python', or 'static'
 * @param {string} username Tenant username
 * @param {string} userId Tenant ID
 * @param {number} memoryLimitMb Memory limit mapped from user's plan
 * @param {number} cpuLimit CPU limit mapped from user's plan
 * @param {number} assignedPort The internal port allocated by the PortManager
 * @param {string} projectId The UUID of the project for fetching environment variables
 */
async function deploy(projectPath, projectName, framework, username, userId, memoryLimitMb, cpuLimit, assignedPort, projectId) {
    const uniqueContainerName = `${userId.substring(0, 8)}-${projectName}`;
    const imageName = `deploy-${uniqueContainerName}`;

    if (!assignedPort) throw new Error("Assigned port is required to bind the container securely.");

    // 1. Build the Docker image
    logger.info(`[${projectName}] Building Docker image: ${imageName}...`);
    await runCommand('docker', ['build', '-t', imageName, '.'], projectPath);

    // 2. Stop and remove existing container if it exists
    logger.info(`[${projectName}] Stopping and removing old container if exists...`);
    try {
        await runCommand('docker', ['rm', '-f', uniqueContainerName], projectPath);
    } catch (e) {
        logger.info(`[${projectName}] No existing container found to remove.`);
    }

    // 3. Detect exposed port based on framework conventions inside the Dockerfile
    let exposedPort = 3000;
    if (framework === 'react' || framework === 'static') exposedPort = 80;
    if (framework === 'python') exposedPort = 5000; // default flask/wsgi port
    if (framework === 'docker') exposedPort = 8080; // generic fallback

    const dockerRunArgs = [
        'run', '-d',
        '--name', uniqueContainerName,
        '--memory', `${memoryLimitMb}m`,
        '--cpus', `${cpuLimit}`,
        '--restart', 'unless-stopped',
        '-p', `127.0.0.1:${assignedPort}:${exposedPort}` // Securely bind only to localhost reverse proxy
    ];

    // 4. Inject Encrypted Environment Variables at runtime
    if (projectId) {
        try {
            const envsRes = await pool.query('SELECT key_name, value_encrypted FROM project_envs WHERE project_id = $1', [projectId]);
            for (const env of envsRes.rows) {
                const plaintextValue = decrypt(env.value_encrypted);
                if (plaintextValue !== 'ERROR_DECRYPTING') {
                    dockerRunArgs.push('-e', `${env.key_name}=${plaintextValue}`);
                }
            }
        } catch (e) {
            logger.error(`[${projectName}] Failed to load environment variables into container: ${e.message}`);
        }
    }

    dockerRunArgs.push(imageName);

    logger.info(`[${projectName}] Starting new container...`);
    await runCommand('docker', dockerRunArgs, projectPath);
    logger.info(`[${projectName}] Container successfully deployed and running!`);
}

module.exports = {
    deploy
};
