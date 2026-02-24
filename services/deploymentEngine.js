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
 * @param {number} deploymentId The ID of the current deployment record
 */
async function deploy(projectPath, projectName, framework, username, userId, memoryLimitMb, cpuLimit, assignedPort, projectId, deploymentId) {
    const uniqueContainerName = `${userId.substring(0, 8)}-${projectName}`;
    const imageName = `vpsphere-${uniqueContainerName}:${Date.now()}`;
    let buildLogs = '';

    if (!assignedPort) throw new Error("Assigned port is required to bind the container securely.");

    // 1. Build the Docker image
    logger.info(`[${projectName}] Building Docker image: ${imageName}...`);

    let lastUpdateTime = Date.now();
    const LOG_UPDATE_INTERVAL = 2000; // Update DB every 2 seconds

    // Custom execution to capture logs for the DB
    const buildProcess = spawn('docker', ['build', '-t', imageName, '.'], { cwd: projectPath });

    await new Promise((resolve, reject) => {
        const updateLogsInDb = async (force = false) => {
            const now = Date.now();
            if (force || now - lastUpdateTime > LOG_UPDATE_INTERVAL) {
                lastUpdateTime = now;
                if (deploymentId) {
                    await pool.query(
                        'UPDATE deployments SET logs = $1 WHERE id = $2',
                        [buildLogs, deploymentId]
                    ).catch(err => logger.error(`[Streaming Logs Error] ${err.message}`));
                }
            }
        };

        buildProcess.stdout.on('data', async (data) => {
            const chunk = data.toString();
            buildLogs += chunk;
            await updateLogsInDb();
        });

        buildProcess.stderr.on('data', async (data) => {
            const chunk = data.toString();
            buildLogs += chunk;
            await updateLogsInDb();
        });

        buildProcess.on('close', async (code) => {
            await updateLogsInDb(true); // Final update
            if (code === 0) resolve();
            else reject(new Error(`Docker build failed with code ${code}. Logs: ${buildLogs.slice(-500)}`));
        });
    });

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
    if (framework === 'python') exposedPort = 5000;
    if (framework === 'docker') exposedPort = 8080;

    const dockerRunArgs = [
        'run', '-d',
        '--name', uniqueContainerName,
        '--network', 'vpsphere-net',
        '--memory', `${memoryLimitMb}m`,
        '--cpus', `${cpuLimit}`,
        '--restart', 'unless-stopped',
        '-p', `127.0.0.1:${assignedPort}:${exposedPort}`
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

    // 5. Update Deployment Metadata in DB
    if (deploymentId) {
        await pool.query(
            `UPDATE deployments 
             SET docker_image = $1, container_name = $2, port = $3, build_logs = $4, status = 'running' 
             WHERE id = $5`,
            [imageName, uniqueContainerName, assignedPort, buildLogs, deploymentId]
        );
    }

    logger.info(`[${projectName}] Container successfully deployed and running!`);
}

module.exports = {
    deploy
};
