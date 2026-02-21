const { pool } = require('./db');
const logger = require('../utils/logger');
const net = require('node:net');

/**
 * Checks if a specific port is currently in use on the host system.
 * @param {number} port Socket port to proxy test
 * @returns {Promise<boolean>} True if free, False if in use
 */
function isPortAvailable(port) {
    return new Promise((resolve) => {
        const server = net.createServer();
        server.unref();
        server.on('error', () => resolve(false));
        server.listen(port, () => {
            server.close(() => resolve(true));
        });
    });
}

/**
 * Dynamically queries the PostgreSQL database for the highest allocated port,
 * increments it, tests if it's genuinely free on the OS level, and claims it.
 * 
 * @param {string} projectId The UUID of the project
 * @returns {Promise<number>} The next available localhost TCP port
 */
async function allocateFreePort(projectId) {
    const client = await pool.connect();
    try {
        await client.query('BEGIN'); // Transaction lock for concurrency safety

        // Check if project already has a port
        const existingProjectPort = await client.query('SELECT assigned_port FROM projects WHERE id = $1', [projectId]);
        if (existingProjectPort.rows.length > 0 && existingProjectPort.rows[0].assigned_port) {
            await client.query('COMMIT');
            return existingProjectPort.rows[0].assigned_port;
        }

        // Find the highest port currently logged in the DB, starting at baseline 4000
        const result = await client.query('SELECT MAX(assigned_port) as max_port FROM projects');
        let nextPort = (result.rows[0].max_port || 4000) + 1;

        // Ensure port isn't secretly bound by the OS despite DB records
        while (!(await isPortAvailable(nextPort))) {
            logger.warn(`Port ${nextPort} logged as free but in use by OS. Incrementing...`);
            nextPort++;
        }

        // Claim it
        await client.query('UPDATE projects SET assigned_port = $1 WHERE id = $2', [nextPort, projectId]);
        await client.query('COMMIT');

        logger.info(`Project ${projectId} securely assigned to 127.0.0.1:${nextPort}`);
        return nextPort;
    } catch (error) {
        await client.query('ROLLBACK');
        logger.error(`Failed to assign dynamic NGINX port: ${error.message}`);
        throw error;
    } finally {
        client.release();
    }
}

module.exports = {
    allocateFreePort,
    isPortAvailable
};
