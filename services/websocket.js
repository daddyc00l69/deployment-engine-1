const { Server } = require('socket.io');
const logger = require('../utils/logger');
const { pool } = require('./db');

let io;

function initWebSockets(server) {
    io = new Server(server, {
        cors: {
            origin: ['https://app.devtushar.uk', 'https://devtushar.uk', 'http://localhost:3000'],
            methods: ['GET', 'POST'],
            credentials: true
        }
    });

    io.on('connection', (socket) => {
        logger.info(`[Socket.io] Client connected: ${socket.id}`);

        // Clients will emit 'subscribeToProject' with their projectId
        socket.on('subscribeToProject', async (projectId) => {
            if (!projectId) return;

            // Join a dedicated room for this specific project
            socket.join(`project_${projectId}`);
            logger.info(`[Socket.io] Client ${socket.id} joined room: project_${projectId}`);

            // Send them the initial caught-up state
            try {
                const latestDeploy = await pool.query(
                    'SELECT status, logs FROM deployments WHERE project_id = $1 ORDER BY created_at DESC LIMIT 1',
                    [projectId]
                );

                if (latestDeploy.rows.length > 0) {
                    socket.emit('deploymentUpdate', latestDeploy.rows[0]);
                }
            } catch (err) {
                logger.error(`[Socket.io] Fetch initial state failed: ${err.message}`);
            }
        });

        socket.on('disconnect', () => {
            logger.info(`[Socket.io] Client disconnected: ${socket.id}`);
        });
    });

    // We use PostgreSQL's built in LISTEN/NOTIFY logic to trigger updates
    // instead of polluting the Worker thread with direct Socket.io references.
    setupPostgresListener();
}

/**
 * Listens to a Postgres logical replication channel.
 * When a deployment row updates in the DB, Postgres notifies us, and we broadcast it.
 */
async function setupPostgresListener() {
    const client = await pool.connect();
    try {
        await client.query('LISTEN deployment_updates');
        logger.info('[Socket.io] Listening for PG Notify channel: deployment_updates');

        client.on('notification', (msg) => {
            if (msg.channel === 'deployment_updates') {
                try {
                    const payload = JSON.parse(msg.payload); // { projectId, status, logs }
                    if (io && payload.projectId) {
                        io.to(`project_${payload.projectId}`).emit('deploymentUpdate', {
                            status: payload.status,
                            logs: payload.logs
                        });
                    }
                } catch (e) {
                    logger.error(`[Socket.io] Invalid PG Notify payload: ${e.message}`);
                }
            }
        });
    } catch (e) {
        logger.error(`[Socket.io] Failed to setup PG listener: ${e.message}`);
        client.release();
    }
}

module.exports = {
    initWebSockets
};
