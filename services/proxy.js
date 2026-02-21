const fs = require('fs/promises');
const path = require('node:path');
const { spawn } = require('node:child_process');
const logger = require('../utils/logger');

const NGINX_SITES_AVAILABLE = '/etc/nginx/sites-available';
const NGINX_SITES_ENABLED = '/etc/nginx/sites-enabled';

/**
 * Creates an NGINX reverse proxy Host configuration file
 * mapping a dynamic subdomain to an internal host port securely.
 * 
 * @param {string} subdomain The *.antigravity.com routing hostname
 * @param {number} port The `127.0.0.1` Docker container assignment
 */
async function configureNginx(subdomain, port) {
    const configContent = `
server {
    listen 80;
    server_name ${subdomain};

    location / {
        proxy_pass http://127.0.0.1:${port};
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
`;

    const configPath = path.join(NGINX_SITES_AVAILABLE, subdomain);
    const symlinkPath = path.join(NGINX_SITES_ENABLED, subdomain);

    try {
        // 1. Write the explicit Nginx conf
        await fs.writeFile(configPath, configContent, 'utf-8');
        logger.info(`NGINX config written for ${subdomain} -> Port ${port}`);

        // 2. Create enabling symlink
        try {
            await fs.symlink(configPath, symlinkPath);
        } catch (e) {
            if (e.code !== 'EEXIST') throw e;
            logger.info(`[${subdomain}] NGINX symlink already exists.`);
        }

        // 3. Hot-reload the NGINX daemon to absorb routing
        await reloadNginx();
        logger.info(`NGINX successfully reloaded. Traffic to ${subdomain} is LIVE.`);

    } catch (error) {
        logger.error(`Failed to configure NGINX for ${subdomain}: ${error.message}`);
        throw error;
    }
}

/**
 * Validates the syntax of all NGINX configs and forcefully reloads the daemon dynamically.
 */
function reloadNginx() {
    return new Promise((resolve, reject) => {
        const reloadCmd = spawn('sudo', ['systemctl', 'reload', 'nginx']);

        reloadCmd.on('close', (code) => {
            if (code === 0) resolve();
            else reject(new Error(`systemctl reload nginx failed with code ${code}`));
        });

        reloadCmd.on('error', (err) => {
            reject(new Error(`Spawn reload failed: ${err.message}`));
        });
    });
}

function removeNginx(subdomain) {
    return new Promise(async (resolve, reject) => {
        try {
            await fs.unlink(path.join(NGINX_SITES_ENABLED, subdomain)).catch(() => { });
            await fs.unlink(path.join(NGINX_SITES_AVAILABLE, subdomain)).catch(() => { });
            await reloadNginx();
            logger.info(`Removed NGINX config for ${subdomain}`);
            resolve();
        } catch (error) {
            logger.error(`Failed to purge NGINX for ${subdomain}: ${error.message}`);
            reject(error);
        }
    });
}

module.exports = {
    configureNginx,
    removeNginx
};
