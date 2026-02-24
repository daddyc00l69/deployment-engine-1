const fs = require('node:fs');
const path = require('node:path');
const logger = require('../utils/logger');

/**
 * Generates a Dockerfile in the project root based on the detected framework.
 * 
 * @param {string} projectPath Absolute path to the cloned code
 * @param {string} framework 'next', 'react', or 'static'
 */
async function generate(projectPath, framework, buildCommand, startCommand) {
    const dockerfilePath = path.join(projectPath, 'Dockerfile');

    if (fs.existsSync(dockerfilePath)) {
        logger.info(`Existing Dockerfile found at ${dockerfilePath}. Skipping generation.`);
        return;
    }

    let content = '';

    if (framework === 'next' || framework === 'node' || framework === 'react') {
        const build = buildCommand || (framework === 'next' ? 'npm run build' : '');
        const startRaw = startCommand || (framework === 'next' ? 'npm start' : 'node server.js');
        const start = `CMD [${startRaw.split(' ').map(s => `"${s}"`).join(', ')}]`;

        // detect package manager
        let installCmd = 'npm install';
        if (fs.existsSync(path.join(projectPath, 'yarn.lock'))) installCmd = 'yarn';
        else if (fs.existsSync(path.join(projectPath, 'pnpm-lock.yaml'))) installCmd = 'pnpm install';

        if (framework === 'react') {
            let buildDir = 'build';
            try {
                const pkg = JSON.parse(fs.readFileSync(path.join(projectPath, 'package.json'), 'utf8'));
                if (pkg.devDependencies?.vite || pkg.dependencies?.vite) buildDir = 'dist';
            } catch (e) { }

            content = `
FROM node:20-alpine AS build
WORKDIR /app
COPY package*.json ./
${fs.existsSync(path.join(projectPath, 'yarn.lock')) ? 'COPY yarn.lock ./' : ''}
RUN ${installCmd}
COPY . .
RUN ${buildCommand || 'npm run build'}

FROM nginx:alpine
COPY --from=build /app/${buildDir} /usr/share/nginx/html
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
            `.trim();
        } else {
            content = `
FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
${fs.existsSync(path.join(projectPath, 'yarn.lock')) ? 'COPY yarn.lock ./' : ''}
RUN ${installCmd}
COPY . .
${build ? `RUN ${build}` : ''}
EXPOSE 3000
${start}
            `.trim();
        }
    } else if (framework === 'python') {
        const startRaw = startCommand || 'python app.py';
        const start = `CMD [${startRaw.split(' ').map(s => `"${s}"`).join(', ')}]`;
        content = `
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 5000
${start}
        `.trim();
    } else if (framework === 'static') {
        content = `
FROM nginx:alpine
COPY . /usr/share/nginx/html
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
        `.trim();
    }

    // Write the Dockerfile
    fs.writeFileSync(dockerfilePath, content, 'utf8');
    logger.info(`Generated Dockerfile for ${framework} at ${dockerfilePath}`);
}

module.exports = {
    generate
};
