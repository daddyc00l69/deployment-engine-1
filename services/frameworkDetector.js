const fs = require('node:fs');
const path = require('node:path');
const logger = require('../utils/logger');

/**
 * Detects the framework of a given project path based on package.json
 * or existence of index.html.
 * 
 * @param {string} projectPath Absolute path to the cloned code
 * @returns {Promise<string>} 'next', 'react', or 'static'
 */
async function detect(projectPath) {
    const packageJsonPath = path.join(projectPath, 'package.json');
    const indexHtmlPath = path.join(projectPath, 'index.html');

    if (fs.existsSync(packageJsonPath)) {
        try {
            const rawData = fs.readFileSync(packageJsonPath, 'utf-8');
            const pkg = JSON.parse(rawData);

            const deps = { ...pkg.dependencies, ...pkg.devDependencies };

            if (deps['next'] || fs.existsSync(path.join(projectPath, 'next.config.js')) || fs.existsSync(path.join(projectPath, 'next.config.mjs'))) {
                logger.info(`Detected framework: next.js for ${projectPath}`);
                return 'next';
            }

            if (deps['react']) {
                logger.info(`Detected framework: react for ${projectPath}`);
                return 'react';
            }

            // Fallback for any Node.js project
            logger.info(`Detected framework: node (generic) for ${projectPath}`);
            return 'node';
        } catch (error) {
            logger.error(`Failed to parse package.json at ${packageJsonPath}: ${error.message}`);
            // If package.json is corrupt, still try static fallback before failing
        }
    }

    // Python detection based on requirements.txt or pyproject.toml
    if (fs.existsSync(path.join(projectPath, 'requirements.txt')) || fs.existsSync(path.join(projectPath, 'pyproject.toml'))) {
        logger.info(`Detected framework: python for ${projectPath}`);
        return 'python';
    }

    // If no package.json or it failed to parse, check for index.html
    if (fs.existsSync(indexHtmlPath)) {
        logger.info(`Detected framework: static for ${projectPath}`);
        return 'static';
    }

    // New: Check for common static assets if index.html is missing but it looks like a static site
    const commonStaticFolders = ['public', 'dist', 'build', 'html'];
    for (const folder of commonStaticFolders) {
        if (fs.existsSync(path.join(projectPath, folder, 'index.html'))) {
            logger.info(`Detected framework: static (in ${folder}/) for ${projectPath}`);
            return 'static';
        }
    }

    // Last resort: If there's ANYTHING in the folder, treat it as static or just try to serve it
    const files = fs.readdirSync(projectPath).filter(f => !f.startsWith('.'));
    if (files.length > 0) {
        logger.info(`Low confidence detection: assuming 'static' for ${projectPath}`);
        return 'static';
    }

    throw new Error('Unsupported framework: The repository appears to be empty or missing an entry point.');
}

module.exports = {
    detect
};
