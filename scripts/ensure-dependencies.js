#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const rootDir = path.resolve(__dirname, '..');
const packageJsonPath = path.join(rootDir, 'package.json');
const packageLockPath = path.join(rootDir, 'package-lock.json');
const nodeModulesPath = path.join(rootDir, 'node_modules');

function readPackageJson() {
    try {
        return JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
    } catch (error) {
        console.error(`Unable to read package.json: ${error.message}`);
        process.exit(1);
    }
}

function missingDependencies(packageJson) {
    const dependencyNames = Object.keys(packageJson.dependencies || {});
    return dependencyNames.filter(name => {
        try {
            require.resolve(name, { paths: [rootDir] });
            return false;
        } catch (error) {
            return true;
        }
    });
}

const packageJson = readPackageJson();
const missing = missingDependencies(packageJson);

if (missing.length === 0) {
    process.exit(0);
}

const npmCommand = process.env.npm_execpath || 'npm';
const installArgs = fs.existsSync(packageLockPath)
    ? ['ci', '--no-audit', '--no-fund']
    : ['install', '--no-audit', '--no-fund'];

console.log(`Missing npm dependencies: ${missing.join(', ')}`);
console.log(`Installing with: npm ${installArgs.join(' ')}`);

if (!fs.existsSync(nodeModulesPath)) {
    fs.mkdirSync(nodeModulesPath, { recursive: true });
}

const result = spawnSync(npmCommand, installArgs, {
    cwd: rootDir,
    stdio: 'inherit',
    shell: process.platform === 'win32'
});

if (result.error) {
    console.error(`Unable to install npm dependencies: ${result.error.message}`);
    process.exit(1);
}

process.exit(result.status || 0);
