const { spawn } = require('child_process');
const path = require('path');

function runGoogleDriveHelper(args, dataDir, input = null) {
    return new Promise((resolve) => {
        const helperCommand = process.env.NMAPUI_GOOGLE_DRIVE_HELPER
            || path.join(__dirname, 'packaging/macos/.build/out/Products/Debug/GoogleDriveHelper');
        const child = spawn(helperCommand, [...args, '--root', dataDir]);
        let stdout = '';
        let stderr = '';

        child.stdout.on('data', data => { stdout += data.toString(); });
        child.stderr.on('data', data => { stderr += data.toString(); });
        child.on('close', (code) => {
            try {
                const payload = JSON.parse(stdout.trim() || '{}');
                resolve({ ...payload, exitCode: code });
            } catch (error) {
                resolve({ success: false, exitCode: code, error: stderr.trim() || stdout.trim() || error.message });
            }
        });

        if (input) child.stdin.end(input);
        else child.stdin.end();
    });
}

function getGoogleDriveRedirectUri(port) {
    return `http://localhost:${port}/google-drive/oauth2callback`;
}

module.exports = {
    runGoogleDriveHelper,
    getGoogleDriveRedirectUri,
};
