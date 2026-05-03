const VERSION = 'v2026.5.2.15.58';

const express = require('express');
const http = require('http');
const { Server } = require("socket.io");
const { spawn, exec, execFile } = require('child_process');
const path = require('path');
const fs = require('fs');
const cron = require('node-cron');
const axios = require('axios');
const xml2js = require('xml2js');
const crypto = require('crypto');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const APP_IDENTITY = 'tm-network-scanner';
const PORT = Number(process.env.PORT || 9000);

app.use(express.static(path.join(__dirname)));
app.use('/static', express.static(path.join(__dirname, 'static')));
app.use('/reports', express.static(path.join(__dirname, 'reports_archive')));

app.get('/api/app-identity', (req, res) => {
    res.json({ app: APP_IDENTITY, name: 'TM-NMapUI', version: VERSION });
});

app.get('/google-drive/oauth2callback', async (req, res) => {
    const result = await runGoogleDriveHelper([
        'exchange-code',
        '--code', req.query.code || '',
        '--state', req.query.state || ''
    ]);
    if (result.success) {
        const googleDrive = saveGoogleDriveConfig({ enabled: true });
        logEvent(null, 'settings', 'Google Drive connected and sync enabled.');
        io.emit('google_drive_status', { ...result, config: googleDrive });
        res.send('<html><body><h1>Google Drive connected</h1><p>You can close this window and return to TM-NMapUI.</p></body></html>');
        return;
    }
    io.emit('google_drive_status', { ...result, config: getGoogleDriveConfig() });
    res.status(400).send(`<html><body><h1>Google Drive connection failed</h1><p>${String(result.error || 'Unknown error')}</p></body></html>`);
});

// Global state for persistence across tabs
let currentScan = null;
let scanStartTime = null;
let autoScanTask = null;
let discoveredHosts = [];
let currentScanPhase = null;
let currentTarget = null;
let currentScanKind = null;
let lastScanResult = null;
let cachedHops = [];
let isTracerouteRunning = false;
let cachedNetworkInfo = null;
let cachedPublicIP = null;

const CONFIG_PATH = path.join(__dirname, 'config.json');
const HISTORY_PATH = path.join(__dirname, 'history.json');
const REPORTS_DIR = path.join(__dirname, 'reports_archive');
const NMAP_PATH = resolveExecutable(process.env.NMAP_PATH, [
    '/opt/homebrew/bin/nmap',
    '/usr/local/bin/nmap',
    '/usr/bin/nmap',
    '/bin/nmap',
    'nmap'
]);
const TRACEROUTE_PATH = resolveExecutable(process.env.TRACEROUTE_PATH, [
    '/usr/sbin/traceroute',
    '/sbin/traceroute',
    '/opt/homebrew/bin/traceroute',
    '/usr/local/bin/traceroute',
    'traceroute'
]);
const BREW_PATH = resolveExecutable(process.env.BREW_PATH, [
    '/opt/homebrew/bin/brew',
    '/usr/local/bin/brew',
    'brew'
]);
const GOWITNESS_PATH = resolveExecutable(process.env.GOWITNESS_PATH, [
    '/opt/homebrew/bin/gowitness',
    '/usr/local/bin/gowitness',
    'gowitness',
    ...getGoExecutableCandidates('gowitness')
]);
let customerProfileConfig = loadJSON(CONFIG_PATH, {}).customerProfile || {};
let appConfig = loadJSON(CONFIG_PATH, {});

if (!fs.existsSync(REPORTS_DIR)) fs.mkdirSync(REPORTS_DIR);

function loadJSON(filePath, defaultVal = {}) {
    if (fs.existsSync(filePath)) {
        try { return JSON.parse(fs.readFileSync(filePath)); } catch(e) { return defaultVal; }
    }
    return defaultVal;
}

function saveJSON(filePath, data) {
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
}

function saveCustomerProfileConfig(profileConfig) {
    const config = loadJSON(CONFIG_PATH, {});
    config.customerProfile = profileConfig;
    appConfig = config;
    customerProfileConfig = profileConfig;
    saveJSON(CONFIG_PATH, config);
}

function saveGoogleDriveConfig(googleDriveConfig) {
    const config = loadJSON(CONFIG_PATH, {});
    config.googleDrive = { ...(config.googleDrive || {}), ...googleDriveConfig };
    appConfig = config;
    saveJSON(CONFIG_PATH, config);
    return config.googleDrive;
}

function saveAutoScanConfig(autoScanConfig) {
    const config = loadJSON(CONFIG_PATH, {});
    config.autoScan = { ...(config.autoScan || {}), ...autoScanConfig };
    appConfig = config;
    saveJSON(CONFIG_PATH, config);
    setupAutoScan(config);
    return config.autoScan;
}

function getGoogleDriveConfig() {
    return appConfig.googleDrive || {};
}

function isExecutable(filePath) {
    if (!filePath) return false;
    try {
        fs.accessSync(filePath, fs.constants.X_OK);
        return true;
    } catch (error) {
        return false;
    }
}

function resolveExecutable(explicitPath, candidates) {
    const searchPaths = (process.env.PATH || '')
        .split(path.delimiter)
        .filter(Boolean);
    const pathCandidates = candidates
        .filter(candidate => !candidate.includes(path.sep))
        .flatMap(name => searchPaths.map(dir => path.join(dir, name)));
    return [explicitPath, ...candidates, ...pathCandidates]
        .filter(Boolean)
        .map(expandUserPath)
        .find(isExecutable) || null;
}

function expandUserPath(filePath) {
    if (!filePath || !filePath.startsWith('~')) return filePath;
    const homeDir = process.env.HOME || (process.env.SUDO_USER ? `/Users/${process.env.SUDO_USER}` : '');
    if (!homeDir) return filePath;
    return path.join(homeDir, filePath.slice(1));
}

function getGoExecutableCandidates(binaryName) {
    const candidates = [];
    if (process.env.GOBIN) candidates.push(path.join(process.env.GOBIN, binaryName));
    if (process.env.GOPATH) {
        process.env.GOPATH.split(path.delimiter).filter(Boolean).forEach(goPath => {
            candidates.push(path.join(goPath, 'bin', binaryName));
        });
    }
    if (process.env.HOME) candidates.push(path.join(process.env.HOME, 'go', 'bin', binaryName));
    if (process.env.SUDO_USER) candidates.push(path.join('/Users', process.env.SUDO_USER, 'go', 'bin', binaryName));
    return candidates;
}

function getPrivilegedCommand(executablePath, args) {
    if (process.getuid && process.getuid() === 0) {
        return { command: executablePath, args };
    }
    return { command: 'sudo', args: ['-n', executablePath, ...args] };
}

function describeMissingExecutable(name, envVar) {
    return `${name} was not found. Install it or set ${envVar} to the executable path.`;
}

function getBrewCommand(args) {
    if (process.getuid && process.getuid() === 0) {
        const sudoUser = process.env.SUDO_USER;
        if (!sudoUser || sudoUser === 'root') return null;
        return {
            command: 'sudo',
            args: ['-u', sudoUser, BREW_PATH, ...args],
            env: { ...process.env, HOME: `/Users/${sudoUser}`, USER: sudoUser }
        };
    }
    return { command: BREW_PATH, args, env: process.env };
}

function runBrewStep(args) {
    return new Promise((resolve) => {
        const commandSpec = getBrewCommand(args);
        if (!BREW_PATH || !commandSpec) {
            resolve({ success: false, error: 'Homebrew is unavailable or cannot be run from the current user context.' });
            return;
        }

        const brew = spawn(commandSpec.command, commandSpec.args, { env: commandSpec.env });
        brew.stdout.on('data', data => {
            const text = data.toString().trim();
            if (text) console.log(`[BREW] ${text}`);
        });
        brew.stderr.on('data', data => {
            const text = data.toString().trim();
            if (text) console.warn(`[BREW] ${text}`);
        });
        brew.on('error', error => resolve({ success: false, error: error.message }));
        brew.on('close', code => resolve({ success: code === 0, error: code === 0 ? '' : `brew ${args.join(' ')} exited with code ${code}` }));
    });
}

async function updateNmapFromHomebrew() {
    if (!BREW_PATH) {
        console.warn('Skipping Homebrew nmap upgrade: brew was not found.');
        return;
    }
    const commandSpec = getBrewCommand(['update']);
    if (!commandSpec) {
        console.warn('Skipping Homebrew nmap upgrade: brew cannot run as root without SUDO_USER.');
        return;
    }

    console.log('Startup - Running brew update && brew upgrade nmap...');
    const update = await runBrewStep(['update']);
    if (!update.success) {
        console.warn(`Skipping brew upgrade nmap: ${update.error}`);
        return;
    }
    const upgrade = await runBrewStep(['upgrade', 'nmap']);
    if (!upgrade.success) {
        console.warn(`Homebrew nmap upgrade did not complete: ${upgrade.error}`);
    }
}

function updateNmapScriptDatabase() {
    if (!NMAP_PATH) {
        console.warn(describeMissingExecutable('nmap', 'NMAP_PATH'));
        return;
    }

    console.log('Prescan - Updating scripts...');
    const updateCommand = getPrivilegedCommand(NMAP_PATH, ['--script-updatedb']);
    const updateProcess = spawn(updateCommand.command, updateCommand.args);
    updateProcess.stderr.on('data', data => {
        const text = data.toString();
        if (isSudoAuthFailure(text)) {
            console.warn('Skipping nmap script update: passwordless sudo is required.');
        } else if (!text.includes('Warning: ')) {
            console.warn(`[NMAP UPDATE] ${text.trim()}`);
        }
    });
    updateProcess.on('error', error => console.warn(`Skipping nmap script update: ${error.message}`));
}

function isSudoAuthFailure(text) {
    return /sudo:.*password|a password is required|no tty present|permission denied/i.test(text || '');
}

function requestJSON(url, timeoutMs = 1000) {
    return new Promise((resolve) => {
        const request = http.get(url, { timeout: timeoutMs }, response => {
            let raw = '';
            response.on('data', chunk => { raw += chunk.toString(); });
            response.on('end', () => {
                try {
                    resolve(JSON.parse(raw || '{}'));
                } catch (error) {
                    resolve(null);
                }
            });
        });
        request.on('timeout', () => {
            request.destroy();
            resolve(null);
        });
        request.on('error', () => resolve(null));
    });
}

function getPortListenerPids(port) {
    return new Promise((resolve) => {
        exec(`lsof -ti tcp:${Number(port)} -sTCP:LISTEN`, (error, stdout) => {
            if (error || !stdout.trim()) {
                resolve([]);
                return;
            }
            resolve(stdout.trim().split(/\s+/).map(pid => Number(pid)).filter(Boolean));
        });
    });
}

async function stopExistingAppOnPort(port) {
    const identity = await requestJSON(`http://127.0.0.1:${port}/api/app-identity`);
    if (identity?.app !== APP_IDENTITY) {
        return false;
    }

    const pids = (await getPortListenerPids(port)).filter(pid => pid !== process.pid);
    if (pids.length === 0) return false;

    console.warn(`Port ${port} is already used by ${identity.name || APP_IDENTITY}; stopping pid(s): ${pids.join(', ')}`);
    pids.forEach(pid => {
        try {
            process.kill(pid, 'SIGTERM');
        } catch (error) {
            console.warn(`Failed to stop pid ${pid}: ${error.message}`);
        }
    });

    await new Promise(resolve => setTimeout(resolve, 1200));
    const remaining = (await getPortListenerPids(port)).filter(pid => pid !== process.pid);
    remaining.forEach(pid => {
        try {
            process.kill(pid, 'SIGKILL');
        } catch (error) {
            console.warn(`Failed to force stop pid ${pid}: ${error.message}`);
        }
    });
    return true;
}

function shellQuote(value) {
    return `'${String(value).replace(/'/g, `'\\''`)}'`;
}

function escapeHtml(value) {
    return String(value ?? '').replace(/[&<>"']/g, (char) => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;'
    })[char]);
}

function getChromeExecutable() {
    const candidates = [
        process.env.CHROME_PATH,
        '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
        '/Applications/Chromium.app/Contents/MacOS/Chromium',
        '/usr/bin/google-chrome',
        '/usr/bin/chromium',
        '/usr/bin/chromium-browser'
    ].filter(Boolean);
    return candidates.find(candidate => fs.existsSync(candidate)) || null;
}

function generatePDF(reportPath, pdfPath, callback) {
    const chromePath = getChromeExecutable();
    if (chromePath) {
        const reportUrl = `file://${reportPath}`;
        const command = [
            shellQuote(chromePath),
            '--headless',
            '--disable-gpu',
            '--no-sandbox',
            '--no-pdf-header-footer',
            '--run-all-compositor-stages-before-draw',
            '--virtual-time-budget=5000',
            '--print-to-pdf-page-size=Letter',
            `--print-to-pdf=${shellQuote(pdfPath)}`,
            shellQuote(reportUrl)
        ].join(' ');
        exec(command, callback);
        return;
    }

    const wkhtmltopdfCommand = [
        'wkhtmltopdf',
        '--enable-local-file-access',
        '--print-media-type',
        '--page-size', 'Letter',
        '--orientation', 'Portrait',
        '--margin-top', '8mm',
        '--margin-right', '8mm',
        '--margin-bottom', '8mm',
        '--margin-left', '8mm',
        '--javascript-delay', '3000',
        '--no-stop-slow-scripts',
        shellQuote(reportPath),
        shellQuote(pdfPath)
    ].join(' ');
    exec(wkhtmltopdfCommand, callback);
}

function sanitizeReportSegment(value, fallback = 'unknown') {
    const cleaned = String(value || '')
        .trim()
        .replace(/[^0-9A-Za-z_.-]+/g, '_')
        .replace(/^_+|_+$/g, '');
    return cleaned || fallback;
}

function formatReportTimestamp(date = new Date()) {
    const pad = value => String(value).padStart(2, '0');
    return [
        date.getFullYear(),
        pad(date.getMonth() + 1),
        pad(date.getDate())
    ].join('') + '_' + [
        pad(date.getHours()),
        pad(date.getMinutes()),
        pad(date.getSeconds())
    ].join('');
}

function formatReportDisplayTimestamp(date = new Date()) {
    return date.toLocaleString('en-US', {
        year: 'numeric',
        month: 'short',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false,
        timeZoneName: 'short'
    });
}

function formatDriveDayFolder(date = new Date()) {
    const pad = value => String(value).padStart(2, '0');
    return [
        date.getFullYear(),
        pad(date.getMonth() + 1),
        pad(date.getDate())
    ].join('-');
}

function getDriveMetadataPath(reportPath) {
    return `${reportPath}.drive.json`;
}

function saveDriveMetadata(reportPath, result) {
    if (!reportPath || !result?.success) return null;
    const metadataPath = getDriveMetadataPath(reportPath);
    const metadata = {
        uploadedAt: new Date().toISOString(),
        folderId: result.folder_id || null,
        dayFolderId: result.day_folder_id || null,
        links: (result.uploaded || []).map(file => ({
            name: file.name || '',
            webViewLink: file.webViewLink || '',
            id: file.id || ''
        })).filter(file => file.name || file.webViewLink || file.id)
    };
    saveJSON(metadataPath, metadata);
    return metadata;
}

function loadDriveMetadata(reportPath) {
    const metadata = loadJSON(getDriveMetadataPath(reportPath), null);
    if (!metadata || !Array.isArray(metadata.links)) return null;
    return metadata;
}

function findDriveLink(metadata, fileName) {
    return (metadata?.links || []).find(file => file.name === fileName)?.webViewLink || null;
}

function getTopologyFingerprintParts() {
    const hosts = discoveredHosts
        .map(host => [host.ip, host.mac || '', host.vendor || '', host.hostname || ''].join('|'))
        .sort();
    const hops = cachedHops
        .map(hop => `${hop.hop}:${hop.ip}`)
        .sort();
    return {
        hosts,
        hops,
        network: cachedNetworkInfo ? `${cachedNetworkInfo.localIP || ''}|${cachedNetworkInfo.cidr || ''}|${cachedNetworkInfo.mask || ''}` : ''
    };
}

function getCustomerFingerprintProfile() {
    const publicIP = cachedPublicIP && cachedPublicIP !== 'Unknown' ? cachedPublicIP : 'unknown_wan';
    const prefix = sanitizeReportSegment(customerProfileConfig.prefix || 'CSP', 'CSP');
    const wan = sanitizeReportSegment(publicIP, 'unknown_wan');
    const topology = getTopologyFingerprintParts();
    const fingerprintSource = JSON.stringify({ publicIP, topology });
    const fingerprint = crypto.createHash('sha256').update(fingerprintSource).digest('hex').slice(0, 8);
    const baseName = `${prefix}_${wan}`;
    const reportLabel = `${prefix}_(${wan})`;

    return {
        prefix,
        publicIP,
        wan,
        fingerprint,
        baseName,
        reportLabel,
        folderName: `${baseName}_${fingerprint}`,
        topology
    };
}

function runGoogleDriveHelper(args, input = null) {
    return new Promise((resolve) => {
        const child = spawn('python3', [path.join(__dirname, 'google_drive.py'), ...args, '--root', __dirname]);
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

function getGoogleDriveRedirectUri() {
    return `http://localhost:${PORT}/google-drive/oauth2callback`;
}

async function uploadReportFilesToDrive(socket, filePaths, profile, context = {}) {
    const googleDrive = appConfig.googleDrive || {};
    const label = context.label || 'report';
    if (!googleDrive.enabled) {
        logEvent(socket, 'report', `Google Drive sync disabled; skipping upload for ${label}.`);
        return null;
    }

    const existingFiles = filePaths.filter(filePath => filePath && fs.existsSync(filePath));
    if (existingFiles.length === 0) {
        logEvent(socket, 'error', `Google Drive upload skipped for ${label}: no generated files were found.`);
        return null;
    }

    const folderName = 'Nmap Reports';
    const dayFolderName = context.dayFolderName || formatDriveDayFolder();
    const args = ['upload', '--folder-name', folderName, '--day-folder-name', dayFolderName, '--files', ...existingFiles];
    if (googleDrive.folderId) args.splice(1, 0, '--folder-id', googleDrive.folderId);

    const fileNames = existingFiles.map(filePath => path.basename(filePath)).join(', ');
    const destination = googleDrive.folderId ? `folder ID ${googleDrive.folderId}` : folderName;
    logEvent(socket, 'report', `Google Drive upload starting for ${label}: ${fileNames} -> ${destination}`);

    const result = await runGoogleDriveHelper(args);
    if (result.success) {
        if (result.folder_id && !googleDrive.folderId) saveGoogleDriveConfig({ folderId: result.folder_id });
        const uploadedNames = (result.uploaded || []).map(file => file.name).filter(Boolean).join(', ') || `${existingFiles.length} file(s)`;
        logEvent(socket, 'report', `Google Drive upload complete for ${label}: ${uploadedNames}${result.folder_id ? ` (folder ID ${result.folder_id})` : ''}`);
        (result.uploaded || [])
            .map(file => file.webViewLink)
            .filter(Boolean)
            .forEach(link => logEvent(socket, 'report', `Google Drive file link: ${link}`));
        if (context.reportPath) {
            saveDriveMetadata(context.reportPath, result);
            io.emit('reports_refresh');
        }
        io.emit('google_drive_upload_complete', { ...result, label });
    } else {
        logEvent(socket, 'error', `Google Drive upload failed for ${label}: ${result.error || 'Unknown error'}`);
        io.emit('google_drive_status', { ...result, label });
    }
    return result;
}

function isCompleteNmapXML(xmlPath) {
    if (!fs.existsSync(xmlPath)) return false;
    const xml = fs.readFileSync(xmlPath, 'utf8').trim();
    return xml.includes('<nmaprun') && xml.endsWith('</nmaprun>');
}

function buildPhase2Args(usePn = false, fullPortScan = false, options = {}) {
    const hostGroupArgs = options.hostGroup
        ? ['--min-hostgroup', '1', '--max-hostgroup', String(options.hostGroup)]
        : [];
    const scripts = options.disableScripts ? [] : (options.consolidateScripts ? ['default,vulners'] : ['vulners']);
    const rateArgs = options.minRate ? ['--min-rate', String(options.minRate)] : [];
    const defaultScriptArgs = options.includeDefaultScripts === false || options.consolidateScripts ? [] : ['-sC'];
    const scriptArgs = scripts.length && options.scriptArgs !== false
        ? ['--script-args', options.scriptArgs || 'mincvss=0,threads=10']
        : [];
    const args = [
        ...(fullPortScan ? ['-p-'] : []),
        '-sS', '-sV',
        ...defaultScriptArgs,
        '-O',
        ...(usePn ? ['-Pn'] : []),
        options.timing || '-T3',
        ...rateArgs,
        ...(options.maxParallelism ? ['--max-parallelism', String(options.maxParallelism)] : []),
        ...(options.maxRetries ? ['--max-retries', String(options.maxRetries)] : []),
        ...hostGroupArgs,
        '--open',
        ...(scripts.length ? ['--script', scripts.join(',')] : []),
        ...scriptArgs,
        '--stylesheet', 'nmap-modern.xsl',
        '-oX', 'phase2_results.xml',
        '-iL', 'targets.tmp'
    ];
    return args;
}

function parseTargetInput(target) {
    return String(target || '')
        .split(/[,\n]+/)
        .map(item => item.trim())
        .filter(Boolean);
}

function formatTargetLabel(targets) {
    return targets.length > 1 ? targets.join(', ') : targets[0];
}

function compactErrorText(value, maxLength = 4000) {
    const text = String(value || '').replace(/\s+\n/g, '\n').trim();
    if (text.length <= maxLength) return text;
    return text.slice(-maxLength).trim();
}

function saveFailedScanHistory({ target, duration, hostCount, scanKind, customerProfile, error }) {
    const history = loadJSON(HISTORY_PATH, []);
    history.unshift({
        timestamp: new Date().toISOString(),
        target,
        duration,
        hostCount,
        scanKind,
        status: 'failed',
        error: compactErrorText(error),
        customerProfile
    });
    saveJSON(HISTORY_PATH, history.slice(0, 50));
    io.emit('reports_refresh');
}

function setupAutoScan(config) {
    if (autoScanTask) autoScanTask.stop();
    autoScanTask = null;
    const autoScan = config.autoScan || {};
    if (!autoScan.enabled) return;

    const startTime = autoScan.startTime || '01:00';
    const [hour = '1', minute = '0'] = startTime.split(':');
    const recurrence = ['hourly', 'daily', 'weekly', 'monthly'].includes(autoScan.recurrence)
        ? autoScan.recurrence
        : 'daily';
    const cronExpression = {
        hourly: `${minute} * * * *`,
        daily: `${minute} ${hour} * * *`,
        weekly: `${minute} ${hour} * * 0`,
        monthly: `${minute} ${hour} 1 * *`
    }[recurrence];

    autoScanTask = cron.schedule(cronExpression, () => {
        const target = autoScan.target || cachedNetworkInfo?.cidr || '192.168.1.0/24';
        logEvent(null, 'job', `Starting scheduled ${recurrence} Complete+PDF scan for ${target}...`);
        startChainedScan(null, target, true);
    });
    console.log(`Auto-monitor scheduled ${recurrence} at ${startTime}.`);
}

function logEvent(socket, level, message) {
    const entry = { timestamp: new Date().toISOString(), level, message };
    console.log(`[${level.toUpperCase()}] ${message}`);
    if (socket) socket.emit('log_entry', entry);
    else io.emit('log_entry', entry);
}

function ipToInt(ip) {
    const parts = String(ip).split('.').map(Number);
    if (parts.length !== 4 || parts.some(part => !Number.isInteger(part) || part < 0 || part > 255)) return null;
    return (((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3]) >>> 0;
}

function intToIp(value) {
    return [
        (value >>> 24) & 255,
        (value >>> 16) & 255,
        (value >>> 8) & 255,
        value & 255
    ].join('.');
}

function maskHexToInfo(maskHex) {
    const normalized = String(maskHex || '').replace(/^0x/i, '').padStart(8, '0').slice(-8);
    const maskInt = parseInt(normalized, 16) >>> 0;
    if (!Number.isFinite(maskInt)) return null;
    const binary = maskInt.toString(2).padStart(32, '0');
    if (!/^1*0*$/.test(binary)) return null;
    const prefix = binary.indexOf('0') === -1 ? 32 : binary.indexOf('0');
    return { maskInt, prefix, dotted: intToIp(maskInt) };
}

function getNetworkCidr(localIP, maskHex) {
    const ipInt = ipToInt(localIP);
    const maskInfo = maskHexToInfo(maskHex);
    if (ipInt === null || !maskInfo) return '';
    return `${intToIp((ipInt & maskInfo.maskInt) >>> 0)}/${maskInfo.prefix}`;
}

async function getNetworkInfo() {
    return new Promise((resolve) => {
        exec("route get default", (error, routeOutput) => {
            const ifaceMatch = routeOutput && routeOutput.match(/interface:\s+(\w+)/);
            const iface = ifaceMatch ? ifaceMatch[1] : 'en0';
            exec(`ifconfig ${iface}`, (error, ifconfigOutput) => {
                const ipMatch = ifconfigOutput && ifconfigOutput.match(/inet\s+([0-9.]+)/);
                const maskMatch = ifconfigOutput && ifconfigOutput.match(/netmask\s+0x([0-9a-f]+)/);
                const localIP = ipMatch ? ipMatch[1] : 'Unknown';
                const maskInfo = maskMatch ? maskHexToInfo(maskMatch[1]) : null;
                const cidr = maskMatch ? getNetworkCidr(localIP, maskMatch[1]) : '';
                const result = {
                    localIP,
                    mask: maskInfo ? maskInfo.dotted : (maskMatch ? '0x' + maskMatch[1] : 'Unknown'),
                    cidr: cidr || '192.168.1.0/24'
                };
                cachedNetworkInfo = result;
                resolve(result);
            });
        });
    });
}

async function getPublicIP() {
    try {
        const response = await axios.get('https://api.ipify.org?format=json');
        cachedPublicIP = response.data.ip;
        return cachedPublicIP;
    } catch (error) {
        cachedPublicIP = 'Unknown';
        return 'Unknown';
    }
}

function runTraceroute() {
    if (isTracerouteRunning) return;
    if (!TRACEROUTE_PATH) {
        console.warn(describeMissingExecutable('traceroute', 'TRACEROUTE_PATH'));
        return;
    }
    isTracerouteRunning = true;
    cachedHops = [];
    const traceroute = spawn(TRACEROUTE_PATH, ['-m', '15', '-n', '-q', '1', '8.8.8.8']);
    traceroute.stdout.on('data', (data) => {
        const lines = data.toString().split('\n');
        lines.forEach(line => {
            const match = line.match(/^\s*(\d+)\s+([0-9.]+)/);
            if (match) {
                const hop = { hop: parseInt(match[1]), ip: match[2] };
                if (!cachedHops.find(h => h.hop === hop.hop)) {
                    cachedHops.push(hop);
                    io.emit('traceroute_hop', hop);
                }
            }
        });
    });
    traceroute.on('error', error => {
        console.error(`[TRACEROUTE ERROR] ${error.message}`);
        isTracerouteRunning = false;
    });
    traceroute.on('close', () => { isTracerouteRunning = false; });
}

function parseNmapXML(xmlPath, onParsed = null) {
    if (!fs.existsSync(xmlPath)) {
        console.log('XML result file not found at:', xmlPath);
        return;
    }
    if (!isCompleteNmapXML(xmlPath)) {
        console.log('XML parse error: Nmap XML is incomplete at:', xmlPath);
        return;
    }
    const xml = fs.readFileSync(xmlPath, 'utf8');
    const parser = new xml2js.Parser();
    parser.parseString(xml, (err, result) => {
        if (err || !result || !result.nmaprun || !result.nmaprun.host) {
            console.log('XML parse error or no hosts found in XML');
            return;
        }
        result.nmaprun.host.forEach(hostData => {
            const ipData = hostData.address.find(a => a.$.addrtype === 'ipv4');
            if (!ipData) return;
            const ip = ipData.$.addr;
            const macData = hostData.address.find(a => a.$.addrtype === 'mac');
            const mac = macData ? macData.$.addr : '';
            const vendor = macData ? macData.$.vendor : '';
            const hostname = (hostData.hostnames && hostData.hostnames[0].hostname) ? hostData.hostnames[0].hostname[0].$.name : '';
            
            let os = '--';
            if (hostData.os && hostData.os[0].osmatch) {
                os = hostData.os[0].osmatch[0].$.name;
            }

            const latency = hostData.times ? (parseFloat(hostData.times[0].$.srtt) / 1000).toFixed(2) + 'ms' : '--';
            
            const ports = [];
            const versions = [];
            const highCVEs = new Set();
            const lowCVEs = new Set();

            if (hostData.ports && hostData.ports[0].port) {
                hostData.ports[0].port.forEach(p => {
                    if (p.state[0].$.state === 'open') {
                        const portId = p.$.portid;
                        ports.push(portId);
                        
                        if (p.service) {
                            const s = p.service[0].$;
                            const v = `${s.name} ${s.product || ''} ${s.version || ''}`.trim();
                            if (v) versions.push(`${portId}:${v}`);
                        }

                        if (p.script) {
                            p.script.forEach(s => {
                                if (s.$.id === 'vulners' && s.table) {
                                    const vulnTables = s.table[0].table;
                                    if (vulnTables) {
                                        vulnTables.forEach(t => {
                                            const getElemName = (elem) => elem.$.name || elem.$.key;
                                            const cvssElem = t.elem ? t.elem.find(e => getElemName(e) === 'cvss') : null;
                                            const idElem = t.elem ? t.elem.find(e => getElemName(e) === 'id') : null;
                                            
                                            if (cvssElem && idElem) {
                                                const score = parseFloat(cvssElem._);
                                                const id = idElem._;
                                                if (!id || !id.startsWith('CVE-') || Number.isNaN(score)) return;
                                                if (score >= 7.0) {
                                                    highCVEs.add(`${id}(${score})`);
                                                } else {
                                                    lowCVEs.add(id);
                                                }
                                            }
                                        });
                                    }
                                }
                            });
                        }
                    }
                });
            }

            updateDiscoveredHost(ip, { 
                mac, vendor, hostname, os, latency, 
                ports: ports.join(', '), 
                version: versions.join(' | '),
                highCVEs: Array.from(highCVEs).join(', '),
                lowCVECount: lowCVEs.size
            });
        });
        if (onParsed) onParsed(getScanStats());
    });
}

function getWebTargetsFromDiscoveredHosts() {
    const webPorts = new Set([80, 443, 3000, 5000, 8000, 8080, 8443, 8888, 9000, 9443]);
    const targets = [];
    discoveredHosts.forEach(host => {
        const versionText = String(host.version || '').toLowerCase();
        const serviceByPort = new Map();
        versionText.split('|').forEach(chunk => {
            const match = chunk.trim().match(/^(\d+):(.+)$/);
            if (match) serviceByPort.set(Number(match[1]), match[2]);
        });
        const ports = String(host.ports || '')
            .split(',')
            .map(port => Number(String(port).trim()))
            .filter(port => {
                if (!Number.isInteger(port)) return false;
                const serviceHint = serviceByPort.get(port) || '';
                return webPorts.has(port) || /\bhttp\b|\bhttps\b/.test(serviceHint);
            });
        ports.forEach(port => {
            const portHint = serviceByPort.get(port) || '';
            const isHttps = [443, 8443, 9443].includes(port) || /\bssl\b|\bhttps\b/.test(portHint);
            const scheme = isHttps ? 'https' : 'http';
            const defaultPort = (scheme === 'http' && port === 80) || (scheme === 'https' && port === 443);
            targets.push({
                ip: host.ip,
                port,
                url: `${scheme}://${host.ip}${defaultPort ? '' : `:${port}`}`
            });
        });
    });
    return targets.slice(0, 40);
}

function listImageFiles(dirPath) {
    if (!fs.existsSync(dirPath)) return [];
    return fs.readdirSync(dirPath)
        .filter(file => /\.(png|jpe?g|webp)$/i.test(file))
        .map(file => ({
            file,
            path: path.join(dirPath, file),
            mtime: fs.statSync(path.join(dirPath, file)).mtimeMs
        }))
        .sort((a, b) => b.mtime - a.mtime);
}

function runGowitnessCommand(args) {
    return new Promise(resolve => {
        execFile(GOWITNESS_PATH, args, { cwd: __dirname, timeout: 90000 }, (error, stdout, stderr) => {
            resolve({ success: !error, error, stdout, stderr });
        });
    });
}

async function captureGowitnessTarget(target, screenshotDir, reportBaseName) {
    const beforeFiles = new Set(listImageFiles(screenshotDir).map(item => item.file));
    const safeName = sanitizeReportSegment(`${target.ip}_${target.port}`);
    const explicitPath = path.join(screenshotDir, `${safeName}.png`);
    const metaPath = path.join(screenshotDir, `${safeName}.jsonl`);
    const commandAttempts = [
        ['scan', 'single', '--url', target.url, '--screenshot-path', screenshotDir, '--write-jsonl', '--write-jsonl-file', metaPath],
        ['single', '--url', target.url, '--screenshot-path', screenshotDir, '--write-jsonl', '--write-jsonl-file', metaPath],
        ['single', '--disable-db', '--screenshot-path', screenshotDir, target.url],
        ['single', '-o', explicitPath, target.url]
    ];

    for (const args of commandAttempts) {
        const result = await runGowitnessCommand(args);
        if (!result.success) continue;
        const files = listImageFiles(screenshotDir);
        const created = files.find(item => !beforeFiles.has(item.file));
        if (created) return created;
    }
    return null;
}

async function captureGowitnessScreenshots(socket, profile, reportBaseName) {
    const startedAt = Date.now();
    const finishPhase = (status, screenshotCount = 0) => {
        const duration = ((Date.now() - startedAt) / 1000).toFixed(2);
        io.emit('phase_complete', { phase: 3, duration, ...getScanStats(), screenshotCount, status });
        return duration;
    };

    currentScanPhase = 3;
    scanStartTime = startedAt;
    io.emit('scan_started', { phase: 3, target: 'Web Services', startTime: scanStartTime, scanKind: currentScanKind });

    if (!GOWITNESS_PATH) {
        logEvent(socket, 'report', 'Phase 3 gowitness skipped: gowitness is not installed.');
        finishPhase('skipped');
        return [];
    }

    const targets = getWebTargetsFromDiscoveredHosts();
    if (!targets.length) {
        logEvent(socket, 'report', 'Phase 3 gowitness skipped: no web services were identified.');
        finishPhase('skipped');
        return [];
    }

    const screenshotDir = path.join(REPORTS_DIR, profile.folderName, 'gowitness', reportBaseName);
    fs.mkdirSync(screenshotDir, { recursive: true });
    logEvent(socket, 'job', `Starting Phase 3 gowitness capture for ${targets.length} web service(s)...`);
    logEvent(socket, 'scan', `gowitness path: ${GOWITNESS_PATH}`);

    const results = [];
    for (const target of targets) {
        const image = await captureGowitnessTarget(target, screenshotDir, reportBaseName);
        if (!image) {
            logEvent(socket, 'error', `gowitness did not capture ${target.url}`);
            continue;
        }
        const encodedFileName = encodeURIComponent(image.file);
        const screenshot = {
            ip: target.ip,
            port: target.port,
            url: target.url,
            fileName: image.file,
            reportSrc: `gowitness/${reportBaseName}/${encodedFileName}`,
            dashboardUrl: `/reports/${profile.folderName}/gowitness/${reportBaseName}/${encodedFileName}`
        };
        results.push(screenshot);
        const host = discoveredHosts.find(item => item.ip === target.ip) || {};
        updateDiscoveredHost(target.ip, {
            screenshots: [...(host.screenshots || []), screenshot],
            screenshotUrl: screenshot.dashboardUrl,
            screenshotTarget: screenshot.url
        });
    }

    if (results.length) {
        fs.writeFileSync(path.join(screenshotDir, 'screenshots.json'), JSON.stringify(results, null, 2));
    }
    const duration = finishPhase('complete', results.length);
    logEvent(socket, 'job', `Phase 3 gowitness complete in ${duration}s. Screenshots: ${results.length}.`);
    return results;
}

function buildGowitnessReportSection(screenshots) {
    if (!screenshots.length) return '';
    const cards = screenshots.map(item => `
                    <article class="gowitness-card">
                        <a href="${escapeHtml(item.reportSrc)}" target="_blank" rel="noopener noreferrer">
                            <img src="${escapeHtml(item.reportSrc)}" alt="Screenshot of ${escapeHtml(item.url)}" />
                        </a>
                        <div>
                            <strong>${escapeHtml(item.ip)}:${escapeHtml(item.port)}</strong>
                            <span>${escapeHtml(item.url)}</span>
                        </div>
                    </article>`).join('');
    return `
            <section class="gowitness-section">
                <h2>Web Service Screenshots</h2>
                <div class="gowitness-grid">${cards}
                </div>
            </section>`;
}

function injectGowitnessReportSection(reportPath, screenshots) {
    const section = buildGowitnessReportSection(screenshots);
    if (!section) return;
    const style = `
        <style>
            .gowitness-section { break-before: page; page-break-before: always; margin: 24px 0; }
            .gowitness-section h2 { margin: 0 0 16px; color: #2f331b; font-size: 22px; }
            .gowitness-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 14px; }
            .gowitness-card { overflow: hidden; border: 1px solid #c8cf9b; border-radius: 8px; background: #fff; }
            .gowitness-card img { display: block; width: 100%; height: 180px; object-fit: cover; background: #eef0df; }
            .gowitness-card div { padding: 10px 12px; font-size: 11px; color: #444827; }
            .gowitness-card strong, .gowitness-card span { display: block; overflow-wrap: anywhere; }
        </style>`;
    let html = fs.readFileSync(reportPath, 'utf8');
    if (!html.includes('.gowitness-section')) {
        html = html.replace('</head>', `${style}\n    </head>`);
    }
    const footerMarker = '        <!-- Footer -->';
    if (html.includes(footerMarker)) {
        html = html.replace(footerMarker, `${section}\n\n${footerMarker}`);
    } else {
        html = html.replace('</body>', `${section}\n</body>`);
    }
    fs.writeFileSync(reportPath, html);
}

function generateReportFromXml(socket, xmlPath, duration, reportScanKind, onComplete = null) {
    const profile = getCustomerFingerprintProfile();
    const networkInfo = cachedNetworkInfo || {};
    const tracerouteSummary = cachedHops.length
        ? cachedHops
            .slice()
            .sort((a, b) => Number(a.hop) - Number(b.hop))
            .map(hop => `${hop.hop}: ${hop.ip}`)
            .join('  ->  ')
        : '';
    const reportDir = path.join(REPORTS_DIR, profile.folderName);
    if (!fs.existsSync(reportDir)) fs.mkdirSync(reportDir, { recursive: true });
    const reportDate = new Date();
    const reportTimestamp = formatReportTimestamp(reportDate);
    const reportDisplayTimestamp = formatReportDisplayTimestamp(reportDate);
    const reportBaseName = `${profile.reportLabel}-${reportTimestamp}`;
    const reportName = `${reportBaseName}.html`;
    const pdfName = `${reportBaseName}.pdf`;
    const xmlName = `${reportBaseName}.xml`;
    const reportPath = path.join(reportDir, reportName);
    const pdfPath = path.join(reportDir, pdfName);
    const xmlArchivePath = path.join(reportDir, xmlName);
    const reportUrl = `/reports/${profile.folderName}/${reportName}`;
    const pdfUrl = `/reports/${profile.folderName}/${pdfName}`;
    const xmlUrl = `/reports/${profile.folderName}/${xmlName}`;
    try {
        fs.copyFileSync(xmlPath, xmlArchivePath);
        logEvent(socket, 'report', `XML archived: ${xmlName}`);
    } catch (error) {
        logEvent(socket, 'error', `XML archive failed for ${xmlName}: ${error.message}`);
    }
    captureGowitnessScreenshots(socket, profile, reportBaseName).catch(error => {
        logEvent(socket, 'error', `gowitness capture failed: ${error.message}`);
        return [];
    }).then((screenshots) => {
        const xslPath = path.join(__dirname, 'nmap-modern.xsl');
        const xsltCommand = [
            'xsltproc',
            '-o', shellQuote(reportPath),
            '--stringparam', 'techmore_version', shellQuote(VERSION),
            '--stringparam', 'customer_name', shellQuote(profile.prefix),
            '--stringparam', 'report_identifier', shellQuote(profile.reportLabel),
            '--stringparam', 'report_timestamp', shellQuote(reportTimestamp),
            '--stringparam', 'report_display_timestamp', shellQuote(reportDisplayTimestamp),
            '--stringparam', 'public_ip', shellQuote(profile.publicIP),
            '--stringparam', 'local_ip', shellQuote(networkInfo.localIP || ''),
            '--stringparam', 'subnet_mask', shellQuote(networkInfo.mask || ''),
            '--stringparam', 'cidr', shellQuote(networkInfo.cidr || ''),
            '--stringparam', 'traceroute_summary', shellQuote(tracerouteSummary),
            shellQuote(xslPath),
            shellQuote(xmlPath)
        ].join(' ');
        exec(xsltCommand, (err) => {
            if (!err) {
                injectGowitnessReportSection(reportPath, screenshots);
                generatePDF(reportPath, pdfPath, (pdfErr) => {
                    const pdfReady = !pdfErr && fs.existsSync(pdfPath);
                    if (pdfErr) {
                        logEvent(socket, 'error', `PDF generation failed for ${reportName}: ${pdfErr.message}`);
                    }
                    logEvent(socket, 'report', `Report generated: ${reportName}${pdfReady ? ` and ${pdfName}` : ''}`);
                    const reportPayload = {
                        url: reportUrl,
                        pdfUrl: pdfReady ? pdfUrl : null,
                        name: reportName,
                        pdfName: pdfReady ? pdfName : null,
                        xmlName,
                        xmlUrl: fs.existsSync(xmlArchivePath) ? xmlUrl : null,
                        customerProfile: profile
                    };
                    io.emit('report_ready', reportPayload);
                    const history = loadJSON(HISTORY_PATH, []);
                    history.unshift({
                        timestamp: new Date().toISOString(),
                        target: currentTarget,
                        duration,
                        hostCount: discoveredHosts.length,
                        reportUrl,
                        pdfUrl: pdfReady ? pdfUrl : null,
                        xmlUrl: fs.existsSync(xmlArchivePath) ? xmlUrl : null,
                        customerProfile: profile
                    });
                    saveJSON(HISTORY_PATH, history.slice(0, 50));
                    if (['complete', 'quick'].includes(reportScanKind)) {
                        const uploadLabel = reportScanKind === 'quick' ? 'Quick Scan report' : 'Complete+PDF report';
                        uploadReportFilesToDrive(socket, [reportPath, pdfReady ? pdfPath : null], profile, {
                            label: uploadLabel,
                            reportPath,
                            dayFolderName: formatDriveDayFolder(reportDate)
                        })
                            .then(result => {
                                if (!result?.success) return;
                                const metadata = loadDriveMetadata(reportPath);
                                io.emit('report_ready', {
                                    ...reportPayload,
                                    driveHtmlUrl: findDriveLink(metadata, reportName),
                                    drivePdfUrl: pdfReady ? findDriveLink(metadata, pdfName) : null
                                });
                            })
                            .catch(error => logEvent(socket, 'error', `Google Drive upload failed for ${uploadLabel}: ${error.message}`));
                    }
                    if (onComplete) onComplete({ success: true, screenshots });
                });
            } else {
                logEvent(socket, 'error', `HTML report generation failed: ${err.message}`);
                if (onComplete) onComplete({ success: false, error: err.message, screenshots });
            }
        });
    });
}

function runNmapFallbackPass(socket, args, phase, xmlFile, label, options = {}) {
    return new Promise((resolve) => {
        const startedAt = Date.now();
        const commandSpec = getPrivilegedCommand(NMAP_PATH, args);
        let stderrBuffer = '';

        currentScanPhase = phase;
        scanStartTime = startedAt;
        io.emit('scan_started', { phase, target: 'Multiple Targets', startTime: scanStartTime, scanKind: options.scanKind || currentScanKind });
        logEvent(socket, 'job', `Starting Phase ${phase} fallback pass: ${label}...`);
        logEvent(socket, 'scan', `Nmap command: sudo -n ${NMAP_PATH} ${args.join(' ')}`);

        const nmap = spawn(commandSpec.command, commandSpec.args);
        currentScan = nmap;

        nmap.stderr.on('data', data => {
            const errText = data.toString();
            stderrBuffer = compactErrorText(`${stderrBuffer}\n${errText}`);
            if (!errText.includes('Warning: ')) console.error('[NMAP ERROR]', errText);
            if (isSudoAuthFailure(errText)) {
                logEvent(socket, 'error', 'Nmap requires passwordless sudo for this runtime. Configure sudoers for nmap or run with the required privileges.');
            }
        });

        nmap.on('error', error => {
            currentScan = null;
            const duration = ((Date.now() - startedAt) / 1000).toFixed(2);
            logEvent(socket, 'error', `Failed to start Phase ${phase} fallback pass: ${error.message}`);
            resolve({ success: false, duration, error: error.message, xmlPath: path.join(__dirname, xmlFile) });
        });

        nmap.on('close', (code, signal) => {
            currentScan = null;
            const duration = ((Date.now() - startedAt) / 1000).toFixed(2);
            const statusText = code === 0 ? 'complete' : `ended with code ${code ?? 'null'}${signal ? `, signal ${signal}` : ''}`;
            const xmlPath = path.join(__dirname, xmlFile);
            const complete = isCompleteNmapXML(xmlPath);
            logEvent(socket, complete ? 'job' : 'error', `Phase ${phase} fallback pass ${statusText} in ${duration}s. XML ${complete ? 'complete' : 'incomplete'}.`);
            io.emit('phase_complete', { phase, duration, ...getScanStats() });
            resolve({
                success: complete,
                duration,
                error: compactErrorText(stderrBuffer || `Phase ${phase} fallback pass ${statusText}. XML ${complete ? 'complete' : 'incomplete'}.`),
                xmlPath
            });
        });
    });
}

async function runPhase2Fallback(socket, originalDuration, reportScanKind) {
    const noScriptXml = 'phase2_no_script.xml';
    const vulnersXml = 'phase2_vulners.xml';
    [noScriptXml, vulnersXml].forEach(file => {
        const filePath = path.join(__dirname, file);
        if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
    });

    logEvent(socket, 'job', 'Starting Phase 2 fallback recovery as two passes: 2.1 service/OS detection, then 2.2 vulners only.');
    const pass21 = await runNmapFallbackPass(socket, [
        '-sS', '-sV', '-O', '-Pn',
        '-T3',
        '--open',
        '-oX', noScriptXml,
        '-iL', 'targets.tmp'
    ], 2.1, noScriptXml, 'service + OS detection without scripts', { scanKind: reportScanKind });
    if (!pass21.success) {
        logEvent(socket, 'error', `Phase 2.1 fallback failed: ${pass21.error}`);
        io.emit('scan_complete', { phase: 2.1, duration: pass21.duration, ...getScanStats(), status: 'failed', error: pass21.error });
        return;
    }

    parseNmapXML(pass21.xmlPath, (parsedStats) => {
        logEvent(socket, 'job', `Phase 2.1 fallback XML parsed. Hosts: ${parsedStats.hostCount}, open ports: ${parsedStats.openPortCount}, critical CVEs: ${parsedStats.criticalCVECount}, LOW CVEs: ${parsedStats.lowCVECount}.`);
        io.emit('phase_stats', { phase: 2.1, ...parsedStats });
    });

    const pass22 = await runNmapFallbackPass(socket, [
        '-sV',
        '--script', 'vulners',
        '--script-args', 'threads=8',
        '-iL', 'targets.tmp',
        '-oX', vulnersXml
    ], 2.2, vulnersXml, 'vulners only', { scanKind: reportScanKind });
    if (!pass22.success) {
        logEvent(socket, 'error', `Phase 2.2 fallback failed: ${pass22.error}`);
        io.emit('scan_complete', { phase: 2.2, duration: pass22.duration, ...getScanStats(), status: 'failed', error: pass22.error });
        return;
    }

    parseNmapXML(pass22.xmlPath, (parsedStats) => {
        logEvent(socket, 'job', `Phase 2.2 fallback XML parsed. Hosts: ${parsedStats.hostCount}, open ports: ${parsedStats.openPortCount}, critical CVEs: ${parsedStats.criticalCVECount}, LOW CVEs: ${parsedStats.lowCVECount}.`);
        io.emit('phase_stats', { phase: 2.2, ...parsedStats });
    });

    const totalDuration = (Number(originalDuration || 0) + Number(pass21.duration || 0) + Number(pass22.duration || 0)).toFixed(2);
    generateReportFromXml(socket, pass22.xmlPath, totalDuration, reportScanKind, () => {
        io.emit('scan_complete', { phase: 3, duration: totalDuration, ...getScanStats(), status: 'fallback_complete' });
    });
}

function runNmap(socket, args, phase = 1, onComplete = null, options = {}) {
    if (currentScan && phase === 1) {
        if (socket) logEvent(socket, 'error', 'A scan is already running.');
        return;
    }
    if (!NMAP_PATH) {
        logEvent(socket, 'error', describeMissingExecutable('nmap', 'NMAP_PATH'));
        return;
    }

    if (phase === 1) {
        discoveredHosts = [];
        // Ensure XML is gone so we don't parse stale data
        const oldXml = path.join(__dirname, 'phase2_results.xml');
        if (fs.existsSync(oldXml)) fs.unlinkSync(oldXml);
    }
    
    currentScanPhase = phase;
    currentTarget = options.targetLabel || (args.includes('-iL') ? 'Multiple Targets' : args[args.length - 1]);
    currentScanKind = options.scanKind || currentScanKind || (phase >= 3 ? 'dragnet' : 'quick');
    scanStartTime = Date.now();
    
    io.emit('scan_started', { phase, target: currentTarget, startTime: scanStartTime, scanKind: currentScanKind });
    logEvent(socket, 'job', `Starting Phase ${phase} scan...`);
    if (phase >= 2) {
        logEvent(socket, 'scan', `Nmap command: sudo -n ${NMAP_PATH} ${args.join(' ')}`);
    }

    const commandSpec = getPrivilegedCommand(NMAP_PATH, args);
    const nmap = spawn(commandSpec.command, commandSpec.args);
    currentScan = nmap;

    let currentHostIP = null;
    let hostBuffer = [];
    let stderrBuffer = '';

    nmap.stdout.on('data', (data) => {
        const text = data.toString();
        const lines = text.split('\n');

        lines.forEach(line => {
            if (line.includes('Nmap scan report for')) {
                if (!options.deferHostUpdates && currentHostIP && hostBuffer.length > 0) processHostBuffer(currentHostIP, hostBuffer);
                const match = line.match(/report for (.*?)(?: \(([0-9.]+)\))?$/);
                if (match) {
                    currentHostIP = match[2] || match[1];
                    hostBuffer = [line];
                    const hostname = match[2] ? match[1] : '';
                    if (!options.deferHostUpdates) {
                        updateDiscoveredHost(currentHostIP, { hostname });
                        io.emit('phase_host_started', { phase, ip: currentHostIP, hostname });
                    }
                    if (phase >= 2 && !options.deferHostUpdates) {
                        logEvent(socket, 'scan', `Phase ${phase} scanning ${currentHostIP}${hostname ? ` (${hostname})` : ''}`);
                    }
                }
            } else if (currentHostIP) {
                hostBuffer.push(line);
                if (line.includes('Host is up')) {
                    const latMatch = line.match(/\(([0-9.]+)s latency\)/);
                    if (!options.deferHostUpdates && latMatch) updateDiscoveredHost(currentHostIP, { latency: (parseFloat(latMatch[1]) * 1000).toFixed(2) + 'ms' });
                }
                if (line.includes('MAC Address:')) {
                    const macMatch = line.match(/MAC Address: ([0-9A-F:]+) \((.*?)\)/);
                    if (!options.deferHostUpdates && macMatch) updateDiscoveredHost(currentHostIP, { mac: macMatch[1], vendor: macMatch[2] });
                }
            }
        });
    });

    nmap.stderr.on('data', (data) => {
        const errText = data.toString();
        stderrBuffer = compactErrorText(`${stderrBuffer}\n${errText}`);
        if (!errText.includes('Warning: ')) console.error('[NMAP ERROR]', errText);
        if (isSudoAuthFailure(errText)) {
            logEvent(socket, 'error', 'Nmap requires passwordless sudo for this runtime. Configure sudoers for nmap or run with the required privileges.');
        }
    });

    nmap.on('error', error => {
        currentScan = null;
        logEvent(socket, 'error', `Failed to start Nmap: ${error.message}`);
    });

    nmap.on('close', (code, signal) => {
        if (!options.deferHostUpdates && currentHostIP && hostBuffer.length > 0) processHostBuffer(currentHostIP, hostBuffer);
        const duration = ((Date.now() - scanStartTime) / 1000).toFixed(2);
        const phaseStats = getScanStats();
        currentScan = null;
        const statusText = code === 0 ? 'complete' : `ended with code ${code ?? 'null'}${signal ? `, signal ${signal}` : ''}`;
        logEvent(socket, code === 0 ? 'job' : 'error', `Phase ${phase} scan ${statusText} in ${duration}s. Hosts: ${phaseStats.hostCount}, open ports: ${phaseStats.openPortCount}, critical CVEs: ${phaseStats.criticalCVECount}.`);
        io.emit('phase_complete', { phase, duration, ...phaseStats });
        
        if (phase >= 2) {
            const xmlPath = path.join(__dirname, 'phase2_results.xml');
            const reportScanKind = options.scanKind || currentScanKind;
            setTimeout(() => {
                if (!isCompleteNmapXML(xmlPath)) {
                    const failureError = compactErrorText(stderrBuffer || `Phase ${phase} scan ${statusText}. XML output was incomplete.`);
                    logEvent(socket, 'error', 'Phase 2 XML is incomplete, likely because Nmap/NSE crashed. Recording this run as failed so it remains visible in history and reports.');
                    saveFailedScanHistory({
                        target: currentTarget,
                        duration,
                        hostCount: phaseStats.hostCount,
                        scanKind: reportScanKind,
                        customerProfile: getCustomerFingerprintProfile(),
                        error: failureError
                    });
                    if (options.fallbackOnIncomplete) {
                        runPhase2Fallback(socket, duration, reportScanKind).catch(error => {
                            logEvent(socket, 'error', `Phase 2 fallback recovery failed: ${error.message}`);
                            io.emit('scan_complete', { phase, duration, ...phaseStats, status: 'failed', error: error.message });
                        });
                        return;
                    }
                    io.emit('scan_complete', { phase, duration, ...phaseStats, status: 'failed', error: failureError });
                    return;
                }
                parseNmapXML(xmlPath, (parsedStats) => {
                    logEvent(socket, 'job', `Phase ${phase} XML results parsed. Hosts: ${parsedStats.hostCount}, open ports: ${parsedStats.openPortCount}, critical CVEs: ${parsedStats.criticalCVECount}, LOW CVEs: ${parsedStats.lowCVECount}.`);
                    io.emit('phase_stats', { phase, ...parsedStats });
                });
                generateReportFromXml(socket, xmlPath, duration, reportScanKind, () => {
                    if (options.deferScanComplete) io.emit('scan_complete', { phase: 3, duration, ...getScanStats() });
                });
            }, 1000);
        }
        if (onComplete) onComplete();
        else if (!options.deferScanComplete) io.emit('scan_complete', { phase, duration, ...phaseStats });
    });
}

function processHostBuffer(ip, buffer) {
    const text = buffer.join('\n');
    const updates = {};
    const osMatch = text.match(/OS details: (.*)/);
    if (osMatch) updates.os = osMatch[1];
    
    const ports = [];
    const versions = [];
    const portLines = text.match(/^\d+\/\w+\s+open\s+(.*)/gm);
    if (portLines) {
        portLines.forEach(line => {
            const pMatch = line.match(/^(\d+)\/\w+\s+open\s+(.*)/);
            if (pMatch) {
                ports.push(pMatch[1]);
                if (pMatch[2].trim()) versions.push(`${pMatch[1]}:${pMatch[2].trim()}`);
            }
        });
        updates.ports = ports.join(', ');
        if (versions.length > 0) updates.version = versions.join(' | ');
    }

    const highCVEs = new Map();
    const lowCVEs = new Set();
    text.split('\n').forEach(line => {
        const cveMatch = line.match(/\b(CVE-\d{4}-\d+)\b\s+([0-9]+(?:\.[0-9]+)?)/i);
        if (!cveMatch) return;

        const cveId = cveMatch[1].toUpperCase();
        const score = parseFloat(cveMatch[2]);
        if (Number.isNaN(score)) return;

        if (score >= 7.0) {
            highCVEs.set(cveId, `${cveId}(${score})`);
        } else {
            lowCVEs.add(cveId);
        }
    });

    if (highCVEs.size > 0) updates.highCVEs = Array.from(highCVEs.values()).join(', ');
    if (lowCVEs.size > 0) updates.lowCVECount = lowCVEs.size;

    if (Object.keys(updates).length > 0) updateDiscoveredHost(ip, updates);
}

function updateDiscoveredHost(ip, data) {
    let host = discoveredHosts.find(h => h.ip === ip);
    if (!host) {
        host = { ip, status: 'up', ...data };
        discoveredHosts.push(host);
    } else {
        Object.assign(host, data);
    }
    io.emit('discovery_update', host);
}

function getScanStats() {
    const openPortCount = discoveredHosts.reduce((total, host) => {
        if (!host.ports) return total;
        return total + String(host.ports).split(',').map(port => port.trim()).filter(Boolean).length;
    }, 0);
    const criticalCVECount = discoveredHosts.reduce((total, host) => {
        if (!host.highCVEs) return total;
        return total + String(host.highCVEs).split(',').map(cve => cve.trim()).filter(Boolean).length;
    }, 0);
    const lowCVECount = discoveredHosts.reduce((total, host) => total + Number(host.lowCVECount || 0), 0);

    return {
        hostCount: discoveredHosts.length,
        openPortCount,
        criticalCVECount,
        lowCVECount
    };
}

function startChainedScan(socket, target, usePn = false, options = {}) {
    const scanKind = usePn ? 'complete' : 'quick';
    const targets = parseTargetInput(target);
    if (targets.length === 0) {
        logEvent(socket, 'error', 'No scan target provided.');
        return;
    }
    const targetLabel = formatTargetLabel(targets);
    runNmap(socket, ['-sn', '-T4', ...targets], 1, () => {
        if (discoveredHosts.length === 0) {
            logEvent(socket, 'error', 'No hosts found in Phase 1. Stopping.');
            return;
        }
        const discoveredTargets = discoveredHosts.map(h => h.ip).join('\n');
        fs.writeFileSync('targets.tmp', discoveredTargets);

        if (usePn) {
            const vpnHelper = !!options.vpnHelper;
            const phase2Options = vpnHelper
                ? {
                    includeDefaultScripts: false,
                    minRate: false,
                    timing: '-T2',
                    scriptArgs: 'mincvss=0,threads=5',
                    maxParallelism: 15,
                    maxRetries: 2
                }
                : {
                    includeDefaultScripts: false,
                    minRate: false
                };
            logEvent(socket, 'job', `Complete+PDF Phase 2 scanning all ${discoveredHosts.length} host(s) in one Nmap command with vulners${vpnHelper ? ' using VPN helper timing' : ''}. UI details will populate after XML parsing completes.`);
            runNmap(
                socket,
                buildPhase2Args(true, false, phase2Options),
                2,
                null,
                { deferHostUpdates: true, scanKind, fallbackOnIncomplete: true, deferScanComplete: true }
            );
            return;
        }

        runNmap(socket, buildPhase2Args(false), 2, null, { scanKind });
    }, { scanKind, targetLabel });
}

io.on('connection', (socket) => {
    socket.emit('sync_state', { version: VERSION, hosts: discoveredHosts, isScanning: !!currentScan, phase: currentScanPhase, target: currentTarget, startTime: scanStartTime, scanKind: currentScanKind, hops: cachedHops, customerProfile: getCustomerFingerprintProfile(), autoScan: appConfig.autoScan || {} });
    socket.on('get_initial_data', async () => {
        const network = cachedNetworkInfo || await getNetworkInfo();
        const publicIP = cachedPublicIP || await getPublicIP();
        socket.emit('initial_data', { ...network, publicIP, customerProfile: getCustomerFingerprintProfile(), googleDrive: appConfig.googleDrive || {}, autoScan: appConfig.autoScan || {} });
        if (cachedHops.length === 0 && !isTracerouteRunning) runTraceroute();
        cachedHops.forEach(hop => socket.emit('traceroute_hop', hop));
    });
    socket.on('start_quick_scan', (data) => startChainedScan(socket, data.target, false));
    socket.on('start_complete_scan', (data) => startChainedScan(socket, data.target, true, { vpnHelper: !!data.vpnHelper }));
    socket.on('start_dragnet_scan', (data) => {
        if (discoveredHosts.length === 0) { logEvent(socket, 'error', 'No hosts discovered in Phase 1.'); return; }
        const targets = discoveredHosts.map(h => h.ip).join('\n');
        fs.writeFileSync('targets.tmp', targets);
        runNmap(socket, buildPhase2Args(true, true), 3, null, { scanKind: 'dragnet' });
    });
    socket.on('stop_scan', () => { if (currentScan) currentScan.kill(); });
    socket.on('enable_auto_scan', (data = {}) => {
        const autoScan = saveAutoScanConfig({
            enabled: true,
            recurrence: ['hourly', 'daily', 'weekly', 'monthly'].includes(data.recurrence) ? data.recurrence : 'daily',
            startTime: data.startTime || '01:00',
            target: data.target || cachedNetworkInfo?.cidr || '192.168.1.0/24'
        });
        logEvent(socket, 'settings', `Auto-monitor enabled: ${autoScan.recurrence} at ${autoScan.startTime} for ${autoScan.target}.`);
        io.emit('auto_scan_config', autoScan);
    });
    socket.on('disable_auto_scan', () => {
        const autoScan = saveAutoScanConfig({ enabled: false });
        logEvent(socket, 'settings', 'Auto-monitor disabled.');
        io.emit('auto_scan_config', autoScan);
    });
    socket.on('get_history', () => socket.emit('history_data', loadJSON(HISTORY_PATH, [])));
    socket.on('get_customer_profile', () => socket.emit('customer_profile', getCustomerFingerprintProfile()));
    socket.on('get_google_drive_status', async () => {
        const status = await runGoogleDriveHelper(['status']);
        if (status.connected && !getGoogleDriveConfig().enabled) {
            saveGoogleDriveConfig({ enabled: true });
            logEvent(socket, 'settings', 'Google Drive connection found; sync enabled on server.');
        }
        socket.emit('google_drive_status', { ...status, config: getGoogleDriveConfig() });
    });
    socket.on('save_google_drive_credentials', async (data = {}) => {
        const result = await runGoogleDriveHelper(['save-credentials'], data.credentialsJson || '');
        const googleDrive = result.success ? saveGoogleDriveConfig({ enabled: true }) : getGoogleDriveConfig();
        if (result.success) logEvent(socket, 'settings', 'Google Drive credentials imported and sync enabled.');
        socket.emit('google_drive_status', { ...result, config: googleDrive });
    });
    socket.on('connect_google_drive', async () => {
        const result = await runGoogleDriveHelper(['auth-url', '--redirect-uri', getGoogleDriveRedirectUri()]);
        socket.emit('google_drive_auth_url', result);
    });
    socket.on('disconnect_google_drive', async () => {
        const result = await runGoogleDriveHelper(['disconnect']);
        const googleDrive = saveGoogleDriveConfig({ enabled: false });
        if (result.success) logEvent(socket, 'settings', 'Google Drive disconnected and sync disabled.');
        socket.emit('google_drive_status', { ...result, config: googleDrive });
    });
    socket.on('save_google_drive_settings', (data = {}) => {
        const googleDrive = saveGoogleDriveConfig({
            enabled: !!data.enabled,
            folderId: data.folderId || ''
        });
        socket.emit('google_drive_status', { success: true, status: 'Google Drive settings saved', config: googleDrive });
    });
    socket.on('set_customer_profile_prefix', (data = {}) => {
        saveCustomerProfileConfig({ ...customerProfileConfig, prefix: data.prefix || 'CSP' });
        const profile = getCustomerFingerprintProfile();
        logEvent(socket, 'settings', `Customer fingerprint prefix set to ${profile.prefix}.`);
        io.emit('customer_profile', profile);
    });
    socket.on('get_reports', () => {
        const reports = [];
        const history = loadJSON(HISTORY_PATH, []);
        const historyByReportUrl = new Map(
            history
                .filter(entry => entry?.reportUrl)
                .map(entry => [entry.reportUrl, entry])
        );
        if (fs.existsSync(REPORTS_DIR)) {
            fs.readdirSync(REPORTS_DIR, { withFileTypes: true }).forEach(entry => {
                const folder = entry.isDirectory() ? entry.name : '';
                const folderPath = folder ? path.join(REPORTS_DIR, folder) : REPORTS_DIR;
                if (!entry.isDirectory() && !entry.name.endsWith('.html')) return;
                const files = entry.isDirectory()
                    ? fs.readdirSync(folderPath).filter(f => f.endsWith('.html'))
                    : [entry.name];
                files.forEach(f => {
                    const pdfName = f.replace(/\.html$/i, '.pdf');
                    const xmlName = f.replace(/\.html$/i, '.xml');
                    const reportPath = path.join(folderPath, f);
                    const pdfPath = path.join(folderPath, pdfName);
                    const xmlPath = path.join(folderPath, xmlName);
                    const driveMetadata = loadDriveMetadata(reportPath);
                    const urlBase = folder ? `/reports/${folder}` : '/reports';
                    const reportUrl = `${urlBase}/${f}`;
                    const historyEntry = historyByReportUrl.get(reportUrl);
                    const fileMtime = fs.statSync(reportPath).mtime;
                    reports.push({
                        name: f,
                        folder,
                        url: reportUrl,
                        pdfName: fs.existsSync(pdfPath) ? pdfName : null,
                        pdfUrl: fs.existsSync(pdfPath) ? `${urlBase}/${pdfName}` : null,
                        xmlName: fs.existsSync(xmlPath) ? xmlName : null,
                        xmlUrl: fs.existsSync(xmlPath) ? `${urlBase}/${xmlName}` : null,
                        driveHtmlUrl: findDriveLink(driveMetadata, f),
                        drivePdfUrl: fs.existsSync(pdfPath) ? findDriveLink(driveMetadata, pdfName) : null,
                        date: historyEntry?.timestamp || fileMtime,
                        duration: historyEntry?.duration || null,
                        hostCount: historyEntry?.hostCount || null
                    });
                });
            });
        }
        history
            .filter(entry => entry && entry.status === 'failed')
            .forEach(entry => {
                const date = entry.timestamp || new Date().toISOString();
                const scanLabel = entry.scanKind === 'complete' ? 'Complete+PDF' : (entry.scanKind || 'Scan');
                reports.push({
                    name: `Failed ${scanLabel} scan - ${new Date(date).toLocaleString()}`,
                    folder: entry.customerProfile?.folderName || '',
                    url: null,
                    pdfName: null,
                    pdfUrl: null,
                    driveHtmlUrl: null,
                    drivePdfUrl: null,
                    date,
                    status: 'failed',
                    error: entry.error || 'Nmap scan failed before a complete XML report was written.',
                    hostCount: entry.hostCount,
                    duration: entry.duration
                });
            });
        socket.emit('reports_data', reports.sort((a, b) => new Date(b.date) - new Date(a.date)));
    });
});

// Initialization
updateNmapFromHomebrew().finally(updateNmapScriptDatabase);

setupAutoScan(loadJSON(CONFIG_PATH, {}));
getNetworkInfo(); getPublicIP(); runTraceroute();

function listenWithPortGuard(retried = false) {
    server.once('error', async error => {
        if (error.code !== 'EADDRINUSE' || retried) {
            console.error(`Failed to start server on port ${PORT}: ${error.message}`);
            process.exit(1);
        }
        const stopped = await stopExistingAppOnPort(PORT);
        if (!stopped) {
            console.error(`Port ${PORT} is already in use by another service. Stop it or set PORT to a different value.`);
            process.exit(1);
        }
        listenWithPortGuard(true);
    });
    server.listen(PORT);
}

server.on('listening', () => console.log(`${VERSION} Server running on http://localhost:${PORT}`));
listenWithPortGuard();
