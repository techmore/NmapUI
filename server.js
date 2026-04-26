const express = require('express');
const http = require('http');
const { Server } = require("socket.io");
const { spawn, exec } = require('child_process');
const path = require('path');
const fs = require('fs');
const cron = require('node-cron');
const axios = require('axios');
const xml2js = require('xml2js');
const crypto = require('crypto');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = process.env.PORT || 9000;

app.use(express.static(path.join(__dirname)));
app.use('/static', express.static(path.join(__dirname, 'static')));
app.use('/reports', express.static(path.join(__dirname, 'reports_archive')));

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
        res.send('<html><body><h1>Google Drive connected</h1><p>You can close this window and return to Gemini Nmap.</p></body></html>');
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
const PHASE2_MAX_HOSTGROUP = String(Math.max(1, parseInt(process.env.NMAP_MAX_HOSTGROUP || '4', 10) || 4));
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

function shellQuote(value) {
    return `'${String(value).replace(/'/g, `'\\''`)}'`;
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
        '--orientation', 'Landscape',
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

    const folderName = profile?.folderName ? `Gemini Nmap Reports/${profile.folderName}` : 'Gemini Nmap Reports';
    const args = ['upload', '--folder-name', folderName, '--files', ...existingFiles];
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
    const hostGroupArgs = options.allHostsAtOnce
        ? []
        : ['--min-hostgroup', '1', '--max-hostgroup', PHASE2_MAX_HOSTGROUP];
    const scripts = options.consolidateScripts ? ['default,vulners'] : ['vulners'];
    const rateArgs = options.minRate === false ? [] : ['--min-rate', options.minRate || '3000'];
    const defaultScriptArgs = options.includeDefaultScripts === false || options.consolidateScripts ? [] : ['-sC'];
    const args = [
        ...(fullPortScan ? ['-p-'] : []),
        '-sS', '-sV',
        ...defaultScriptArgs,
        '-O',
        ...(usePn ? ['-Pn'] : []),
        '-T4',
        ...rateArgs,
        ...(options.maxParallelism ? ['--max-parallelism', String(options.maxParallelism)] : []),
        ...hostGroupArgs,
        '--open',
        '--script', scripts.join(','),
        '--stylesheet', 'nmap-modern.xsl',
        '-oX', 'phase2_results.xml',
        '-iL', 'targets.tmp'
    ];
    return args;
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
    isTracerouteRunning = true;
    cachedHops = [];
    const traceroute = spawn('traceroute', ['-m', '15', '-n', '-q', '1', '8.8.8.8']);
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

function runNmap(socket, args, phase = 1, onComplete = null, options = {}) {
    if (currentScan && phase === 1) {
        if (socket) logEvent(socket, 'error', 'A scan is already running.');
        return;
    }

    if (phase === 1) {
        discoveredHosts = [];
        // Ensure XML is gone so we don't parse stale data
        const oldXml = path.join(__dirname, 'phase2_results.xml');
        if (fs.existsSync(oldXml)) fs.unlinkSync(oldXml);
    }
    
    currentScanPhase = phase;
    currentTarget = args.includes('-iL') ? 'Multiple Targets' : args[args.length - 1];
    currentScanKind = options.scanKind || currentScanKind || (phase >= 3 ? 'dragnet' : 'quick');
    scanStartTime = Date.now();
    
    io.emit('scan_started', { phase, target: currentTarget, startTime: scanStartTime, scanKind: currentScanKind });
    logEvent(socket, 'job', `Starting Phase ${phase} scan...`);
    if (phase >= 2) {
        logEvent(socket, 'scan', `Nmap command: sudo nmap ${args.join(' ')}`);
    }
    
    const nmap = spawn('sudo', ['nmap', ...args]);
    currentScan = nmap;

    let currentHostIP = null;
    let hostBuffer = [];

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
        if (!errText.includes('Warning: ')) console.error('[NMAP ERROR]', errText);
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
                    logEvent(socket, 'error', 'Phase 2 XML is incomplete, likely because Nmap/NSE crashed. Skipping XML parse and report/PDF generation for this run.');
                    return;
                }
                parseNmapXML(xmlPath, (parsedStats) => {
                    logEvent(socket, 'job', `Phase ${phase} XML results parsed. Hosts: ${parsedStats.hostCount}, open ports: ${parsedStats.openPortCount}, critical CVEs: ${parsedStats.criticalCVECount}, LOW CVEs: ${parsedStats.lowCVECount}.`);
                    io.emit('phase_stats', { phase, ...parsedStats });
                });
                const profile = getCustomerFingerprintProfile();
                const reportDir = path.join(REPORTS_DIR, profile.folderName);
                if (!fs.existsSync(reportDir)) fs.mkdirSync(reportDir, { recursive: true });
                const reportDate = new Date();
                const reportTimestamp = formatReportTimestamp(reportDate);
                const reportDisplayTimestamp = formatReportDisplayTimestamp(reportDate);
                const reportBaseName = `${profile.reportLabel}-${reportTimestamp}`;
                const reportName = `${reportBaseName}.html`;
                const pdfName = `${reportBaseName}.pdf`;
                const reportPath = path.join(reportDir, reportName);
                const pdfPath = path.join(reportDir, pdfName);
                const reportUrl = `/reports/${profile.folderName}/${reportName}`;
                const pdfUrl = `/reports/${profile.folderName}/${pdfName}`;
                const xslPath = path.join(__dirname, 'nmap-modern.xsl');
                const xsltCommand = [
                    'xsltproc',
                    '-o', shellQuote(reportPath),
                    '--stringparam', 'customer_name', shellQuote(profile.prefix),
                    '--stringparam', 'report_identifier', shellQuote(profile.reportLabel),
                    '--stringparam', 'report_timestamp', shellQuote(reportTimestamp),
                    '--stringparam', 'report_display_timestamp', shellQuote(reportDisplayTimestamp),
                    '--stringparam', 'public_ip', shellQuote(profile.publicIP),
                    shellQuote(xslPath),
                    shellQuote(xmlPath)
                ].join(' ');
                exec(xsltCommand, (err) => {
                    if (!err) {
                        generatePDF(reportPath, pdfPath, (pdfErr) => {
                            const pdfReady = !pdfErr && fs.existsSync(pdfPath);
                            if (pdfErr) {
                                logEvent(socket, 'error', `PDF generation failed for ${reportName}: ${pdfErr.message}`);
                            }
                            logEvent(socket, 'report', `Report generated: ${reportName}${pdfReady ? ` and ${pdfName}` : ''}`);
                            io.emit('report_ready', {
                                url: reportUrl,
                                pdfUrl: pdfReady ? pdfUrl : null,
                                name: reportName,
                                pdfName: pdfReady ? pdfName : null,
                                customerProfile: profile
                            });
                            const history = loadJSON(HISTORY_PATH, []);
                            history.unshift({
                                timestamp: new Date().toISOString(),
                                target: currentTarget,
                                duration,
                                hostCount: discoveredHosts.length,
                                reportUrl,
                                pdfUrl: pdfReady ? pdfUrl : null,
                                customerProfile: profile
                            });
                            saveJSON(HISTORY_PATH, history.slice(0, 50));
                            if (['complete', 'quick'].includes(reportScanKind)) {
                                const uploadLabel = reportScanKind === 'quick' ? 'Quick Scan report' : 'Complete+PDF report';
                                uploadReportFilesToDrive(socket, [reportPath, pdfReady ? pdfPath : null], profile, { label: uploadLabel })
                                    .catch(error => logEvent(socket, 'error', `Google Drive upload failed for ${uploadLabel}: ${error.message}`));
                            }
                        });
                    } else {
                        logEvent(socket, 'error', `HTML report generation failed: ${err.message}`);
                    }
                });
            }, 1000);
        }
        if (onComplete) onComplete();
        else io.emit('scan_complete', { phase, duration, ...phaseStats });
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

function startChainedScan(socket, target, usePn = false) {
    const scanKind = usePn ? 'complete' : 'quick';
    runNmap(socket, ['-sn', '-T4', target], 1, () => {
        if (discoveredHosts.length === 0) {
            logEvent(socket, 'error', 'No hosts found in Phase 1. Stopping.');
            return;
        }
        const targets = discoveredHosts.map(h => h.ip).join('\n');
        fs.writeFileSync('targets.tmp', targets);

        if (usePn) {
            logEvent(socket, 'job', `Complete+PDF Phase 2 scanning all ${discoveredHosts.length} host(s) in one Nmap command with vulners. UI details will populate after XML parsing completes.`);
            runNmap(
                socket,
                buildPhase2Args(true, false, {
                    allHostsAtOnce: true,
                    includeDefaultScripts: false,
                    minRate: false
                }),
                2,
                null,
                { deferHostUpdates: true, scanKind }
            );
            return;
        }

        runNmap(socket, buildPhase2Args(false), 2, null, { scanKind });
    }, { scanKind });
}

io.on('connection', (socket) => {
    socket.emit('sync_state', { hosts: discoveredHosts, isScanning: !!currentScan, phase: currentScanPhase, target: currentTarget, startTime: scanStartTime, scanKind: currentScanKind, hops: cachedHops, customerProfile: getCustomerFingerprintProfile(), autoScan: appConfig.autoScan || {} });
    socket.on('get_initial_data', async () => {
        const network = cachedNetworkInfo || await getNetworkInfo();
        const publicIP = cachedPublicIP || await getPublicIP();
        socket.emit('initial_data', { ...network, publicIP, customerProfile: getCustomerFingerprintProfile(), googleDrive: appConfig.googleDrive || {}, autoScan: appConfig.autoScan || {} });
        cachedHops.forEach(hop => socket.emit('traceroute_hop', hop));
    });
    socket.on('start_quick_scan', (data) => startChainedScan(socket, data.target, false));
    socket.on('start_complete_scan', (data) => startChainedScan(socket, data.target, true));
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
        if (!fs.existsSync(REPORTS_DIR)) return;
        const reports = [];
        fs.readdirSync(REPORTS_DIR, { withFileTypes: true }).forEach(entry => {
            const folder = entry.isDirectory() ? entry.name : '';
            const folderPath = folder ? path.join(REPORTS_DIR, folder) : REPORTS_DIR;
            if (!entry.isDirectory() && !entry.name.endsWith('.html')) return;
            const files = entry.isDirectory()
                ? fs.readdirSync(folderPath).filter(f => f.endsWith('.html'))
                : [entry.name];
            files.forEach(f => {
                const pdfName = f.replace(/\.html$/i, '.pdf');
                const pdfPath = path.join(folderPath, pdfName);
                const urlBase = folder ? `/reports/${folder}` : '/reports';
                reports.push({
                    name: f,
                    folder,
                    url: `${urlBase}/${f}`,
                    pdfName: fs.existsSync(pdfPath) ? pdfName : null,
                    pdfUrl: fs.existsSync(pdfPath) ? `${urlBase}/${pdfName}` : null,
                    date: fs.statSync(path.join(folderPath, f)).mtime
                });
            });
        });
        socket.emit('reports_data', reports.sort((a, b) => new Date(b.date) - new Date(a.date)));
    });
});

// Initialization
console.log('Prescan - Updating scripts...');
exec('sudo nmap --script-updatedb');

setupAutoScan(loadJSON(CONFIG_PATH, {}));
getNetworkInfo(); getPublicIP(); runTraceroute();
server.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
