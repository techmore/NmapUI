function createRuntimeStateSnapshot(deps) {
    function getCustomerFingerprintProfile() {
        if (deps.cachedCustomerProfile()?.folderName && deps.cachedCustomerProfile()?.reportLabel) {
            return deps.cachedCustomerProfile();
        }
        const publicIP = deps.cachedPublicIP() && deps.cachedPublicIP() !== 'Unknown' ? deps.cachedPublicIP() : 'unknown_wan';
        const topology = deps.getTopologyFingerprintParts();
        const helperResult = deps.runRuntimeReportHelper([
            'customer-profile',
            '--payload', JSON.stringify({
                prefix: deps.customerProfileConfig().prefix || 'CSP',
                publicIP,
                topology
            })
        ]);
        const fallback = {
            prefix: deps.sanitizeReportSegment(deps.customerProfileConfig().prefix || 'CSP', 'CSP'),
            publicIP,
            wan: deps.sanitizeReportSegment(publicIP, 'unknown_wan'),
            fingerprint: deps.createFingerprint(publicIP, topology),
            baseName: `${deps.sanitizeReportSegment(deps.customerProfileConfig().prefix || 'CSP', 'CSP')}_${deps.sanitizeReportSegment(publicIP, 'unknown_wan')}`,
            reportLabel: `${deps.sanitizeReportSegment(deps.customerProfileConfig().prefix || 'CSP', 'CSP')}_(${deps.sanitizeReportSegment(publicIP, 'unknown_wan')})`,
            folderName: `${deps.sanitizeReportSegment(deps.customerProfileConfig().prefix || 'CSP', 'CSP')}_${deps.sanitizeReportSegment(publicIP, 'unknown_wan')}_${deps.createFingerprint(publicIP, topology)}`,
            topology
        };
        const profile = helperResult?.folderName ? helperResult : fallback;
        deps.setCachedCustomerProfile(profile);
        return profile;
    }

    function getRuntimeBootstrapSnapshot() {
        const helperResult = deps.runRuntimeReportHelper([
            'bootstrap-snapshot',
            '--prefix', deps.customerProfileConfig().prefix || 'CSP',
            '--topology', JSON.stringify(deps.getTopologyFingerprintParts()),
            '--google-drive', JSON.stringify(deps.appConfig().googleDrive || {}),
            '--auto-scan', JSON.stringify(deps.appConfig().autoScan || {})
        ]);
        if (helperResult?.network && helperResult?.customerProfile) {
            return {
                network: helperResult.network,
                publicIP: helperResult.publicIP || deps.cachedPublicIP() || 'Unknown',
                customerProfile: helperResult.customerProfile,
                googleDrive: deps.appConfig().googleDrive || {},
                autoScan: deps.appConfig().autoScan || {}
            };
        }
        const network = deps.cachedNetworkInfo() || {};
        const customerProfile = getCustomerFingerprintProfile();
        return {
            network,
            publicIP: deps.cachedPublicIP() || network.publicIP || 'Unknown',
            customerProfile,
            googleDrive: deps.appConfig().googleDrive || {},
            autoScan: deps.appConfig().autoScan || {}
        };
    }

    function buildReportListEntry({
        name,
        folder,
        url,
        pdfName,
        pdfUrl,
        xmlName,
        xmlUrl,
        driveHtmlUrl,
        drivePdfUrl,
        date,
        duration,
        hostCount,
        status = null,
        error = null
    }) {
        const helperResult = deps.runRuntimeReportHelper([
            'report-list-entry',
            '--name', String(name || ''),
            '--folder', String(folder || ''),
            '--url', String(url || ''),
            '--pdf-name', String(pdfName || ''),
            '--pdf-url', String(pdfUrl || ''),
            '--xml-name', String(xmlName || ''),
            '--xml-url', String(xmlUrl || ''),
            '--drive-html-url', String(driveHtmlUrl || ''),
            '--drive-pdf-url', String(drivePdfUrl || ''),
            '--date', String(date || new Date().toISOString()),
            '--duration', String(duration || ''),
            '--host-count', String(hostCount || ''),
            '--status', String(status || ''),
            '--error', String(error || '')
        ]);
        if (helperResult?.name) return helperResult;
        return {
            name,
            folder,
            url,
            pdfName,
            pdfUrl,
            xmlName,
            xmlUrl,
            driveHtmlUrl,
            drivePdfUrl,
            date: new Date(date).toISOString(),
            duration,
            hostCount,
            status,
            error
        };
    }

    function buildReportsSnapshot() {
        const helperSnapshot = deps.runRuntimeReportHelper(['snapshot', '--reports-dir', deps.reportsDir(), '--history-path', deps.historyPath()]);
        if (helperSnapshot?.reports) return helperSnapshot;

        const reports = [];
        const history = deps.loadJSON(deps.historyPath(), []);
        const historyByReportUrl = new Map(
            history
                .filter(entry => entry?.reportUrl)
                .map(entry => [entry.reportUrl, entry])
        );
        if (deps.fs().existsSync(deps.reportsDir())) {
            deps.fs().readdirSync(deps.reportsDir(), { withFileTypes: true }).forEach(entry => {
                const folder = entry.isDirectory() ? entry.name : '';
                const folderPath = folder ? deps.path().join(deps.reportsDir(), folder) : deps.reportsDir();
                if (!entry.isDirectory() && !entry.name.endsWith('.html')) return;
                const files = entry.isDirectory()
                    ? deps.fs().readdirSync(folderPath).filter(f => f.endsWith('.html'))
                    : [entry.name];
                files.forEach(f => {
                    const pdfName = f.replace(/\.html$/i, '.pdf');
                    const xmlName = f.replace(/\.html$/i, '.xml');
                    const reportPath = deps.path().join(folderPath, f);
                    const pdfPath = deps.path().join(folderPath, pdfName);
                    const xmlPath = deps.path().join(folderPath, xmlName);
                    const driveMetadata = deps.loadDriveMetadata(reportPath);
                    const urlBase = folder ? `/reports/${folder}` : '/reports';
                    const reportUrl = `${urlBase}/${f}`;
                    const historyEntry = historyByReportUrl.get(reportUrl);
                    const fileMtime = deps.fs().statSync(reportPath).mtime;
                    reports.push(buildReportListEntry({
                        name: f,
                        folder,
                        url: reportUrl,
                        pdfName: deps.fs().existsSync(pdfPath) ? pdfName : null,
                        pdfUrl: deps.fs().existsSync(pdfPath) ? `${urlBase}/${pdfName}` : null,
                        xmlName: deps.fs().existsSync(xmlPath) ? xmlName : null,
                        xmlUrl: deps.fs().existsSync(xmlPath) ? `${urlBase}/${xmlName}` : null,
                        driveHtmlUrl: deps.findDriveLink(driveMetadata, f),
                        drivePdfUrl: deps.fs().existsSync(pdfPath) ? deps.findDriveLink(driveMetadata, pdfName) : null,
                        date: historyEntry?.timestamp || fileMtime,
                        duration: historyEntry?.duration || null,
                        hostCount: historyEntry?.hostCount || null
                    }));
                });
            });
        }
        history
            .filter(entry => entry && entry.status === 'failed')
            .forEach(entry => {
                const date = entry.timestamp;
                const scanLabel = entry.scanKind === 'complete' ? 'Complete+PDF' : (entry.scanKind.isEmpty ? 'Scan' : entry.scanKind);
                reports.push(buildReportListEntry({
                    name: `Failed ${scanLabel} scan - ${date}`,
                    folder: entry.customerProfile?.folderName ?? '',
                    url: null,
                    pdfName: null,
                    pdfUrl: null,
                    xmlName: null,
                    xmlUrl: null,
                    driveHtmlUrl: null,
                    drivePdfUrl: null,
                    date,
                    duration: entry.duration,
                    hostCount: entry.hostCount,
                    status: 'failed',
                    error: entry.error
                }));
            });

        return {
            generatedAt: new Date().toISOString(),
            reports: reports.sort((a, b) => new Date(b.date) - new Date(a.date))
        };
    }

    return {
        getCustomerFingerprintProfile,
        getRuntimeBootstrapSnapshot,
        buildReportListEntry,
        buildReportsSnapshot,
    };
}

module.exports = {
    createRuntimeStateSnapshot,
};
