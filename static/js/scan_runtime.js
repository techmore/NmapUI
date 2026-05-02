function isPrivateIP(ip) {
    const parts = ip.split('.').map(Number);
    if (parts[0] === 10) return true;
    if (parts[0] === 172 && (parts[1] >= 16 && parts[1] <= 31)) return true;
    if (parts[0] === 192 && parts[1] === 168) return true;
    return false;
}

let activeScanPhase = null;
let activePhaseStartedAt = null;
let activePhaseTimer = null;
let activeScanKind = null;

function setText(id, value) {
    const el = document.getElementById(id);
    if (el) el.textContent = value;
}

function formatDurationSeconds(totalSeconds) {
    const seconds = Math.max(0, Math.floor(Number(totalSeconds) || 0));
    const h = String(Math.floor(seconds / 3600)).padStart(2, '0');
    const m = String(Math.floor((seconds % 3600) / 60)).padStart(2, '0');
    const s = String(seconds % 60).padStart(2, '0');
    return `${h}:${m}:${s}`;
}

function startPhaseTimer(phase, startedAt) {
    activeScanPhase = phase;
    activePhaseStartedAt = startedAt ? new Date(startedAt).getTime() : Date.now();
    if (activePhaseTimer) clearInterval(activePhaseTimer);

    const targetId = phase === 1 ? 'quick-time' : 'deep-time';
    const tick = () => setText(targetId, formatDurationSeconds((Date.now() - activePhaseStartedAt) / 1000));
    tick();
    activePhaseTimer = setInterval(tick, 1000);
}

function stopPhaseTimer(phase, duration) {
    if (activePhaseTimer && activeScanPhase === phase) {
        clearInterval(activePhaseTimer);
        activePhaseTimer = null;
        activeScanPhase = null;
        activePhaseStartedAt = null;
    }
    setText(phase === 1 ? 'quick-time' : 'deep-time', formatDurationSeconds(duration));
}

function getHighCVEList(data) {
    if (Array.isArray(data.highCVEs)) return data.highCVEs.filter(Boolean);
    if (typeof data.highCVEs !== 'string' || !data.highCVEs.trim()) return [];
    return data.highCVEs.split(',').map(item => item.trim()).filter(Boolean);
}

function escapeHTML(value) {
    return String(value).replace(/[&<>"']/g, (char) => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;'
    })[char]);
}

function renderCVELink(cveText) {
    const safeText = escapeHTML(cveText);
    const cveId = String(cveText).match(/CVE-\d{4}-\d+/)?.[0];
    if (!cveId) return safeText;
    return `<a href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cveId)}" target="_blank" rel="noopener noreferrer" class="block text-red-700 underline decoration-red-300 underline-offset-2 hover:text-red-900">${safeText}</a>`;
}

function reportActionLink({ href, title, icon, download = false, disabled = false }) {
    if (disabled || !href) {
        return `<span title="${escapeHTML(title)}" class="inline-flex size-8 items-center justify-center rounded-lg border border-zinc-200 bg-zinc-50 text-zinc-400"><i data-lucide="${icon}" class="size-4"></i></span>`;
    }
    return `<a href="${escapeHTML(href)}" ${download ? 'download' : 'target="_blank" rel="noopener noreferrer"'} title="${escapeHTML(title)}" aria-label="${escapeHTML(title)}" class="inline-flex size-8 items-center justify-center rounded-lg border border-olive-200 bg-white text-olive-700 transition-colors hover:border-olive-300 hover:bg-olive-50 hover:text-olive-950"><i data-lucide="${icon}" class="size-4"></i></a>`;
}

function refreshLucideIcons() {
    if (window.lucide?.createIcons) window.lucide.createIcons();
}

function getCVECountsFromRows() {
    return Array.from(document.querySelectorAll('#discovery-table tbody tr')).reduce((totals, row) => {
        totals.high += Number(row.dataset.highCveCount || 0);
        totals.low += Number(row.dataset.lowCveCount || 0);
        return totals;
    }, { high: 0, low: 0 });
}

function updateCVESummaries() {
    const totals = getCVECountsFromRows();
    const total = totals.high + totals.low;
    const summaryCVEs = document.getElementById('summary-cves');
    const deepCVEs = document.getElementById('deep-cves');
    const dragnetCVEs = document.getElementById('dragnet-cves');

    if (summaryCVEs) summaryCVEs.textContent = total ? `${total} (${totals.high} >=7.0, ${totals.low} LOW)` : '--';
    if (deepCVEs) deepCVEs.textContent = totals.high ? `${totals.high} >=7.0` : '--';
    if (dragnetCVEs) dragnetCVEs.textContent = totals.high ? `${totals.high} >=7.0` : '--';
}

function getDiscoveryTableStats() {
    const rows = Array.from(document.querySelectorAll('#discovery-table tbody tr'));
    return rows.reduce((stats, row) => {
        stats.hostCount++;
        const ports = row.querySelector('.ports-cell')?.textContent || '';
        if (ports && ports !== '--') {
            stats.openPortCount += ports.split(',').map(port => port.trim()).filter(Boolean).length;
        }
        stats.criticalCVECount += Number(row.dataset.highCveCount || 0);
        stats.lowCVECount += Number(row.dataset.lowCveCount || 0);
        return stats;
    }, { hostCount: 0, openPortCount: 0, criticalCVECount: 0, lowCVECount: 0 });
}

function updateQuickScanStats(stats = getDiscoveryTableStats()) {
    setText('quick-hosts', stats.hostCount || '--');
}

function updateDeepScanStats(stats = getDiscoveryTableStats()) {
    setText('deep-hosts', stats.hostCount || '--');
    setText('deep-ports', stats.openPortCount || '--');
    setText('deep-cves', stats.criticalCVECount ? `${stats.criticalCVECount} >=7.0` : '--');
}

function highlightActiveScanHost(data) {
    if (!data || !data.ip) return;

    const label = data.hostname ? `${data.ip} (${data.hostname})` : data.ip;
    setText('scan-console-status', `Scanning ${label}`);

    document.querySelectorAll('#discovery-table tbody tr.is-active-scan-host').forEach(row => {
        row.classList.remove('is-active-scan-host', 'bg-amber-50', 'ring-1', 'ring-amber-300');
    });

    updateHostRow({ ip: data.ip, hostname: data.hostname });
    const row = document.getElementById(`row-${data.ip.replace(/\./g, '-')}`);
    if (row) row.classList.add('is-active-scan-host', 'bg-amber-50', 'ring-1', 'ring-amber-300');
}

let appVersion = null;

function initializeScanRuntime(socket) {
    socket.on('sync_state', (state) => {
        if (state.version) {
            appVersion = state.version;
            const versionEl = document.getElementById('app-version');
            if (versionEl) versionEl.textContent = state.version;
        }
        if (state.customerProfile && typeof renderCustomerFingerprint === 'function') {
            renderCustomerFingerprint(state.customerProfile);
        }

        if (state.hosts && state.hosts.length > 0) {
            const tableBody = document.querySelector('#discovery-table tbody');
            tableBody.innerHTML = '';
            state.hosts.forEach(host => {
                updateHostRow(host);
            });
            updateQuickScanStats({ hostCount: state.hosts.length });
            updateDeepScanStats(getDiscoveryTableStats());
        }

        if (state.isScanning) {
            document.getElementById('scan-target').value = state.target;
            setScanUIActive(state.phase, state.scanKind);
            startPhaseTimer(state.phase, state.startTime);
        }

        if (state.lastResult) {
            document.getElementById('last-scan-time-val').textContent = state.lastResult.duration + 's';
            document.getElementById('last-scan-duration').classList.remove('hidden');
        }

        if (state.hops && state.hops.length > 0) {
            const routePath = document.getElementById('route-path');
            routePath.innerHTML = '';
            state.hops.forEach(hop => {
                renderHop(hop);
            });
        }
    });

    socket.on('scan_started', (data) => {
        setScanUIActive(data.phase, data.scanKind);
        startPhaseTimer(data.phase, data.startTime);
        if (data.phase === 1) {
            const tb = document.querySelector('#discovery-table tbody');
            if (tb) tb.innerHTML = '';
            setText('quick-time', '00:00:00');
            setText('quick-hosts', '--');
            setText('deep-time', '--:--:--');
            setText('deep-hosts', '--');
            setText('deep-ports', '--');
            setText('deep-cves', '--');
            setText('summary-hosts', '--');
            setText('summary-ports', '--');
            setText('summary-cves', '--');
        }
        if (data.phase >= 2) {
            setText('deep-time', '00:00:00');
            updateDeepScanStats(getDiscoveryTableStats());
        }
    });

    socket.on('phase_complete', (data) => {
        stopPhaseTimer(data.phase, data.duration);
        if (data.phase === 1) {
            updateQuickScanStats(data);
        }
        if (data.phase >= 2) {
            updateDeepScanStats(data);
        }
    });

    socket.on('phase_stats', (data) => {
        if (data.phase >= 2) {
            updateDeepScanStats(data);
        }
    });

    socket.on('phase_host_started', (data) => {
        highlightActiveScanHost(data);
    });

    socket.on('scan_stopped', () => {
        resetScanUI();
    });

    socket.on('initial_data', (data) => {
        document.getElementById('local-ip-value').textContent = data.localIP;
        document.getElementById('subnet-mask-value').textContent = data.mask;
        document.getElementById('cidr-value').textContent = data.cidr;
        document.getElementById('public-ip-value').textContent = data.publicIP;
        if (data.customerProfile && typeof renderCustomerFingerprint === 'function') {
            renderCustomerFingerprint(data.customerProfile);
        }
        
        const targetInput = document.getElementById('scan-target');
        if (!targetInput.value) {
            targetInput.value = data.cidr;
        }
    });

    socket.emit('get_initial_data');
    socket.emit('get_history');
    socket.emit('get_reports');

    socket.on('traceroute_hop', (data) => {
        renderHop(data);
    });

    socket.on('scan_complete', (data) => {
        resetScanUI();
        stopPhaseTimer(data.phase, data.duration);
        document.getElementById('last-scan-time-val').textContent = data.duration + 's';
        document.getElementById('last-scan-duration').classList.remove('hidden');
        socket.emit('get_history');
        socket.emit('get_reports');
    });

    socket.on('report_ready', (data) => {
        const reportStatus = document.getElementById('report-status');
        if (reportStatus) {
            const actions = [
                reportActionLink({ href: data.url, title: 'Open HTML report', icon: 'file-code-2' }),
                reportActionLink({ href: data.pdfUrl, title: 'Open PDF report', icon: 'file-text', disabled: !data.pdfUrl }),
                reportActionLink({ href: data.pdfUrl, title: 'Download PDF', icon: 'download', download: true, disabled: !data.pdfUrl }),
                reportActionLink({ href: data.driveHtmlUrl || data.drivePdfUrl, title: 'Open in Google Drive', icon: 'cloud', disabled: !(data.driveHtmlUrl || data.drivePdfUrl) })
            ].join('');
            reportStatus.classList.remove('hidden');
            document.getElementById('report-status-text').innerHTML = `
                <div class="flex flex-wrap items-center gap-3">
                    <span class="min-w-0 flex-1 text-sm text-emerald-900 font-medium">Report Ready: <strong>${escapeHTML(data.name)}</strong>${data.customerProfile ? `<span class="block truncate text-xs text-emerald-700">${escapeHTML(data.customerProfile.folderName)}</span>` : ''}</span>
                    <div class="flex items-center gap-1.5">${actions}</div>
                </div>
            `;
            refreshLucideIcons();
        }
        socket.emit('get_reports');
    });

    socket.on('history_data', (data) => {
        const historyList = document.getElementById('history-tab-list');
        const historyStatus = document.getElementById('history-tab-status');
        if (historyList) {
            if (!data || data.length === 0) {
                historyList.innerHTML = '';
                if (historyStatus) {
                    historyStatus.textContent = 'No scan history found yet.';
                    historyStatus.classList.remove('hidden');
                }
                return;
            }
            if (historyStatus) {
                historyStatus.textContent = '';
                historyStatus.classList.add('hidden');
            }
            historyList.innerHTML = data.map(item => `
                <div class="bg-white border border-olive-200 rounded-2xl p-5 shadow-sm hover:shadow-md transition-shadow">
                    <div class="flex justify-between items-start mb-4">
                        <span class="text-[10px] font-bold text-olive-400 uppercase tracking-widest">${new Date(item.timestamp).toLocaleString()}</span>
                        <span class="px-2 py-1 bg-olive-100 text-olive-700 text-[10px] font-bold rounded-lg">${item.duration}s</span>
                    </div>
                    <div class="mb-4">
                        <h4 class="text-olive-900 font-bold text-lg">${item.customerProfile?.baseName || item.target}</h4>
                        <p class="text-xs text-olive-500">${item.hostCount} Hosts Discovered${item.customerProfile?.folderName ? ` | ${item.customerProfile.folderName}` : ''}</p>
                    </div>
                    <div class="grid gap-2 sm:grid-cols-2">
                        <a href="${item.reportUrl}" target="_blank" class="block text-center py-2 bg-olive-50 text-olive-700 text-xs font-bold rounded-xl hover:bg-olive-100 transition-colors">OPEN HTML</a>
                        ${item.pdfUrl ? `<a href="${item.pdfUrl}" target="_blank" class="block text-center py-2 bg-red-50 text-red-700 text-xs font-bold rounded-xl hover:bg-red-100 transition-colors">OPEN PDF</a>` : ''}
                    </div>
                </div>
            `).join('');
        }
    });

    socket.on('reports_data', (data) => {
        const reportsList = document.getElementById('reports-tab-list');
        const reportsStatus = document.getElementById('reports-tab-status');
        const reportsBadge = document.getElementById('reports-badge');
        if (reportsBadge) {
            reportsBadge.textContent = data && data.length > 99 ? '99+' : String((data || []).length);
            reportsBadge.classList.toggle('hidden', !data || data.length === 0);
        }
        if (reportsList) {
            if (!data || data.length === 0) {
                reportsList.innerHTML = '';
                if (reportsStatus) {
                    reportsStatus.textContent = 'No completed reports found yet.';
                    reportsStatus.classList.remove('hidden');
                }
                return;
            }
            if (reportsStatus) {
                reportsStatus.textContent = '';
                reportsStatus.classList.add('hidden');
            }
            reportsList.innerHTML = data.map(report => {
                const actions = [
                    reportActionLink({ href: report.url, title: 'Open HTML report', icon: 'file-code-2' }),
                    reportActionLink({ href: report.pdfUrl, title: 'Open PDF report', icon: 'file-text', disabled: !report.pdfUrl }),
                    reportActionLink({ href: report.pdfUrl, title: 'Download PDF', icon: 'download', download: true, disabled: !report.pdfUrl }),
                    reportActionLink({ href: report.driveHtmlUrl || report.drivePdfUrl, title: 'Open in Google Drive', icon: 'cloud', disabled: !(report.driveHtmlUrl || report.drivePdfUrl) })
                ].join('');
                return `
                    <div class="bg-white border border-olive-200 rounded-lg p-3 shadow-sm transition-shadow hover:shadow-md">
                        <div class="flex items-start justify-between gap-3">
                            <div class="min-w-0">
                                <h4 class="truncate text-sm font-bold text-olive-900" title="${escapeHTML(report.name)}">${escapeHTML(report.name)}</h4>
                                <p class="mt-0.5 truncate font-mono text-[10px] text-olive-500" title="${escapeHTML(report.folder || '')}">${escapeHTML(report.folder || 'reports')}</p>
                            </div>
                            <span class="shrink-0 text-[10px] font-bold uppercase text-olive-400">${new Date(report.date).toLocaleDateString()}</span>
                        </div>
                        <div class="mt-3 flex items-center justify-between gap-2">
                            <span class="text-[10px] font-medium text-olive-500">${report.driveHtmlUrl || report.drivePdfUrl ? 'Drive synced' : 'Local only'}</span>
                            <div class="flex items-center gap-1.5">${actions}</div>
                        </div>
                    </div>
                `;
            }).join('');
            refreshLucideIcons();
        }
    });

    socket.on('reports_refresh', () => socket.emit('get_reports'));
}

function renderHop(data) {
    const routePath = document.getElementById('route-path');
    if (!routePath) return;
    if (routePath.querySelector('span.italic')) {
        routePath.innerHTML = '';
    }
    if (document.getElementById(`hop-${data.hop}`)) return;
    const isPrivate = isPrivateIP(data.ip);
    const colorClass = isPrivate ? 'bg-amber-100 text-amber-700 border-amber-200' : 'bg-emerald-100 text-emerald-700 border-emerald-200';
    if (data.hop > 1) {
        const arrow = document.createElement('span');
        arrow.className = 'text-olive-300 mx-1';
        arrow.textContent = '→';
        routePath.appendChild(arrow);
    }
    const hopSpan = document.createElement('span');
    hopSpan.id = `hop-${data.hop}`;
    hopSpan.className = `px-2 py-1 rounded-lg text-[10px] font-mono font-bold border ${colorClass} shadow-sm`;
    hopSpan.textContent = `${data.hop}: ${data.ip}`;
    routePath.appendChild(hopSpan);
    const allHops = Array.from(routePath.querySelectorAll('[id^="hop-"]'));
    document.getElementById('total-hops').textContent = allHops.length;
    let privateCount = 0; let publicCount = 0; let lastIp = '--';
    allHops.forEach(el => {
        const ip = el.textContent.split(': ')[1];
        if (isPrivateIP(ip)) privateCount++; else publicCount++;
        lastIp = ip;
    });
    document.getElementById('private-hops').textContent = privateCount;
    document.getElementById('public-hops').textContent = publicCount;
    document.getElementById('exit-ip').textContent = lastIp;
}

function getScanButtonByKind(kind) {
    if (kind === 'complete') return document.getElementById('generate-report-btn');
    if (kind === 'dragnet') return document.getElementById('dragnet-scan-btn');
    return document.getElementById('start-scan-btn');
}

function setScanUIActive(phase, scanKind = activeScanKind || 'quick') {
    activeScanKind = scanKind;
    const scanButtons = [
        document.getElementById('start-scan-btn'),
        document.getElementById('generate-report-btn'),
        document.getElementById('dragnet-scan-btn')
    ].filter(Boolean);
    const activeButton = getScanButtonByKind(scanKind);

    scanButtons.forEach(button => {
        button.disabled = true;
        button.classList.toggle('opacity-50', button !== activeButton);
        button.classList.toggle('opacity-90', button === activeButton);
        button.classList.toggle('ring-4', button === activeButton);
        button.classList.toggle('ring-white/50', button === activeButton);
        button.querySelector('.scan-button-pulse')?.classList.toggle('hidden', button !== activeButton);
    });

    if (phase === 1) document.getElementById('quick-scan-indicator').classList.remove('hidden');
    if (phase >= 2) document.getElementById('deep-scan-indicator').classList.remove('hidden');
}

function resetScanUI() {
    activeScanKind = null;
    [
        document.getElementById('start-scan-btn'),
        document.getElementById('generate-report-btn'),
        document.getElementById('dragnet-scan-btn')
    ].filter(Boolean).forEach(button => {
        button.disabled = false;
        button.classList.remove('opacity-50', 'opacity-90', 'ring-4', 'ring-white/50');
        button.querySelector('.scan-button-pulse')?.classList.add('hidden');
    });
    if (document.getElementById('quick-scan-indicator')) document.getElementById('quick-scan-indicator').classList.add('hidden');
    if (document.getElementById('deep-scan-indicator')) document.getElementById('deep-scan-indicator').classList.add('hidden');
    document.querySelectorAll('#discovery-table tbody tr.is-active-scan-host').forEach(row => {
        row.classList.remove('is-active-scan-host', 'bg-amber-50', 'ring-1', 'ring-amber-300');
    });
    setText('scan-console-status', 'Waiting for scan activity');
}

function updateHostRow(data) {
    const tableBody = document.querySelector('#discovery-table tbody');
    if (!tableBody) return;
    let row = document.getElementById(`row-${data.ip.replace(/\./g, '-')}`);
    if (!row) {
        row = document.createElement('tr');
        row.id = `row-${data.ip.replace(/\./g, '-')}`;
        row.className = 'hover:bg-olive-50 transition-colors border-b border-olive-100';
        row.innerHTML = `
            <td class="px-2 py-1 text-center"><span class="size-2 rounded-full bg-emerald-500 inline-block shadow-[0_0_8px_rgba(16,185,129,0.5)]"></span></td>
            <td class="px-1 py-1 font-mono text-[11px] text-olive-900 ip-cell">${data.ip}</td>
            <td class="px-1 py-1 font-mono text-[10px] text-olive-600 mac-cell">${data.mac || '--'}</td>
            <td class="px-1 py-1 text-[10px] text-olive-700 truncate vendor-cell" title="${data.vendor || '--'}">${data.vendor || '--'}</td>
            <td class="px-1 py-1 text-[10px] font-medium text-olive-900 truncate hostname-cell" title="${data.hostname || '--'}">${data.hostname || '--'}</td>
            <td class="px-1 py-1 text-[10px] cve-cell">--</td>
            <td class="px-2 py-1 text-[10px] text-olive-700 os-cell">${data.os || '--'}</td>
            <td class="px-2 py-1 text-[10px] text-olive-700 latency-cell">${data.latency || '--'}</td>
            <td class="px-2 py-1 text-[10px] text-olive-700 ports-cell">${data.ports || '--'}</td>
            <td class="px-2 py-1 text-[10px] text-olive-700 version-cell">${data.version || '--'}</td>
            <td class="px-2 py-1 text-right"><button class="text-[10px] font-bold text-olive-600 bg-olive-100 hover:bg-olive-200 px-1.5 py-0.5 rounded-full transition-all">DETAILS</button></td>
        `;
        tableBody.appendChild(row);
    }

    if (data.mac) row.querySelector('.mac-cell').textContent = data.mac;
    if (data.vendor) {
        const vendorCell = row.querySelector('.vendor-cell');
        vendorCell.textContent = data.vendor;
        vendorCell.title = data.vendor;
    }
    if (data.hostname) {
        const hostnameCell = row.querySelector('.hostname-cell');
        hostnameCell.textContent = data.hostname;
        hostnameCell.title = data.hostname;
    }
    if (data.os) row.querySelector('.os-cell').textContent = data.os;
    if (data.latency) row.querySelector('.latency-cell').textContent = data.latency;
    if (data.ports) row.querySelector('.ports-cell').textContent = data.ports;
    if (data.version) row.querySelector('.version-cell').textContent = data.version;
    
    const highCVEs = getHighCVEList(data);
    const lowCVECount = Number(data.lowCVECount || 0);
    row.dataset.highCveCount = String(highCVEs.length);
    row.dataset.lowCveCount = String(lowCVECount);

    const cveCell = row.querySelector('.cve-cell');
    let html = '';
    if (highCVEs.length > 0) {
        const highCVEText = highCVEs.map(escapeHTML).join('\n');
        html += `<div class="font-mono text-[10px] leading-snug" title="${highCVEText}">${highCVEs.map(renderCVELink).join('')}</div>`;
    }
    if (lowCVECount > 0) {
        html += `<div class="mt-1 inline-flex px-1.5 py-0.5 bg-amber-50 text-amber-700 rounded-md font-medium" title="Found ${lowCVECount} LOW priority CVEs in the report">${lowCVECount} LOW</div>`;
    }
    cveCell.innerHTML = html || '--';
    updateCVESummaries();
}

function initializeDiscoveryUI(socket) {
    const startScanBtn = document.getElementById('start-scan-btn');
    const completeScanBtn = document.getElementById('generate-report-btn');
    const dragnetScanBtn = document.getElementById('dragnet-scan-btn');
    const stopScanBtn = document.getElementById('stop-scan-btn');

    if (startScanBtn) {
        startScanBtn.addEventListener('click', () => {
            const target = document.getElementById('scan-target').value;
            socket.emit('start_quick_scan', { target });
        });
    }
    if (completeScanBtn) {
        completeScanBtn.addEventListener('click', () => {
            const target = document.getElementById('scan-target').value;
            socket.emit('start_complete_scan', { target });
        });
    }
    if (dragnetScanBtn) {
        dragnetScanBtn.addEventListener('click', () => {
            const target = document.getElementById('scan-target').value;
            socket.emit('start_dragnet_scan', { target });
        });
    }
    if (stopScanBtn) {
        stopScanBtn.addEventListener('click', () => {
            socket.emit('stop_scan');
        });
    }

    socket.on('discovery_update', (data) => {
        updateHostRow(data);
        const stats = getDiscoveryTableStats();
        if (activeScanPhase === 1) updateQuickScanStats(stats);
        if (activeScanPhase >= 2 || data.ports || data.highCVEs || data.lowCVECount) updateDeepScanStats(stats);
        setText('summary-hosts', stats.hostCount || '--');
        setText('summary-ports', stats.openPortCount || '--');
    });
}
