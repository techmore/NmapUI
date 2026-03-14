function setSafeExternalLink(link, rawUrl) {
    if (!rawUrl) return false;

    try {
        const url = new URL(String(rawUrl), window.location.origin);
        if (url.protocol !== 'http:' && url.protocol !== 'https:') {
            return false;
        }

        link.href = url.href;
        link.target = '_blank';
        link.rel = 'noopener noreferrer';
        return true;
    } catch (error) {
        console.warn('Ignoring invalid external URL:', rawUrl);
        return false;
    }
}

function renderDelimitedCell(cell, items, options = {}) {
    cell.replaceChildren();
    const values = Array.isArray(items) ? items : [];
    values.forEach(item => {
        const row = document.createElement('div');
        row.className = options.className || 'whitespace-nowrap';
        row.textContent = item;
        if (typeof options.onClick === 'function') {
            row.classList.add('cursor-pointer');
            row.addEventListener('click', options.onClick);
        }
        cell.appendChild(row);
    });
}

function renderCveArrayCell(cell, cveArray) {
    cell.replaceChildren();
    cveArray.forEach(cve => {
        const row = document.createElement('div');
        row.className = 'text-xs py-0.5';

        const score = document.createElement('span');
        score.className = 'inline-block px-1.5 py-0.5 rounded bg-red-100 text-red-700 font-medium mr-1';
        score.textContent = cve.score;
        row.appendChild(score);

        const link = document.createElement('a');
        link.className = 'text-olive-600 hover:text-olive-800 hover:underline';
        link.textContent = cve.id;
        if (setSafeExternalLink(link, cve.url)) {
            row.appendChild(link);
        } else {
            const fallback = document.createElement('span');
            fallback.className = 'text-olive-700';
            fallback.textContent = cve.id;
            row.appendChild(fallback);
        }

        cell.appendChild(row);
    });
}

function appendServiceInfoLine(cell, line) {
    const entry = document.createElement('div');
    entry.className = 'text-xs text-olive-600';
    entry.textContent = line;
    cell.appendChild(entry);
}

function renderRoutePath(data) {
    const routePath = document.getElementById('route-path');
    routePath.replaceChildren();

    if (data.hops && data.hops.length > 0) {
        const reversedHops = [...data.hops].reverse();
        reversedHops.forEach((hop, i) => {
            const typeColor = hop.is_private ? 'bg-amber-100 text-amber-800 border-amber-200' : 'bg-emerald-100 text-emerald-800 border-emerald-200';
            const isLast = i === reversedHops.length - 1;

            const hopDiv = document.createElement('div');
            hopDiv.className = `flex items-center gap-2 px-2 py-1 rounded-lg border text-[11px] font-mono font-bold ${typeColor} shadow-sm transition-all hover:scale-105`;

            const countSpan = document.createElement('span');
            countSpan.className = 'opacity-40 text-[9px]';
            countSpan.textContent = String(reversedHops.length - i);
            hopDiv.appendChild(countSpan);

            const ipSpan = document.createElement('span');
            ipSpan.textContent = hop.ip;
            hopDiv.appendChild(ipSpan);
            routePath.appendChild(hopDiv);

            if (!isLast) {
                const arrow = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
                arrow.setAttribute('class', 'w-3 h-3 text-olive-300');
                arrow.setAttribute('fill', 'none');
                arrow.setAttribute('stroke', 'currentColor');
                arrow.setAttribute('viewBox', '0 0 24 24');
                const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
                path.setAttribute('stroke-linecap', 'round');
                path.setAttribute('stroke-linejoin', 'round');
                path.setAttribute('stroke-width', '2');
                path.setAttribute('d', 'M9 5l7 7-7 7');
                arrow.appendChild(path);
                routePath.appendChild(arrow);
            }
        });
    } else {
        const span = document.createElement('span');
        if (data.error) {
            span.className = 'text-red-700 font-medium';
            span.textContent = data.error;
        } else {
            span.className = 'text-olive-500 italic';
            span.textContent = 'No route data available';
        }
        routePath.appendChild(span);
    }
}

function updateHistoryBadge(customerName) {
    const badge = document.getElementById('history-badge');
    const lastScanSpan = document.getElementById('last-scan-days');
    if (!badge || !window.historyCounts) return;

    const key = (customerName && customerName !== 'Unassigned') ? customerName.split(' (')[0] : 'Unassigned';
    const count = window.historyCounts[key] || 0;

    if (count > 0) {
        badge.textContent = count > 99 ? '99+' : count;
        badge.classList.remove('hidden');
        badge.className = 'absolute -top-1 -right-1 flex items-center justify-center min-w-[1.25rem] h-5 px-1.5 rounded-full bg-olive-900 text-white text-[10px] font-bold shadow-sm transition-all scale-110';
        badge.classList.remove('scale-110');
        void badge.offsetWidth;
        badge.classList.add('scale-110');
    } else {
        badge.classList.add('hidden');
    }

    const lastScanTime = window.historyCounts.last_scans ? window.historyCounts.last_scans[key] : null;
    const container = document.getElementById('last-scan-container');
    if (lastScanTime && lastScanSpan) {
        const lastDate = new Date(lastScanTime);
        const now = new Date();
        const diffTime = Math.abs(now - lastDate);
        const diffDays = Math.floor(diffTime / (1000 * 60 * 60 * 24));

        lastScanSpan.textContent = diffDays === 0 ? 'Today' : `${diffDays} days ago`;
        if (container) container.classList.remove('hidden');

        lastScanSpan.className = 'px-3 py-1 rounded-full text-xs font-medium transition-all';
        if (diffDays <= 1) {
            lastScanSpan.classList.add('bg-olive-200', 'text-olive-900');
        } else if (diffDays <= 7) {
            lastScanSpan.classList.add('bg-olive-100', 'text-olive-700');
        } else {
            lastScanSpan.classList.add('bg-olive-50', 'text-olive-500');
        }
    } else if (container) {
        container.classList.add('hidden');
    }
}

function updateRowWithResults(host) {
    const tb = document.querySelector('#discovery-table tbody');
    let rowToUpdate = Array.from(tb.rows).find(row => row.cells[1].textContent === host.ip);
    if (!rowToUpdate) {
        return;
    }

    const ports = host.ports || [];
    const portsStr = ports.map(port => `${port.port}/${String(port.service || '').split(/\s+/)[0]}`).join(', ');
    const versionHtml = ports.map(port => `<div class="text-xs">${port.service}</div>`).join('');

    rowToUpdate.cells[5].textContent = portsStr;
    rowToUpdate.cells[6].innerHTML = versionHtml;

    if (host.cves && host.cves.length > 0) {
        rowToUpdate.cells[7].innerHTML = host.cves
            .map(cve => `<div class="text-xs py-0.5"><span class="inline-block px-1.5 py-0.5 rounded bg-red-100 text-red-700 font-medium mr-1">${cve.score}</span><a href="${cve.url}" target="_blank" class="text-olive-600 hover:text-olive-800 hover:underline">${cve.id}</a></div>`)
            .join('');
    }

    if (window.currentHosts[host.ip]) {
        window.currentHosts[host.ip].open_ports = portsStr;
        window.currentHosts[host.ip].version = ports.map(port => port.service).join(', ');
        window.currentHosts[host.ip].cves = (host.cves || []).map(cve => cve.id).join(', ');
    }
}

function hostsStorageKey() {
    return window.currentCIDR ? `nmapui_hosts_${window.currentCIDR}` : null;
}

function saveHostsToStorage() {
    const key = hostsStorageKey();
    if (!key || !Object.keys(window.currentHosts).length) {
        return;
    }

    try {
        localStorage.setItem(key, JSON.stringify({
            hosts: Object.values(window.currentHosts),
            savedAt: new Date().toISOString(),
        }));
    } catch (error) {
        console.warn('localStorage save failed', error);
    }
}

function loadHostsFromStorage() {
    const key = hostsStorageKey();
    if (!key) {
        return false;
    }

    try {
        const raw = localStorage.getItem(key);
        if (!raw) {
            return false;
        }

        const { hosts, savedAt } = JSON.parse(raw);
        if (!hosts || !hosts.length) {
            return false;
        }

        populateTableWithResults(hosts, true);
        const ageDays = Math.floor((Date.now() - new Date(savedAt)) / 86400000);
        showHistoricalDataBanner({
            age_days: ageDays,
            scan_date: savedAt,
            total: hosts.length,
            total_vulnerabilities: hosts.reduce((count, host) => count + (host.cves ? host.cves.split(',').filter(Boolean).length : 0), 0),
            total_exploits: 0,
        });

        const reloadButton = document.getElementById('reload-last-scan-btn');
        if (reloadButton) {
            reloadButton.classList.remove('hidden');
        }
        window.localStorageLoaded = true;
        return true;
    } catch {
        return false;
    }
}

function dimExistingRows() {
    document.querySelectorAll('#discovery-table tbody tr').forEach((row) => {
        row.classList.add('historical-row');
    });
}

function undimAllRows() {
    document.querySelectorAll('#discovery-table tbody tr').forEach((row) => {
        row.classList.remove('historical-row');
    });
}

function populateTableWithResults(data, isHistorical = false) {
    const tb = document.querySelector('#discovery-table tbody');
    tb.innerHTML = '';

    window.assetData = {};
    window.currentHosts = {};

    data.forEach(result => {
        if (result.ip) {
            window.assetData[result.ip] = result;
            window.currentHosts[result.ip] = result;
        }

        const newRow = tb.insertRow(-1);
        if (isHistorical) {
            newRow.classList.add('historical-row');
        }
        const statusCell = newRow.insertCell(0);
        statusCell.className = 'px-4 py-3 text-center';
        statusCell.innerHTML = '';

        ['ip', 'mac', 'vendor', 'hostname', 'open_ports', 'version', 'cves'].forEach((col, i) => {
            const cell = newRow.insertCell(i + 1);
            cell.className = 'px-4 py-3 text-olive-900';

            if (col === 'open_ports' || col === 'version' || col === 'cves') {
                const value = result[col] || '';
                if (value) {
                    const items = value.split(',').map(item => item.trim()).filter(item => item);

                    if (col === 'cves') {
                        renderDelimitedCell(cell, items, {
                            className: 'whitespace-nowrap text-purple-600 hover:text-purple-800 underline',
                            onClick: event => {
                                event.stopPropagation();
                                showAssetDetailsModal(window.assetData[result.ip]);
                            },
                        });
                    } else {
                        renderDelimitedCell(cell, items);
                    }
                } else {
                    cell.textContent = '';
                }
                if (col === 'open_ports') cell.classList.add('open-ports-cell');
            } else {
                cell.textContent = result[col] || '';
            }

            if (col === 'mac') cell.classList.add('font-mono', 'text-xs');
            if (col === 'vendor') cell.classList.add('text-olive-600');
            if (col === 'hostname') {
                cell.classList.add('truncate', 'max-w-[150px]', 'block');
                cell.title = result[col];
            }
        });
        const rescanCell = newRow.insertCell(-1);
        rescanCell.className = 'px-4 py-3';
        const rescanBtn = document.createElement('button');
        rescanBtn.textContent = 'Rescan';
        rescanBtn.classList.add('inline-flex', 'items-center', 'justify-center', 'rounded-full', 'bg-olive-950', 'text-white', 'hover:bg-olive-800', 'font-medium', 'py-1', 'px-3', 'text-xs', 'transition-colors');
        rescanBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            handleRescan(result['ip']);
        });
        rescanCell.appendChild(rescanBtn);
    });
}

function initializeDiscoveryUI(socket) {
    window.currentHosts = window.currentHosts || {};
    window.currentCIDR = window.currentCIDR || null;
    window.localStorageLoaded = window.localStorageLoaded || false;

    socket.on('local_ip', data => {
        ['local-ip', 'subnet-mask', 'public-ip'].forEach((id, i) => document.getElementById(`${id}-value`).textContent = Object.values(data)[i]);
        document.getElementById('cidr-value').textContent = data.cidr || '';
        document.getElementById('scan-target').value = data.cidr;
        window.currentCIDR = data.cidr || null;
        if (typeof window.loadHostsFromStorage === 'function') {
            window.loadHostsFromStorage();
        }
    });

    socket.on('cve_array', data => {
        const tb = document.querySelector('#discovery-table tbody');
        for (let row of tb.rows) {
            if (row.cells[1].textContent === data.target) {
                let cell = row.cells[7];
                renderCveArrayCell(cell, data.cve_array || []);
                break;
            }
        }
        if (window.tableSorter) window.tableSorter.resort();
    });

    socket.on('service_info', data => {
        const tb = document.querySelector('#discovery-table tbody');
        for (let row of tb.rows) {
            if (row.cells[1].textContent === data.target) {
                appendServiceInfoLine(row.cells[4], data.line);
                break;
            }
        }
        if (window.tableSorter) window.tableSorter.resort();
    });

    socket.on('quickscan_results', data => {
        console.log('Received quick_scan_results:', data);
        document.getElementById('quick-time').textContent = data.time_taken + 's';
        document.getElementById('quick-hosts').textContent = data.hosts_up;
    });

    socket.on('deep_scan_results', data => {
        data.forEach(updateRowWithResults);
        saveHostsToStorage();
        updateLastScanResults('deepScan', data);
        if (window.tableSorter) window.tableSorter.resort();
    });

    socket.on('network_key', data => {
        console.log('Network key received:', data);
        document.getElementById('total-hops').textContent = data.total_hops;
        document.getElementById('private-hops').textContent = data.private_hops.length;
        document.getElementById('public-hops').textContent = data.public_hops.length;
        document.getElementById('exit-ip').textContent = data.exit_ip || '--';
        renderRoutePath(data);
    });

    socket.on('resumable_scan_check', data => {
        if (data.available && !window.localStorageLoaded) {
            console.log('Resumable scan available:', data);
            socket.emit('resume_from_last_scan', {
                customer_id: window.currentMatchedCustomerId,
                max_days: 7
            });
        } else {
            if (!window.localStorageLoaded) {
                hideHistoricalDataBanner();
            }
        }
    });

    socket.on('resume_scan_error', data => {
        console.error('Resume scan error:', data.error);
        hideHistoricalDataBanner();
    });

    socket.on('versions', data => {
        console.log('Versions received:', data);
        const nmapVersion = data.nmap || 'Not found';
        const vulnersVersion = data.vulners || 'Not found';
        const arpScanVersion = data.arp_scan || 'Not found';
        const appVersion = data.app || 'v--.--.--.__';

        document.getElementById('app-version').textContent = appVersion;
        document.getElementById('nmap-version').textContent = `Nmap: ${nmapVersion}`;
        document.getElementById('vulners-version').textContent = `Vulners: ${vulnersVersion}`;
        document.getElementById('arpscan-version').textContent = `ARP-Scan: ${arpScanVersion}`;
        socket.emit('check_app_updates');
    });

    socket.on('history_counts', data => {
        console.log('History counts received:', data);
        window.historyCounts = data;

        const dropdown = document.getElementById('customer-quick-add');
        const currentCustomerName = dropdown.selectedOptions[0]?.text || 'Unassigned';
        updateHistoryBadge(currentCustomerName);
    });

    socket.on('scan_complete_summary', function(data) {
        showScanSummaryBanner(data);
    });

    socket.on('scan_results', function(data) {
        const hosts = Array.isArray(data) ? data : data.hosts;
        const isHistorical = !!data.is_historical;

        if (isHistorical) {
            showHistoricalDataBanner(data);
        } else {
            hideHistoricalDataBanner();
            const reloadButton = document.getElementById('reload-last-scan-btn');
            if (reloadButton) {
                reloadButton.classList.add('hidden');
            }
            window.localStorageLoaded = false;
        }

        populateTableWithResults(hosts, isHistorical);
        updateLastScanResults('quickScan', data);
        if (!isHistorical) {
            saveHostsToStorage();
        }
        if (window.tableSorter) window.tableSorter.resort();
    });

    socket.on('report_complete', function(data) {
        if (typeof window.showReportCompleteStatus === 'function') {
            window.showReportCompleteStatus(data);
        } else {
            showReportStatus(formatReportCompleteMessage(data), 'success');
        }
        window.dispatchEvent(new CustomEvent('report-complete-refresh'));
        document.getElementById('generate-report-btn').classList.remove('card-pulsing');
        stopReportTimer();
        socket.emit('get_history_counts');
        if (!document.getElementById('history-modal').classList.contains('hidden')) {
            loadScanHistory();
        }
    });

    socket.on('report_error', function(data) {
        showReportStatus('Error: ' + data.error, 'error');
        document.getElementById('generate-report-btn').classList.remove('card-pulsing');
        stopReportTimer();
    });

    socket.on('arp_results', data => {
        console.log('ARP results received:', data);
        const tb = document.querySelector('#discovery-table tbody');
        for (let row of tb.rows) {
            const ip = row.cells[1].textContent;
            if (data[ip]) {
                row.cells[2].textContent = data[ip].mac;
                row.cells[3].textContent = data[ip].vendor;
            }
        }
        updateLastScanResults('arpScan', data);
        if (window.tableSorter) window.tableSorter.resort();
    });

    socket.emit('get_local_ip');
    socket.emit('get_network_key');
    socket.emit('get_customer_info');
    socket.emit('get_versions');
    socket.emit('get_customers');
    socket.emit('get_history_counts');
    socket.emit('get_job_status');

    document.getElementById('info-icon').addEventListener('click', () => {
        document.getElementById('tooltip').classList.toggle('hidden');
    });
}

function formatReportCompleteMessage(data) {
    const scanDir = data?.scan_dir || 'saved scan folder';
    const diffSummary = data?.diff_summary;
    if (!diffSummary || !diffSummary.has_changes) {
        return 'Report generated successfully. Check: ' + scanDir;
    }

    const facts = [];
    if (diffSummary.added_hosts?.length) {
        facts.push(`${diffSummary.added_hosts.length} new host(s)`);
    }
    if (diffSummary.removed_hosts?.length) {
        facts.push(`${diffSummary.removed_hosts.length} removed host(s)`);
    }
    if (diffSummary.changed_hosts?.length) {
        facts.push(`${diffSummary.changed_hosts.length} changed host(s)`);
    }
    if (diffSummary.new_ports?.length) {
        facts.push(`${diffSummary.new_ports.length} new port(s)`);
    }
    if (diffSummary.new_vulnerabilities?.length) {
        facts.push(`${diffSummary.new_vulnerabilities.length} new vulnerabilit${diffSummary.new_vulnerabilities.length === 1 ? 'y' : 'ies'}`);
    }

    const summaryText = facts.length ? ` Changes detected: ${facts.join(', ')}.` : ' Changes detected.';
    return `Report generated successfully. Check: ${scanDir}.${summaryText}`;
}

window.setSafeExternalLink = setSafeExternalLink;
window.renderDelimitedCell = renderDelimitedCell;
window.formatReportCompleteMessage = formatReportCompleteMessage;
window.renderCveArrayCell = renderCveArrayCell;
window.appendServiceInfoLine = appendServiceInfoLine;
window.renderRoutePath = renderRoutePath;
window.updateHistoryBadge = updateHistoryBadge;
window.hostsStorageKey = hostsStorageKey;
window.saveHostsToStorage = saveHostsToStorage;
window.loadHostsFromStorage = loadHostsFromStorage;
window.dimExistingRows = dimExistingRows;
window.undimAllRows = undimAllRows;
window.updateRowWithResults = updateRowWithResults;
window.populateTableWithResults = populateTableWithResults;
window.initializeDiscoveryUI = initializeDiscoveryUI;
