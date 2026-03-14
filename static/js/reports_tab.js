let appTabsInitialized = false;
let reportsTabLoaded = false;
let historyTabLoaded = false;
let currentAppTab = 'dashboard';
let historyCompareBasePath = null;

function ensureTabPanelsAreSiblings() {
    const dashboardPanel = document.getElementById('dashboard-tab-panel');
    if (!dashboardPanel || !dashboardPanel.parentElement) {
        return;
    }

    const parent = dashboardPanel.parentElement;
    const panelIds = [
        'history-tab-panel',
        'reports-tab-panel',
        'logs-tab-panel',
        'settings-tab-panel',
    ];

    panelIds.forEach((panelId) => {
        const panel = document.getElementById(panelId);
        if (!panel || panel.parentElement !== dashboardPanel) {
            return;
        }
        parent.insertBefore(panel, dashboardPanel.nextSibling);
    });
}

function setTabStatus(elementId, message, isError = false) {
    const status = document.getElementById(elementId);
    if (!status) {
        return;
    }

    if (!message) {
        status.textContent = '';
        status.classList.add('hidden');
        status.classList.remove('bg-red-50', 'text-red-700', 'bg-olive-50', 'text-olive-800');
        return;
    }

    status.textContent = message;
    status.classList.remove('hidden');
    status.classList.remove('bg-red-50', 'text-red-700', 'bg-olive-50', 'text-olive-800');
    status.classList.add(isError ? 'bg-red-50' : 'bg-olive-50');
    status.classList.add(isError ? 'text-red-700' : 'text-olive-800');
}

function createScanActionLink(href, label, newTab = false) {
    const link = document.createElement('a');
    link.href = href;
    link.textContent = label;
    link.className = 'action-button action-button-primary action-button-compact';
    if (newTab) {
        link.target = '_blank';
        link.rel = 'noopener noreferrer';
    }
    return link;
}

function formatScanTimestamp(scan) {
    const timestamp = scan?.timestamp;
    if (!timestamp) {
        return '--';
    }
    return new Date(timestamp).toLocaleString();
}

function renderCompareStatus(message, isError = false) {
    setTabStatus('history-compare-status', message, isError);
}

function renderHistoryCompareResult(payload) {
    const panel = document.getElementById('history-compare-panel');
    const summary = document.getElementById('history-compare-summary');
    const details = document.getElementById('history-compare-details');
    if (!panel || !summary || !details) {
        return;
    }

    const diffSummary = payload?.diff_summary || {};
    const facts = [];
    if (diffSummary.added_hosts?.length) facts.push(`${diffSummary.added_hosts.length} new host(s)`);
    if (diffSummary.removed_hosts?.length) facts.push(`${diffSummary.removed_hosts.length} removed host(s)`);
    if (diffSummary.changed_hosts?.length) facts.push(`${diffSummary.changed_hosts.length} changed host(s)`);
    if (diffSummary.new_ports?.length) facts.push(`${diffSummary.new_ports.length} new port(s)`);
    if (diffSummary.removed_ports?.length) facts.push(`${diffSummary.removed_ports.length} removed port(s)`);
    if (diffSummary.new_vulnerabilities?.length) facts.push(`${diffSummary.new_vulnerabilities.length} new vulnerabilities`);
    if (diffSummary.removed_vulnerabilities?.length) facts.push(`${diffSummary.removed_vulnerabilities.length} resolved vulnerabilities`);

    summary.textContent = `${formatScanTimestamp(payload.base_scan)} -> ${formatScanTimestamp(payload.current_scan)}`
        + (facts.length ? ` | ${facts.join(' | ')}` : ' | No changes detected');

    details.replaceChildren();

    const sections = [
        ['New Hosts', diffSummary.added_hosts || []],
        ['Removed Hosts', diffSummary.removed_hosts || []],
        ['New Ports', diffSummary.new_ports || []],
        ['Removed Ports', diffSummary.removed_ports || []],
        ['New Vulnerabilities', diffSummary.new_vulnerabilities || []],
        ['Resolved Vulnerabilities', diffSummary.removed_vulnerabilities || []],
    ];

    sections.forEach(([title, items]) => {
        if (!items.length) {
            return;
        }
        const section = document.createElement('div');
        section.className = 'rounded-xl border border-olive-200 bg-white p-4';
        const heading = document.createElement('h4');
        heading.className = 'text-sm font-bold uppercase tracking-widest text-olive-700';
        heading.textContent = title;
        section.appendChild(heading);

        const list = document.createElement('ul');
        list.className = 'mt-2 space-y-1 text-sm text-olive-800';
        items.forEach((item) => {
            const row = document.createElement('li');
            row.className = 'font-mono';
            row.textContent = item;
            list.appendChild(row);
        });
        section.appendChild(list);
        details.appendChild(section);
    });

    if (diffSummary.changed_hosts?.length) {
        const changedSection = document.createElement('div');
        changedSection.className = 'rounded-xl border border-olive-200 bg-white p-4';
        const heading = document.createElement('h4');
        heading.className = 'text-sm font-bold uppercase tracking-widest text-olive-700';
        heading.textContent = 'Changed Hosts';
        changedSection.appendChild(heading);

        diffSummary.changed_hosts.forEach((hostDiff) => {
            const hostCard = document.createElement('div');
            hostCard.className = 'mt-3 rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-sm text-amber-900';
            hostCard.innerHTML = `<div class="font-mono font-semibold">${hostDiff.host}</div>`;
            const hostFacts = [];
            if (hostDiff.new_ports?.length) hostFacts.push(`new ports: ${hostDiff.new_ports.join(', ')}`);
            if (hostDiff.removed_ports?.length) hostFacts.push(`removed ports: ${hostDiff.removed_ports.join(', ')}`);
            if (hostDiff.new_vulnerabilities?.length) hostFacts.push(`new vulns: ${hostDiff.new_vulnerabilities.join(', ')}`);
            if (hostDiff.removed_vulnerabilities?.length) hostFacts.push(`resolved vulns: ${hostDiff.removed_vulnerabilities.join(', ')}`);
            const hostMeta = document.createElement('div');
            hostMeta.className = 'mt-1 text-xs text-amber-800';
            hostMeta.textContent = hostFacts.join(' | ');
            hostCard.appendChild(hostMeta);
            changedSection.appendChild(hostCard);
        });
        details.appendChild(changedSection);
    }

    panel.classList.remove('hidden');
}

async function compareHistoryScans(basePath, currentPath) {
    renderCompareStatus('Comparing selected scans...');
    try {
        const response = await fetch(
            `/api/scans/compare?base_path=${encodeURIComponent(basePath)}&current_path=${encodeURIComponent(currentPath)}`
        );
        if (!response.ok) {
            const payload = await response.json().catch(() => ({}));
            throw new Error(payload.error || `Failed to compare scans (${response.status})`);
        }
        const payload = await response.json();
        renderCompareStatus('');
        renderHistoryCompareResult(payload);
    } catch (error) {
        console.error('Error comparing scans:', error);
        renderCompareStatus(error.message || 'Failed to compare scans.', true);
    }
}

function createHistoryDetailBlock(scan) {
    const details = document.createElement('details');
    details.className = 'mt-4 rounded-xl border border-olive-200 bg-white/70 p-3';

    const summary = document.createElement('summary');
    summary.className = 'cursor-pointer text-sm font-semibold text-olive-800';
    summary.textContent = 'Scan details';
    details.appendChild(summary);

    const meta = document.createElement('div');
    meta.className = 'mt-3 grid gap-2 text-sm text-olive-700';
    meta.innerHTML = `
        <div><span class="font-semibold text-olive-900">Path:</span> <span class="font-mono">${scan.path}</span></div>
        <div><span class="font-semibold text-olive-900">Customer ID:</span> <span class="font-mono">${scan.customer_id || '--'}</span></div>
        <div><span class="font-semibold text-olive-900">Status:</span> ${scan.status || 'completed'}</div>
        <div><span class="font-semibold text-olive-900">Timestamp:</span> ${formatScanTimestamp(scan)}</div>
    `;
    details.appendChild(meta);
    return details;
}

function createHistoryCard(scan, options = {}) {
    const card = document.createElement('article');
    card.className = 'rounded-2xl border border-olive-200 bg-olive-50 p-4 shadow-sm';

    const title = document.createElement('h3');
    title.className = 'text-xl font-display italic text-olive-950';
    title.textContent = scan.customer_name || 'Unknown';
    card.appendChild(title);

    const meta = document.createElement('p');
    meta.className = 'mt-1 text-sm text-olive-600';
    meta.textContent = new Date(scan.timestamp).toLocaleString();
    card.appendChild(meta);

    const target = document.createElement('p');
    target.className = 'mt-2 text-sm text-olive-800';
    target.innerHTML = `Target: <span class="font-mono">${scan.target || '--'}</span>`;
    card.appendChild(target);

    if (scan.status && scan.status !== 'completed') {
        const status = document.createElement('p');
        status.className = 'mt-2 text-sm font-medium text-amber-700';
        status.textContent = `Status: ${scan.status}`;
        card.appendChild(status);
    }

    if (scan.diff_summary?.has_changes && typeof window.createHistoryDiffSummary === 'function') {
        const diffCard = window.createHistoryDiffSummary(scan.diff_summary);
        if (diffCard) {
            card.appendChild(diffCard);
        }
    }

    card.appendChild(createHistoryDetailBlock(scan));

    const actions = document.createElement('div');
    actions.className = 'mt-4 flex flex-wrap gap-2';

    if (scan.has_html) {
        actions.appendChild(createScanActionLink(`/api/scans/${scan.path}/html`, 'View Report', true));
    }
    if (scan.has_pdf) {
        actions.appendChild(createScanActionLink(`/api/scans/${scan.path}/pdf`, 'Download PDF'));
    }
    if (scan.has_xml) {
        actions.appendChild(createScanActionLink(`/api/scans/${scan.path}/xml`, 'Download XML'));
    }

    if (options.enableCompare) {
        const selectBaseButton = document.createElement('button');
        selectBaseButton.type = 'button';
        selectBaseButton.className = 'action-button action-button-secondary action-button-compact';
        selectBaseButton.textContent = historyCompareBasePath === scan.path ? 'Base Selected' : 'Select Base';
        selectBaseButton.addEventListener('click', () => {
            historyCompareBasePath = historyCompareBasePath === scan.path ? null : scan.path;
            renderCompareStatus(
                historyCompareBasePath
                    ? `Base scan selected: ${formatScanTimestamp(scan)}`
                    : ''
            );
            historyTabLoaded = false;
            loadHistoryTab(true);
        });
        actions.appendChild(selectBaseButton);

        const compareButton = document.createElement('button');
        compareButton.type = 'button';
        compareButton.className = 'action-button action-button-primary action-button-compact';
        compareButton.textContent = 'Compare to Base';
        compareButton.disabled = !historyCompareBasePath || historyCompareBasePath === scan.path;
        compareButton.classList.toggle('opacity-50', compareButton.disabled);
        compareButton.addEventListener('click', () => {
            if (!historyCompareBasePath || historyCompareBasePath === scan.path) {
                return;
            }
            compareHistoryScans(historyCompareBasePath, scan.path);
        });
        actions.appendChild(compareButton);
    }

    card.appendChild(actions);
    return card;
}

function renderHistoryTab(scans) {
    const list = document.getElementById('history-tab-list');
    if (!list) {
        return;
    }

    list.replaceChildren();

    if (!scans.length) {
        setTabStatus('history-tab-status', 'No scan history found yet.');
        return;
    }

    setTabStatus('history-tab-status', '');
    scans.forEach((scan) => {
        list.appendChild(createHistoryCard(scan, { enableCompare: true }));
    });
}

function renderReportsTab(scans) {
    const list = document.getElementById('reports-tab-list');
    if (!list) {
        return;
    }

    list.replaceChildren();

    if (!scans.length) {
        setTabStatus('reports-tab-status', 'No completed reports found yet.');
        return;
    }

    setTabStatus('reports-tab-status', '');
    scans.forEach((scan) => {
        list.appendChild(createHistoryCard(scan));
    });
}

async function fetchScansForTabs() {
    const response = await fetch('/api/scans');
    if (!response.ok) {
        throw new Error(`Failed to load scans (${response.status})`);
    }
    const data = await response.json();
    return data.scans || [];
}

async function loadHistoryTab(force = false) {
    if (historyTabLoaded && !force) {
        return;
    }

    setTabStatus('history-tab-status', 'Loading history...');
    try {
        const scans = await fetchScansForTabs();
        renderHistoryTab(scans);
        historyTabLoaded = true;
    } catch (error) {
        console.error('Error loading history tab:', error);
        setTabStatus('history-tab-status', 'Failed to load history.', true);
    }
}

async function loadReportsTab(force = false) {
    if (reportsTabLoaded && !force) {
        return;
    }

    setTabStatus('reports-tab-status', 'Loading reports...');
    try {
        const scans = await fetchScansForTabs();
        renderReportsTab(scans.filter((scan) => scan.has_html || scan.has_pdf || scan.has_xml));
        reportsTabLoaded = true;
    } catch (error) {
        console.error('Error loading reports tab:', error);
        setTabStatus('reports-tab-status', 'Failed to load reports.', true);
    }
}

function setTabButtonState(button, active) {
    if (!button) {
        return;
    }

    button.classList.toggle('action-button-primary', active);
    button.classList.toggle('text-olive-700', !active);
    button.classList.toggle('hover:bg-olive-100', !active);
}

function switchAppTab(tabName) {
    currentAppTab = tabName;

    const panels = {
        dashboard: document.getElementById('dashboard-tab-panel'),
        history: document.getElementById('history-tab-panel'),
        reports: document.getElementById('reports-tab-panel'),
        logs: document.getElementById('logs-tab-panel'),
        settings: document.getElementById('settings-tab-panel'),
    };

    Object.entries(panels).forEach(([name, panel]) => {
        panel?.classList.toggle('hidden', name !== tabName);
    });

    setTabButtonState(document.getElementById('tab-dashboard-btn'), tabName === 'dashboard');
    setTabButtonState(document.getElementById('tab-history-btn'), tabName === 'history');
    setTabButtonState(document.getElementById('tab-reports-btn'), tabName === 'reports');
    setTabButtonState(document.getElementById('tab-logs-btn'), tabName === 'logs');
    setTabButtonState(document.getElementById('tab-settings-btn'), tabName === 'settings');

    if (tabName === 'history') {
        loadHistoryTab();
    } else if (tabName === 'reports') {
        loadReportsTab();
    }
}

function initializeReportsTab() {
    if (appTabsInitialized) {
        return;
    }
    appTabsInitialized = true;
    ensureTabPanelsAreSiblings();

    document.getElementById('tab-dashboard-btn')?.addEventListener('click', () => switchAppTab('dashboard'));
    document.getElementById('tab-history-btn')?.addEventListener('click', () => switchAppTab('history'));
    document.getElementById('tab-reports-btn')?.addEventListener('click', () => switchAppTab('reports'));
    document.getElementById('tab-logs-btn')?.addEventListener('click', () => switchAppTab('logs'));
    document.getElementById('tab-settings-btn')?.addEventListener('click', () => switchAppTab('settings'));

    document.getElementById('refresh-history-tab-btn')?.addEventListener('click', () => {
        historyTabLoaded = false;
        loadHistoryTab(true);
    });

    document.getElementById('refresh-reports-btn')?.addEventListener('click', () => {
        reportsTabLoaded = false;
        loadReportsTab(true);
    });

    window.addEventListener('report-complete-refresh', () => {
        historyTabLoaded = false;
        reportsTabLoaded = false;
        if (currentAppTab === 'history') {
            loadHistoryTab(true);
        }
        if (currentAppTab === 'reports') {
            loadReportsTab(true);
        }
    });
}

window.loadHistoryTab = loadHistoryTab;
window.loadReportsTab = loadReportsTab;
window.switchAppTab = switchAppTab;
window.initializeReportsTab = initializeReportsTab;
