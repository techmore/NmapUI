let appTabsInitialized = false;
let reportsTabLoaded = false;
let historyTabLoaded = false;
let currentAppTab = 'dashboard';

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

function createHistoryCard(scan) {
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
        list.appendChild(createHistoryCard(scan));
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
