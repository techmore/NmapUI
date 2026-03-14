let reportsTabInitialized = false;
let reportsTabLoaded = false;
let currentAppTab = 'dashboard';

function setReportsTabStatus(message, isError = false) {
    const status = document.getElementById('reports-tab-status');
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

function createReportsTabCard(scan) {
    const card = document.createElement('article');
    card.className = 'rounded-2xl border border-olive-200 bg-olive-50 p-4 shadow-sm';

    const title = document.createElement('h3');
    title.className = 'text-xl font-display italic text-olive-950';
    title.textContent = scan.customer_name || 'Unknown';
    card.appendChild(title);

    const date = document.createElement('p');
    date.className = 'mt-1 text-sm text-olive-600';
    date.textContent = new Date(scan.timestamp).toLocaleString();
    card.appendChild(date);

    const target = document.createElement('p');
    target.className = 'mt-2 text-sm text-olive-800';
    target.innerHTML = `Target: <span class="font-mono">${scan.target || '--'}</span>`;
    card.appendChild(target);

    if (scan.diff_summary?.has_changes && typeof window.createHistoryDiffSummary === 'function') {
        const diffCard = window.createHistoryDiffSummary(scan.diff_summary);
        if (diffCard) {
            card.appendChild(diffCard);
        }
    }

    const actions = document.createElement('div');
    actions.className = 'mt-4 flex flex-wrap gap-2';

    const buildLink = (href, label, newTab = false) => {
        const link = document.createElement('a');
        link.href = href;
        link.textContent = label;
        link.className = 'action-button action-button-primary action-button-compact';
        if (newTab) {
            link.target = '_blank';
            link.rel = 'noopener noreferrer';
        }
        actions.appendChild(link);
    };

    if (scan.has_html) {
        buildLink(`/api/scans/${scan.path}/html`, 'View Report', true);
    }
    if (scan.has_pdf) {
        buildLink(`/api/scans/${scan.path}/pdf`, 'Download PDF');
    }
    if (scan.has_xml) {
        buildLink(`/api/scans/${scan.path}/xml`, 'Download XML');
    }

    card.appendChild(actions);
    return card;
}

function renderReportsTab(scans) {
    const list = document.getElementById('reports-tab-list');
    if (!list) {
        return;
    }

    list.replaceChildren();

    if (!scans.length) {
        setReportsTabStatus('No completed reports found yet.');
        return;
    }

    setReportsTabStatus('');
    scans.forEach((scan) => {
        list.appendChild(createReportsTabCard(scan));
    });
}

async function loadReportsTab(force = false) {
    if (reportsTabLoaded && !force) {
        return;
    }

    setReportsTabStatus('Loading reports...');

    try {
        const response = await fetch('/api/scans');
        if (!response.ok) {
            throw new Error(`Failed to load reports (${response.status})`);
        }
        const data = await response.json();
        const scans = (data.scans || []).filter((scan) => scan.has_html || scan.has_pdf || scan.has_xml);
        renderReportsTab(scans);
        reportsTabLoaded = true;
    } catch (error) {
        console.error('Error loading reports tab:', error);
        setReportsTabStatus('Failed to load reports.', true);
    }
}

function switchAppTab(tabName) {
    currentAppTab = tabName;
    const dashboardPanel = document.getElementById('dashboard-tab-panel');
    const reportsPanel = document.getElementById('reports-tab-panel');
    const dashboardButton = document.getElementById('tab-dashboard-btn');
    const reportsButton = document.getElementById('tab-reports-btn');

    const dashboardActive = tabName === 'dashboard';
    dashboardPanel?.classList.toggle('hidden', !dashboardActive);
    reportsPanel?.classList.toggle('hidden', dashboardActive);

    dashboardButton?.classList.toggle('action-button-primary', dashboardActive);
    dashboardButton?.classList.toggle('text-olive-700', !dashboardActive);
    dashboardButton?.classList.toggle('hover:bg-olive-100', !dashboardActive);

    reportsButton?.classList.toggle('action-button-primary', !dashboardActive);
    reportsButton?.classList.toggle('text-olive-700', dashboardActive);
    reportsButton?.classList.toggle('hover:bg-olive-100', dashboardActive);

    if (!dashboardActive) {
        loadReportsTab();
    }
}

function initializeReportsTab() {
    if (reportsTabInitialized) {
        return;
    }
    reportsTabInitialized = true;

    document.getElementById('tab-dashboard-btn')?.addEventListener('click', () => {
        switchAppTab('dashboard');
    });

    document.getElementById('tab-reports-btn')?.addEventListener('click', () => {
        switchAppTab('reports');
    });

    document.getElementById('refresh-reports-btn')?.addEventListener('click', () => {
        reportsTabLoaded = false;
        loadReportsTab(true);
    });

    window.addEventListener('report-complete-refresh', () => {
        reportsTabLoaded = false;
        if (currentAppTab === 'reports') {
            loadReportsTab(true);
        }
    });
}

window.setReportsTabStatus = setReportsTabStatus;
window.loadReportsTab = loadReportsTab;
window.switchAppTab = switchAppTab;
window.initializeReportsTab = initializeReportsTab;
