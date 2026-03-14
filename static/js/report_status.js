function createReportProgressCard(message) {
    const reportCard = document.createElement('div');
    reportCard.id = 'report-progress-card';
    reportCard.className = 'mt-4 bg-olive-50 p-4 rounded-xl border border-olive-300 card-pulsing';
    const row = document.createElement('div');
    row.className = 'flex items-center gap-3';

    const indicator = document.createElement('span');
    indicator.className = 'relative flex size-3';

    const ping = document.createElement('span');
    ping.className = 'absolute inline-flex h-full w-full animate-ping rounded-full bg-olive-500 opacity-75';
    indicator.appendChild(ping);

    const dot = document.createElement('span');
    dot.className = 'relative inline-flex size-3 rounded-full bg-olive-600';
    indicator.appendChild(dot);

    const text = document.createElement('p');
    text.id = 'report-progress-text';
    text.className = 'text-sm font-medium text-olive-900';
    text.textContent = message;

    row.appendChild(indicator);
    row.appendChild(text);
    reportCard.appendChild(row);
    const statusDiv = document.getElementById('report-status');
    statusDiv.parentNode.insertBefore(reportCard, statusDiv.nextSibling);
}

function updateReportProgress(message) {
    const progressText = document.getElementById('report-progress-text');
    if (!progressText) {
        createReportProgressCard(message);
        return;
    }

    progressText.textContent = message;
}

function removeReportProgressCard() {
    const card = document.getElementById('report-progress-card');
    if (card) {
        card.remove();
    }
}

function showReportStatus(message, type) {
    const statusDiv = document.getElementById('report-status');
    const statusText = document.getElementById('report-status-text');

    statusDiv.classList.remove('hidden', 'bg-olive-100', 'bg-olive-200', 'bg-red-100', 'text-olive-800', 'text-olive-900', 'text-red-800');
    statusDiv.classList.add(
        type === 'error' ? 'bg-red-100' : 'bg-olive-100',
        type === 'error' ? 'text-red-800' :
        type === 'success' ? 'text-olive-900' :
        'text-olive-800'
    );

    statusText.textContent = message;

    if (type === 'success' || type === 'error') {
        setTimeout(() => statusDiv.classList.add('hidden'), 5000);
    }
}

window.createReportProgressCard = createReportProgressCard;
window.updateReportProgress = updateReportProgress;
window.removeReportProgressCard = removeReportProgressCard;
window.showReportStatus = showReportStatus;
