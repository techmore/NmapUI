let lastScanTarget = '';
let lastScanResults = {};
let reportTimerInterval = null;
let reportStartTime = 0;
let reportSocket = null;
let getClientJobs = null;

function startReportTimer() {
    const container = document.getElementById('scan-timer-container');
    const display = document.getElementById('scan-timer');
    const feedbackBox = document.getElementById('feedback-container');

    container.classList.remove('hidden');
    feedbackBox.classList.add('card-pulsing');
    reportStartTime = Date.now();

    if (reportTimerInterval) clearInterval(reportTimerInterval);

    reportTimerInterval = setInterval(() => {
        const elapsed = Math.floor((Date.now() - reportStartTime) / 1000);
        const mins = Math.floor(elapsed / 60).toString().padStart(2, '0');
        const secs = (elapsed % 60).toString().padStart(2, '0');
        display.textContent = `${mins}:${secs}`;
    }, 1000);
}

function stopReportTimer() {
    const feedbackBox = document.getElementById('feedback-container');
    const timerContainer = document.getElementById('scan-timer-container');

    if (reportTimerInterval) {
        clearInterval(reportTimerInterval);
        reportTimerInterval = null;
    }

    feedbackBox.classList.remove('card-pulsing');

    setTimeout(() => {
        timerContainer.classList.add('hidden');
        feedbackBox.innerHTML = '';
        feedbackBox.parentElement.classList.add('hidden');
    }, 5000);
}

function setLastScanTarget(target) {
    lastScanTarget = target;
}

function updateLastScanResults(key, data) {
    lastScanResults[key] = data;
}

function initializeReportGenerationUI(socket, deps) {
    reportSocket = socket;
    getClientJobs = deps.getClientJobs;

    document.getElementById('generate-report-btn').addEventListener('click', function() {
        if (getClientJobs().report.status === 'running') {
            return;
        }

        const target = document.getElementById('scan-target').value || lastScanTarget;
        if (!target) {
            showReportStatus('Please enter a target or run a scan first', 'error');
            return;
        }

        const customerOption = document.getElementById('current-customer').selectedOptions[0];
        let customerName = 'Unknown';

        if (customerOption) {
            customerName = customerOption.text.split(' (')[0];
        }

        this.classList.add('card-pulsing');
        startReportTimer();

        reportSocket.emit('generate_report', {
            target: target,
            customer_name: customerName,
            scan_results: lastScanResults
        });
    });

    document.getElementById('start-scan-btn').addEventListener('click', function() {
        setLastScanTarget(document.getElementById('scan-target').value);
    });
}

window.startReportTimer = startReportTimer;
window.stopReportTimer = stopReportTimer;
window.setLastScanTarget = setLastScanTarget;
window.updateLastScanResults = updateLastScanResults;
window.initializeReportGenerationUI = initializeReportGenerationUI;
